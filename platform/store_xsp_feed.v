module platform

import code {
	is_err_value,
	mk_err,
}
import cx

// store_xsp_feed.v — the change feed on the XSP store-profile listener
// (I5 stream 4 W4; spec/03-approved/xap/xsp_store_profile.md §5.1–§5.3). ONE
// mechanism for four spec'd consumers (changes-since, replica seeding, peer
// revocation propagation, shred propagation — W5 adds no new machinery):
// a server-level subscription registry over the mount's E3 lineage
// (MemStore.advances — the same log the fixed `store:log` reads), pumped
// after local writes and from the liveness sweeper tick (cross-listener
// writes), credit-governed on the REQUEST's stream-id, NEVER coalesced (one
// act, one frame), cancel → terminal `[eos cancelled=true]`, and HEAD-SET
// map cursors bound to the mount's durable EPOCH token (FL-1 #764: data-
// plane positions survive restart on the local durable substrates, so a
// prior-boot cursor RESUMES; a cursor outside the retained lineage — wrong
// epoch, below a retention floor, above a head — is CXER5020, the honest
// `:gapless`-class refusal, never silent divergence).

const sx_err_feed = 'cx-err:CXER5019' // E_XSP_STORE_FEED (§4.2)
const sx_err_cursor = 'cx-err:CXER5020' // E_XSP_STORE_CURSOR (§4.2)
const sx_err_peer = 'cx-err:CXER5022' // E_XSP_STORE_PEER (§4.2, W5)

const sx_feed_planes = ['docs', 'refs', 'aliases']
const sx_feed_rung = ':complete-ordered'
// the §7.1 peer-channel sweep cadence the convergence bound reports (the
// liveness sweeper tick that pumps cross-listener writes and rev folds).
const sx_feed_lag_ms = 250

// SxFeed is one live change-feed subscription. `idx` is the next
// MemStore.advances index to consider; `from` holds the per-stream position
// floors of the resume cursor (empty = no floor — deliver everything).
struct SxFeed {
mut:
	conn_id  int
	stream   i64
	mount    string
	planes   []string
	bodies   bool
	windowed bool
	credits  i64
	idx      int
	from     map[string]i64
	sent     i64
	// W5 §7.1: a revocations-plane subscription (subscribes ALONE) — the
	// designated journal replayed/tailed by seq; rev_seq = last delivered
	// (durable positions, boot-exempt).
	rev        bool
	rev_tenant string
	rev_seq    i64
}

fn sx_feed_key(conn_id int, stream i64) string {
	return '${conn_id}:${stream}'
}

// sx_feed_start_locked validates a `[feed …]` subscribe, registers it, sends
// the `[feed-sub …]` reply (whose head-set IS the anchor), and pumps any
// replay the cursor asks for. Gate order: negotiation, lanes, cursor.
fn sx_feed_start_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node) {
	// transcript gate: `feed` is spoken only to a peer that confirmed
	// `store-feed`; `bodies=true` additionally needs `store-delta` (§5.2).
	if !c.confirmed_features.split(' ').contains('store-feed') {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_unsupported,
			'E_XSP_STORE_UNSUPPORTED: [feed] is un-negotiated on this session — the transcript did not confirm store-feed (§5.2)'))
		return
	}
	bodies := req.attr('bodies') == 'true'
	if bodies && !c.confirmed_features.split(' ').contains('store-delta') {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
			'E_XSP_STORE_FEED: bodies=true needs the confirmed store-delta token (§5.2)'))
		return
	}
	if req.has_attr('rung') && req.attr('rung') != sx_feed_rung {
		// refuse-to-lie at wiring time: this surface declares exactly
		// :complete-ordered (the CDC top rung); an unknown or undeclarable
		// rung never silently downgrades (§5.2).
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
			'E_XSP_STORE_FEED: this feed declares rung=${sx_feed_rung} (got "${req.attr('rung')}")'))
		return
	}
	mut windowed := false
	mut window := i64(0)
	if req.has_attr('window') {
		window = req.attr('window').i64()
		if window < 1 {
			sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
				'E_XSP_STORE_WIRE: window= must be ≥ 1'))
			return
		}
		windowed = true
	}
	mut planes := sx_feed_planes.clone()
	for it in req.items {
		if it is cx.Element && it.name == 'planes' {
			// §5.2: [planes …] is ONE space-separated scalar
			// ([planes "docs refs"]). A multi-SCALAR shape
			// ([planes "docs" "refs"]) is malformed — refuse loudly
			// (no-dual-accept), never silently keep the last (audit F-21).
			mut ptxt := ''
			mut n_scalars := 0
			for pit in it.items {
				t := authz_node_text(pit)
				if t != '' {
					ptxt = t
					n_scalars++
				}
			}
			if n_scalars > 1 {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
					'E_XSP_STORE_FEED: [planes …] takes ONE space-separated scalar (e.g. [planes "docs refs"]); a multi-scalar shape is malformed'))
				return
			}
			planes = []
			for p in ptxt.split(' ') {
				if p == '' {
					continue
				}
				if p !in sx_feed_planes && p != 'revocations' {
					sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
						'E_XSP_STORE_FEED: unknown plane "${p}" (docs refs aliases revocations)'))
					return
				}
				planes << p
			}
		}
	}
	if planes.len == 0 {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
			'E_XSP_STORE_FEED: [planes …] names no plane'))
		return
	}
	if 'revocations' in planes {
		// §7.1: the peer channel — subscribes ALONE, gated by the
		// transcript-confirmed peer token AND the deny-by-default peer
		// capability (no open-mode exception), on a daemon that designates
		// a revocations journal.
		if planes.len > 1 {
			sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
				'E_XSP_STORE_FEED: the revocations plane subscribes alone (§5.2)'))
			return
		}
		sx_feed_start_revocations_locked(mut srv, mut c, stream, req, local, bodies,
			windowed, window)
		return
	}
	if sx_feed_key(c.id, stream) in srv.feeds || stream in c.streams {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: stream ${stream} already carries a live stream'))
		return
	}
	mut guard := store_for_guard(local) or { unsafe { nil } }
	if guard == unsafe { nil } {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
			'E_XSP_STORE_FEED: this mount keeps no local lineage (remote mounts subscribe at their origin)'))
		return
	}
	// cursor (§5.1/§5.2): [from boot="…" [s plane= name=? pos=]…]. Entries
	// demand the epoch token — positions are relative to the retention
	// boundary it names, and durable across restarts (FL-1); an empty
	// [from] is the full replay and asserts no positions.
	mut has_from := false
	mut from := map[string]i64{}
	mut from_boot := ''
	for it in req.items {
		if it is cx.Element && it.name == 'from' {
			has_from = true
			from_boot = sw_attr(it, 'boot')
			for s in it.items {
				if s is cx.Element && s.name == 's' {
					plane := sw_attr(s, 'plane')
					name := sw_attr(s, 'name')
					pos := sw_attr(s, 'pos').i64()
					if plane !in sx_feed_planes || pos < 0 || (plane != 'docs' && name == '') {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
							'E_XSP_STORE_FEED: malformed [from [s …]] entry (plane=docs|refs|aliases, name= for refs/aliases, pos ≥ 0)'))
						return
					}
					from[store_feed_stream_key(plane, name)] = pos
				}
			}
		}
	}
	store_lock_enter(mut guard)
	// cursor validation (FL-1 #764, the narrowed CXER5020): positions are
	// durable on the local durable substrates, so a valid prior-boot cursor
	// RESUMES. The typed :gapless-class refusal now means exactly "gapless
	// resume is impossible": an epoch token this lineage never issued, a
	// position below a stream's retention floor (compacted-away history),
	// or a position above its head (never issued).
	boot := guard.feed_boot
	if has_from && from.len > 0 {
		if from_boot != boot {
			store_lock_exit(mut guard)
			sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_cursor,
				'E_XSP_STORE_CURSOR: the cursor is below the retention boundary (epoch "${from_boot}" is not this lineage\'s epoch "${boot}") — re-seed and resume from the new head-set'))
			return
		}
		for key, pos in from {
			floor := guard.adv_floor[key] or { i64(0) }
			head := guard.adv_pos[key] or { i64(0) }
			if pos < floor || pos > head {
				store_lock_exit(mut guard)
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_cursor,
					'E_XSP_STORE_CURSOR: the cursor is outside the retained lineage for stream "${key}" (pos=${pos}, retained ${floor}..${head}) — re-seed and resume from the new head-set'))
				return
			}
		}
	}
	// the reply's head-set IS the anchor; absent [from] tails from it.
	// (ONE head-set implementation — the §7a advert renders the same form.)
	hs := sx_head_set_locked(mut guard)
	idx := if has_from { 0 } else { guard.advances.len }
	store_lock_exit(mut guard)
	srv.feeds[sx_feed_key(c.id, stream)] = &SxFeed{
		conn_id:  c.id
		stream:   stream
		mount:    c.mount
		planes:   planes
		bodies:   bodies
		windowed: windowed
		credits:  window
		idx:      idx
		from:     from.clone()
	}
	sx_reply_locked(mut srv, c.id, stream, '[feed-sub rung="${sx_feed_rung}" ${hs}]')
	sx_pump_feed_locked(mut srv, sx_feed_key(c.id, stream))
}

// sx_feed_start_revocations_locked validates and registers a `revocations`
// plane subscription (§7.1): the designated journal replayed strictly above
// the cursor's seq (DURABLE positions — boot-exempt), then tailed live. The
// reply reports the convergence bound. The PEP already decided the `peer`
// capability in dispatch; here the structural gates refuse (CXER5022).
fn sx_feed_start_revocations_locked(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node, bodies bool, windowed bool, window i64) {
	if !c.confirmed_features.split(' ').contains('peer') {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_peer,
			'E_XSP_STORE_PEER: the revocations plane needs the transcript-confirmed peer token (§7.1)'))
		return
	}
	if srv.cfg.revocations_tenant == '' {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_peer,
			'E_XSP_STORE_PEER: this daemon designates no revocations journal ([xsp [revocations journal=…]])'))
		return
	}
	if c.authz == unsafe { nil } {
		// deny-by-default with NO open-mode exception (§7.1): the peer
		// capability exists only under the enforcing posture.
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_peer,
			'E_XSP_STORE_PEER: the peer capability is deny-by-default — it has no open-mode exception (configure [grants …])'))
		return
	}
	if bodies {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
			'E_XSP_STORE_FEED: the revocations plane carries no bodies'))
		return
	}
	if sx_feed_key(c.id, stream) in srv.feeds || stream in c.streams {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: stream ${stream} already carries a live stream'))
		return
	}
	// cursor: [from [s plane="revocations" pos=N]] — journal seqs are
	// durable, so the cursor needs no boot token (§5.2). Absent = full
	// replay from seq 0 (idempotent folds make redelivery safe).
	mut floor := i64(0)
	for it in req.items {
		if it is cx.Element && it.name == 'from' {
			for s in it.items {
				if s is cx.Element && s.name == 's' {
					// §5.2: the revocations plane is a SINGLE stream — its cursor
					// carries plane + pos ONLY. A name= attr is meaningful only on
					// the per-name refs/aliases planes; on revocations it is
					// malformed and refuses (never accepted-and-ignored, audit F-21).
					if sw_attr(s, 'plane') != 'revocations' || sw_attr(s, 'pos').i64() < 0
						|| sw_attr(s, 'name') != '' {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_feed,
							'E_XSP_STORE_FEED: a revocations cursor carries [s plane="revocations" pos=N] entries only (no name=)'))
						return
					}
					floor = sw_attr(s, 'pos').i64()
				}
			}
		}
	}
	tenant := srv.cfg.revocations_tenant
	head := sx_rev_head_seq(local, tenant, 0)
	srv.feeds[sx_feed_key(c.id, stream)] = &SxFeed{
		conn_id:    c.id
		stream:     stream
		mount:      c.mount
		planes:     ['revocations']
		windowed:   windowed
		credits:    window
		rev:        true
		rev_tenant: tenant
		rev_seq:    floor
	}
	sx_reply_locked(mut srv, c.id, stream, '[feed-sub rung="${sx_feed_rung}" [revocations tenant="${sw_msg_esc(tenant)}" head=${head}] [convergence feed-lag-ms=${sx_feed_lag_ms} enforcement="next-pep-check"]]')
	sx_pump_feed_locked(mut srv, sx_feed_key(c.id, stream))
}

// sx_pump_rev_feed_locked delivers journal revocation events strictly above
// the delivered seq while credit remains. Caller resolved the mount.
fn sx_pump_rev_feed_locked(mut srv StoreXspServer, mut f SxFeed, local cx.Node) {
	head := sx_rev_head_seq(local, f.rev_tenant, int(f.rev_seq))
	if head <= int(f.rev_seq) {
		return
	}
	for ev in sx_rev_events(local, f.rev_tenant, int(f.rev_seq), head) {
		if f.windowed && f.credits <= 0 {
			return // window exhausted: the next credit frame resumes here
		}
		sx_event_locked(mut srv, f.conn_id, f.stream, '[revoke plane="revocations" pos=${ev.seq} vc-id="${sw_msg_esc(ev.vc_id)}"]',
			false)
		f.sent++
		f.rev_seq = ev.seq
		if f.windowed {
			f.credits--
		}
	}
	f.rev_seq = head // non-revocation entries consume their seqs silently
}

// sx_render_advance renders one lineage act as its §5.3 notification (one
// act, one frame — ∂ streams MUST NOT coalesce). Caller holds the op lock.
fn sx_render_advance(mut guard MemStore, local cx.Node, a StoreAdvance, bodies bool) string {
	match a.plane {
		'docs' {
			if a.kind == 'retract' {
				return '[retract plane="docs" pos=${a.pos} hash="${a.hash}"]'
			}
			if a.kind == 'erase' {
				// §5.3/§7b.1: a lawful shred is a DISTINCT act (never a
				// retract — the delete/erase discriminator survives the
				// wire), and the notification carries its attribution: the
				// shred-request AS journal data on this feed. A replica
				// executes its OWN local shred from it — no reach-in.
				mut sb := '[erase plane="docs" pos=${a.pos} hash="${a.hash}"'
				if tomb := guard.erased[a.hash] {
					if doc := cx.parse(tomb) {
						if doc.elements.len > 0 {
							e := doc.elements[0]
							if e is cx.Element {
								for name in ['at', 'actor', 'authority'] {
									v := e.attr(name)
									if v != '' {
										sb += ' ${name}="${sw_msg_esc(v)}"'
									}
								}
								// The act's request= carries the tombstone's
								// shred-request= (the §6 ruled tombstone shape,
								// stream 20 W5); the act itself keeps the
								// profile's §5.3 act vocabulary.
								rq := e.attr('shred-request')
								if rq != '' {
									sb += ' request="${sw_msg_esc(rq)}"'
								}
							}
						}
					}
				}
				return sb + ']'
			}
			mut sb := '[insert plane="docs" pos=${a.pos} hash="${a.hash}"'
			if bodies {
				// the get-lane body carriage (§5.3); a doc gone by delivery
				// time carries no body — its retract follows in the same
				// ordered stream, never a silent inconsistency. A doc ERASED
				// by delivery time is a redaction, not a silence: the frame
				// carries the visible count (§5.3's first producer).
				if a.hash in guard.erased {
					return sb + ' redacted=1]'
				}
				r := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(a.hash)]) or {
					cx.Node(cx.Element{})
				}
				if !is_err_value(r) && r is cx.ScalarNode {
					text := cx.scalar_value_str_public(r.value)
					if doc := cx.parse(text) {
						bin := cx.emit_ast_bin(doc)
						sb += ' [body::bytes 0x${bin.hex()}]'
					}
				}
			}
			return sb + ']'
		}
		'refs' {
			mh := cx.cx_multihash_encode('sha2-256', a.root) or { []u8{} }
			return '[advance plane="refs" name="${sw_msg_esc(a.name)}" pos=${a.pos} root::bytes=0x${mh.hex()}]'
		}
		'aliases' {
			if a.kind == 'retract' {
				return '[retract plane="aliases" name="${sw_msg_esc(a.name)}" pos=${a.pos}]'
			}
			return '[advance plane="aliases" name="${sw_msg_esc(a.name)}" pos=${a.pos} hash="${a.hash}"]'
		}
		else {}
	}
	return ''
}

// sx_pump_feed_locked delivers eligible lineage acts to one feed while
// credit remains. Per-stream position order IS arrival order within a
// stream (positions are dense and appended monotonically); cross-stream
// order is arrival order — no cross-stream total order exists (§5.1).
fn sx_pump_feed_locked(mut srv StoreXspServer, key string) {
	mut f := srv.feeds[key] or { return }
	if f.conn_id !in srv.conns {
		srv.feeds.delete(key) // subscription state dies with the connection
		return
	}
	local := srv.ctx.mounts[f.mount] or {
		srv.feeds.delete(key)
		return
	}
	if f.rev {
		sx_pump_rev_feed_locked(mut srv, mut f, local)
		return
	}
	mut guard := store_for_guard(local) or { unsafe { nil } }
	if guard == unsafe { nil } {
		return
	}
	store_lock_enter(mut guard)
	defer {
		store_lock_exit(mut guard)
	}
	for f.idx < guard.advances.len {
		a := guard.advances[f.idx]
		if a.plane !in f.planes {
			f.idx++
			continue
		}
		if fl := f.from[store_feed_stream_key(a.plane, a.name)] {
			if a.pos <= fl {
				f.idx++
				continue
			}
		}
		if f.windowed && f.credits <= 0 {
			return // window exhausted: the next credit frame resumes here
		}
		body := sx_render_advance(mut guard, local, a, f.bodies)
		if body != '' {
			sx_event_locked(mut srv, f.conn_id, f.stream, body, false)
			f.sent++
			if f.windowed {
				f.credits--
			}
		}
		f.idx++
	}
}

// sx_pump_all_feeds_locked wakes every registered feed — called after local
// write dispatches and from the sweeper tick (cross-listener writers drive
// the same op core, so their acts land in the same lineage; the sweeper is
// how they reach subscribers on THIS listener).
fn sx_pump_all_feeds_locked(mut srv StoreXspServer) {
	for key, _ in srv.feeds {
		sx_pump_feed_locked(mut srv, key)
	}
}
