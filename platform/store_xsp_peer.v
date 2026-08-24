module platform

import code {
	arg_string,
	bytes_node,
	crypto_random_octets,
	crypto_string_node,
	is_err_value,
	net_close_id,
	net_dial_tcp_real,
	net_dial_tls_real,
	net_h_write,
	net_handle_id,
	net_mut_handle,
	x25519_clamp,
	x25519_scalar_base_mult,
}
import cx
import time

// store_xsp_peer.v — the server↔server peer surface (I5 stream 4 W5;
// spec/03-approved/xap/xsp_store_profile.md §7/§7.1). ONE mechanism, both sides:
//
//  * SERVING: the feed's `revocations` plane — the designated revocations
//    journal ([xsp [revocations journal=<tenant>]]) replayed by journal seq
//    (DURABLE positions — the plane is boot-exempt) and tailed live. Gated
//    by the transcript-confirmed `peer` token AND the deny-by-default `peer`
//    capability (NO open-mode exception — CXER5022).
//  * CONSUMING: one worker per configured [peer …] dials the peer as a
//    mutual XSP-AUTH initiator (responder DID pinned), subscribes the
//    revocations plane, and FOLDS arriving [revoke …] events into the local
//    revoked-set. Folding is the ONLY effect (no reach-in): enforcement is
//    §6.1's two local points — refuse at present, drop compiled-from-revoked
//    delegations at the next PEP check. An offline peer is lag, never an
//    error state (vc.md 3b) — the worker retries with backoff.
//
// The daemon also folds its OWN designated journal (a daemon honors its own
// revocations without dialing itself) from the liveness sweeper tick.

// sx_rev_head_seq discovers the designated revocations journal's head seq
// by probing the per-seq entry aliases upward from `floor` (journal seqs
// are dense, so the first absent alias is one past the head). O(delta) per
// call against a moving cursor; floor=0 walks the whole journal (once, at
// subscribe). Probing the entries — rather than reading the head alias —
// keeps ONE read path for anything that writes entry aliases.
fn sx_rev_head_seq(local cx.Node, tenant string, floor int) int {
	mut head := floor
	for {
		r := store_stdlib_builtin_inner('store-get-alias', [local,
			store_str(jrn_entry_alias(tenant, head + 1))]) or { break }
		if r is cx.ScalarNode {
			head++
			continue
		}
		break
	}
	return head
}

// sx_revoke_vc_id extracts the vc-id from a revocation event payload —
// [revoke vc-id=…] possibly wrapped one level (the vc_revoke_event_id
// descent, applied to the detached payload doc).
fn sx_revoke_vc_id(n cx.Node) ?string {
	if n is cx.Element {
		if n.name == 'revoke' {
			id := sw_attr(n, 'vc-id')
			if id != '' {
				return id
			}
			return none
		}
		for it in n.items {
			if r := sx_revoke_vc_id(it) {
				return r
			}
		}
	}
	return none
}

// sx_rev_events collects the revocation events strictly above `from_seq` up
// to `upto` from the designated journal: (seq, vc-id) pairs in seq order.
// Non-revocation entries in the journal consume their seq but emit nothing.
fn sx_rev_events(local cx.Node, tenant string, from_seq int, upto int) []SxRevEvent {
	mut out := []SxRevEvent{}
	for seq := from_seq + 1; seq <= upto; seq++ {
		dh := store_stdlib_builtin_inner('store-get-alias', [local,
			store_str(jrn_entry_alias(tenant, seq))]) or { continue }
		if dh !is cx.ScalarNode {
			continue
		}
		et := store_stdlib_builtin_inner('store-get-doc-text', [local,
			store_str(sw_scalar(dh))]) or { continue }
		if et !is cx.ScalarNode {
			continue
		}
		entry := jrn_parse_entry(sw_scalar(et)) or { continue }
		addr := jrn_entry_attr(entry, 'payload')
		if addr == '' {
			continue
		}
		pt := store_stdlib_builtin_inner('store-get-doc-text', [local, store_str(addr)]) or {
			continue
		}
		if pt !is cx.ScalarNode {
			continue
		}
		pdoc := cx.parse(sw_scalar(pt)) or { continue }
		if pdoc.elements.len == 0 {
			continue
		}
		vcid := sx_revoke_vc_id(pdoc.elements[0]) or { continue }
		out << SxRevEvent{
			seq:   seq
			vc_id: vcid
		}
	}
	return out
}

struct SxRevEvent {
	seq   int
	vc_id string
}

// sx_fold_local_revocations_locked folds every mount's designated journal
// into the daemon's revoked-set (the liveness sweeper tick — §7.1's
// convergence bound is the tick period). Caller holds srv.mu.
fn sx_fold_local_revocations_locked(mut srv StoreXspServer) {
	tenant := srv.cfg.revocations_tenant
	if tenant == '' {
		return
	}
	for name, local in srv.ctx.mounts {
		key := name
		folded := srv.rev_folded[key] or { 0 }
		head := sx_rev_head_seq(local, tenant, folded)
		if head <= folded {
			continue
		}
		for ev in sx_rev_events(local, tenant, folded, head) {
			srv.revoked[ev.vc_id] = true
		}
		srv.rev_folded[key] = head
	}
}

// sx_revoked_set_locked renders the daemon's revoked-set as the
// [revoked-set [id …]…] fold vc_is_revoked consumes. Caller holds srv.mu.
fn sx_revoked_set_locked(srv &StoreXspServer) cx.Node {
	mut ids := []cx.Node{}
	for id, _ in srv.revoked {
		ids << cx.Node(cx.Element{
			name:  'id'
			items: [cx.Node(bus_str(id))]
		})
	}
	return cx.Element{
		name:  'revoked-set'
		items: ids
	}
}

// ── the outbound peer worker (§7.1) ────────────────────────────────────────

pub fn store_xsp_peer_workers(mut srv StoreXspServer) {
	for peer in srv.cfg.peers {
		spawn sx_peer_worker(mut srv, peer)
	}
}

fn sx_peer_worker(mut srv StoreXspServer, peer XspPeer) {
	mut folded := i64(0) // in-memory cursor: at-least-once + idempotent folds
	mut backoff := 1
	for {
		if svc_shutdown_requested() {
			return
		}
		ok, nf := sx_peer_session(mut srv, peer, folded)
		folded = nf
		if svc_shutdown_requested() {
			return
		}
		if ok {
			backoff = 1 // the session lived; reconnect promptly
		} else {
			backoff = if backoff >= 8 { 8 } else { backoff * 2 }
		}
		for _ in 0 .. backoff * 4 {
			if svc_shutdown_requested() {
				return
			}
			time.sleep(250 * time.millisecond)
		}
	}
}

// sx_peer_session runs one dial → attach → subscribe → fold lifetime.
// Returns (subscription-established, the advanced fold cursor).
fn sx_peer_session(mut srv StoreXspServer, peer XspPeer, folded_in i64) (bool, i64) {
	mut folded := folded_in
	// dial (operator-configured target — the [peers] section is the
	// authority; xsps:// rides the TLS transport)
	a := parse_transport_url(peer.url.replace('xsps://', 'tls://').replace('xsp://',
		'tcp://'), false) or { return false, folded }
	empty_opts := cx.Node(cx.Element{
		name: code.map_marker_name
	})
	sock := if peer.url.starts_with('xsps://') {
		net_dial_tls_real(a.host, a.host, a.port, empty_opts, a)
	} else {
		net_dial_tcp_real(a, empty_opts)
	}
	if is_err_value(sock) {
		return false, folded
	}
	net_id := net_handle_id(sock) or { return false, folded }
	defer {
		net_close_id(net_id)
	}
	mut h := net_mut_handle(sock) or { return false, folded }
	h.read_deadline_ms = 1000

	// XSP-AUTH initiator (mutual: the daemon's own identity; §7.1)
	nonce := crypto_random_octets(32) or { return false, folded }
	eph_priv := crypto_random_octets(32) or { return false, folded }
	mut sk := eph_priv.clone()
	x25519_clamp(mut sk)
	eph_pub := x25519_scalar_base_mult(sk)
	m1 := xsp_auth_stdlib_builtin('xsp-auth-hello', [
		cx.Node(cx.Element{
			name:  code.map_marker_name
			items: [
				session_kv('nonce', bytes_node(nonce)),
				session_kv('eph', bytes_node(eph_pub)),
				session_kv('endpoint', crypto_string_node(peer.url)),
				session_kv('did', crypto_string_node(srv.cfg.identity_did)),
				session_kv('offer-profiles', crypto_string_node('store')),
				session_kv('offer-features', crypto_string_node('credit peer store-delta store-feed')),
			]
		}),
	]) or { return false, folded }
	if is_err_value(m1) {
		return false, folded
	}
	m2 := sx_peer_turn(mut h, m1) or { return false, folded }
	if is_err_value(m2) {
		return false, folded
	}
	m3 := xsp_auth_stdlib_builtin('xsp-auth-prove', [m1, m2,
		cx.Node(cx.Element{
			name:  code.map_marker_name
			items: [
				session_kv('eph-priv', bytes_node(eph_priv)),
				session_kv('key', bytes_node(srv.cfg.identity_seed)),
				session_kv('attach', cx.Node(cx.Element{
					name:  'attach'
					items: [
						cx.Node(cx.Element{
							name:  'tenant'
							items: [cx.Node(bus_str(peer.tenant))]
						}),
					]
				})),
			]
		})]) or { return false, folded }
	if is_err_value(m3) {
		return false, folded
	}
	m4 := sx_peer_turn(mut h, m3) or { return false, folded }
	if is_err_value(m4) {
		return false, folded
	}
	done := xsp_auth_stdlib_builtin('xsp-auth-finish', [m1, m2, m4,
		cx.Node(cx.Element{
			name:  code.map_marker_name
			items: [session_kv('eph-priv', bytes_node(eph_priv))]
		})]) or { return false, folded }
	if is_err_value(done) {
		return false, folded
	}
	mut responder := ''
	mut confirmed := ''
	if done is cx.Element {
		responder = xap_elem_attr(done, 'responder')
		if conf := xsp_auth_child(done, 'confirmed') {
			confirmed = xap_elem_attr(conf, 'features')
		}
	}
	if responder != peer.did {
		eprintln('cx store-serve[xsp]: peer ${peer.url} identity "${responder}" is not the pinned did "${peer.did}" — refusing')
		return false, folded
	}
	if !confirmed.split(' ').contains('peer') {
		eprintln('cx store-serve[xsp]: peer ${peer.url} did not confirm the peer token — no revocations surface there')
		return false, folded
	}

	// subscribe the revocations plane, resuming from the durable cursor
	mut from := ''
	if folded > 0 {
		from = ' [from [s plane="revocations" pos=${folded}]]'
	}
	sub := cx.parse('[feed [planes "revocations"]${from}]') or { return false, folded }
	req := fs_frame_bytes('request', 1, sub.elements[0]) or { return false, folded }
	net_h_write(mut h, req) or { return false, folded }

	// consume: the feed-sub reply, then live [revoke …] events. Stream-0
	// events (the §7a advert) are consumed and ignored here — the worker's
	// one job is the fold. No reach-in: folding is the ONLY effect.
	mut subscribed := false
	mut idle := 0
	for {
		if svc_shutdown_requested() {
			return subscribed, folded
		}
		st, raw := fs_read_frame(mut h, srv.cfg.max_frame_bytes)
		match st {
			.idle {
				idle++
				if !subscribed && idle > 10 {
					return false, folded // no feed-sub within the budget
				}
				continue
			}
			.closed {
				return subscribed, folded
			}
			.frame {
				idle = 0
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					return subscribed, folded
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					return subscribed, folded
				}
				ftype := xap_elem_attr(fe, 'type')
				stream := xap_elem_attr(fe, 'stream').i64()
				if ftype == 'error' {
					return subscribed, folded // typed refusal (e.g. CXER5022) — retry later
				}
				if ftype == 'reply' && stream == 1 {
					subscribed = true
					continue
				}
				if ftype != 'event' || stream != 1 {
					continue // stream-0 advert etc.
				}
				pv := xsp_payload_value(fe) or { continue }
				txt := arg_string(pv) or { continue }
				pdoc := cx.parse(txt) or { continue }
				if pdoc.elements.len == 0 {
					continue
				}
				ev := pdoc.elements[0]
				if ev is cx.Element && ev.name == 'revoke' {
					vcid := sw_attr(ev, 'vc-id')
					pos := sw_attr(ev, 'pos').i64()
					if vcid != '' {
						srv.mu.lock()
						srv.revoked[vcid] = true
						srv.mu.unlock()
						if pos > folded {
							folded = pos
						}
					}
				}
			}
		}
	}
	return subscribed, folded
}

// sx_peer_turn sends one handshake message as a BINARY stream-0 request and
// returns the reply/error payload.
fn sx_peer_turn(mut h code.NetHandle, msg cx.Node) ?cx.Node {
	b := fs_frame_bytes_bin('request', 0, msg) or { return none }
	net_h_write(mut h, b) or { return none }
	mut ticks := 0
	for ticks < 10 {
		st, raw := fs_read_frame(mut h, i64(16777216))
		match st {
			.idle {
				ticks++
				continue
			}
			.closed {
				return none
			}
			.frame {
				node := xsp_decode_at(raw, 0)
				if node !is cx.Element {
					return none
				}
				fe := node as cx.Element
				if fe.name != 'frame' {
					return none
				}
				return xsp_payload_value(fe)
			}
		}
	}
	return none
}
