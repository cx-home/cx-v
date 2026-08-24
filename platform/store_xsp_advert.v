module platform

import cx

// store_xsp_advert.v — the generation-bound, signed profile advert (I5
// stream 4 W5; spec/03-approved/xap/xsp_store_profile.md §7a/§7a.1). Immediately
// after the M4 reply the server pushes ONE text `event` frame on stream 0:
//
//   [store-advert generation=<gen> [head-set …] [guarantees "<tokens>"]
//    signer="<daemon-did>" sig-algo=":ed25519" sig="<hex>"]
//
// The signature covers render_canonical of `[store-advert-canonical
// generation= [head-set …] [guarantees …]]` (the journal snapshot-canonical
// pattern) under the daemon's [identity] key — generation, coordinate, and
// guarantee set are bound together. F3: every APPLIED config-reload
// (generation bump) re-advertises to every established session — the
// listener's own reload verb reports through the same hot-config box the
// other listeners use, and the liveness sweeper's generation watch catches
// cross-listener reloads. A cached advert across reload is a cached lie.

// The consistency-vocabulary token set this surface satisfies as an ORIGIN
// mount (canonical sorted — §7a.1; a replica's set is stream 9's).
const sx_guarantees = ':at-least-once :gapless :linearizable-ref :monotonic-reads :prefix-consistent :read-your-writes'

// sx_head_set_locked renders the mount's HEAD-SET map (§5.1) — one entry per
// lineage stream, bound to the boot token. Caller holds the op lock. ALSO
// the anchor the feed-sub reply carries (one implementation, two consumers).
fn sx_head_set_locked(mut guard MemStore) string {
	mut keys := guard.adv_pos.keys()
	keys.sort()
	mut hs := '[head-set boot="${guard.feed_boot}"'
	for k in keys {
		pos := guard.adv_pos[k] or { continue }
		if k == 'docs' {
			hs += ' [s plane="docs" pos=${pos}]'
		} else {
			plane := k.all_before('/')
			name := k.all_after('/')
			hs += ' [s plane="${plane}" name="${sw_msg_esc(name)}" pos=${pos}]'
		}
	}
	return hs + ']'
}

// sx_advert_generation reads the daemon's live config generation (0 =
// startup config / no hot-config box in this context).
fn sx_advert_generation(mut srv StoreXspServer) int {
	if srv.ctx.cfgbox == unsafe { nil } {
		return 0
	}
	mut box := srv.ctx.cfgbox
	return box.generation()
}

// sx_advert_canonical builds the SIGNED bytes: the STRICT canonical text of
// the wrapper (cx_text_canonical — the same canonicalization content
// addresses use), so a verifier that rebuilds the wrapper from the advert's
// parts and canonicalizes it ($cx:canonical) reproduces the bytes exactly.
fn sx_advert_canonical(gen int, head_set string, guarantees string) ?string {
	text := '[store-advert-canonical generation=${gen} ${head_set} [guarantees "${guarantees}"]]'
	return cx.cx_text_canonical(text) or { return none }
}

// sx_send_advert_locked pushes the signed advert to one established session.
// A mount with no local lineage (remote byte-source) adverts generation +
// guarantees without a head-set (the origin owns the coordinate).
fn sx_send_advert_locked(mut srv StoreXspServer, conn_id int) {
	c := srv.conns[conn_id] or { return }
	if !c.established {
		return
	}
	local := srv.ctx.mounts[c.mount] or { return }
	mut hs := ''
	mut guard := store_for_guard(local) or { unsafe { nil } }
	if guard != unsafe { nil } {
		store_lock_enter(mut guard)
		hs = sx_head_set_locked(mut guard)
		store_lock_exit(mut guard)
	}
	gen := sx_advert_generation(mut srv)
	canonical := sx_advert_canonical(gen, hs, sx_guarantees) or { return }
	sig := jrn_sign(canonical, srv.cfg.identity_seed) or { return }
	mut advert := '[store-advert generation=${gen}'
	if hs != '' {
		advert += ' ${hs}'
	}
	advert += ' [guarantees "${sx_guarantees}"] signer="${srv.cfg.identity_did}" sig-algo=":ed25519" sig="${sig}"]'
	sx_event_locked(mut srv, conn_id, 0, advert, false)
}

// sx_readvertise_locked — the F3 sweep: when the config generation moved
// (any listener's applied reload), push a fresh advert to EVERY established
// session. Idempotent per generation (last_gen gates).
fn sx_readvertise_locked(mut srv StoreXspServer) {
	gen := sx_advert_generation(mut srv)
	if gen == srv.last_gen {
		return
	}
	srv.last_gen = gen
	for id, c in srv.conns {
		if c.established {
			sx_send_advert_locked(mut srv, id)
		}
	}
}
