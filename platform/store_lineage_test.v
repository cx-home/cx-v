module platform

import code {
	caps_set_all,
}

import cx
import os
import sync

// store_lineage_test.v — durable feed lineage across daemon restarts
// (#764, RULED: FL-1; xsp_store_profile.md §5.1/§5.2).
//
// BEHAVIORAL proof of the restart-resume contract, driven through the real
// open path and the real `feed` verb entry (sx_feed_start_locked — the same
// function the XSP dispatch calls), with a "daemon restart" simulated the
// only honest way: store-close, then a fresh open of the same root from
// disk, with a fresh server over the fresh mount.
//
//   1. positions + the epoch token survive restart; a prior-boot cursor
//      RESUMES exactly (the missed acts and nothing else — no duplicates,
//      no losses), including acts appended AFTER the restart;
//   2. the narrowed CXER5020: a wrong-epoch cursor, a below-retention-floor
//      cursor (post-compaction), and an above-head cursor all refuse typed;
//   3. an upgraded / pre-lineage store (no sidecar) keeps today's behavior:
//      seed-from-snapshot under a FRESH epoch (old cursors refuse honestly);
//   4. a torn/corrupt sidecar is never trusted: fresh epoch, reseed,
//      clean rewrite.

fn lin_call(name string, args []cx.Node) cx.Node {
	return store_stdlib_builtin_inner(name, args) or { panic('${name} returned none') }
}

fn lin_open(url string) cx.Node {
	caps_set_all()
	return store_open_impl(url, '', '', false, true, map[string]string{})
}

fn lin_handle_ms(n cx.Node) &MemStore {
	mut id := 0
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				id = cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return store_lookup(id) or { panic('handle ${id} not registered') }
}

fn lin_put(h cx.Node, text string) string {
	r := lin_call('store-put-doc-text', [h, store_str(text)])
	if r is cx.ScalarNode {
		return cx.scalar_value_str_public(r.value)
	}
	panic('put did not return a hash: ${r}')
}

fn lin_server(handle cx.Node) &StoreXspServer {
	return &StoreXspServer{
		mu:  sync.new_mutex()
		cfg: XspConfig{}
		ctx: ServeContext{
			mounts: {
				'main': handle
			}
		}
	}
}

fn lin_conn(mut srv StoreXspServer) int {
	srv.next_conn++
	id := srv.next_conn
	srv.conns[id] = &SxConn{
		id:                 id
		out:                chan []u8{cap: 1024}
		open:               true
		established:        true
		mount:              'main'
		confirmed_features: 'store-feed store-delta'
	}
	return id
}

// lin_sub drives the REAL feed verb entry with a parsed request and returns
// everything the server framed onto the connection, frames joined by a
// marker (payload text is embedded verbatim in the frame bytes).
fn lin_sub(mut srv StoreXspServer, conn_id int, stream i64, req_text string) string {
	doc := cx.parse(req_text) or { panic('req parse: ${err.msg()}') }
	req := doc.elements[0] as cx.Element
	mut c := srv.conns[conn_id] or { panic('conn ${conn_id} missing') }
	local := srv.ctx.mounts['main'] or { panic('mount missing') }
	sx_feed_start_locked(mut srv, mut c, stream, req, local)
	return lin_drain(c)
}

fn lin_drain(c &SxConn) string {
	mut outp := ''
	for {
		mut b := []u8{}
		if c.out.try_pop(mut b) != .success {
			break
		}
		outp += b.bytestr() + '\n<<FR>>\n'
	}
	return outp
}

fn lin_count(haystack string, needle string) int {
	mut n := 0
	mut at := 0
	for {
		i := haystack.index_after(needle, at) or { break }
		n++
		at = i + needle.len
	}
	return n
}

// ── 1. restart resume: positions + epoch survive; the cursor resumes ─────

fn test_lineage_restart_resume_pack_substrate() {
	dir := os.join_path(os.temp_dir(), 'cx_lineage_resume_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}

	// boot 1: two docs, one alias.
	h1 := lin_open('file://${dir}')
	hash1 := lin_put(h1, '[doc n=1]')
	hash2 := lin_put(h1, '[doc n=2]')
	lin_call('store-set-alias', [h1, store_str('tag'), store_str(hash1)])
	ms1 := lin_handle_ms(h1)
	boot1 := ms1.feed_boot
	assert boot1 != '', 'epoch token minted at first open'
	assert ms1.lineage_active, 'durable lineage active on the pack substrate'
	assert (ms1.adv_pos['docs'] or { i64(0) }) == 2, 'docs head after two puts'
	assert (ms1.adv_pos['aliases/tag'] or { i64(0) }) == 1, 'alias stream head'
	sidecar := os.join_path(dir, store_lineage_name)
	assert os.exists(sidecar), 'sidecar written at first open'

	// the subscriber's cursor: it has consumed docs pos=1 (hash1) and
	// nothing on the alias stream — captured, then the daemon "restarts".
	lin_call('store-close', [h1])

	// boot 2: reopen from disk.
	h2 := lin_open('file://${dir}')
	ms2 := lin_handle_ms(h2)
	assert ms2.feed_boot == boot1, 'epoch token survives restart (was per-boot before FL-1)'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'docs positions survive restart'
	assert (ms2.adv_pos['aliases/tag'] or { i64(0) }) == 1, 'alias positions survive restart'
	// positions stay monotonic across the boundary: a post-restart put
	// continues the same stream.
	hash3 := lin_put(h2, '[doc n=3]')
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'post-restart put continues the docs stream'

	// resume with the PRIOR-BOOT cursor: no CXER5020; delivery continues
	// from strictly above pos=1 — hash2 (missed pre-restart) then hash3
	// (post-restart), never hash1 again (no duplicates), nothing lost.
	mut srv := lin_server(h2)
	cid := lin_conn(mut srv)
	out := lin_sub(mut srv, cid, 10, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
	assert !out.contains('CXER5020'), 'prior-boot cursor RESUMES: ${out}'
	assert out.contains('[feed-sub'), 'subscription established: ${out}'
	assert out.contains('boot="${boot1}"'), 'head-set anchored to the durable epoch: ${out}'
	assert out.contains('[insert plane="docs" pos=2 hash="${hash2}"'), 'missed act replays: ${out}'
	assert out.contains('[insert plane="docs" pos=3 hash="${hash3}"'), 'post-restart act delivers: ${out}'
	assert !out.contains('[insert plane="docs" pos=1'), 'consumed act is NOT redelivered: ${out}'
	assert !out.contains('[insert plane="docs" pos=1 hash="${hash1}"'), 'hash1 insert stays consumed: ${out}'
	assert lin_count(out, '[insert plane="docs"') == 2, 'exactly the two acts above the cursor: ${out}'
	i2 := out.index('[insert plane="docs" pos=2') or { panic('insert pos=2 missing') }
	i3 := out.index('[insert plane="docs" pos=3') or { panic('insert pos=3 missing') }
	assert i2 < i3, 'per-stream position order IS delivery order'
	// a stream absent from the cursor map replays from its beginning (§5.2)
	assert out.contains('[advance plane="aliases" name="tag" pos=1'), 'absent stream replays from start: ${out}'

	// wrong epoch → the typed refusal (re-seed), never silent divergence.
	cid2 := lin_conn(mut srv)
	bad := lin_sub(mut srv, cid2, 11, '[feed [from boot="not-this-epoch" [s plane="docs" pos=1]]]')
	assert bad.contains('CXER5020'), 'wrong-epoch cursor refuses typed: ${bad}'

	// above-head → typed refusal (a position this lineage never issued).
	cid3 := lin_conn(mut srv)
	ahead := lin_sub(mut srv, cid3, 12, '[feed [from boot="${boot1}" [s plane="docs" pos=99]]]')
	assert ahead.contains('CXER5020'), 'above-head cursor refuses typed: ${ahead}'

	lin_call('store-close', [h2])
}

// ── 2. bounded retention: below-floor refuses; floors survive restart ────

fn test_lineage_retention_floor_refuses_below() {
	dir := os.join_path(os.temp_dir(), 'cx_lineage_floor_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}

	h1 := lin_open('file://${dir}')
	hash_a := lin_put(h1, '[doc keep="no"]')
	hash_b := lin_put(h1, '[doc keep="yes"]')
	lin_call('store-delete-doc', [h1, store_str(hash_a)])
	mut ms1 := lin_handle_ms(h1)
	assert (ms1.adv_pos['docs'] or { i64(0) }) == 3, 'insert, insert, retract'
	// compact the retention (the append path fires this on the redundancy
	// heuristic; the rule is the same either way): the retracted doc's
	// history compacts away, the floor rises to its highest dropped pos.
	store_lock_enter(mut ms1)
	store_lineage_compact(mut ms1)
	store_lock_exit(mut ms1)
	assert (ms1.adv_floor['docs'] or { i64(0) }) == 3, 'floor = highest compacted-away position'
	boot1 := ms1.feed_boot

	mut srv := lin_server(h1)
	cid := lin_conn(mut srv)
	below := lin_sub(mut srv, cid, 20, '[feed [from boot="${boot1}" [s plane="docs" pos=2]]]')
	assert below.contains('CXER5020'), 'below-floor cursor refuses typed: ${below}'
	cid2 := lin_conn(mut srv)
	at := lin_sub(mut srv, cid2, 21, '[feed [from boot="${boot1}" [s plane="docs" pos=3]]]')
	assert !at.contains('CXER5020'), 'at-floor cursor (the head) resumes: ${at}'
	assert at.contains('[feed-sub'), 'subscription established: ${at}'

	// floors + the sparse retained story survive restart.
	lin_call('store-close', [h1])
	h2 := lin_open('file://${dir}')
	ms2 := lin_handle_ms(h2)
	assert ms2.feed_boot == boot1, 'epoch survives the compacted restart'
	assert (ms2.adv_floor['docs'] or { i64(0) }) == 3, 'retention floor survives restart'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'head survives restart'
	mut srv2 := lin_server(h2)
	cid3 := lin_conn(mut srv2)
	full := lin_sub(mut srv2, cid3, 22, '[feed [from]]')
	// the from-empty full replay is the state-compacted story: the live doc
	// at its ORIGINAL position, the dropped history gone.
	assert full.contains('[insert plane="docs" pos=2 hash="${hash_b}"'), 'retained act at its original position: ${full}'
	assert !full.contains('hash="${hash_a}"'), 'compacted-away history is gone: ${full}'
	cid4 := lin_conn(mut srv2)
	below2 := lin_sub(mut srv2, cid4, 23, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
	assert below2.contains('CXER5020'), 'below-floor refusal survives restart: ${below2}'
	lin_call('store-close', [h2])
}

// ── 3. upgraded / pre-lineage store: first-boot seed, fresh epoch ─────────

fn test_lineage_first_boot_of_pre_lineage_store_seeds() {
	dir := os.join_path(os.temp_dir(), 'cx_lineage_upgrade_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}

	h1 := lin_open('file://${dir}')
	hash1 := lin_put(h1, '[doc pre="lineage"]')
	ms1 := lin_handle_ms(h1)
	boot1 := ms1.feed_boot
	lin_call('store-close', [h1])

	// simulate the pre-FL-1 store: state on disk, no sidecar.
	sidecar := os.join_path(dir, store_lineage_name)
	os.rm(sidecar) or { panic('sidecar missing before rm') }

	h2 := lin_open('file://${dir}')
	ms2 := lin_handle_ms(h2)
	assert ms2.feed_boot != '', 'fresh epoch minted'
	assert ms2.feed_boot != boot1, 'a store with no persisted lineage seeds under a FRESH epoch'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 1, 'seeded compacted-from-snapshot'
	assert os.exists(sidecar), 'the initial sidecar is written by the seed path'
	// and the old epoch's cursor refuses honestly (today's exact behavior).
	mut srv := lin_server(h2)
	cid := lin_conn(mut srv)
	old := lin_sub(mut srv, cid, 30, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
	assert old.contains('CXER5020'), 'pre-lineage-epoch cursor refuses typed: ${old}'
	// the from-empty replay tells the seeded story.
	cid2 := lin_conn(mut srv)
	full := lin_sub(mut srv, cid2, 31, '[feed [from]]')
	assert full.contains('hash="${hash1}"'), 'seeded story replays: ${full}'
	lin_call('store-close', [h2])
}

// ── 4. a torn sidecar is never trusted ────────────────────────────────────

fn test_lineage_torn_sidecar_reseeds_fresh_epoch() {
	dir := os.join_path(os.temp_dir(), 'cx_lineage_torn_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}

	h1 := lin_open('file://${dir}')
	lin_put(h1, '[doc a=1]')
	lin_put(h1, '[doc b=2]')
	ms1 := lin_handle_ms(h1)
	boot1 := ms1.feed_boot
	lin_call('store-close', [h1])

	// tear the sidecar (a crash mid-append): an unparseable tail record.
	sidecar := os.join_path(dir, store_lineage_name)
	mut f := os.open_append(sidecar) or { panic('append: ${err.msg()}') }
	f.write_string('V\tdocs\tinsert\t7\t') or { panic('tear write') }
	f.close()

	h2 := lin_open('file://${dir}')
	ms2 := lin_handle_ms(h2)
	assert ms2.feed_boot != boot1, 'a torn sidecar is discarded: fresh epoch, reseed'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'reseeded from the snapshot'
	// the rewritten sidecar is clean again: close + reopen resumes durably.
	boot2 := ms2.feed_boot
	lin_call('store-close', [h2])
	h3 := lin_open('file://${dir}')
	ms3 := lin_handle_ms(h3)
	assert ms3.feed_boot == boot2, 'the reseeded lineage is durable again'
	lin_call('store-close', [h3])
}

// ── 5. the document (flat-index) substrate rides the same contract ───────

fn test_lineage_document_model_survives_restart() {
	dir := os.join_path(os.temp_dir(), 'cx_lineage_doc_${os.getpid()}')
	os.rmdir_all(dir) or {}
	defer {
		os.rmdir_all(dir) or {}
	}

	h1 := lin_open('document+file://${dir}')
	lin_put(h1, '[doc flat=1]')
	ms1 := lin_handle_ms(h1)
	assert ms1.backend == 'file', 'document model on the flat index'
	assert ms1.lineage_active, 'durable lineage active on the document substrate'
	boot1 := ms1.feed_boot
	lin_call('store-close', [h1])
	h2 := lin_open('document+file://${dir}')
	ms2 := lin_handle_ms(h2)
	assert ms2.feed_boot == boot1, 'document-model epoch survives restart'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 1, 'document-model positions survive restart'
	lin_call('store-close', [h2])
}

// ── 6. mem:// keeps the process-lifetime story (nothing durable exists) ──

fn test_lineage_mem_backend_stays_process_lifetime() {
	h := lin_open('mem://lineage-mem')
	ms := lin_handle_ms(h)
	assert ms.feed_boot != '', 'volatile epoch minted'
	assert !ms.lineage_active, 'mem:// has no durable substrate — no sidecar'
	assert ms.lineage_path == '', 'no sidecar path for mem://'
	lin_call('store-close', [h])
}
