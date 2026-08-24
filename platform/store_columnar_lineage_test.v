module platform

import code {
	caps_set_all,
}

import cx
import os
import sync

// store_columnar_lineage_test.v — durable feed lineage on the COLUMNAR
// substrate (#887, RULED: FL-3; the columnar completion of FL-1/#764 and
// FL-2/#885).
//
// FL-1 gave every local durable substrate a lineage sidecar; FL-2 gave
// s3-ROOTED subtree stores per-segment bucket lineage. The columnar backend
// was neither: `store_columnar_open_s3` builds a store with backend
// 'columnar', root '', and the WHOLE store as one Parquet/Arrow object behind
// an injected S3Transport, so no arm fired and every boot reseeded under a
// fresh epoch. FL-3 mounts it on the FL-2 object medium — lineage keys are
// siblings of the columnar object (`<key>.cxstore-lineage/…`), exactly as its
// alias sidecar is `<key>.cxstore-aliases`.
//
// This is the FL-2 restart-resume proof mirrored at the columnar seam, driven
// through the real load path (store_columnar_load), the real registration
// (store_register → store_feed_open → store_s3_lineage_open), the real verb
// builtins, and the real `feed` verb entry (sx_feed_start_locked) —
// HERMETICALLY over the same in-memory transport seam the §6 columnar
// conformance test uses (never a live bucket). A "daemon restart" is
// simulated the only honest way: store-close, then a fresh MemStore + load +
// register over the SAME bucket contents.
//
//   1. positions + the epoch token survive restart as bucket objects; a
//      prior-boot cursor RESUMES exactly (no CXER5020, no duplicates, no
//      losses); wrong-epoch and above-head refuse typed;
//   2. two columnar stores in ONE bucket keep independent lineages (the
//      mount hangs off the object key, not the bucket root);
//   3. compaction bumps the generation, raises the retention floor, purges
//      the old generation; below-floor refuses and the floor survives
//      restart;
//   4. a pre-FL-3 columnar object (state, no lineage keys) seeds FRESH;
//   5. torn lineage is never trusted: discard, fresh epoch, reseed — and the
//      reseeded lineage is durable again;
//   6. a columnar store over a LOCAL root resumes through the FL-1 sidecar
//      (`<path>.cxstore-lineage`) — listed by FL-1 but never gated until now,
//      because the columnar pack is compile-gated and no lineage test ran in
//      that lane.
//
// The whole file is `-d cxstore_columnar` (+ `-d cx_arrow_files`) gated, like
// store_columnar_test.v: without the flags there is no columnar substrate to
// prove anything about. `make test-vcx-columnar` runs it.

// ColLinStub — the in-memory S3 transport (PUT/GET/HEAD over a map; LIST =
// keys; DELETE = map delete). One stub shared by several MemStores models
// reopens against the same bucket.
@[heap]
struct ColLinStub {
mut:
	blobs map[string][]u8
}

fn (t &ColLinStub) fetch(method string, key string) (int, []u8, bool) {
	match method {
		'HEAD' {
			return if key in t.blobs { 200 } else { 404 }, []u8{}, true
		}
		'GET' {
			if v := t.blobs[key] {
				return 200, v, true
			}
			return 404, []u8{}, true
		}
		else {
			return 400, []u8{}, true
		}
	}
}

fn (mut t ColLinStub) store(key string, body []u8) (int, bool) {
	t.blobs[key] = body.clone()
	return 200, true
}

fn (mut t ColLinStub) remove(key string) (int, bool) {
	t.blobs.delete(key)
	return 204, true
}

fn (t &ColLinStub) keys() []string {
	return t.blobs.keys()
}

fn cls_call(name string, args []cx.Node) cx.Node {
	return store_stdlib_builtin_inner(name, args) or { panic('${name} returned none') }
}

// cls_open_s3 is the real columnar-over-s3 open from the transport seam
// onward: build the MemStore exactly as store_columnar_open_s3 does, read the
// single columnar object (store_columnar_load), then register — which runs
// store_feed_open and the FL-3 bucket-lineage load-else-seed.
fn cls_open_s3(t &ColLinStub, key string) cx.Node {
	$if cxstore_columnar ? {
		caps_set_all()
		mut ms := &MemStore{
			url:             'document+s3://bucket/${key}'
			backend:         'columnar'
			model:           'document'
			encoding:        'parquet'
			compression:     'zstd'
			is_open:         true
			op_lock:         sync.new_mutex()
			columnar_s3:     S3Transport(t)
			columnar_s3_key: key
		}
		store_columnar_load(mut ms) or { panic('columnar s3 load: ${err.msg()}') }
		id := store_register(ms)
		return store_handle_element(id, ms)
	}
	return store_null()
}

// cls_open_file is the real columnar-over-a-local-root open (the FL-1 sidecar
// medium): the same store_columnar_open the `document+file://…?encoding=
// parquet` dispatch calls.
fn cls_open_file(path string) cx.Node {
	$if cxstore_columnar ? {
		caps_set_all()
		return store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
	}
	return store_null()
}

fn cls_ms(n cx.Node) &MemStore {
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

fn cls_put(h cx.Node, text string) string {
	r := cls_call('store-put-doc-text', [h, store_str(text)])
	if r is cx.ScalarNode {
		return cx.scalar_value_str_public(r.value)
	}
	panic('put did not return a hash: ${r}')
}

fn cls_server(handle cx.Node) &StoreXspServer {
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

fn cls_conn(mut srv StoreXspServer) int {
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

// cls_sub drives the REAL feed verb entry and returns everything the server
// framed onto the connection.
fn cls_sub(mut srv StoreXspServer, conn_id int, stream i64, req_text string) string {
	doc := cx.parse(req_text) or { panic('req parse: ${err.msg()}') }
	req := doc.elements[0] as cx.Element
	mut c := srv.conns[conn_id] or { panic('conn ${conn_id} missing') }
	local := srv.ctx.mounts['main'] or { panic('mount missing') }
	sx_feed_start_locked(mut srv, mut c, stream, req, local)
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

// cls_prefix — the columnar mount's lineage key prefix: siblings of the
// columnar OBJECT, never of the bucket root.
fn cls_prefix(key string) string {
	return key + s3_lineage_prefix
}

fn cls_lineage_keys(t &ColLinStub, prefix string) []string {
	mut out := []string{}
	for k in t.blobs.keys() {
		if k.starts_with(prefix) {
			out << k
		}
	}
	out.sort()
	return out
}

fn cls_count(haystack string, needle string) int {
	mut n := 0
	mut at := 0
	for {
		i := haystack.index_after(needle, at) or { break }
		n++
		at = i + needle.len
	}
	return n
}

// ── 1. restart resume over the columnar s3 mount ──────────────────────────

fn test_columnar_s3_lineage_restart_resume() {
	$if cxstore_columnar ? {
		mut stub := &ColLinStub{}
		pfx := cls_prefix('events.parquet')

		// boot 1: two docs, one alias.
		h1 := cls_open_s3(stub, 'events.parquet')
		hash1 := cls_put(h1, '[event n=1]')
		hash2 := cls_put(h1, '[event n=2]')
		cls_call('store-set-alias', [h1, store_str('tag'), store_str(hash1)])
		ms1 := cls_ms(h1)
		boot1 := ms1.feed_boot
		assert boot1 != '', 'epoch token minted at first open'
		assert ms1.lineage_active, 'durable lineage active on the columnar substrate (was process-lifetime before FL-3)'
		assert ms1.lineage_gen == 1, 'first boot writes generation 1'
		assert (ms1.adv_pos['docs'] or { i64(0) }) == 2, 'docs head after two puts'
		assert (ms1.adv_pos['aliases/tag'] or { i64(0) }) == 1, 'alias stream head'
		lk := cls_lineage_keys(stub, pfx)
		assert s3_lineage_full_key(pfx, 1) in lk, 'generation-1 full object written at first open: ${lk}'
		assert s3_lineage_seg_key(pfx, 1, 1) in lk && s3_lineage_seg_key(pfx, 1, 2) in lk
			&& s3_lineage_seg_key(pfx, 1, 3) in lk, 'one segment object per live act: ${lk}'
		// the mount hangs off the columnar OBJECT, not the bucket root (a
		// bucket-root lineage would collide with any other store there).
		assert s3_lineage_full_key(s3_lineage_prefix, 1) !in stub.blobs, 'columnar lineage must not land at the bucket root'
		assert 'events.parquet' in stub.blobs, 'the columnar object itself still written'

		// the subscriber has consumed docs pos=1 (hash1); the daemon restarts.
		cls_call('store-close', [h1])

		// boot 2: a fresh MemStore over the same bucket contents.
		h2 := cls_open_s3(stub, 'events.parquet')
		ms2 := cls_ms(h2)
		assert ms2.feed_boot == boot1, 'epoch token survives restart (was seed-per-boot before FL-3)'
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'docs positions survive restart'
		assert (ms2.adv_pos['aliases/tag'] or { i64(0) }) == 1, 'alias positions survive restart'
		hash3 := cls_put(h2, '[event n=3]')
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'post-restart put continues the docs stream'
		assert s3_lineage_seg_key(pfx, 1, 4) in cls_lineage_keys(stub, pfx), 'post-restart act appends the next segment'

		// resume with the PRIOR-BOOT cursor: no CXER5020; delivery continues
		// strictly above pos=1 — hash2 (missed pre-restart) then hash3
		// (post-restart), never hash1 again, nothing lost.
		mut srv := cls_server(h2)
		cid := cls_conn(mut srv)
		out := cls_sub(mut srv, cid, 10, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
		assert !out.contains('CXER5020'), 'prior-boot cursor RESUMES: ${out}'
		assert out.contains('[feed-sub'), 'subscription established: ${out}'
		assert out.contains('boot="${boot1}"'), 'head-set anchored to the durable epoch: ${out}'
		assert out.contains('[insert plane="docs" pos=2 hash="${hash2}"'), 'missed act replays: ${out}'
		assert out.contains('[insert plane="docs" pos=3 hash="${hash3}"'), 'post-restart act delivers: ${out}'
		assert !out.contains('[insert plane="docs" pos=1'), 'consumed act is NOT redelivered: ${out}'
		assert cls_count(out, '[insert plane="docs"') == 2, 'exactly the two acts above the cursor: ${out}'
		i2 := out.index('[insert plane="docs" pos=2') or { panic('insert pos=2 missing') }
		i3 := out.index('[insert plane="docs" pos=3') or { panic('insert pos=3 missing') }
		assert i2 < i3, 'per-stream position order IS delivery order'
		assert out.contains('[advance plane="aliases" name="tag" pos=1'), 'absent stream replays from start: ${out}'

		// wrong epoch → the typed refusal (re-seed), never silent divergence.
		cid2 := cls_conn(mut srv)
		bad := cls_sub(mut srv, cid2, 11, '[feed [from boot="not-this-epoch" [s plane="docs" pos=1]]]')
		assert bad.contains('CXER5020'), 'wrong-epoch cursor refuses typed: ${bad}'

		// above-head → typed refusal (a position this lineage never issued).
		cid3 := cls_conn(mut srv)
		ahead := cls_sub(mut srv, cid3, 12, '[feed [from boot="${boot1}" [s plane="docs" pos=99]]]')
		assert ahead.contains('CXER5020'), 'above-head cursor refuses typed: ${ahead}'

		cls_call('store-close', [h2])
	}
}

// ── 2. two columnar stores in ONE bucket keep independent lineages ────────

fn test_columnar_s3_lineage_two_stores_one_bucket_are_independent() {
	$if cxstore_columnar ? {
		mut stub := &ColLinStub{}
		ha := cls_open_s3(stub, 'a.parquet')
		hb := cls_open_s3(stub, 'b.parquet')
		cls_put(ha, '[a n=1]')
		cls_put(ha, '[a n=2]')
		cls_put(hb, '[b n=1]')
		msa := cls_ms(ha)
		msb := cls_ms(hb)
		boot_a := msa.feed_boot
		boot_b := msb.feed_boot
		assert boot_a != boot_b, 'two stores in one bucket mint distinct epochs'
		assert (msa.adv_pos['docs'] or { i64(0) }) == 2, 'store a head'
		assert (msb.adv_pos['docs'] or { i64(0) }) == 1, 'store b head — never sees a-s acts'
		assert cls_lineage_keys(stub, cls_prefix('a.parquet')).len == 3, 'a: full + 2 segments'
		assert cls_lineage_keys(stub, cls_prefix('b.parquet')).len == 2, 'b: full + 1 segment'
		cls_call('store-close', [ha])
		cls_call('store-close', [hb])

		// both resume independently across the restart.
		ha2 := cls_open_s3(stub, 'a.parquet')
		hb2 := cls_open_s3(stub, 'b.parquet')
		assert cls_ms(ha2).feed_boot == boot_a, 'store a resumes its own epoch'
		assert cls_ms(hb2).feed_boot == boot_b, 'store b resumes its own epoch'
		assert (cls_ms(ha2).adv_pos['docs'] or { i64(0) }) == 2, 'store a positions survive'
		assert (cls_ms(hb2).adv_pos['docs'] or { i64(0) }) == 1, 'store b positions survive'
		cls_call('store-close', [ha2])
		cls_call('store-close', [hb2])
	}
}

// ── 3. compaction: generation guard, floor rises, below-floor refuses ─────

fn test_columnar_s3_lineage_compaction_generation_and_floor() {
	$if cxstore_columnar ? {
		mut stub := &ColLinStub{}
		pfx := cls_prefix('c.parquet')
		h1 := cls_open_s3(stub, 'c.parquet')
		hash_a := cls_put(h1, '[c keep="no"]')
		hash_b := cls_put(h1, '[c keep="yes"]')
		cls_call('store-delete-doc', [h1, store_str(hash_a)])
		mut ms1 := cls_ms(h1)
		assert (ms1.adv_pos['docs'] or { i64(0) }) == 3, 'insert, insert, retract'
		assert ms1.lineage_gen == 1, 'still generation 1 before compaction'
		store_lock_enter(mut ms1)
		store_lineage_compact(mut ms1)
		store_lock_exit(mut ms1)
		assert (ms1.adv_floor['docs'] or { i64(0) }) == 3, 'floor = highest compacted-away position'
		assert ms1.lineage_gen == 2, 'compaction writes the NEXT generation (the guard)'
		lk := cls_lineage_keys(stub, pfx)
		assert s3_lineage_full_key(pfx, 2) in lk, 'generation-2 full object is the new base: ${lk}'
		assert s3_lineage_full_key(pfx, 1) !in lk, 'generation-1 base purged after the new base landed: ${lk}'
		assert s3_lineage_seg_key(pfx, 1, 1) !in lk && s3_lineage_seg_key(pfx, 1, 2) !in lk
			&& s3_lineage_seg_key(pfx, 1, 3) !in lk, 'generation-1 segments purged: ${lk}'
		boot1 := ms1.feed_boot

		mut srv := cls_server(h1)
		cid := cls_conn(mut srv)
		below := cls_sub(mut srv, cid, 20, '[feed [from boot="${boot1}" [s plane="docs" pos=2]]]')
		assert below.contains('CXER5020'), 'below-floor cursor refuses typed: ${below}'
		cid2 := cls_conn(mut srv)
		at := cls_sub(mut srv, cid2, 21, '[feed [from boot="${boot1}" [s plane="docs" pos=3]]]')
		assert !at.contains('CXER5020'), 'at-floor cursor (the head) resumes: ${at}'

		// floors + the sparse retained story survive restart.
		cls_call('store-close', [h1])
		h2 := cls_open_s3(stub, 'c.parquet')
		ms2 := cls_ms(h2)
		assert ms2.feed_boot == boot1, 'epoch survives the compacted restart'
		assert ms2.lineage_gen == 2, 'boot trusts the highest generation with a full object'
		assert (ms2.adv_floor['docs'] or { i64(0) }) == 3, 'retention floor survives restart'
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'head survives restart'
		mut srv2 := cls_server(h2)
		cid3 := cls_conn(mut srv2)
		full := cls_sub(mut srv2, cid3, 22, '[feed [from]]')
		assert full.contains('[insert plane="docs" pos=2 hash="${hash_b}"'), 'retained act at its original position: ${full}'
		assert !full.contains('hash="${hash_a}"'), 'compacted-away history is gone: ${full}'
		cid4 := cls_conn(mut srv2)
		below2 := cls_sub(mut srv2, cid4, 23, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
		assert below2.contains('CXER5020'), 'below-floor refusal survives restart: ${below2}'
		cls_call('store-close', [h2])
	}
}

// ── 4. a pre-FL-3 columnar object seeds FRESH ─────────────────────────────

fn test_columnar_s3_lineage_pre_fl3_object_seeds_fresh() {
	$if cxstore_columnar ? {
		mut stub := &ColLinStub{}
		pfx := cls_prefix('pre.parquet')
		h1 := cls_open_s3(stub, 'pre.parquet')
		hash1 := cls_put(h1, '[pre n=1]')
		ms1 := cls_ms(h1)
		boot1 := ms1.feed_boot
		cls_call('store-close', [h1])

		// the pre-FL-3 shape: the columnar object + its alias sidecar, no
		// lineage keys at all (what every columnar store on disk looks like
		// today).
		for k in cls_lineage_keys(stub, pfx) {
			stub.blobs.delete(k)
		}

		h2 := cls_open_s3(stub, 'pre.parquet')
		ms2 := cls_ms(h2)
		assert ms2.feed_boot != '', 'fresh epoch minted'
		assert ms2.feed_boot != boot1, 'a columnar object with no persisted lineage seeds under a FRESH epoch'
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 1, 'seeded compacted-from-snapshot'
		assert ms2.lineage_active, 'the seed path writes the initial lineage'
		assert cls_lineage_keys(stub, pfx).len > 0, 'initial full object written by the seed path'
		mut srv := cls_server(h2)
		cid := cls_conn(mut srv)
		old := cls_sub(mut srv, cid, 30, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
		assert old.contains('CXER5020'), 'pre-lineage-epoch cursor refuses typed: ${old}'
		cid2 := cls_conn(mut srv)
		full := cls_sub(mut srv, cid2, 31, '[feed [from]]')
		assert full.contains('hash="${hash1}"'), 'seeded story replays: ${full}'
		cls_call('store-close', [h2])
	}
}

// ── 5. torn lineage is never trusted: discard, fresh epoch, durable again ─

fn test_columnar_s3_lineage_torn_reseeds_fresh_epoch() {
	$if cxstore_columnar ? {
		mut stub := &ColLinStub{}
		pfx := cls_prefix('torn.parquet')
		h1 := cls_open_s3(stub, 'torn.parquet')
		cls_put(h1, '[t a=1]')
		cls_put(h1, '[t b=2]')
		ms1 := cls_ms(h1)
		boot1 := ms1.feed_boot
		cls_call('store-close', [h1])

		// tear the lineage: replace the last segment with a truncated record.
		stub.blobs[s3_lineage_seg_key(pfx, 1, 2)] = 'V\tdocs\tinsert\t7\t'.bytes()

		h2 := cls_open_s3(stub, 'torn.parquet')
		ms2 := cls_ms(h2)
		assert ms2.feed_boot != boot1, 'torn lineage is discarded: fresh epoch, reseed'
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'reseeded from the columnar snapshot'
		assert ms2.lineage_gen == 2, 'the reseed lands under a NEW generation'
		lk := cls_lineage_keys(stub, pfx)
		assert s3_lineage_full_key(pfx, 2) in lk, 'reseeded base written: ${lk}'
		assert s3_lineage_full_key(pfx, 1) !in lk, 'untrusted generation purged: ${lk}'
		boot2 := ms2.feed_boot
		cls_call('store-close', [h2])
		h3 := cls_open_s3(stub, 'torn.parquet')
		assert cls_ms(h3).feed_boot == boot2, 'the reseeded lineage is durable again'
		cls_call('store-close', [h3])
	}
}

// ── 6. a lost middle segment (density gap) is never served silently ───────

fn test_columnar_s3_lineage_missing_segment_gap_reseeds() {
	$if cxstore_columnar ? {
		mut stub := &ColLinStub{}
		pfx := cls_prefix('gap.parquet')
		h1 := cls_open_s3(stub, 'gap.parquet')
		cls_put(h1, '[g n=1]')
		cls_put(h1, '[g n=2]')
		cls_put(h1, '[g n=3]')
		boot1 := cls_ms(h1).feed_boot
		cls_call('store-close', [h1])

		stub.blobs.delete(s3_lineage_seg_key(pfx, 1, 2))

		h2 := cls_open_s3(stub, 'gap.parquet')
		ms2 := cls_ms(h2)
		assert ms2.feed_boot != boot1, 'a position gap is discarded: fresh epoch, reseed'
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'reseeded from the snapshot (all three docs)'
		cls_call('store-close', [h2])
	}
}

// ── 7. a columnar store over a LOCAL root resumes via the FL-1 sidecar ────

fn test_columnar_file_lineage_restart_resume() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_lineage_${os.getpid()}.parquet')
		os.rm(path) or {}
		os.rm(path + '.cxstore-lineage') or {}
		os.rm(path + '.cxstore-aliases') or {}
		defer {
			os.rm(path) or {}
			os.rm(path + '.cxstore-lineage') or {}
			os.rm(path + '.cxstore-aliases') or {}
		}

		h1 := cls_open_file(path)
		assert !(h1 is cx.Element && (h1 as cx.Element).name == 'err'), 'columnar file open failed: ${h1}'
		hash1 := cls_put(h1, '[f n=1]')
		hash2 := cls_put(h1, '[f n=2]')
		ms1 := cls_ms(h1)
		boot1 := ms1.feed_boot
		assert ms1.lineage_active, 'the FL-1 sidecar is active on a local columnar root'
		assert ms1.lineage_path == path + '.cxstore-lineage', 'sidecar beside the columnar file: ${ms1.lineage_path}'
		assert os.exists(ms1.lineage_path), 'sidecar written at first open'
		assert (ms1.adv_pos['docs'] or { i64(0) }) == 2, 'docs head after two puts'
		cls_call('store-close', [h1])

		h2 := cls_open_file(path)
		ms2 := cls_ms(h2)
		assert ms2.feed_boot == boot1, 'epoch token survives restart on a local columnar root'
		assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'positions survive restart'
		hash3 := cls_put(h2, '[f n=3]')

		mut srv := cls_server(h2)
		cid := cls_conn(mut srv)
		out := cls_sub(mut srv, cid, 40, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
		assert !out.contains('CXER5020'), 'prior-boot cursor RESUMES on a local columnar root: ${out}'
		assert out.contains('[insert plane="docs" pos=2 hash="${hash2}"'), 'missed act replays: ${out}'
		assert out.contains('[insert plane="docs" pos=3 hash="${hash3}"'), 'post-restart act delivers: ${out}'
		assert !out.contains('hash="${hash1}"'), 'consumed act is NOT redelivered: ${out}'
		assert cls_count(out, '[insert plane="docs"') == 2, 'exactly the two acts above the cursor: ${out}'
		cls_call('store-close', [h2])
	}
}
