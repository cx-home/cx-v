module platform

import code {
	caps_set_all,
}

import cx
import cxstore
import sync

// store_s3_lineage_test.v — durable feed lineage on s3-rooted stores
// (#885, RULED: FL-2; the s3 completion of FL-1/#764).
//
// The store_lineage_test.v restart-resume proof, mirrored against the s3
// substrate: driven through the real load path (store_s3_load), the real
// registration (store_register → store_feed_open → store_s3_lineage_open),
// the real verb builtins, and the real `feed` verb entry
// (sx_feed_start_locked), HERMETICALLY over the same in-memory S3 transport
// seam the §6 conformance test uses (no live S3/minio). A "daemon restart"
// is simulated the only honest way for a bucket: store-close, then a fresh
// MemStore + load + register over the SAME bucket contents.
//
//   1. positions + the epoch token survive restart as bucket objects; a
//      prior-boot cursor RESUMES exactly; wrong-epoch and above-head refuse;
//   2. compaction bumps the lineage GENERATION (guard: boot trusts the
//      highest generation with a full object), purges the old one, raises
//      the retention floor; below-floor refuses, floors survive restart;
//   3. a pre-FL-2 bucket (state, no lineage keys) keeps today's behavior:
//      seed-from-snapshot under a FRESH epoch, initial lineage written;
//   4. torn/inconsistent bucket lineage is never trusted: discard, fresh
//      epoch, reseed — and the reseeded lineage is durable again.

// S3LStub — the in-memory S3 transport (PUT/GET/HEAD over a map; LIST =
// keys; DELETE = map delete). One stub shared by several MemStores models
// reopens against the same bucket.
@[heap]
struct S3LStub {
mut:
	blobs map[string][]u8
}

fn (t &S3LStub) fetch(method string, key string) (int, []u8, bool) {
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

fn (mut t S3LStub) store(key string, body []u8) (int, bool) {
	t.blobs[key] = body.clone()
	return 200, true
}

fn (mut t S3LStub) remove(key string) (int, bool) {
	t.blobs.delete(key)
	return 204, true
}

fn (t &S3LStub) keys() []string {
	return t.blobs.keys()
}

fn s3l_call(name string, args []cx.Node) cx.Node {
	return store_stdlib_builtin_inner(name, args) or { panic('${name} returned none') }
}

// s3l_open is the real s3 open from the transport seam onward: build the
// MemStore exactly as store_open_impl's s3 arm does, replay the manifest
// (store_s3_load), then register — which runs store_feed_open and the FL-2
// bucket-lineage load-else-seed.
fn s3l_open(t &S3LStub) cx.Node {
	caps_set_all()
	mut ms := &MemStore{
		url:         's3://bucket/lineage'
		backend:     's3'
		encoding:    'cxbin'
		compression: 'none'
		is_open:     true
		op_lock:     sync.new_mutex()
		obj_backend: cxstore.ObjectBackend(&S3ObjectBackend{
			transport: S3Transport(t)
		})
	}
	store_s3_load(mut ms) or { panic('s3 load: ${err.msg()}') }
	id := store_register(ms)
	return store_handle_element(id, ms)
}

fn s3l_ms(n cx.Node) &MemStore {
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

fn s3l_put(h cx.Node, text string) string {
	r := s3l_call('store-put-doc-text', [h, store_str(text)])
	if r is cx.ScalarNode {
		return cx.scalar_value_str_public(r.value)
	}
	panic('put did not return a hash: ${r}')
}

fn s3l_server(handle cx.Node) &StoreXspServer {
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

fn s3l_conn(mut srv StoreXspServer) int {
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

fn s3l_sub(mut srv StoreXspServer, conn_id int, stream i64, req_text string) string {
	doc := cx.parse(req_text) or { panic('req parse: ${err.msg()}') }
	req := doc.elements[0] as cx.Element
	mut c := srv.conns[conn_id] or { panic('conn ${conn_id} missing') }
	local := srv.ctx.mounts['main'] or { panic('mount missing') }
	sx_feed_start_locked(mut srv, mut c, stream, req, local)
	return s3l_drain(c)
}

fn s3l_drain(c &SxConn) string {
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

fn s3l_lineage_keys(t &S3LStub) []string {
	mut out := []string{}
	for k in t.blobs.keys() {
		if k.contains(s3_lineage_prefix) {
			out << k
		}
	}
	out.sort()
	return out
}

fn s3l_count(haystack string, needle string) int {
	mut n := 0
	mut at := 0
	for {
		i := haystack.index_after(needle, at) or { break }
		n++
		at = i + needle.len
	}
	return n
}

// ── 1. restart resume: positions + epoch survive as bucket objects ────────

fn test_s3_lineage_restart_resume() {
	mut stub := &S3LStub{}

	// boot 1: two docs, one alias.
	h1 := s3l_open(stub)
	hash1 := s3l_put(h1, '[doc n=1]')
	hash2 := s3l_put(h1, '[doc n=2]')
	s3l_call('store-set-alias', [h1, store_str('tag'), store_str(hash1)])
	ms1 := s3l_ms(h1)
	boot1 := ms1.feed_boot
	assert boot1 != '', 'epoch token minted at first open'
	assert ms1.lineage_active, 'durable lineage active on the s3 substrate'
	assert ms1.lineage_gen == 1, 'first boot writes generation 1'
	assert (ms1.adv_pos['docs'] or { i64(0) }) == 2, 'docs head after two puts'
	assert (ms1.adv_pos['aliases/tag'] or { i64(0) }) == 1, 'alias stream head'
	lk := s3l_lineage_keys(stub)
	assert s3_lineage_full_key(s3_lineage_prefix, 1) in lk, 'generation-1 full object written at first open: ${lk}'
	assert s3_lineage_seg_key(s3_lineage_prefix, 1, 1) in lk && s3_lineage_seg_key(s3_lineage_prefix, 1, 2) in lk
		&& s3_lineage_seg_key(s3_lineage_prefix, 1, 3) in lk, 'one segment object per live act: ${lk}'

	// the subscriber's cursor: it has consumed docs pos=1 (hash1) and
	// nothing on the alias stream — captured, then the daemon "restarts".
	s3l_call('store-close', [h1])

	// boot 2: a fresh MemStore over the same bucket.
	h2 := s3l_open(stub)
	ms2 := s3l_ms(h2)
	assert ms2.feed_boot == boot1, 'epoch token survives restart (was seed-per-boot before FL-2)'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'docs positions survive restart'
	assert (ms2.adv_pos['aliases/tag'] or { i64(0) }) == 1, 'alias positions survive restart'
	// positions stay monotonic across the boundary: a post-restart put
	// continues the same stream (and appends segment seq 4 in gen 1).
	hash3 := s3l_put(h2, '[doc n=3]')
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'post-restart put continues the docs stream'
	assert s3_lineage_seg_key(s3_lineage_prefix, 1, 4) in s3l_lineage_keys(stub), 'post-restart act appends the next segment'

	// resume with the PRIOR-BOOT cursor: no CXER5020; delivery continues
	// from strictly above pos=1 — hash2 (missed pre-restart) then hash3
	// (post-restart), never hash1 again (no duplicates), nothing lost.
	mut srv := s3l_server(h2)
	cid := s3l_conn(mut srv)
	out := s3l_sub(mut srv, cid, 10, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
	assert !out.contains('CXER5020'), 'prior-boot cursor RESUMES: ${out}'
	assert out.contains('[feed-sub'), 'subscription established: ${out}'
	assert out.contains('boot="${boot1}"'), 'head-set anchored to the durable epoch: ${out}'
	assert out.contains('[insert plane="docs" pos=2 hash="${hash2}"'), 'missed act replays: ${out}'
	assert out.contains('[insert plane="docs" pos=3 hash="${hash3}"'), 'post-restart act delivers: ${out}'
	assert !out.contains('[insert plane="docs" pos=1'), 'consumed act is NOT redelivered: ${out}'
	assert s3l_count(out, '[insert plane="docs"') == 2, 'exactly the two acts above the cursor: ${out}'
	i2 := out.index('[insert plane="docs" pos=2') or { panic('insert pos=2 missing') }
	i3 := out.index('[insert plane="docs" pos=3') or { panic('insert pos=3 missing') }
	assert i2 < i3, 'per-stream position order IS delivery order'
	// a stream absent from the cursor map replays from its beginning (§5.2)
	assert out.contains('[advance plane="aliases" name="tag" pos=1'), 'absent stream replays from start: ${out}'

	// wrong epoch → the typed refusal (re-seed), never silent divergence.
	cid2 := s3l_conn(mut srv)
	bad := s3l_sub(mut srv, cid2, 11, '[feed [from boot="not-this-epoch" [s plane="docs" pos=1]]]')
	assert bad.contains('CXER5020'), 'wrong-epoch cursor refuses typed: ${bad}'

	// above-head → typed refusal (a position this lineage never issued).
	cid3 := s3l_conn(mut srv)
	ahead := s3l_sub(mut srv, cid3, 12, '[feed [from boot="${boot1}" [s plane="docs" pos=99]]]')
	assert ahead.contains('CXER5020'), 'above-head cursor refuses typed: ${ahead}'

	s3l_call('store-close', [h2])
}

// ── 2. compaction: generation guard, floor rises, old gen purged ──────────

fn test_s3_lineage_compaction_generation_and_floor() {
	mut stub := &S3LStub{}
	h1 := s3l_open(stub)
	hash_a := s3l_put(h1, '[doc keep="no"]')
	hash_b := s3l_put(h1, '[doc keep="yes"]')
	s3l_call('store-delete-doc', [h1, store_str(hash_a)])
	mut ms1 := s3l_ms(h1)
	assert (ms1.adv_pos['docs'] or { i64(0) }) == 3, 'insert, insert, retract'
	assert ms1.lineage_gen == 1, 'still generation 1 before compaction'
	// compact the retention (the append path fires this on the redundancy
	// heuristic; the rule is the same either way): the retracted doc's
	// history compacts away, the floor rises, the GENERATION bumps.
	store_lock_enter(mut ms1)
	store_lineage_compact(mut ms1)
	store_lock_exit(mut ms1)
	assert (ms1.adv_floor['docs'] or { i64(0) }) == 3, 'floor = highest compacted-away position'
	assert ms1.lineage_gen == 2, 'compaction writes the NEXT generation (the guard)'
	lk := s3l_lineage_keys(stub)
	assert s3_lineage_full_key(s3_lineage_prefix, 2) in lk, 'generation-2 full object is the new base: ${lk}'
	assert s3_lineage_full_key(s3_lineage_prefix, 1) !in lk, 'generation-1 base purged after the new base landed: ${lk}'
	assert s3_lineage_seg_key(s3_lineage_prefix, 1, 1) !in lk && s3_lineage_seg_key(s3_lineage_prefix, 1, 2) !in lk
		&& s3_lineage_seg_key(s3_lineage_prefix, 1, 3) !in lk, 'generation-1 segments purged: ${lk}'
	boot1 := ms1.feed_boot

	mut srv := s3l_server(h1)
	cid := s3l_conn(mut srv)
	below := s3l_sub(mut srv, cid, 20, '[feed [from boot="${boot1}" [s plane="docs" pos=2]]]')
	assert below.contains('CXER5020'), 'below-floor cursor refuses typed: ${below}'
	cid2 := s3l_conn(mut srv)
	at := s3l_sub(mut srv, cid2, 21, '[feed [from boot="${boot1}" [s plane="docs" pos=3]]]')
	assert !at.contains('CXER5020'), 'at-floor cursor (the head) resumes: ${at}'
	assert at.contains('[feed-sub'), 'subscription established: ${at}'

	// floors + the sparse retained story survive restart.
	s3l_call('store-close', [h1])
	h2 := s3l_open(stub)
	ms2 := s3l_ms(h2)
	assert ms2.feed_boot == boot1, 'epoch survives the compacted restart'
	assert ms2.lineage_gen == 2, 'boot trusts the highest generation with a full object'
	assert (ms2.adv_floor['docs'] or { i64(0) }) == 3, 'retention floor survives restart'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'head survives restart'
	mut srv2 := s3l_server(h2)
	cid3 := s3l_conn(mut srv2)
	full := s3l_sub(mut srv2, cid3, 22, '[feed [from]]')
	// the from-empty full replay is the state-compacted story: the live doc
	// at its ORIGINAL position, the dropped history gone.
	assert full.contains('[insert plane="docs" pos=2 hash="${hash_b}"'), 'retained act at its original position: ${full}'
	assert !full.contains('hash="${hash_a}"'), 'compacted-away history is gone: ${full}'
	cid4 := s3l_conn(mut srv2)
	below2 := s3l_sub(mut srv2, cid4, 23, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
	assert below2.contains('CXER5020'), 'below-floor refusal survives restart: ${below2}'
	s3l_call('store-close', [h2])
}

// ── 3. pre-FL-2 bucket: first-boot seed, fresh epoch, lineage written ──────

fn test_s3_lineage_first_boot_of_pre_lineage_bucket_seeds() {
	mut stub := &S3LStub{}
	h1 := s3l_open(stub)
	hash1 := s3l_put(h1, '[doc pre="lineage"]')
	ms1 := s3l_ms(h1)
	boot1 := ms1.feed_boot
	s3l_call('store-close', [h1])

	// simulate the pre-FL-2 bucket: state objects + manifest present, no
	// lineage keys at all.
	for k in s3l_lineage_keys(stub) {
		stub.blobs.delete(k)
	}

	h2 := s3l_open(stub)
	ms2 := s3l_ms(h2)
	assert ms2.feed_boot != '', 'fresh epoch minted'
	assert ms2.feed_boot != boot1, 'a bucket with no persisted lineage seeds under a FRESH epoch'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 1, 'seeded compacted-from-snapshot'
	assert ms2.lineage_active, 'the seed path writes the initial bucket lineage'
	assert s3l_lineage_keys(stub).len > 0, 'initial full object written by the seed path'
	// and the old epoch's cursor refuses honestly (today's exact behavior).
	mut srv := s3l_server(h2)
	cid := s3l_conn(mut srv)
	old := s3l_sub(mut srv, cid, 30, '[feed [from boot="${boot1}" [s plane="docs" pos=1]]]')
	assert old.contains('CXER5020'), 'pre-lineage-epoch cursor refuses typed: ${old}'
	// the from-empty replay tells the seeded story.
	cid2 := s3l_conn(mut srv)
	full := s3l_sub(mut srv, cid2, 31, '[feed [from]]')
	assert full.contains('hash="${hash1}"'), 'seeded story replays: ${full}'
	s3l_call('store-close', [h2])
}

// ── 4. torn/inconsistent bucket lineage is never trusted ──────────────────

fn test_s3_lineage_torn_segment_reseeds_fresh_epoch() {
	mut stub := &S3LStub{}
	h1 := s3l_open(stub)
	s3l_put(h1, '[doc a=1]')
	s3l_put(h1, '[doc b=2]')
	ms1 := s3l_ms(h1)
	boot1 := ms1.feed_boot
	s3l_call('store-close', [h1])

	// tear the lineage: replace the last segment with a truncated record
	// (the shape a torn local sidecar tail has; on s3 this models any
	// unparseable/inconsistent lineage object).
	stub.blobs[s3_lineage_seg_key(s3_lineage_prefix, 1, 2)] = 'V\tdocs\tinsert\t7\t'.bytes()

	h2 := s3l_open(stub)
	ms2 := s3l_ms(h2)
	assert ms2.feed_boot != boot1, 'torn bucket lineage is discarded: fresh epoch, reseed'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 2, 'reseeded from the snapshot'
	assert ms2.lineage_gen == 2, 'the reseed lands under a NEW generation'
	lk := s3l_lineage_keys(stub)
	assert s3_lineage_full_key(s3_lineage_prefix, 2) in lk, 'reseeded base written: ${lk}'
	assert s3_lineage_full_key(s3_lineage_prefix, 1) !in lk, 'untrusted generation purged: ${lk}'
	// the rewritten lineage is clean again: close + reopen resumes durably.
	boot2 := ms2.feed_boot
	s3l_call('store-close', [h2])
	h3 := s3l_open(stub)
	ms3 := s3l_ms(h3)
	assert ms3.feed_boot == boot2, 'the reseeded lineage is durable again'
	s3l_call('store-close', [h3])
}

// ── 5. a density gap (a lost segment) is never served silently ────────────

fn test_s3_lineage_missing_segment_gap_reseeds() {
	mut stub := &S3LStub{}
	h1 := s3l_open(stub)
	s3l_put(h1, '[doc g=1]')
	s3l_put(h1, '[doc g=2]')
	s3l_put(h1, '[doc g=3]')
	ms1 := s3l_ms(h1)
	boot1 := ms1.feed_boot
	s3l_call('store-close', [h1])

	// lose the MIDDLE act's segment (the failed-PUT / lost-write shape):
	// positions 1,3 remain — dense-above-floor fails, never trusted.
	stub.blobs.delete(s3_lineage_seg_key(s3_lineage_prefix, 1, 2))

	h2 := s3l_open(stub)
	ms2 := s3l_ms(h2)
	assert ms2.feed_boot != boot1, 'a position gap is discarded: fresh epoch, reseed'
	assert (ms2.adv_pos['docs'] or { i64(0) }) == 3, 'reseeded from the snapshot (all three docs)'
	s3l_call('store-close', [h2])
}
