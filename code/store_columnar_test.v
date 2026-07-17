module code

import cx
import os

// store_columnar_test.v — #129 PR-D / D5 (#76) acceptance gate (spec/02-working/
// cxstore_columnar_backend.md §9), driven through the LIVE `[$store]` verb engine
// (store_stdlib_builtin_inner) — no engine-only island. The body is gated on
// `-d cxstore_columnar` (matching the backend's feature gate) AND needs the Arrow
// build (`-d cx_arrow_files` + libcx_arrow); without the flags this is a no-op, so
// the default `test-vcx-code` build compiles clean and never references an
// Arrow-gated symbol. The dedicated gate target is `make test-vcx-columnar`.
//
// store_columnar_open is the real open engine (the cap_guard sits in the
// stdlib_store.v dispatcher store_open_columnar, exercised by the CX/conformance
// layer; here we drive the persistence + verb engine the dispatcher forwards to).

fn col_is_err(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == 'err'
}

fn col_str(n cx.Node) string {
	return store_arg_str(n) or { panic('expected scalar result, got ${n}') }
}

// GATE 1 (round-trip + self-describing reopen) + GATE 6 (interop: the reopen reads
// the file back through the production vcx/arrow reader, i.e. the file IS standard
// Parquet/Arrow).
fn test_columnar_roundtrip_reopen() {
	$if cxstore_columnar ? {
		for enc in ['parquet', 'arrow-ipc'] {
			ext := if enc == 'arrow-ipc' { 'arrow' } else { 'parquet' }
			path := os.join_path(os.temp_dir(), 'cxcol_rt_${os.getpid()}.${ext}')
			os.rm(path) or {}
			os.rm(path + '.cxstore-aliases') or {}
			defer {
				os.rm(path) or {}
			}
			h := store_columnar_open('document+file://${path}', path, enc, 'zstd', false, '')
			assert !col_is_err(h), 'open err (${enc}): ${h}'

			docs := [
				'[event [level "error"] [ts 1] [msg "boom"]]',
				'[event [level "info"] [ts 2] [msg "ok"]]',
				'[event [level "error"] [ts 3] [msg "again"]]',
			]
			mut keys := []string{}
			for d in docs {
				r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or {
					panic('put none (${enc})')
				}
				assert !col_is_err(r), 'put err (${enc}): ${r}'
				keys << col_str(r)
			}
			assert os.exists(path), 'columnar file not written (${enc})'

			// Self-describing reopen (read-only): same docs, byte-identical canonical.
			h2 := store_columnar_open('document+file://${path}', path, enc, 'zstd', true, '')
			assert !col_is_err(h2), 'reopen err (${enc}): ${h2}'
			for i, k in keys {
				r := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k)]) or {
					panic('get none (${enc})')
				}
				got := col_str(r)
				want := cx.cx_text_canonical(docs[i]) or { panic('canon') }
				assert got == want, 'roundtrip mismatch (${enc}) ${k}: got=${got} want=${want}'
			}
		}
	}
}

// GATE 2 (doc-identity universality): the store-key in a columnar store == the
// store-key in a mem:// store (same strict-canonical hash, substrate-invariant).
fn test_columnar_doc_identity_universal() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_id_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		doc := '[record [id 42] [name "Acme"] [active +]]'

		col := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		assert !col_is_err(col), 'columnar open err: ${col}'
		rc := store_stdlib_builtin_inner('store-put-doc-text', [col, store_str(doc)]) or {
			panic('col put none')
		}
		k_col := col_str(rc)

		mem := store_open_impl('mem://', '', '', false, true, map[string]string{})
		assert !col_is_err(mem), 'mem open err: ${mem}'
		rm := store_stdlib_builtin_inner('store-put-doc-text', [mem, store_str(doc)]) or {
			panic('mem put none')
		}
		k_mem := col_str(rm)

		assert k_col == k_mem, 'doc-identity not universal: columnar=${k_col} mem=${k_mem}'
	}
}

// GATE 3 (migrate): migrate a mem:// collection → columnar and back; all
// store-keys preserved (doc-identity is substrate-invariant; columnar interops at
// the document level via the migrate fallback).
fn test_columnar_migrate_roundtrip() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_mig_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		docs := [
			'[m [a 1]]',
			'[m [a 2]]',
			'[m [a 3]]',
		]
		mem := store_open_impl('mem://', '', '', false, true, map[string]string{})
		mut keys := []string{}
		for d in docs {
			r := store_stdlib_builtin_inner('store-put-doc-text', [mem, store_str(d)]) or {
				panic('mem put')
			}
			keys << col_str(r)
		}

		col := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		mr := store_stdlib_builtin_inner('store-migrate', [mem, col]) or { panic('migrate none') }
		assert !col_is_err(mr), 'migrate err: ${mr}'

		// reopen the columnar store: every store-key is preserved and the doc it
		// resolves to re-hashes to that key (doc-identity is substrate-invariant;
		// the byte form may re-canonicalize across a subtree→document migrate, but
		// the store-key — the SHA-256 of strict-canonical bytes — does not).
		col2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', true, '')
		for k in keys {
			r := store_stdlib_builtin_inner('store-get-doc-text', [col2, store_str(k)]) or {
				panic('col get')
			}
			got := col_str(r)
			rehash := cx.cx_text_hash(got) or { panic('rehash') }
			assert rehash == k, 'migrated doc ${k} no longer hashes to its key (got rehash ${rehash})'
		}

		// migrate back columnar → fresh mem; keys preserved.
		mem2 := store_open_impl('mem://', '', '', false, true, map[string]string{})
		mr2 := store_stdlib_builtin_inner('store-migrate', [col2, mem2]) or { panic('migrate-back none') }
		assert !col_is_err(mr2), 'migrate-back err: ${mr2}'
		for k in keys {
			r := store_stdlib_builtin_inner('store-exists', [mem2, store_str(k)]) or {
				panic('exists')
			}
			present := if r is cx.ScalarNode { cx.scalar_value_str_public(r.value) } else { '' }
			assert present == 'true', 'key ${k} lost on migrate-back (exists=${r})'
		}
	}
}

// GATE 5 (heterogeneity totality): an irregular collection (varied shapes) stores
// and round-trips byte-identically via the blob path — fidelity + doc-identity are
// preserved regardless of shape.
fn test_columnar_heterogeneity_totality() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_het_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		docs := [
			'[a [x 1]]',
			'[b [nested [deep [v "z"]]] [list 1 2 3]]',
			"[c 'just a scalar body']",
			'[d [k "v"] [k2 [inner +]]]',
		]
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		mut keys := []string{}
		for d in docs {
			r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or {
				panic('put')
			}
			keys << col_str(r)
		}
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', true, '')
		for i, k in keys {
			r := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k)]) or {
				panic('get')
			}
			got := col_str(r)
			want := cx.cx_text_canonical(docs[i]) or { panic('canon') }
			assert got == want, 'irregular doc ${k} not byte-identical'
		}
	}
}

// GATE 7 (integrity): a tampered __cx_doc that no longer re-hashes to its __cx_key
// is a HARD error on reopen (CXER1120) — never a silent wrong doc.
fn test_columnar_integrity_rehash_guard() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_int_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[doc [v 1]]')]) or {
			panic('put')
		}
		key := col_str(r)

		// Tamper the live body so it no longer hashes to its key, then flush a
		// corrupted file.
		id := store_handle_of(h) or { panic('no handle') }
		mut ms := store_lookup(id) or { panic('no store') }
		ms.docs[key] = '[doc [v 999]]' // different bytes, same key
		store_columnar_flush(mut ms) or { panic('flush: ${err.msg()}') }

		// Reopen must HARD-error (integrity), not return the wrong doc.
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', true, '')
		assert col_is_err(h2), 'tampered file must fail reopen, got: ${h2}'
		el := h2 as cx.Element
		err_code := cx.scalar_value_str_public(el.attrs[0].value)
		assert err_code == 'cx-err:CXER1120', 'expected CXER1120, got ${h2}'
	}
}

// Step 2 — schema union + scalar column promotion: a homogeneous record
// collection promotes its top-level scalar fields to typed columns (so the file
// carries projectable/predicate columns alongside the __cx_doc anchor), sets
// columnar_pushdown, and still round-trips byte-identically.
fn test_columnar_scalar_promotion() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_promote_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		// homogeneous: same scalar fields (level::string, ts::int, ratio::float, ok::bool)
		docs := [
			'[event [level "error"] [ts 1] [ratio 0.5] [ok +]]',
			'[event [level "info"] [ts 2] [ratio 0.9] [ok -]]',
			'[event [level "warn"] [ts 3] [ratio 0.1] [ok +]]',
		]
		mut keys := []string{}
		for d in docs {
			r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or {
				panic('put')
			}
			keys << col_str(r)
		}

		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }
		assert ms.columnar_pushdown, 'homogeneous records must promote columns (pushdown)'

		// The written file carries the reserved columns PLUS the promoted scalar
		// fields, typed by union — proving it is a real columnar projection, not
		// just the __cx_doc blob. (String columns report an empty type_name —
		// string is the implicit CXCol default; `+`/`-` with no type context are
		// text → string, not bool.)
		framed := store_columnar_read_file(path, 'parquet') or { panic('read: ${err}') }
		doc := cx.parse_data_bin(framed) or { panic('decode: ${err}') }
		td := store_columnar_table_of(doc) or { panic('no table') }
		mut byname := map[string]string{}
		for c in td.cols {
			byname[c.name] = c.type_name
		}
		assert '__cx_key' in byname && '__cx_doc' in byname, 'reserved cols missing: ${byname}'
		assert 'level' in byname && byname['level'] in ['', 'string'], 'level col: ${byname}'
		assert 'ok' in byname && byname['ok'] in ['', 'string'], 'ok col: ${byname}'
		assert byname['ts'] == 'int', 'ts col: ${byname}'
		assert byname['ratio'] == 'float', 'ratio col: ${byname}'

		// Reopen: docs byte-identical AND pushdown re-derived true.
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', true, '')
		id2 := store_handle_of(h2) or { panic('no handle2') }
		ms2 := store_lookup(id2) or { panic('no store2') }
		assert ms2.columnar_pushdown, 'pushdown not re-derived on reopen'
		for i, k in keys {
			r := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k)]) or {
				panic('get')
			}
			want := cx.cx_text_canonical(docs[i]) or { panic('canon') }
			assert col_str(r) == want, 'promoted-store doc ${k} not byte-identical'
		}
	}
}

// G3-Q2=a done right — one-level-nested promotion via column FLATTENING: a flat
// scalar sub-record `[meta [src …] [seq …]]` promotes to real typed columns
// `meta.src` / `meta.seq` (not a blob, not a serialized string), round-trips
// byte-identically, and a name seen in MORE THAN ONE shape stays unpromoted.
fn test_columnar_nested_flattening() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_flat_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		docs := [
			'[event [level "error"] [meta [src "a"] [seq 1]]]',
			'[event [level "info"] [meta [src "b"] [seq 2]]]',
		]
		mut keys := []string{}
		for d in docs {
			r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
			keys << col_str(r)
		}
		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }
		assert ms.columnar_pushdown, 'flat sub-record must promote (pushdown)'

		// the file carries FLATTENED typed columns meta.src (string) + meta.seq (int).
		framed := store_columnar_read_file(path, 'parquet') or { panic('read') }
		doc := cx.parse_data_bin(framed) or { panic('decode') }
		td := store_columnar_table_of(doc) or { panic('no table') }
		mut byname := map[string]string{}
		for c in td.cols {
			byname[c.name] = c.type_name
		}
		assert 'meta.src' in byname && byname['meta.src'] in ['', 'string'], 'meta.src col: ${byname}'
		assert byname['meta.seq'] == 'int', 'meta.seq col: ${byname}'
		assert 'level' in byname, 'level col: ${byname}'

		// byte-identical round-trip (reconstruction via __cx_doc, untouched by flattening).
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', true, '')
		for i, k in keys {
			r := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k)]) or { panic('get') }
			want := cx.cx_text_canonical(docs[i]) or { panic('canon') }
			assert col_str(r) == want, 'nested-flattened doc ${k} not byte-identical'
		}
	}
}

// A field seen in MORE THAN ONE shape (scalar vs sub-record) is NOT promoted —
// keeps column-null ⟺ path-absent so pushdown stays exact.
fn test_columnar_mixed_shape_not_promoted() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_mix_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		// `info` is a scalar in doc 1 but a sub-record in doc 2 → mixed → unpromoted.
		for d in ['[r [info "x"] [n 1]]', '[r [info [a 1]] [n 2]]'] {
			store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
		}
		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }
		framed := store_columnar_read_file(path, 'parquet') or { panic('read') }
		doc := cx.parse_data_bin(framed) or { panic('decode') }
		td := store_columnar_table_of(doc) or { panic('no table') }
		mut names := []string{}
		for c in td.cols {
			names << c.name
		}
		// `n` (consistently scalar) promotes; `info` (mixed) and `info.a` do NOT.
		assert 'n' in names, 'n should promote: ${names}'
		assert 'info' !in names, 'mixed-shape info must NOT promote: ${names}'
		assert 'info.a' !in names, 'mixed-shape info.a must NOT promote: ${names}'
	}
}

// An irregular collection (no uniformly-scalar field) promotes NO columns
// (columnar_pushdown=false, blob fallback) and still round-trips byte-identically.
fn test_columnar_irregular_no_promotion() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_irr_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		// `v` is scalar in one doc but nested in another → disqualified (would make
		// pushdown unsound); no other shared scalar field → nothing promotable.
		docs := [
			'[a [v 1]]',
			'[b [v [nested [x 2]]]]',
		]
		for d in docs {
			store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
		}
		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }
		assert !ms.columnar_pushdown, 'irregular collection must NOT promote (got pushdown)'

		// totality: both docs still round-trip byte-identically (blob fallback).
		framed := store_columnar_read_file(path, 'parquet') or { panic('read') }
		rdoc := cx.parse_data_bin(framed) or { panic('decode') }
		td := store_columnar_table_of(rdoc) or { panic('no table') }
		assert td.cols.len == 2, 'irregular store must be blob-only (2 cols), got ${td.cols.len}'
	}
}

fn col_seq_len(n cx.Node) int {
	if n is cx.Element {
		return n.items.len
	}
	return -1
}

fn col_attr(n cx.Node, name string) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == name {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// Introspection (§4): a columnar store reports its OWN observables (row count,
// encoding, codec, pushdown flag, column count) and NOT object-graph / remote
// metrics (doc-identity only — no fabricated object_count, not remote).
fn test_columnar_status_observables() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_st_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		for d in ['[r [a 1] [b "x"]]', '[r [a 2] [b "y"]]'] {
			store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
		}
		st := store_stdlib_builtin_inner('store-status', [h]) or { panic('status') }
		assert col_attr(st, 'backend') == 'columnar', 'backend: ${st}'
		assert col_attr(st, 'encoding') == 'parquet', 'encoding: ${st}'
		assert col_attr(st, 'codec') == 'zstd', 'codec: ${st}'
		assert col_attr(st, 'columnar-pushdown') == 'true', 'pushdown: ${st}'
		assert col_attr(st, 'docs') == '2', 'docs: ${st}'
		assert col_attr(st, 'columns') == '4', 'columns (2 reserved + a,b): ${st}'
		// object-identity / remote metrics are NOT-APPLICABLE → absent (not 0/true).
		assert col_attr(st, 'objects') == '', 'object_count must be absent: ${st}'
		assert col_attr(st, 'remote') == '', 'columnar is not remote: ${st}'
	}
}

// GATE 4 — query pushdown: a column-projecting query over a promoted column runs
// the columnar scan (pushdown), while a structural / non-promoted-field query
// falls back to row materialization (no pushdown) — both return the correct rows.
fn test_columnar_query_pushdown() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_q_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		docs := [
			'[event [level "error"] [ts 1] [meta [src "alpha"]]]',
			'[event [level "info"] [ts 2] [meta [src "beta"]]]',
		]
		for d in docs {
			store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
		}
		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }

		// PUSHDOWN: //level is a promoted depth-1 scalar column → the columnar
		// executor answers it (some), reading only that column.
		pd := store_columnar_query(ms, '//level') or { panic('expected pushdown for //level') }
		assert col_seq_len(pd) == 2, 'pushdown //level should match 2 rows, got ${col_seq_len(pd)}'

		// PUSHDOWN over a FLATTENED one-level-nested column (G3-Q2=a done right):
		// `meta` is a flat scalar sub-record → promoted to a `meta.src` column, so
		// //meta/src pushes down to that column.
		pn := store_columnar_query(ms, '//meta/src') or {
			panic('expected pushdown for //meta/src (flattened column)')
		}
		assert col_seq_len(pn) == 2, 'pushdown //meta/src should match 2 rows, got ${col_seq_len(pn)}'

		// FALLBACK (pushdown=false): a bare `//src` names no column (the column is
		// `meta.src`); `//meta` names the parent, not a leaf column; a 3-segment path
		// is not column-projectable → all decline (none) → caller materializes.
		if _ := store_columnar_query(ms, '//src') {
			assert false, '//src (no such column; flattened is meta.src) must NOT push down'
		}
		if _ := store_columnar_query(ms, '//meta') {
			assert false, '//meta (parent, not a leaf column) must NOT push down'
		}
		if _ := store_columnar_query(ms, '//a/b/c') {
			assert false, 'a 3-segment path must NOT push down'
		}

		// LIVE verb correctness, BOTH paths: //level (pushdown) and //src (fallback
		// materialization) return the correct rows through the same [$store:query].
		r1 := store_stdlib_builtin_inner('store-query', [h, store_str('//level')]) or { panic('q1') }
		assert col_seq_len(r1) == 2, 'verb //level should return 2, got ${col_seq_len(r1)}'
		r2 := store_stdlib_builtin_inner('store-query', [h, store_str('//src')]) or { panic('q2') }
		assert col_seq_len(r2) == 2, 'verb //src (fallback) should return 2, got ${col_seq_len(r2)}'
	}
}

// ColStubS3 — an in-memory S3 transport for the hermetic s3-columnar gate (no live
// S3). Mirrors the s3-subtree test stub; two stores sharing one stub model a reopen
// against the same bucket.
@[heap]
struct ColStubS3 {
mut:
	blobs map[string][]u8
}

fn (t &ColStubS3) fetch(method string, key string) (int, []u8, bool) {
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

fn (mut t ColStubS3) store(key string, body []u8) (int, bool) {
	t.blobs[key] = body.clone()
	return 200, true
}

fn (t &ColStubS3) keys() []string {
	return t.blobs.keys()
}

// GATE (G3-Q5=b) — s3-hosted columnar: the columnar file is a single s3 object;
// put / reopen / get round-trips through the live verbs over an in-memory stub,
// and column promotion (pushdown) still holds over s3.
fn test_columnar_s3_roundtrip() {
	$if cxstore_columnar ? {
		mut stub := &ColStubS3{}
		mut ms := &MemStore{
			url:             'document+s3://bucket/events.parquet'
			backend:         'columnar'
			model:           'document'
			encoding:        'parquet'
			compression:     'zstd'
			is_open:         true
			columnar_s3:     S3Transport(stub)
			columnar_s3_key: 'events.parquet'
		}
		id := store_register(ms)
		h := store_handle_element(id, ms)
		docs := [
			'[event [level "error"] [ts 1]]',
			'[event [level "info"] [ts 2]]',
		]
		mut keys := []string{}
		for d in docs {
			r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or {
				panic('s3 put')
			}
			keys << col_str(r)
		}
		assert 'events.parquet' in stub.blobs, 's3 columnar object not written'

		// reopen: a fresh store over the SAME stub bucket → load the object.
		mut ms2 := &MemStore{
			url:             'document+s3://bucket/events.parquet'
			backend:         'columnar'
			model:           'document'
			encoding:        'parquet'
			compression:     'zstd'
			is_open:         true
			columnar_s3:     S3Transport(stub)
			columnar_s3_key: 'events.parquet'
		}
		store_columnar_load(mut ms2) or { panic('s3 reopen: ${err.msg()}') }
		id2 := store_register(ms2)
		h2 := store_handle_element(id2, ms2)
		for i, k in keys {
			r := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(k)]) or {
				panic('s3 get')
			}
			want := cx.cx_text_canonical(docs[i]) or { panic('canon') }
			assert col_str(r) == want, 's3 roundtrip mismatch ${k}'
		}
		assert ms2.columnar_pushdown, 's3-backed columnar must still promote level/ts'
	}
}

// G3-Q3=a done right — declared ?schema= pins the table: a conforming doc is
// accepted, a non-conforming doc is REJECTED (CXER1115) at put time, via the
// existing cx-stdlib/validate engine.
fn test_columnar_declared_schema() {
	$if cxstore_columnar ? {
		schema_src := '[?cx schema-of event]\n[event\n  [elem level [card "1..1"]]\n  [elem ts [card "1..1"]]\n]\n[type level::string]\n[type ts::int]\n'
		path := os.join_path(os.temp_dir(), 'cxcol_sch_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false,
			schema_src)
		assert !col_is_err(h), 'open err: ${h}'

		// conforming doc → accepted.
		ok := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[event [level "error"] [ts 1]]')]) or {
			panic('put none')
		}
		assert !col_is_err(ok), 'conforming put should succeed: ${ok}'

		// non-conforming doc (missing required ts) → hard CXER1115, not stored.
		bad := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str('[event [level "error"]]')]) or {
			panic('put none2')
		}
		assert col_is_err(bad), 'non-conforming put must be rejected: ${bad}'
		bel := bad as cx.Element
		assert cx.scalar_value_str_public(bel.attrs[0].value) == 'cx-err:CXER1115', 'expected CXER1115: ${bad}'

		// only the conforming doc landed.
		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }
		assert ms.doc_order.len == 1, 'only the conforming doc should be stored, got ${ms.doc_order.len}'
	}
}

// store_normalize_uri unit coverage (pure, no caps): model prefix + query parse.
fn test_columnar_normalize_uri() {
	base1, q1, m1 := store_normalize_uri('document+file:///tmp/x.parquet?encoding=parquet&compression=zstd&schema=/etc/s.cxs')
	assert base1 == 'file:///tmp/x.parquet', base1
	assert m1 == 'document', m1
	assert q1['encoding'] == 'parquet', q1.str()
	assert q1['compression'] == 'zstd', q1.str()
	assert q1['schema'] == '/etc/s.cxs', q1.str()

	// additive: a plain URL is unchanged.
	base2, q2, m2 := store_normalize_uri('mem://')
	assert base2 == 'mem://' && m2 == '' && q2.len == 0

	base3, _, m3 := store_normalize_uri('subtree+file:///data')
	assert base3 == 'file:///data' && m3 == 'subtree'
}

// Subtree + columnar are incompatible: a bare (no document+) ?encoding=parquet is a
// hard error directing the caller to the document model.
fn test_columnar_requires_document_model() {
	$if cxstore_columnar ? {
		// bare file://…?encoding=parquet (subtree default) → hard error before any
		// capability work (the document-model check precedes cap_guard).
		r := store_open_impl('file:///tmp/whatever.parquet?encoding=parquet', '', '', false,
			true, map[string]string{})
		assert col_is_err(r), 'bare ?encoding=parquet must error, got ${r}'
	}
}
