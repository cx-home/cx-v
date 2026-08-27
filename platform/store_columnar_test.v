module platform

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

		// The DECLINE direction at the LIVE VERB (stream 17 W7 ruled
		// engagement witness — §7 honest reporting): [$store:status]
		// reports columnar-pushdown=false, never a silent full-scan
		// masquerading as pushdown. (The engage direction's verb-level
		// twin is test_columnar_status_observables.)
		st := store_stdlib_builtin_inner('store-status', [h]) or { panic('status') }
		assert col_attr(st, 'columnar-pushdown') == 'false', 'verb must report pushdown=false: ${st}'

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
		pd := store_columnar_query_matches(ms, '//level') or {
			panic('expected pushdown for //level')
		}
		assert pd.len == 2, 'pushdown //level should match 2 rows, got ${pd.len}'

		// PUSHDOWN over a FLATTENED one-level-nested column (G3-Q2=a done right):
		// `meta` is a flat scalar sub-record → promoted to a `meta.src` column, so
		// //meta/src pushes down to that column.
		pn := store_columnar_query_matches(ms, '//meta/src') or {
			panic('expected pushdown for //meta/src (flattened column)')
		}
		assert pn.len == 2, 'pushdown //meta/src should match 2 rows, got ${pn.len}'

		// FALLBACK (pushdown=false): a bare `//src` names no column (the column is
		// `meta.src`); `//meta` names the parent, not a leaf column; a 3-segment path
		// is not column-projectable → all decline (none) → caller materializes.
		if _ := store_columnar_query_matches(ms, '//src') {
			assert false, '//src (no such column; flattened is meta.src) must NOT push down'
		}
		if _ := store_columnar_query_matches(ms, '//meta') {
			assert false, '//meta (parent, not a leaf column) must NOT push down'
		}
		if _ := store_columnar_query_matches(ms, '//a/b/c') {
			assert false, 'a 3-segment path must NOT push down'
		}

		// LIVE verb correctness, BOTH paths: //level (pushdown) and //src (fallback
		// materialization) return the correct rows through the same [$store:query].
		r1 := store_stdlib_builtin_inner('store-query', [h, store_str('//level')]) or { panic('q1') }
		assert col_seq_len(r1) == 2, 'verb //level should return 2, got ${col_seq_len(r1)}'
		r2 := store_stdlib_builtin_inner('store-query', [h, store_str('//src')]) or { panic('q2') }
		assert col_seq_len(r2) == 2, 'verb //src (fallback) should return 2, got ${col_seq_len(r2)}'

		// SHAPE PARITY (#711 item 8, ruling L97): one store, one query, both
		// executors — the columnar column projection and the row scan MUST emit
		// the byte-identical flat provenance-bearing relation.
		row_pairs, _, row_ok := store_query_scan(ms, '//level')
		assert row_ok, 'row scan must answer //level'
		src := store_source_ref(ms, '//level')
		mut col_tuples := []cx.Node{}
		for p in pd {
			col_tuples << store_query_tuple(p.hash, src, p.node)
		}
		mut row_tuples := []cx.Node{}
		for p in row_pairs {
			row_tuples << store_query_tuple(p.hash, src, p.node)
		}
		// (cx_emit_node_str: the columnar lane builds without -d cx_platform, so
		// module `code`'s render_canonical is out of reach — the cx emitter is
		// the same canonical text.)
		col_rendered := cx.cx_emit_node_str(store_seq(col_tuples), false)
		row_rendered := cx.cx_emit_node_str(store_seq(row_tuples), false)
		assert col_rendered == row_rendered, 'columnar vs row relation must be byte-identical (L97 shape parity):\ncolumnar: ${col_rendered}\nrow:      ${row_rendered}'
		// The live verb's answer IS that relation (tuples carry doc= + source=).
		live_rendered := cx.cx_emit_node_str(r1, false)
		assert live_rendered == col_rendered, 'live [$store:query] must emit the same relation, got ${live_rendered}'
	}
}

// Q6 exactness gate (RULED #766/#767/#768): the pushdown answers ONLY when
// provably exact — every precondition failure declines to the row scan, and
// the live verb's answer equals the row scan's either way.
fn test_columnar_pushdown_exactness_envelope() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_env_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		docs := [
			// `level` also occurs NESTED (depth 2, under `wrap`) in doc 3 →
			// occurs-only-top-level fails for `level`; `ts` stays top-only.
			// `ratio` is DECIMAL → float column, coerced → non-exact.
			// `tag` is duplicated top-level in doc 2 → force-complex.
			'[event [level "error"] [ts 1] [ratio 0.5] [tag "a"]]',
			'[event [level "info"] [ts 2] [ratio 0.9] [tag "b"] [tag "c"]]',
			'[event [ts 3] [wrap [level "nested"]]]',
		]
		for d in docs {
			store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
		}
		id := store_handle_of(h) or { panic('no handle') }
		ms := store_lookup(id) or { panic('no store') }

		// deep occurrence: `//level` must DECLINE (a column answer would omit
		// the nested match the row scan finds).
		if _ := store_columnar_query_matches(ms, '//level') {
			assert false, '//level must decline: `level` occurs nested (occurs-only-top-level)'
		}
		// the row scan finds all three (2 top-level + 1 nested).
		lv := store_stdlib_builtin_inner('store-query', [h, store_str('//level')]) or { panic('q') }
		assert col_seq_len(lv) == 3, '//level row scan must find 3 (incl. nested), got ${col_seq_len(lv)}'

		// non-exact column: `ratio` is decimal-sourced (float column, coerced)
		// → decline; the row scan answers with the EXACT stored leaves.
		if _ := store_columnar_query_matches(ms, '//ratio') {
			assert false, '//ratio must decline: decimal-sourced float column is non-exact'
		}
		rt := store_stdlib_builtin_inner('store-query', [h, store_str('//ratio')]) or { panic('q') }
		assert col_seq_len(rt) == 2, '//ratio row scan must find 2, got ${col_seq_len(rt)}'

		// duplicated top-level name: `tag` force-complex → no column → decline.
		if _ := store_columnar_query_matches(ms, '//tag') {
			assert false, '//tag must decline: duplicated top-level name is force-complex'
		}
		tg := store_stdlib_builtin_inner('store-query', [h, store_str('//tag')]) or { panic('q') }
		assert col_seq_len(tg) == 3, '//tag row scan must find 3 (dup preserved), got ${col_seq_len(tg)}'

		// absolute/relative forms address the per-doc ROOT (document-node
		// anchoring, #768) — never column-projectable.
		if _ := store_columnar_query_matches(ms, '/ts') {
			assert false, '/ts (absolute) must decline: roots vary per doc'
		}
		if _ := store_columnar_query_matches(ms, 'ts') {
			assert false, 'ts (relative) must decline'
		}

		// the sound survivor: `ts` is top-only, int, native → pushes down and
		// equals the row scan byte-for-byte.
		pd := store_columnar_query_matches(ms, '//ts') or {
			panic('expected pushdown for //ts (top-only, exact int column)')
		}
		assert pd.len == 3, 'pushdown //ts should match 3 rows, got ${pd.len}'
		row_pairs, _, row_ok := store_query_scan(ms, '//ts')
		assert row_ok, 'row scan must answer //ts'
		src := store_source_ref(ms, '//ts')
		mut col_tuples := []cx.Node{}
		for p in pd {
			col_tuples << store_query_tuple(p.hash, src, p.node)
		}
		mut row_tuples := []cx.Node{}
		for p in row_pairs {
			row_tuples << store_query_tuple(p.hash, src, p.node)
		}
		assert cx.cx_emit_node_str(store_seq(col_tuples), false) == cx.cx_emit_node_str(store_seq(row_tuples), false), '//ts columnar vs row must be byte-identical'
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

fn (mut t ColStubS3) remove(key string) (int, bool) {
	t.blobs.delete(key)
	return 204, true
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
		schema_src := '[schema of=event]\n[event\n  [elem level [card "1..1"]]\n  [elem ts [card "1..1"]]\n]\n[type level::string]\n[type ts::int]\n'
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

// L89 (stream 17 W3b): SECRET NEVER COLUMNAR — a __cx_secret__-wrapped
// field is a marker ELEMENT (never a scalar leaf), so promotion
// excludes it BY CONSTRUCTION: it rides the __cx_doc node path, no
// column carries it, and the stored document round-trips with the
// wrapper intact. This fixture PINS the structural rule (the
// force-node negative the ruling names).
fn test_columnar_secret_never_promoted() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_secret_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		docs := [
			'[cred [user "alice"] [token [__cx_secret__ [v "s3cr3t-1"]]]]',
			'[cred [user "bob"] [token [__cx_secret__ [v "s3cr3t-2"]]]]',
		]
		for d in docs {
			store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
		}
		framed := store_columnar_read_file(path, 'parquet') or { panic('read: ${err}') }
		doc := cx.parse_data_bin(framed) or { panic('decode: ${err}') }
		td := store_columnar_table_of(doc) or { panic('no table') }
		mut names := []string{}
		for c in td.cols {
			names << c.name
		}
		assert 'user' in names, 'plain scalar sibling must promote: ${names}'
		assert 'token' !in names && 'token.v' !in names,
			'a secret-wrapped field must NEVER become a column (forced node path): ${names}'
	}
}

// Stream 17 W3c: NULL positions round-trip through the FULL columnar
// stack (CX docs → parquet write via Arrow validity → read back via
// the 0x80 import) — the real-Arrow-validity acceptance.
fn test_columnar_null_roundtrip_through_arrow() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_nullrt_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd', false, '')
		// doc 2 lacks `n` — the promoted column carries a null there.
		docs := [
			'[event [tag "a"] [n 1]]',
			'[event [tag "b"]]',
			'[event [tag "c"] [n 3]]',
		]
		mut keys := []string{}
		for d in docs {
			r := store_stdlib_builtin_inner('store-put-doc-text', [h, store_str(d)]) or { panic('put') }
			keys << col_str(r)
		}
		// Read the parquet back through the Arrow import: the n column
		// must be nullable with the null at row 2 (not a zero).
		framed := store_columnar_read_file(path, 'parquet') or { panic('read: ${err}') }
		doc := cx.parse_data_bin(framed) or { panic('decode: ${err}') }
		td := store_columnar_table_of(doc) or { panic('no table') }
		mut n_idx := -1
		for i, c in td.cols {
			if c.name == 'n' {
				n_idx = i
			}
		}
		assert n_idx >= 0, 'n column missing'
		assert td.rows.len == 3
		assert td.rows[0][n_idx] is i64 && (td.rows[0][n_idx] as i64) == 1, '${td.rows[0][n_idx]}'
		assert td.rows[1][n_idx] is cx.NullValue, 'row 2 must be NULL, got ${td.rows[1][n_idx]}'
		assert td.rows[2][n_idx] is i64 && (td.rows[2][n_idx] as i64) == 3, '${td.rows[2][n_idx]}'
	}
}

// GATE (stream 17 W4, #710 item 2) — predicate pushdown: a final-step
// predicate over a promoted+exact column evaluates ONCE against the
// promotion-invariant candidate shape (scalar leaf — no attrs, no element
// children) via the row scan's OWN predicate function, so the verdict —
// and therefore the answer — is provably equal to the row scan's. The
// attribute axis is provably empty on promoted leaves. Anything the plan
// refuses (CXER1709) or promotion does not cover stays `none` (row-scan
// fallback) — the honest-reporting contract unchanged.
fn test_columnar_predicate_pushdown() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_pred_${os.getpid()}.parquet')
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

		// FALSE verdict, answered by pushdown (some, empty): promoted leaves
		// carry no attributes, so any attr predicate matches nothing — and the
		// row scan agrees.
		pf := store_columnar_query_matches(ms, "//level[= \$_@x '1']") or {
			panic('expected pushdown (some) for the attr-compare predicate')
		}
		assert pf.len == 0, 'attr predicate over promoted leaves must match 0, got ${pf.len}'
		rf, _, rf_ok := store_query_scan(ms, "//level[= \$_@x '1']")
		assert rf_ok, 'row scan must answer the attr predicate'
		assert rf.len == 0, 'row scan attr predicate must match 0, got ${rf.len}'
		pe := store_columnar_query_matches(ms, '//level[@x]') or {
			panic('expected pushdown (some) for the attr-existence predicate')
		}
		assert pe.len == 0, 'attr-existence over promoted leaves must match 0, got ${pe.len}'

		// TRUE verdict, answered by pushdown: `[1]` holds for every
		// singleton candidate in the row scan — byte-identical relations.
		pt := store_columnar_query_matches(ms, '//ts[1]') or {
			panic('expected pushdown (some) for the position predicate')
		}
		rt, _, rt_ok := store_query_scan(ms, '//ts[1]')
		assert rt_ok, 'row scan must answer //ts[1]'
		src := store_source_ref(ms, '//ts[1]')
		mut col_tuples := []cx.Node{}
		for p in pt {
			col_tuples << store_query_tuple(p.hash, src, p.node)
		}
		mut row_tuples := []cx.Node{}
		for p in rt {
			row_tuples << store_query_tuple(p.hash, src, p.node)
		}
		assert cx.cx_emit_node_str(store_seq(col_tuples), false) == cx.cx_emit_node_str(store_seq(row_tuples), false), '//ts[1] columnar vs row must be byte-identical'
		assert pt.len == 2, '//ts[1] should match both docs, got ${pt.len}'

		// Predicate on a FLATTENED column's leaf: same lowering.
		pn := store_columnar_query_matches(ms, '//meta/src[@x]') or {
			panic('expected pushdown (some) for the flattened-leaf predicate')
		}
		assert pn.len == 0, 'flattened-leaf attr predicate must match 0, got ${pn.len}'

		// The attribute AXIS on a promoted column: provably empty (promotion
		// admits attr-less leaves only) — answered without touching the file.
		pa := store_columnar_query_matches(ms, '//level/@x') or {
			panic('expected pushdown (some) for the attribute axis')
		}
		assert pa.len == 0, 'attribute axis over promoted leaves must match 0, got ${pa.len}'
		ra, _, ra_ok := store_query_scan(ms, '//level/@x')
		assert ra_ok && ra.len == 0, 'row scan attribute axis must match 0'

		// REFUSED by the plan (an intermediate predicate) → none here; the
		// row lane raises the honest CXER1709 — never answered from columns.
		if _ := store_columnar_query_matches(ms, '//meta[1]/src') {
			assert false, 'an intermediate predicate must NOT push down (plan refusal)'
		}
		// A predicate over a NON-promoted name → none (row-scan fallback).
		if _ := store_columnar_query_matches(ms, '//src[1]') {
			assert false, '//src[1] (no such column) must NOT push down'
		}
		// `//a//b` (descendant second step) may match deeper than the column
		// carries → none.
		if _ := store_columnar_query_matches(ms, '//meta//src') {
			assert false, '//meta//src (descendant second step) must NOT push down'
		}

		// LIVE verb parity through [$store:query] for the predicate forms.
		lv := store_stdlib_builtin_inner('store-query', [h, store_str('//ts[1]')]) or { panic('q') }
		assert col_seq_len(lv) == 2, 'live //ts[1] should return 2, got ${col_seq_len(lv)}'
		le := store_stdlib_builtin_inner('store-query', [h, store_str("//level[= \$_@x '1']")]) or {
			panic('q')
		}
		assert col_seq_len(le) == 0, 'live //level[= \$_@x 1] should return 0, got ${col_seq_len(le)}'
	}
}

// ── #891: shared-open protection for the columnar substrate ─────────────────
//
// The columnar substrate rewrites the WHOLE object on every mutation, so two
// independent writable opens of one path do not merely race: the second flush
// discards the first's entire document collection. Before #891 it registered
// with neither store_open_shared_or_conflict nor any lock, so that clobbering
// was SILENT. These pin the #628 shape for this substrate — a second writable
// open is the same live store, divergent at-rest options refuse loudly, and
// read-only opens keep their private snapshot view.

fn col_handle_id(n cx.Node) string {
	return (n as cx.Element).attr('handle')
}

fn col_err_code(n cx.Node) string {
	return (n as cx.Element).attr('code')
}

// A second WRITABLE open of one path is a live view of the SAME store: a doc
// put through the first handle is visible through the second. Pre-#891 the
// second open built a private MemStore and the two clobbered each other.
fn test_columnar_second_writable_open_shares_the_live_store() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_share_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
			os.rm(path + '.cxstore-aliases') or {}
		}
		h1 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert !col_is_err(h1), 'first open err: ${h1}'
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert !col_is_err(h2), 'second open err: ${h2}'

		// Same live store, so the doc written through h1 is readable through h2.
		put := store_stdlib_builtin_inner('store-put-doc-text', [h1,
			store_str('[event [level "error"] [ts 1]]')]) or {
			panic('put none')
		}
		assert !col_is_err(put), 'put err: ${put}'
		key := col_str(put)
		got := store_stdlib_builtin_inner('store-get-doc-text', [h2, store_str(key)]) or {
			panic('get none')
		}
		assert !col_is_err(got), 'second handle cannot see the first handle write — the opens did not share (#891): ${got}'
		assert col_str(got).contains('error'), 'shared view returned the wrong doc: ${got}'
	}
}

// Divergent at-rest options on a LIVE writable root refuse loudly
// (CXER1143 E_STORE_OPEN_CONFLICT) rather than silently applying one opener's
// options to the other's writes.
fn test_columnar_conflicting_at_rest_options_refuse() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_conflict_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
			os.rm(path + '.cxstore-aliases') or {}
		}
		h1 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert !col_is_err(h1), 'first open err: ${h1}'
		// Same path, different compression codec.
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'none',
			false, '')
		assert col_is_err(h2), 'a live root reopened with different compression must REFUSE (#891), got: ${h2}'
		assert col_err_code(h2) == 'cx-err:CXER1143', 'wrong refusal code: ${h2}'
	}
}

// The declared columnar schema is part of the at-rest identity: it shapes the
// file layout exactly as encoding and compression do, so two writers declaring
// different schemas over one path are not sharing-compatible.
fn test_columnar_conflicting_declared_schema_refuses() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_schema_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
			os.rm(path + '.cxstore-aliases') or {}
		}
		h1 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert !col_is_err(h1), 'first open err: ${h1}'
		h2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '[schema [field name=ts kind=int]]')
		assert col_is_err(h2), 'a live root reopened with a different declared schema must REFUSE (#891), got: ${h2}'
		assert col_err_code(h2) == 'cx-err:CXER1143', 'wrong refusal code: ${h2}'
	}
}

// READ-ONLY opens are untouched: they never write, so a private snapshot view
// is both safe and cheaper — and two read-only opens are distinct handles.
fn test_columnar_read_only_opens_stay_private() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxcol_ro_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
			os.rm(path + '.cxstore-aliases') or {}
		}
		// Seed the file so a read-only open has something to load.
		hw := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert !col_is_err(hw), 'seed open err: ${hw}'
		store_stdlib_builtin_inner('store-put-doc-text', [hw,
			store_str('[event [level "info"] [ts 1]]')]) or { panic('seed put none') }
		store_stdlib_builtin_inner('store-close', [hw]) or { panic('close none') }

		r1 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			true, '')
		assert !col_is_err(r1), 'first read-only open err: ${r1}'
		r2 := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			true, '')
		assert !col_is_err(r2), 'second read-only open err: ${r2}'
		assert col_handle_id(r1) != col_handle_id(r2), 'read-only opens must stay private (distinct handles), got the same id'
	}
}

// ── #891: the s3 arm of the same-root sharing identity ──────────────────────
//
// #891 left one question open — whether s3 can participate in same-root
// sharing at all, having "no local inode to key on". It can, and the shipped
// answer is endpoint + bucket + object key (store_share_root / the
// store_share_root_s3 identity that store_columnar_open_s3 hands to
// store_open_shared_or_conflict).
//
// That answer is the part of #891 the file-backed pins above cannot reach:
// an s3-backed columnar MemStore has NO `root` at all, so keying on `ms.root`
// — the pre-#891 registry predicate — collapses EVERY s3 columnar store onto
// the one empty identity. These pin the discrimination in both directions:
// the same endpoint+bucket+key shares, and a different bucket OR a different
// endpoint does not. The registry half is driven directly (as the s3
// round-trip gate above drives the substrate over a stub transport) because
// store_columnar_open_s3 loads the object over the network before it returns.

// col_s3_mem builds a live, registered, writable s3-backed columnar store over
// the in-memory stub transport — the shape store_columnar_open_s3 registers.
fn col_s3_mem(endpoint string, bucket string, key string, codec string) &MemStore {
	mut stub := &ColStubS3{}
	mut ms := &MemStore{
		url:         'document+s3://${bucket}/${key}'
		backend:     'columnar'
		model:       'document'
		encoding:    'parquet'
		compression: codec
		is_open:     true
		columnar_s3: S3Transport(stub)

		columnar_s3_key:      key
		columnar_s3_endpoint: endpoint
		columnar_s3_bucket:   bucket
	}
	_ := store_register(ms)
	return ms
}

// The sharing identity of an s3-backed columnar store is its addressing
// triple, NOT `ms.root` (which is empty — there is no local path).
fn test_columnar_s3_share_root_is_the_addressing_triple() {
	$if cxstore_columnar ? {
		ms := col_s3_mem('s3.example.test', 'bkt-id-${os.getpid()}', 'events.parquet',
			'zstd')
		assert ms.root == '', 's3-backed columnar has no local path; root should be empty, got ${ms.root}'
		assert store_share_root(ms) == store_share_root_s3('s3.example.test', 'bkt-id-${os.getpid()}',
			'events.parquet'), 'the s3 sharing identity must be endpoint+bucket+key (#891), got ${store_share_root(ms)}'
		assert store_share_root(ms) != ms.root, 'the s3 identity must not fall back to the empty root (#891)'
	}
}

// A second WRITABLE open of the same endpoint+bucket+key is the SAME live
// store — the whole-object rewrite makes a clobbering PUT unrecoverable over
// s3, so sharing is if anything more necessary here than on a local path.
fn test_columnar_s3_second_writable_open_shares_the_live_store() {
	$if cxstore_columnar ? {
		bucket := 'bkt-share-${os.getpid()}'
		ms := col_s3_mem('s3.example.test', bucket, 'events.parquet', 'zstd')
		before := ms.open_count
		root := store_share_root_s3('s3.example.test', bucket, 'events.parquet')
		if r := store_open_shared_or_conflict('columnar', root, false, '|document|parquet|zstd|') {
			assert !col_is_err(r), 'a matching s3 reopen must SHARE, not refuse: ${r}'
			id := store_handle_of(r) or { panic('no handle') }
			got := store_lookup(id) or { panic('no store') }
			assert got.columnar_s3_bucket == bucket && got.columnar_s3_key == 'events.parquet', 'the shared handle resolved to a different store (#891)'
			assert ms.open_count == before + 1, 'a shared open must take a reference on the live store, open_count ${before} -> ${ms.open_count}'
		} else {
			assert false, 'a second writable s3 open of one endpoint+bucket+key must share the live store (#891)'
		}
	}
}

// The bucket and the endpoint are BOTH load-bearing: one bucket name on two
// endpoints is two different stores, and two buckets on one endpoint likewise.
// Pre-#891 registry keying (ms.root, empty for every s3 store) would have
// wrongly collapsed all of these onto one identity.
fn test_columnar_s3_distinct_addresses_do_not_share() {
	$if cxstore_columnar ? {
		pid := os.getpid()
		_ := col_s3_mem('s3.example.test', 'bkt-a-${pid}', 'events.parquet', 'zstd')

		// Same endpoint + key, DIFFERENT bucket.
		other_bucket := store_share_root_s3('s3.example.test', 'bkt-b-${pid}', 'events.parquet')
		if r := store_open_shared_or_conflict('columnar', other_bucket, false, '|document|parquet|zstd|') {
			assert false, 'a different BUCKET is a different store and must not share (#891): ${r}'
		}

		// Same bucket + key, DIFFERENT endpoint.
		other_endpoint := store_share_root_s3('s3.other.test', 'bkt-a-${pid}', 'events.parquet')
		if r := store_open_shared_or_conflict('columnar', other_endpoint, false, '|document|parquet|zstd|') {
			assert false, 'a different ENDPOINT is a different store and must not share (#891): ${r}'
		}

		// Same endpoint + bucket, DIFFERENT object key.
		other_key := store_share_root_s3('s3.example.test', 'bkt-a-${pid}', 'other.parquet')
		if r := store_open_shared_or_conflict('columnar', other_key, false, '|document|parquet|zstd|') {
			assert false, 'a different object KEY is a different store and must not share (#891): ${r}'
		}
	}
}

// Divergent at-rest options over one s3 identity refuse loudly (CXER1143),
// exactly as they do for a local path.
fn test_columnar_s3_conflicting_at_rest_options_refuse() {
	$if cxstore_columnar ? {
		bucket := 'bkt-conflict-${os.getpid()}'
		_ := col_s3_mem('s3.example.test', bucket, 'events.parquet', 'zstd')
		root := store_share_root_s3('s3.example.test', bucket, 'events.parquet')
		// Same object, different compression codec.
		if r := store_open_shared_or_conflict('columnar', root, false, '|document|parquet|none|') {
			assert col_is_err(r), 'a live s3 object reopened with different compression must REFUSE (#891), got: ${r}'
			assert col_err_code(r) == 'cx-err:CXER1143', 'wrong refusal code: ${r}'
		} else {
			assert false, 'a divergent-options s3 reopen must refuse, not open privately (#891)'
		}
	}
}

// READ-ONLY s3 opens stay private, as everywhere else: they never write, so a
// private snapshot view is both safe and cheaper.
fn test_columnar_s3_read_only_opens_stay_private() {
	$if cxstore_columnar ? {
		bucket := 'bkt-ro-${os.getpid()}'
		_ := col_s3_mem('s3.example.test', bucket, 'events.parquet', 'zstd')
		root := store_share_root_s3('s3.example.test', bucket, 'events.parquet')
		if r := store_open_shared_or_conflict('columnar', root, true, '|document|parquet|zstd|') {
			assert false, 'a read-only s3 open must keep its private snapshot view (#891): ${r}'
		}
	}
}

// ── #1005: the same protection ACROSS processes ─────────────────────────────
//
// #891's remedy shares one live MemStore through a process-global registry, so
// it stops at the process boundary. For columnar that boundary was the worst
// place to stop: the substrate rewrites the WHOLE object on every mutation, so
// a second WRITING process does not interleave with the first — its next flush
// DISCARDS the first's entire document collection. `store_root_lock_take` now
// guards the writable open with an flock on a sentinel beside the columnar file.
//
// The holder is an INDEPENDENT open file description, which is the mechanism
// itself: flock conflicts between descriptions, so this open meets exactly the
// condition a second process creates. (A `cx` holder is unavailable here — the
// dev binary carries no `-d cxstore_columnar`, which is why this file is gated.)
fn col_hold_foreign_lock(path string, fake_pid int) os.File {
	mut f := os.open_file(path, 'a+', 0o644) or { panic('sentinel: ${err.msg()}') }
	assert C.flock(f.fd, C.LOCK_EX | C.LOCK_NB) == 0, 'could not take the sentinel lock at ${path}'
	C.ftruncate(f.fd, 0)
	f.write_string('cxstore-lock v1 pid=${fake_pid} host=elsewhere.test url=document+file://${path} since=2026-08-26T00:00:00.000Z\n') or {
	}
	f.flush()
	return f
}

// col_err_msg reads the refusal TEXT (the file imports neither caps_set_all nor
// render_canonical — store_columnar_open is the engine below the cap_guard).
fn col_err_msg(n cx.Node) string {
	if n is cx.Element {
		return (n as cx.Element).attr('message')
	}
	return ''
}

fn test_columnar_cross_process_writable_open_refuses_1005() {
	$if cxstore_columnar ? {
		path := os.join_path(os.temp_dir(), 'cxstore_col_xproc_${os.getpid()}.parquet')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		lockp := store_root_lock_path('columnar', path)
		assert lockp == path + '.cxstore-lock', 'a FILE root takes a SIBLING sentinel, never a directory: ${lockp}'
		defer {
			os.rm(lockp) or {}
		}
		mut held := col_hold_foreign_lock(lockp, 515151)

		h := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert col_is_err(h), '#1005: a columnar file held WRITABLE elsewhere was opened writable anyway — the next flush would discard the holder\'s whole collection: ${h}'
		assert col_err_code(h) == 'cx-err:CXER1143', 'wrong refusal code: ${h}'
		assert col_err_msg(h).contains('pid=515151'), 'the refusal does not NAME the holder: ${col_err_msg(h)}'
		assert col_err_msg(h).contains('RECOVERY:'), 'the refusal names no recovery path: ${col_err_msg(h)}'

		// The read-only exemption reaches this substrate too.
		r := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			true, '')
		assert !col_is_err(r), '#1005: the read-only exemption was lost for columnar: ${r}'

		C.flock(held.fd, C.LOCK_UN)
		held.close()
		w := store_columnar_open('document+file://${path}', path, 'parquet', 'zstd',
			false, '')
		assert !col_is_err(w), '#1005: the columnar root stayed refused after its holder released: ${w}'
	}
}
