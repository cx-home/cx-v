module platform
import code {
	mk_err,
}

import cx
import arrow
import os
import sync
import strings

// store_columnar_d_cxstore_columnar.v — #129 PR-D / D5 (#76): the columnar
// (Parquet / Arrow-IPC) document backend, per spec/02-working/
// cxstore_columnar_backend.md (G3 1a/2a/3a/4a/5b).
//
// FRAMING (owner-locked option (a)): columnar is a `document`-model store with a
// columnar AT-REST ENCODING — a PEER to the subtree object model, not built on
// it. It presents the same `[$store]` document API (put-doc / get-doc / list /
// iter / query / delete); columnar is an encoding choice, invisible to the verb
// surface. It is doc-identity only (no Merkle object graph): the store-key is the
// SHA-256 of the doc's strict-canonical bytes, exactly as on every other
// substrate, so `migrate` preserves keys across columnar ↔ any other backend.
//
// FEATURE-GATED: this file (and the `arrow` module / libcx_arrow / libparquet it
// pulls in) compiles ONLY with `-d cxstore_columnar`. The default / core / wasm
// build never links Arrow. stdlib_store.v consults this via a `$if
// cxstore_columnar ?` guard; without the flag, `…?encoding=parquet` errors clearly
// (store_columnar_unbuilt, the gated-substrate posture shared with sqlite/sftp).
// The Arrow file I/O itself additionally needs `-d cx_arrow_files` on the `arrow`
// module (see vcx/Makefile lib-arrow-files + the test-vcx-columnar gate target).
//
// AT-REST LAYOUT (spec §3): the live document collection is assembled into one
// CXCol (`data-bin`) table — each document is one row. Two reserved columns are
// ALWAYS present:
//   __cx_key :: string   — the doc's store-key (doc-identity), for keyed lookup
//                          (get-doc/exists/delete) and `migrate`.
//   __cx_doc :: string   — the doc's canonical TEXT. This is the reconstruction +
//                          integrity ANCHOR: get-doc returns it verbatim and it
//                          re-hashes to __cx_key (CXER1120 on mismatch). Promoted
//                          scalar field columns (step 2) are a REDUNDANT projection
//                          riding alongside, used only for query pushdown — never
//                          the source of truth — so reconstruction stays exact and
//                          TOTAL for any document collection (spec §5 totality).
// The CXCol table is serialized via the existing vcx/arrow bridge
// (write_parquet_data_bin / write_ipc_data_bin), so a CX columnar store IS a
// standard Parquet / Arrow file (spec §1, §9.6 interop) — no new serializer.
//
// Aliases (mutable name → store-key) are NOT documents and would pollute the clean
// record table that the Parquet ecosystem reads; they persist in a tiny sidecar
// (`<path>.cxstore-aliases` for file, a sidecar object for s3) so a columnar store
// loses no data while the data file stays interop-clean.

// store_columnar_reserved_key / _doc are the two reserved column names. The
// double-underscore prefix keeps them out of any plausible user field namespace
// while remaining valid Parquet/Arrow column identifiers.
const store_columnar_reserved_key = '__cx_key'
const store_columnar_reserved_doc = '__cx_doc'

const store_columnar_alias_suffix = '.cxstore-aliases'

// store_columnar_writer/reader dispatch the encoding to the vcx/arrow file
// bridge.
//
// #819: the arrow file bridge is behind its OWN build flag, so this backend's
// flag is not self-sufficient. `-d cxstore_columnar` alone used to fail with
// eight "unknown function: arrow.*" errors pointing at arrow internals, which
// reads as a broken pack rather than a missing flag — and that is exactly how
// #744 was first mis-diagnosed, at the cost of a re-triage.
//
// The requirement is now a STATED contract rather than a build-layer
// coincidence: the arrow-calling arms are `$if cx_arrow_files ?`-guarded and
// the unguarded build refuses at the call with a message naming the flag to
// add. That survives someone invoking `v` directly instead of going through
// `make test-vcx-columnar` (which passes both flags and is green), which
// making one flag imply the other in the Makefile would not.
//
// No shipped-artifact impact: the default `make build` never enables this
// backend, and the whole pack is compile-flag-gated and absent from the
// shipped binary (audit AF-7).
fn store_columnar_missing_arrow_files() IError {
	return error('cxstore columnar file I/O needs the arrow file bridge: rebuild with BOTH ' +
		'`-d cxstore_columnar -d cx_arrow_files` (the supported composition, and what ' +
		'`make test-vcx-columnar` uses) — see #819')
}

fn store_columnar_write_file(framed []u8, path string, encoding string) ! {
	$if cx_arrow_files ? {
		match encoding {
			'arrow-ipc' { arrow.write_ipc_data_bin(framed, path)! }
			else { arrow.write_parquet_data_bin(framed, path)! } // 'parquet' default
		}
		return
	}
	return store_columnar_missing_arrow_files()
}

fn store_columnar_read_file(path string, encoding string) ![]u8 {
	$if cx_arrow_files ? {
		return match encoding {
			'arrow-ipc' { arrow.read_ipc_to_data_bin(path)! }
			else { arrow.read_parquet_to_data_bin(path)! }
		}
	}
	return store_columnar_missing_arrow_files()
}

// store_columnar_open builds a columnar document store over a local file. `path`
// is the resolved .parquet / .arrow file path; `encoding` is 'parquet' (default)
// or 'arrow-ipc'; `codec` is the data-bin compression ('zstd' default per G3-Q4,
// 'none' to disable). On open an existing file is loaded (self-describing — its
// own magic identifies the format; a stated encoding that mismatches is a hard
// error). The caller (stdlib_store.v) has already applied the capability gate.
fn store_columnar_open(url string, path string, encoding string, codec string, read_only bool, schema_text string) cx.Node {
	enc := if encoding == '' { 'parquet' } else { encoding }
	comp := if codec == '' { 'zstd' } else { codec }
	mut ms := &MemStore{
		url:             url
		backend:         'columnar'
		model:           'document'
		encoding:        enc
		compression:     comp
		root:            path
		read_only:       read_only
		is_open:         true
		op_lock:         sync.new_mutex()
		columnar_schema: schema_text
	}
	if os.exists(path) {
		store_columnar_load(mut ms) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
		}
	} else if !read_only {
		// Ensure the parent directory exists so the first flush can persist.
		dir := os.dir(path)
		if dir != '' && dir != '.' {
			os.mkdir_all(dir) or {
				return mk_err('cx-err:CXER1100',
					'E_STORE_UNRESOLVED_BACKEND: cannot create ${dir}: ${err.msg()}')
			}
		}
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}

// store_columnar_compress_mode maps the codec string to the chunked emitter's
// CompressMode (G3-Q4: zstd default; 'none' disables). Parquet applies its own
// codec inside the shim; the data-bin layer compression is reported as the store's
// codec observable.
fn store_columnar_compress_mode(codec string) cx.CompressMode {
	return if codec == 'none' { cx.CompressMode.never } else { cx.CompressMode.always }
}

// ColumnarFieldSpec is one promoted top-level scalar field → its own typed column.
// `exact` is the Q2 exactness bit (RULED #766/#767, 2026-08-10): true iff every
// observed cell's re-synthesis reproduces the stored leaf byte-for-byte — no
// type widening ever occurred and no coerced source (decimal→float,
// temporal→string, …) contributed. Only exact columns may answer query
// pushdown (Q6); non-exact columns still serve the external-analytics
// projection (the projection is redundant — __cx_doc is the exact source).
struct ColumnarFieldSpec {
	name      string
	type_name string // 'int' | 'float' | 'bool' | 'string'
	exact     bool
}

// ColumnarSchemaInfo is the schema pass's full derivation: the promotable
// column specs plus the `deep` name set — names occurring as a doc ROOT or
// deeper than depth 1 anywhere in the corpus. A first path segment in `deep`
// fails Q6's occurs-only-top-level precondition: a descendant query on it
// could match nodes no column carries, so the pushdown declines.
struct ColumnarSchemaInfo {
	specs []ColumnarFieldSpec
	deep  map[string]bool
}

// ColumnarLeaf is one observed scalar-leaf value with its projection typing:
// `token` = the column type this value contributes, `native` = re-synthesis
// from the projected cell reproduces the stored leaf byte-for-byte (decimal→
// float and temporal/bigint→string projections are coerced, never native —
// Q2, RULED #766).
struct ColumnarLeaf {
	val    cx.ScalarValue
	token  string // 'int' | 'float' | 'bool' | 'string'
	native bool
}

// store_columnar_leaf_of maps a ScalarNode to its column contribution.
fn store_columnar_leaf_of(sn cx.ScalarNode) ColumnarLeaf {
	v := sn.value
	match sn.data_type {
		.int_type {
			if v is i64 {
				return ColumnarLeaf{cx.ScalarValue(v), 'int', true}
			}
		}
		.float_type {
			if v is f64 {
				return ColumnarLeaf{cx.ScalarValue(v), 'float', true}
			}
		}
		.bool_type {
			if v is bool {
				return ColumnarLeaf{cx.ScalarValue(v), 'bool', true}
			}
		}
		.string_type {
			if v is string {
				return ColumnarLeaf{cx.ScalarValue(v), 'string', true}
			}
		}
		.decimal_type {
			// RULED #766: decimal → float column (the analytics interop type);
			// coerced — the scale-preserving text does not round-trip through
			// f64, so the column is never exact.
			if v is string {
				return ColumnarLeaf{cx.ScalarValue(v.f64()), 'float', false}
			}
			if v is f64 {
				return ColumnarLeaf{cx.ScalarValue(v), 'float', false}
			}
		}
		else {}
	}
	// Every other kind (bigint / date / datetime / bytes / duration / null …)
	// projects as its canonical text — coerced, never exact.
	return ColumnarLeaf{cx.ScalarValue(cx.scalar_value_str_public(v)), 'string', false}
}

// Column-shape codes for a top-level document field (one-pass classification —
// V autofree frees a sum-type loop var after a single by-value call, so a node is
// handed to exactly one classifier).
const col_shape_nonelem = -1 // a bare scalar body etc. — not a named field
const col_shape_scalar = 0   // `[name <scalar>]` — a depth-1 scalar column
const col_shape_record = 1   // `[name [sub <scalar>]…]` — a FLAT scalar sub-record
const col_shape_complex = 2  // deeper-nested / attributed / mixed — stays in __cx_doc

// store_columnar_scalar_leaf classifies a node as a `[name <scalar>]` leaf in ONE
// pass: (name, is-scalar-leaf, typed leaf). name is '' for a non-element.
// ScalarNode carries numbers/typed; TextNode is the string/atom leaf (native —
// the cell text reproduces the leaf verbatim).
fn store_columnar_scalar_leaf(n cx.Node) (string, bool, ColumnarLeaf) {
	if n is cx.Element {
		name := n.name
		if n.attrs.len == 0 && n.items.len == 1 {
			item := n.items[0]
			if item is cx.ScalarNode {
				return name, true, store_columnar_leaf_of(item)
			}
			if item is cx.TextNode {
				return name, true, ColumnarLeaf{cx.ScalarValue(item.value), 'string', true}
			}
		}
		return name, false, ColumnarLeaf{}
	}
	return '', false, ColumnarLeaf{}
}

// store_columnar_child_shape classifies one top-level document field in a single
// pass: its name, its shape (scalar / flat-record / complex), the scalar value (for
// a scalar field), and the flat sub-record's (sub-name, sub-value) pairs (for a
// record). A field promotes to a column only as a depth-1 scalar (`name`) or a
// one-level FLATTENED record (`name.sub`, all subs scalar leaves); anything deeper,
// attributed, or mixed is `complex` and rides losslessly in __cx_doc (spec §5
// totality; G3-Q2=a one-level-nested promotion realized as column flattening, the
// standard analytics-columnar form — typed, pushdown-able, DuckDB/pandas-clean).
fn store_columnar_child_shape(n cx.Node) (string, int, ColumnarLeaf, []string, []ColumnarLeaf) {
	if n is cx.Element {
		name := n.name
		if n.attrs.len != 0 {
			return name, col_shape_complex, ColumnarLeaf{}, []string{}, []ColumnarLeaf{}
		}
		// scalar leaf?
		if n.items.len == 1 {
			item := n.items[0]
			if item is cx.ScalarNode {
				return name, col_shape_scalar, store_columnar_leaf_of(item), []string{}, []ColumnarLeaf{}
			}
			if item is cx.TextNode {
				return name, col_shape_scalar, ColumnarLeaf{cx.ScalarValue(item.value), 'string', true}, []string{}, []ColumnarLeaf{}
			}
		}
		// flat scalar sub-record? every child must itself be a scalar leaf
		// (one level deep, no deeper nesting) — and no DUPLICATE sub-name
		// (RULED #767: a column holds one cell; duplicates cannot round-trip).
		if n.items.len >= 1 {
			mut sn := []string{cap: n.items.len}
			mut sv := []ColumnarLeaf{cap: n.items.len}
			mut flat := true
			for c in n.items {
				cname, ok, leaf := store_columnar_scalar_leaf(c)
				if !ok || cname == '' || cname in sn {
					flat = false
					break
				}
				sn << cname
				sv << leaf
			}
			if flat && sn.len > 0 {
				return name, col_shape_record, ColumnarLeaf{}, sn, sv
			}
		}
		return name, col_shape_complex, ColumnarLeaf{}, []string{}, []ColumnarLeaf{}
	}
	return '', col_shape_nonelem, ColumnarLeaf{}, []string{}, []ColumnarLeaf{}
}

// store_columnar_unify_type widens two observed type tokens for one field to a
// column type that can carry both: int+float → float; anything else mixed →
// string (the scalar's canonical text), which is always representable.
fn store_columnar_unify_type(cur string, tok string) string {
	if cur == '' {
		return tok
	}
	if cur == tok {
		return cur
	}
	if (cur == 'int' || cur == 'float') && (tok == 'int' || tok == 'float') {
		return 'float'
	}
	return 'string'
}

// store_columnar_register_path records one promotable column path + widens its
// union type, preserving first-seen order, and maintains the Q2 exactness bit:
// a coerced observation (non-native leaf) or ANY widening (two distinct
// observed tokens — the earlier observations no longer re-synthesize
// byte-exactly under the widened type) marks the column non-exact.
fn store_columnar_register_path(mut order []string, mut types map[string]string, mut exact map[string]bool, path string, leaf ColumnarLeaf) {
	if path !in types {
		order << path
		exact[path] = true
	}
	cur := types[path]
	if !leaf.native || (cur != '' && cur != leaf.token) {
		exact[path] = false
	}
	types[path] = store_columnar_unify_type(cur, leaf.token)
}

// store_columnar_collect_deep records every element name occurring as the doc
// ROOT (depth 0) or deeper than depth 1 — the Q6 occurs-only-top-level
// precondition's complement (#767/#768).
fn store_columnar_collect_deep(node cx.Node, depth int, mut deep map[string]bool) {
	if node is cx.Element {
		if depth != 1 {
			deep[node.name] = true
		}
		for c in node.items {
			store_columnar_collect_deep(c, depth + 1, mut deep)
		}
	}
}

// store_columnar_schema derives the SOUND promotable column schema over the live
// collection (spec §5: schema = union, nullable; G3-Q2=a one-level promotion via
// column FLATTENING). A top-level field is promotable as a depth-1 scalar column
// (`name`) iff it is a scalar leaf in EVERY doc that has it, or as FLATTENED depth-2
// columns (`name.sub`) iff it is a flat scalar sub-record in every doc that has it.
// A name observed in MORE THAN ONE shape (scalar vs record), or ever complex
// (deeper-nested / attributed / mixed), is NOT promoted — so a column null ⟺ the
// PATH is absent, which keeps predicate pushdown EXACT. Non-promoted structure
// rides losslessly in __cx_doc (totality). Columns are sorted for a reproducible
// file (spec §5).
fn store_columnar_schema(ms &MemStore) []ColumnarFieldSpec {
	return store_columnar_schema_info(ms).specs
}

fn store_columnar_schema_info(ms &MemStore) ColumnarSchemaInfo {
	// Pass 1 — each top-level field name's observed shapes (OR of 1<<shape). A
	// reserved-name collision is force-marked complex so it never promotes; so
	// is a DUPLICATED top-level name (the same name twice in one doc — RULED
	// #767: a column holds one cell). The same pass collects the `deep` name
	// set (root names + names deeper than depth 1) for Q6's
	// occurs-only-top-level precondition.
	mut shapes := map[string]int{}
	mut deep := map[string]bool{}
	for h in ms.doc_order {
		if h.starts_with('code:') {
			continue
		}
		doc := cx.parse(ms.docs[h]) or { continue }
		if doc.elements.len == 0 {
			continue
		}
		root := doc.elements[0]
		store_columnar_collect_deep(root, 0, mut deep)
		if root is cx.Element {
			mut seen_in_doc := map[string]bool{}
			for child in root.items {
				name, shape, _, _, _ := store_columnar_child_shape(child)
				if name == '' {
					continue
				}
				if name == store_columnar_reserved_key || name == store_columnar_reserved_doc {
					shapes[name] = 1 << col_shape_complex
					continue
				}
				if name in seen_in_doc {
					shapes[name] = 1 << col_shape_complex
					continue
				}
				seen_in_doc[name] = true
				cur := shapes[name]
				shapes[name] = cur | (1 << shape)
			}
		}
	}
	// Pass 2 — collect promotable PATHS + union types + exactness bits for the
	// consistently-shaped names (pure scalar → `name`; pure flat-record →
	// `name.sub`).
	scalar_only := 1 << col_shape_scalar
	record_only := 1 << col_shape_record
	mut order := []string{}
	mut types := map[string]string{}
	mut exact := map[string]bool{}
	for h in ms.doc_order {
		if h.starts_with('code:') {
			continue
		}
		doc := cx.parse(ms.docs[h]) or { continue }
		if doc.elements.len == 0 {
			continue
		}
		root := doc.elements[0]
		if root is cx.Element {
			for child in root.items {
				name, shape, leaf, sn, sv := store_columnar_child_shape(child)
				if name == '' {
					continue
				}
				sh := shapes[name]
				if sh == scalar_only && shape == col_shape_scalar {
					store_columnar_register_path(mut order, mut types, mut exact, name,
						leaf)
				} else if sh == record_only && shape == col_shape_record {
					for i, subn in sn {
						store_columnar_register_path(mut order, mut types, mut exact,
							'${name}.${subn}', sv[i])
					}
				}
			}
		}
	}
	mut specs := []ColumnarFieldSpec{}
	for p in order {
		specs << ColumnarFieldSpec{
			name:      p
			type_name: types[p]
			exact:     exact[p]
		}
	}
	specs.sort(a.name < b.name)
	return ColumnarSchemaInfo{
		specs: specs
		deep:  deep
	}
}

// store_columnar_coerce_cell projects a field's scalar value into its unified
// column type. int/float/bool columns carry the native scalar (int widened to
// float as needed); a string column carries the scalar's canonical text.
fn store_columnar_coerce_cell(v cx.ScalarValue, type_name string) cx.TableCellValue {
	match type_name {
		'int' {
			if v is i64 {
				return cx.TableCellValue(v)
			}
		}
		'float' {
			if v is f64 {
				return cx.TableCellValue(v)
			}
			if v is i64 {
				return cx.TableCellValue(f64(v))
			}
		}
		'bool' {
			if v is bool {
				return cx.TableCellValue(v)
			}
		}
		else {
			return cx.TableCellValue(cx.scalar_value_str_public(v))
		}
	}
	return cx.TableCellValue(cx.NullValue{})
}

// store_columnar_row_cells builds the promoted-column cells for one doc: each
// field's scalar value coerced to its column type, or null when the doc lacks it.
fn store_columnar_row_cells(body string, fields []ColumnarFieldSpec) []cx.TableCellValue {
	mut vals := map[string]cx.ScalarValue{}
	if doc := cx.parse(body) {
		if doc.elements.len > 0 {
			root := doc.elements[0]
			if root is cx.Element {
				for child in root.items {
					name, shape, leaf, sn, sv := store_columnar_child_shape(child)
					if name == '' {
						continue
					}
					if shape == col_shape_scalar {
						vals[name] = leaf.val
					} else if shape == col_shape_record {
						for i, subn in sn {
							vals['${name}.${subn}'] = sv[i].val
						}
					}
				}
			}
		}
	}
	mut out := []cx.TableCellValue{cap: fields.len}
	for f in fields {
		if v := vals[f.name] {
			out << store_columnar_coerce_cell(v, f.type_name)
		} else {
			out << cx.TableCellValue(cx.NullValue{})
		}
	}
	return out
}

// store_columnar_build_framed assembles the live doc collection into a CXCol table
// Document and returns its framed bytes. Columns: the two reserved columns
// __cx_key + __cx_doc, then the promoted scalar field columns (the pushdown
// projection — redundant with __cx_doc, never the reconstruction source).
fn store_columnar_build_framed(ms &MemStore, fields []ColumnarFieldSpec) ![]u8 {
	mut cols := [
		cx.TableColumn{
			name:      store_columnar_reserved_key
			type_name: 'string'
		},
		cx.TableColumn{
			name:      store_columnar_reserved_doc
			type_name: 'string'
		},
	]
	for f in fields {
		cols << cx.TableColumn{
			name:      f.name
			type_name: f.type_name
		}
	}
	mut rows := [][]cx.TableCellValue{cap: ms.doc_order.len}
	for h in ms.doc_order {
		body := ms.docs[h]
		mut row := [cx.TableCellValue(h), cx.TableCellValue(body)]
		if fields.len > 0 {
			row << store_columnar_row_cells(body, fields)
		}
		rows << row
	}
	mut td := &cx.TableData{
		cols: cols
		rows: rows
	}
	root := cx.Element{
		name:  'cxstore_columnar'
		table: td
	}
	doc := cx.Document{
		elements: [cx.Node(root)]
	}
	return cx.emit_data_bin_chunked(doc, cx.ChunkedEmitOptions{
		compress: store_columnar_compress_mode(ms.compression)
	})!
}

// store_columnar_temp_path is a process-unique scratch path for the arrow bridge
// (which is path-based) when the durable substrate is s3 (bytes, not a path).
fn store_columnar_temp_path(ms &MemStore, tag string) string {
	ext := if ms.encoding == 'arrow-ipc' { 'arrow' } else { 'parquet' }
	safe := ms.columnar_s3_key.replace('/', '_')
	return os.join_path(os.temp_dir(), 'cxcol_${tag}_${os.getpid()}_${safe}.${ext}')
}

// store_columnar_flush serializes the live collection to the columnar file/object
// (and the alias sidecar). A write failure PROPAGATES (`!`, matching
// store_persist): the in-process state stays authoritative for the open handle
// and the triggering op raises instead of acknowledging an un-landed write.
// read_only stores never flush. Recomputes the promoted-schema pushdown flag
// each flush.
fn store_columnar_flush(mut ms MemStore) ! {
	if ms.read_only {
		return
	}
	fields := store_columnar_schema(ms)
	ms.columnar_pushdown = fields.len > 0
	framed := store_columnar_build_framed(ms, fields) or {
		return error('columnar ${ms.url}: frame build failed: ${err.msg()}')
	}
	if mut s3 := ms.columnar_s3 {
		// s3 (G3-Q5=b): the arrow bridge is path-based, so write the columnar file to
		// a temp path, then PUT its bytes as a SINGLE object. The object is a standard
		// Parquet/Arrow file. The alias sidecar is a second object. A non-2xx PUT is
		// a raised failure (#213: never a phantom success).
		tmp := store_columnar_temp_path(ms, 'w')
		store_columnar_write_file(framed, tmp, ms.encoding) or {
			return error('columnar ${ms.url}: file write failed: ${err.msg()}')
		}
		bytes := os.read_bytes(tmp) or {
			os.rm(tmp) or {}
			return error('columnar ${ms.url}: temp read-back failed: ${err.msg()}')
		}
		os.rm(tmp) or {}
		st, ok := s3.store(ms.columnar_s3_key, bytes)
		if !ok || (st != 200 && st != 201) {
			return error('columnar s3 put status ${st} for ${ms.url}')
		}
		st2, ok2 := s3.store(ms.columnar_s3_key + store_columnar_alias_suffix,
			store_columnar_alias_text(ms).bytes())
		if !ok2 || (st2 != 200 && st2 != 201) {
			return error('columnar s3 alias-sidecar put status ${st2} for ${ms.url}')
		}
		return
	}
	if ms.root == '' {
		return
	}
	// #221 hardening: the local flush is a WHOLE-FILE rewrite; writing straight to
	// ms.root would let a crash mid-write leave a torn parquet against the live
	// path. Write to a temp path in the SAME directory (same filesystem — rename
	// is atomic; os.temp_dir() could be a different mount, where mv degrades to
	// copy+delete), then rename — a (re)open sees either the old file or the new
	// file, whole (mirrors the s3 arm's single-object PUT atomicity).
	tmp := '${ms.root}.tmp${os.getpid()}'
	store_columnar_write_file(framed, tmp, ms.encoding) or {
		return error('columnar ${ms.url}: file write failed: ${err.msg()}')
	}
	os.mv(tmp, ms.root) or {
		os.rm(tmp) or {}
		return error('columnar ${ms.url}: atomic rename failed: ${err.msg()}')
	}
	store_columnar_flush_aliases(ms)!
}

// store_columnar_alias_text serializes the alias map to the sidecar wire form
// (always emits the header so an empty map supersedes a prior sidecar).
fn store_columnar_alias_text(ms &MemStore) string {
	mut sb := strings.new_builder(256)
	sb.write_string('CXSTORE-ALIASES\tv1\n')
	for a in ms.alias_order {
		hash := ms.aliases[a]
		sb.write_string('A\t${a.len}\t${hash}\n')
		sb.write_string(a)
		sb.write_string('\n')
	}
	return sb.str()
}

// store_columnar_flush_aliases persists the alias map to the file:// sidecar. When
// the store has no aliases the sidecar is removed (so it never goes stale).
fn store_columnar_flush_aliases(ms &MemStore) ! {
	sidecar := ms.root + store_columnar_alias_suffix
	if ms.alias_order.len == 0 {
		if os.exists(sidecar) {
			os.rm(sidecar) or {}
		}
		return
	}
	os.write_file(sidecar, store_columnar_alias_text(ms)) or {
		return error('columnar alias sidecar write failed: ${err.msg()}')
	}
}

// store_columnar_find_nl — index of the next `\n` at/after `start`, -1 when
// none. (Was the stdlib_store `store_find_nl` helper; a later refactor
// removed it with its stdlib callers, leaving THIS pack — never compiled by
// the default gates — as the sole caller: #744, the columnar backend dead
// on arrival post-I3. Restored here with its one consumer, pack-gated.)
fn store_columnar_find_nl(s string, start int) int {
	for j := start; j < s.len; j++ {
		if s[j] == `\n` {
			return j
		}
	}
	return -1
}

// store_columnar_apply_alias_text replays a sidecar wire form into ms.aliases.
fn store_columnar_apply_alias_text(mut ms MemStore, content string) {
	n := content.len
	hnl := store_columnar_find_nl(content, 0)
	if hnl < 0 {
		return
	}
	mut i := hnl + 1
	for i < n {
		le := store_columnar_find_nl(content, i)
		if le < 0 {
			break
		}
		line := content[i..le]
		i = le + 1
		parts := line.split('\t')
		if parts.len < 3 || parts[0] != 'A' {
			break
		}
		alen := parts[1].int()
		hash := parts[2]
		if i + alen > n {
			break
		}
		name := content[i..i + alen]
		i += alen + 1
		if name !in ms.aliases {
			ms.alias_order << name
		}
		ms.aliases[name] = hash
	}
}

// store_columnar_load reads the columnar file/object (if present) into ms.docs /
// doc_order, verifying each row's __cx_doc re-hashes to its __cx_key (spec §3
// integrity; CXER1120 on mismatch — never a silent wrong doc). Then replays the
// alias sidecar. An absent file/object is an empty store, not an error.
fn store_columnar_load(mut ms MemStore) ! {
	mut framed := []u8{}
	if mut s3 := ms.columnar_s3 {
		st, body, ok := s3.fetch('GET', ms.columnar_s3_key)
		if !ok {
			return error('columnar s3 fetch failed')
		}
		if st == 404 {
			store_columnar_load_aliases(mut ms)
			return
		}
		if st != 200 {
			return error('columnar s3 GET status ${st}')
		}
		// arrow bridge is path-based: stage the object bytes to a temp file, read it.
		tmp := store_columnar_temp_path(ms, 'r')
		mut f := os.create(tmp) or { return error('columnar temp create: ${err.msg()}') }
		f.write(body) or {
			f.close()
			os.rm(tmp) or {}
			return error('columnar temp write: ${err.msg()}')
		}
		f.close()
		framed = store_columnar_read_file(tmp, ms.encoding) or {
			os.rm(tmp) or {}
			return error('columnar s3 decode failed (${ms.encoding}): ${err.msg()}')
		}
		os.rm(tmp) or {}
	} else {
		if !os.exists(ms.root) {
			store_columnar_load_aliases(mut ms)
			return
		}
		framed = store_columnar_read_file(ms.root, ms.encoding) or {
			return error('columnar read failed (${ms.encoding}): ${err.msg()}')
		}
	}
	doc := cx.parse_data_bin(framed) or {
		return error('columnar data-bin decode failed: ${err.msg()}')
	}
	td := store_columnar_table_of(doc) or {
		return error('columnar file has no table payload')
	}
	key_idx, doc_idx := store_columnar_reserved_indices(td) or {
		return error('columnar table missing reserved ${store_columnar_reserved_key}/${store_columnar_reserved_doc} columns')
	}
	for row in td.rows {
		if key_idx >= row.len || doc_idx >= row.len {
			return error('columnar row has fewer cells than columns')
		}
		key := store_columnar_cell_str(row[key_idx])
		body := store_columnar_cell_str(row[doc_idx])
		// code: entries are verbatim source (not data docs) — keyed raw, not by a
		// canonical hash, so they skip the re-hash check (mirrors store_migrate).
		if !key.starts_with('code:') {
			rehash := cx.cx_text_hash(body) or {
				return error('rehash failed for ${key}: ${err.msg()}')
			}
			if rehash != key {
				return error('stored ${key} rehashes to ${rehash}')
			}
		}
		if key !in ms.docs {
			ms.docs[key] = body
			ms.doc_order << key
		}
	}
	// Recompute the promoted-schema pushdown flag from the loaded collection (the
	// promoted columns themselves are a redundant projection — the docs are rebuilt
	// from __cx_doc — so the schema is re-derived, not trusted from the file).
	ms.columnar_pushdown = store_columnar_schema(ms).len > 0
	store_columnar_load_aliases(mut ms)
}

// store_columnar_load_aliases replays the alias sidecar (file) or sidecar object
// (s3) into ms.aliases.
fn store_columnar_load_aliases(mut ms MemStore) {
	if mut s3 := ms.columnar_s3 {
		st, body, ok := s3.fetch('GET', ms.columnar_s3_key + store_columnar_alias_suffix)
		if ok && st == 200 {
			store_columnar_apply_alias_text(mut ms, body.bytestr())
		}
		return
	}
	sidecar := ms.root + store_columnar_alias_suffix
	if !os.exists(sidecar) {
		return
	}
	content := os.read_file(sidecar) or { return }
	store_columnar_apply_alias_text(mut ms, content)
}

// store_columnar_open_s3 opens a columnar document store backed by a single s3
// object (G3-Q5=b). The columnar file bytes are PUT/GET as one object at the URL
// path. The capability gate (`net`) was applied by the dispatcher.
fn store_columnar_open_s3(base_url string, encoding string, codec string, read_only bool, auth map[string]string, schema_text string) cx.Node {
	mut rb, errn, ok := store_remote_parse(base_url)
	if !ok {
		return errn
	}
	// store_remote_parse folds the whole URL path into rb.prefix (key-prefix
	// semantics); columnar stores ONE object AT the path. Recover it as the object
	// key and clear the prefix so the transport addresses the object directly.
	mut key := rb.prefix.trim_right('/')
	if key == '' {
		key = 'cxstore.parquet'
	}
	rb.prefix = ''
	enc := if encoding == '' { 'parquet' } else { encoding }
	comp := if codec == '' { 'zstd' } else { codec }
	mut ms := &MemStore{
		url:             base_url
		backend:         'columnar'
		model:           'document'
		encoding:        enc
		compression:     comp
		read_only:       read_only
		is_open:         true
		op_lock:         sync.new_mutex()
		columnar_s3:     S3Transport(&S3HttpTransport{
			rb: rb
		})
		columnar_s3_key: key
		columnar_schema: schema_text
	}
	store_columnar_load(mut ms) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	id := store_register(ms)
	return store_handle_element(id, ms)
}

// store_columnar_table_of returns the single table-bodied root element's TableData
// from a parsed data-bin Document (the chunked reader wraps a named table under a
// 1-pair map, which parse_data_bin materializes back onto the element).
fn store_columnar_table_of(doc cx.Document) ?&cx.TableData {
	for el in doc.elements {
		if el is cx.Element {
			if td := el.table_opt() {
				return td
			}
		}
	}
	return none
}

// store_columnar_reserved_indices locates the __cx_key / __cx_doc columns.
fn store_columnar_reserved_indices(td &cx.TableData) ?(int, int) {
	mut ki := -1
	mut di := -1
	for i, c in td.cols {
		if c.name == store_columnar_reserved_key {
			ki = i
		} else if c.name == store_columnar_reserved_doc {
			di = i
		}
	}
	if ki < 0 || di < 0 {
		return none
	}
	return ki, di
}

// store_columnar_cell_str extracts a cell's value as a string (the reserved
// columns are always string-typed; a non-string cell degrades to its V string
// form, which never happens for the reserved columns we write).
fn store_columnar_cell_str(cell cx.TableCellValue) string {
	return match cell {
		string { cell }
		i64 { cell.str() }
		f64 { cell.str() }
		bool { cell.str() }
		else { '' }
	}
}

// store_columnar_cell_to_node rebuilds a column cell as the leaf node a `[field
// value]` projection element carries: TextNode for strings, typed ScalarNode for
// numbers/bools.
fn store_columnar_cell_to_node(cell cx.TableCellValue) cx.Node {
	return match cell {
		string { cx.TextNode{
			value: cell
		} }
		i64 { cx.ScalarNode{
			data_type: cx.ScalarType.int_type
			value:     cx.ScalarValue(cell)
		} }
		f64 { cx.ScalarNode{
			data_type: cx.ScalarType.float_type
			value:     cx.ScalarValue(cell)
		} }
		bool { cx.ScalarNode{
			data_type: cx.ScalarType.bool_type
			value:     cx.ScalarValue(cell)
		} }
		else { cx.TextNode{
			value: ''
		} }
	}
}

// store_columnar_read_framed fetches the durable columnar payload as framed CXCol
// bytes — from the file (file substrate) or the single s3 object (s3) — without
// touching the in-memory docs. Used by the pushdown executor to read a column
// projection straight off the durable store. none when absent/unreadable.
fn store_columnar_read_framed(ms &MemStore) ?[]u8 {
	if mut s3 := ms.columnar_s3 {
		st, body, ok := s3.fetch('GET', ms.columnar_s3_key)
		if !ok || st != 200 {
			return none
		}
		tmp := store_columnar_temp_path(ms, 'q')
		mut f := os.create(tmp) or { return none }
		f.write(body) or {
			f.close()
			os.rm(tmp) or {}
			return none
		}
		f.close()
		fr := store_columnar_read_file(tmp, ms.encoding) or {
			os.rm(tmp) or {}
			return none
		}
		os.rm(tmp) or {}
		return fr
	}
	if ms.root == '' || !os.exists(ms.root) {
		return none
	}
	return store_columnar_read_file(ms.root, ms.encoding) or { return none }
}

// store_columnar_query_matches is the columnar PUSHDOWN executor for
// [$store:query] (spec Q6, exactness-gated — RULED #766/#767/#768,
// 2026-08-10). The pushdown answers exactly when its answer provably equals
// the row scan's: the DESCENDANT forms `//field` / `//parent/child` only
// (absolute/relative paths address the per-doc ROOT under document-node
// anchoring — not a column), the first segment's name occurs ONLY at top
// level (never a doc root, never deeper — else a descendant query could
// match nodes no column carries), and the answering column is
// exactness-marked (Q2: no widening, no coerced source — decimal-sourced
// float columns decline here and row-scan instead). It answers by reading
// ONLY that column + __cx_key from the file (parse_data_bin_projected — the
// other columns cursor-skip, never boxed; stream 17 W4, #710 item 2),
// returning the same (doc-hash, match) pairs the row scan produces, which
// the caller wraps into the L97 flat provenance relation — the #711
// shape-AND-answer parity contract.
//
// Final-step PREDICATES lower too (W4): a promoted+exact column's matched
// elements are shape-invariant BY PROMOTION — scalar leaves, no attrs, no
// element children, one fixed name — so the row scan's per-candidate
// store_elem_matches_predicates verdict is the SAME for every row. The
// executor evaluates that same function ONCE against the invariant shape:
// false ⇒ zero matches, true ⇒ every non-null row matches. The verdict is
// computed by the identical predicate engine the row scan uses (including
// its fail-closed arms), so parity holds by construction, not by a
// re-implementation. Likewise a trailing attribute axis (`/@x`): promoted
// leaves carry no attributes, so the answer is provably empty. Both arms
// run store_query_plan FIRST and return none on refusal — a path the row
// lane would refuse with CXER1709 is never answered here.
//
// Returns none on any failed precondition or a deeper path → the caller
// materializes rows from __cx_doc. This is the honest pushdown report:
// `some` means the column fast-path ran; `none` means full-scan fallback —
// never a fast WRONG answer and never a silent full-scan masquerading as
// pushdown.
fn store_columnar_query_matches(ms &MemStore, cxpath string) ?[]StoreQueryMatch {
	target := cxpath.trim_space()
	if !target.starts_with('//') {
		// Absolute (`/x` = the root element) / relative forms are not
		// column-projectable — root names vary per doc.
		return none
	}
	// The SAME plan the row scan runs: a path it refuses (CXER1709) is
	// never answered from columns.
	attr_name, elem_path := store_query_split_attr(target)
	path, preds := store_query_plan(elem_path) or { return none }
	if path.form != cx.PathForm.descendant {
		return none
	}
	// Map a 1- or 2-step name path to a column: `//field` → `field`
	// (depth-1), `//parent/child` → `parent.child` (a FLATTENED
	// one-level-nested column, CHILD axis only — `//a//b` may match deeper
	// than the column carries). Deeper paths are not column-projectable.
	if path.steps.len < 1 || path.steps.len > 2 {
		return none
	}
	if path.steps.len == 2 && path.steps[1].axis != cx.PathAxis.child {
		return none
	}
	mut segs := []string{cap: path.steps.len}
	for st in path.steps {
		segs << st.node_test.trim_space()
	}
	mut col_name := segs[0]
	mut leaf_name := segs[0]
	if segs.len == 2 {
		col_name = '${segs[0]}.${segs[1]}'
		leaf_name = segs[1]
	}
	if '' in segs {
		return none
	}
	if col_name == store_columnar_reserved_key || col_name == store_columnar_reserved_doc {
		return none
	}
	info := store_columnar_schema_info(ms)
	if segs[0] in info.deep {
		// The first segment's name occurs as a doc root or deeper than depth 1
		// somewhere in the corpus — a descendant query could match nodes the
		// column does not carry. Row scan answers.
		return none
	}
	mut promoted := false
	mut exact := false
	for s in info.specs {
		if s.name == col_name {
			promoted = true
			exact = s.exact
			break
		}
	}
	if !promoted || !exact {
		return none
	}
	if attr_name != '' {
		// The attribute axis on a promoted column: promotion admits ONLY
		// attr-less scalar leaves (store_columnar_child_shape), so no
		// candidate carries the attribute — provably empty, answered
		// without touching the file.
		return []StoreQueryMatch{}
	}
	if preds.len > 0 {
		// The row-invariant predicate verdict (W4): every candidate the walk
		// yields for this column IS `[leaf <scalar>]` — no attrs, no element
		// children — so one evaluation of the row scan's own predicate
		// function decides all rows.
		invariant := cx.Element{
			name: leaf_name
		}
		if !store_elem_matches_predicates(invariant, preds) {
			return []StoreQueryMatch{}
		}
	}
	// Read the column projection from the durable file/object (the columnar fast
	// path) — only the projected column + __cx_key MATERIALIZE; every other
	// column's payload cursor-skips in the reader (no row materialization on
	// the pushdown path — cxstore_columnar_backend §6).
	framed := store_columnar_read_framed(ms) or { return none }
	doc := cx.parse_data_bin_projected(framed, [col_name, store_columnar_reserved_key]) or {
		return none
	}
	td := store_columnar_table_of(doc) or { return none }
	key_idx, _ := store_columnar_reserved_indices(td) or { return none }
	mut col_idx := -1
	for i, c in td.cols {
		if c.name == col_name {
			col_idx = i
			break
		}
	}
	if col_idx < 0 {
		return none
	}
	mut results := []StoreQueryMatch{}
	for row in td.rows {
		if key_idx >= row.len || col_idx >= row.len {
			continue
		}
		cell := row[col_idx]
		if cell is cx.NullValue {
			continue // field absent in this doc
		}
		key := store_columnar_cell_str(row[key_idx])
		field_el := cx.Element{
			name:  leaf_name
			items: [store_columnar_cell_to_node(cell)]
		}
		results << StoreQueryMatch{
			hash: key
			node: cx.Node(field_el)
		}
	}
	return results
}
