module cx

// ── Codec registry — one source of truth for format ⇄ tree ───────────────────
//
// Per spec/core/codec.md §6 and spec/02-inprogress/codec_architecture.md §5/§9
// (Phase 1). The CX tree is the universal pivot: every conversion is
// `format → tree → format`, never `format → format`. A single registry keys
// format name → {parse, parse_bytes, emit, emit_bytes}, and the conversion
// layers (here: `convert()` and the CLI `--from/--to` dispatch) route through
// it rather than maintaining a per-pair `match`.
//
// Relation to the spec struct sketch (codec_architecture.md §5): the sketch
// shows `emit fn (Document) string`. The V member here takes a `ParseResult`
// plus a `lossless` flag instead, because `convert()` must preserve two
// pre-existing behaviours the sketch elides — multi-document inputs
// (ParseResult.is_multi → the `*_docs` emitters) and the XML lossless `<cx:T>`
// image (conversions.md §0.2). The mandatory contract members
// (parse/parse_bytes/emit/emit_bytes) are all present and named per §6.
//
// Phase scope: this registry is populated from the codecs that have a core V
// implementation today — cx/json/csv(+tsv/psv)/xml/yaml/toml as text codecs,
// and ast/cxcol/data-bin as binary codecs (the `*-bytes`-only half of the
// contract, codec.md §4 / §10.5). The markdown/html/url codecs live in the
// stdlib (Phase 2, stdlib_bundle.v) and are registered there, not here.

// Codec is one registry entry. Unset members default to `none`: a text-only
// codec leaves parse_bytes/emit_bytes unset; a binary codec leaves parse/emit
// unset.
pub struct Codec {
pub mut:
	name        string
	// parse: source text → tree. ParseResult carries single|multi documents.
	parse       ?fn (string) !ParseResult
	// parse_bytes: binary input → tree (binary codecs).
	parse_bytes ?fn ([]u8) !Document
	// emit: tree → text. `lossless` requests the codec's lossless image where
	// one exists (XML's `<cx:T>` typing); ignored by codecs without one.
	emit        ?fn (ParseResult, bool) !string
	// emit_bytes: tree → binary output (binary codecs).
	emit_bytes  ?fn (Document) []u8
}

// codec_table is the static base registry, built once at program init from the
// codecs with a `cx`-layer implementation.
const codec_table = build_codec_table()

// ── Runtime overlay: codecs registered by the upper `code` layer ─────────────
//
// `cx` is the lowest layer and cannot import `code`, yet some codecs' canonical
// parser/emitter live there (e.g. the strict json parser in
// vcx/code/stdlib_json.v). The overlay lets `code` install those at init
// (register_codec) so the one registry — read by the CLI, the C ABI,
// convert_by_name and the in-program dispatch — reaches them. Held behind a
// const pointer (no `-enable-globals` needed) and mutated under init ordering:
// V runs every imported module's `init()` before main / the libcx constructor,
// after const initialisation, so the overlay is populated before any lookup.
struct CodecOverlay {
mut:
	codecs map[string]Codec
}

const codec_overlay = &CodecOverlay{}

// register_codec installs (or overrides) a codec in the runtime overlay. Unset
// members of `c` inherit from any base-table entry of the same name, so a
// registration can override just the parser and keep the base emitter — which
// is exactly how `code` backs the `json` codec's parse without touching its
// emit.
pub fn register_codec(c Codec) {
	mut merged := codec_table[c.name] or { Codec{
		name: c.name
	} }
	if pf := c.parse {
		merged.parse = pf
	}
	if pbf := c.parse_bytes {
		merged.parse_bytes = pbf
	}
	if ef := c.emit {
		merged.emit = ef
	}
	if ebf := c.emit_bytes {
		merged.emit_bytes = ebf
	}
	// codec_overlay is a process-global singleton registry. The newer V checker
	// (Jun-11 upstream) disallows aliasing the immutable const pointer as `mut` to
	// mutate its map, so the intentional in-place registration is done under
	// `unsafe` (the established escape hatch for a deliberate global mutation).
	unsafe {
		mut o := codec_overlay
		o.codecs[c.name] = merged
	}
}

fn build_codec_table() map[string]Codec {
	mut t := map[string]Codec{}
	// ── Text codecs (full parse/emit contract) ──────────────────────────────
	t['cx'] = Codec{
		name:  'cx'
		parse: parse_cx
		emit:  cx_codec_emit
	}
	t['xml'] = Codec{
		name:  'xml'
		parse: parse_xml_cx
		emit:  xml_codec_emit
	}
	// json — the strict, lossless parser lives in the upper `code` layer
	// (vcx/code/stdlib_json.v::json_do_parse) which `cx` cannot import. The
	// base entry carries only the emitter; `code` registers the parser into
	// the runtime overlay at init (register_codec, see below). The deprecated
	// element-synthesising `parse_json_cx` is retired (conversions.md §4.1).
	t['json'] = Codec{
		name: 'json'
		emit: json_codec_emit
	}
	t['yaml'] = Codec{
		name:  'yaml'
		parse: parse_yaml_cx
		emit:  yaml_codec_emit
	}
	t['toml'] = Codec{
		name:  'toml'
		parse: parse_toml_cx
		emit:  toml_codec_emit
	}
	// markdown — a bytes ⇄ CX tree codec (codec.md header / §4); there is no
	// markdown CX *syntax*, only this codec. Present as a core V codec on the
	// merged tree (restored parser_md.v / emitter_md.v).
	t['md'] = Codec{
		name:  'md'
		parse: parse_md_cx
		emit:  md_codec_emit
	}
	// csv and its tab/pipe dialects (codec.md §4: TSV/PSV are CSV dialects, not
	// distinct grammars — registered under their CLI-facing names here).
	t['csv'] = Codec{
		name:  'csv'
		parse: csv_codec_parse
		emit:  csv_codec_emit
	}
	t['tsv'] = Codec{
		name:  'tsv'
		parse: tsv_codec_parse
		emit:  tsv_codec_emit
	}
	t['psv'] = Codec{
		name:  'psv'
		parse: psv_codec_parse
		emit:  psv_codec_emit
	}
	// ── Binary codecs (`*-bytes`-only half — codec.md §4 / §10.5) ────────────
	t['cxcol'] = Codec{
		name:        'cxcol'
		parse_bytes: parse_data_bin
		emit_bytes:  emit_data_bin
	}
	t['data-bin'] = Codec{
		name:        'data-bin'
		parse_bytes: parse_data_bin
		emit_bytes:  emit_data_bin
	}
	t['ast'] = Codec{
		name:        'ast'
		parse_bytes: bin_to_doc
		emit_bytes:  emit_ast_bin
	}
	return t
}

// codec_names returns every registered codec name — the registry-driven
// discovery surface the in-program dispatch, the CLI, and the gate read from
// (codec.md §6). Order is unspecified.
pub fn codec_names() []string {
	mut names := codec_table.keys()
	for k in codec_overlay.codecs.keys() {
		if k !in names {
			names << k
		}
	}
	return names
}

// codec_lookup returns the registered Codec for `name`, or none. The runtime
// overlay (register_codec) takes precedence over the static base table.
pub fn codec_lookup(name string) ?Codec {
	if c := codec_overlay.codecs[name] {
		return c
	}
	if c := codec_table[name] {
		return c
	}
	return none
}

// convert_by_name is the registry compose primitive: parse `src` with the
// `from` codec, then emit the tree with the `to` codec. This is the single
// `parse → emit` path that `convert()` and the CLI `--from/--to` dispatch
// share (codec.md §6 / §7). Errors if either name is unknown or the codec
// lacks the requested text half.
pub fn convert_by_name(src string, from string, to string, lossless bool) !string {
	from_codec := codec_lookup(from) or { return error('unknown source format: ${from}') }
	to_codec := codec_lookup(to) or { return error('unknown target format: ${to}') }
	parse_fn := from_codec.parse or { return error('codec ${from} has no text parser') }
	emit_fn := to_codec.emit or { return error('codec ${to} has no text emitter') }
	res := parse_fn(src)!
	return emit_fn(res, lossless)!
}

// parse_to_doc parses `src` with codec `name` and returns the single Document.
// It is the registry-backed bridge for the C ABI loaders (data-bin / ast emit)
// that previously called a per-format `parse_*` helper directly — now that the
// json parser lives in the `code` overlay, those sites route through here so
// they pick up the canonical parser without an upward import.
pub fn parse_to_doc(name string, src string) !Document {
	c := codec_lookup(name) or { return error('unknown codec: ${name}') }
	pf := c.parse or { return error('codec ${name} has no text parser') }
	res := pf(src)!
	if res.is_multi {
		return error('codec ${name}: multi-document (---) streams are not supported here')
	}
	return res.single or { return error('codec ${name}: parse produced no document') }
}

// ── Node-level entry points: the in-program (CX value) codec surface ─────────
//
// The CLI composes `parse → emit` over strings (convert_by_name). In-program,
// a codec call passes and returns ONE `Node` value, so these entry points
// bridge the registry's ParseResult/Document shape to a single Node:
//
//   • parse → a transparent `DocumentNode` (design D7 / codec.md §1) so a
//     multi-root / prolog / doctype source round-trips by construction.
//   • emit  → `node_to_doc` unwraps a DocumentNode (or wraps a bare node in a
//     single-element document) before the registry emitter runs.
//   • the `-bytes` halves are AUTO-DERIVED here (design D4): a binary codec's
//     own parse_bytes/emit_bytes is used when present; a text codec decodes
//     UTF-8 (BOM-stripped) / encodes UTF-8 around the text half. No codec
//     hand-writes a bytes variant.

// codec_strip_bom drops a leading UTF-8 BOM, if present.
fn codec_strip_bom(s string) string {
	if s.len >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		return s[3..]
	}
	return s
}

// codec_parse_node parses `src` with the named codec and returns the tree as a
// single Node (a transparent DocumentNode for whole-document codecs).
pub fn codec_parse_node(name string, src string) !Node {
	c := codec_lookup(name) or { return error('unknown codec: ${name}') }
	pf := c.parse or { return error('codec ${name} has no text parser') }
	res := pf(src)!
	if res.is_multi {
		return error('codec ${name}: multi-document (---) streams are not yet supported by parse → node')
	}
	doc := res.single or { return error('codec ${name}: parse produced no document') }
	return parse_doc_to_value_node(doc)
}

// parse_doc_to_value_node shapes a parsed Document for the in-program parse
// surface (`[$<codec>:parse]`). Per codec.md §7: a document with a SINGLE
// top-level node (no prolog / doctype) returns THAT node directly — so a
// `[$cx:parse "[feature name=helm]"]` is navigable as the element
// (`$f@name`, `$f/child`), not only via the descendant axis (#39). A
// multi-top-level / prolog / doctype document returns the transparent
// DocumentNode (D7), navigated with `//`.
fn parse_doc_to_value_node(doc Document) Node {
	mut has_doctype := false
	if _ := doc.doctype {
		has_doctype = true
	}
	if doc.elements.len == 1 && doc.prolog.len == 0 && !has_doctype {
		return doc.elements[0]
	}
	return doc_to_node(doc)
}

// codec_emit_node emits a single Node as text with the named codec.
pub fn codec_emit_node(name string, n Node, lossless bool) !string {
	c := codec_lookup(name) or { return error('unknown codec: ${name}') }
	ef := c.emit or { return error('codec ${name} has no text emitter') }
	doc := node_to_doc(n)
	return ef(ParseResult{
		single:   doc
		is_multi: false
	}, lossless)!
}

// codec_parse_bytes_node parses bytes → Node. Binary codecs use their native
// parse_bytes; text codecs decode UTF-8 (BOM-stripped) then parse (auto-derived).
pub fn codec_parse_bytes_node(name string, b []u8) !Node {
	c := codec_lookup(name) or { return error('unknown codec: ${name}') }
	if pbf := c.parse_bytes {
		doc := pbf(b)!
		return parse_doc_to_value_node(doc)
	}
	return codec_parse_node(name, codec_strip_bom(b.bytestr()))!
}

// codec_emit_bytes_node emits a Node → bytes. Binary codecs use their native
// emit_bytes; text codecs emit then encode UTF-8 (auto-derived).
pub fn codec_emit_bytes_node(name string, n Node) ![]u8 {
	c := codec_lookup(name) or { return error('unknown codec: ${name}') }
	if ebf := c.emit_bytes {
		return ebf(node_to_doc(n))
	}
	return codec_emit_node(name, n, false)!.bytes()
}

// ── Emit adapters: tree (ParseResult) → text ─────────────────────────────────
// Each mirrors the single/multi/lossless dispatch that lived inline in
// convert_opts() and the per-format to_* helpers, so routing through the
// registry is behaviour-identical.

fn cx_codec_emit(res ParseResult, lossless bool) !string {
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_cx_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_cx(doc)
}

fn xml_codec_emit(res ParseResult, lossless bool) !string {
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return if lossless { emit_xml_docs_lossless(docs) } else { emit_xml_docs(docs) }
	}
	doc := res.single or { return error('no document') }
	return if lossless { emit_xml_lossless(doc) } else { emit_xml(doc) }
}

fn json_codec_emit(res ParseResult, lossless bool) !string {
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_semantic_json_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_semantic_json(doc)
}

fn yaml_codec_emit(res ParseResult, lossless bool) !string {
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_yaml_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_yaml(doc)
}

fn toml_codec_emit(res ParseResult, lossless bool) !string {
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_toml_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_toml(doc)
}

fn md_codec_emit(res ParseResult, lossless bool) !string {
	if res.is_multi {
		docs := res.multi or { return error('no multi docs') }
		return emit_md_docs(docs)
	}
	doc := res.single or { return error('no document') }
	return emit_md(doc)
}

// ── Delimited (csv/tsv/psv) adapters ─────────────────────────────────────────
// These mirror from_delimited (parse) and to_delimited (emit): delimited input
// is single-document, so parse wraps a single Document and emit reads
// res.single. tsv/psv differ from csv only in the delimiter byte.

fn delimited_codec_parse(src string, delim u8) !ParseResult {
	mut opts := default_parse_options()
	opts.delimiter = delim
	doc := parse_delimited(src, opts)!
	return ParseResult{
		single:   doc
		is_multi: false
	}
}

fn delimited_codec_emit(res ParseResult, delim u8) !string {
	doc := res.single or { return error('no document') }
	mut opts := default_emit_options()
	opts.delimiter = delim
	return emit_delimited(doc, opts)
}

fn csv_codec_parse(src string) !ParseResult {
	return delimited_codec_parse(src, `,`)
}

fn csv_codec_emit(res ParseResult, lossless bool) !string {
	return delimited_codec_emit(res, `,`)
}

fn tsv_codec_parse(src string) !ParseResult {
	return delimited_codec_parse(src, u8(`\t`))
}

fn tsv_codec_emit(res ParseResult, lossless bool) !string {
	return delimited_codec_emit(res, u8(`\t`))
}

fn psv_codec_parse(src string) !ParseResult {
	return delimited_codec_parse(src, `|`)
}

fn psv_codec_emit(res ParseResult, lossless bool) !string {
	return delimited_codec_emit(res, `|`)
}
