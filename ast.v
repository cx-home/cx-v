module cx

// ── Node sum type ─────────────────────────────────────────────────────────────

pub type Node = Element
	| TextNode
	| ScalarNode
	| AliasNode
	| CommentNode
	| PINode
	| XMLDeclNode
	| CXDirectiveNode
	| EntityRefNode
	| RawTextNode
	| BlockContentNode
	| EntityDeclNode
	| ElementDeclNode
	| AttlistDeclNode
	| NotationDeclNode
	| PEReferenceNode
	// DoctypeDecl joins the Node sum-type so a `[!DOCTYPE …]` can be carried as a
	// standalone node value (program reader's node_lit seam + parse_data_node).
	// It remains the type of `Document.doctype` (prolog position); membership in
	// Node only adds the standalone-node usage. The three emitters (CX/JSON/XML)
	// already have doctype renderers — the Node-match arms delegate to them.
	| DoctypeDecl
	| ConditionalSectNode
	| InterpolationNode
	| EvalDirectiveNode
	| SequenceNode
	| ArrayNode
	| MapNode
	// First-class program-AST value kinds.
	// MatchNode + ModifyNode join the Node sum-type so the standalone
	// AST helpers (`match_node.v` / `modify_node.v`) can participate in
	// emitter / decoder / dispatcher pattern-matches uniformly. Wire
	// codecs (`match_node_codec.v` 0x14 / `modify_node_codec.v` 0x15)
	// were landed standalone at Phase 2.4 / 2.5 — the graft here wires
	// them into `binary.v::encode_node` / `decode_node` so a v8 buffer
	// can carry these variants embedded in a Document.
	//
	// PathNode is intentionally LEFT OUT of the sum-type at this graft
	// — its codec (`path_node_codec.v` 0x13) remains standalone for now
	// per the Phase 2.x sequencing plan. The path here is to graft it
	// alongside the structural ProgramExpr work in a later phase.
	| MatchNode
	| ModifyNode
	// DocumentNode: the first-class transparent carrier for a whole
	// CX document as ONE node (codec.md §1 — "every document is one CX node
	// tree"; design D7). Mirrors `Document` (prolog/doctype/elements) so a
	// `[$cx:parse]` of a multi-root / prolog-bearing / doctype-bearing source
	// round-trips by construction: emit unwraps it back to a `Document` and
	// renders children as bare top-level, prolog as prolog, doctype as doctype.
	// It is the codec pivot's parse return value; it is NOT a surface form (no
	// grammar production yields it) and emitters render it transparently.
	| DocumentNode
	// Iterator value kind. Lazy + memoized stream of
	// items; materializes to a Sequence at every host-language /
	// emitter boundary (D7). Identity-only equality per OQ4 — two
	// IteratorNode values compare equal iff their `id` field matches.
	// W3a foundation: source is captured opaquely as a `source_kind`
	// tag + evaluated argument list (e.g. range(start, end, step));
	// W3c expands to closure-style generators backing [?map] / [?filter]
	// / [?take] / etc. result-form combinators.
	| IteratorNode

// ── Document ──────────────────────────────────────────────────────────────────

pub struct Document {
pub mut:
	prolog   []Node
	doctype  ?DoctypeDecl
	elements []Node
}

// ── Element ───────────────────────────────────────────────────────────────────
//
// Element header diet (gate 30.5 /).
//
// The previous Element carried seven `?string` fields + an inline
// `?TableData` directly, totalling ~536 bytes per element struct.
// Spine-copy under [?modify] paid that cost on every spine-frame copy
// — driving heap-per-match well above the 1 KB / 100 KB perf gates.
//
// The diet pools the eight rarely-set optional fields (anchor, merge,
// data_type, id, body_ref, lang_resolved, local, ns_uri) behind a
// single `meta` pointer to a heap-allocated `ElementMeta`, and turns
// the inline `?TableData` into a `&TableData` pointer. The common
// metadata-free element pays only one nil-byte for each — sizeof
// drops to ~96 B (5.6× reduction). Spine-copy now copies two
// pointers instead of eight option slots, automatically sharing
// metadata across the new and old spine.
//
// Public access is via accessor methods (e.g. `el.anchor() ?string`)
// — readers do `if a := el.anchor() { ... }` instead of the legacy
// direct-field unwrap. Mutators use `set_anchor` / `set_merge` etc.,
// which lazy-allocate `meta` on first set.
//
// ABI/wire layout is unaffected: ast_bin encoding inspects fields
// through the same accessor surface; the binary tag space and field
// presence rules are unchanged.

pub struct Element {
pub mut:
	name  string
	attrs []Attribute
	items []Node
	// Pooled optional metadata. `nil` when the element
	// carries no anchor/merge/id/body_ref/lang/namespace/data-type
	// data — the overwhelming majority of parsed elements. Allocated
	// lazily by parser / namespace-resolver / mutator helpers.
	meta  &ElementMeta = unsafe { nil }
	// Pointer-ized table payload. `nil` for non-table
	// elements (i.e. nearly all elements); a heap-allocated TableData
	// for elements that parsed `:table` blocks.
	table &TableData = unsafe { nil }
}

// OpaqueValue is a host-language value carried transparently inside a Node —
// currently a `code.Closure` riding on the `__cx_closure__` function-value
// sentinel (§8.6). `cx` is the lowest layer and cannot name `code.Closure`, so
// the payload travels behind this interface and `code` implements it on
// `Closure`. The value is carried BY REFERENCE (the interface boxes it on the
// heap), so an ESCAPING closure travels WITH its value — resolved wherever it is
// applied, against its own defining scope, with no id→table registry
// (cx-private #45). It never reaches a serialization boundary: the sentinel
// raises CXER0291 first (`is_fn_value`), and no emitter/codec ever inspects this
// field — the binary codec enumerates the named meta fields only.
pub interface OpaqueValue {
	opaque_kind() string
}

// ElementMeta pools the eight optional fields that used to live
// inline on Element. Allocated lazily — every element with at least
// one metadata bit set carries one `ElementMeta`; metadata-free
// elements carry no allocation.
@[heap]
pub struct ElementMeta {
pub mut:
	// opaque carries a host-language value (a closure) on the function-value
	// sentinel only — nil on every ordinary element. See OpaqueValue (#45).
	opaque ?OpaqueValue
	// v3.4: anchor / merge — declared via `[name &anchor]`
	// and `[name @anchor]` surface forms.
	anchor    ?string
	merge     ?string
	// v3.4: ascribed data-type label (e.g. `:int`, `:date`, `:user`).
	data_type ?string
	// v3.4: syntactic ID — `[user #u-1 ...]`.
	id        ?string
	// v3.4 (second bullet): `[ref @id]` body-position
	// reference. body_ref carries the target id; name is 'ref'.
	body_ref  ?string
	// Z-row: in-scope BCP 47 language tag (spec/i18n.md §1.3).
	lang_resolved ?string
	// v3.4: expanded local name. Empty when local == name
	// (no namespace prefix); populated by resolve_namespaces() when
	// the source carried a `prefix:local` form.
	local  string
	// v3.4: resolved namespace URI from the in-scope
	// xmlns declaration. none when no binding is in scope.
	ns_uri ?string
}

// ── Element accessors ────────────────────────────────────────────────────────
//
// The accessor methods preserve the legacy read pattern:
//   if a := el.anchor() { ... }   — was: if a := el.anchor { ... }
// Returning the same `?string` shape lets callers migrate by appending
// `()` to existing field reads. Mutators are separate `set_*` methods
// that lazy-allocate `meta` on first non-none set.

pub fn (e Element) anchor() ?string {
	if isnil(e.meta) { return none }
	return e.meta.anchor
}

pub fn (e Element) merge() ?string {
	if isnil(e.meta) { return none }
	return e.meta.merge
}

pub fn (e Element) data_type() ?string {
	if isnil(e.meta) { return none }
	return e.meta.data_type
}

pub fn (e Element) id() ?string {
	if isnil(e.meta) { return none }
	return e.meta.id
}

pub fn (e Element) body_ref() ?string {
	if isnil(e.meta) { return none }
	return e.meta.body_ref
}

pub fn (e Element) lang_resolved() ?string {
	if isnil(e.meta) { return none }
	return e.meta.lang_resolved
}

// local returns the element's local name. Defaults to `name` when no
// namespace metadata is present (no prefix in the source). Mirrors the
// pre-diet behavior: namespace-resolver populates ElementMeta.local
// only when the source had a 'prefix:local' form.
pub fn (e Element) local() string {
	if isnil(e.meta) || e.meta.local == '' { return e.name }
	return e.meta.local
}

pub fn (e Element) ns_uri() ?string {
	if isnil(e.meta) { return none }
	return e.meta.ns_uri
}

// opaque returns the host-language value carried on a function-value sentinel
// (a `code.Closure`), or none for an ordinary element. See OpaqueValue (#45).
pub fn (e Element) opaque() ?OpaqueValue {
	if isnil(e.meta) { return none }
	return e.meta.opaque
}

// table_opt returns the table payload as an option. nil pointer
// becomes `none`. Callers migrate `if td := el.table { ... }` to
// `if td := el.table_opt() { ... }` — the unwrap shape is preserved.
// (The struct field stays named `table` for ast_bin / wire / direct
// pointer-equality checks; `table_opt` is the optional-unwrap API.)
pub fn (e Element) table_opt() ?&TableData {
	if isnil(e.table) { return none }
	return e.table
}

// lang returns the BCP 47 language tag in scope at this Element, per
// spec/i18n.md §1.3 inherited-scope semantics. Returns "" when no
// cx:lang is in scope.
pub fn (e Element) lang() string {
	return e.lang_resolved() or { '' }
}

// ── Element mutators ─────────────────────────────────────────────────────────
//
// Mutators lazy-allocate ElementMeta on first non-none set. Setting a
// field to `none` does NOT deallocate meta (the bookkeeping cost of
// reference-counting other fields outweighs the rare benefit).

fn (mut e Element) ensure_meta() {
	if isnil(e.meta) {
		e.meta = &ElementMeta{}
	}
}

pub fn (mut e Element) set_anchor(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.anchor = v
}

pub fn (mut e Element) set_merge(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.merge = v
}

pub fn (mut e Element) set_data_type(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.data_type = v
}

pub fn (mut e Element) set_id(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.id = v
}

pub fn (mut e Element) set_body_ref(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.body_ref = v
}

pub fn (mut e Element) set_lang_resolved(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.lang_resolved = v
}

pub fn (mut e Element) set_local(v string) {
	if isnil(e.meta) && v == '' { return }
	e.ensure_meta()
	e.meta.local = v
}

pub fn (mut e Element) set_ns_uri(v ?string) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.ns_uri = v
}

// set_opaque attaches a host-language value (a closure) to a function-value
// sentinel — the only caller (mk_closure_value in `code`). See OpaqueValue (#45).
pub fn (mut e Element) set_opaque(v ?OpaqueValue) {
	if isnil(e.meta) && v == none { return }
	e.ensure_meta()
	e.meta.opaque = v
}

// new_element constructs an Element with the optional metadata fields
// expressed as a single ElementMeta literal. The helper auto-allocates
// `meta` only when at least one metadata slot is set. Use this for
// callers that previously built `Element{ name: ..., anchor: a, merge: m, ... }`
// inline — the diet keeps the call ergonomic without paying the
// 480-byte-per-element option-tax of the pre-diet layout.
pub fn new_element(name string, m ElementMeta, attrs []Attribute, items []Node) Element {
	if element_meta_is_empty(m) {
		return Element{
			name:  name
			attrs: attrs
			items: items
		}
	}
	return Element{
		name:  name
		attrs: attrs
		items: items
		meta:  &ElementMeta{ ...m }
	}
}

// with_table is a fluent helper: attaches a TableData pointer to an
// Element (typically right after `new_element(...)`). Returns the
// element by value with the `table` field set.
pub fn (e Element) with_table(td &TableData) Element {
	return Element{
		name:  e.name
		attrs: e.attrs
		items: e.items
		meta:  e.meta
		table: td
	}
}

fn element_meta_is_empty(m ElementMeta) bool {
	if m.anchor != none || m.merge != none || m.data_type != none
	   || m.id != none || m.body_ref != none || m.lang_resolved != none
	   || m.ns_uri != none || m.opaque != none {
		return false
	}
	return m.local == ''
}

// TableColumn describes one column of a :table block.
pub struct TableColumn {
pub mut:
	name      string  // column name, required
	type_name string  // long-form type name ('string', 'int', 'i32',
	                  // 'decimal', etc.); empty means :string default
}

// TableData carries the parsed contents of a :table block. Columns
// declared once in the header; rows are parallel sequences of
// TableCellValue per column, in declaration order.
//
// Cell values may be either scalar (bool / i64 / f64 / string /
// NullValue — the existing ScalarValue variants) OR collection-
// literal Items (ArrayNode / MapNode / SequenceNode
// §D1 +). Scalar cells preserve their declared column
// type per TableColumn.type_name; collection cells carry their
// structure inline (the column type's collection-production
// `arr[T]` / `map[K, V]` / `seq[T]` informs
// emitters but is not enforced at AST level).
@[heap]
pub struct TableData {
pub mut:
	cols []TableColumn
	rows [][]TableCellValue
	// from_chunked is true when this TableData was materialized from a
	// chunked (`0x63`) data_bin payload. Streaming events check this flag
	// to decide between StartElement+per-cell-Scalar+EndElement (false)
	// and StartTable+RowGroup*+EndTable (true) per spec/streaming.md §1.1.
	// CX text source and non-chunked data_bin (`0x60` / `0x61`) leave it
	// false. Runtime provenance only — NOT serialized in ast_bin (the
	// table CONTENT rides the v9 Element table record, tag 0x17, per
	// binary.v / ast-bin.md §4.8 (#464); decoded tables restore false);
	// set by the data_bin chunked reader path.
	from_chunked bool
}

// TableCellValue is the value type for a single :table cell. Flat
// sum of ScalarValue variants + collection-literal Node kinds, so
// consumers can match on the concrete variant directly without
// nested unwrapping. The collection variants reuse ArrayNode /
// MapNode / SequenceNode defined alongside the rest of the AST so
// emitters and ast_bin can dispatch via the existing collection-
// literal codepaths.
pub type TableCellValue = bool
                        | i64
                        | f64
                        | string
                        | NullValue
                        | ArrayNode
                        | MapNode
                        | SequenceNode

// scalar_value_from_cell extracts the cell's value as a ScalarValue
// if and only if the cell holds a scalar variant. Returns none for
// collection cells (ArrayNode / MapNode / SequenceNode). Used by
// existing scalar-only consumers (CSV emit, data_bin scalar-cell
// encoding) that want to preserve their pre-collection-cells code
// path for scalar cells while branching to a separate code path
// for collections.
pub fn scalar_value_from_cell(c TableCellValue) ?ScalarValue {
	return match c {
		bool      { ScalarValue(c) }
		i64       { ScalarValue(c) }
		f64       { ScalarValue(c) }
		string    { ScalarValue(c) }
		NullValue { ScalarValue(c) }
		else      { none }
	}
}

// cell_value_from_scalar wraps a ScalarValue as a TableCellValue.
// Convenience constructor for parser / decoder code paths that
// produce ScalarValue and store cells via the new sum type.
pub fn cell_value_from_scalar(s ScalarValue) TableCellValue {
	return match s {
		bool      { TableCellValue(s) }
		i64       { TableCellValue(s) }
		f64       { TableCellValue(s) }
		string    { TableCellValue(s) }
		NullValue { TableCellValue(s) }
	}
}

// scalar_rows_from_cells projects a [][]TableCellValue back to the
// pre-collection-cells [][]ScalarValue shape. Errors if any cell
// is a collection-literal (Array / Map / Sequence). Used by the
// legacy scalar-only code paths (data_bin wire format, CSV emit,
// scalar-only consumers) to preserve their existing behavior while
// the Phase 2 collection-cell rollout extends each path to handle
// the new variants natively. This helper will be deleted once
// Phase 2.2 (ast_bin) + Phase 2.3 (emitters) + Phase 2.4 (Table
// API) complete and every consumer accepts TableCellValue directly.
pub fn scalar_rows_from_cells(cells [][]TableCellValue) ![][]ScalarValue {
	mut out := [][]ScalarValue{cap: cells.len}
	for row_idx, row in cells {
		mut srow := []ScalarValue{cap: row.len}
		for col_idx, c in row {
			s := scalar_value_from_cell(c) or {
				return error('row ${row_idx} col ${col_idx}: collection-cell value not supported on this code path yet')
			}
			srow << s
		}
		out << srow
	}
	return out
}

// cell_rows_from_scalars wraps each ScalarValue cell as a
// TableCellValue. Inverse of scalar_rows_from_cells for the data
// flow direction (decoder → AST). Used by ast_bin / data_bin
// decoder code paths that currently produce [][]ScalarValue.
pub fn cell_rows_from_scalars(rows [][]ScalarValue) [][]TableCellValue {
	mut out := [][]TableCellValue{cap: rows.len}
	for row in rows {
		mut crow := []TableCellValue{cap: row.len}
		for s in row {
			crow << cell_value_from_scalar(s)
		}
		out << crow
	}
	return out
}

// ── Attribute ─────────────────────────────────────────────────────────────────
//
// Attribute struct diet (gate 30.5 /).
//
// The previous Attribute carried four cold optional/string fields
// inline (`data_type ?ScalarType`, `local string`, `ns_uri ?string`, and
// the since-removed `body ?[]Node`) totalling 208 B per attribute struct. Spine-copy
// under [?modify] cloned the attribute slice on every spine-frame,
// paying that cost on every attribute of every spine element.
//
// The diet pools the four cold fields behind a single `meta` pointer
// to a heap-allocated `AttributeMeta`, leaving only the hot fields
// (`name`, `value`, `is_ref`) inline. The common metadata-free
// attribute pays only one nil pointer for `meta` — sizeof drops to
// ~48 B (4× reduction). The is_ref flag stays inline because (a) it
// is a single bool, near-zero cost; (b) it is read on every emit
// path so promoting it to an accessor would add a nil-check per call.
//
// Public access is via accessor methods (e.g. `a.data_type() ?string`)
// — readers do `if dt := a.data_type() { ... }` instead of the legacy
// direct-field unwrap. Mutators use `set_data_type` etc.,
// which lazy-allocate `meta` on first non-empty set.
//
// ABI/wire layout is unaffected: ast_bin encoding inspects fields
// through the same accessor surface; binary tag space and field
// presence rules are unchanged.

pub struct Attribute {
pub mut:
	name   string
	value  ScalarValue
	// v3.4: true when the source attribute value was a bare
	// `@id` token (e.g. `assigned-to=@u-1`). Quoted strings starting
	// with '@' have is_ref = false. Round-trip preserves the bare
	// form on emit. References resolve via Document.resolve_id() at
	// parse end. Inline (bool) — read on every emit path.
	is_ref bool
	// Pooled cold metadata (data_type, local, ns_uri,
	// body). nil when the attribute carries no ascribed type, no
	// namespace data, and no BracketBody — the overwhelming majority
	// of parsed attributes. Allocated lazily by parser / namespace-
	// resolver / mutator helpers.
	meta &AttributeMeta = unsafe { nil }
}

// AttributeMeta pools the four cold optional fields that used to
// live inline on Attribute. Allocated lazily — every attribute with
// at least one metadata bit set carries one `AttributeMeta`;
// metadata-free attributes carry no allocation.
@[heap]
pub struct AttributeMeta {
pub mut:
	// v3.4: ascribed scalar data-type, carried as the canonical long
	// type NAME (e.g. `int`, `date`, `u16`, `decimal`, `atom`). none for
	// default-typed/string attributes.
	//
	// D3: widened from `?ScalarType` (a closed enum that could
	// not name the sized numerics) to `?string` so a typed attribute can
	// preserve sized-int / decimal / bigint / bytes / atom types across
	// the CX⇄XML round-trip via the `cx:attr-types` sidecar. The runtime
	// value model still collapses sized numerics to their base kind —
	// see `scalar_type_from_name`.
	data_type ?string
	// v3.4: expanded local name. Empty when local == name
	// (no namespace prefix); populated by resolve_namespaces() when
	// the source carried a `prefix:local` form.
	local string
	// v3.4: resolved namespace URI from the in-scope
	// xmlns declaration. none when no binding is in scope.
	// Note that per XML namespaces 1.0 §6.2, default namespaces
	// do NOT apply to unprefixed attributes — `ns_uri` stays none
	// for unprefixed attrs even when a default ns is in scope.
	ns_uri ?string
	// (The v3.5 `body ?[]Node` BracketBody channel was REMOVED here —
	// #396 owner ruling 1b, 2026-07-13: attributes are strictly scalar,
	// one value channel. D2/lexicon §10 is the normative home.)
}

// ── Attribute accessors ──────────────────────────────────────────────────────
//
// Returning the same option/string shapes as the legacy direct-field
// reads lets callers migrate by appending `()` to existing reads.

pub fn (a Attribute) data_type() ?string {
	if isnil(a.meta) { return none }
	return a.meta.data_type
}

// local returns the attribute's local name. Defaults to '' when no
// namespace metadata is present, matching the pre-diet shape: the
// namespace-resolver only sets `local` for attributes that originally
// carried a prefix.
pub fn (a Attribute) local() string {
	if isnil(a.meta) { return '' }
	return a.meta.local
}

pub fn (a Attribute) ns_uri() ?string {
	if isnil(a.meta) { return none }
	return a.meta.ns_uri
}

// ── Attribute mutators ───────────────────────────────────────────────────────
//
// Mutators lazy-allocate AttributeMeta on first non-empty set.

fn (mut a Attribute) ensure_meta() {
	if isnil(a.meta) {
		a.meta = &AttributeMeta{}
	}
}

pub fn (mut a Attribute) set_data_type(v ?string) {
	if isnil(a.meta) && v == none { return }
	a.ensure_meta()
	a.meta.data_type = v
}

pub fn (mut a Attribute) set_local(v string) {
	if isnil(a.meta) && v == '' { return }
	a.ensure_meta()
	a.meta.local = v
}

pub fn (mut a Attribute) set_ns_uri(v ?string) {
	if isnil(a.meta) && v == none { return }
	a.ensure_meta()
	a.meta.ns_uri = v
}

// new_attribute constructs an Attribute with the optional metadata
// fields expressed as a single AttributeMeta literal. Auto-allocates
// `meta` only when at least one slot is set. Use this for callers
// that previously built `Attribute{ name, value, data_type, local, ns_uri }`
// inline.
pub fn new_attribute(name string, value ScalarValue, m AttributeMeta) Attribute {
	if attribute_meta_is_empty(m) {
		return Attribute{
			name:  name
			value: value
		}
	}
	return Attribute{
		name:  name
		value: value
		meta:  &AttributeMeta{ ...m }
	}
}

fn attribute_meta_is_empty(m AttributeMeta) bool {
	if m.data_type != none || m.ns_uri != none {
		return false
	}
	return m.local == ''
}

fn (a Attribute) str_value() string {
	return scalar_value_str(a.value)
}

// ── Scalar types ──────────────────────────────────────────────────────────────

pub enum ScalarType {
	int_type
	float_type
	bool_type
	null_type
	string_type
	date_type
	datetime_type
	bytes_type
	// v3.4 additions
	decimal_type
	bigint_type
	// D-A4 / new type: temporal-span refinements (lexicon [L25]/[L26]).
	// Both carry their verbatim CX form as a string ScalarValue (like
	// decimal/bigint). `duration` is an EXACT span ({ns,us,ms,s,m,h,d,w} →
	// i64 ns); `period` is a CALENDAR span ({mo,y}, needs an anchor date).
	// XML image is ISO 8601 (PT1H30M / P10D ; P1Y2M).
	duration_type
	period_type
	// atom — tag-shaped scalar, surface `:NAME`,
	// type-strict (atom never equals string of same characters). The
	// ScalarValue payload is a `string` carrying the atom's name
	// (without the leading `:`). See spec/cxdm.md §2.2 / §4.1.
	atom_type
}

fn scalar_type_name(t ScalarType) string {
	return match t {
		.int_type      { 'int' }
		.float_type    { 'float' }
		.bool_type     { 'bool' }
		.null_type     { 'null' }
		.string_type   { 'string' }
		.date_type     { 'date' }
		.datetime_type { 'datetime' }
		.bytes_type    { 'bytes' }
		.decimal_type  { 'decimal' }
		.bigint_type   { 'bigint' }
		.duration_type { 'duration' }
		.period_type   { 'period' }
		.atom_type     { 'atom' }
	}
}

// scalar_type_name_public exposes the long type name for a ScalarType
// to other modules (and to code that bridges the closed enum into the
// string-named attribute carrier introduced by D3).
pub fn scalar_type_name_public(t ScalarType) string {
	return scalar_type_name(t)
}

// opt_scalar_type_name bridges an optional ScalarType into the optional
// type-NAME form the attribute carrier uses (D3). `none` and `string`
// both yield `none` (the unannotated default).
pub fn opt_scalar_type_name(t ?ScalarType) ?string {
	st := t or { return none }
	if st == .string_type { return none }
	return scalar_type_name(st)
}

// scalar_type_from_name maps a canonical long type-name string back to a
// runtime ScalarType. Sized numerics collapse to their base kind
// (`u8..u64`/`i8..i64` → int, `f16/f32/f64` → float) because the runtime
// value model has no sized representation — the precise name is preserved
// only on the attribute carrier / element `data_type` string. `string`,
// unknown names, and array suffixes (`T[]`) yield `none`.
pub fn scalar_type_from_name(name string) ?ScalarType {
	if name.ends_with('[]') {
		return none
	}
	return match name {
		'int', 'u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64' {
			ScalarType.int_type
		}
		'float', 'f16', 'f32', 'f64' { ScalarType.float_type }
		'bool'     { ScalarType.bool_type }
		'null'     { ScalarType.null_type }
		'date'     { ScalarType.date_type }
		'datetime' { ScalarType.datetime_type }
		'bytes'    { ScalarType.bytes_type }
		'decimal'  { ScalarType.decimal_type }
		'bigint'   { ScalarType.bigint_type }
		'duration' { ScalarType.duration_type }
		'period'   { ScalarType.period_type }
		'atom'     { ScalarType.atom_type }
		else       { none }
	}
}

// type_name_is_auto_recoverable reports whether a bare CX scalar of this
// type round-trips through XML WITHOUT a `cx:attr-types` sidecar entry —
// i.e. the XML→CX attribute auto-typer reconstructs it from the lexical
// form alone. Only the default lexical types qualify: a bare `5` re-types
// to `int` (never `u16`), `1.5` to `float` (never `decimal`/`f32`), so
// the sized / non-lexical kinds always need the sidecar. (D3)
pub fn type_name_is_auto_recoverable(name string) bool {
	return name in ['int', 'float', 'bool', 'null', 'date', 'datetime']
}

pub type ScalarValue = bool | i64 | f64 | string | NullValue

pub struct NullValue {}

// scalar_value_str_public exposes scalar_value_str for binding code
// that needs the canonical string form of a ScalarValue (e.g.,
// lang/v/native/table.v for map-key emission to JSON). Just a
// re-export of the internal function.
pub fn scalar_value_str_public(v ScalarValue) string {
	return scalar_value_str(v)
}

fn scalar_value_str(v ScalarValue) string {
	return match v {
		i64       { v.str() }
		f64       { format_float(v) }
		bool      { if v { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { v }
	}
}

fn format_float(v f64) string {
	s := '${v}'
	if s.contains('.') || s.contains('e') {
		return s
	}
	return '${s}.0'
}

// ── Leaf node types ───────────────────────────────────────────────────────────

pub struct TextNode {
pub mut:
	value string
}

pub struct ScalarNode {
pub mut:
	data_type ScalarType
	value     ScalarValue
}

pub struct AliasNode {
pub mut:
	name string
}

pub struct CommentNode {
pub mut:
	value   string
	is_line bool   // true for `# line` form; false for `[- block ]` form
}

pub struct PINode {
pub mut:
	target string
	data   ?string
}

pub struct XMLDeclNode {
pub mut:
	version    string
	encoding   ?string
	standalone ?string
}

pub struct CXDirectiveNode {
pub mut:
	attrs []Attribute
	// Directives may carry an `&anchor` and/or nested elements.
	// Currently used by `[?cx frag &name [body :TYPE :flags]]` (spec
	// schema.md §8 standalone fragment form). Other directives populate
	// these as none / empty. ast_bin format version 4 carries them; v1-3
	// decoders see the attrs-only shape.
	anchor ?string
	items  []Node
}

pub struct EntityRefNode {
pub mut:
	name string
}

// InterpolationNode carries a CX value-interpolation form `[?=EXPR]`
// (grammar v3.5 [58]). The CX parser captures EXPR as opaque
// text — bracket-balanced characters between `[?=` and the matching
// `]` — and stores it here. The program evaluator parses EXPR
// as CXPath at evaluation time; pre-evaluator tooling (formatters,
// hashers, diff) treats this node as opaque preserved structure.
pub struct InterpolationNode {
pub mut:
	// Captured expression text (the `EXPR` body, leading/trailing
	// whitespace trimmed). Stored verbatim; not parsed as CXPath at
	// CX-parse time.
	expr string
}

// EvalDirectiveNode carries a program evaluation directive form
// `[?Name (S Attribute)* (S BodyItem)* S? ]` (grammar v3.5 [59],
// ). Reserved EvalNames (`if`, `for`, `with`,
// `cond`, `include`, `def`, `use`, `let`, `fn`, `match`, `try`) parse
// into this node. The program evaluator dispatches on `name` and
// reads `attrs` (with BracketBody values where present) and `items`.
// Inert outside program evaluation context; round-trips as opaque
// preserved structure R5.
pub struct EvalDirectiveNode {
pub mut:
	name  string
	attrs []Attribute
	items []Node
}

pub struct RawTextNode {
pub mut:
	value string
}

pub struct BlockContentNode {
pub mut:
	items []Node
}

// DocumentNode carries a whole CX document as one Node value (design D7 /
// codec.md §1). Field layout mirrors `Document` exactly so the converters
// below are field copies.
pub struct DocumentNode {
pub mut:
	prolog   []Node
	doctype  ?DoctypeDecl
	elements []Node
}

// doc_to_node wraps a parsed `Document` as a transparent `DocumentNode`.
pub fn doc_to_node(doc Document) Node {
	return DocumentNode{
		prolog:   doc.prolog
		doctype:  doc.doctype
		elements: doc.elements
	}
}

// node_to_doc unwraps any Node to a `Document` for emission. A `DocumentNode`
// restores its prolog/doctype/elements verbatim; any other node becomes a
// single-element document (the bare-node convenience form).
pub fn node_to_doc(n Node) Document {
	if n is DocumentNode {
		return Document{
			prolog:   n.prolog
			doctype:  n.doctype
			elements: n.elements
		}
	}
	return Document{
		elements: [n]
	}
}

// ── Collection literal nodes (grammar v3.6) ─────────────────────────
//
// Three new container Item kinds per spec/cxdm.md §2.4–§2.6:
//   - SequenceNode: source `(a, b, c)`. Flat per CXDM §1 sequence-flat
//     principle; nested SequenceNodes flatten on construction at the parse /
//     AST-build layer (the parser delivers the flattened form). Used for
//     query results, union expressions, iteration sources.
//   - ArrayNode: source `[a, b, c]`. Nested-preserving; arrays inside arrays
//     keep their structure. Used for positional directive slots, structured
//     data, JSON-array round-trip.
//   - MapNode: source `{k: v, k: v}`. Atomic-keyed entries; duplicate keys
//     are W014 / parse error. Used for JSON-object round-trip and
//     keyword-style directive parameters.
//
// Wire-level encoding: ast_bin v6 tags 0x0F / 0x10 / 0x11 (spec/core/ast-bin.md
// §4.1). Capability bit 29 (spec/abi.md §1.5) signals support.
pub struct SequenceNode {
pub mut:
	items []Node
}

pub struct ArrayNode {
pub mut:
	items []Node
}

// MapEntry carries one `key: value` pair inside a MapNode. The key is held
// as a flattened scalar (type-tag + value) per ast_bin §4.3; reconstruction
// into a typed AST node happens at host-language materialization time.
pub struct MapEntry {
pub mut:
	key_type  ScalarType   // string | int | float | bool | date | datetime | bytes
	key_value ScalarValue  // canonical-string-formatted scalar value
	value     Node
}

pub struct MapNode {
pub mut:
	entries []MapEntry
}

// ── Iterator value kind ───────────────────────────────────────────
//
// IteratorNode is the lazy + memoized stream value kind, sitting
// alongside the existing Sequence / Array / Map kinds (CXDM
// §2). Two foundational properties:
//
//   - LAZY: items are not computed until consumed. `iterate(IteratorNode)`
//     materializes — until then the source is just a description.
//   - MEMOIZED: once consumed, items are stashed in `memo`. Subsequent
//     pulls of the same iterator (e.g. `[?def $foo ITER]` re-walked)
//     return the memoized snapshot rather than re-evaluating.
//
// Identity-only equality — two IteratorNode values are
// equal iff they share the same backing heap allocation. The struct
// is `@[heap]`-annotated so V allocates each construction on the heap
// and propagates the pointer through sum-type copies; `nodes_equal()`
// compares the pointer addresses. This sidesteps "should two freshly-
// constructed iterators with identical sources compare equal?" in
// favour of pointer-style identity (Python's `iter(x) != iter(x)`
// model).
//
// W3a / W3b foundation surface — the `source_kind` discriminator
// catalogues which generator the iterator wraps. For W3a only
// `iter_range` is supported (range(start, end, step) sugar / builtin);
// W3c grafts the combinator family (`iter_map`, `iter_filter`,
// `iter_take`, `iter_drop`, `iter_concat`) when [?map] / [?filter] /
// [?take] / [?drop] gain result-form return types.
//
// `source_args` carries the already-evaluated argument list captured at
// iterator construction time — for `iter_range` that's [start, end,
// step] scalar nodes. The eval-side `pull_iterator_to_end()` helper
// (vcx/code/eval.v) dispatches on `source_kind` to do the actual pull.
//
// `single_use` (D25) marks iterators backed by an external stream
// (network / large file) whose source cannot be re-walked — once
// `exhausted == true` the memo is the only valid snapshot, and a
// second consumer that arrives *during* iteration is an error. W4-C
// wires this for HTTP body streaming; W3a constructs all iterators
// with `single_use = false`.
//
// Render-materialize semantics: every host-language emitter (cx, json,
// xml, md, semantic, yaml/toml — and the test-side renderer) FORCE-
// MATERIALIZES the iterator before serializing. This is 
// "lazy iterators become eager Sequences at the host boundary." The
// emitter calls `iterate(Node(iter))` (which appends to memo + flips
// `exhausted`) and then renders the resulting `[]Node` in the paren-
// comma `(a, b, c)` form matching SequenceNode.
@[heap]
pub struct IteratorNode {
pub mut:
	// Discriminator selecting which generator backs this iterator.
	// W3a ships `iter_range` only; combinator kinds land in W3c.
	source_kind IteratorSourceKind
	// Evaluated source arguments. For `iter_range` this is the
	// [start, end, step] scalar tuple. For combinators (W3c) this is
	// the upstream iterator(s) + the projection / predicate function.
	source_args []Node
	// Memoization buffer. Appended on each pull; full on `exhausted`.
	memo []Node
	// Marks the iterator as fully pulled — `iterate()` returns `memo`
	// as-is on subsequent calls instead of re-pulling.
	exhausted bool
	// external-stream marker. W4-C wires this; W3a
	// constructs all iterators with `single_use = false`.
	single_use bool
}

// IteratorSourceKind catalogues which generator backs an IteratorNode.
// W3a shipped `iter_range`; W3c grafts the combinator family per
//
// Combinator slot semantics — what `source_args` carries per kind:
//
//   iter_range        [start, end, step?] scalar ints
// iter_range_open [start, step?] scalar ints; the
//                     end is implicit (unbounded). Materialising the
//                     iterator without :take/:takewhile is an error.
//   iter_map          [src_iter, closure_sentinel]
//   iter_filter       [src_iter, closure_sentinel]
//   iter_take         [src_iter, count_scalar]
//   iter_drop         [src_iter, count_scalar]
//   iter_concat       [src_iter_1, src_iter_2, ...]
//   iter_chain        alias of iter_concat — recorded as iter_concat at
//                     construction time so the dispatch is uniform
//   iter_zip          [src_iter_1, src_iter_2, ...] — emits per-position
//                     sequence tuples up to shortest-source length
//   iter_enumerate    [src_iter] — emits (i, item) pairs
//   iter_chunks       [src_iter, count_scalar] — emits sub-sequences of
//                     `count` items each (final chunk may be short)
//   iter_cycle        [src_iter, max_scalar] — repeats source up to
// `max` total items (bounded; no
//                     unbounded cycle currently)
//   iter_scan         [src_iter, closure_sentinel, init_value] — emits
//                     running fold prefixes (init, f(init, a), f(.., b)..)
//   iter_flatten      [src_iter] — flattens one level of sequence nesting
//   iter_partition    [src_iter, closure_sentinel] — emits 2-tuple of
//                     (truthy_seq, falsy_seq); terminal-ish but typed
//                     as iterator-of-two-sequences
//   iter_group_by     [src_iter, closure_sentinel] — emits map of
//                     key -> sub-sequence
//   iter_reduce       reserved slot — `[?reduce]` is terminal (returns
//                     a scalar). Listed for completeness; constructing
//                     an IteratorNode with this kind is invalid (the
//                     reduce directive materialises promptly).
pub enum IteratorSourceKind {
	iter_none       // unset / placeholder
	iter_range      // range(start, end, step) — W3a
	iter_range_open // range(start, _open_end_, step?) — W4-A
	                // Unbounded; source_args is [start, step?] (no end).
	                // Materialising without `:take` / `:takewhile` raises
	                // CXER0100.
	iter_map        // [?map src :using f]                       — W3c
	iter_filter     // [?filter src :where pred]                 — W3c
	iter_take       // [?take n src]                              — W3c
	iter_drop       // [?drop n src]                              — W3c
	iter_concat     // [?concat A B C] / [?chain A B C]           — W3c
	iter_chain      // alias slot (concat semantics)              — W3c
	iter_zip        // [?zip A B …]                               — W3c
	iter_enumerate  // [?enumerate src]                           — W3c
	iter_chunks     // [?chunks n src]                            — W3c
	iter_cycle      // [?cycle src :max N]                        — W3c
	iter_scan       // [?scan src :using f :init v]               — W3c
	iter_flatten    // [?flatten src]                             — W3c
	iter_partition  // [?partition src :where pred]               — W3c
	iter_group_by   // [?group-by src :key f]                     — W3c
	iter_reduce     // [?reduce] terminal — reserved              — W3c
	iter_iterate    // [$iterate f seed] — functional progression — gen-reshape
	                // source_args is [f_value, seed]; statically infinite
	                // (emits seed, f(seed), …); forcing whole without a
	                // bound raises CXER0100. Closure applied per pull.
	iter_unfold     // [$unfold f seed] — general anamorphism      — gen-reshape
	                // source_args is [f_value, seed]; f returns () (stop) or a
	                // 2-element [value, next-state] Array. Force-realizable
	                // (runs to () with a host budget backstop).
	iter_net_accept // [$net:accept-iter listener] — pulls one accepted [socket]
	                // per iteration (net.md §3.3); source_args is [listener-handle].
	                // Statically infinite (terminates only on listener close /
	                // a [?take]/[?while] bound). The accept lives in eval.v.
	iter_http_accept // [$http:accept-iter server] — pulls one accepted connection
	                 // per iteration and yields an [exchange] (http.md §3.5);
	                 // source_args is [http-server-handle]. Same lifecycle as
	                 // iter_net_accept; the accept + exchange-wrap live in eval.v.
	iter_sse_events  // [$http:sse-events source] — reads one SSE frame off the
	                 // held-open [sse-source] connection per iteration and yields
	                 // the parsed [event] (http.md §3.6); source_args is
	                 // [sse-source-handle]. Single-use; clean EOF = absence. The
	                 // live frame read + auto-reconnect live in eval.v.
	iter_net_line    // [$net:line-iter sock] — yields one CRLF/LF-stripped line off
	                 // the socket per iteration until EOF (net.md §3.4); source_args
	                 // is [socket-handle]. The read lives in eval.v.
	iter_net_chunk   // [$net:chunk-iter sock n] — yields one up-to-n-byte chunk off
	                 // the socket per iteration until EOF (net.md §3.4); source_args
	                 // is [socket-handle, n]. The read lives in eval.v.
}

// new_iterator constructs an IteratorNode wrapping `source_kind` with
// the already-evaluated `source_args` list. The iterator starts empty
// (`memo = []`, `exhausted = false`, `single_use = false`).
//
// Identity is the heap-allocation address: because IteratorNode is
// `@[heap]`, V allocates each construction on the heap and propagates
// the pointer through sum-type copies (the Node sum holds the struct
// by reference, not by value). Two IteratorNode values compare equal
// in `nodes_equal()` iff their backing pointers match.
// The `id` field is left as a derived nonce (currently always 0 — the
// heap address is the real identity); reserved for future explicit
// labeling if needed.
pub fn new_iterator(source_kind IteratorSourceKind, source_args []Node) Node {
	return Node(IteratorNode{
		source_kind: source_kind
		source_args: source_args
	})
}

// iterator_to_sequence is the host-boundary materialization helper
// Returns the iterator's already-memoized items as
// a SequenceNode. This is the SHALLOW form — it does NOT pull from
// the source generator (that lives in `code/eval.v` because the
// generator dispatch depends on the program-AST sum type which is
// not visible from the `cx` module).
//
// Emitters call this when they encounter an IteratorNode mid-render;
// the eval pipeline is responsible for pulling the iterator first
// (via `iterate()`) so by the time the value reaches an emitter the
// `memo` already holds the full snapshot. The emitter's call here is
// a defence-in-depth render of whatever has accumulated — if the
// iterator was never pulled, the emitter emits the empty sequence
// `()`. The exhaustive-pull path runs in eval before host handoff.
pub fn iterator_to_sequence(iter IteratorNode) SequenceNode {
	return SequenceNode{ items: iter.memo.clone() }
}

// ── Declaration types ─────────────────────────────────────────────────────────

pub enum EntityKind {
	ge
	pe
}

pub type EntityDef = string | ExternalEntityDef

pub struct ExternalEntityDef {
pub mut:
	external_id ExternalID
	ndata       ?string
}

pub struct ExternalID {
pub mut:
	public ?string
	system ?string
}

pub struct DoctypeDecl {
pub mut:
	name        string
	external_id ?ExternalID
	int_subset  []Node
}

pub struct EntityDeclNode {
pub mut:
	kind EntityKind
	name string
	def  EntityDef
}

pub struct ElementDeclNode {
pub mut:
	name        string
	contentspec string
}

pub struct AttDef {
pub mut:
	name     string
	att_type string
	default  string
}

pub struct AttlistDeclNode {
pub mut:
	name string
	defs []AttDef
}

pub struct NotationDeclNode {
pub mut:
	name      string
	public_id ?string
	system_id ?string
}

// PEReferenceNode carries a parameter-entity reference `%name;`
// (grammar [68]) that appears as a DeclSep [39] inside a DOCTYPE
// internal subset. Stored OPAQUE — the name only — and NEVER
// expanded (CX has no PE machinery); it round-trips verbatim to
// `%name;` in both CX and XML. Adding this node fixes the prior
// defect where a `%name;` in the int-subset broke the CX parse loop
// (and was silently dropped by the XML reader).
pub struct PEReferenceNode {
pub mut:
	name string
}

pub enum ConditionalKind {
	include
	ignore
}

pub struct ConditionalSectNode {
pub mut:
	kind   ConditionalKind
	subset []Node
}
