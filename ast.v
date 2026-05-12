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
	| ConditionalSectNode
	| InterpolationNode
	| EvalDirectiveNode
	| SequenceNode
	| ArrayNode
	| MapNode

// ── Document ──────────────────────────────────────────────────────────────────

pub struct Document {
pub mut:
	prolog   []Node
	doctype  ?DoctypeDecl
	elements []Node
}

// ── Element ───────────────────────────────────────────────────────────────────

pub struct Element {
pub mut:
	name      string
	anchor    ?string
	merge     ?string
	data_type ?string
	attrs     []Attribute
	items     []Node
	// v3.4: when set, this Element is a `:table` block. The columns
	// and rows are carried here instead of in attrs/items. Emitters
	// check this field first; non-table elements have it set to none
	// and fall through to the standard element-emission path. See
	// spec/grammar.ebnf [29] and spec/data_bin.md §3.10.
	table     ?TableData
	// v3.4 (ADR 0002): expanded-name fields populated by
	// resolve_namespaces() at the end of parse. `name` retains the
	// source form ('prefix:local' or 'local'); `local` is the
	// post-colon part; `ns_uri` is the resolved URI from the
	// in-scope xmlns declaration (or the reserved-prefix URI for
	// `xml:` and `cx:`). `ns_uri` is none when no binding is in
	// scope (the legacy / no-namespace case).
	local     string
	ns_uri    ?string
	// v3.4 (ADR 0003): syntactic ID declaration. Set when the source
	// has a `#name` token immediately after the element name (e.g.
	// `[user #u-1 name=alice]`). Distinct from anchors (`&name`) and
	// from user-data attributes named `id`. None when the element has
	// no ID. Resolved at parse time; duplicates within a document are
	// a parse error per ADR 0003 D5.
	id        ?string
	// v3.4 (ADR 0003 D1 second bullet): body-position reference. Set
	// when the source had a `[ref @id]` body-position node form — an
	// element named `ref` whose body is exactly a single `@name`
	// token. `body_ref` carries the target id; `name` is fixed to
	// `ref`; `attrs` and `items` are empty. The reserved-name rule
	// (D1) kicks in only for elements named `ref` with this exact
	// shape; other content under `ref` is left as a regular element
	// for back-compat. Carried over the ast_bin wire format at v3+
	// (Phase 7.70 bumped 2 → 3); bindings expose `body_ref` (or the
	// language-idiomatic spelling) on their Element type.
	body_ref  ?string
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
// literal Items (ArrayNode / MapNode / SequenceNode per ADR 0017
// §D1 + ADR 0018 §D4). Scalar cells preserve their declared column
// type per TableColumn.type_name; collection cells carry their
// structure inline (the column type's collection-production
// `arr[T]` / `map[K, V]` / `seq[T]` per ADR 0017 §D15 informs
// emitters but is not enforced at AST level).
pub struct TableData {
pub mut:
	cols []TableColumn
	rows [][]TableCellValue
	// from_chunked is true when this TableData was materialized from a
	// chunked (`0x63`) data_bin payload. Streaming events check this flag
	// to decide between StartElement+per-cell-Scalar+EndElement (false)
	// and StartTable+RowGroup*+EndTable (true) per spec/streaming.md §1.1.
	// CX text source and non-chunked data_bin (`0x60` / `0x61`) leave it
	// false. Not serialized in ast_bin (table content is not serialized
	// in ast_bin per binary.v); set by the data_bin chunked reader path.
	from_chunked bool
}

// TableCellValue is the value type for a single :table cell. Flat
// sum of ScalarValue variants + collection-literal Node kinds, so
// consumers can match on the concrete variant directly without
// nested unwrapping. The collection variants reuse ArrayNode /
// MapNode / SequenceNode defined alongside the rest of the AST so
// emitters and ast_bin can dispatch via the existing collection-
// literal codepaths (per ADR 0017 §D1).
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
// pre-ADR-0018 §D4 code paths (data_bin wire format, CSV emit,
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
				return error('row ${row_idx} col ${col_idx}: collection-cell value not supported on this code path yet (ADR 0018 §D4 Phase 2.2/2.3 pending)')
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

pub struct Attribute {
pub mut:
	name      string
	value     ScalarValue
	data_type ?ScalarType
	// v3.4 (ADR 0002): expanded-name fields. See Element comment.
	// Note that per XML namespaces 1.0 §6.2, default namespaces
	// do NOT apply to unprefixed attributes — `ns_uri` stays none
	// for unprefixed attrs even when a default ns is in scope.
	local     string
	ns_uri    ?string
	// v3.4 (ADR 0003): true when the source attribute value was a bare
	// `@id` token (e.g. `assigned-to=@u-1`). Quoted strings starting
	// with '@' have is_ref = false. Round-trip preserves the bare
	// form on emit. References resolve via Document.resolve_id() at
	// parse end.
	is_ref    bool
	// v3.5 (ADR 0016): BracketBody attribute value — `name=[BodyItem*]`.
	// When set, `value` is empty/unused and the attribute's content is
	// the parsed body sequence. Used by CXL evaluation directives like
	// `[?if cond :then=[BODY] :else=[BODY]]` (spec/cxl.md §3.2). Auto-
	// typing rules do not apply. Inert outside CXL evaluation context;
	// round-trips as opaque structure (ADR 0016 R5).
	body      ?[]Node
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
	}
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
	// v0.6.0 — directives may carry an `&anchor` and/or nested elements.
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

// InterpolationNode carries a CXL value-interpolation form `[?=EXPR]`
// (grammar v3.5 [58], ADR 0016). The CX parser captures EXPR as opaque
// text — bracket-balanced characters between `[?=` and the matching
// `]` — and stores it here. The CXL evaluator at v0.7.0+ parses EXPR
// as CXPath at evaluation time; pre-evaluator tooling (formatters,
// hashers, diff) treats this node as opaque preserved structure.
pub struct InterpolationNode {
pub mut:
	// Captured expression text (the `EXPR` body, leading/trailing
	// whitespace trimmed). Stored verbatim; not parsed as CXPath at
	// CX-parse time.
	expr string
}

// EvalDirectiveNode carries a CXL evaluation directive form
// `[?Name (S Attribute)* (S BodyItem)* S? ]` (grammar v3.5 [59],
// ADR 0016). Reserved EvalNames at v0.6.0 (`if`, `for`, `with`,
// `cond`, `include`, `def`, `use`, `let`, `fn`, `match`, `try`) parse
// into this node. The v0.7.0+ CXL evaluator dispatches on `name` and
// reads `attrs` (with BracketBody values where present) and `items`.
// Inert outside CXL evaluation context; round-trips as opaque
// preserved structure per ADR 0016 R5.
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

// ── Collection literal nodes (v0.6.0 / grammar v3.6 / ADR 0017) ──────────────
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
// Wire-level encoding: ast_bin v6 tags 0x0F / 0x10 / 0x11 (spec/ast_bin.md
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

pub enum ConditionalKind {
	include
	ignore
}

pub struct ConditionalSectNode {
pub mut:
	kind   ConditionalKind
	subset []Node
}
