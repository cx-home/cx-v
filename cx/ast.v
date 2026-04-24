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
}

// ── Attribute ─────────────────────────────────────────────────────────────────

pub struct Attribute {
pub mut:
	name      string
	value     ScalarValue
	data_type ?ScalarType
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
	}
}

pub type ScalarValue = bool | i64 | f64 | string | NullValue

pub struct NullValue {}

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
	value string
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
}

pub struct EntityRefNode {
pub mut:
	name string
}

pub struct RawTextNode {
pub mut:
	value string
}

pub struct BlockContentNode {
pub mut:
	items []Node
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
