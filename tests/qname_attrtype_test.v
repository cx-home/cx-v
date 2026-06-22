module main

import code
import cx

// v08_qname_attrtype_test — cluster 4 (NAMESPACE + ATTR-TYPE) of the
// parser-parity convergence. The PROGRAM parser must:
//   • fold a byte-adjacent `prefix:local` QName element HEAD ([L11]/[7a]),
//     not read `:local` as an atom child;
//   • auto-type a BARE attribute value via the [L25a] scalar priority — in
//     particular `nil=null` → NullValue, not the string "null".
// Convergence target is cx.parse; both render identically through
// code.render_canonical.

fn cc(src string) string {
	n := code.program_parse_to_typed_node(src) or { return 'REJECT' }
	return code.render_canonical(n)
}

fn xc(src string) string {
	doc := cx.parse(src) or { return 'REJECT: ${err}' }
	if doc.elements.len != 1 {
		return 'REJECT: ${doc.elements.len} elements'
	}
	return code.render_canonical(doc.elements[0])
}

// ── D1: a colon inside a BARE attribute value must NOT split into an atom ──
fn test_bare_attr_value_with_colon() {
	// cxparse Class-D D1: the program parser read `xmlns=urn:example` as
	// attr xmlns="urn" + a stray `:example` atom body item. Lexicon §10
	// [L70] BareValue admits `:`, so the whole `urn:example` is one string.
	// canonical render keeps the value bare (`:` is bare-safe in an attr value)
	// — the point is ONE attribute, no stray `:example` atom body item.
	assert cc('[doc xmlns=urn:example]') == '[doc xmlns=urn:example]'
	assert cc('[doc xmlns=urn:example]') == xc('[doc xmlns=urn:example]')
	// multi-attr line (ns-012 shape) and a multi-segment QName-style value
	assert cc('[item xmlns=urn:foo name=widget count=3]') == xc('[item xmlns=urn:foo name=widget count=3]')
	assert cc('[a v=x:y:z]') == '[a v=x:y:z]'
	assert cc('[a v=x:y:z]') == xc('[a v=x:y:z]')
}

// ── NAMESPACE ──
fn test_qname_head_bare() {
	assert cc('[svg:rect]') == '[svg:rect]'
	assert cc('[svg:rect]') == xc('[svg:rect]')
}

fn test_qname_head_with_attr() {
	assert cc('[svg:rect x=1]') == '[svg:rect x=1]'
	assert cc('[svg:rect x=1]') == xc('[svg:rect x=1]')
}

fn test_qname_head_with_child_prose() {
	// Body `child` is a bareword → prose string (matches cx).
	assert cc('[prefix:local child]') == xc('[prefix:local child]')
}

fn test_plain_atom_child_still_atom() {
	// A SPACE-separated `:rect` is still an atom child, not a qualifier.
	assert cc('[svg :rect]') == '[svg :rect]'
}

// ── ATTR-TYPE ──
fn test_attr_null_autotypes() {
	assert cc('[u nil=null]') == '[u nil=null]'
	assert cc('[u nil=null]') == xc('[u nil=null]')
}

fn test_attr_string_unaffected() {
	// A plain bareword attr value stays a string.
	assert cc('[u name=pizza]') == xc('[u name=pizza]')
}
