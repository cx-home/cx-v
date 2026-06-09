module cx

// namespaces.v — namespace resolution.
//
// Walks a parsed Document and populates Element.{local, ns_uri}
// and Attribute.{local, ns_uri} based on in-scope xmlns / xmlns:
// declarations. Called once at the tail of every parse entry point
// (CX, XML, JSON, YAML, TOML, MD, ast_bin) so downstream consumers
// see a uniform expanded-name view of the document.
//
// Reserved prefixes:
//   - `xml`   → http://www.w3.org/XML/1998/namespace (XML built-in)
//   - `cx`    → https://cx-home.org/ns/cx           (CX metadata)
//   - `xmlns` → declaration-only; never resolves as a name prefix
//
// Default-namespace semantics (XML Namespaces 1.0 §6.2):
//   - `xmlns=URI` declares a default ns scoped to declaring element
//     and unprefixed descendants until redeclared.
//   - Default ns applies to elements only — unprefixed attributes
//     are NEVER in any namespace. This module preserves that rule.

pub const xml_namespace_uri = 'http://www.w3.org/XML/1998/namespace'
pub const cx_namespace_uri  = 'https://cx-home.org/ns/cx'

// resolve_namespaces walks the document and populates expanded-name
// fields on every Element and Attribute. Idempotent: calling twice
// produces the same result. Called automatically by parse(),
// parse_xml(), parse_yaml(), parse_toml(), and the ast_bin decoder.
//
// Z2: also resolves inherited cx:lang scope per spec/i18n.md
// §1.3 — each Element's `lang_resolved` field is populated with the
// nearest in-scope BCP 47 language tag (or empty Option when no
// cx:lang is in scope, or Some("") when explicitly shadowed).
pub fn resolve_namespaces(mut doc Document) {
	mut scope := []map[string]string{}
	for i := 0; i < doc.elements.len; i++ {
		mut n := doc.elements[i]
		if mut n is Element {
			resolve_element(mut n, mut scope)
			doc.elements[i] = n
		}
	}
	// Language-scope pass. Independent of the namespace pass because
	// cx:lang inheritance follows element nesting only, with no
	// xmlns-scope interactions.
	mut lang_stack := []?string{}
	for i := 0; i < doc.elements.len; i++ {
		mut n := doc.elements[i]
		if mut n is Element {
			resolve_element_lang(mut n, mut lang_stack)
			doc.elements[i] = n
		}
	}
}

// resolve_element_lang propagates the in-scope cx:lang per
// spec/i18n.md §1.3. Stack holds the lang tags of strict ancestors
// (innermost-on-top); on entry we look for an own `cx:lang` attribute
// and otherwise inherit the top-of-stack value.
fn resolve_element_lang(mut e Element, mut stack []?string) {
	mut own_lang := ?string(none)
	mut declared := false
	for a in e.attrs {
		if a.name == 'cx:lang' {
			own_lang = scalar_value_str(a.value)
			declared = true
			break
		}
	}
	resolved := if declared {
		own_lang
	} else if stack.len > 0 {
		stack[stack.len - 1]
	} else {
		?string(none)
	}
	e.set_lang_resolved(resolved)
	stack << resolved
	for i := 0; i < e.items.len; i++ {
		mut item := e.items[i]
		if mut item is Element {
			resolve_element_lang(mut item, mut stack)
			e.items[i] = item
		}
	}
	stack.delete_last()
}

fn resolve_element(mut e Element, mut scope []map[string]string) {
	mut frame := map[string]string{}
	for a in e.attrs {
		if a.name == 'xmlns' {
			frame[''] = scalar_value_str(a.value)
		} else if a.name.starts_with('xmlns:') && a.name.len > 6 {
			frame[a.name[6..]] = scalar_value_str(a.value)
		}
	}
	pushed := frame.len > 0
	if pushed {
		scope << frame
	}

	prefix, local := split_ns_prefix(e.name)
	if local != e.name {
		e.set_local(local)
	}
	e.set_ns_uri(lookup_element_ns(prefix, scope))

	for i := 0; i < e.attrs.len; i++ {
		ap, al := split_ns_prefix(e.attrs[i].name)
		e.attrs[i].set_local(al)
		if e.attrs[i].name == 'xmlns' || ap == 'xmlns' {
			e.attrs[i].set_ns_uri(?string(none))
			continue
		}
		if ap == '' {
			// Default ns does not apply to unprefixed attrs.
			e.attrs[i].set_ns_uri(?string(none))
			continue
		}
		e.attrs[i].set_ns_uri(lookup_attribute_ns(ap, scope))
	}

	for i := 0; i < e.items.len; i++ {
		mut item := e.items[i]
		if mut item is Element {
			resolve_element(mut item, mut scope)
			e.items[i] = item
		}
	}

	if pushed {
		scope.delete_last()
	}
}

// split_ns_prefix splits a name like "prefix:local" into ("prefix",
// "local"). For "local" with no colon returns ("", "local"). The
// first colon delimits; trailing colons (e.g., XML Schema's
// "xs:simpleType") only the first matters in CX since prefixes are
// single-segment identifiers.
fn split_ns_prefix(name string) (string, string) {
	for i := 0; i < name.len; i++ {
		if name[i] == `:` {
			return name[..i], name[i + 1..]
		}
	}
	return '', name
}

fn lookup_element_ns(prefix string, scope []map[string]string) ?string {
	if prefix == 'xml' {
		return xml_namespace_uri
	}
	if prefix == 'cx' {
		return cx_namespace_uri
	}
	if prefix == 'xmlns' {
		return ?string(none)
	}
	for i := scope.len - 1; i >= 0; i-- {
		if uri := scope[i][prefix] {
			if uri.len > 0 {
				return uri
			}
			// Empty URI un-declares (XML Namespaces 1.0 errata)
			return ?string(none)
		}
	}
	return ?string(none)
}

fn lookup_attribute_ns(prefix string, scope []map[string]string) ?string {
	// Same lookup rules as elements except default-ns does not apply
	// (caller already short-circuits prefix=='').
	return lookup_element_ns(prefix, scope)
}

// ── Canonical-form namespace rewrite (/ namespaces.md §3.2) ──
//
// Strict canonical form requires deterministic prefix selection so that
// two semantically equal namespaced documents — e.g., one declaring
// `xmlns:foo=urn:x` and using `foo:bar`, the other declaring
// `xmlns:bar=urn:x` and using `bar:bar` — hash to the same value via
// `cx hash` (which is SHA-256 of strict-canonical bytes).
//
// canonicalize_namespaces walks the document with a scope stack and:
//   1. For every element/attribute whose source name uses a prefix
//      that resolves to a URI, rewrites the prefix to the lex-
//      smallest in-scope prefix mapping to that URI.
//   2. Sorts the xmlns / xmlns:* declaration attributes within each
//      declaring element: default-namespace declaration (`xmlns=...`)
//      first when present, then xmlns:prefix declarations in
//      lexicographic order by prefix.
//   3. Preserves all non-xmlns attributes in source order, after the
//      sorted xmlns block. (This is the only deviation from the
//      §2.1 "attribute order = source order" rule, scoped to xmlns
//      declarations only — required for cross-document hash equality.)
//
// Reserved prefixes `xml:` and `cx:` are seeded into every scope and
// never appear as xmlns declarations on emit; they don't participate
// in the sort step. They CAN be canonical winners if a document
// happens to declare an alias prefix for the XML or CX URIs.
//
// Idempotent. Run from cx_text_canonical (strict canonical) only;
// lossless `cx fmt` preserves source attribute order verbatim per
// spec/canonical.md §2.1.
pub fn canonicalize_namespaces(mut doc Document) {
	mut scope := []map[string]string{}
	for i := 0; i < doc.elements.len; i++ {
		mut n := doc.elements[i]
		if mut n is Element {
			canonicalize_element_ns(mut n, mut scope)
			doc.elements[i] = n
		}
	}
}

fn canonicalize_element_ns(mut e Element, mut scope []map[string]string) {
	mut frame := map[string]string{}
	mut xmlns_attrs := []Attribute{}
	mut other_attrs := []Attribute{}
	for a in e.attrs {
		if a.name == 'xmlns' {
			frame[''] = scalar_value_str(a.value)
			xmlns_attrs << a
		} else if a.name.starts_with('xmlns:') && a.name.len > 6 {
			frame[a.name[6..]] = scalar_value_str(a.value)
			xmlns_attrs << a
		} else {
			other_attrs << a
		}
	}

	pushed := xmlns_attrs.len > 0
	if pushed {
		scope << frame
	}

	if xmlns_attrs.len > 1 {
		xmlns_attrs.sort_with_compare(canonical_xmlns_compare)
	}

	flat := flatten_scope_with_reserved(scope)
	canon_pfx := canonical_prefix_per_uri(flat)

	e_pfx, e_local := split_ns_prefix(e.name)
	if e_pfx != '' {
		if uri := flat[e_pfx] {
			if uri.len > 0 {
				if cp := canon_pfx[uri] {
					if cp != '' && cp != e_pfx {
						e.name = cp + ':' + e_local
					}
				}
			}
		}
	}

	for i := 0; i < other_attrs.len; i++ {
		ap, al := split_ns_prefix(other_attrs[i].name)
		if ap == '' || ap == 'xmlns' {
			continue
		}
		if uri := flat[ap] {
			if uri.len == 0 {
				continue
			}
			if cp := canon_pfx[uri] {
				if cp != '' && cp != ap {
					other_attrs[i].name = cp + ':' + al
				}
			}
		}
	}

	mut new_attrs := []Attribute{cap: e.attrs.len}
	for a in xmlns_attrs {
		new_attrs << a
	}
	for a in other_attrs {
		new_attrs << a
	}
	e.attrs = new_attrs

	for i := 0; i < e.items.len; i++ {
		mut item := e.items[i]
		if mut item is Element {
			canonicalize_element_ns(mut item, mut scope)
			e.items[i] = item
		}
	}

	if pushed {
		scope.delete_last()
	}
}

fn canonical_xmlns_compare(a &Attribute, b &Attribute) int {
	a_default := a.name == 'xmlns'
	b_default := b.name == 'xmlns'
	if a_default && !b_default {
		return -1
	}
	if !a_default && b_default {
		return 1
	}
	if a.name < b.name {
		return -1
	}
	if a.name > b.name {
		return 1
	}
	return 0
}

fn flatten_scope_with_reserved(scope []map[string]string) map[string]string {
	mut flat := map[string]string{}
	for f in scope {
		for k, v in f {
			flat[k] = v
		}
	}
	flat['xml'] = xml_namespace_uri
	flat['cx']  = cx_namespace_uri
	return flat
}

// canonical_prefix_per_uri picks the lex-smallest non-empty prefix
// mapping to each URI in the flattened in-scope map. The empty-key
// (default-namespace) entry never wins — default ns doesn't apply
// to attributes (XML Namespaces 1.0 §6.2) and we want a single rule
// for elements + attributes alike.
fn canonical_prefix_per_uri(flat map[string]string) map[string]string {
	mut canon := map[string]string{}
	for pfx, uri in flat {
		if uri.len == 0 || pfx == '' {
			continue
		}
		if existing := canon[uri] {
			if pfx < existing {
				canon[uri] = pfx
			}
		} else {
			canon[uri] = pfx
		}
	}
	return canon
}
