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
//   - `cx`    → tag:cxhome.org,2026:ns/cx            (CX metadata)
//   - `xmlns` → declaration-only; never resolves as a name prefix
//
// Default-namespace semantics (XML Namespaces 1.0 §6.2):
//   - `xmlns=URI` declares a default ns scoped to declaring element
//     and unprefixed descendants until redeclared.
//   - Default ns applies to elements only — unprefixed attributes
//     are NEVER in any namespace. This module preserves that rule.

pub const xml_namespace_uri = 'http://www.w3.org/XML/1998/namespace'

// I1 stream 15 (L50): the CX namespace URI is the RFC 4151 tag URI —
// permanently valid independent of DNS registration (the date pins the
// authority moment). cxhome.org remains only the rotatable
// resolution/infrastructure host; the URI is an IDENTIFIER, never
// dereferenced. Changing this string is an identity migration (the XML
// C14N image signs it) — owner-ruled only.
pub const cx_namespace_uri = 'tag:cxhome.org,2026:ns/cx'

// L51: both legacy https spellings are RESERVED aliases — recognized only
// to REJECT (E213 on binding), never carriers, never user namespaces.
// This closes the squatting/confusion hole the historical
// cxhome.org / cx-home.org split created (#704).
pub const cx_namespace_uri_legacy = [
	'https://cxhome.org/ns/cx',
	'https://cx-home.org/ns/cx',
]!

// is_cx_namespace_spelling reports whether `uri` is ANY spelling that ever
// denoted the CX namespace — the canonical tag URI or a reserved legacy
// alias. Reserved-URI enforcement (#704) matches on this, not on prefixes.
pub fn is_cx_namespace_spelling(uri string) bool {
	if uri == cx_namespace_uri {
		return true
	}
	for l in cx_namespace_uri_legacy {
		if uri == l {
			return true
		}
	}
	return false
}

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

// validate_reserved_ns_bindings — I1 stream 15 (#704, L50/L51): reserved-
// namespace enforcement by RESOLVED URI, not literal prefix. Binding any
// prefix (or the default namespace) to the CX namespace URI is a loud
// E213, in EVERY spelling that ever denoted it; the reserved `cx` prefix
// may not be re-bound to anything else. ONE carve-out: `xmlns:cx` bound to
// the canonical tag URI restates the built-in binding the XML C14N image
// MUST declare on its root (parser-rules) — accepted; strict canonical
// strips it (canonical.md §2.7a: cx:/xml: are never emitted as
// declarations). Called at the tail of every parse entry, right after
// resolve_namespaces, so no lane (CX, XML, JSON, MD, ast_bin) can smuggle
// the reserved URI into Tier-1 bytes — the pre-#704 canonicalizer
// rewrote `p:x`→`cx:x` while PRESERVING the declaration, emitting output
// its own parser rejects (a canonical∘canonical non-idempotence).
pub fn validate_reserved_ns_bindings(doc Document) ! {
	for n in doc.elements {
		if n is Element {
			validate_reserved_ns_el(n)!
		}
	}
}

fn validate_reserved_ns_el(e Element) ! {
	cx_check_reserved_ns_attrs(e.attrs)!
	for item in e.items {
		if item is Element {
			validate_reserved_ns_el(item)!
		}
	}
}

// cx_check_reserved_ns_attrs is the per-element core of the #704
// enforcement — exposed so the program engine's element-literal lane
// (which materializes elements without a Document-level parse tail)
// applies the SAME rule; the two readings must agree on every document.
pub fn cx_check_reserved_ns_attrs(attrs []Attribute) ! {
	for a in attrs {
		is_default := a.name == 'xmlns'
		is_pfx := a.name.starts_with('xmlns:') && a.name.len > 6
		if !is_default && !is_pfx {
			continue
		}
		uri := scalar_value_str(a.value)
		pfx := if is_pfx { a.name[6..] } else { '' }
		if is_cx_namespace_spelling(uri) {
			if pfx == 'cx' && uri == cx_namespace_uri {
				continue // the mandated C14N carrier declaration (no-op)
			}
			return error('`${a.name}` binds the reserved CX namespace URI — the namespace is built-in and may not be bound (its legacy https spellings are reserved-to-reject) (cx-err:E213)')
		}
		if pfx == 'cx' {
			return error('the `cx` namespace prefix is reserved and may not be re-bound (`${a.name}=${uri}`) (cx-err:E213)')
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
	// Allocate a scope frame only when this element ACTUALLY declares a
	// namespace (#804). The frame was built unconditionally and then
	// discarded whenever it came out empty — one map allocation per
	// element, and the overwhelming majority of elements declare
	// nothing (gate-15's JSON-shape corpus declares none at all). The
	// pre-scan reads the same attrs the frame loop does, and `pushed`
	// still means exactly "a non-empty frame is on the scope stack":
	// only these two attribute shapes ever write to it.
	mut declares_ns := false
	for a in e.attrs {
		if a.name == 'xmlns' || (a.name.starts_with('xmlns:') && a.name.len > 6) {
			declares_ns = true
			break
		}
	}
	mut pushed := false
	if declares_ns {
		mut frame := map[string]string{}
		for a in e.attrs {
			if a.name == 'xmlns' {
				frame[''] = scalar_value_str(a.value)
			} else if a.name.starts_with('xmlns:') && a.name.len > 6 {
				frame[a.name[6..]] = scalar_value_str(a.value)
			}
		}
		if frame.len > 0 {
			scope << frame
			pushed = true
		}
	}

	prefix, local := split_ns_prefix(e.name)
	if local != e.name {
		e.set_local(local)
	}
	e.set_ns_uri(lookup_element_ns(prefix, scope))

	for i := 0; i < e.attrs.len; i++ {
		ap, al := split_ns_prefix(e.attrs[i].name)
		// Only record `local` when it DIFFERS from the name — the same
		// guard the element side above already applies, and what the
		// AttributeMeta contract says ("Empty when local == name").
		// Writing it unconditionally forced an AttributeMeta allocation
		// for every attribute (#804); Attribute.local() now falls back
		// to the name for an unset slot, exactly as Element.local() does.
		if al != e.attrs[i].name {
			e.attrs[i].set_local(al)
		}
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
			// I1 stream 15 (§2.7a): `xmlns:cx="<canonical URI>"` restates
			// the built-in binding (the accepted C14N carrier declaration)
			// — strict canonical STRIPS it, so the declared and undeclared
			// spellings of one document share one address. Every other
			// binding of the reserved URI was rejected at parse (E213).
			if a.name == 'xmlns:cx' && scalar_value_str(a.value) == cx_namespace_uri {
				continue
			}
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
