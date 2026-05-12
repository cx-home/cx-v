module cx

// identity.v — ID/IDREF resolution per ADR 0003.
//
// Walks a parsed Document and:
//   1. Collects all elements declaring `#id` into the document-scope
//      ID table. Duplicate declarations are an error reporting both
//      source IDs (the second occurrence triggers the error since
//      the first was registered when seen).
//   2. Validates every attribute marked `is_ref=true` against the
//      table, surfacing a parse error for unresolved references.
//
// v0 limitations (documented; tracked in ROADMAP):
//   - Document scope only. The `[?cx include=other.cx]` directive
//     does NOT yet merge ID spaces across files (ADR 0003 D3 second
//     paragraph). Cross-include references are out of scope until
//     the include-resolution work lands.
//   - No XML round-trip mapping yet. `xs:ID` / `xs:IDREF` import +
//     export deferred to a follow-up phase (ADR 0003 D6 first bullet).
//   - No canonical-form ID renaming yet (ADR 0003 D7).
//   - `[ref @id]` body-position node form (ADR 0003 D1 second bullet)
//     is not yet recognized; only attribute-value `@id` references.
//   - C ABI surface (cx_resolve_ref / cx_node_id / cx_id_lookup) and
//     9-binding rollout are deferred. Public V API (resolve_id /
//     elements_by_id) is the v0 surface.

// resolve_ids walks the document, builds the ID table, and validates
// every reference attribute against it. Idempotent for documents
// without ID conflicts; calling twice is safe. Errors:
//   - duplicate-ID: a `#name` appearing on two different elements.
//   - unresolved-reference: an `@name` whose target ID was not
//     declared anywhere in the document.
pub fn resolve_ids(doc Document) ! {
	mut id_table := map[string]bool{}
	collect_ids(doc.elements, mut id_table)!
	collect_ids(doc.prolog, mut id_table)!
	validate_refs(doc.elements, id_table)!
	validate_refs(doc.prolog, id_table)!
}

fn collect_ids(nodes []Node, mut id_table map[string]bool) ! {
	for n in nodes {
		if n is Element {
			if id := n.id {
				if id in id_table {
					return error("duplicate ID '#${id}' — declared on more than one element in the document")
				}
				id_table[id] = true
			}
			collect_ids(n.items, mut id_table)!
		}
	}
}

fn validate_refs(nodes []Node, id_table map[string]bool) ! {
	for n in nodes {
		if n is Element {
			for a in n.attrs {
				if a.is_ref {
					ref_id := scalar_value_str(a.value)
					if ref_id !in id_table {
						return error("unresolved reference '@${ref_id}' on attribute '${a.name}' — no '#${ref_id}' declared in the document")
					}
				}
			}
			if br := n.body_ref {
				if br !in id_table {
					return error("unresolved reference '[ref @${br}]' — no '#${br}' declared in the document")
				}
			}
			validate_refs(n.items, id_table)!
		}
	}
}

// resolve_id returns the Element declaring `#id`, or none if no such
// declaration exists in the document. Walks the tree on each call;
// callers that need repeated lookups should cache via a local map
// built from elements_by_id().
pub fn (d Document) resolve_id(id string) ?Element {
	return find_element_by_id(d.elements, id) or {
		find_element_by_id(d.prolog, id) or { return none }
	}
}

fn find_element_by_id(nodes []Node, id string) ?Element {
	for n in nodes {
		if n is Element {
			if eid := n.id {
				if eid == id {
					return n
				}
			}
			if found := find_element_by_id(n.items, id) {
				return found
			}
		}
	}
	return none
}

// elements_by_id returns a map from id-string to the Element
// declaring it. Built once for the whole document; useful for
// repeated reference resolution.
pub fn (d Document) elements_by_id() map[string]Element {
	mut out := map[string]Element{}
	collect_elements_by_id(d.elements, mut out)
	collect_elements_by_id(d.prolog, mut out)
	return out
}

fn collect_elements_by_id(nodes []Node, mut out map[string]Element) {
	for n in nodes {
		if n is Element {
			if eid := n.id {
				out[eid] = n
			}
			collect_elements_by_id(n.items, mut out)
		}
	}
}

// canonicalize_ids rewrites every `#id` declaration to a deterministic
// `id-N` name in document order, and rewrites every `is_ref` attribute
// value to track the renamed declaration. Per ADR 0003 D7: two
// documents that differ only in ID *spelling* produce byte-identical
// strict-canonical output (and therefore hash to the same value).
//
// Numbering: declarations are visited depth-first in source order;
// the Nth declaration becomes `id-N` (1-indexed). Reference values
// pointing at undeclared IDs are left unchanged (the parse-time
// resolve_ids pass would already have errored on them; surfacing
// here is defensive).
//
// Idempotent: running on input whose ids already match the
// `id-1`, `id-2`, ... document-order pattern produces the same
// output. Run from cx_text_canonical (strict canonical) only;
// lossless cx fmt preserves source spellings per
// spec/canonical.md §2.7b.
pub fn canonicalize_ids(mut doc Document) {
	mut rename := map[string]string{}
	collect_id_renames(doc.prolog, mut rename)
	collect_id_renames(doc.elements, mut rename)
	if rename.len == 0 {
		return
	}
	apply_id_renames(mut doc.prolog, rename)
	apply_id_renames(mut doc.elements, rename)
}

fn collect_id_renames(nodes []Node, mut rename map[string]string) {
	for n in nodes {
		if n is Element {
			if eid := n.id {
				if eid !in rename {
					rename[eid] = 'id-${rename.len + 1}'
				}
			}
			collect_id_renames(n.items, mut rename)
		}
	}
}

fn apply_id_renames(mut nodes []Node, rename map[string]string) {
	for i := 0; i < nodes.len; i++ {
		mut n := nodes[i]
		if mut n is Element {
			rename_element_ids(mut n, rename)
			nodes[i] = n
		}
	}
}

fn rename_element_ids(mut e Element, rename map[string]string) {
	if eid := e.id {
		if new_name := rename[eid] {
			e.id = new_name
		}
	}
	if br := e.body_ref {
		if new_name := rename[br] {
			e.body_ref = new_name
		}
	}
	for j := 0; j < e.attrs.len; j++ {
		if e.attrs[j].is_ref {
			ref_id := scalar_value_str(e.attrs[j].value)
			if new_name := rename[ref_id] {
				e.attrs[j].value = ScalarValue(new_name)
			}
		}
	}
	for j := 0; j < e.items.len; j++ {
		mut item := e.items[j]
		if mut item is Element {
			rename_element_ids(mut item, rename)
			e.items[j] = item
		}
	}
}
