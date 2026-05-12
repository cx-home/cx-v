module cx

import crypto.sha256

// Canonical-form tooling per spec/canonical.md and spec/abi.md §2.6.
//
// Public V API:
//   cx_text_fmt(input)        -> lossless canonical text CX
//   cx_text_canonical(input)  -> strict canonical text CX
//   cx_text_hash(input)       -> SHA-256 hex of strict canonical bytes
//   cx_text_eq(a, b)          -> true iff strict canonical(a) == strict canonical(b)
//
// Names are prefixed `cx_text_` (rather than just `fmt`/`canonical`/etc.)
// because the V module is `cx`, and the C ABI exports — which use the
// short names — live in cabi.v as `cx_fmt`, `cx_canonical`, `cx_hash`,
// `cx_eq`. The prefix here avoids clashing with V keywords/builtins.
//
// v0 limitations (documented; future enhancement):
//   - Strict canonical strips Comment, RawText, BlockContent, CXDirective,
//     and XMLDecl from prolog/items, and drops Element.anchor /
//     Element.merge metadata. It does NOT resolve anchor/alias references
//     or expand merges to their referent's content. For the vast majority
//     of CX documents (which use neither anchors nor merges) this is a
//     correct strict canonical. Documents that rely on anchor/merge for
//     semantic content will produce incorrect strict canonical bytes;
//     when the merge-resolver lands those will become correct.

// cx_text_fmt parses the input and re-emits it through the lossless
// CX emitter. Property: cx_text_fmt(cx_text_fmt(x)) == cx_text_fmt(x)
// for any valid input.
pub fn cx_text_fmt(input string) !string {
	doc := parse(input)!
	return emit_cx(doc)
}

// cx_text_canonical parses the input, strips presentation nodes,
// canonicalizes namespace prefix usage and xmlns-declaration order
// per ADR 0002 D6, sorts MapNode entries into lexicographic Unicode
// order per ADR 0017 §D14 / spec/canonical.md §2.11.1, and re-emits
// it. The output is the strict canonical text per spec/canonical.md
// §1.2.
pub fn cx_text_canonical(input string) !string {
	doc := parse(input)!
	mut stripped := canonicalize_doc(doc)
	canonicalize_namespaces(mut stripped)
	canonicalize_ids(mut stripped)
	canonicalize_collection_literals(mut stripped)
	return emit_cx(stripped)
}

// cx_text_hash returns the lowercase hex SHA-256 of the strict
// canonical text bytes.
pub fn cx_text_hash(input string) !string {
	canonical := cx_text_canonical(input)!
	digest := sha256.sum256(canonical.bytes())
	return digest.hex()
}

// cx_text_eq returns true iff the strict canonical of `a` equals the
// strict canonical of `b` (byte-identical, not just data-equivalent —
// per the canonical-form spec, byte-identity *is* data equivalence).
pub fn cx_text_eq(a string, b string) !bool {
	ca := cx_text_canonical(a)!
	cb := cx_text_canonical(b)!
	return ca == cb
}

// canonicalize_doc returns a new Document with presentation-only
// nodes stripped: Comment, RawText, CXDirective, XMLDecl, BlockContent.
// Anchor/merge metadata on Elements is also dropped (v0 — see note at
// top of file).
fn canonicalize_doc(d Document) Document {
	mut new_prolog := []Node{cap: d.prolog.len}
	for n in d.prolog {
		if keep := canonicalize_node(n) {
			new_prolog << keep
		}
	}
	mut new_elements := []Node{cap: d.elements.len}
	for n in d.elements {
		if keep := canonicalize_node(n) {
			new_elements << keep
		}
	}
	return Document{
		prolog:   new_prolog
		doctype:  d.doctype
		elements: new_elements
	}
}

// canonicalize_node returns Some(stripped node) if it should be kept,
// None if it should be dropped from the parent's items list.
fn canonicalize_node(n Node) ?Node {
	match n {
		CommentNode, RawTextNode, CXDirectiveNode, XMLDeclNode {
			return none
		}
		BlockContentNode {
			// BlockContent is presentation; expand its items in place
			// so callers see a flattened list. Since we can't return
			// multiple nodes from one call, drop the wrapper here and
			// let the caller's list-build flatten via canonicalize_items.
			return none
		}
		Element {
			mut new_items := []Node{cap: n.items.len}
			for item in n.items {
				if item is BlockContentNode {
					// Inline BlockContent's items into the parent.
					for inner in item.items {
						if keep := canonicalize_node(inner) {
							new_items << keep
						}
					}
				} else if keep := canonicalize_node(item) {
					new_items << keep
				}
			}
			return Node(Element{
				name:      n.name
				anchor:    none // strip anchor metadata
				merge:     none // strip merge metadata
				data_type: n.data_type
				attrs:     n.attrs
				items:     new_items
				id:        n.id // preserved; canonicalize_ids renames in document order
				body_ref:  n.body_ref // preserved; canonicalize_ids rewrites
			})
		}
		else {
			// TextNode, ScalarNode, EntityRefNode, AliasNode, PINode,
			// DoctypeDecl, SequenceNode, ArrayNode, MapNode: keep as-is.
			// Collection-literal canonicalization (lex key sort for maps,
			// recursive descent) runs in a dedicated pass —
			// canonicalize_collection_literals below.
			return n
		}
	}
}

// canonicalize_collection_literals rewrites every MapNode in the
// document so its entries appear in lexicographic Unicode order of
// the canonical key serialization per ADR 0017 §D14 + spec/canonical.md
// §2.11.1. SequenceNode and ArrayNode items keep their source order
// (sequences are flat at parse time per CXDM §1, arrays are nested-
// preserving per §D3). Recurses into element bodies, sequence /
// array / map values, and map values. Idempotent: a map already in
// canonical order produces the same output.
pub fn canonicalize_collection_literals(mut doc Document) {
	canonicalize_collection_nodes(mut doc.prolog)
	canonicalize_collection_nodes(mut doc.elements)
}

fn canonicalize_collection_nodes(mut nodes []Node) {
	for i := 0; i < nodes.len; i++ {
		mut n := nodes[i]
		if mut n is Element {
			canonicalize_collection_nodes(mut n.items)
			nodes[i] = n
		} else if mut n is SequenceNode {
			canonicalize_collection_nodes(mut n.items)
			nodes[i] = n
		} else if mut n is ArrayNode {
			canonicalize_collection_nodes(mut n.items)
			nodes[i] = n
		} else if mut n is MapNode {
			for j := 0; j < n.entries.len; j++ {
				mut value_nodes := [n.entries[j].value]
				canonicalize_collection_nodes(mut value_nodes)
				n.entries[j].value = value_nodes[0]
			}
			n.entries.sort_with_compare(map_entry_cmp)
			nodes[i] = n
		}
	}
}

// map_entry_cmp implements the canonical-form key ordering rules
// from spec/canonical.md §2.11.1. The primary sort is by type-tag
// name (bool < bytes < date < datetime < float < int < string); ties
// break by lexicographic Unicode order of the canonical-string
// serialization of the key value. v0.6.0 restricts map keys to
// strings per ADR §D4 — the type-tag tie-break is in place for the
// CXL 3.1 widening but exercises rarely today.
fn map_entry_cmp(a &MapEntry, b &MapEntry) int {
	a_tag := map_key_type_tag_name(a.key_type)
	b_tag := map_key_type_tag_name(b.key_type)
	if a_tag != b_tag {
		return if a_tag < b_tag { -1 } else { 1 }
	}
	a_key := scalar_value_str(a.key_value)
	b_key := scalar_value_str(b.key_value)
	if a_key < b_key { return -1 }
	if a_key > b_key { return 1 }
	return 0
}

fn map_key_type_tag_name(t ScalarType) string {
	return match t {
		.bool_type     { 'bool' }
		.bytes_type    { 'bytes' }
		.date_type     { 'date' }
		.datetime_type { 'datetime' }
		.float_type    { 'float' }
		.int_type      { 'int' }
		.string_type   { 'string' }
		.null_type     { 'null' }
		.decimal_type  { 'decimal' }
		.bigint_type   { 'bigint' }
	}
}
