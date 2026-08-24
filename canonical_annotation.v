module cx

// canonical_annotation.v — strict-canonical redundant type-ascription strip
// (I1 identity epoch; campaign stream 12, row 2: one value, one spelling).
//
// An element-level `::T` ascription is REDUNDANT when bare re-typing of the
// canonical body image reproduces the same typed value — `[n::int 1]` and
// `[n 1]` denote the same int, so they must share one canonical spelling
// (hence one Tier-1 address). The attr lane has stripped these since D3
// (cx_attr_scalar); this pass closes the element lane by clearing
// `e.data_type` when redundant, so every emit branch renders the bare form
// and the body emitter's quoting rules take over — a date-shaped `::string`
// body emits QUOTED (`[n '2026-08-05']`), exactly as the attr lane quotes
// `v='2026-08-05'`.
//
// Load-bearing ascriptions stay: sized numerics / decimal / bigint / bytes /
// f16 / duration / period (no self-evident lexical form — the same set the
// attr lane keeps glued), array types (`::T[]` / `::[]`), the internal table
// marker, an empty or whitespace-only body (nothing left to re-type), and
// any body that is not exactly one scalar.

// canonicalize_annotations strips every redundant element-level `::T`
// ascription in the document. Runs after canonicalize_datetimes so the
// re-type oracle judges the final (UTC-Z-normalized) body image.
pub fn canonicalize_annotations(mut doc Document) {
	canonical_ann_nodes(mut doc.prolog)
	canonical_ann_nodes(mut doc.elements)
}

fn canonical_ann_nodes(mut nodes []Node) {
	for i := 0; i < nodes.len; i++ {
		mut n := nodes[i]
		match mut n {
			Element {
				canonical_ann_nodes(mut n.items)
				if element_annotation_is_redundant(n) {
					n.set_data_type(none)
				}
				nodes[i] = n
			}
			SequenceNode {
				canonical_ann_nodes(mut n.items)
				nodes[i] = n
			}
			ArrayNode {
				canonical_ann_nodes(mut n.items)
				nodes[i] = n
			}
			MapNode {
				for j := 0; j < n.entries.len; j++ {
					canonical_ann_node(mut n.entries[j].value)
				}
				nodes[i] = n
			}
			else {}
		}
	}
}

fn canonical_ann_node(mut n Node) {
	mut arr := [n]
	canonical_ann_nodes(mut arr)
	n = arr[0]
}

// element_annotation_is_redundant reports whether e's `::T` ascription is
// reproduced by bare re-typing of the canonical body image — the decision
// table mirrors cx_attr_scalar's attr-lane rules exactly.
fn element_annotation_is_redundant(e Element) bool {
	dt := e.data_type() or { return false }
	if dt.ends_with('[]') || dt == '[]' || dt == 'table' {
		return false
	}
	// Exactly one scalar item — mixed bodies, retained comments, and empty
	// bodies keep their ascription (nothing to re-type in body position).
	if e.items.len != 1 {
		return false
	}
	sn := e.items[0]
	if dt == 'string' {
		// A string body may sit as a coerced ScalarNode (bare token) or a
		// TextNode (quoted source) — the value is the text either way, and
		// a bare or quoted re-read reproduces it: the emitter quotes any
		// image that would autotype away, the empty string survives as `''`
		// (W-6), and whitespace-only strings survive quoted (the W-6
		// companion ruling). Every string body carries its own type — the
		// ascription is always the second spelling.
		match sn {
			TextNode {
				return true
			}
			ScalarNode {
				if sn.data_type != .string_type {
					return false
				}
				return sn.value is string
			}
			else {
				return false
			}
		}
	}
	if sn !is ScalarNode {
		return false
	}
	body := sn as ScalarNode
	if dt == 'atom' {
		// The body emits the `:name` sigil, and the sigil alone re-types
		// atom ([L40]) — the head ascription is always the double spelling.
		// (Reserved :true/:false/:null can never be atom names — CXERLEX-ATOM.)
		return body.data_type == .atom_type
	}
	if dt == 'bigint' || dt == 'decimal' {
		// I1 stream 11 (L45 + ruling 2b): the ascription strips exactly when
		// the bare image re-types the SAME kind on its own — over-i64
		// bigints auto-promote ([L20]); fixed-point fractions ARE decimals
		// (2b), so `[a::decimal 1.50]` sheds its annotation while an
		// integral-image decimal (`[a::decimal 2]` → image `2` re-types
		// int) keeps it.
		if sn is ScalarNode {
			bg := sn as ScalarNode
			want := if dt == 'bigint' { ScalarType.bigint_type } else { ScalarType.decimal_type }
			if bg.data_type == want {
				re := try_autotype(cx_scalar(bg)) or { return false }
				return re.data_type == want
			}
		}
		return false
	}
	if !type_name_is_auto_recoverable(dt) {
		return false
	}
	// The ascription must agree with the parsed body's kind — a divergent
	// pair is not this pass's business.
	expected := scalar_type_from_name(dt) or { return false }
	if body.data_type != expected {
		return false
	}
	// The bare-typing oracle: the canonical body image must re-type to the
	// same kind (value equality follows — the image IS the value's render).
	re := try_autotype(cx_scalar(body)) or { return false }
	return re.data_type == body.data_type
}
