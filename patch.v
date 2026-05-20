module cx

import strconv

// ── DD6 cx:patch engine (spec/modules/cx.md §1.1) ────────────────────────
//
// Apply a diff doc to a cx-value, producing the patched cx-value.
// The diff doc shape mirrors what cx:diff produces (a sequence of
// `[item ...]` records per `vcx/cx/diff.v`):
//
//   [item
//     [kind <change-kind>]
//     [path <cxpath>]
//     [before <scalar>]
//     [after <scalar>]
//   ]
//
// Path syntax matches the diff renderer at `vcx/cx/diff.v`:
//   /name              — unique-named root child
//   /name[2]           — positional sibling (1-based)
//   /a/b               — nested
//   /a/b/@attr         — attribute on element
//
// The patch engine traverses by parsing the path into segments,
// walks the Element tree to the target, and applies the kind-
// specific mutation. Order changes are applied in input order;
// callers needing transactional semantics should snapshot their
// value before invoking patch.

pub struct PatchChange {
pub:
	kind   string
	path   string
	before string
	after  string
}

// patch_value applies a list of changes to a cx-value, returning a
// new mutated value. Surfaces errors as cx-err:CXER0022 when a
// change cannot be applied (path-not-found, unknown kind, before-
// value mismatch).
pub fn patch_value(v CXLValue, changes []PatchChange) !CXLValue {
	if changes.len == 0 {
		return v
	}
	if v.len == 0 {
		// Empty value + nonempty patch → can't apply.
		return error('cx-err:CXER0022\x1Fcx:patch cannot apply ${changes.len} change(s) to an empty value\x1F')
	}
	// Project to a Document so we can mutate elements.
	mut doc := cxl_value_to_doc(v)
	for ch in changes {
		apply_change(mut doc, ch)!
	}
	// Re-project back to a CXLValue.
	mut items := []CXLItem{cap: doc.elements.len}
	for n in doc.elements {
		match n {
			Element { items << CXLItem(n) }
			TextNode, ScalarNode, CommentNode, PINode, CXDirectiveNode,
			ArrayNode, MapNode { items << CXLItem(n) }
			else {}
		}
	}
	return CXLValue(items)
}

// apply_change dispatches one PatchChange to its kind-specific handler.
fn apply_change(mut doc Document, ch PatchChange) ! {
	segments := parse_patch_path(ch.path) or {
		return error('cx-err:CXER0022\x1Fcx:patch malformed path "${ch.path}": ${err.msg()}\x1F')
	}
	match ch.kind {
		'element-renamed'    { apply_element_renamed(mut doc, segments, ch)! }
		'element-added'      { apply_element_added(mut doc, segments, ch)! }
		'element-removed'    { apply_element_removed(mut doc, segments, ch)! }
		'attribute-added'    { apply_attribute_added(mut doc, segments, ch)! }
		'attribute-removed'  { apply_attribute_removed(mut doc, segments, ch)! }
		'attribute-changed'  { apply_attribute_changed(mut doc, segments, ch)! }
		'body-changed'       { apply_body_changed(mut doc, segments, ch)! }
		'type-changed'       { apply_type_changed(mut doc, segments, ch)! }
		'order-changed'      {
			// Order changes are emitted only when the underlying diff
			// detects a same-name-sibling rearrangement; v0.7.0 cx:patch
			// applies them as no-op (positions in the patched output
			// follow the source-side order). Future v0.7.x can lift this
			// to a real sibling-permutation operation if a use case
			// surfaces.
		}
		else {
			return error('cx-err:CXER0022\x1Fcx:patch unknown change kind "${ch.kind}"\x1F')
		}
	}
}

// PathSegment is one step in a parsed CXPath.
struct PathSegment {
	name    string  // element or attribute name
	is_attr bool    // attribute step (@name)
	idx     int     // 1-based sibling index; 0 means unspecified (unique by name)
}

// parse_patch_path turns a CXPath string into a list of segments.
// Per the diff renderer (vcx/cx/diff.v:141 element_path + line 198
// attribute path), the form is `/name` or `/name[N]` for elements
// and `/name/@attr` for attributes. We don't handle the full CXPath
// surface — just the subset cx:diff produces.
fn parse_patch_path(p string) ![]PathSegment {
	if p == '' || p == '/' {
		return []PathSegment{}
	}
	mut s := p
	if s.starts_with('/') {
		s = s[1..]
	}
	mut segments := []PathSegment{}
	for raw in s.split('/') {
		if raw == '' { continue }
		if raw.starts_with('@') {
			segments << PathSegment{ name: raw[1..], is_attr: true, idx: 0 }
			continue
		}
		// Element step — may have `[N]` index suffix.
		mut name := raw
		mut idx := 0
		if bracket := raw.index('[') {
			if !raw.ends_with(']') {
				return error('element step missing closing `]`: "${raw}"')
			}
			name = raw[..bracket]
			idx_str := raw[bracket + 1..raw.len - 1]
			idx = strconv.atoi(idx_str) or {
				return error('non-numeric index in element step: "${raw}"')
			}
			if idx < 1 {
				return error('1-based index must be ≥ 1: "${raw}"')
			}
		}
		segments << PathSegment{ name: name, is_attr: false, idx: idx }
	}
	return segments
}

// walk_to_element traverses the document by element segments,
// returning the path of indices used to reach the target so the
// caller can mutate the parent.
//
// Returns (parent_chain, target_index) where:
//   parent_chain[0] is the index into doc.elements
//   parent_chain[i] is the index into the previous element's items
//   target_index is the final index into the deepest parent's items
//
// Errors when any segment can't resolve.
fn walk_to_element(doc Document, segments []PathSegment) ![]int {
	if segments.len == 0 {
		return []int{}
	}
	mut indices := []int{cap: segments.len}
	// Find the first segment among doc.elements.
	first := segments[0]
	if first.is_attr {
		return error('first path segment must be an element, got @${first.name}')
	}
	mut cur_idx := find_sibling_index(doc.elements, first.name, first.idx) or {
		return error('element /${first.name}${index_suffix(first.idx)} not found at root')
	}
	indices << cur_idx
	mut cur := doc.elements[cur_idx] as Element
	// Walk remaining element segments. Attribute step (if present)
	// must be the last segment; we stop one early.
	end := if segments.last().is_attr { segments.len - 1 } else { segments.len }
	for i := 1; i < end; i++ {
		seg := segments[i]
		if seg.is_attr {
			return error('attribute step "@${seg.name}" must be last in path')
		}
		next_idx := find_sibling_index(cur.items, seg.name, seg.idx) or {
			return error('element /${seg.name}${index_suffix(seg.idx)} not found at depth ${i}')
		}
		indices << next_idx
		cur = cur.items[next_idx] as Element
	}
	return indices
}

// find_sibling_index returns the index of the matching child element
// in the items list. `idx` is 1-based; 0 means "any unique-named".
fn find_sibling_index(items []Node, name string, idx int) ?int {
	mut nth := 0
	for i, n in items {
		if n is Element {
			el := n as Element
			if el.name == name {
				nth++
				if idx == 0 || idx == nth {
					return i
				}
			}
		}
	}
	return none
}

fn index_suffix(idx int) string {
	if idx <= 0 { return '' }
	return '[${idx}]'
}

// element_at_indices returns a mutable copy of the element reached
// by walking indices through doc.elements.
fn element_at_indices(doc Document, indices []int) Element {
	mut cur := doc.elements[indices[0]] as Element
	for i in 1 .. indices.len {
		cur = cur.items[indices[i]] as Element
	}
	return cur
}

// write_element_at_indices walks indices through doc and writes a
// mutated element back into the parent's items list.
fn write_element_at_indices(mut doc Document, indices []int, new_el Element) {
	if indices.len == 1 {
		doc.elements[indices[0]] = Node(new_el)
		return
	}
	// Need to walk down + write back up. Rebuild the chain.
	doc.elements[indices[0]] = Node(rebuild_chain(doc.elements[indices[0]] as Element, indices[1..], new_el))
}

fn rebuild_chain(root Element, indices []int, new_el Element) Element {
	mut r := root
	mut items := r.items.clone()
	if indices.len == 1 {
		items[indices[0]] = Node(new_el)
		r.items = items
		return r
	}
	child := items[indices[0]] as Element
	items[indices[0]] = Node(rebuild_chain(child, indices[1..], new_el))
	r.items = items
	return r
}

// ── Per-kind handlers ────────────────────────────────────────────────────────

fn apply_element_renamed(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 {
		return error('cx-err:CXER0022\x1Fcx:patch element-renamed needs non-empty path\x1F')
	}
	indices := walk_to_element(doc, segments)!
	mut el := element_at_indices(doc, indices)
	if ch.before != '' && el.name != ch.before {
		return error('cx-err:CXER0022\x1Fcx:patch element-renamed at ${ch.path}: expected "${ch.before}", got "${el.name}"\x1F')
	}
	el.name = ch.after
	write_element_at_indices(mut doc, indices, el)
}

fn apply_element_added(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	// Add to the parent of `segments`. The diff record carries just
	// the element name in `after`; we synthesize an empty element.
	// (Per spec/modules/cx.md §1.1: cx:patch is the inverse of cx:diff
	// at the data-model level; the diff format is lossy for attrs +
	// body of added elements at v0.7.0. Patch reconstructs the name
	// only; richer reconstruction is a v0.7.x extension if a use case
	// surfaces.)
	if segments.len == 0 {
		return error('cx-err:CXER0022\x1Fcx:patch element-added needs non-empty path\x1F')
	}
	if segments.last().is_attr {
		return error('cx-err:CXER0022\x1Fcx:patch element-added path cannot end at attribute\x1F')
	}
	new_el := Element{ name: ch.after, attrs: [], items: [] }
	if segments.len == 1 {
		doc.elements << Node(new_el)
		return
	}
	parent_segments := segments[..segments.len - 1]
	parent_indices := walk_to_element(doc, parent_segments)!
	mut parent := element_at_indices(doc, parent_indices)
	parent.items << Node(new_el)
	write_element_at_indices(mut doc, parent_indices, parent)
}

fn apply_element_removed(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 {
		return error('cx-err:CXER0022\x1Fcx:patch element-removed needs non-empty path\x1F')
	}
	indices := walk_to_element(doc, segments)!
	if indices.len == 1 {
		doc.elements.delete(indices[0])
		return
	}
	// Walk to parent, mutate items, rebuild chain.
	parent_indices := indices[..indices.len - 1]
	mut parent := element_at_indices(doc, parent_indices)
	parent.items.delete(indices.last())
	write_element_at_indices(mut doc, parent_indices, parent)
}

fn apply_attribute_added(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 || !segments.last().is_attr {
		return error('cx-err:CXER0022\x1Fcx:patch attribute-added path must end in @attr\x1F')
	}
	attr_name := segments.last().name
	el_segments := segments[..segments.len - 1]
	indices := walk_to_element(doc, el_segments)!
	mut el := element_at_indices(doc, indices)
	for a in el.attrs {
		if a.name == attr_name {
			return error('cx-err:CXER0022\x1Fcx:patch attribute-added at ${ch.path}: attr already present\x1F')
		}
	}
	val, dt := parse_typed_scalar(ch.after)
	el.attrs << Attribute{ name: attr_name, value: val, data_type: dt }
	write_element_at_indices(mut doc, indices, el)
}

// parse_typed_scalar infers a typed (ScalarValue, ?ScalarType) pair
// from the lexical form of an attribute value. Matches the parser's
// auto-typing rules for attribute values (int → float → bool → null
// → string fallback) so a round-trip cx:diff → cx:patch produces a
// value byte-identical to the diff's `after` side under canonical-
// form comparison.
//
// The ScalarType return is normally none (matches parser convention
// for auto-typed values), BUT when the lexical form would re-parse
// as a string under cx_would_autotype (i.e. the value text looks
// numeric / bool / null but we *want* it stored as int/bool/null),
// we set data_type explicitly so the cx_emit_element conservative
// quoting (emitter_cx.v:296) doesn't force-string-quote the output.
fn parse_typed_scalar(s string) (ScalarValue, ?ScalarType) {
	if s == 'true' { return ScalarValue(true), ?ScalarType(ScalarType.bool_type) }
	if s == 'false' { return ScalarValue(false), ?ScalarType(ScalarType.bool_type) }
	if iv := strconv.atoi(s) {
		if s == iv.str() {
			return ScalarValue(i64(iv)), ?ScalarType(ScalarType.int_type)
		}
	}
	if s.contains('.') || s.contains('e') || s.contains('E') {
		if fv := strconv.atof64(s) {
			return ScalarValue(fv), ?ScalarType(ScalarType.float_type)
		}
	}
	return ScalarValue(s), ?ScalarType(none)
}

fn apply_attribute_removed(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 || !segments.last().is_attr {
		return error('cx-err:CXER0022\x1Fcx:patch attribute-removed path must end in @attr\x1F')
	}
	attr_name := segments.last().name
	el_segments := segments[..segments.len - 1]
	indices := walk_to_element(doc, el_segments)!
	mut el := element_at_indices(doc, indices)
	mut found := false
	for i, a in el.attrs {
		if a.name == attr_name {
			if ch.before != '' && scalar_value_str(a.value) != ch.before {
				return error('cx-err:CXER0022\x1Fcx:patch attribute-removed at ${ch.path}: expected "${ch.before}", got "${scalar_value_str(a.value)}"\x1F')
			}
			el.attrs.delete(i)
			found = true
			break
		}
	}
	if !found {
		return error('cx-err:CXER0022\x1Fcx:patch attribute-removed at ${ch.path}: attr not present\x1F')
	}
	write_element_at_indices(mut doc, indices, el)
}

fn apply_attribute_changed(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 || !segments.last().is_attr {
		return error('cx-err:CXER0022\x1Fcx:patch attribute-changed path must end in @attr\x1F')
	}
	attr_name := segments.last().name
	el_segments := segments[..segments.len - 1]
	indices := walk_to_element(doc, el_segments)!
	mut el := element_at_indices(doc, indices)
	mut found := false
	for i, a in el.attrs {
		if a.name == attr_name {
			if ch.before != '' && scalar_value_str(a.value) != ch.before {
				return error('cx-err:CXER0022\x1Fcx:patch attribute-changed at ${ch.path}: expected "${ch.before}", got "${scalar_value_str(a.value)}"\x1F')
			}
			val, dt := parse_typed_scalar(ch.after)
			el.attrs[i] = Attribute{ ...a, value: val, data_type: dt }
			found = true
			break
		}
	}
	if !found {
		return error('cx-err:CXER0022\x1Fcx:patch attribute-changed at ${ch.path}: attr not present\x1F')
	}
	write_element_at_indices(mut doc, indices, el)
}

fn apply_body_changed(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 {
		return error('cx-err:CXER0022\x1Fcx:patch body-changed needs non-empty path\x1F')
	}
	if segments.last().is_attr {
		return error('cx-err:CXER0022\x1Fcx:patch body-changed path cannot end at attribute\x1F')
	}
	indices := walk_to_element(doc, segments)!
	mut el := element_at_indices(doc, indices)
	// Replace the body's leaf text/scalar content. Walk items, drop
	// existing TextNode/ScalarNode/EntityRef/Sequence/Array/Map leaves,
	// preserve Element children; prepend a TextNode carrying the new
	// body content. This matches cx:diff's concat_leaf_text view of
	// body — patch produces a single TextNode carrying the after-
	// payload (semantically equivalent under canonical-form compare).
	mut new_items := []Node{cap: el.items.len + 1}
	if ch.after != '' {
		new_items << Node(TextNode{ value: ch.after })
	}
	for it in el.items {
		match it {
			Element { new_items << it }
			else {}
		}
	}
	el.items = new_items
	write_element_at_indices(mut doc, indices, el)
}

fn apply_type_changed(mut doc Document, segments []PathSegment, ch PatchChange) ! {
	if segments.len == 0 {
		return error('cx-err:CXER0022\x1Fcx:patch type-changed needs non-empty path\x1F')
	}
	if segments.last().is_attr {
		return error('cx-err:CXER0022\x1Fcx:patch type-changed path cannot end at attribute\x1F')
	}
	indices := walk_to_element(doc, segments)!
	mut el := element_at_indices(doc, indices)
	if ch.after == '' {
		el.data_type = none
	} else {
		el.data_type = ?string(ch.after)
	}
	write_element_at_indices(mut doc, indices, el)
}

// ── Diff-doc → PatchChange list extraction ───────────────────────────────────
//
// The diff cx-value shape is a sequence of `[item ...]` Elements (one
// per Change record). Each item carries `[kind <k>] [path <p>]
// [before <b>] [after <a>]` children. extract_patch_changes pulls them
// into the PatchChange list cx_patch consumes.

fn extract_patch_changes(diff_v CXLValue) ![]PatchChange {
	mut changes := []PatchChange{}
	for item in diff_v {
		if item is Element {
			el := item as Element
			if el.name == 'item' {
				changes << extract_one_change(el)!
			} else if el.name == '#document' {
				// Synthetic-document wrapping (from cxl_value_to_cx_text /
				// cxl_value_to_doc multi-item path). Walk its items.
				for sub in el.items {
					if sub is Element {
						sub_el := sub as Element
						if sub_el.name == 'item' {
							changes << extract_one_change(sub_el)!
						}
					}
				}
			}
		}
	}
	return changes
}

fn extract_one_change(item Element) !PatchChange {
	mut kind := ''
	mut path := ''
	mut before := ''
	mut after := ''
	for child in item.items {
		if child is Element {
			ce := child as Element
			text := concat_leaf_text(ce.items)
			match ce.name {
				'kind'   { kind = text }
				'path'   { path = text }
				'before' { before = text }
				'after'  { after = text }
				else {}
			}
		}
	}
	if kind == '' {
		return error('diff item missing [kind ...] child')
	}
	return PatchChange{ kind: kind, path: path, before: before, after: after }
}
