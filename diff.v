module cx

// cx diff — semantic diff at the strict-canonical level.
//
// Per internal design record
//
// Public V API:
// cx_text_diff(a, b) -> []Change — compute the change list
// diff_render_unified(changes, color) -> string — diff -u-style hunks
// diff_render_json(changes) -> string — JSON array of records
// diff_render_summary(changes) -> string — one-line counts
//
// Both inputs are reduced to strict canonical (via canonicalize_doc)
// before comparison, so reformatting / comment moves / attribute order
// changes / anchor expansion produce empty diffs. The walk is positional
// element compare with name + attribute + scalar body comparison and
// recursion into element children.
//
// v0 limitations (documented; future enhancement):
// - Element-rename detection at the same path depth is exact-name
// match only; LCS / move detection is rejected.
// - Cross-format diff (cx_text_diff of CX vs JSON) is not yet wired
// here; the CLI implements it by parsing both inputs to Documents
// before calling cx_text_diff. C ABI helper lands in a future phase.

// ChangeKind names match the JSON shape's `kind` field ().
pub enum ChangeKind {
	element_added
	element_removed
	element_renamed
	attribute_added
	attribute_removed
	attribute_changed
	body_changed
	type_changed
	order_changed
}

pub fn change_kind_str(k ChangeKind) string {
	return match k {
		.element_added { 'element-added' }
		.element_removed { 'element-removed' }
		.element_renamed { 'element-renamed' }
		.attribute_added { 'attribute-added' }
		.attribute_removed { 'attribute-removed' }
		.attribute_changed { 'attribute-changed' }
		.body_changed { 'body-changed' }
		.type_changed { 'type-changed' }
		.order_changed { 'order-changed' }
	}
}

// Change is one semantic delta between two canonical Documents.
// `path` uses CXPath syntax (spec/cxpath.md). `before` and `after`
// carry the relevant value for the change kind; an absent side is
// the empty string (kind disambiguates "missing" vs "empty").
pub struct Change {
pub:
	kind ChangeKind
	path string
	before string
	after string
}

// cx_text_diff parses both inputs, reduces them to strict canonical,
// and returns the ordered list of semantic deltas.
pub fn cx_text_diff(a string, b string) ![]Change {
	doc_a := parse(a)!
	doc_b := parse(b)!
	mut can_a := canonicalize_doc(doc_a)
	mut can_b := canonicalize_doc(doc_b)
	// — collection literals canonicalize before diff
	// so two maps differing only in insertion order produce an empty
	// change list.
	canonicalize_collection_literals(mut can_a)
	canonicalize_collection_literals(mut can_b)
	mut changes := []Change{}
	diff_node_lists('', can_a.elements, can_b.elements, mut changes)
	return changes
}

// diff_node_lists compares two ordered lists of top-level / sibling
// nodes and emits Change records. Path is the parent CXPath prefix
// (empty for the document root).
fn diff_node_lists(parent_path string, a []Node, b []Node, mut changes []Change) {
	// Phase 1: extract the Element children only (canonicalize_doc has
	// already stripped non-data nodes; what remains is Elements plus
	// occasionally text/scalar leaves at the document root).
	a_els := elements_of(a)
	b_els := elements_of(b)

	// Build per-name occurrence index for path generation.
	mut a_name_count := map[string]int{}
	mut b_name_count := map[string]int{}
	mut a_paths := []string{cap: a_els.len}
	mut b_paths := []string{cap: b_els.len}
	for el in a_els {
		idx := a_name_count[el.name]
		a_name_count[el.name] = idx + 1
		a_paths << element_path(parent_path, el.name, idx, total_with_name(a_els, el.name))
	}
	for el in b_els {
		idx := b_name_count[el.name]
		b_name_count[el.name] = idx + 1
		b_paths << element_path(parent_path, el.name, idx, total_with_name(b_els, el.name))
	}

	// Phase 2: positional walk. v0 algorithm — positions match by
	// index. If lengths differ, the tail is reported as add/remove.
	common := if a_els.len < b_els.len { a_els.len } else { b_els.len }
	for i in 0 .. common {
		diff_element(a_paths[i], a_els[i], b_els[i], mut changes)
	}
	for i in common .. a_els.len {
		changes << Change{ kind: .element_removed, path: a_paths[i], before: a_els[i].name, after: '' }
	}
	for i in common .. b_els.len {
		changes << Change{ kind: .element_added, path: b_paths[i], before: '', after: b_els[i].name }
	}
}

fn elements_of(nodes []Node) []Element {
	mut out := []Element{cap: nodes.len}
	for n in nodes {
		if n is Element {
			out << n
		}
	}
	return out
}

fn total_with_name(els []Element, name string) int {
	mut count := 0
	for el in els {
		if el.name == name { count++ }
	}
	return count
}

fn element_path(parent string, name string, idx int, total int) string {
	prefix := if parent == '' { '/' } else { parent + '/' }
	if total <= 1 {
		return prefix + name
	}
	// CXPath uses 1-based indices.
	return prefix + name + '[${idx + 1}]'
}

fn diff_element(path string, a Element, b Element, mut changes []Change) {
	// Element name change (rare under positional walk — usually
	// surfaces as add+remove; explicit kind for the same-position
	// case).
	if a.name != b.name {
		changes << Change{ kind: .element_renamed, path: path, before: a.name, after: b.name }
		return
	}

	// Type annotation
	a_dt := a.data_type() or { '' }
	b_dt := b.data_type() or { '' }
	if a_dt != b_dt {
		changes << Change{ kind: .type_changed, path: path, before: a_dt, after: b_dt }
	}

	// Attributes — compare as ordered name->value maps. v0 normalizes
	// to canonical attribute order in canonicalize_doc; here we walk
	// each attribute name in both elements.
	diff_attributes(path, a.attrs, b.attrs, mut changes)

	// Body: compare text/scalar leaves and recurse into element
	// children.
	diff_body_items(path, a.items, b.items, mut changes)
}

fn diff_attributes(path string, a []Attribute, b []Attribute, mut changes []Change) {
	mut a_idx := map[string]int{}
	mut b_idx := map[string]int{}
	for i, attr in a { a_idx[attr.name] = i }
	for i, attr in b { b_idx[attr.name] = i }

	for attr in a {
		if attr.name !in b_idx {
			changes << Change{
				kind: .attribute_removed
				path: path + '/@' + attr.name
				before: scalar_value_str(attr.value)
				after: ''
			}
			continue
		}
		bv := b[b_idx[attr.name]]
		av_s := scalar_value_str(attr.value)
		bv_s := scalar_value_str(bv.value)
		if av_s != bv_s {
			changes << Change{
				kind: .attribute_changed
				path: path + '/@' + attr.name
				before: av_s
				after: bv_s
			}
		}
	}
	for attr in b {
		if attr.name !in a_idx {
			changes << Change{
				kind: .attribute_added
				path: path + '/@' + attr.name
				before: ''
				after: scalar_value_str(attr.value)
			}
		}
	}
}

fn diff_body_items(parent_path string, a []Node, b []Node, mut changes []Change) {
	// Split into scalar/text leaves vs element children. Leaves
	// compare by concatenated string; child elements recurse.
	a_text := concat_leaf_text(a)
	b_text := concat_leaf_text(b)
	if a_text != b_text {
		changes << Change{
			kind: .body_changed
			path: parent_path
			before: a_text
			after: b_text
		}
	}

	diff_node_lists(parent_path, a, b, mut changes)
}

fn concat_leaf_text(nodes []Node) string {
	mut parts := []string{}
	for n in nodes {
		match n {
			TextNode { parts << n.value }
			ScalarNode { parts << scalar_value_str(n.value) }
			EntityRefNode { parts << '&' + n.name + ';' }
			// — collection literals carry data, not
			// presentation. Treat them as leaf content for body-diff
			// purposes: render each via its canonical CX form so two
			// bodies with identical collection content compare equal
			// (after the canonical pass already sorted map keys).
			SequenceNode { parts << cx_emit_sequence_inline(n, true) }
			ArrayNode { parts << cx_emit_array_inline(n, true) }
			MapNode { parts << cx_emit_map_inline(n, true) }
			else {}
		}
	}
	return parts.join('')
}

// ── Renderers ────────────────────────────────────────────────────────────────

// diff_render_unified produces a diff -u-style report. Each change is
// a small hunk rooted at the element path. `color` enables ANSI color
// (callers wire to TTY detection).
pub fn diff_render_unified(changes []Change, color bool) string {
	if changes.len == 0 {
		return ''
	}
	mut out := []string{cap: changes.len * 4}
	for ch in changes {
		out << '@@ ${ch.path} @@'
		match ch.kind {
			.element_added {
				out << color_str('+ ${ch.after}', color, '32') // green
			}
			.element_removed {
				out << color_str('- ${ch.before}', color, '31') // red
			}
			.element_renamed {
				out << color_str('- ${ch.before}', color, '31')
				out << color_str('+ ${ch.after}', color, '32')
			}
			.attribute_added {
				out << color_str('+ ${ch.path.all_after_last('@')}=${ch.after}', color, '32')
			}
			.attribute_removed {
				out << color_str('- ${ch.path.all_after_last('@')}=${ch.before}', color, '31')
			}
			.attribute_changed {
				attr := ch.path.all_after_last('@')
				out << color_str('- ${attr}=${ch.before}', color, '31')
				out << color_str('+ ${attr}=${ch.after}', color, '32')
			}
			.body_changed {
				out << color_str('- ${ch.before}', color, '31')
				out << color_str('+ ${ch.after}', color, '32')
			}
			.type_changed {
				out << color_str('- :${ch.before}', color, '31')
				out << color_str('+ :${ch.after}', color, '32')
			}
			.order_changed {
				out << '* order changed: ${ch.before} -> ${ch.after}'
			}
		}
	}
	return out.join('\n')
}

fn color_str(s string, on bool, code string) string {
	if !on { return s }
	return '\x1b[${code}m${s}\x1b[0m'
}

// diff_render_json produces an array of change records §D4.
// Output is canonical (sorted keys) and stable byte-for-byte across
// runs for the same input pair.
pub fn diff_render_json(changes []Change) string {
	if changes.len == 0 {
		return '[]'
	}
	mut out := []string{cap: changes.len + 2}
	out << '['
	for i, ch in changes {
		mut fields := []string{}
		fields << '"kind": "${change_kind_str(ch.kind)}"'
		fields << '"path": ${json_quote(ch.path)}'
		if ch.before.len > 0 || kind_has_before(ch.kind) {
			fields << '"before": ${json_quote(ch.before)}'
		}
		if ch.after.len > 0 || kind_has_after(ch.kind) {
			fields << '"after": ${json_quote(ch.after)}'
		}
		comma := if i < changes.len - 1 { ',' } else { '' }
		out << ' { ' + fields.join(', ') + ' }' + comma
	}
	out << ']'
	return out.join('\n')
}

fn kind_has_before(k ChangeKind) bool {
	return k != .element_added && k != .attribute_added
}

fn kind_has_after(k ChangeKind) bool {
	return k != .element_removed && k != .attribute_removed
}

fn json_quote(s string) string {
	mut out := ['"']
	for c in s {
		match c {
			`"` { out << '\\"' }
			`\\` { out << '\\\\' }
			`\n` { out << '\\n' }
			`\r` { out << '\\r' }
			`\t` { out << '\\t' }
			else {
				if c < 0x20 {
					out << '\\u${c:04x}'
				} else {
					out << c.ascii_str()
				}
			}
		}
	}
	out << '"'
	return out.join('')
}

// diff_render_summary produces a one-line summary: counts of changes
// by category. Stable format suitable for shell prompts and PR bots.
pub fn diff_render_summary(changes []Change) string {
	if changes.len == 0 {
		return 'no changes'
	}
	mut el_count := 0
	mut attr_count := 0
	mut body_count := 0
	for ch in changes {
		match ch.kind {
			.element_added, .element_removed, .element_renamed { el_count++ }
			.attribute_added, .attribute_removed, .attribute_changed { attr_count++ }
			.body_changed, .type_changed, .order_changed { body_count++ }
		}
	}
	return '${changes.len} change(s): ${el_count} element, ${attr_count} attribute, ${body_count} body'
}
