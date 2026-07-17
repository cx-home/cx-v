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
//
// #437 (cx:patch — apply is the inverse of diff): `payload_kind` +
// `before_payload` / `after_payload` carry apply-grade compact canonical
// CX text so a change list can be APPLIED to the `a` document to obtain
// `b`. The name-only / stringified `before`/`after` fields are lossy
// (an added element's subtree, a typed attribute value, a typed scalar
// body are not reconstructible from them); the payloads are not. The
// renderers (unified/json/summary) are payload-blind — CLI output is
// unchanged. Kinds:
//   'subtree' — full-element payloads: patch replaces (rename /
//               type-change) / appends (add) / removes the whole
//               element at `path`.
//   'attr'    — single-attribute carrier `[v name=value]` preserving
//               the typed attribute value.
//   'leaves'  — leaf-item carrier `[v <leaf …>]` holding the element's
//               non-element body items (typed scalars survive).
//   'table'   — full-element payloads for a `[table]`-bearing element;
//               patch replaces the whole element once per path (the
//               per-row records at that path are then satisfied).
pub struct Change {
pub:
	kind ChangeKind
	path string
	before string
	after string
	payload_kind   string
	before_payload string
	after_payload  string
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
		changes << Change{
			kind:           .element_removed
			path:           a_paths[i]
			before:         a_els[i].name
			after:          ''
			payload_kind:   'subtree'
			before_payload: cx_emit_node_str(Node(a_els[i]), true)
		}
	}
	for i in common .. b_els.len {
		changes << Change{
			kind:          .element_added
			path:          b_paths[i]
			before:        ''
			after:         b_els[i].name
			payload_kind:  'subtree'
			after_payload: cx_emit_node_str(Node(b_els[i]), true)
		}
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
		// Rename stops the walk (v0 positional compare) — the subtree
		// payloads carry BOTH sides whole so patch replaces the element
		// and any content difference comes along.
		changes << Change{
			kind:           .element_renamed
			path:           path
			before:         a.name
			after:          b.name
			payload_kind:   'subtree'
			before_payload: cx_emit_node_str(Node(a), true)
			after_payload:  cx_emit_node_str(Node(b), true)
		}
		return
	}

	// Type annotation
	a_dt := a.data_type() or { '' }
	b_dt := b.data_type() or { '' }
	if a_dt != b_dt {
		// Whole-subtree payloads: the annotation is element meta the
		// leaf-level records cannot re-apply; patch replaces the element
		// and later records at this path apply idempotently.
		changes << Change{
			kind:           .type_changed
			path:           path
			before:         a_dt
			after:          b_dt
			payload_kind:   'subtree'
			before_payload: cx_emit_node_str(Node(a), true)
			after_payload:  cx_emit_node_str(Node(b), true)
		}
	}

	// Attributes — compare as ordered name->value maps. v0 normalizes
	// to canonical attribute order in canonicalize_doc; here we walk
	// each attribute name in both elements.
	diff_attributes(path, a.attrs, b.attrs, mut changes)

	// `[table]` payload (#414): TableData lives in the pooled `table`
	// field, NOT in `items` — without this the walker compared two tables
	// as empty bodies and reported "no changes" while cx eq / cx hash
	// (whose canonical text includes the rows) disagreed.
	diff_table(path, a, b, mut changes)

	// Body: compare text/scalar leaves and recurse into element
	// children.
	diff_body_items(path, a.items, b.items, mut changes)
}

// diff_table compares the `[table]` payloads of two same-named elements.
// A side without a payload reads as the empty table (no columns, no rows),
// so a table degrading to a bare `::table` annotation — the exact shape the
// pre-#413 XML round-trip produced — surfaces as a header change plus one
// row removal per lost row. Header changes and per-row (positional) cell
// changes are `.body_changed` records whose before/after carry the
// canonical CX text of the header / row.
fn diff_table(path string, a Element, b Element, mut changes []Change) {
	mut a_td := &TableData{}
	mut b_td := &TableData{}
	mut a_has := false
	mut b_has := false
	if td := a.table_opt() {
		a_td = td
		a_has = true
	}
	if td := b.table_opt() {
		b_td = td
		b_has = true
	}
	if !a_has && !b_has {
		return
	}

	// Table records carry whole-element payloads: patch replaces the
	// element ONCE at this path (the b-side table comes along whole);
	// the per-row records below are then satisfied (#437).
	a_payload := cx_emit_node_str(Node(a), true)
	b_payload := cx_emit_node_str(Node(b), true)

	// Header — canonical CX column declaration text.
	a_hdr := table_header_text(a_td)
	b_hdr := table_header_text(b_td)
	if a_hdr != b_hdr {
		changes << Change{
			kind:   .body_changed
			path:   path
			before: 'table[${a_hdr}]'
			after:  'table[${b_hdr}]'
			payload_kind:   'table'
			before_payload: a_payload
			after_payload:  b_payload
		}
	}

	// Rows — positional walk (rows are ordered, document order per
	// canonical.md); the tail is reported as removed/added rows.
	common := if a_td.rows.len < b_td.rows.len { a_td.rows.len } else { b_td.rows.len }
	for i in 0 .. common {
		a_row := table_row_text(a_td, i)
		b_row := table_row_text(b_td, i)
		if a_row != b_row {
			changes << Change{
				kind: .body_changed
				path: path
				before: a_row
				after: b_row
				payload_kind:   'table'
				before_payload: a_payload
				after_payload:  b_payload
			}
		}
	}
	for i in common .. a_td.rows.len {
		changes << Change{
			kind: .body_changed
			path: path
			before: table_row_text(a_td, i)
			after: ''
			payload_kind:   'table'
			before_payload: a_payload
			after_payload:  b_payload
		}
	}
	for i in common .. b_td.rows.len {
		changes << Change{
			kind: .body_changed
			path: path
			before: ''
			after: table_row_text(b_td, i)
			payload_kind:   'table'
			before_payload: a_payload
			after_payload:  b_payload
		}
	}
}

fn table_header_text(td &TableData) string {
	mut parts := []string{}
	for col in td.cols {
		if col.type_name == '' {
			parts << col.name
		} else {
			parts << '${col.name}::${col.type_name}'
		}
	}
	return parts.join(' ')
}

fn table_row_text(td &TableData, i int) string {
	mut cells := []string{}
	for j, cell in td.rows[i] {
		ct := if j < td.cols.len { td.cols[j].type_name } else { '' }
		cells << cx_format_table_cell(cell, ct)
	}
	return cells.join(' ')
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
				payload_kind:   'attr'
				before_payload: diff_attr_payload(attr)
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
				payload_kind:   'attr'
				before_payload: diff_attr_payload(attr)
				after_payload:  diff_attr_payload(bv)
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
				payload_kind:  'attr'
				after_payload: diff_attr_payload(attr)
			}
		}
	}
}

// diff_attr_payload renders the single-attribute carrier `[v name=value]`
// — compact canonical text preserving the TYPED attribute value, so
// patch can re-apply the attribute without guessing the scalar type
// from a stringified form (#437).
fn diff_attr_payload(attr Attribute) string {
	return cx_emit_node_str(Node(Element{ name: 'v', attrs: [attr] }), true)
}

// diff_leaves_payload renders the leaf-item carrier `[v <leaf …>]` for a
// body-changed record: every non-element body item (text, typed scalars,
// collection literals) in document order (#437).
fn diff_leaves_payload(nodes []Node) string {
	mut leaves := []Node{}
	for n in nodes {
		if n !is Element {
			leaves << n
		}
	}
	return cx_emit_node_str(Node(Element{ name: 'v', items: leaves }), true)
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
			payload_kind:   'leaves'
			before_payload: diff_leaves_payload(a)
			after_payload:  diff_leaves_payload(b)
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
