module code

import os
import cx

// stdlib_cx_analysis.v — the `cx:` module's §2.2 analysis and §2.3 transform
// surface (spec/03-approved/modules/cx.md), #940 / RULED: VC-6.
//
// Eight of the ten functions VC-6 ruled implemented live here:
//
//   cx:validate          (value, schema) → [sequence any]   pure
//   cx:anchors           (value)         → [sequence string] pure
//   cx:ids               (value)         → [sequence string] pure
//   cx:references        (value)         → [sequence map]    pure
//   cx:resolve-includes  (value, root)   → any               impure (read)
//   cx:strip-comments    (value)         → any               pure
//   cx:strip-attrs       (value, pattern)→ any               pure
//   cx:pretty-print      (value, opts?)  → string            pure
//
// `cx:eval` / `cx:render` are the other two; they live in
// dynamic_construction.v beside the sandbox they share with `cx:eval-tree`.
// All ten dispatch from `cx_module_stdlib_builtin_env` in stdlib_cx.v, which
// accepts both the `cx:<fn>` and flat `cx-<fn>` spellings (§4).
//
// Every function here takes stdlib_cx.v's documented STRING-AS-SOURCE pivot on
// its value argument (a string reads as CX source text; any other value
// serializes through the cx codec first), so they agree with `cx:canonical` /
// `cx:hash` and with the `cx <verb>` CLI lane on what "the value" means.
//
// Refusals are err VALUES (mk_err), never a `!` error: the dispatch chain
// converts a propagated `!` into `none` and falls through to the next
// dispatcher, which renders as `no callable "cx:fn"` — the exact
// silent-absence defect #940 is about (measured on `cx:eval-tree` at zero
// args, which returns `!`). An err value surfaces.

// ── shared plumbing ─────────────────────────────────────────────────────────

// cx_mod_arg_doc projects an argument to a parsed cx.Document — the shared
// front of every analysis / transform function here.
fn cx_mod_arg_doc(n cx.Node) !cx.Document {
	src := cx_mod_value_source(n)!
	return cx.parse(src)!
}

// cx_mod_doc_value shapes a transformed Document back into a VALUE with the
// §4 result shape `cx:parse` uses (codec.md §7): a single top-level node with
// no prolog / doctype IS the value; anything else is the transparent
// multi-root carrier, navigated with the descendant axis.
fn cx_mod_doc_value(doc cx.Document) cx.Node {
	mut has_doctype := false
	if _ := doc.doctype {
		has_doctype = true
	}
	if doc.elements.len == 1 && doc.prolog.len == 0 && !has_doctype {
		return doc.elements[0]
	}
	return cx.doc_to_node(doc)
}

// cx_mod_str_seq wraps a []string as the `[sequence string]` value shape.
fn cx_mod_str_seq(items []string) cx.Node {
	mut out := []cx.Node{cap: items.len}
	for s in items {
		out << codec_str_node(s)
	}
	return cx.Element{
		name:  seq_marker_name
		items: out
	}
}

// cx_mod_kv_map builds a `map` value from key/value pairs. The keys MUST
// arrive SORTED — a map value is self-canonicalizing only when its entry order
// is the canonical one (the cx:env precedent).
fn cx_mod_kv_map(keys []string, vals []cx.Node) cx.Node {
	mut items := []cx.Node{cap: keys.len}
	for i, k in keys {
		items << cx.Node(cx.Element{
			name:  k
			items: [vals[i]]
		})
	}
	return cx.Element{
		name:  map_marker_name
		items: items
	}
}

// ── cx:validate — the in-program .cxs validator (§2.2) ──────────────────────
//
// `[$cx:validate VALUE SCHEMA] → [sequence any]`, pure. An EMPTY sequence is
// "valid"; otherwise one item per diagnostic. The item is the SAME
// `[violation code=… path=… message=…]` value `validate-against` puts inside
// its `[invalid …]` result (stdlib_validate.v `val_violation`) — one violation
// vocabulary across the two surfaces, never a second shape. §2.2 types the
// return `[sequence any]` rather than the `[ok]`/`[invalid]` result
// vocabulary, so the sequence is bare.
//
// A malformed / unloadable schema is NOT an err here: `cx.validate` surfaces
// schema-load failure as an S0xx diagnostic inside the report (schema.md
// §10.1), so it arrives as a violation item like any other — one uniform way
// to read the outcome. Only a VALUE that does not read as CX at all is
// CXER4100.
fn cx_mod_validate(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:validate requires VALUE and SCHEMA arguments')
	}
	doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:validate: malformed CX source: ${err.msg()}')
	}
	schema_text := cx_mod_value_source(args[1]) or {
		return mk_err('cx-err:CXER4101', 'cx:validate: ${err.msg()}')
	}
	rep := cx.validate(doc, schema_text) or {
		return mk_err('cx-err:CXER4100', 'cx:validate: ${err.msg()}')
	}
	mut items := []cx.Node{cap: rep.diagnostics.len}
	for d in rep.diagnostics {
		items << val_violation(d.code, '', '', '', d.message)
	}
	return cx.Element{
		name:  seq_marker_name
		items: items
	}
}

// ── cx:anchors / cx:ids / cx:references — the identity projections (§2.2) ───
//
// cxdm.md §4 gives a document two DISJOINT identity namespaces: `&anchor` /
// `[*alias]` (a serialization-level sharing device) and `#id` / `@ref` (the
// document's ID/IDREF graph, cx/identity.v). These three functions project
// them. Document order, no dedup — a duplicate `#id` is a real document
// defect, and hiding it here would make `cx:ids` disagree with `resolve_ids`,
// which REFUSES it (CXER0208).

fn cx_mod_anchors(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:anchors requires exactly one VALUE argument')
	}
	doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:anchors: malformed CX source: ${err.msg()}')
	}
	mut out := []string{}
	cx_collect_anchors(doc.prolog, mut out)
	cx_collect_anchors(doc.elements, mut out)
	return cx_mod_str_seq(out)
}

fn cx_collect_anchors(nodes []cx.Node, mut out []string) {
	for n in nodes {
		if n is cx.Element {
			if a := n.anchor() {
				out << a
			}
			cx_collect_anchors(n.items, mut out)
		}
	}
}

fn cx_mod_ids(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:ids requires exactly one VALUE argument')
	}
	doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:ids: malformed CX source: ${err.msg()}')
	}
	mut out := []string{}
	cx_collect_ids(doc.prolog, mut out)
	cx_collect_ids(doc.elements, mut out)
	return cx_mod_str_seq(out)
}

fn cx_collect_ids(nodes []cx.Node, mut out []string) {
	for n in nodes {
		if n is cx.Element {
			if i := n.id() {
				out << i
			}
			cx_collect_ids(n.items, mut out)
		}
	}
}

// cx_mod_references projects every REFERENCE SITE as a map (§2.2:
// `[sequence map]`). §2.2 types the item `map` without naming its keys, so the
// record carries the four facts a consumer needs to act on plus the one it
// cannot cheaply recompute, keys in canonical (sorted) order:
//
//   attr      the attribute name carrying the reference; '' for the
//             body-position and alias forms, which have no attribute
//   kind      the reference form, by grammar production: 'idref' (`@name`
//             attribute) and 'body-ref' (`[ref @name]`) reference the ID
//             namespace; 'alias' (`[*name]`, AliasElement) and 'merge'
//             (`*name` MergeRef on an element head) reference the ANCHOR
//             namespace — all four forms the grammar admits, none omitted
//   path      the canonical position of the referring node, in the same
//             `/root/child[2]` spelling cx:diff / cx:patch address with
//   ref       the referenced name, WITHOUT its sigil
//   resolved  whether the name is declared in this value — checked against
//             the ID table for idref/body-ref, the anchor table for alias
//             (the two namespaces are disjoint, cxdm.md §4)
//
// `resolved` is why this is a map rather than a `[sequence string]`:
// resolution is the question a caller is asking, and recomputing it
// in-language would mean re-walking the whole value once per reference.
fn cx_mod_references(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:references requires exactly one VALUE argument')
	}
	doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:references: malformed CX source: ${err.msg()}')
	}
	mut ids := []string{}
	cx_collect_ids(doc.prolog, mut ids)
	cx_collect_ids(doc.elements, mut ids)
	mut anchors := []string{}
	cx_collect_anchors(doc.prolog, mut anchors)
	cx_collect_anchors(doc.elements, mut anchors)
	mut out := []cx.Node{}
	cx_collect_refs(doc.prolog, '', ids, anchors, mut out)
	cx_collect_refs(doc.elements, '', ids, anchors, mut out)
	return cx.Element{
		name:  seq_marker_name
		items: out
	}
}

fn cx_ref_record(kind string, path string, attr string, name string, resolved bool) cx.Node {
	// keys pre-sorted: attr < kind < path < ref < resolved.
	return cx_mod_kv_map(['attr', 'kind', 'path', 'ref', 'resolved'], [
		codec_str_node(attr),
		codec_str_node(kind),
		codec_str_node(path),
		codec_str_node(name),
		cx_mod_bool_node(resolved),
	])
}

fn cx_collect_refs(nodes []cx.Node, base string, ids []string, anchors []string, mut out []cx.Node) {
	// Positional disambiguation matches cx_mod_split_path / cx_mod_child_pos:
	// 1-based among SAME-NAME element siblings, the index written only from
	// the second occurrence on (a bare name addresses the first).
	mut seen := map[string]int{}
	for n in nodes {
		if n is cx.AliasNode {
			out << cx_ref_record('alias', base, '', n.name, n.name in anchors)
			continue
		}
		if n is cx.Element {
			seen[n.name]++
			nth := seen[n.name]
			path := if nth > 1 {
				'${base}/${n.name}[${nth}]'
			} else {
				'${base}/${n.name}'
			}
			for a in n.attrs {
				if a.is_ref {
					rid := cx.scalar_value_str_public(a.value)
					out << cx_ref_record('idref', path, a.name, rid, rid in ids)
				}
			}
			if br := n.body_ref() {
				out << cx_ref_record('body-ref', path, '', br, br in ids)
			}
			if mr := n.merge() {
				// MergeRef `*Name` (grammar [61]) is the anchor namespace's
				// other reference form: merge the anchor's attrs/items into
				// this element rather than replace the element with it.
				out << cx_ref_record('merge', path, '', mr, mr in anchors)
			}
			cx_collect_refs(n.items, path, ids, anchors, mut out)
		}
	}
}

// ── cx:resolve-includes — §13 inclusion, at runtime (§2.2) ──────────────────
//
// `[$cx:resolve-includes VALUE ROOT] → any`, impure. Runs the code.md §13
// `[?cx include]` resolution algorithm (cx/include.v, whose own doc-comment
// has named this function as its intended second caller since it was written)
// against an EXPLICIT root — §3.1's "no filesystem-relative paths inherit from
// the caller" is exactly why the root is a required argument and not ambient.
//
// Capability: `read`. security.md's capability table scopes `read` as
// "filesystem reads, `[?cx include]`" (spec-cited), and this is `[?cx include]`
// at runtime, so it is gated there. Denial is CXER0271, the one
// capability-refusal code.
//
// Error mapping. The algorithm's own codes are code.md §13.8's `E9xx`; §6 of
// this module assigns CXER codes to three of those outcomes, so those three
// are re-coded and the rest pass through on §13.8, which stays their normative
// table:
//   E904 include cycle           → CXER4107
//   E906 included file missing   → CXER4108
//   E902 escapes the root        → CXER4109  (the traversal refusal)
//   E901/E903/E905/E907..E911    → unchanged (§13.8; §6 assigns them nothing)
fn cx_mod_resolve_includes(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:resolve-includes requires VALUE and ROOT arguments')
	}
	if !cap_allowed('read') {
		return mk_err('cx-err:CXER0271', 'read capability denied — cx:resolve-includes reads the included files from disk (run with --allow-read)')
	}
	root := cx_mod_source_text(args[1]) or {
		return mk_err('cx-err:CXER0100', 'cx:resolve-includes: ROOT must be a directory path string')
	}
	if root.trim_space() == '' {
		return mk_err('cx-err:CXER0100', 'cx:resolve-includes: ROOT must be a non-empty directory path — resolution runs against an EXPLICIT root (modules/cx.md §3.1), never the caller\'s cwd')
	}
	mut doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:resolve-includes: malformed CX source: ${err.msg()}')
	}
	mut abs_root := root
	if !os.is_abs_path(abs_root) {
		abs_root = os.abs_path(abs_root)
	}
	if os.exists(abs_root) {
		abs_root = os.real_path(abs_root)
	}
	cx.resolve_includes_doc(mut doc, cx.ResolveIncludeOpts{
		root:          abs_root
		max_depth:     cx.max_include_depth_default
		current_file:  abs_root
		include_stack: []
	}) or {
		return mk_err(cx_include_err_code(err.msg()), 'cx:resolve-includes: ${err.msg()}')
	}
	return cx_mod_doc_value(doc)
}

// cx_include_err_code re-codes the three §13.8 outcomes modules/cx.md §6
// names, and leaves every other one on its §13.8 code.
fn cx_include_err_code(msg string) string {
	if msg.contains('cx-err:E904') {
		return 'cx-err:CXER4107'
	}
	if msg.contains('cx-err:E906') {
		return 'cx-err:CXER4108'
	}
	if msg.contains('cx-err:E902') {
		return 'cx-err:CXER4109'
	}
	idx := msg.index('cx-err:') or { return 'cx-err:CXER4100' }
	rest := msg[idx + 7..]
	mut end := 0
	for end < rest.len && rest[end] != ` ` {
		end++
	}
	if end == 0 {
		return 'cx-err:CXER4100'
	}
	return 'cx-err:${rest[..end]}'
}

// ── cx:strip-comments / cx:strip-attrs — §2.3 transform helpers ─────────────

// `[$cx:strip-comments VALUE] → any`, pure. Drops every comment node — both
// spellings (`# line` and `[; block]`) at every depth. Comments are excluded
// from identity by canonical.md, so this makes explicit at the VALUE level
// what `cx:canonical` does silently at the bytes level.
fn cx_mod_strip_comments(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:strip-comments requires exactly one VALUE argument')
	}
	mut doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:strip-comments: malformed CX source: ${err.msg()}')
	}
	doc.prolog = cx_strip_comment_nodes(doc.prolog)
	doc.elements = cx_strip_comment_nodes(doc.elements)
	return cx_mod_doc_value(doc)
}

fn cx_strip_comment_nodes(nodes []cx.Node) []cx.Node {
	mut out := []cx.Node{cap: nodes.len}
	for n in nodes {
		if n is cx.CommentNode {
			continue
		}
		if n is cx.Element {
			mut el := n
			el.items = cx_strip_comment_nodes(n.items)
			out << cx.Node(el)
			continue
		}
		out << n
	}
	return out
}

// `[$cx:strip-attrs VALUE PATTERN] → any`, pure. Drops every attribute whose
// NAME matches PATTERN, at every depth.
//
// SPEC NOTE (inferred, NOT spec-cited). §2.3 types the second argument
// `$pattern::string` and §6 gives CXER4115 for an "invalid name-pattern", but
// no approved spec text defines the pattern LANGUAGE. This implements the
// single-segment GLOB the engine already carries for names (`*` any run, `?`
// one char, `[abc]` / `[a-z]` a class — stdlib_path.v `match_one_seg`, the same
// matcher `io:glob` and the bus head-name patterns use), because "name-pattern"
// is the glob vocabulary in this tree and reusing one matcher beats
// introducing a second. It is deliberately NOT the RE2 `pattern=` of
// schema/validate: that one is spelled `pattern`, is a full-match regex over
// VALUES, and would make `x-*` mean something else entirely. Flagged for the
// owner rather than resolved in spec text (VC-6 authorizes implementation
// only).
//
// CXER4115 fires on an empty/blank pattern and on an unterminated `[` class —
// the two ways a name-glob is malformed rather than merely non-matching.
fn cx_mod_strip_attrs(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:strip-attrs requires VALUE and PATTERN arguments')
	}
	pattern := cx_mod_source_text(args[1]) or {
		return mk_err('cx-err:CXER4115', 'cx:strip-attrs: PATTERN must be a name-pattern string (cx-err:CXER4115)')
	}
	if !cx_name_pattern_valid(pattern) {
		return mk_err('cx-err:CXER4115', 'cx:strip-attrs: `${pattern}` is not a valid name-pattern — expected a name glob (`*`, `?`, `[…]`), non-empty and with every `[` class closed (cx-err:CXER4115)')
	}
	mut doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:strip-attrs: malformed CX source: ${err.msg()}')
	}
	doc.prolog = cx_strip_attr_nodes(doc.prolog, pattern)
	doc.elements = cx_strip_attr_nodes(doc.elements, pattern)
	return cx_mod_doc_value(doc)
}

// cx_name_pattern_valid rejects the two malformed name-globs: empty / blank,
// and an unterminated `[` character class.
fn cx_name_pattern_valid(p string) bool {
	if p.trim_space() == '' {
		return false
	}
	mut i := 0
	for i < p.len {
		if p[i] == `[` {
			mut j := i + 1
			mut closed := false
			for j < p.len {
				if p[j] == `]` {
					closed = true
					break
				}
				j++
			}
			if !closed {
				return false
			}
			i = j + 1
			continue
		}
		i++
	}
	return true
}

fn cx_strip_attr_nodes(nodes []cx.Node, pattern string) []cx.Node {
	mut out := []cx.Node{cap: nodes.len}
	for n in nodes {
		if n is cx.Element {
			mut el := n
			mut keep := []cx.Attribute{cap: n.attrs.len}
			for a in n.attrs {
				if match_one_seg(pattern, a.name) {
					continue
				}
				keep << a
			}
			el.attrs = keep
			el.items = cx_strip_attr_nodes(n.items, pattern)
			out << cx.Node(el)
			continue
		}
		out << n
	}
	return out
}

// ── cx:pretty-print — §2.3 layout with options ──────────────────────────────
//
// `[$cx:pretty-print VALUE OPTS?] → string`, pure. §2.3 opts and defaults:
// `indent` 2, `max-line-length` 80, `sort-attrs` false, `strip-comments`
// false.
//
// This is a LAYOUT pass, not a second emitter: every token — element heads,
// attribute spellings, scalar quoting, collection forms — comes from
// `cx.cx_emit_node_str(n, true)`, the shipped compact canonical emitter. This
// function owns only the two decisions the canonical emitter does not model:
//   - how WIDE one nesting level is (`indent`; emit_cx hardcodes two spaces),
//   - WHETHER a node goes on one line (`max-line-length`; emit_cx decides
//     structurally — block iff it has element children and no text — and has
//     no notion of a line budget at all).
// A node whose compact form fits the budget at its indent stays on one line;
// otherwise it opens, lays its children out one level deeper, and closes.
// Because the token layer is shared, `indent=2` with a large
// `max-line-length` converges on the canonical form rather than approximating
// it.
struct CxPrettyOpts {
mut:
	indent          int
	max_line_length int
	sort_attrs      bool
	strip_comments  bool
}

fn cx_mod_pretty_print(args []cx.Node) cx.Node {
	if args.len < 1 || args.len > 2 {
		return mk_err('cx-err:CXER0100', 'cx:pretty-print requires (VALUE OPTS?)')
	}
	mut o := CxPrettyOpts{
		indent:          2
		max_line_length: 80
		sort_attrs:      false
		strip_comments:  false
	}
	if args.len > 1 {
		iv, has_indent := map_get_int(args[1], 'indent')
		if has_indent {
			if iv < 0 {
				return mk_err('cx-err:CXER0100', 'cx:pretty-print: `indent` must be >= 0')
			}
			o.indent = iv
		}
		mv, has_max := map_get_int(args[1], 'max-line-length')
		if has_max {
			if mv < 1 {
				return mk_err('cx-err:CXER0100', 'cx:pretty-print: `max-line-length` must be >= 1')
			}
			o.max_line_length = mv
		}
		o.sort_attrs = cx_opt_bool(args[1], 'sort-attrs')
		o.strip_comments = cx_opt_bool(args[1], 'strip-comments')
	}
	mut doc := cx_mod_arg_doc(args[0]) or {
		return mk_err('cx-err:CXER4100', 'cx:pretty-print: malformed CX source: ${err.msg()}')
	}
	if o.strip_comments {
		doc.prolog = cx_strip_comment_nodes(doc.prolog)
		doc.elements = cx_strip_comment_nodes(doc.elements)
	}
	if o.sort_attrs {
		doc.prolog = cx_sort_attr_nodes(doc.prolog)
		doc.elements = cx_sort_attr_nodes(doc.elements)
	}
	mut lines := []string{}
	for n in doc.prolog {
		cx_pretty_node(n, 0, o, mut lines)
	}
	for n in doc.elements {
		cx_pretty_node(n, 0, o, mut lines)
	}
	return codec_str_node(lines.join('\n'))
}

// cx_opt_bool reads a bool option out of an opts map. Absent / non-bool is
// false, which is every §2.3 bool default.
fn cx_opt_bool(v cx.Node, key string) bool {
	binds := map_value_to_bindings(v)
	val := binds[key] or { return false }
	if val is cx.ScalarNode {
		bv := val.value
		if bv is bool {
			return bv
		}
	}
	return false
}

fn cx_sort_attr_nodes(nodes []cx.Node) []cx.Node {
	mut out := []cx.Node{cap: nodes.len}
	for n in nodes {
		if n is cx.Element {
			mut el := n
			mut attrs := n.attrs.clone()
			attrs.sort(a.name < b.name)
			el.attrs = attrs
			el.items = cx_sort_attr_nodes(n.items)
			out << cx.Node(el)
			continue
		}
		out << n
	}
	return out
}

fn cx_pretty_node(n cx.Node, depth int, o CxPrettyOpts, mut lines []string) {
	ind := ' '.repeat(depth * o.indent)
	compact := cx.cx_emit_node_str(n, true)
	if ind.len + compact.len <= o.max_line_length {
		lines << '${ind}${compact}'
		return
	}
	if head := cx_pretty_block_head(n) {
		el := n as cx.Element
		lines << '${ind}${head}'
		for item in el.items {
			cx_pretty_node(item, depth + 1, o, mut lines)
		}
		lines << '${ind}]'
		return
	}
	// Over budget but not splittable: the compact form is the honest
	// rendering. Never truncate and never wrap mid-token — max-line-length is
	// a layout preference, not a licence to emit text that no longer
	// re-parses to the value.
	lines << '${ind}${compact}'
}

// cx_pretty_block_head returns the element's OPEN form (`[name attrs…`) when
// the node can be laid out as a block, or none when it must stay atomic.
//
// The head is derived by rendering the element with its children REMOVED and
// dropping the closing `]`, so the head's tokens are the canonical emitter's
// own rather than a re-implementation of its private head builder.
//
// Atomic (no block form) when:
//   - the node is not an Element;
//   - it has no children to move onto their own lines;
//   - any child is NOT an element or comment: a text / scalar body shares the
//     element's line in the canonical form (emit_cx's `has_child_elements &&
//     !has_text` rule), and splitting it would change the parse;
//   - it renders through one of the three special element lanes whose text is
//     produced whole — `[ref @id]` (body_ref), a `[table[…]]` block, or a
//     typed-array body.
fn cx_pretty_block_head(n cx.Node) ?string {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	if el.items.len == 0 {
		return none
	}
	if _ := el.body_ref() {
		return none
	}
	if _ := el.table_opt() {
		return none
	}
	if dt := el.data_type() {
		if dt.ends_with('[]') {
			return none
		}
	}
	for item in el.items {
		if item !is cx.Element && item !is cx.CommentNode {
			return none
		}
	}
	mut childless := el
	childless.items = []
	rendered := cx.cx_emit_node_str(cx.Node(childless), true)
	if !rendered.ends_with(']') {
		return none
	}
	return rendered[..rendered.len - 1]
}
