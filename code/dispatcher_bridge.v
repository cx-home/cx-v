module code

import cx

// dispatcher_bridge.v — Z79g rock-solid finish of the dispatcher
// integration started in Z79a–Z79f.
//
// This file closes the two structural gaps documented at the
// `eval_match` / `eval_modify` TODO blocks in `eval.v`:
//
//   Gap 1 — `[?modify]` path-precision: standalone
//     `eval_modify_node_structural` reduces the focus path to its
//     final element-name (`target_name_for_focus`), losing multi-step
//     axis composition + predicate filters. Predicate-bearing focus
//     like `//user[@active=false]` reduces to "any user element" at
//     standalone scope, which doesn't match the dispatcher's spec.
//
//     Fix here: a NEW path-precise structural evaluator
//     `eval_modify_node_path_aware` that uses
//     `vcx/code/cxpath_eval.v::eval_cxpath` to materialise the
//     candidate-node set from a `&CxNode` adapter tree and
//     translates matches back to a positional index path so actions
// apply only to the filtered candidates. multi-match
//     semantics preserved.
//
//   Gap 2 — `[?match]` pattern typing: standalone `match_eval.v`
//     consumes `MatchNode.arms[i].pattern_node ?cx.Node` populated by
//     `cx.parse(...)` (the cx-DATA parser) — which returns
//     `TextNode("200")` for scalar literals. The dispatcher
//     pre-evaluates the scrutinee to `ScalarNode(int_type, 200)`.
//     `node_structural_eq` requires same-variant nodes, so scalar
//     `:case 200` arms never fire.
//
//     Fix here: a re-typer `retype_match_pattern_nodes` that walks
//     the parsed MatchNode, re-parses each `:case` arm's pattern
//     source via the PROGRAM parser, and replaces `pattern_node`
//     with a typed `cx.Node` produced by `eval_node(...)` against
//     an empty env. Same treatment applied to the body slot when
//     it parses cleanly (so `:yield 200` evaluates to
//     ScalarNode(int_type, 200) rather than TextNode).
//
// Live dispatch wiring lands in `eval.v::eval_match` / `eval_modify`
// — both now invoke `try_eval_match_via_bridge` /
// `try_eval_modify_via_bridge` first and fall back to the legacy
// implementations only when the bridge returns `none` (single-arm
// match form; unparseable focus / scrutinee; un-handled action
// shape). The bridge functions themselves are extended below to
// drive the new path-aware modify evaluator + the retyped match
// pattern nodes.
//
// Cross-references:
//   - vcx/code/eval.v  — dispatcher hops + Z79f bridge entry points
//   - vcx/code/match_eval.v / modify_eval.v — standalone evaluators
//   - vcx/code/cxpath_eval.v — &CxNode axis walker (Z79e)
//   - vcx/code/program_emit.v — cx.ProgramNode → source emitter (Z79f)
//   - vcx/cx/match_parser.v / modify_parser.v — surface → AST parsers
// (match) (modify) (sharing)

// ── Gap 2 — re-type match pattern nodes via program parser ────────────────────

// program_parse_to_typed_node parses `src` via the PROGRAM parser
// (`code.parse`) and evaluates the resulting cx.ProgramNode against an
// empty MatchEnv via `eval_node`. The result is a typed `cx.Node` —
// e.g. `"200"` → ScalarNode(int_type, 200), `":ok"` → ScalarNode(atom_type, ":ok"),
// `"[user 1]"` → Element{name:"user", items:[ScalarNode(int_type, 1)]}.
//
// Returns `none` when the program parser rejects the source (e.g.
// unbalanced brackets) OR when evaluation surfaces an error (e.g.
// the source references an unbound binding). The caller falls back
// to the cx-data-parsed value or the verbatim string.
//
// The function is conservative: it only evaluates a CLOSED cx.ProgramNode
// (no free bindings). When the pattern source contains `$name`
// bindings (legitimate in `:case` element-with-bind patterns), the
// program-parser path errors out and we keep the cx-data-parsed
// pattern_node intact.
pub fn program_parse_to_typed_node(src string) ?cx.Node {
	trimmed := src.trim_space()
	if trimmed.len == 0 {
		return none
	}
	prog := cx.parse_program(trimmed) or { return none }
	mut env := new_env()
	result := eval_node(prog.body, mut env) or { return none }
	return result
}

// retype_match_pattern_nodes walks a `cx.MatchNode` and replaces each
// `:case` arm's `pattern_node` with a typed cx.Node produced by the
// program parser (when possible). The original cx-data-parsed
// pattern_node is retained as fallback if program parsing fails.
//
// Same treatment applied to arm `body_node` slots — so `:yield 200`
// resolves to a typed ScalarNode that round-trips through render.
//
// Guard slots are left untouched: guards are evaluated via the
// PredicateExpr parser path (`eval_arm_predicate_body` in
// `match_eval.v`), which already handles the typing.
//
// Returns a new MatchNode with patched arms. Source-level fields
// (`scrutinee`, `source`, `loc`) are preserved verbatim.
pub fn retype_match_pattern_nodes(m cx.MatchNode) cx.MatchNode {
	mut new_arms := []cx.MatchArm{cap: m.arms.len}
	for arm in m.arms {
		mut new_arm := arm
		// Pattern slot — only :case arms carry patterns. We try the
		// program parser; on success the typed node replaces the
		// cx-data-parsed one. On failure (e.g. element-with-bind
		// `[user $u]` references unbound $u) we keep the original.
		if arm.kind == cx.ArmKind.case_arm && arm.pattern.len > 0 {
			// First, try to detect patterns that the program parser
			// would mishandle: bind-only `$name` patterns and
			// element-with-bind shapes. These contain free bindings
			// that eval_node would error on. The cx-data-parsed
			// pattern_node is the right shape for these.
			if !pattern_has_free_bindings(arm.pattern) {
				if typed := program_parse_to_typed_node(arm.pattern) {
					new_arm.pattern_node = ?cx.Node(typed)
				}
			}
		}
		// Body slot — re-typed for all arm kinds. The dispatcher hop
		// (eval_match / try_eval_match_via_bridge) re-evaluates the
		// body via eval_node against the dispatcher's MatchEnv anyway,
		// so the structural body_node is advisory. But for arms
		// whose body is a closed literal (e.g. `:yield :ok`), the
		// typed body_node lets the bridge short-circuit the parse
		// step in the common case.
		if arm.body.len > 0 && !pattern_has_free_bindings(arm.body) {
			if typed := program_parse_to_typed_node(arm.body) {
				new_arm.body_node = ?cx.Node(typed)
			}
		}
		new_arms << new_arm
	}
	return cx.MatchNode{
		scrutinee: m.scrutinee
		arms:      new_arms
		source:    m.source
		loc:       m.loc
	}
}

// pattern_has_free_bindings returns true when the source contains a
// `$`-prefixed identifier that the program-parser path would treat
// as an unbound binding. Element-with-bind patterns like `[user $u]`
// AND bind-only patterns like `$u` AND any source containing `$`
// trigger the conservative fallback. Wildcard `_` does not trigger
// (it parses as cx.ProgramCall and evaluates fine via dispatch_call).
fn pattern_has_free_bindings(src string) bool {
	return src.contains('\$')
}

// is_bridge_compatible_case_pattern reports whether the dispatcher
// bridge can route a `:case` arm with this pattern through the
// standalone evaluator (vcx/code/match_eval.v) + Gap-2 retype. The
// bridge supports CLOSED literal patterns (scalars + element literals
// without $-bindings). It declines for shapes that need legacy
// binding-capture or wildcard semantics:
//
//   - cx.ProgramBinding (`$x`)                     — bind-only, no eq test
//   - cx.ProgramPattern (`[name $u]` / `[* …]`)    — pattern shape with
//     binding capture / wildcard heads
//   - cx.ProgramCall (`_()` / `**`)                — wildcard-call shapes
//     the standalone evaluator's wildcard short-circuit can't see
//     after the emit→reparse round-trip (the emitter produces `_()`
//     not `_`, breaking the pat_trim equality test in match_arm_case)
//   - Anything containing a free `$`-binding via the emit→reparse
//     round-trip (conservative source-scan fallback)
pub fn is_bridge_compatible_case_pattern(n cx.ProgramNode) bool {
	match n {
		cx.ProgramBinding {
			return false
		}
		cx.ProgramPattern {
			// Element-shape patterns with binding capture / wildcard
			// heads can't be handled at the standalone scope. Even a
			// "closed" pattern like `[user 1]` won't parse: the
			// program parser requires pattern body items to be `[..]`,
			// `$bind`, `*`, or `**` — it won't accept literal int
			// bodies in pattern position.
			return false
		}
		cx.ProgramCall {
			// `_()` and `**()` shapes — the emit→reparse roundtrip
			// loses the bare-name shape the standalone wildcard
			// short-circuit expects.
			if n.name == '_' || n.name == '*' || n.name == '**' {
				return false
			}
			// Conservative: any call with args might carry side-effects
			// or unbound refs. Decline.
			if n.args.len > 0 {
				return false
			}
			return false
		}
		cx.ProgramLiteral {
			// Scalar / atom literals + closed element literals are
			// bridge-compatible. Scan nested items for free bindings.
			return !has_free_binding_in_literal(n)
		}
		else {
			// PathExpr / Directive / ForComp / Wildcard / cx.Program —
			// not legal in `:case` pattern position per the grammar.
			// Conservative decline.
			return false
		}
	}
}

// has_free_binding_in_literal walks a cx.ProgramLiteral's nested items
// looking for any cx.ProgramBinding or any cx.ProgramPattern (which would
// carry its own free bindings). Returns true when the literal isn't
// fully closed.
fn has_free_binding_in_literal(l cx.ProgramLiteral) bool {
	for it in l.items {
		match it {
			cx.ProgramBinding {
				return true
			}
			cx.ProgramPattern {
				return true
			}
			cx.ProgramLiteral {
				if has_free_binding_in_literal(it) {
					return true
				}
			}
			cx.ProgramCall {
				for a in it.args {
					if a is cx.ProgramBinding {
						return true
					}
				}
			}
			else {}
		}
	}
	return false
}

// ── Gap 1 — path-aware structural modify evaluator ────────────────────────────

// eval_modify_node_path_aware runs the action chain over a parsed
// `cx.Node` doc-root using CXPath-precision focus resolution. Unlike
// `eval_modify_node_structural` (which reduces focus to a final
// element-name), this evaluator builds a parallel `&CxNode` adapter
// tree, runs the focus through `eval_cxpath`, and translates matched
// `&CxNode` references back to positional index paths in the
// original `cx.Node` tree so actions apply only to the filtered
// candidates (predicate-bearing focus → only matching elements).
//
// multi-match semantics preserved. Actions process
// matches in REVERSE document order so earlier matches' positions
// stay stable across structural mutations.
//
// Returns `none` when:
//   - The focus source doesn't parse as a `cx.PathNode`.
//   - The doc-root is not an `cx.Element` (paths require an element
//     root for the adapter walk).
//   - An action surfaces an unrecoverable error from the underlying
//     `apply_action_to_element_subtree` helper.
//
// Backward-compat: the existing `eval_modify_node_structural` (Z79d
// surface, target-name-reduced focus) is preserved unchanged for the
// dispatcher tests that pin the standalone-scope reduction.
pub fn eval_modify_node_path_aware(node cx.ModifyNode, doc_root cx.Node,
	context EvalContext) !ModifyResult {
	_ = context
	// Parse focus → PathNode. Failure → return identity-ish + no matches.
	raw_path := cx.parse_path(node.focus) or {
		return ModifyResult{
			result_doc:      emit_node_compact_doc(doc_root)
			result_node:     ?cx.Node(doc_root)
			actions_applied: 0
			actions_skipped: node.actions.len
			focus_matches:   0
		}
	}
	// Z79g — Gap 1 detail: `cx.parse_path("//doc")` produces
	// `form: .descendant, steps[0].axis: .child` (the descendant-form
	// surface lowering happens at evaluation time). Two evaluation
	// strategies exist:
	//
	//   - `cxpath_eval.v` (Z79e) prepends `descendant-or-self::node()`
	//     to the step list — strict XPath semantics where `//doc` is
	//     `descendant-or-self::node()/child::doc`, EXCLUDING the
	//     document root from matches.
	//   - `eval.v::apply_first_step` (legacy) iterates EVERY element in
	//     doc-order under descendant-or-self axis, INCLUDING the root.
	//     This is the spec semantics the dispatcher tests pin (see
	//     fixture `program-modify-string-scalar-roundtrip` which
	//     renames the root `[doc …]` via `//doc :rename root`).
	//
	// To match the dispatcher / spec semantics, promote the first step's
	// axis from `.child` → `.descendant_or_self` when `form == .descendant`
	// AND the step doesn't carry an explicit axis prefix. This is the
	// same lowering the program parser applies up-front (see
	// `code.parse_path_expr` line 287 — `cx.ProgramPathAxis.descendant_or_self`).
	promoted := promote_descendant_first_step(raw_path)
	// when the focus path terminates at an attribute axis
	// step (`//user/@name`), strip the attribute step and capture the
	// attribute name. The CXPath evaluator then locates the PARENT
	// element matches; `:set "X"` is rewritten to `:set-attr <attr> "X"`.
	// This unblocks the spec-canonical `[?modify $doc //user/@name :set X]`
	// pattern without a second evaluator pass.
	mut path := promoted
	mut attr_tail := ''
	if promoted.steps.len > 0 {
		last := promoted.steps[promoted.steps.len - 1]
		final_test := last.node_test.trim_space()
		is_attr_axis := last.axis == .attribute || final_test.starts_with('@')
		if is_attr_axis {
			mut attr := final_test
			if attr.starts_with('@') { attr = attr[1..] }
			if attr.len > 0 && promoted.steps.len >= 2 {
				attr_tail = attr
				mut shorter := promoted.steps[..promoted.steps.len - 1].clone()
				path = cx.PathNode{
					form:       promoted.form
					binding:    promoted.binding
					steps:      shorter
					predicates: promoted.predicates
				}
			}
		}
	}
	// Doc must be an Element for the adapter walk.
	if doc_root !is cx.Element {
		return ModifyResult{
			result_doc:      emit_node_compact_doc(doc_root)
			result_node:     ?cx.Node(doc_root)
			actions_applied: 0
			actions_skipped: node.actions.len
			focus_matches:   0
		}
	}
	mut current := doc_root
	mut applied := 0
	mut skipped := 0
	mut total_matches := 0
	for raw_action in node.actions {
		action := if attr_tail.len > 0 && raw_action.kind == cx.ModifyActionKind.set {
			cx.ModifyAction{
				kind:       cx.ModifyActionKind.set_attr
				name:       attr_tail
				value:      raw_action.value
				value_node: raw_action.value_node
				loc:        raw_action.loc
			}
		} else {
			raw_action
		}
		// Build a fresh adapter tree per action — the previous action
		// may have mutated `current` structurally.
		root_el := current as cx.Element
		adapter_root, index_map := build_cxnode_tree(root_el)
		dispatcher := new_default_axis_dispatcher()
		matches := eval_cxpath(path, [adapter_root], dispatcher) or {
			// Path doesn't evaluate → treat as no-match.
			skipped++
			continue
		}
		if matches.len == 0 {
			skipped++
			continue
		}
		// Translate matches → index paths in the original cx.Node tree.
		mut idx_paths := [][]int{cap: matches.len}
		for m in matches {
			if path_to_match := index_path_of_cxnode(m, index_map) {
				idx_paths << path_to_match
			}
		}
		if idx_paths.len == 0 {
			skipped++
			continue
		}
		// Apply in REVERSE document order so deletions / insertions
		// don't shift earlier match positions.
		idx_paths.sort_with_compare(fn (a &[]int, b &[]int) int {
			la := a.len
			lb := b.len
			mut i := 0
			for i < la && i < lb {
				if a[i] != b[i] {
					return if a[i] < b[i] { 1 } else { -1 }
				}
				i++
			}
			if la == lb { return 0 }
			return if la < lb { 1 } else { -1 }
		})
		total_matches += idx_paths.len
		for p in idx_paths {
			current = apply_action_at_index_path(current, p, action)!
		}
		applied++
	}
	return ModifyResult{
		result_doc:      emit_node_compact_doc(current)
		result_node:     ?cx.Node(current)
		actions_applied: applied
		actions_skipped: skipped
		focus_matches:   total_matches
	}
}

// promote_descendant_first_step rewrites a `.descendant`-form PathNode
// whose first step has the default `.child` axis to use the
// `.descendant_or_self` axis instead. This aligns `cx.parse_path`'s
// raw output with the lowering the program parser applies upfront —
// see `code.parse_path_expr` and the `cxpath_eval.v` step-list prefix
// synthesis at `node.form == .descendant`. Returns the input
// unchanged when no promotion is needed (form is not descendant, or
// the first step already has an explicit non-default axis).
fn promote_descendant_first_step(p cx.PathNode) cx.PathNode {
	if p.form != cx.PathForm.descendant {
		return p
	}
	if p.steps.len == 0 {
		return p
	}
	if p.steps[0].axis != cx.PathAxis.child {
		return p
	}
	mut new_steps := p.steps.clone()
	new_steps[0] = cx.PathStep{
		axis:       cx.PathAxis.descendant_or_self
		node_test:  p.steps[0].node_test
		binding:    p.steps[0].binding
		predicates: p.steps[0].predicates
	}
	// Form stays .descendant so `cxpath_eval.v`'s step-list synthesis
	// still prepends `descendant-or-self::node()` — combined with our
	// promoted first step that's `descendant-or-self::node()/descendant-or-self::doc`
	// which is equivalent to `descendant-or-self::doc` modulo dedup.
	// To prevent the prepend (which would yield a redundant pass), we
	// downgrade form to .relative when the first step already carries
	// descendant-or-self axis post-promotion.
	return cx.PathNode{
		form:       cx.PathForm.relative
		binding:    p.binding
		steps:      new_steps
		predicates: p.predicates
		source:     p.source
		loc:        p.loc
	}
}

// ── CxNode adapter — build a &CxNode tree from a cx.Element subtree ──────────

// CxNodeIndex carries the reverse-mapping from a `&CxNode` adapter
// pointer back to its index path in the source `cx.Element` tree.
// `path` is the sequence of child positions in `.items[]` from doc
// root to the target element. Empty path = root.
struct CxNodeIndex {
mut:
	addr voidptr
	path []int
}

// build_cxnode_tree mirrors a `cx.Element` subtree into a parallel
// `&CxNode` tree suitable for `eval_cxpath`. The returned index map
// is a slice of `CxNodeIndex` records — one per node in the adapter
// tree — that lets callers translate a matched `&CxNode` back to its
// positional path in the original `cx.Element` tree.
//
// Only Element children are mirrored as adapter elements; ScalarNode
// / TextNode / etc. children are mirrored as text-kind adapter nodes
// so the axis walker can see them but doesn't recurse into them as
// elements. Attribute axes are populated from `cx.Attribute.value`
// using the canonical scalar-string projection.
fn build_cxnode_tree(root cx.Element) (&CxNode, []CxNodeIndex) {
	mut index_map := []CxNodeIndex{}
	root_adapter := build_cxnode_tree_recursive(root, []int{}, mut index_map)
	return root_adapter, index_map
}

// build_cxnode_tree_recursive builds the adapter tree depth-first.
// `path` is the current node's positional path; updated for each
// child.
fn build_cxnode_tree_recursive(el cx.Element, path []int,
	mut index_map []CxNodeIndex) &CxNode {
	mut attrs := map[string]string{}
	for a in el.attrs {
		attrs[a.name] = cx.scalar_value_str_public(a.value)
	}
	mut node := &CxNode{
		kind:     .element
		name:     ?string(el.name)
		attrs:    attrs
		children: []&CxNode{}
	}
	index_map << CxNodeIndex{
		addr: voidptr(node)
		path: path.clone()
	}
	for i, item in el.items {
		mut child_path := path.clone()
		child_path << i
		match item {
			cx.Element {
				mut child := build_cxnode_tree_recursive(item, child_path, mut index_map)
				child.parent = node
				node.children << child
			}
			cx.ScalarNode {
				// Mirror scalars as text-kind so axis walker sees them
				// but doesn't recurse. Path tracked so attribute-style
				// modifies still locate the leaf if focus targets it.
				text_node := &CxNode{
					kind:     .text
					value:    ?string(cx.scalar_value_str_public(item.value))
					attrs:    map[string]string{}
					children: []&CxNode{}
					parent:   ?&CxNode(node)
				}
				index_map << CxNodeIndex{
					addr: voidptr(text_node)
					path: child_path.clone()
				}
				node.children << text_node
			}
			cx.TextNode {
				text_node := &CxNode{
					kind:     .text
					value:    ?string(item.value)
					attrs:    map[string]string{}
					children: []&CxNode{}
					parent:   ?&CxNode(node)
				}
				index_map << CxNodeIndex{
					addr: voidptr(text_node)
					path: child_path.clone()
				}
				node.children << text_node
			}
			else {
				// Other node kinds (MatchNode / ModifyNode / etc.) —
				// mirror as text-kind placeholder so the walker sees
				// something. Path still tracked.
				text_node := &CxNode{
					kind:     .text
					value:    ?string('')
					attrs:    map[string]string{}
					children: []&CxNode{}
					parent:   ?&CxNode(node)
				}
				index_map << CxNodeIndex{
					addr: voidptr(text_node)
					path: child_path.clone()
				}
				node.children << text_node
			}
		}
	}
	return node
}

// index_path_of_cxnode resolves a matched `&CxNode` pointer back to
// its index path via the `index_map`. Returns `none` when the pointer
// isn't in the map (e.g. an attribute axis match — attributes are
// not currently mirrored into the adapter tree as standalone &CxNode
// references).
fn index_path_of_cxnode(target &CxNode, index_map []CxNodeIndex) ?[]int {
	target_addr := voidptr(target)
	for entry in index_map {
		if entry.addr == target_addr {
			return entry.path.clone()
		}
	}
	return none
}

// ── Action application at an index path ──────────────────────────────────────

// apply_action_at_index_path walks the doc tree to the element at
// `path` (sequence of child positions in `.items[]`) and applies the
// `action`. The walk rebuilds the spine bottom-up so the doc-root
// returns a freshly-allocated tree with the action's effect at the
// target position (v0.8.0 ships full-copy).
fn apply_action_at_index_path(doc cx.Node, path []int,
	action cx.ModifyAction) !cx.Node {
	// Empty path → action targets the root.
	if path.len == 0 {
		if doc is cx.Element {
			return apply_modify_action_to_element_node(doc, action)!
		}
		// Non-element root + non-empty action → identity.
		return doc
	}
	// Sibling-mutating actions (delete / insert-before / insert-after /
	// replace) modify the parent's items[] slice — they need the
	// path's parent spine plus the target child position.
	sibling_action := action.kind == cx.ModifyActionKind.delete
		|| action.kind == cx.ModifyActionKind.insert_before
		|| action.kind == cx.ModifyActionKind.insert_after
		|| action.kind == cx.ModifyActionKind.replace
	if sibling_action {
		return apply_sibling_action_at_path(doc, path, action)!
	}
	// Element / attribute action — walk to target, apply, rebuild spine.
	return apply_element_action_at_path(doc, path, action)!
}

// apply_element_action_at_path rebuilds the spine of Elements from
// doc root down to `path[-1]`'s target, applying `action` to the
// terminal Element. Non-sibling actions (set / set-attr / delete-attr
// / rename / using / append / prepend) use this path.
fn apply_element_action_at_path(doc cx.Node, path []int,
	action cx.ModifyAction) !cx.Node {
	if doc !is cx.Element {
		return doc
	}
	root_el := doc as cx.Element
	if path.len == 1 {
		// Direct child of root.
		idx := path[0]
		if idx < 0 || idx >= root_el.items.len {
			return doc
		}
		child := root_el.items[idx]
		if child !is cx.Element {
			return doc
		}
		new_child := apply_modify_action_to_element_node(child as cx.Element, action)!
		mut new_items := root_el.items.clone()
		new_items[idx] = new_child
		return cx.Node(cx.Element{
			name:  root_el.name
			attrs: root_el.attrs
			items: new_items
			meta:  root_el.meta
			table: root_el.table
		})
	}
	// Deeper — recurse into the first child along path.
	first := path[0]
	if first < 0 || first >= root_el.items.len {
		return doc
	}
	child := root_el.items[first]
	if child !is cx.Element {
		return doc
	}
	rest := path[1..]
	new_child := apply_element_action_at_path(cx.Node(child as cx.Element),
		rest, action)!
	mut new_items := root_el.items.clone()
	new_items[first] = new_child
	return cx.Node(cx.Element{
		name:  root_el.name
		attrs: root_el.attrs
		items: new_items
		meta:  root_el.meta
		table: root_el.table
	})
}

// apply_sibling_action_at_path handles delete / insert-before /
// insert-after / replace. These actions modify the PARENT's items[]
// slice at the target's index — different mechanics from
// element-actions which mutate the target itself.
fn apply_sibling_action_at_path(doc cx.Node, path []int,
	action cx.ModifyAction) !cx.Node {
	if doc !is cx.Element {
		return doc
	}
	if path.len == 0 {
		// Root sibling action — fall back to identity for delete /
		// replace; this is an unusual shape and the dispatcher
		// itself surfaces an error here.
		return doc
	}
	root_el := doc as cx.Element
	if path.len == 1 {
		// Path[0] is the index in root_el.items to mutate.
		idx := path[0]
		if idx < 0 || idx >= root_el.items.len {
			return doc
		}
		new_items := apply_sibling_op(root_el.items, idx, action)!
		return cx.Node(cx.Element{
			name:  root_el.name
			attrs: root_el.attrs
			items: new_items
			meta:  root_el.meta
			table: root_el.table
		})
	}
	// Deeper — recurse into the first child along path.
	first := path[0]
	if first < 0 || first >= root_el.items.len {
		return doc
	}
	child := root_el.items[first]
	if child !is cx.Element {
		return doc
	}
	rest := path[1..]
	new_child := apply_sibling_action_at_path(cx.Node(child as cx.Element),
		rest, action)!
	mut new_items := root_el.items.clone()
	new_items[first] = new_child
	return cx.Node(cx.Element{
		name:  root_el.name
		attrs: root_el.attrs
		items: new_items
		meta:  root_el.meta
		table: root_el.table
	})
}

// apply_sibling_op applies a sibling-mutating action to a parent's
// items slice at position `idx`. Returns a new slice with the change.
fn apply_sibling_op(items []cx.Node, idx int,
	action cx.ModifyAction) ![]cx.Node {
	match action.kind {
		.delete {
			mut new_items := []cx.Node{cap: items.len - 1}
			for i, it in items {
				if i != idx {
					new_items << it
				}
			}
			return new_items
		}
		.insert_before {
			vn := value_node_for_action(action) or {
				return error('MODIFY_INSERT_BEFORE: value unparseable (got `${action.value}`)')
			}
			mut new_items := []cx.Node{cap: items.len + 1}
			for i, it in items {
				if i == idx {
					new_items << vn
				}
				new_items << it
			}
			return new_items
		}
		.insert_after {
			vn := value_node_for_action(action) or {
				return error('MODIFY_INSERT_AFTER: value unparseable (got `${action.value}`)')
			}
			mut new_items := []cx.Node{cap: items.len + 1}
			for i, it in items {
				new_items << it
				if i == idx {
					new_items << vn
				}
			}
			return new_items
		}
		.replace {
			vn := value_node_for_action(action) or {
				return error('MODIFY_REPLACE: value unparseable (got `${action.value}`)')
			}
			mut new_items := items.clone()
			new_items[idx] = vn
			return new_items
		}
		else {
			return error('apply_sibling_op: action kind `${cx.modify_action_kind_name(action.kind)}` is not a sibling action')
		}
	}
}

// apply_modify_action_to_element_node applies an element-targeted
// action to a single Element and returns the resulting cx.Node. This
// is the path-aware equivalent of `apply_action_to_element` in
// `modify_eval.v` — it dispatches the same way but uses the
// path-aware sibling helpers above for the four sibling kinds.
//
// At the element-scope entry point we ONLY handle element + attribute
// actions (set / set-attr / delete-attr / rename / using / append /
// prepend). Sibling actions (delete / insert-* / replace) are routed
// via `apply_sibling_op` at the parent level — they never reach this
// function because `apply_action_at_index_path` dispatches first.
fn apply_modify_action_to_element_node(el cx.Element,
	action cx.ModifyAction) !cx.Node {
	return match action.kind {
		.set {
			apply_set_to_element(el, action)
		}
		.set_attr {
			apply_set_attr_to_element(el, action)
		}
		.delete_attr {
			apply_delete_attr_to_element(el, action)
		}
		.rename {
			cx.Node(cx.Element{
				name:  action.name
				attrs: el.attrs
				items: el.items
				meta:  el.meta
				table: el.table
			})
		}
		.using_fn {
			apply_using_to_element(el, action)!
		}
		.append {
			apply_append_to_element(el, action)!
		}
		.prepend {
			apply_prepend_to_element(el, action)!
		}
		// Sibling actions land here only when path is empty (root
		// targets). For .delete return empty element; for the rest
		// fall back to identity.
		.delete {
			cx.Node(cx.Element{ name: '' })
		}
		.replace {
			value_node_for_action(action) or {
				return error('MODIFY_REPLACE_ROOT: value unparseable (got `${action.value}`)')
			}
		}
		.insert_before, .insert_after {
			// Root-level insert-before/after is an unusual shape;
			// fall back to identity (the standalone scope
			// has no concept of root-siblings).
			cx.Node(el)
		}
	}
}

// value_node_for_action returns the structural cx.Node for an
// action's value slot. Prefers `action.value_node` (populated by
// `cx.parse_modify` via the cx-data parser) but re-types via the
// program parser when the value has no free bindings — same Gap-2
// fix applied to modify action values so `:set 42` becomes a typed
// int rather than the cx-data parser's TextNode("42").
fn value_node_for_action(action cx.ModifyAction) ?cx.Node {
	// Try program parser first for typed scalars + element literals.
	if !pattern_has_free_bindings(action.value) {
		if typed := program_parse_to_typed_node(action.value) {
			return typed
		}
	}
	// Fallback — cx-data-parsed value_node if populated.
	if vn := action.value_node {
		return vn
	}
	// Final fallback — re-parse via cx-data parser.
	return cx.try_parse_snippet_to_node(action.value)
}

// apply_set_to_element replaces an Element's body with the action's
// structural value. When the action targets attribute-axis (no
// element body to set), the dispatcher would have routed differently;
// here we treat `:set` as body-replace.
fn apply_set_to_element(el cx.Element, action cx.ModifyAction) cx.Node {
	new_items := if vn := value_node_for_action(action) {
		[vn]
	} else {
		[]cx.Node{}
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: el.attrs
		items: new_items
		meta:  el.meta
		table: el.table
	})
}

// apply_set_attr_to_element writes / overwrites an attribute on `el`.
// The attribute value is extracted via `value_scalar_for_action` so
// string literals like `"active"` are stored as the unquoted scalar
// value `active` (matching the legacy `apply_modify_action` behaviour
// on the same fixture).
fn apply_set_attr_to_element(el cx.Element, action cx.ModifyAction) cx.Node {
	scalar_val := value_scalar_for_action(action)
	mut new_attrs := []cx.Attribute{cap: el.attrs.len + 1}
	mut found := false
	for a in el.attrs {
		if a.name == action.name {
			new_attrs << cx.Attribute{
				name:  action.name
				value: scalar_val
			}
			found = true
		} else {
			new_attrs << a
		}
	}
	if !found {
		new_attrs << cx.Attribute{
			name:  action.name
			value: scalar_val
		}
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: new_attrs
		items: el.items
		meta:  el.meta
		table: el.table
	})
}

// value_scalar_for_action extracts the structural scalar value an
// action carries (for `:set-attr` etc.) by routing through the program
// parser and unwrapping the resulting ScalarNode. Falls back to the
// raw `action.value` string when typed extraction fails.
fn value_scalar_for_action(action cx.ModifyAction) cx.ScalarValue {
	if !pattern_has_free_bindings(action.value) {
		if typed := program_parse_to_typed_node(action.value) {
			if typed is cx.ScalarNode {
				return typed.value
			}
		}
	}
	return cx.ScalarValue(action.value)
}

// apply_delete_attr_to_element removes the named attribute from `el`.
fn apply_delete_attr_to_element(el cx.Element, action cx.ModifyAction) cx.Node {
	mut new_attrs := []cx.Attribute{cap: el.attrs.len}
	for a in el.attrs {
		if a.name != action.name {
			new_attrs << a
		}
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: new_attrs
		items: el.items
		meta:  el.meta
		table: el.table
	})
}

// apply_using_to_element handles `:using` — degraded to `:replace`
// (without `[?fn` lambda evaluation) per the standalone evaluator's
// scope. `[?fn` triggers MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED.
fn apply_using_to_element(el cx.Element, action cx.ModifyAction) !cx.Node {
	if action.value.contains('[?fn') {
		return error('MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED: :using lambda evaluation is deferred to Phase 2.x (got `${action.value}`)')
	}
	return value_node_for_action(action) or {
		return error('MODIFY_USING: value unparseable (got `${action.value}`)')
	}
}

// apply_append_to_element appends the action's structural value as
// the LAST child of `el.items`.
fn apply_append_to_element(el cx.Element, action cx.ModifyAction) !cx.Node {
	mut new_items := el.items.clone()
	if vn := value_node_for_action(action) {
		new_items << vn
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: el.attrs
		items: new_items
		meta:  el.meta
		table: el.table
	})
}

// apply_prepend_to_element inserts the action's structural value as
// the FIRST child of `el.items`.
fn apply_prepend_to_element(el cx.Element, action cx.ModifyAction) !cx.Node {
	mut new_items := []cx.Node{cap: el.items.len + 1}
	if vn := value_node_for_action(action) {
		new_items << vn
	}
	for it in el.items {
		new_items << it
	}
	return cx.Node(cx.Element{
		name:  el.name
		attrs: el.attrs
		items: new_items
		meta:  el.meta
		table: el.table
	})
}
