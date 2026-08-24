module code

// planar_membership.v — the six-point planar-fragment membership test
// (code.md §7.8, stream-2 ruling L95; spec/03-approved/core/planar_algebra.md).
//
// Planarity is CONSUMER-RELATIVE: a general [?for] outside the fragment is
// fully legal — only a planar consumer (plan-form normalization / plan
// address, identity-keyed caching, quoted store queries, incremental
// maintenance) applies this test, and non-membership there is the typed
// error cx-err:CXER0120 E_NOT_PLANAR whose message names the violated
// point — never a silent fallback (the CXER1709 refuse-to-lie posture).
//
// The six points, in refusal-priority order:
//   1. head ∈ {for, for-array, for-map}
//   2. clause vocabulary closed to {generator, where, =, order-by, group-by,
//      limit, take, drop} (+ the point-6 erased hints); take-while /
//      drop-while / fail-fast excluded
//   3. every generator source names its root: a canonical source-reference
//      call ([$store:source …] / [$journal:source …]), a nested planar
//      comprehension (recursive, inheriting the enclosing locals — the
//      correlated form), or a PURE expression over comprehension-local
//      bindings and literals; the ambient document (bare pattern-generators,
//      CXPath value sources, enclosing-scope references) and unbounded
//      generators ([$range N *]) are non-members
//   4. every predicate, key, binder expression, and yield body is pure under
//      the shipped §6.5.x classification, verbatim
//   5. no [?eval], no [?with-scope] anywhere in clause expressions, generator
//      sources, or yield bodies (refused BY NAME, in addition to purity)
//   6. $_position / $_last in the yield body refused (order-observers);
//      [par] / [lazy] / [ordered] accepted and ERASED by planar consumers
//
// Membership guarantees the properties the consumers rely on: the source set
// is exactly the source references in the text (authorize-before-execute),
// every source is versionable (cacheability), and the comprehension is
// deterministic given the sources' contents.

import cx

// planar_err_code is the E_NOT_PLANAR wire code (code.md §9.4, the
// for-comprehension band).
pub const planar_err_code = 'cx-err:CXER0120'

// The canonical source-reference call spellings (code.md §7.8 point 3;
// store.md §6.2, journal.md §3.3). Membership recognizes these canonical
// spellings — an aliased module prefix is not recognized (deterministic
// static recognition; the refusal message says what it saw).
const planar_source_ref_names = ['store:source', 'journal:source']

// PlanarRefusal is one membership refusal: the violated point (1–6) and a
// human-readable reason. The zero value is never a valid refusal.
pub struct PlanarRefusal {
pub:
	point  int
	reason string
}

// planar_refusal_err builds the typed E_NOT_PLANAR err VALUE for a refusal,
// carrying the §9.5.1 canonical message `comprehension is not planar:
// ‹reason›` with the violated point named.
pub fn planar_refusal_err(r PlanarRefusal) cx.Node {
	return mk_err(planar_err_code, 'comprehension is not planar: ${r.reason} (membership point ${r.point}, code.md §7.8)')
}

// planar_membership applies the six-point test to a program node. Returns
// `none` when the node IS a member of the planar fragment; otherwise the
// first refusal in point order. Consumers turn a refusal into the typed
// error via planar_refusal_err — never a silent fallback.
pub fn planar_membership(n cx.ProgramNode) ?PlanarRefusal {
	if n is cx.ProgramForComp {
		return planar_membership_comp(n, map[string]bool{})
	}
	if n is cx.Program {
		return planar_membership(n.body)
	}
	return PlanarRefusal{
		point:  1
		reason: 'not a [?for] / [?for-array] / [?for-map] comprehension'
	}
}

// planar_membership_comp runs points 2–6 over one comprehension. `inherited`
// carries the enclosing comprehension's locals when this comp appears as a
// nested (correlated) generator source.
fn planar_membership_comp(f cx.ProgramForComp, inherited map[string]bool) ?PlanarRefusal {
	// Point 1 is satisfied by the node kind: every ProgramForComp head is one
	// of for / for-array / for-map (the three outer forms).
	// Point 2 — closed clause vocabulary. take-while / drop-while are
	// order-observers; fail-fast is a parallel-execution observable.
	for c in f.clauses {
		match c.kind {
			.generator, .filter, .binding, .order_by, .group_by, .limit, .take, .drop {}
			.par, .lazy, .ordered {} // point 6: erased execution hints
			.takewhile {
				return PlanarRefusal{
					point:  2
					reason: '[take-while] is an order-observer outside the closed clause vocabulary'
				}
			}
			.dropwhile {
				return PlanarRefusal{
					point:  2
					reason: '[drop-while] is an order-observer outside the closed clause vocabulary'
				}
			}
			.fail_fast {
				return PlanarRefusal{
					point:  2
					reason: '[fail-fast] is a parallel-execution observable outside the closed clause vocabulary'
				}
			}
		}
	}
	// Clause-ordered walk: generator sources (point 3) see the locals bound
	// by EARLIER clauses only (the correlated-unnest form).
	mut locals := inherited.clone()
	for c in f.clauses {
		match c.kind {
			.generator {
				if src := c.source {
					if r := planar_generator_source(src, locals) {
						return r
					}
				} else {
					// a generator with NO source scans the implicit ambient
					// document — point 3, whatever the spelling. The bare
					// shortcut `[?for [user] …]` parses with the pattern in
					// SOURCE position (caught above), but its re-emission
					// `[?for [in [user]] …]` parses as a source-less
					// pattern-bind generator and reached execution before
					// this arm existed (the W6 quote-round-trip discovery).
					return PlanarRefusal{
						point:  3
						reason: 'a source-less generator scans the implicit ambient document — the source cannot name its root'
					}
				}
				if c.bind != '' && c.bind != '_' {
					locals[c.bind] = true
				}
				// A pattern-bind generator ([in [PAT] SRC]) captures names
				// inside the pattern.
				if pex := c.expr {
					if pex is cx.ProgramPattern {
						planar_pattern_binds(pex, mut locals)
					}
				}
			}
			.binding {
				if e := c.expr {
					if r := planar_body_expr(e, '[= …] binder') {
						return r
					}
				}
				if c.bind != '' && c.bind != '_' {
					locals[c.bind] = true
				}
			}
			.filter {
				if e := c.expr {
					if r := planar_body_expr(e, '[where] predicate') {
						return r
					}
				}
			}
			.order_by {
				if e := c.expr {
					if r := planar_body_expr(e, '[order-by] key') {
						return r
					}
				}
			}
			.group_by {
				if e := c.expr {
					if r := planar_body_expr(e, '[group-by] key') {
						return r
					}
				}
			}
			.limit, .take, .drop {
				// λ counts are clause expressions: the point-5 by-name scan,
				// the point-3 ambient scan, and — since the #770 ruling
				// (2026-08-10) — the point-4 purity enumeration all reach
				// them. A free-name count stays a member (a §7.9 plan
				// parameter).
				if e := c.expr {
					clause_name := match c.kind {
						.limit { 'limit' }
						.take { 'take' }
						else { 'drop' }
					}
					if r := planar_body_expr(e, '[${clause_name}] count') {
						return r
					}
				}
			}
			else {}
		}
	}
	// Yield body (and the yield-map VALUE — the ONE-walk lesson: both nodes).
	if r := planar_yield_body(f.yield) {
		return r
	}
	if yv := f.yield_value {
		if r := planar_yield_body(yv) {
			return r
		}
	}
	return none
}

// planar_generator_source applies point 3 (+ 4/5 on computed sources) to one
// generator source expression, given the locals bound by earlier clauses.
fn planar_generator_source(src cx.ProgramNode, locals map[string]bool) ?PlanarRefusal {
	if src is cx.ProgramPattern {
		return PlanarRefusal{
			point:  3
			reason: 'a bare pattern-generator scans the implicit ambient document — the source cannot name its root'
		}
	}
	if src is cx.ProgramPathExpr {
		return PlanarRefusal{
			point:  3
			reason: 'a CXPath source (`${planar_path_leading(src)}…`) reads the implicit ambient document — the source cannot name its root'
		}
	}
	if src is cx.ProgramCall {
		if src.name in planar_source_ref_names {
			// A canonical source reference. Its arguments (the handle, the
			// path/stream) necessarily arrive from enclosing scope — the
			// reference itself names the root.
			return none
		}
		if is_planar_open_end_range(src) {
			return PlanarRefusal{
				point:  3
				reason: 'an unbounded generator (`[\$range N *]`) has no finite source set'
			}
		}
	}
	if src is cx.ProgramForComp {
		// A nested planar comprehension — recursive membership, inheriting
		// the enclosing locals (the correlated form).
		return planar_membership_comp(src, locals)
	}
	// A computed source: must be free of [?eval]/[?with-scope], pure (an
	// impure call is an external root the source set cannot name), and rooted
	// exclusively in comprehension-local bindings and literals. The head
	// check runs FIRST so [?eval] gets its point-5 refusal rather than the
	// generic impure-directive one.
	if head := planar_find_head(src, ['eval', 'with-scope']) {
		return PlanarRefusal{
			point:  5
			reason: '[?${head}] inside a generator source'
		}
	}
	// #770: an ambient read NESTED in a computed source (the top-level
	// PathExpr form is refused above with its own spelling).
	if lead := planar_find_ambient_path(src) {
		return PlanarRefusal{
			point:  3
			reason: 'the generator source reads the ambient document (`${lead}…`) — a document dependency the source set cannot name (lift it into a source reference)'
		}
	}
	if node_calls_impure_builtin(src) {
		callee := planar_impure_name(src) or { 'an impure form' }
		return PlanarRefusal{
			point:  3
			reason: 'the generator source calls impure `${callee}` — an effectful source the source set cannot name'
		}
	}
	mut free := map[string]bool{}
	planar_free_bindings(src, map[string]bool{}, mut free)
	for name, _ in free {
		if name !in locals {
			return PlanarRefusal{
				point:  3
				reason: 'the generator source references `\$${name}` from enclosing scope — the source cannot name its root (use a source reference, a nested planar comprehension, or earlier-clause bindings)'
			}
		}
	}
	return none
}

// planar_body_expr applies points 5, 3, and 4 (in that order — so [?eval] /
// [?with-scope] get their by-name point-5 refusal, and an ambient read its
// specific point-3 refusal, rather than the generic impure-directive one) to
// a predicate / key / binder / λ-count / yield expression.
// The purity decision is node_calls_impure_builtin — the shipped §6.5.x
// classification over the FULL node walk (impure builtins AND impure
// directive heads, nested comprehensions via the ONE walk); the callee name
// is best-effort message detail. The ambient scan is the #770 ruling
// (2026-08-10): the point-3 exclusion is not source-slot-scoped — a
// document-context CXPath read anywhere is a dependency the source set
// cannot name.
fn planar_body_expr(e cx.ProgramNode, what string) ?PlanarRefusal {
	if head := planar_find_head(e, ['eval', 'with-scope']) {
		return PlanarRefusal{
			point:  5
			reason: '[?${head}] inside the ${what}'
		}
	}
	if lead := planar_find_ambient_path(e) {
		return PlanarRefusal{
			point:  3
			reason: 'the ${what} reads the ambient document (`${lead}…`) — a document dependency the source set cannot name (lift it into a source reference)'
		}
	}
	if node_calls_impure_builtin(e) {
		callee := planar_impure_name(e) or { 'an impure form' }
		return PlanarRefusal{
			point:  4
			reason: 'the ${what} calls impure `${callee}` — every predicate, key, and yield must be pure (§6.5.x)'
		}
	}
	return none
}

// planar_find_ambient_path walks an expression for a ProgramPathExpr — the
// document-context CXPath form (a binding-rooted path is a ProgramBinding
// with path steps, a different node kind) — and returns its leading spelling.
// #770 (RULED (a) 2026-08-10): ambient reads are non-members in EVERY slot.
fn planar_find_ambient_path(n cx.ProgramNode) ?string {
	match n {
		cx.ProgramPathExpr {
			return planar_path_leading(n)
		}
		cx.ProgramDirective {
			for slot in n.slots {
				if h := planar_find_ambient_path(slot.value) {
					return h
				}
			}
		}
		cx.ProgramCall {
			for arg in n.args {
				if h := planar_find_ambient_path(arg) {
					return h
				}
			}
		}
		cx.ProgramLiteral {
			for child in n.items {
				if h := planar_find_ambient_path(child) {
					return h
				}
			}
			for slot in n.slots {
				if h := planar_find_ambient_path(slot.value) {
					return h
				}
			}
			for attr in n.attrs {
				if h := planar_find_ambient_path(attr.value) {
					return h
				}
			}
		}
		cx.ProgramForComp {
			for item in cx.for_comp_children(n) {
				if h := planar_find_ambient_path(item.node) {
					return h
				}
			}
		}
		cx.ProgramPattern {
			for child in n.body {
				if h := planar_find_ambient_path(child) {
					return h
				}
			}
			for attr in n.attrs {
				if v := attr.value {
					if h := planar_find_ambient_path(v) {
						return h
					}
				}
			}
		}
		cx.ProgramSliceAccess {
			for ax in n.axes {
				if s := ax.start {
					if h := planar_find_ambient_path(s) {
						return h
					}
				}
				if s := ax.stop {
					if h := planar_find_ambient_path(s) {
						return h
					}
				}
				if s := ax.step {
					if h := planar_find_ambient_path(s) {
						return h
					}
				}
			}
		}
		cx.Program {
			return planar_find_ambient_path(n.body)
		}
		else {}
	}
	return none
}

// planar_impure_name finds the NAME of the first impure callee / impure
// directive head in an expression — full node-kind coverage (the decision is
// node_calls_impure_builtin; this recovers the name for the refusal
// message, which program_node_impure_callee cannot do through directive /
// literal nodes).
fn planar_impure_name(n cx.ProgramNode) ?string {
	impure_dirs := impure_directive_table()
	return planar_impure_name_walk(n, impure_dirs)
}

fn planar_impure_name_walk(n cx.ProgramNode, impure_dirs map[string]bool) ?string {
	match n {
		cx.ProgramCall {
			if call_name_is_impure_builtin(n.name) {
				return n.name
			}
			for arg in n.args {
				if h := planar_impure_name_walk(arg, impure_dirs) {
					return h
				}
			}
		}
		cx.ProgramDirective {
			if ('?' + n.name) in impure_dirs {
				return '?${n.name}'
			}
			for slot in n.slots {
				if h := planar_impure_name_walk(slot.value, impure_dirs) {
					return h
				}
			}
		}
		cx.ProgramLiteral {
			for child in n.items {
				if h := planar_impure_name_walk(child, impure_dirs) {
					return h
				}
			}
			for slot in n.slots {
				if h := planar_impure_name_walk(slot.value, impure_dirs) {
					return h
				}
			}
			for attr in n.attrs {
				if h := planar_impure_name_walk(attr.value, impure_dirs) {
					return h
				}
			}
		}
		cx.ProgramForComp {
			for item in cx.for_comp_children(n) {
				if h := planar_impure_name_walk(item.node, impure_dirs) {
					return h
				}
			}
		}
		cx.ProgramPattern {
			for child in n.body {
				if h := planar_impure_name_walk(child, impure_dirs) {
					return h
				}
			}
		}
		cx.Program {
			return planar_impure_name_walk(n.body, impure_dirs)
		}
		else {}
	}
	return none
}

// planar_yield_body applies points 4, 5, and 6 to the yield body.
fn planar_yield_body(y cx.ProgramNode) ?PlanarRefusal {
	if r := planar_body_expr(y, 'yield body') {
		return r
	}
	if name := planar_find_reserved_binding(y) {
		return PlanarRefusal{
			point:  6
			reason: '`\$${name}` in the yield body observes the emission order — order-observers are outside the fragment'
		}
	}
	return none
}

// planar_path_leading spells a PathExpr's anchor for refusal messages.
fn planar_path_leading(p cx.ProgramPathExpr) string {
	return match p.leading {
		.descendant { '//' }
		.absolute { '/' }
		.relative { '' }
	}
}

// is_planar_open_end_range detects `range(start, *, step?)` — the parser
// substitutes the `_open_end_` atom literal for `*` (the CXLS006 shape).
fn is_planar_open_end_range(n cx.ProgramCall) bool {
	if n.name != 'range' || n.args.len < 2 {
		return false
	}
	end_arg := n.args[1]
	if end_arg is cx.ProgramLiteral {
		return end_arg.kind == .atom_lit && end_arg.str_val == '_open_end_'
	}
	return false
}

// planar_pattern_binds collects the names a pattern CAPTURES (head `$bind`,
// body bindings incl. rest-captures, nested patterns) into `out`.
fn planar_pattern_binds(p cx.ProgramPattern, mut out map[string]bool) {
	if p.head.bind != '' && p.head.bind != '_' {
		out[p.head.bind] = true
	}
	for child in p.body {
		match child {
			cx.ProgramBinding {
				// In pattern position a binding IS a bind site.
				if child.name != '' && child.name != '_' {
					out[child.name] = true
				}
			}
			cx.ProgramPattern {
				planar_pattern_binds(child, mut out)
			}
			else {}
		}
	}
}

// planar_find_head walks an expression for a ProgramDirective whose name is
// in `names`, returning the first hit. Covers every child-bearing node kind
// (the walk_impure coverage) plus pattern-attr values.
fn planar_find_head(n cx.ProgramNode, names []string) ?string {
	match n {
		cx.ProgramDirective {
			if n.name in names {
				return n.name
			}
			for slot in n.slots {
				if h := planar_find_head(slot.value, names) {
					return h
				}
			}
		}
		cx.ProgramCall {
			for arg in n.args {
				if h := planar_find_head(arg, names) {
					return h
				}
			}
		}
		cx.ProgramLiteral {
			for child in n.items {
				if h := planar_find_head(child, names) {
					return h
				}
			}
			for slot in n.slots {
				if h := planar_find_head(slot.value, names) {
					return h
				}
			}
			for attr in n.attrs {
				if h := planar_find_head(attr.value, names) {
					return h
				}
			}
		}
		cx.ProgramForComp {
			for item in cx.for_comp_children(n) {
				if h := planar_find_head(item.node, names) {
					return h
				}
			}
		}
		cx.ProgramPattern {
			for child in n.body {
				if h := planar_find_head(child, names) {
					return h
				}
			}
			for attr in n.attrs {
				if v := attr.value {
					if h := planar_find_head(v, names) {
						return h
					}
				}
			}
		}
		cx.ProgramSliceAccess {
			for ax in n.axes {
				if s := ax.start {
					if h := planar_find_head(s, names) {
						return h
					}
				}
				if s := ax.stop {
					if h := planar_find_head(s, names) {
						return h
					}
				}
				if s := ax.step {
					if h := planar_find_head(s, names) {
						return h
					}
				}
			}
		}
		cx.Program {
			return planar_find_head(n.body, names)
		}
		else {}
	}
	return none
}

// planar_find_reserved_binding walks an expression for a `$_position` /
// `$_last` binding READ (the order-observers). Path-predicate-internal
// positions ([2], [$_position = N] inside a step predicate) are DOCUMENT
// order — value-derived and relationally sound — and live in PredicateExpr
// structures, not ProgramBinding nodes, so this scan never flags them.
fn planar_find_reserved_binding(n cx.ProgramNode) ?string {
	match n {
		cx.ProgramBinding {
			if n.name in ['_position', '_last'] {
				return n.name
			}
		}
		cx.ProgramDirective {
			for slot in n.slots {
				if h := planar_find_reserved_binding(slot.value) {
					return h
				}
			}
		}
		cx.ProgramCall {
			for arg in n.args {
				if h := planar_find_reserved_binding(arg) {
					return h
				}
			}
		}
		cx.ProgramLiteral {
			for child in n.items {
				if h := planar_find_reserved_binding(child) {
					return h
				}
			}
			for slot in n.slots {
				if h := planar_find_reserved_binding(slot.value) {
					return h
				}
			}
			for attr in n.attrs {
				if h := planar_find_reserved_binding(attr.value) {
					return h
				}
			}
		}
		cx.ProgramForComp {
			for item in cx.for_comp_children(n) {
				if h := planar_find_reserved_binding(item.node) {
					return h
				}
			}
		}
		cx.ProgramPattern {
			for child in n.body {
				if h := planar_find_reserved_binding(child) {
					return h
				}
			}
		}
		cx.ProgramSliceAccess {
			if h := planar_find_reserved_binding(cx.ProgramNode(n.binding)) {
				return h
			}
			for ax in n.axes {
				if s := ax.start {
					if h := planar_find_reserved_binding(s) {
						return h
					}
				}
				if s := ax.stop {
					if h := planar_find_reserved_binding(s) {
						return h
					}
				}
				if s := ax.step {
					if h := planar_find_reserved_binding(s) {
						return h
					}
				}
			}
		}
		cx.Program {
			return planar_find_reserved_binding(n.body)
		}
		else {}
	}
	return none
}

// planar_free_bindings collects the names an expression READS that are not
// shadowed: ProgramBinding names in expression position (a `$o/line`
// correlated path is a read of `o`). `shadow` carries names bound INSIDE the
// expression (nested comprehension clauses, pattern captures); reserved
// names and `$_` never count as free.
fn planar_free_bindings(n cx.ProgramNode, shadow map[string]bool, mut out map[string]bool) {
	match n {
		cx.ProgramBinding {
			if n.name != '' && n.name != '_' && n.name !in ['_position', '_last', 'key', 'count', 'group']
				&& n.name !in shadow {
				out[n.name] = true
			}
		}
		cx.ProgramDirective {
			for slot in n.slots {
				planar_free_bindings(slot.value, shadow, mut out)
			}
		}
		cx.ProgramCall {
			for arg in n.args {
				planar_free_bindings(arg, shadow, mut out)
			}
		}
		cx.ProgramLiteral {
			for child in n.items {
				planar_free_bindings(child, shadow, mut out)
			}
			for slot in n.slots {
				planar_free_bindings(slot.value, shadow, mut out)
			}
			for attr in n.attrs {
				planar_free_bindings(attr.value, shadow, mut out)
			}
		}
		cx.ProgramForComp {
			// A nested comprehension shadows its own clause binds (and pattern
			// captures) for every child node — an un-ordered approximation: a
			// forward reference would fail at eval anyway, and membership only
			// needs bound-vs-ambient.
			mut inner := shadow.clone()
			for c in n.clauses {
				if c.bind != '' && c.bind != '_' {
					inner[c.bind] = true
				}
				if pex := c.expr {
					if c.kind == .generator {
						if pex is cx.ProgramPattern {
							planar_pattern_binds(pex, mut inner)
						}
					}
				}
			}
			for item in cx.for_comp_children(n) {
				planar_free_bindings(item.node, inner, mut out)
			}
		}
		cx.ProgramPattern {
			// Pattern-position bindings are BIND sites, not reads; attr
			// equality VALUES are reads.
			for attr in n.attrs {
				if v := attr.value {
					planar_free_bindings(v, shadow, mut out)
				}
			}
		}
		cx.ProgramSliceAccess {
			planar_free_bindings(cx.ProgramNode(n.binding), shadow, mut out)
			for ax in n.axes {
				if s := ax.start {
					planar_free_bindings(s, shadow, mut out)
				}
				if s := ax.stop {
					planar_free_bindings(s, shadow, mut out)
				}
				if s := ax.step {
					planar_free_bindings(s, shadow, mut out)
				}
			}
		}
		cx.Program {
			planar_free_bindings(n.body, shadow, mut out)
		}
		else {}
	}
}
