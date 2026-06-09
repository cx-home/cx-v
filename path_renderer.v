module cx

// path_renderer.v — PathNode → canonical text-CX emitter (Phase 2.9).
//
// Implements the canonical-form rules in `spec/canonical.md §2.12`
// (ratified Phase 1.9) for the PathNode AST landed in Phase 2.1
// (`vcx/cx/path_node.v`). The output is the terse-preferred surface
// per §2.12.1 and is byte-identical for any two PathNodes that
// compare equal under `PathNode.eq()` (the §2.12.7 identity round-
// trip guarantee).
//
// Emit rules summary (full spec at `spec/canonical.md §2.12`):
//   §2.12.2 Form discriminator:
//     - absolute   → leading `/`
//     - descendant → leading `//`
//     - relative   → no leading token
//     - binding    → `$<name>/` lead (the `binding` field carries
//                    the bound identifier without `$`)
//   §2.12.3 Axis:
//     - child (default)         → OMITTED on output
//     - attribute               → `@` sigil prefixed on the node-test
//     - 10 other axes           → `axis-name::` verbatim prefix
//   §2.12.4 Node-test: bare names / wildcards / kind-tests verbatim.
//   §2.12.5 Predicates: `[BODY]` per predicate; atomic-template
//     terse forms preferred when the PredicateExpr AST matches one
// of the templates. The Phase 2.1 PathPredicate
//     struct carries the predicate body as a verbatim source
//     string only (the structural ProgramExpr graft is Phase 2.4);
//     this renderer therefore emits the verbatim source. The
//     atomic-template recognition pass grafts in at Phase 2.4 when
//     PathPredicate gains an `expr ?ProgramExpr` field.
//   §2.12.6 Whitespace: zero spaces between any two tokens of the
//     PathNode emit.
//   §2.12.8 example 3 — `descendant-or-self::node()/child::user`
//     collapses back to the `//user` two-step shorthand: detected
//     and rendered as `//` lead followed by the second step.
//
// Cross-references:
//   - spec/canonical.md §2.12 (authoritative; this file's contract).
//   - vcx/cx/path_node.v (PathNode + PathStep + PathPredicate).
//   - vcx/cx/path_parser.v (round-trip pair: `parse_path` accepts
//     every string `render_path` produces for the parser-supported
//     subset of inputs).

// ── Public entry ──────────────────────────────────────────────────────────────

// render_path emits the canonical text-CX surface for a PathNode
// per `spec/canonical.md §2.12`. The output is byte-identical for
// any two PathNodes that compare equal via `.eq()` (the §2.12.7
// identity round-trip guarantee).
//
// The output round-trips through `parse_path` for the parser-
// supported subset of inputs (Phase 2.3-partial: single step, bare
// name, optional single predicate). Inputs whose AST shape exercises
// deferred parser features (multi-step / multi-predicate / kind-test
// / wildcard / prefixed names) still render correctly; the parser
// catches up in later Phase 2.3 sub-phases.
pub fn render_path(node PathNode) string {
	mut out := []u8{}

	// Step list — possibly with the `descendant-or-self::node()` /
	// `child::*` collapse per §2.12.8 example 3.
	mut steps := node.steps.clone()
	mut lead := render_form_lead(node)

	// Collapse `[descendant-or-self::node(), child::X]` → `//X`,
	// adjusting the lead. Only applies when the original form was
	// `absolute`; the desugaring of `//X` is exactly
	// `/descendant-or-self::node()/child::X` (absolute). The collapse
	// upgrades that absolute-with-shorthand-prefix pair to the terse
	// descendant lead.
	if node.form == .absolute && steps.len >= 2
		&& steps[0].axis == .descendant_or_self
		&& steps[0].node_test == 'node()'
		&& steps[0].predicates.len == 0 {
		// Shift the descendant lead in; drop the first step.
		lead = '//'
		steps = steps[1..].clone()
	}

	out << lead.bytes()

	// Emit each step, joined by `/` (§2.12.6).
	for i, s in steps {
		if i > 0 {
			out << u8(`/`)
		}
		out << render_step(s).bytes()
	}

	// Trailing top-level predicates (rare; §2.12.5).
	for pred in node.predicates {
		out << u8(`[`)
		out << pred.source.bytes()
		out << u8(`]`)
	}

	return out.bytestr()
}

// ── Form lead ─────────────────────────────────────────────────────────────────

// render_form_lead returns the leading-token bytes for `node.form`
// per §2.12.2. The four discriminator values are exhaustive; an
// unrecognised `form` would have failed earlier at PathNode
// construction time.
fn render_form_lead(node PathNode) string {
	return match node.form {
		.absolute   { '/' }
		.descendant { '//' }
		.relative   { '' }
		.binding    {
			// `$<name>/` — the trailing `/` is the inter-step separator
			// that introduces the first step (per §2.12.2 binding row).
			name := node.binding or { '' }
			'\$${name}/'
		}
	}
}

// ── Step ──────────────────────────────────────────────────────────────────────

// render_step emits one PathStep: the axis prefix (per §2.12.3) +
// the node-test (per §2.12.4) + each predicate (per §2.12.5). No
// whitespace anywhere (§2.12.6).
pub fn render_step(step PathStep) string {
	mut out := []u8{}
	out << render_node_test(step.axis, step.node_test).bytes()
	// `:bind NAME` peer-modifier (+ grammar [160]) — emit
	// between NodeTest and Predicates. Whitespace-free per §2.12.6.
	if bn := step.binding {
		out << ':bind '.bytes()
		out << bn.bytes()
	}
	for pred in step.predicates {
		out << render_predicate(pred).bytes()
	}
	return out.bytestr()
}

// render_node_test combines the axis prefix and the node-test name
// into one token sequence per §2.12.3 + §2.12.4:
//
//   axis=child         → `<node_test>` (axis omitted)
//   axis=attribute     → `@<node_test>` (terse sigil)
//   any other axis     → `<axis-name>::<node_test>`
//
// The node-test value is emitted verbatim — bare names, wildcards
// (`*`, `*:Local`, `Prefix:*`), and kind-tests (`node()`, `text()`,
// `element()`, `attribute()`) all retain their source spelling.
pub fn render_node_test(axis PathAxis, node_test string) string {
	return match axis {
		.child     { node_test }
		.attribute { '@${node_test}' }
		else       { '${path_axis_name(axis)}::${node_test}' }
	}
}

// ── Predicate ─────────────────────────────────────────────────────────────────

// render_predicate emits `[BODY]` for one PathPredicate per §2.12.5.
//
// TODO(Phase 2.4): graft atomic-template recognition once predicate
// body becomes a structural ProgramExpr. At present `PathPredicate`
// carries the body as a verbatim `source string` (per the Phase 2.1
// contract — see `path_node.v` PathPredicate doc) and we faithfully
// echo that source. The atomic-template table
// AttrTest (`@name`), AttrCompare (`@name = V`), IntPos (`N`),
// BareFn (`fn(...)`), CountStar (`count(*) > N`) — will be matched
// against the structural AST shape (NOT the source string) and the
// terse form emitted in preference to the general form. Until then,
// the verbatim-source emit is conservatively correct: it preserves
// byte-identity for §2.12.7 because two PathPredicates with equal
// `source` strings always compare equal under `path_predicates_eq`
// (`vcx/cx/path_node.v`), and conversely two that compare equal
// here always have the same `source`. The pre-graft renderer is
// therefore a sound proper-subset of the post-graft renderer's
// behaviour — every byte-identity claim made today remains true
// after the graft; only the strictly-stronger terse-output cases
// become possible.
pub fn render_predicate(pred PathPredicate) string {
	return '[${pred.source}]'
}
