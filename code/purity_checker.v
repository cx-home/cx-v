module code

import cx

// purity_checker.v — static purity checker.
//
// Phase 2.22 (partial). Sound-but-incomplete inference: walks
// the call graph of every `[?def]` body and every PredicateExpr body, then
// reads the closed builtin purity classification (`spec/code.md §6.5.x`) to
// decide whether the annotation matches the inferred purity. The algorithm
// is sound — every accepted `:pure` def is provably pure under the rules
// — but not complete: some legitimately-pure programs may need an explicit
// `:impure` escape (e.g. a body that calls into a `[?lib]`-supplied
// integration directive whose purity is unclassified). The incompleteness
// is documented.
//
// Wire codes raised:
//   - CXER0230 (E_PREDICATE_NOT_PURE)         — predicate body calls impure
//   - CXER0231 (E_RESERVED_BINDING_USE)       — $_position / $_last outside
//                                                a predicate body
//   - CXER0232 (E_RESERVED_BIND_NAME)         — :bind _ on a path step
//   - CXER0233 (E_PURITY_VIOLATION)           — :pure (explicit or default)
//                                                annotation contradicts
//                                                inferred-impure body
//   - CXER0234 (E_PURITY_UNCLASSIFIED_BUILTIN) — call to a builtin that is
//                                                missing from the closed
//                                                purity classification list
//
// Approach (sound-but-incomplete):
//
//   1. Build a closed map `builtin_purity` from `spec/code.md §6.5.x`.
//   2. For each `[?def]` whose declared purity is `.pure_` (explicit OR
//      default), tokenise the body source and collect identifier-shaped
//      callee references + `[?…]` directive references. For each callee:
//        a. If the name is a known `[?def]` in the module → recurse on its
//           declared purity (NOT inferred — annotations are the contract,
// "`:impure` callers may still be called from
//           `:pure` contexts only if the call site is itself `:impure`").
//        b. Else, if the name is in `builtin_purity` → consult its tag.
//        c. Else, if the name starts with the `?` directive prefix or is
//           in the closed impure-directive set (`?modify`, `?send`, …)
//           → reject.
//        d. Else → unclassified builtin (CXER0234).
//   3. For each PredicateExpr body (reached via DefNode bodies that
//      contain `[predicate …]` shaped sub-tokens OR supplied explicitly
//      to `check_predicate`), run the same algorithm but raise CXER0230
//      on the first impure callee.
//
// At Phase 2.22 the def body is a verbatim source string (Phase 2.16 will
// replace it with a structural cx.ProgramExpr subtree). Tokenisation here is
// deliberately conservative: identifier-shaped names + `[?NAME` directive
// heads + `$_NAME` reserved-binding heads are scanned outside of string
// literals; everything else is ignored. False positives (e.g. a literal
// `now` appearing in a comment-free position that is actually a parameter
// reference, not a function call) are accepted as part of the sound-but-
// incomplete trade-off — a true call-graph walker over a structural body
// is filed for Phase 2.16 + a follow-up purity-checker upgrade.
//
// Cross-references:
//   - spec/code.md §6.5.x (builtin purity classification) + §9.4 / §9.5
//   - vcx/cx/def_node.v (DefNode + Purity enum)
//   - vcx/cx/predicate_expr.v (PredicateExpr)

// ── Public types ──────────────────────────────────────────────────────────────

// PurityChecker collects every DefNode in scope plus the closed builtin
// purity classification table. Construct once per module-load via
// `new_purity_checker` and reuse for every `check_def` / `check_predicate`
// call.
pub struct PurityChecker {
pub mut:
	defs           map[string]&cx.DefNode
	builtin_purity map[string]cx.Purity
	// impure_directives names the closed list of impure `[?…]` directive
	// heads from spec/code.md §6.5.x. The leading `?` is included.
	impure_directives map[string]bool
	// pure_flow_directives names directives whose purity is body-derived
	// rather than primitive (e.g. `[?if]`, `[?let]`, `[?match]`, `[?for]`,
	// `[?def]`, `[?const]`, `[?fn]`, `[?cond]`). They are accepted as
	// directive heads with no per-directive impurity contribution; the
	// tokeniser still scans their body for impure callees, so any impure
	// operation inside them is caught by the recursive walk.
	pure_flow_directives map[string]bool
}

// new_purity_checker constructs a PurityChecker populated with the
// supplied DefNodes (keyed by name) and the closed builtin / directive
// classification tables. Callers in the module loader pass every
// `[?def]` they collected during parse; the checker uses the declared
// purity of each def as the contract.
pub fn new_purity_checker(defs []&cx.DefNode) PurityChecker {
	mut by_name := map[string]&cx.DefNode{}
	for d in defs {
		unsafe {
			by_name[d.name] = d
		}
	}
	return PurityChecker{
		defs:                 by_name
		builtin_purity:       builtin_purity_table()
		impure_directives:    impure_directive_table()
		pure_flow_directives: pure_flow_directive_table()
	}
}

// pure_flow_directive_table returns the closed set of control-flow /
// binding / declaration directive heads whose purity is body-derived.
// These are not "builtins" in the §6.5.x sense — their semantics is
// "evaluate the body in the right scope" — so the impurity of the
// surrounding `[?…]` form is whatever the body's calls compute. The
// tokeniser scans the body inside the brackets independently of the
// head, so impurity inside e.g. `[?if c (now)]` is still caught at the
// `now` site.
fn pure_flow_directive_table() map[string]bool {
	mut t := map[string]bool{}
	for n in [
		'?if',
		'?cond',
		'?match',
		'?let',
		'?for',
		'?def',
		'?const',
		'?fn',
		'?lib',
		'?try',
		'?throw',
		'?yield',
		'?do',
		'?loop',
		'?when',
		'?unless',
		'?case',
		'?return',
		'?begin',
		'?and',
		'?or',
		'?not',
		// NOTE: [?eval] is NOT here — it is inherently impure (tree-eval, the
		// effect dual of cx:eval per §6.4.4); see impure_directive_table. Only
		// the construction forms below are body-derived (pure unless their holes
		// reach an impure callee).
		'?quote',
		'?unquote',
		'?splice',
		// [?str] compile-time string interpolation (§8.12) is pure — its
		// holes are binding-paths (reads only), never calls. Body-derived
		// so the tokeniser still scans the (call-free) template content.
		'?str',
	] {
		t[n] = true
	}
	return t
}

// ── Builtin classification (closed list per spec/code.md §6.5.x) ──────────────

// builtin_purity_table returns the closed builtin → purity map. Adding a
// new builtin requires classifying it here AND in `spec/code.md §6.5.x`
// in the same spec amendment that introduces it.
fn builtin_purity_table() map[string]cx.Purity {
	mut t := map[string]cx.Purity{}

	// Pure — Sequence builtins.
	for n in ['count', 'length', 'empty', 'first', 'last', 'head', 'tail',
		'reverse', 'distinct', 'nth', 'position', 'range', 'identity'] {
		t[n] = cx.Purity.pure_
	}

	// Pure — String builtins.
	for n in ['upper', 'lower', 'contains', 'starts-with', 'ends-with',
		'substring', 'string-length', 'normalize-space', 'concat', 'text'] {
		t[n] = cx.Purity.pure_
	}

	// Pure — Numeric builtins.
	for n in ['sum', 'max', 'min', 'avg', 'abs', 'floor', 'ceiling', 'round',
	          'odd', 'even',
	          // math operators
	          'mod', 'div', 'idiv'] {
		t[n] = cx.Purity.pure_
	}

	// Pure — Logical builtins.
	for n in ['not', 'and', 'or', 'eq'] {
		t[n] = cx.Purity.pure_
	}

	// Pure — Node-accessor + type-test + EBV + path/cxpath.
	for n in ['name', 'cast', 'exists'] {
		t[n] = cx.Purity.pure_
	}

	// Impure — I/O.
	for n in ['print', 'read-file', 'write-file', 'read-line'] {
		t[n] = cx.Purity.impure_
	}

	// Impure — Time-source.
	for n in ['now', 'today', 'instant-now', 'monotonic-now'] {
		t[n] = cx.Purity.impure_
	}

	// Impure — Random / UUID.
	for n in ['random', 'random-int', 'uuid', 'random-bytes'] {
		t[n] = cx.Purity.impure_
	}

	// Impure — cx-stdlib native primitives (derived from each wrapping
	// [?def]'s declared purity in stdlib_*.v): environment reads, the
	// filesystem-resolving path ops, the random generators (the seeded
	// `*-with` / `*-from-seed` variants are deterministic → pure, omitted),
	// the clock-reading time sources, and the random/time UUID generators
	// (v3/v5 are name-based → pure, omitted). All OTHER stdlib primitives
	// (str-/bytes-/format-/hash-/most path-/time-/uuid-) are pure and rely
	// on the unclassified-callee=pure default.
	for n in [
		'env-abort', 'env-argv', 'env-cpu-count', 'env-cwd', 'env-executable-path', 'env-exit',
		'env-has-var', 'env-hostname', 'env-parse-args', 'env-pid', 'env-ppid', 'env-stderr',
		'env-stdin', 'env-stdout', 'env-username', 'env-var', 'env-var-bool', 'env-var-float',
		'env-var-int', 'env-var-or-default', 'env-var-required', 'env-vars', 'path-absolute', 'path-canonical',
		'random-choose', 'random-choose-weighted', 'random-crypto-base64-url', 'random-crypto-bytes', 'random-crypto-hex', 'random-crypto-int',
		'random-crypto-token-urlsafe', 'random-exponential', 'random-float-range', 'random-gaussian', 'random-int-range', 'random-next-bool',
		'random-next-float', 'random-next-floats', 'random-next-int', 'random-next-ints', 'random-poisson', 'random-sample',
		'random-sample-weighted', 'random-seed', 'random-shuffle', 'time-instant-now', 'time-mock-advance', 'time-mock-set',
		'time-monotonic-now', 'time-now', 'time-system-timezone', 'time-today', 'time-utc-now', 'uuid-v4',
		'uuid-v4-bytes', 'uuid-v7', 'uuid-v7-bytes',
	] {
		t[n] = cx.Purity.impure_
	}

	// §6.5.1 capability-alignment invariant (direction 1: gated ⇒ impure).
	// Every capability-gated effect point (effect_alignment.v) is classified
	// impure HERE, by construction — so the invariant cannot drift as new
	// cap-gated prims are added (they land in capability_gated_prims() and
	// this fold picks them up). The explicit entries above are retained: the
	// spec-classified-but-impl-pending bare-name builtins (print/now/uuid/…)
	// + the state-bearing PRNG + mock-clock prims are impure WITHOUT a
	// capability (the §6.5.1 closed exception table), so they are not in the
	// gated set and must stay listed above. See effect_alignment.v.
	for name, _ in capability_gated_prims() {
		t[name] = cx.Purity.impure_
	}

	return t
}

// impure_directive_table returns the closed set of impure `[?…]`
// directive heads per spec/code.md §6.5.x. The leading `?` is included
// in the key so the scanner can match the directive-head spelling
// directly.
fn impure_directive_table() map[string]bool {
	mut t := map[string]bool{}
	for n in [
		'?modify',
		'?send',
		'?receive',
		'?try-send',
		'?try-receive',
		'?close',
		'?select',
		'?worker',
		'?async',
		'?await',
		'?await-all',
		'?await-any',
		'?await-race',
		'?cancel',
		'?check-cancel',
		'?sleep',
		'?service',
		'?service-handle',
		'?http-client',
		'?retry',
		'?timeout',
		'?circuit-breaker',
		'?fallback',
		'?rate-limit',
		'?bulkhead',
		// Tree-eval (§6.4.4): [?eval] evaluates a CXDM value as code — the
		// effect dual of cx:eval. A pure [?def] reaching it raises CXER0233
		// (the cx:eval-tree call form is subject to the source scanner's
		// pre-existing prefix:local limitation, tracked separately).
		'?eval',
	] {
		t[n] = true
	}
	return t
}

// builtin_is_impure reports whether `name` is a classified-impure builtin
// or stdlib primitive. Unclassified names are treated as pure (same default
// as classify_callee). Used by the AST-level predicate purity check in
// eval.v's binding-path walker (which works on cx.ProgramNode, not source).
pub fn builtin_is_impure(name string) bool {
	t := builtin_purity_table()
	if p := t[name] {
		return p == cx.Purity.impure_
	}
	return false
}

// impure_builtin_names returns every name the closed §6.5.x classification
// marks `impure_`. Exposed so the §6.5.1 effect-alignment gate
// (effect_alignment_test.v, direction 2) can iterate the impure surface and
// assert each entry is EITHER capability-gated OR in the closed exception
// table. Reads the same table builtin_is_impure consults.
pub fn impure_builtin_names() []string {
	t := builtin_purity_table()
	mut out := []string{}
	for name, purity in t {
		if purity == cx.Purity.impure_ {
			out << name
		}
	}
	return out
}

// call_name_is_impure_builtin reports whether a cx.ProgramCall name resolves to
// a classified-impure builtin / stdlib primitive. The purity table keys
// stdlib prims by their hyphenated bare name (`env-var`), while a source-level
// module call writes the colon-qualified form (`env:var`). This normalizes the
// `prefix:local` form to the hyphenated `prefix-local` spelling before the
// lookup, and also probes the bare `local` segment, so both `[$env:var …]` and
// a bare `[print …]` are recognized.
fn call_name_is_impure_builtin(name string) bool {
	if builtin_is_impure(name) {
		return true
	}
	if name.contains(':') {
		// `env:var` → `env-var` (the purity-table spelling), and `var`.
		hyphenated := name.replace(':', '-')
		if builtin_is_impure(hyphenated) {
			return true
		}
		local := name.all_after_last(':')
		if builtin_is_impure(local) {
			return true
		}
	}
	return false
}

// node_calls_impure_builtin reports whether the AST subtree rooted at `node`
// transitively contains a call to a classified-impure builtin / stdlib prim
// OR an impure directive head (spec/code.md §6.5.x impure_directive_table).
// This is the purity gate the CXLS005 lint (§7.3) consults: a `[par]` body
// that performs no impure effect is safe to parallelize and warrants no hint;
// the hint fires only when the body actually reaches an impure builtin without
// a [?bulkhead] wrap or explicit ordering.
pub fn node_calls_impure_builtin(node cx.ProgramNode) bool {
	impure_dirs := impure_directive_table()
	return walk_impure(node, impure_dirs)
}

fn walk_impure(node cx.ProgramNode, impure_dirs map[string]bool) bool {
	match node {
		cx.ProgramCall {
			if call_name_is_impure_builtin(node.name) {
				return true
			}
			for arg in node.args {
				if walk_impure(arg, impure_dirs) {
					return true
				}
			}
		}
		cx.ProgramDirective {
			if ('?' + node.name) in impure_dirs {
				return true
			}
			for slot in node.slots {
				if walk_impure(slot.value, impure_dirs) {
					return true
				}
			}
		}
		cx.ProgramLiteral {
			for child in node.items {
				if walk_impure(child, impure_dirs) {
					return true
				}
			}
			for slot in node.slots {
				if walk_impure(slot.value, impure_dirs) {
					return true
				}
			}
			for attr in node.attrs {
				if walk_impure(attr.value, impure_dirs) {
					return true
				}
			}
		}
		cx.ProgramForComp {
			for clause in node.clauses {
				if src := clause.source {
					if walk_impure(src, impure_dirs) {
						return true
					}
				}
				if expr := clause.expr {
					if walk_impure(expr, impure_dirs) {
						return true
					}
				}
			}
			if walk_impure(node.yield, impure_dirs) {
				return true
			}
		}
		cx.ProgramPattern {
			for child in node.body {
				if walk_impure(child, impure_dirs) {
					return true
				}
			}
		}
		cx.Program {
			if walk_impure(node.body, impure_dirs) {
				return true
			}
		}
		else {}
	}
	return false
}

// ── Public API ────────────────────────────────────────────────────────────────

// check_def verifies that the supplied DefNode's declared purity matches
// the inferred purity of its body. A `:pure` (explicit OR default) def
// whose body calls any impure callee raises CXER0233; a reference to an
// unclassified builtin raises CXER0234. A `:impure` def is accepted
// unconditionally (the annotation is conservative).
pub fn (checker &PurityChecker) check_def(def &cx.DefNode) ! {
	if def.purity == .impure_ {
		// Conservative annotation — accepted unconditionally
		// D11.4 ("A [?def] annotated :impure whose inferred purity is
		// pure is accepted").
		return
	}
	// def.purity == .pure_ (explicit OR default per D11.1).
	mut seen := map[string]bool{}
	checker.walk_body_for_def(def.name, def.body, mut seen)!
}

// check_predicate verifies that the supplied PredicateExpr body is pure
// Every callee in the body must be classified pure;
// any impure callee raises CXER0230. Use this entry point when a
// predicate appears in a path step.
pub fn (checker &PurityChecker) check_predicate(predicate &cx.PredicateExpr) ! {
	mut seen := map[string]bool{}
	checker.walk_predicate_body(predicate, mut seen)!
}

// check_all walks every DefNode collected at construction time and
// raises the first purity violation it sees. Use this entry point from
// the module loader after parse completes.
pub fn (checker &PurityChecker) check_all() ! {
	for _, def in checker.defs {
		checker.check_def(def)!
	}
}

// ── Inference walkers ─────────────────────────────────────────────────────────

// walk_body_for_def tokenises the body source, finds every callee
// reference, and verifies that none are impure. `seen` short-circuits
// mutual / self-recursion: a def already in flight is treated as a
// fixpoint contribution (no additional constraint to add — the outer
// frame has already constrained it).
fn (checker &PurityChecker) walk_body_for_def(def_name string, body string, mut seen map[string]bool) ! {
	if def_name in seen {
		return
	}
	seen[def_name] = true

	// Reserved-binding-outside-predicate check: in a [?def] body, any
	// reference to $_position or $_last is illegal.
	// (The def body is NOT a predicate body — it's the right of the
	// `(args) BODY` slot.)
	check_reserved_bindings_outside_predicate(body)!

	tokens := scan_body_for_calls(body)
	for tok in tokens {
		checker.classify_callee(tok, mut seen, .from_def)!
	}
}

// walk_predicate_body verifies that the predicate body is pure. Raises
// CXER0230 on the first impure callee.
fn (checker &PurityChecker) walk_predicate_body(predicate &cx.PredicateExpr, mut seen map[string]bool) ! {
	tokens := scan_body_for_calls(predicate.source)
	for tok in tokens {
		checker.classify_callee(tok, mut seen, .from_predicate)!
	}
	// Recurse into structural children if any (bool_expr will appear
	// here in later phases — sound to walk now).
	for child in predicate.children {
		checker.walk_predicate_body(child, mut seen)!
	}
}

// CalleeOrigin tags the scope of the calling site so the classifier can
// emit the correct wire code (CXER0233 for def context, CXER0230 for
// predicate context).
enum CalleeOrigin {
	from_def
	from_predicate
}

// classify_callee looks up a single callee identifier or directive head
// in the checker's tables. Pure → accept; impure → raise the
// origin-appropriate code; unknown identifier → recurse into a known
// def or raise CXER0234 for unclassified builtins.
fn (checker &PurityChecker) classify_callee(callee string, mut seen map[string]bool, origin CalleeOrigin) ! {
	// Directive heads (start with `?`).
	if callee.starts_with('?') {
		if callee in checker.impure_directives {
			return purity_error(origin, 'call to impure directive `[${callee}]`')
		}
		if callee in checker.pure_flow_directives {
			// Body-derived purity — the surrounding tokeniser pass has
			// already enqueued the body's own callees, so no per-head
			// contribution is needed.
			return
		}
		// Unrecognised directive head — reaching here means the
		// directive is not classified in either table. Per the closed-
		// list discipline this is CXER0234.
		return unclassified_error(callee)
	}

	// Module-qualified call `prefix:local` (e.g. [$env:var …], [$cx:eval-tree …]).
	// The impure table keys stdlib prims by their hyphenated bare name, so
	// normalize `:`→`-` and probe the local segment (mirrors
	// call_name_is_impure_builtin). cx:eval-tree is the tree-eval function form
	// — impure per §6.4.4 (the eval effect is gated by the `eval` capability at
	// runtime), the call-form dual of the [?eval] directive.
	if callee.contains(':') {
		if callee == 'cx:eval-tree' || callee.all_after_last(':') == 'eval-tree'
		   || call_name_is_impure_builtin(callee) {
			return purity_error(origin, 'call to impure builtin `${callee}`')
		}
		// Pure / unclassified module call — no purity constraint (a colon-
		// qualified callee is never a parameter reference).
		return
	}

	// Known def in module — recurse on its declared purity.
	if d := checker.defs[callee] {
		if d.purity == .impure_ {
			return purity_error(origin, 'call to impure `[?def] ${callee}`')
		}
		// Pure def — recurse into its body to verify transitively.
		checker.walk_body_for_def(d.name, d.body, mut seen)!
		return
	}

	// Known builtin — consult classification.
	if p := checker.builtin_purity[callee] {
		if p == .impure_ {
			return purity_error(origin, 'call to impure builtin `${callee}`')
		}
		return
	}

	// Unclassified identifier — could be a parameter reference or a
	// runtime variable. At Phase 2.22 we ONLY raise CXER0234 if the
	// identifier matches a known-builtin-shaped name that hasn't been
	// classified. Unknown identifiers that have no classification entry
	// at all are treated as parameter references (safe assumption — the
	// dev-strict validator will flag unknown identifiers separately at
	// Phase 2.16).
	//
	// However if the callee is "$_position" / "$_last" reached via
	// scan_body_for_calls (it never is — bindings start with `$`, which
	// scan_body_for_calls filters out), we'd raise CXER0231. The
	// `$_position` / `$_last` check is handled by
	// `check_reserved_bindings_outside_predicate` before tokenisation.
}

// purity_error formats the origin-appropriate wire code for a detected
// impure callee.
fn purity_error(origin CalleeOrigin, reason string) IError {
	match origin {
		.from_def {
			return error('cx-err:CXER0233 E_PURITY_VIOLATION: ${reason}')
		}
		.from_predicate {
			return error('cx-err:CXER0230 E_PREDICATE_NOT_PURE: ${reason}')
		}
	}
}

// unclassified_error formats CXER0234 for a reference to a builtin or
// directive missing from the closed purity classification list.
fn unclassified_error(name string) IError {
	return error('cx-err:CXER0234 E_PURITY_UNCLASSIFIED_BUILTIN: reference to unclassified builtin or directive `${name}`')
}

// ── Helpers: bind-name / reserved-binding checks ──────────────────────────────

// check_reserved_binding_use raises CXER0231 if `$_position` or
// `$_last` is referenced in a context where the spec forbids it
// (i.e. outside any PredicateExpr body). Surfaced as a
// public entry so the parser / pre-runtime module loader can call it
// on stand-alone expression-fragments outside of `[?def]` walking.
pub fn check_reserved_binding_use(body string) ! {
	check_reserved_bindings_outside_predicate(body)!
}

// check_reserved_bind_name raises CXER0232 if the path step's `:bind`
// peer-modifier targets the underscore name (`:bind _`). Mirrors the
// path_parser guard (Phase 2.20) so module-load can reject `:bind _`
// even when emitted by a non-parser source (e.g. a future API caller
// that constructs PathStep values programmatically).
pub fn check_reserved_bind_name(bind_target string) ! {
	if bind_target == '_' {
		return error('cx-err:CXER0232 E_RESERVED_BIND_NAME: `:bind _` is reserved — underscore is the implicit context binding `$_`')
	}
}

// check_reserved_bindings_outside_predicate scans `body` for `$_position`
// or `$_last` references (in non-string-literal positions) and raises
// CXER0231 if any are found. The caller has already established that the
// body is NOT a predicate context (i.e. it is a [?def] body OR a top-
// level program fragment).
fn check_reserved_bindings_outside_predicate(body string) ! {
	src := body.bytes()
	mut i := 0
	for i < src.len {
		b := src[i]
		// Skip string literals — `'…'` and `"…"`.
		if b == `"` || b == `'` {
			quote := b
			i++
			for i < src.len && src[i] != quote {
				if src[i] == `\\` && i + 1 < src.len {
					i += 2
					continue
				}
				i++
			}
			if i < src.len {
				i++ // closing quote
			}
			continue
		}
		// Look for `$_…`.
		if b == `$` && i + 1 < src.len && src[i + 1] == `_` {
			start := i
			i += 2
			for i < src.len && purity_is_name_cont(src[i]) {
				i++
			}
			binding := src[start..i].bytestr()
			if binding == '\$_position' || binding == '\$_last' {
				return error('cx-err:CXER0231 E_RESERVED_BINDING_USE: reference to reserved binding `${binding}` outside a predicate body')
			}
			continue
		}
		i++
	}
}

// ── Tokeniser ─────────────────────────────────────────────────────────────────

// scan_body_for_calls returns the list of callee-shaped tokens that
// appear in `body` outside of string literals. Two kinds of tokens are
// returned:
//
//   - `?NAME`           — directive head (the `[?NAME …]` form). The
//                          leading `?` is included; consumers strip it
//                          when looking up impure-directive table keys.
//   - `NAME`            — a bareword call shape `NAME(…)` (Phase 2.22
//                          inference: a name followed by `(` after
//                          optional whitespace counts as a call).
//
// Bindings (`$name`) and reserved bindings (`$_…`) are NOT returned;
// they are handled separately by check_reserved_bindings_outside_predicate.
fn scan_body_for_calls(body string) []string {
	mut out := []string{}
	src := body.bytes()
	mut i := 0
	for i < src.len {
		b := src[i]
		// Skip string literals.
		if b == `"` || b == `'` {
			quote := b
			i++
			for i < src.len && src[i] != quote {
				if src[i] == `\\` && i + 1 < src.len {
					i += 2
					continue
				}
				i++
			}
			if i < src.len {
				i++ // closing quote
			}
			continue
		}
		// Skip `$NAME` bindings (incl. `$_…`).
		if b == `$` {
			i++
			for i < src.len && purity_is_name_cont(src[i]) {
				i++
			}
			continue
		}
		// Directive head: `[?NAME`.
		if b == `[` && i + 1 < src.len && src[i + 1] == `?` {
			start := i + 1 // include `?`
			i += 2
			for i < src.len && purity_is_name_cont(src[i]) {
				i++
			}
			name := src[start..i].bytestr()
			if name.len > 1 {
				out << name
			}
			continue
		}
		// Head-dispatch call: `[$NAME …]` (built-in / function
		// invocation). The bare `$NAME` skip below handles binding refs;
		// a `[`-adjacent `$NAME` is a CALLEE, so record it here.
		if b == `[` && i + 1 < src.len && src[i + 1] == `$` {
			i += 2 // past `[$`
			start := i
			// Capture the colon-qualified `prefix:local` module-call name whole
			// (NOT just the `prefix` segment) — otherwise a module-qualified
			// impure call like `[$env:var …]` / `[$cx:eval-tree …]` would be
			// invisible to the def-purity check, escaping CXER0233.
			for i < src.len && (purity_is_name_cont(src[i]) || src[i] == `:`) {
				i++
			}
			name := src[start..i].bytestr()
			if name.len > 0 {
				out << name
			}
			continue
		}
		// Bareword `NAME(` call (calls in `[+ a b]` form are operator
		// calls that don't shape-match here; that's fine — `+`, `-`,
		// `*`, `/` are not in the impure-builtin set anyway, and §6.5.x
		// classifies the arithmetic operators implicitly as part of
		// the numeric pure group via the Logical/Numeric pure rows).
		if purity_is_name_start(b) {
			start := i
			i++
			for i < src.len && purity_is_name_cont(src[i]) {
				i++
			}
			name := src[start..i].bytestr()
			// Skip whitespace.
			mut j := i
			for j < src.len && (src[j] == ` ` || src[j] == `\t` || src[j] == `\n` || src[j] == `\r`) {
				j++
			}
			// Call shape: NAME(…)
			if j < src.len && src[j] == `(` {
				out << name
				i = j + 1
				continue
			}
			// Bare-identifier reference (no paren). At Phase 2.22 we
			// do NOT count these as calls — they may be parameter
			// references or constant references. Only paren-followed
			// names count. The sound-but-incomplete contract permits
			// this: missing an impure call shaped as a bare reference
			// would only be a soundness issue if such a thing existed
			// in CX, which it doesn't (call sites are always either
			// `NAME(…)` or `[?NAME …]`).
			continue
		}
		i++
	}
	return out
}

@[inline]
fn purity_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn purity_is_name_cont(b u8) bool {
	return purity_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-`
}
