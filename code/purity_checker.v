module code

import cx

// cx_module_impure_fns is the `cx:` module's impure member set, taken from
// modules/cx.md §2.2's Purity column. Kept OUT of builtin_purity_table()
// deliberately: that table is the value `cx:builtins` returns, hence an input
// to `cx:env` and to every computation address, so only a name the §6.5.x SPEC
// table carries may enter it. A `pure` [?def] body reaching any of these
// raises CXER0233 (modules/cx.md §3 for cx:eval; core/code.md §6.4.4 for the
// tree form).
const cx_module_impure_fns = ['cx:eval', 'cx:eval-tree', 'cx:render', 'cx:resolve-includes']

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
	// MIRROR of code.md §6.5.0's normative closed table (RULED tables-1a).
	// The spec owns the classification; this list is checked against it in
	// BOTH directions by the check-directive-purity gate, so it can neither
	// lag the vocabulary nor invent a class the spec does not carry.
	//
	// pure-flow = the directive introduces no effect of its own; its purity
	// is DERIVED FROM ITS BODY. Adding a directive means adding a §6.5.0 row
	// first — the mirror may not lead the spec.
	for n in [
		'?attr', '?chunks', '?concat', '?const',
		'?cycle', '?def', '?do', '?drop',
		'?element', '?else', '?entry', '?enumerate',
		'?filter', '?flatten', '?fn', '?for',
		'?for-array', '?for-map', '?group-by', '?if',
		'?let', '?lib', '?loop', '?map',
		'?match', '?meta', '?name', '?partition',
		'?pipe', '?quote', '?reduce', '?scan',
		'?secret', '?splice', '?str', '?take',
		'?to-array', '?to-map', '?to-sequence', '?unquote',
		'?view', '?views', '?with-caps', '?with-error-hook',
		'?with-open', '?with-scope', '?zip',
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
		'reverse', 'distinct', 'nth', 'position', 'range', 'identity',
		// §6.5.x Sequence — presence predicate (#854, #849); pure.
		'present'] {
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
	// `local-name` / `string` are §6.5.x Node-accessor rows that were missing
	// here (#859) — the spec classified them, the table did not.
	for n in ['name', 'cast', 'exists', 'local-name', 'string'] {
		t[n] = cx.Purity.pure_
	}

	// Pure — Generator (§6.5.x). `iterate`/`unfold` are pure iff their `f` is;
	// the per-call purity of `f` is checked where the argument is, not here.
	// Missing from this table until #859, for the same reason the others were:
	// nothing could observe the omission while CXER0234 was unreachable.
	for n in ['iterate', 'unfold'] {
		t[n] = cx.Purity.pure_
	}

	// Pure — native primitives that BACK stdlib module bodies rather than the
	// language surface: cx-stdlib/math's powers/logs/roots, and the validation
	// primitive. All total and effect-free (math domain errors return NaN per
	// IEEE 754, never raise).
	//
	// §6.5.x's own tables classify THE LANGUAGE — the same distinction it draws
	// when it excludes the `[?test-…]` harness directives. These are
	// dispatchable, so they must be classified SOMEWHERE for the CXER0234 check
	// below to be decidable; classifying them here is the implementation
	// discharging §6.5.x's requirement, not an amendment to its lists. Whether
	// the spec text should also enumerate them is a separate question, filed
	// rather than decided here.
	for n in ['sqrt', 'cbrt', 'exp', 'log', 'log2', 'log10', 'pow',
		'validate-item'] {
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

	// Impure — evaluation-environment introspection (security.md C4, L104):
	// [$caps] reads the ACTIVE grant set. Classified impure because a pure
	// body observing the cap set would break the §6.5.1 cap-set-invariance
	// the pure ⇒ deterministic theorem rests on; capability-FREE by the
	// narrow-only invariant (exception table, effect_alignment.v).
	t['caps'] = cx.Purity.impure_

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

	// Ring-1 pack prims that are IMPURE WITHOUT A CAPABILITY (#818). Each
	// wrapping [?def] in stdlib/*.cx declares `impure`; before this the
	// classifier reached no impure callee from those bodies and read them as
	// PURE — the declaration said impure, the classifier said pure, and a
	// pure-required context (a fold reducer, a pure [?def]) admitted them
	// instead of refusing loud. That is the CXER4611 slip #788 closed for the
	// Ring-2 packs, arriving through the Ring-1 door.
	//
	// The GATED members of these packs are NOT here — they arrive via the
	// capability_gated_prims() fold below, by construction. Every name in
	// this list carries a matching reason in
	// effect_alignment.impure_without_capability_exceptions() (bucket (g) or
	// (h)), and the §6.5.1 direction-2 gate fails if the two ever disagree.
	for n in [
		// object PRNG (handle-scoped, seeded from an argument)
		'random-new', 'random-free', 'random-gen-bool', 'random-gen-choose',
		'random-gen-choose-weighted', 'random-gen-exponential', 'random-gen-float',
		'random-gen-float-range', 'random-gen-floats', 'random-gen-gaussian',
		'random-gen-int', 'random-gen-int-range', 'random-gen-ints',
		'random-gen-poisson', 'random-gen-sample', 'random-gen-sample-weighted',
		'random-gen-shuffle',
		// test harness state
		'test-assert', 'test-assert-contains', 'test-assert-equal',
		'test-assert-match', 'test-assert-near', 'test-assert-not-equal',
		'test-assert-shape', 'test-assert-snapshot', 'test-assert-throws',
		'test-before-all', 'test-before-each', 'test-after-all', 'test-after-each',
		'test-configure', 'test-fail', 'test-skip',
		// profiler process-global state
		'prof-counter-add', 'prof-counter-all', 'prof-counter-get',
		'prof-counter-inc', 'prof-counter-reset', 'prof-flamegraph-emit',
		'prof-gc-trigger', 'prof-histogram-observe', 'prof-histogram-reset',
		'prof-histogram-stats', 'prof-mem-snapshot', 'prof-prof-configure',
		'prof-trace-flush',
		// logging sinks + scope state
		'log-configure', 'log-current-scope', 'log-debug', 'log-emit-raw',
		'log-error', 'log-fatal', 'log-info', 'log-log', 'log-warn',
		// scheduler registry + test clock
		'sched-after', 'sched-at', 'sched-cancel', 'sched-cron', 'sched-every',
		'sched-recur', 'sched-restore', 'sched-test-clock-advance',
		// mime registry mutators + the boundary draw (bucket (h) gap)
		'mime-load-mime-types', 'mime-register-type', 'mime-multipart-boundary',
		// http connection-pool bookkeeping (the socket verbs are gated)
		'http-client', 'http-close',
		// io handle close (documented capability-free, io.md §7)
		'io-close',
		// locale default read (bucket (h) gap)
		'locale-default-locale',
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
	// MIRROR of code.md §6.5.0 (RULED tables-1a) — impure = the directive IS
	// an effect point whatever its body does.
	for n in [
		'?async', '?await', '?await-all', '?await-any',
		'?await-race', '?bulkhead', '?cancel', '?channel', 
		'?check-cancel', '?circuit-breaker', '?close', '?eval',
		'?fallback', '?http-client', '?http-service', '?modify',
		'?monitor', '?rate-limit', '?receive', '?retry',
		'?reveal', '?select', '?send', '?service-handle',
		'?sleep', '?stop', '?subscribe', '?timeout',
		'?try-receive', '?try-send', '?wait-for', '?worker',
		'?worker-handle',
	] {
		t[n] = true
	}
	// Test-only diagnostics: NOT in the §4.1 registry and not language
	// surface, so §6.5.0 deliberately does not carry them (it classifies the
	// language, not the harness). They mutate per-run harness state, so they
	// are impure; the gate permits impl-only rows for exactly this set.
	for n in [
		'?test-always-err', '?test-bulkhead-full', '?test-cb-open', '?test-clock',
		'?test-close-log', '?test-closeable', '?test-counter', '?test-current-scope',
		'?test-err-then-ok', '?test-rate-limited', '?test-single-use-iter',
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
	// Ring-2 pack verbs classify through the registration seam (they are
	// invisible to this table by the I3 ring rule).
	return ring2_is_impure(name)
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
			// L100 (stream-2 W2): the ONE traversal. The hand-rolled walk
			// this replaces SKIPPED the [yield-map K V] VALUE node — an
			// impure expression in map-value position escaped the purity
			// refusal (probed live; pinned by the W2 fixture).
			for item in cx.for_comp_children(node) {
				if walk_impure(item.node, impure_dirs) {
					return true
				}
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

	// Stream-2 W2 (L100 fallout): classify EVERY token before deciding —
	// the earlier `!`-propagating loop ABORTED at the first unclassified
	// directive head (CXER0234), so a single unknown head SHIELDED every
	// later token from the purity check. Probed live: `[?for-map]` was
	// missing from the pure-flow table, so ANY declared-pure for-map def
	// escaped CXER0233 entirely, impure calls and all. Now: impurity
	// (CXER0233) surfaces immediately; the first CXER0234 is raised only
	// after the full pass (impurity dominates; callers that swallow 0234
	// keep their posture, minus the shielding).
	tokens := scan_body_for_calls(body)
	mut first_unclassified := ?IError(none)
	for tok in tokens {
		checker.classify_callee(tok, mut seen, .from_def) or {
			if err.msg().contains('CXER0234') {
				if first_unclassified == none {
					first_unclassified = err
				}
				continue
			}
			return err
		}
	}
	if uc := first_unclassified {
		return uc
	}
}

// walk_predicate_body verifies that the predicate body is pure. Raises
// CXER0230 on the first impure callee.
fn (checker &PurityChecker) walk_predicate_body(predicate &cx.PredicateExpr, mut seen map[string]bool) ! {
	// Same full-pass discipline as walk_body_for_def (no 0234 shielding).
	tokens := scan_body_for_calls(predicate.source)
	mut first_unclassified := ?IError(none)
	for tok in tokens {
		checker.classify_callee(tok, mut seen, .from_predicate) or {
			if err.msg().contains('CXER0234') {
				if first_unclassified == none {
					first_unclassified = err
				}
				continue
			}
			return err
		}
	}
	if uc := first_unclassified {
		return uc
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
	// call_name_is_impure_builtin). The `cx:` module's four impure members
	// (cx_module_impure_fns) are named here rather than in
	// builtin_purity_table(): that table IS the value `cx:builtins` returns and
	// therefore an input to `cx:env` and to every computation address, so a
	// name may only enter it when the §6.5.x SPEC table names it. These four
	// get their purity from modules/cx.md §2.2's own Purity column instead.
	// This is the shipped treatment of cx:eval-tree, widened to the list when
	// the other three landed (#940 / VC-6).
	if callee.contains(':') {
		if callee in cx_module_impure_fns || callee.all_after_last(':') == 'eval-tree'
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

	// #859 ENFORCED (both prior findings resolved): a callee the evaluator
	// would DISPATCH as a builtin but that has no purity row raises CXER0234
	// here, with the BUILTIN-specific message — the def-registration site
	// swallows only the directive-head 0234, so this one propagates (the
	// earlier "measured not to fire" was that swallow eating the raise, not
	// this branch failing to make it). `builtin_dispatchable` covers the
	// bare-name dispatch surface; the `$`-only names outside it (`present`
	// class) are enforced by the source-scan gate in the module umbrella
	// (test_every_dispatch_arm_has_a_purity_row_859), which cross-references
	// EVERY `invoke_builtin` match arm against this table at test time — so
	// a new builtin missing its row is red at CI even when this runtime
	// branch cannot see it.
	if builtin_dispatchable(callee) {
		return unclassified_builtin_error(callee)
	}

	// Unclassified identifier — could be a parameter reference or a
	// runtime variable. Unknown identifiers that are NOT builtins are
	// treated as parameter references (safe assumption — the dev-strict
	// validator flags unknown identifiers separately at Phase 2.16).
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
	return error('cx-err:CXER0234 E_PURITY_UNCLASSIFIED_BUILTIN: reference to unclassified directive `${name}`')
}

// unclassified_builtin_error is the BUILTIN-specific CXER0234 (#859): the
// def-registration site swallows the directive-head spelling above as a
// non-purity concern, so the builtin case needs a message it can
// discriminate — 'unclassified builtin' — to propagate.
fn unclassified_builtin_error(name string) IError {
	return error('cx-err:CXER0234 E_PURITY_UNCLASSIFIED_BUILTIN: reference to unclassified builtin `${name}` — every builtin must have a §6.5.x purity row in the same amendment that adds it')
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

// ── the §6.5.0 mirror accessors (RULED tables-1a, #756) ────────────────
//
// code.md §6.5.0 is the NORMATIVE closed directive-purity table and the
// two tables above are its mirror. These expose the mirror so the
// check-directive-purity gate can assert spec ↔ implementation equality
// in both directions — the same discipline security.md §2.1 carries for
// effect points, and the reason neither side can drift.
//
// Before #756 there was nothing to check against: §6.5.x carried the
// INVARIANTS only, while the closed head list lived solely here, in a
// table whose own comments claimed a spec parity that did not exist. It
// had drifted to 56 classified heads against 85 dispatched, with 13
// entries naming directives the engine answers "unknown directive" for.

// directive_purity_mirror returns every classified directive head mapped
// to its class name ('pure-flow' | 'impure'), matching §6.5.0's spelling.
pub fn directive_purity_mirror() map[string]string {
	mut t := map[string]string{}
	for n, _ in pure_flow_directive_table() {
		t[n] = 'pure-flow'
	}
	for n, _ in impure_directive_table() {
		t[n] = 'impure'
	}
	return t
}

// directive_purity_diagnostics_only names the test-only heads that are
// classified here but deliberately absent from §6.5.0: they are not in
// the §4.1 registry and are not language surface, so the spec table
// classifies the language and this set covers the harness. The gate
// allows an impl-only row for exactly these and nothing else.
pub fn directive_purity_diagnostics_only() []string {
	return ['?test-always-err', '?test-bulkhead-full', '?test-cb-open', '?test-clock',
		'?test-close-log', '?test-closeable', '?test-counter', '?test-current-scope',
		'?test-err-then-ok', '?test-rate-limited', '?test-single-use-iter']
}
