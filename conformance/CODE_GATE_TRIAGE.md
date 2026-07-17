# conformance/code gate — authoritative failure triage (v0.8.0)

The `conformance/code` eval gate (`vcx/tests/code_eval_fixtures_test.v ::
test_all_code_fixtures_evaluate`, over `conformance/code.cxd`) is **enforced**
(`conformance/gates.cxd`). World-class bar: every enforced fixture either
**passes**, is **corrected to match the current spec**, or is **explicitly
moved to `gate=pending` with a reason** — no silent whitelist.

**Status: 103 → 58 → 0 ENFORCED (GATE GREEN, 2026-05-31).** The
`conformance/code` eval gate now passes: 0 enforced failures, with **2
tracked `gate=pending`** deferrals (the harness honors per-case
`gate=pending`):
- `program-with-error-hook-001` — `[?with-error-hook]` is a tier-3
  effectful directive; the effect-context model is unbuilt at v0.8.0.
- `pred-017-purity-unclassified-builtin` — `CXER0234` is "a reference to
  a BUILTIN missing from the purity table", but under §6.5 bare-head=data
  `[no-such-builtin-name]` is a data element, not a builtin reference, so
  `CXER0234` is unreachable from conformant user code (an internal
  table-completeness guard, not a user-facing conformance case).

The 58→0 burn-down cleared: CXPath predicates (infix grammar + TextNode
equality/sort + node-set-source no-unwrap), program-for (§6.5
bare-head=data, n-ary `- * /`, filter/map/reduce head-dispatch builtins),
async/concurrency (cause-shape + future `@state`/`@value`), the full 17
module/`[?lib]` bucket (in-memory test-module registration, two-pass
`[?const]`, CXER0214/0216), def/type (compound-type annotations parse,
two-pass recursion, CXER0204/0205, --strict CXER0206/0207), atom
type-strictness, fn-not-serializable CXER0291, multi-valued case-path
CXER0103, and modify `:using` trap CXER0104. Two background worktree
agents (async, modules) contributed. Design principle locked: atomize in
comparison/arithmetic, serialization/`[yield]` preserves nodes
(bijection). Full `vcx/` suite: only the 5 pre-existing failing files
throughout (arrow build, the gate file itself when run standalone passes,
code_parser `[?str]`, match_multi `[?let]`-colon, render quote-style).

---

## Open spec⇄impl findings — 2026-06-02 (code-tour port + tooling migration) — UNTRIAGED

F1–F8 surfaced while porting `examples/code-tour.cx` to the v0.8.0 surface
(commit `735c4158`) and during the editor-tooling migration the same day;
F9–F12 surfaced porting `examples/cxpath-tour.cx` / `examples/modify-crud.cx`
later that day. All are
**spec-admits-but-impl-diverges** gaps with **no enforced fixture covering
them** (the gate is green because nothing exercises these paths). Each needs a
spec-first fixture before any impl fix; none is currently tracked elsewhere.

Severity key: **S** = silent wrong answer · **E** = hard error where spec says
value/absence · **M** = missing surface · **D** = spec-doc staleness.

| # | Sev | Finding | Spec anchor | Observed |
|---|---|---|---|---|
| F1 | E | ~~`(bind $name)` path-step annotation parses but the path walker never populates the binding~~ **RESOLVED 2026-07-14 (#434)** — the walker binds the step's focus (fork-per-focus for subsequent steps); enforced fixtures `program-cxpath-bind-001…007` in code.cxd | code.md §5.5 (worked example), grammar `[160a]` | was: `//team (bind $t) / member[… $t …]` → `CXER0001 unbound variable $t` at eval; fixture `pred-006` sidesteps via two-generator `[?for]` |
| F2 | **S** | Attribute reads inside **nested** predicates silently match nothing | §5.5.2 (predicate bodies are full CX exprs) | `//team[count($_/member[$_@role="lead"]) >= 1]` → empty; child-element `$_/role` works (`pred-005` uses child elements only) |
| F3 | E | Missing-attribute read hard-errors instead of riding the absence channel | §9.1.2.2 (optional attr miss = absence) | `$u/@absent` and `$u@absent` → `CXER0001 no attribute` (kills any `[?for]`/`[where]` over heterogeneous nodes) |
| F4 | M/E | `[?const]` modifiers: `scope=public` rejected; spec's bare `lazy` parses but the const **never binds** (impl wants `:lazy` atom) | §12.3 | `[?const scope=public K 42]` → `CXER0212`; `[?const lazy K 42]` parses, `$K` unbound on read; `[?const :lazy K …]` (fixture surface) works |
| F5 | M | `[?lib]` selective import unimplemented — modifier parser is still v0.7-shaped | §12.1.2 | clause `[only x]` → `CXLIB_PARSE "expected modifier :LABEL, attr=value, or ]"`; attr `only=(x)` → `CXLIB_UNKNOWN_MODIFIER "expected as"`; legacy `:only (x)` parses but the refer never binds ("no callable") |
| F6 | M | Single-arm `[?match]` rejects bind-only / scalar patterns | §8.2, grammar `[136]`/`[140a]` (MatchPattern admits `$name` + scalar literals) | `[?match 5 $n [yield …]]` → `CXER0001 "[?match] second slot must be a pattern"`; element patterns work |
| F7 | D | §10.3.4 documents client ops as `$c \| get(PATH)` — infix pipe + paren-call, both retired by §8.9; §8.10 "Pipeline composition" example also uses infix `\|` | §10.3.4, §8.10 vs §8.9 tombstones | impl surface is `[$get $client PATH]` (client as first positional arg; `cx-test://NAME` targets hit the in-substrate service) — spec text needs the §8.9-conformant rewrite |
| F8 | **S** | `[?http-service]` handler given as `[?fn]` leaks the closure into the response body instead of being invoked with the request | §10.3.2 (`HANDLER` trailing positional) | `[resource [get "/ping"] [?fn ($req) [response …]]]` → `[response status=200 [body [__cx_closure__ …]]]`; a direct-expression handler evaluates correctly |
| F9 | E | Single-slash-rooted paths rejected in expression position | grammar `[130]` (`PathExpr ::= … \| '/' StepList \| …`) | `/root/users/user` → `CXER0100 unexpected token '/' in expression position` in every context tried (element body, `[?let]` value, `[?for]` generator); `//`-anchored paths work |
| F10 | E | Axis steps on a binding path rejected at `::` | grammar `[135a]` (`BindingStep ::= '/' Step` — "child / wildcard / **axis**"; comment names `$x/axis::name`) | `$u/parent::*`, `$u/following-sibling::user` → `CXER0100 unexpected token '::'`; the same axis anchored at the document (`//user[1]/parent::*`) works |
| F11 | E | Comparison expressions rejected inside XPath-call argument parens in predicates | §5.5.2 (predicate bodies are full CX exprs) | `//user[not($_@banned = true)]` → `CXER0100 expected ')', got =`; bare-truthy `not($_@banned)` and `$_@banned = false` both parse + evaluate |
| F12 | E | A `[?let]`-bound node-set does not distribute attribute steps over its members | §6.2 O4 (normative: `$seq/@x` over `([a x=1], [a x=2])` yields `(1, 2)`, "not a `no attribute` error") | `[?let [= $u //user[1]] … $u/@name]` and `[?let [= $s //user] … $s/@email]` → `CXER0001 no attribute` even though every member carries the attribute; `[?for]`-bound single nodes read fine (workaround used in `examples/cxpath-tour.cx`) |
| F13 | **S** | `cx fmt` output of a PROGRAM file is not program-faithful — the data parser approximates program expressions inside attribute values / text runs, and `emit_cx` re-emits a surface the code parser rejects (or that evaluates differently) | tooling.v idempotence contract (`fmt(fmt(x)) == fmt(x)`); grammar [59] note that clause decomposition is the program layer's job | `cx fmt examples/cxpath-tour.cx` succeeds, but its output fails `cx eval` re-parse (`total=[$count //user[@active=true][@age>=21]]` is split into a quoted text fragment + stray predicate); pre-dates the [59] uniform-directive cutover (reproduced on a `?let`/`?for`-only file). The `verify-examples` gate only checks fmt exit status, so this is invisible to it. Real fix is either a program-aware fmt path (route `.cx` program files through the code parser + program renderer) or excluding program files from data-fmt |

Non-findings confirmed by design while porting (documented in
`examples/code-tour.cx` comments / session memory): module value = **last
top-level expression** (tour files need one wrapper element); eval input flag
is `--data=` (`--input` never existed); postfix `?`/`!` attach only to
`[$call …]` forms (grammar `[125]`); scalar `[case 200 …]` does not match
attr-sourced values (strict match, no atomization — the
atomize-in-comparison-only principle).

---

### Historical (the original 58-item triage, now resolved)

Resolved so far:
- `[?sleep DUR mock]` bareword (`7f406a85`): −21.
- `level=visualization` render-spec fixtures skipped from eval (validated by
  `code_diagram_roundtrip_test.v`), viz-022 → pending (`6dd5b8cb`): −21.
- `[$div]` int/int → integer division per §6.5 (impl bug, fixtures were right)
  (`<this commit>`): −3.

Remaining 58 failures, triaged below (fix order: fixture-invalid →
spec-decision → impl-gap → future-pending).

---

## Bucket 1 — fixture-invalid / miscategorized (false red — fix FIRST)

### 1a. Visualization render-spec fixtures evaluated as eval fixtures (17)
`level=visualization`, `in-code == out-text` (identity render) — these assert a
**structural render** of a directive (a diagram / policy badge), NOT an
evaluation. The eval runner executes them (e.g. `[?fallback …]` → "requires
recover-with") and fails. They belong in a **visualization render harness**
(`vcx/cmd/diagram.v`), not the code-eval gate.

`program-viz-001-for-pattern-tree`, `-002-match-alternative-branches`,
`-003-for-sequential-loop`, `-004-for-par-parallel-branches`,
`-005-map-par-parallel-branches`, `-006-if-alternative-branches`,
`-007-try-catch-recovery-branch`, `-008-retry-policy-badge`,
`-009-timeout-policy-badge`, `-010-circuit-breaker-policy-badge`,
`-011-fallback-policy-badge`, `-012-rate-limit-policy-badge`,
`-013-bulkhead-policy-badge`, `-015-worker-channel-send-receive`,
`-017-async-detached-swimlane`, `-018-await-all-barrier`,
`-019-cancel-arrow-barrier`.

→ **Action:** the eval runner should SKIP `level=visualization` (they are not
eval fixtures); a render-conformance run validates them via the diagram
renderer. Until that render harness exists, mark them `gate=pending` with
reason `render-spec`. **Decision needed:** build the render harness now, or
pending-with-reason for v0.8.0?

### 1b. Unbound-variable cases (~7)
`unbound variable $url` (×3), `$users` (×2), `$x`, `$node`. Likely a fixture
setup gap (a binding the program references is never `[?let]`-bound or wired
from `in-cx`/`doc`) OR a binding-scope evaluator issue. → **Investigate each**;
fix the fixture if it omits a binding, else file an eval scope gap.

---

## Bucket 2 — spec-decision-needed (decide before implementing)

### 2a. `[$div …]` numeric result — int vs true division (3)
`program-num-div-001-element-paren-args`, `-002-element-multi-args`,
`-003-xpath-call`: impl returns `2.5`, fixtures expect `2`. The spec must pin
whether `[$div a b]` over two ints is true division (`2.5`) or
integer/truncating (`2`, with `[$idiv]` as the explicit integer form). → **Spec
decision in code.md**, then correct impl or fixtures to match.

### 2b. CXPath predicate context-bindings — v0.8.0 scope? (11)
`pred-001`…`pred-011`: predicates using `$_@attr`, `$_position`, `$_last`
(e.g. `//user[$_@age >= 18]`, `//section/p[$_position = 1]`). Parser errors
`expected ']' closing CXPath predicate`. **Decision:** does v0.8.0 commit to
predicate context-bindings? If yes → Bucket 3 (parser+eval impl). If deferred →
Bucket 4 (pending with reason).

---

## Bucket 3 — implementation gap (spec is clear; impl missing)

- **CXPath predicate bindings (11, pred-\*)** — IN-SCOPE: code.md §
  (lines 593–641) fully specs `$_position`/`$_last`/`$_@name` + the
  `[@name]`/`[N]`/`[@name=V]` desugarings. **Root cause (diagnosed):** predicate
  bodies use **infix** comparison (`$_@age >= 18`, `$_position = 1`), but
  `parse_path_predicate_general` (parser.v:722) routes the body through the
  **prefix** `parse_expr`, which parses the first operand (`$_position`) then
  can't consume the infix `>=`/`=`/… → "expected ']' closing CXPath predicate".
  Note `$x@age` (normal binding + `@attr`) and standalone `$_@age` parse fine —
  the gap is specifically (a) an infix-comparison expression grammar for
  predicate bodies and (b) binding `$_position`/`$_last`/`$_` + evaluating them
  in `nav.v`'s candidate loop. Substantial parser+eval feature, not a one-liner.
- **`program-for-*` (6)** — `-005-sort-limit` (sort+limit ordering: got Carol,
  want Alice), `-006/-009` (`name()` raising on a multi-item sequence where the
  spec expects element selection), `-011` (attribute path step on non-element),
  `-014-pipe-sugar` (got 0, want 2), `-015-named-def-reuse`.
- **async / concurrency (6, program-async-*/conc-*)** — worker/await-all
  cancel-cause chaining: got an extra nested `[cause …]` the fixture's expected
  shape omits (e.g. `program-conc-012-worker-cancel`).
- **`program-def-*` (2–3)** — def / type enforcement gaps.
- **`program-fn-010-fn-not-serializable`** — expected `CXER0291`, got a raw
  `[__cx_closure__ …]`; a function value must be non-serializable (raise) rather
  than rendering its internal closure.
- **`module-transitive`** — needs an in-memory test module for
  `github.com/example/level-a` (test-harness module registration), not a live
  fetch.

---

## Bucket 4 — future-scope pending (explicit, with reason)

- **`modify :using` lambda** — `MODIFY_USING_LAMBDA_NOT_YET_IMPLEMENTED`
  (`modify_eval.v`): deferred to a later phase per the impl note. → `gate=pending`
  with reason.
- **`program-with-error-hook-001`** — `[?with-error-hook] not in pure-functional
  evaluator subset`: effectful hook; confirm whether v0.8.0 ships it or defers.

---

## Adjacent (P1, separate from the 82 — implementation phase)

- **Capability enforcement** — wire `CXER0271` at every effect point
  (env/time/random/crypto/uuid/io/process/store/prof/test). The 156 advisory
  denial fixtures are the worklist; cap-check must precede type/domain/host
  errors. Promote modules to `enforced` as enforcement lands.
- **Capability-granted harness** — second runner mode (temp dirs, fixed env,
  mock clocks, deterministic subprocesses, local services) for the
  behavior lane (the 127 denial-only + 5 pending functions).
