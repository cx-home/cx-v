# std-lib conformance fixture authoring contract

How to write `conformance/stdlib/<module>.cxd` fixtures, spec-first (ahead of
implementation). Fixtures are CX documents per `conformance/fixtures.cxs`; the
stdlib eval runner (`vcx/tests/code_eval_fixtures_test.v::test_stdlib_module_fixtures`)
auto-discovers every `conformance/stdlib/*.cxd`, runs each case, and compares
the eval result to the expected section. Until the module is implemented these
go **red** — that red list is the implementation worklist.

## File shape

```cx
[test-suite name=<module>
 [case id=<module>-001-<short-desc> level=core
  [tags <module> <fn-name> <facet>]
  [in-cx [#
[empty]
  #]]
  [in-code [#
[?lib 'cx-stdlib/<module>']
[$<module>:<fn> <args…>]
  #]]
  [out-text [#
<expected canonical result>
  #]]
 ]
 …
]
```

Rules:
- **Payloads are flush-left verbatim** inside `[# … #]`: content starts on the
  line after `[#`, and `#]` sits on its own line. No content on the `[#`/`#]`
  lines. A literal `#]` inside a payload is rare; if needed, split it.
- `in-cx` is `[empty]` for pure-function fixtures (no input document). When a
  function operates on a parsed document, put the CX source in `in-cx` and bind
  it via the runner's `doc` binding (see existing `path`/`time` fixtures).
- `in-code`: import the module with `[?lib 'cx-stdlib/<module>']` (the resolver
  argument MUST be quoted), then the call. The LAST expression is the result.
- **Call module members as QName head-dispatch `[$<module>:<fn> …]`** (code.md
  §12.1.1 — exports are QNames `prefix:local`, e.g. `[$strings:upper "hi"]`).
  The `/` operator is data-path navigation, NEVER a module ref — the retired
  `[<module>/<fn> …]` slash form was cut over 2026-05-31 and now fails loudly
  (`no callable "<module>/<fn>"`). The coverage gate rejects any slash head.
- **String rendering follows the PRODUCTION renderer (`code.render_canonical`,
  identical to `cx eval` / `cx fmt` / `cx canonical`).** The gate compares the
  fixture's `out-text` against exactly what the shipped binary emits, so every
  binding (V / Python / Go / Rust) sees the same contract — there is no
  test-only "display" convention any more. Rendering is **lossless** per
  canonical.md §2.3 (`bare > single > double`):
  - A **string scalar** in element-body / sequence / map / collection position
    is **single-quoted** — e.g. `'world'`, `'a@x.com'`, `'text/plain'` — because
    a bare token there would re-parse as an element head or auto-type, losing
    string-ness. Double-quoted only when the value contains a `'` and no `"`
    (`"can't"`); triple-quoted for newlines. `''` for empty.
  - An **attribute** string value is **bare** when bare-eligible AND it would
    NOT auto-type (`name=eng`); **single-quoted** when it contains a special
    char/space OR would auto-type as int/float/bool/null/hex/date (`id='9'`,
    `flag='true'`, `label='hi there'`) — quoting preserves string-ness on
    re-parse.
  - Sequences render `(a, b, c)`; arrays `[a, b, c]`; maps `{k: v, k: v}`;
    atoms `:NAME`; non-string scalars bare (`42`, `true`, `null`).
  Comparison is whitespace-normalised token-by-token. **Author expected outputs
  by running `cx eval` on the program (or re-derive with the `CX_BLESS=1` gate
  mode + `scripts/apply_blesses.cx`) — `cx eval` IS the single oracle.**

## Coverage target (per function)
1. **Happy path** — at least one representative call with the spec's expected
   output. Add cases for meaningfully distinct behaviors (unicode, empties,
   boundaries) the spec describes.
2. **Every documented error** — one `out-err` case per `cx-err:CXERNNNN` the
   spec lists for that function:
   ```cx
   [out-err [#
cx-err:CXER2301
   #]]
   ```
3. **Edge cases the spec calls out** — boundary indices, empty inputs, etc.

## Grounding (critical)
Expected outputs MUST come from the spec — its examples, the §6 conformance
list, and the normative function descriptions. **Do not invent outputs.** If a
function's expected result is genuinely ambiguous from the spec, write the case
with your best reading AND add a `# TODO(spec-ambiguous): …` line-comment in the
suite above that case so it can be reconciled. A wrong fixture is worse than a
missing one (it fails a correct impl).

## Non-deterministic / effectful functions
- **Volatile output** (`$random:crypto-*` generators, `$uuid:v4`, `$time:now`):
  don't assert exact values. Assert deterministic properties instead — format /
  length / version (via a wrapping pure call), seeded/fixed-input behavior, or
  the error cases. Mirror the existing `random`/`uuid`/`time` fixtures.

### Capability lanes (deny-by-default)
Effectful host functions are capability-gated (deny-by-default; a missing
capability raises `cx-err:CXER0271`). Each gated function gets **two** lanes:
- **no-cap denial (now):** under the empty-capability eval runner, calling a
  gated function (`$env:var`, `$time:now`, `$random:crypto-hex`, `$io:read-file`,
  …) MUST raise `CXER0271`. These are normal eval fixtures and are authored
  spec-first. Check each module's spec capability table for which functions are
  gated vs intrinsic (e.g. `$env:pid`, `$random:from-seed`, pure arithmetic /
  parser / formatter calls stay no-cap success).
- **capability-granted (Effort B — the harness now EXISTS):** asserting *granted*
  behavior (real read/write/clock/entropy) needs a capability-granted runner.
  That runner is wired: set a per-case `grant='<cap>[ <cap>…]'` attribute (e.g.
  `grant='random'`, `grant='read write'`) and the eval harness installs exactly
  that least-privilege capability set via `caps_set_list` before running the
  case (a no-`grant` case still runs under the full grant for non-effect cases,
  empty for denial cases). Author such a case as a normal `gate=enforced` case
  asserting the real deterministic outcome. Prefer outcomes that are
  deterministic despite internal entropy / a live clock / a unique sandbox:
  round-trips, structural lengths, verify booleans, lower bounds. Concrete
  patterns proven across the suite:
  - **entropy (crypto/uuid/random):** assert round-trip / structural-length /
    version-variant / verify outcomes, never a literal random value.
  - **wall clock (time/prof):** assert `system-timezone='UTC'`, `instant-now >`
    a fixed past epoch, `monotonic-now > 0`, `time:year >= <a past year>`.
  - **filesystem (io):** make the fixture self-contained and hermetic using
    io's own `temp-dir`/`temp-file` primitives as a per-run sandbox (unique
    path each run); assert booleans/ints (round-trip equals, `exists`, `size`).
  - **subprocess (process):** drive portable commands (`echo`/`true`/`false`/
    `sleep`); assert exit codes, `pid > 0`, signal-exit `143`/`137`, stream
    handles. Signal a live `sleep` that is then killed so the case stays fast.
  - **file-format loaders (i18n/load-catalog, test/fixture-load):** write a
    valid document to a temp path via io, then load it and assert a field.
  Reserve `gate=pending` only for a genuinely non-assertable surface (e.g. a
  function that terminates the runner). Keep the matching no-cap denial twin
  (it pins the `CXER0271` contract).

## Naming & ids
- `id=<module>-NNN-<short-desc>` (zero-padded NNN, unique within the file),
  e.g. `strings-007-trim-chars`. `level=core` unless the spec marks otherwise.
- `tags` include the module, the function name, and a facet word.

## Gate toggle (`gate=`) — does a failure block?

Each case has an optional `gate` attribute controlling whether its failure
**blocks the gate** (deny-by-default):
- `enforced` (default) — a failure blocks the gate (must pass).
- `advisory` — runs + reported, but **never blocks** (spec-first frontier /
  open spec question / unimplemented).
- `pending` — not run, tracked.
- `skip` — excluded.

A per-case `gate=` overrides the per-module policy in
[`conformance/gates.cxd`](../gates.cxd) (where whole unimplemented modules are
marked `advisory`), which overrides the suite default (`enforced`). Resolution:
**per-case > per-module > enforced.** Use a per-case `gate=advisory` for a
single frontier case inside an otherwise-enforced (implemented) module — e.g. a
fixture asserting a proposed-but-unimplemented behavior pending a spec decision.

## Float tolerance (`tol=`) — approximate `out-text` matching

By default `out-text` is matched exactly (token-for-token, whitespace-insensitive).
For cases whose contract is a numeric value with an allowed band — e.g. a spec
that says "≈ 3944 km within 1% tolerance" — add a per-case `tol=` attribute (a
relative float tolerance). When `tol > 0`, both the rendered result and the
`out-text` body are parsed as floats and the case PASSES when
`|actual − expected| <= tol * |expected|`; absent (`tol=0`) keeps today's exact
match. Set `out-text` to the canonical value the spec's band centers on.

```
[case id=geo-009-distance-haversine-nyc-lax level=core tol=0.01
  ...
  [out-text [#
3944.0
#]]]
```

`tol` stacks with `gate=`: an advisory float case still reports without blocking.

## `in_code` surface gotchas (these caused 50 malformed fixtures — avoid)

The `in_code` payload is a **CX program** (parsed by the code parser), not a data
document. Common v0.8.0 surface mistakes that produce `CXER0100` at eval:
- **Module calls are QName head-dispatch:** `[$re:compile "a+"]` — NOT
  `[re/compile "a+"]` (the slash form is retired; see the call-syntax rule
  above). Nest canonically: `[$re:matches [$re:compile "a+"] "aaa"]`.
- **Sequence literals are comma-separated:** `([doc "a"], [doc "b"])` — not
  space-separated. (The former single-element trailing-comma quirk —
  `[$ft:index ([doc "x"],)]` — is RESOLVED; `[$ft:index ([doc "x"])]` now
  parses. See SPEC-FINDINGS §A.)
- **Array literals are comma-separated:** `["a", "b"]` — not `["a" "b"]`.
- **Map literals are colon-separated with bare keys:** `{limit: 2, mark: "x"}` —
  not `{limit=2}` and not `{"limit" 2}`.
- **Backslash in strings must be doubled:** a regex `.+@.+\..+` is written
  `".+@.+\\..+"`. The CX code lexer supports ONLY these escapes:
  `\\ \' \" \n \r \t`. There is **no `\uXXXX` or `\xNN`** — for a raw byte
  (e.g. NUL) you cannot use an escape; pick a test input that doesn't need one.
- **`count` is a head-dispatch builtin, not a directive:** `[$count $seq]` —
  not `[?count …]`. (`[?fn:count …]` also works.)
- **You cannot path/attr a call result directly:** `[$m:f …]/x/@y` and
  `[$m:f …]@y` are parse errors. Bind first:
  `[?let [= $r [$m:f …]] $r/x/@y]`. (`@attr`/`/step` postfix is only valid after
  a `$name` reference.)

## Self-check before finishing (BOTH are required)
1. **Document structure** — `cx --ast conformance/stdlib/<module>.cxd` parses and
   `cx validate conformance/stdlib/<module>.cxd --schema=conformance/fixtures.cxs`
   is clean. (This validates the `.cxd` envelope only — the `in_code` payloads are
   RawText and are NOT checked here.)
2. **Program validity of every `in_code`** — `cx --ast` does NOT validate the
   `in_code` programs (it's the document parser; it silently captures program
   errors like `@count` / `{k=v}` / `id::int` as Text). You MUST parse each
   `in_code` through the **code parser**: write it to a temp `.cx` and
   `cx eval <tmp>`, confirming it does NOT report `CXER0100` (a
   `CXER0210`/`CXER0213` "module unimplemented" is the expected, correct red).
3. Every public function (`[?def NAME scope=public …]` in the spec) has ≥1 case.
