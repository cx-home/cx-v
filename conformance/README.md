# CX Conformance Corpus

Language-neutral conformance fixtures for every CX implementation. The
corpus is the **cross-ring contract** of the partition (partition spec §7)
and the shared contract every language binding is graded against — a
binding is conformant iff it passes the ring-tagged corpus at its ring
through the FFI, with no per-language test invention.

**V is the reference implementation** (`vcx/`). The corpus is
**append-only**: cases are added, never rewritten, except through a
declared identity epoch (one coordinated re-bless; see the campaign
records under `spec/02-working/`).

---

## Layout

| Path | What |
|------|------|
| `*.cxd` | Top-level fixture suites, one `[test-suite …]` document each |
| `stdlib/*.cxd` | Per-module stdlib suites |
| `llm/*.cxd` | The executable backing for the generated LLM primer (#938). Consumed by `scripts/gen_docs/primer_build.cx`, gated by `make docs-check`. It records diagnostic messages BYTE-EXACT — unlike the suites above, whose `[out-err]` pins the error CODE and not the wording — because the wording is what the primer teaches a reader to recognise. Adds `[cli-argv]` for invocation-level cases. Deliberately NOT a top-level `*.cxd`: the corpus scanners in `vcx/tests/` `os.ls` the root and carry pinned baselines that this suite's contract is not part of. See its own `[doc]` block. |
| `fixtures.cxs` | THE fixture schema (CX schema; suites validate against it) |
| `gates.cxd` | Gate-policy manifest (per-module gate toggles; validated by `scripts/gates_manifest_gate.sh`) |

A suite is an ordinary CX document — the corpus dogfoods the parser on
every load. There is no bespoke text format: the historical
`=== test:` / `--- key` line format and its Python parser are RETIRED
(every consumer reads `.cxd` through a CX parser).

## Fixture format

```
[test-suite name=my-family ring=0
  [doc [# free-text header #]]
  [case id=fam-001-descriptive-name level=core
    [tags conversion toml import]
    [title one-line intent]
    [in-cx [#
<input document, verbatim RawText>
#]]
    [out-cx [#
<expected output, verbatim RawText>
#]]
  ]
]
```

- Section payloads are RawText blocks (`[# … #]`); the loader strips ONE
  leading and ONE trailing newline (the layout newlines around the
  delimiters) and nothing else. A literal `#]` inside a payload arrives
  split across adjacent RawText siblings; loaders MUST rejoin them.
- `#` at line start (outside RawText) is a CX comment; a mid-line `#`
  also opens a comment — never put `#` in `[title …]` prose.
- The full section vocabulary, attribute set, and their semantics live in
  [`fixtures.cxs`](fixtures.cxs) — the schema IS the format spec
  (`schema-mode open`: families may add sections; the common set is
  typed there).

### Reference loaders

- V: `vcx/fixtures/fixture_loader.v` (`fixtures.load_fixtures` /
  `load_suite`)
- Python: `lang/python/cxlib/fixtures.py` · Go: `lang/go/cxlib/fixtures.go`
  · Rust: `lang/rust/cxlib/src/fixtures.rs`

All four reconstruct the same legacy-shaped record (snake_case section
keys: `in_cx`, `out_ast`, …), so runner logic is portable.

## Ring tags

Every suite header carries `ring=N` — the partition lane (0 = data
format, 1 = code, 2 = platform). A case may override with its own
`ring=` (resolution: per-case → per-suite). MIXED suites carry
`eval-ring=` (today: `code.cxd`, `ring=0 eval-ring=1` — the parse/doc
lane is Ring 0, the eval lane Ring 1; the lane is defined by the
consuming gate). A ring's artifact MUST pass every fixture at or below
its ring; the Ring-0 extraction gate additionally requires the extracted
artifacts BYTE-IDENTICAL to the monolith over the Ring-0 lane
(`make test-extraction-gate`).

Query the lanes with `make ring-query` (env: `RING=`, `LANE=`,
`FORMAT=`); `make ring-tag-gate` hard-fails any untagged suite.

## Grading semantics

- `out-text` (eval fixtures) compares against the **normative result
  image** — spec/core/code.md "The evaluation result image"
  (rule EV-RESULT-IMAGE). A `tol=` attribute relaxes numeric equality
  only.
- `out-cx` / `out-xml` / `out-canonical` / … compare exactly after
  stripping leading/trailing blank lines.
- `out-ast` compares AST JSON semantically (key order insignificant;
  scalar types must match — int `30` ≠ float `30.0`).
- `out-err` asserts REJECTION: the operation must fail with an error
  containing the section's text (usually a `CXER****` code).
- `out-hash` asserts the Tier-1 content address (tagged
  `sha2-256:<hex>` form) of the input's strict-canonical bytes.
- `out-effects` (stream 22 W1 — LIVE) asserts the ordered
  admitted-effect-point trace: one `capability:resource` line per
  admission through the capability gate — the resource text is
  whatever the effect point presents to the gate (typically its
  primitive name, e.g. `clock:time-now`; io/store points present the
  requested resource). Exact in order AND count
  (denied effects never execute and never trace — the denial is the
  error channel's evidence). Graded in addition to the value channel.
  Concurrent programs must not assert a total order across tasks
  (interleaving is genuinely nondeterministic) — use per-task
  subsequences or multiset-style matchers.
- Typed assertions (`expect-codes`, `expect-valid`, …) are native CX
  values, not payloads — see `fixtures.cxs`.

### Capability grant policy (eval fixtures — normative)

The runner's grant policy is a three-way rule (it used to be inferred
and undocumented — #707):

1. `grant="cap1 cap2"` on the case → grant EXACTLY those capabilities.
2. No `grant=`, and `out-err` expects `CXER0271` → grant NOTHING
   (denial cases run deny-by-default).
3. No `grant=` otherwise → grant ALL capabilities.

### Gate policy

Per-case `gate=` (enforced | advisory | pending | skip) overrides the
per-module policy in `gates.cxd`; unset everywhere = enforced. Advisory
cases run and report but never block; pending/skip are excluded and
counted.

## Runners and gate lanes (reference implementation)

| Lane | Runner | Make target |
|------|--------|-------------|
| Format/document families | `vcx/tests/runners/conformance/conformance_run.v` | `make -C vcx conform` (per-family: `conform-core`, `conform-xml`, …) |
| diff/lint families | `vcx/tests/runners/diff_lint/diff_lint_conform.v` | `conform-diff`, `conform-lint` |
| streaming-write family | `vcx/tests/runners/streaming_write/streaming_write_run.v` | `conform-streaming-write` |
| code.cxd parse lane (Ring 0) | `vcx/tests/code_parse_fixtures_test.v` | `make test-vcx-suite` |
| code.cxd + stdlib eval lanes (Ring 1+) | `vcx/tests/code_eval_fixtures_test.v` | `make test-vcx-suite` |
| Binding parity (FFI) | `lang/*` harnesses over `binding_api.cxd` + shared families | `make test-binding-api-parity`, `make test-python` / `test-go` / `test-rust` |
| Ring-0 extraction gate | `vcx/tests/runners/extraction_gate/` (ABI + CLI differential) | `make test-extraction-gate` |

## Conformance levels

- **core** — every conforming implementation MUST pass every
  `level=core` case of the families it ships.
- Feature claims are all-or-nothing per family: a binding may not claim
  a family while skipping its cases (gate toggles in `gates.cxd` are
  the reference gate's SEQUENCING instrument, not a conformance
  loophole).

## Reference platform

Fixtures with host-dependent output (`path/separator`,
`locale/default-locale`, `time/system-timezone`, …) assert the POSIX
reference host's values; other platforms are expected to differ and the
suites tag such cases.

## Document API / CXPath / streaming binding contracts

The Layer-1 Document API parity contract is fixtured in
[`binding_api.cxd`](binding_api.cxd) (byte-identical results across
V/Python/Go/Rust through the C ABI). The shared API fixture documents
live at the repo root under `fixtures/` (`api_config.cx`,
`api_article.cx`, `api_scalars.cx`, `api_multi.cx`, `errors/*.cx`,
`stream/*.cx`); the per-language API/CXPath/streaming test suites in
`lang/*` consume them. The behavioral checklists formerly duplicated in
this README live where they are enforced: `binding_api.cxd` (parity
rows) and the per-language suites (API surface), against
spec/bindings.md.
