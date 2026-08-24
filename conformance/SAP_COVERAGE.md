# SAP errors/effects/fp — Stage-B clause → fixture coverage map

The `COVERAGE` + `RED-COMPLETE` gate evidence: every Stage-A normative clause has
≥ 1 conformance fixture. **G** = grounded (enforced, true today); **A** = advisory
(expected-red, flips enforced when its impl lands in Stage C). Fixtures live in
`conformance/code.cxd` (core) and `conformance/stdlib/fp.cxd` (fp).

> **2026-06-03 audit reconciliation (SAP audit, finding F-C1):** the core
> `sap-*` cases below were marked `A` while Stage C was in flight. Stage C +
> D014 have landed: `conformance/code.cxd` carries **zero** `gate=advisory`
> cases and `code_eval_fixtures_test.v` runs all 65 `sap-*` cases **enforced**
> (unset gate = blocking) and green (suite exit 0, no advisory report). The
> core rows are therefore now **G** (grounded), flipped below. (fp.cxd
> enforcement is tracked separately and was not re-audited here.)

## §8.13 `[?else]` value-or-default (truth table)
| clause | fixtures | gate |
|---|---|---|
| err → default | `program-sap-else-01-err-defaults` | G |
| empty → default | `program-sap-else-02-empty-defaults` | G |
| null passes | `program-sap-else-03-null-passes` | G |
| false/0/''/[]/{} pass (not EBV-coalescing) | `program-sap-else-04..08` | G |
| `[invalid]` passes | `program-sap-else-09-invalid-passes` | G |
| value passes | `program-sap-else-10-value-passes` | G |
| lazy default | `program-sap-else-11-lazy-default` | G |

## §8.2 `[?match]` scrutinee + O1 uniform pattern grammar
| clause | fixtures | gate |
|---|---|---|
| bind-first err catch (V1a) | `program-sap-match-01-catch-bindfirst` | G |
| inline ProgramExpr scrutinee (§9.2-exempt) | `program-sap-match-02-inline-scrutinee` | G |
| wildcard `_` | `program-sap-O1-00-wildcard` | G |
| attr `@a=v` predicate (rule 6) | `program-sap-O1-01-attr-predicate` | G |
| plain `a=v` equality (rule 9, conformance gap) | `program-sap-O1-01p-attr-plain-equality` | G |
| attr capture `@a=$c` (rule 10) | `program-sap-O1-01b-attr-capture` | G |
| map literal (rule 11) | `program-sap-O1-02-map-literal` | G |
| map capture `{k: $x}` | `program-sap-O1-02b-map-capture` | G |
| map rest `{k:v, *$rest}` | `program-sap-O1-02c-map-rest` | G |
| sequence closed-arity (rule 12) | `program-sap-O1-03-seq-closed` | G |
| sequence spread `(1, *$rest)` | `program-sap-O1-03b-seq-spread` | G |
| array literal `[1,$x,3]` (rule 13) | `program-sap-O1-04-array-literal` | G |
| array rest `[1, *$rest]` | `program-sap-O1-04b-array-rest` | G |
| `::T` typed bind / anon (rule 14) — int/str/float/bool/null/atom | `program-sap-O1-05..10` | G |
| attr type-test `@a::T` | `program-sap-O1-11-attr-type-test` | G |
| scalar-spread NON-MATCH (n/a, falls to else) | `program-sap-O1-12-scalar-spread-nonmatch` | G |

## O4 path/@attr distribution over sequence
`program-sap-O4-01-path-over-seq` (G), `-02-empty-in-empty-out` (G), `-03-missing-attr-skipped` (G), `-04-nonelement-skipped` (G).

## O2 `[?fallback]` binds `$err`
`program-sap-O2-01-fallback-binds-err` (G).

## §8.9 `[?pipe]` reshape
| clause | fixtures | gate |
|---|---|---|
| bare stages | `program-sap-pipe-01-bare-stages` | G |
| absence continues (railway on err only) | `program-sap-pipe-02-absence-continues` | G |
| infix `|` removed | `program-sap-pipe-03-infix-removed` | G (neg) |
| `[through]` removed | `program-sap-pipe-04-through-removed` | G (neg) |
| non-callable stage → CXER0100 | `program-sap-pipe-05-noncallable-stage` | G (neg) |
| `[tap]` passes through | `program-sap-pipe-06-tap-passes` | G |
| `[tap]` fn-errors, value survives | `program-sap-pipe-07-tap-error-survives` | G |
| railway short-circuit on err | `program-sap-pipe-08-skip-on-err` | G |
| tap skipped after upstream err | `program-sap-pipe-09-tap-skipped-after-err` | G |

## §8.8/§9.3 `[?try]`/`[catch]`/`[on-error]` retirement
| clause | fixtures | gate |
|---|---|---|
| `[?try]` → unknown directive (neg) | `program-sap-try-01-removed-negative` | G (neg) |
| `[on-error]` → unknown clause (neg) | `program-sap-try-02-on-error-removed-negative` | G (neg) |
| V2: `[on-error]` ≡ yield-body `[?match]` | `program-sap-try-03-onerror-equiv-match` | G |
| catchability: arithmetic / unbound | `program-sap-catch-01-arith`, `program-sap-catch-02-unbound` | G |

## §9.1.2.1 null-totality matrix
`program-sap-null-01-arith-clean-err` (G), `-02-concat-value` (G), `-03-eq` (G), `-04-count` (G), `-05-first` (G).

## §9.1.2 absence cutover — the null/absence catalog (Phase C1)
The no-conflation guard (§9.1.2.1 rule b): no builtin returns `null` for "absent."
Each cataloged absent-null return migrated to the absence channel (the empty
sequence `()`); extraction is `[?else]` (getOrElse, §8.13). These live in the
stdlib `.cxd` files and run enforced under a least-privilege `grant=`.
| catalog site | channel | fixtures | gate |
|---|---|---|---|
| `env:var` unset → absence (`stdlib/env.cxd`) | absence (`()`) | `sap-absence-env-01-var-unset-empty`, `-02-…-count-zero`, `-03-…-else-default` | G |
| `env:var` deny-lane (cap masks the read) | CXER0271 | `env-001-var-cap-denied` | G |
| `store:get-alias` miss → absence (`stdlib/store.cxd`) | absence (`()`) | `store-alias-002-get-missing-absence` (migrated from `-null`), `sap-absence-store-01-alias-miss-else` | G |
| `store:get-alias` HIT still returns the hash (present flows) | value | `sap-absence-store-02-alias-hit-value` | G |
| `process:poll` / `wait-timeout` no-result → absence | absence (`()`) | manual-grant verification (real-spawn nondeterminism; deny-lane = `process-016-poll-cap-denied`, same discipline as the 27 process deny-lane cases) | G |

The `check-null-absence-conflation` standing guard (`scripts/check_null_absence_conflation.cx`,
wired into `make test`) makes the no-conflation guarantee permanent: it fails on
any `[returns [or T null]]` declared-optional-return in the stdlib def surface.

## §10.5.7 structured concurrency — RAII over handles + cancel-revokes-caps (Phase C5)
| clause | fixtures | gate |
|---|---|---|
| §10.5.7.2 check-cancel after cancel → CXER0260 | `program-sap-cancel-01-checkcancel-after-cancel` | G |
| §10.5.7.1 RAII over a future handle (close cancels-and-joins; value preserved) | `program-sap-raii-01-with-open-future` | G |
| §10.5.7.1 RAII over a worker handle | `program-sap-raii-02-with-open-worker` | G |
| §10.5.7.2 cancel revokes caps — raw effect → CXER0271 backstop | `program-sap-revoke-01-cap-revoked-after-cancel` | G |
| §10.5.7.2 precedence — cancellation point ▷ cap (CXER0260, not CXER0271) | `program-sap-revoke-02-cancel-before-cap-precedence` | G |

The CXLS005 §7.3 lint (warn on a `[par]` body calling an impure builtin without
a `[?bulkhead]` wrap) is **retired** (#94): `[par]` now owns its width as a
bounded worker pool — `[par N]` / `[par max]` — so `[?bulkhead]` is no longer the
concurrency-bounding mechanism. The underlying purity helper
`code.node_calls_impure_builtin` is still used (by `cx-stdlib/journal`) and
remains unit-tested in `vcx/tests/purity_checker_test.v`.

## §3 `cx-stdlib/fp` (all advisory — Phase C4)
sequence/Maybe (`fp-001..006`), result railway (`fp-010/011`), E_NO_INSTANCE=CXER4400 (`fp-020`), fold (`fp-030`), laws (`fp-040..042`), traverse/sequence (`fp-050/051`).

## Deferred to Stage C (standing guards / harnesses)
- `check-effect-alignment` (ALIGNMENT gate, Phase C2) — capability-gated ⇒ impure.
- `NO-LEGACY-TRY` / `NO-LEGACY-PIPE` AST-aware guards (Phase C3c / C3a).
- `check-null-absence-conflation` standing scan (Phase C1).
- pipe skip-proof counter harness — the current `program-sap-pipe-08/09` pin the err
  result; the captured-counter probe is added when `[tap]`/log side effects land.
- queryable-instance check + binding-parity (Phase C4/C6).

## §C6 — PARITY across the 4 bindings + the §0.1 docs guardrail (Phase C6)
- **PARITY.** The V eval-fixtures runner (`code_eval_fixtures_test.v`) runs every
  `[case id=…]` in `code.cxd` with no whitelist, so all 65 enforced `sap-*` cases
  are exercised V-side. The Python (`conformance_code.py`) + Go
  (`conformance_code_test.go`) corpus whitelists gained the full 65-id SAP block;
  Rust (`tests/program_eval.rs`, Tier-1 smoke) gained 8 SAP smoke tests (one per
  surface). Numbers: V 80/80, Python 252/252, Go 252/252, Rust 16/16.
- **Two binding-runner fixes (toward the V oracle):** the Python whitelist's stale
  `program-find-*`→`program-for-*` drift (28 fixtures) corrected; both runners now
  check `out_err` against the rendered RETURN (§9.1.2 errors-are-values: an `[err]`
  is a value `eval_code` returns, not necessarily a raise — program-sap-pipe-08/09).
- **§0.1 Tier-1-only docs guardrail** = `scripts/check_docs_tier1_guardrail.cx`,
  wired into `make test` (`TEST_TARGETS`): the beginner sections (quickstart §0 +
  intro §1) are Tier-1-only — no fp.md / monad / functor / typeclass. Standing
  gate (cross-linked from `readiness-rubric.md`).
- **Archived (C6):** the two superseded drafts (`error_handling_posture.md` +
  `scala_gap_closure.md`, in `spec/_archive/` since promotion) tombstone-relinked;
  the superseded Stage-B `sap_fixtures_preview.cxd` moved to `spec/_archive/`.
- **Spec⇄impl gaps logged (SPEC-FINDINGS §AP):** def-body block-comment apostrophe;
  `[?lib [only …]]`/scope/in-memory/version parser-rejected; let-bound single-node
  rebind-then-navigate returns empty. Pre-existing, non-blocking.
- **Graduation:** NOT performed — user-only G3 (the SAP §§ stay in
  `spec/03-accepted-working/`).
