# Grammar-production → witness traceability map (G16)

**Status:** the stream-14 CONTINUOUS deliverable (corpus audit G16;
partition_corpus_audit.md §7 item 4). Opened 2026-08-14 with the
structure, the correspondence rules, the verified rows, and an HONEST
unmapped census — rows fill by judgment (reading the production against
its witnesses), NEVER by prefix-match (the ruled refusal: a mechanical
prefix pass would manufacture false coverage signal).

## Inputs

- 315 production ids across `grammar.ebnf` + `lexicon.ebnf`
  (`[N]`/`[Na]` grammar rows, `[LN]` lexicon rows).
- `witnesses.txt`: 198 rows across ~30 symbolic families
  (`LX-*` lexicon, `G-*` grammar-shape, `GR-*` grammar-refusal,
  `M-*` mode/document, `EV-*` evaluation).
- The stream-13 review (`spec/_archived/grammar_lexicon_review.md`)
  — the per-production dispositions the judgment rows cite.
- The `rule=` corpus axis (stream 22): EV-rule rows are queryable
  mechanically from `conformance/code.cxd` (`rule=EV-…`).

## Correspondence rules

1. A row maps a PRODUCTION id to the witness families and/or `rule=`
   fixture families that exercise it, with a one-line judgment note.
2. `unmapped` rows are VISIBLE — an unfilled production is listed, never
   silently omitted; the census below is the honest fill state.
3. EV-rule productions (the code.md §Evaluation register) map through
   the `rule=` axis — mechanical BY DESIGN (the id IS the correspondence),
   the one sanctioned non-judgment lane.

## Verified rows (judgment; each checked against the source)

| production | witnesses | note |
|---|---|---|
| `[L20] Number` | `LX-INT-*`, `LX-FLOAT-*` | lexicon.ebnf's own §comment (line ~93/114) defines the number rule against these forms; hex/sign legs in-family |
| `[L21] BoolLiteral` | `LX-BOOL-*` | direct literal family |
| EV register rows (code.md §14) | `rule=EV-LET-SEQ / EV-PULL / EV-BUDGET / EV-EFFECT-SET / EV-SELECT-FAIR / EV-RESULT-IMAGE` fixtures in code.cxd; witnesses.txt `EV-*` kind=eval rows | the stream-22 mechanical axis; per-rule fixture ids queryable by `rule=` |
| `[152]–[152h]` def + command clauses | `cmd-*` family (code.cxd) + `cxast-*` (the AST projection pins the clause fields) | stream-6/18 corpus |
| `[135]/[135a]` BindingPath | `G-BODY`/`GR-BAD-PATH` witnesses + the cxpath fixture families | refusal rows pin the error contract (#472 glued-@ lane) |

## Unmapped census (the continuous remainder)

~300 productions remain unmapped at open. Fill discipline: each session
touching a grammar area adds its rows WITH the work (append-only, same
commit); the census number updates in place. A production with NO
witness after mapping is a REAL coverage gap — file it, never pad it.

Current census: 315 productions; 5 row-groups verified; the rest
UNMAPPED (honest count — no prefix-derived rows).
