# CX-native conformance fixtures — schema DRAFT

**Status:** draft for review · 2026-05-31 · branch `v0.8.0-refactor`

Replaces the bespoke line-delimited fixture format (`=== test:` headers,
`--- key` section dividers — see [README.md](README.md) "File Format") with a
CX document the stock parser reads. Schema: [fixtures.cxs](fixtures.cxs).

This is the dog-food move: we now have a CX processor, so test fixtures stop
being a one-off text format parsed by a hand-rolled ~20-line reader in every
binding and become ordinary CX documents — parsed by `cx`, validated by
`cx validate`, queryable by CXPath.

---

## 1 — Shape

```cx
[test-suite name=core version='1.0' spec-date=2026-04-19
  [doc 'Core conformance — Document, Element, Text, Comment, PI, …']

  [case id=003-element-text level=core
    [tags element text]
    [in-cx [#
[p Hello]
    #]]
    [out-ast [#
{
  "type": "Document",
  "elements": [
    {"type": "Element", "name": "p",
     "items": [{"type": "Text", "value": "Hello"}]}
  ]
}
    #]]
    [out-xml [#
<p>Hello</p>
    #]]
    [out-cx [#
[p Hello]
    #]]
  ]
]
```

- **Suite** → one `[test-suite …]` document per file. `name`/`version`/
  `spec-date` are attributes; an optional `[doc …]` carries the header prose.
- **Case** → `[case …]`. `id` is a bare slug; `level` is a free-form label
  (attributes); `tags` is a space-joined string; an optional `title` holds the
  free-text description; everything else is a *section*. (The legacy `name`
  = `<id-slug> <description>` is split into `id` + `title`.)
- **Section** → a child element whose **tag is the section name** and whose
  body is the section content. Two value shapes (see §2/§3).

Payload content begins on its own line after `[#` and the `#]` closer sits on
its own line — see §2 for why.

The current format's `name:` / `level:` / `tags:` header lines and `--- key`
bodies map 1:1 onto attributes + child sections.

---

## 2 — Verbatim payloads use RawText `[# … #]`

The hard requirement: a section body like `out_ast` holds **literal JSON**;
`in_cx` holds **literal CX source** (full of `[ ] = ' "`); `out_xml` holds
**literal XML**. None of it may be interpreted as CX structure.

CX's raw-text / CDATA form `[# … #]` (grammar rule [31]) is the only fully
verbatim carrier:

- Content is character data — **no** inner-element parsing, **no** escape-
  sequence processing. `\n`, `\`, `'''`, `[`, `]`, `{`, `}` are all literal.
- The single terminator is the two-character sequence `#]`. A bare `]` is
  fine. (`'''…'''` triple-quotes were rejected for payloads: they *do* run
  escape processing, so JSON/regex backslashes would corrupt.)
- Escape hatch for a literal `#]` inside a payload: `#&rsqb;` (rare).

### Loader normalization (the one rule layered on top of raw parsing)

The parser does **not** alter RawText — `[#\n[p Hello]\n#]` parses to the
literal value `"\n[p Hello]\n"`. The fixture loader then applies exactly two
strips before comparison:

1. strip one leading newline (the one after `[#`);
2. strip one trailing newline (the one before `#]`).

**No dedent.** An earlier draft mirrored TripleQuoted's common-leading-
whitespace strip, but that is *lossy* for fixtures: it would also remove a
payload's own indentation (e.g. nested JSON, indented CX). So the convention
is: **payload content starts flush-left, on the line after `[#`, and `#]` sits
on its own line.** With that layout the two-strip rule is byte-exact for any
content — proven by the `_audit_fixture.py` gate (§8; retired with the
migration scaffolding once every legacy `.txt` was converted). Do *not* put
content on the `[#` or `#]` lines (the inline `[# x #]` form leaves stray
spaces the loader won't trim). **This is the only place the fixture format adds
semantics on top of stock CX parsing.**

---

## 3 — Typed assertions use native CX

Sections that are *not* opaque payloads — expected error codes, counts,
pass/fail booleans, severities — become native CX scalars and sequences
instead of stringly-typed text. This is the upgrade the old flat format
couldn't offer:

```cx
[case id=sv-014-purity-codes level=extended
  [tags schema-validate purity]
  [schema-cxs [# …schema… #]]
  [source     [# …document… #]]
  [expect-valid false]
  [expect-codes [:CXER0230, :CXER0233]]
  [expect-count 2]
  [expect-severity error]
]
```

`expect-codes` is a real array of atoms — CXPath can ask
`//case[expect-codes]` and the schema (`fixtures.cxs`) type-checks each entry
as `:atom`, `expect-count` as `int [min 0]`, `expect-valid` as `bool`, etc.
(Note: the validator wants the **array** literal `[…]` for collection bodies,
not the `(…)` sequence literal — see §7.)

The old `sv_expected_codes` / `expected_check_count` / `sv_assert_valid`
text keys collapse onto these.

---

## 4 — Eval fixture (stdlib) conversion

Old (`stdlib_strings.txt`):

```
=== test: strings-001-upper
level: core
tags: strings upper case
--- in_cx
[empty]
--- in_code
[?lib 'cx-stdlib/strings']
[strings/upper "hello"]
--- out_text
HELLO
```

New (the layout the converter emits — payloads flush-left, `#]` on its own line):

```cx
[case id=strings-001-upper level=core
  [tags strings upper case]
  [in-cx [#
[empty]
  #]]
  [in-code [#
[?lib 'cx-stdlib/strings']
[strings/upper "hello"]
  #]]
  [out-text [#
HELLO
  #]]
]
```

---

## 5 — Section vocabulary

The common set is declared in [fixtures.cxs](fixtures.cxs). Because the schema
is `open`, family-specific sections (e.g. `data-bin`'s `arrow-chunk-lengths`,
`schema-validate`'s `sv-assert-valid`) are admitted without amendment; tighten
to `strict` per family later if we want closed validation there.

| old key (snake) | new tag (kebab) | shape |
| --------------- | --------------- | ----- |
| `in_cx` | `in-cx` | payload |
| `in_code` | `in-code` | payload |
| `in_xml` / `input_xml` | `in-xml` | payload |
| `in_a` / `in_b` | `in-a` / `in-b` | payload |
| `source` | `source` | payload |
| `schema_cxs` | `schema-cxs` | payload |
| `out_ast` | `out-ast` | payload |
| `out_xml` | `out-xml` | payload |
| `out_cx` | `out-cx` | payload |
| `out_text` | `out-text` | payload |
| `out_err` | `out-err` | payload |
| `out_md` / `out_json` | `out-md` / `out-json` | payload |
| `events` | `events` | payload |
| (test name, trailing words) | `title` | payload (verbatim) |
| `sv_expected_codes` | `expect-codes` | `[:atom …]` array |
| `sv_expected_warn_codes` | `expect-warn-codes` | `[:atom …]` array |
| `expected_check_count` | `expect-count` | `int` |
| `sv_assert_valid` | `expect-valid` | `bool` |
| `expected_severity` | `expect-severity` | `string` enum |

---

## 6 — Decisions (resolved 2026-05-31)

1. **Tag casing** — **kebab** (`in-cx`). House style §3.4; these become XML
   element names on export.
2. **File extension** — **`.cxd`** (canonical CX text / data — same convention
   as `store.cxd`/`aliases.cxd`). A fixture suite is pure data: no executable
   top-level code (the `in-code` payload is verbatim text, never run). Reserve
   `.cx` for files meant to be evaluated.
3. **`tags` typing** — **space-joined string** body, loader splits on
   whitespace (matches the legacy `tags:` line). Switch to `[list string]` if
   per-tag CXPath querying is ever wanted.
4. **`level` typing** — **free-form string, no enum.** The suite uses ~12
   family-specific level vocabularies (core, extended, must, resilience,
   services, async, md, …); constraining it would reject real fixtures.
5. **`id` vs `title`** — the legacy `name` (`<slug> <free description>`) splits
   into a bare-slug `id` (CXPath-addressable, filename-safe) and a verbatim
   `title`. Required because names carry spaces, quotes, and brackets.
6. **Migration** — via the parse→emit pipeline, never text substitution
   (`_convert_fixture.py`, retired). Payloads are copied verbatim;
   no CX syntax is rewritten. Every conversion was gated by
   `_audit_fixture.py` (§8).

---

## 7 — Validation status & impl gaps found

The schema and a worked two-case suite ([_sample_suite.cx](_sample_suite.cx))
both parse with `cx 0.8.0` and validate clean:

```
$ cx validate conformance/_sample_suite.cx --schema=conformance/fixtures.cxs
$ echo $?
0
```

Three `cx 0.8.0` behaviours used to diverge from `spec/core/schema.md` and
shaped the draft. **All three are now fixed in the V reference
implementation** (conformance fixtures `sv-058`…`sv-061`); the draft's
workarounds can be unwound:

- **`schema-name` directive rejected.** ~~`[?cx schema-name '…']` (spec §2,
  shown in the spec's own example) fails the validator's schema parser with
  `S009: expected name`.~~ **Fixed:** the directive parser now accepts a
  quoted positional argument. Fixture `sv-058`.
- **`schema-version` ceiling is 0.6, not 0.8.** ~~`[?cx schema-version 0.8]`
  (the literal value in the spec §2 example) is rejected `S020`.~~ **Fixed:**
  the supported schema-dialect version tracks the 0.8.0 release. Fixture
  `sv-059`. (`0.7` is still rejected `S020` — see `sv-035`.)
- **Atom enums / atom attr values broken.** ~~`[attr x::atom [enum :a :b]]`
  registers only the *last* atom, and an attr written `x=:a` parses the value
  as the string `'a'`.~~ **Fixed:** the parser no longer eats the first atom
  as a schema slot-label, so every enum member is registered, and atom enum
  members are stored canonically so they compare equal to atom-typed attribute
  values. Fixtures `sv-060` / `sv-061`. Atom values inside a `[list atom]`
  *body* (e.g. `expect-codes`) were always unaffected.

- **Collection bodies require the array literal.** A `[list T]` / `[seq T]`
  body matches the `[a, b]` array literal but **not** the `(a, b)` sequence
  literal (`S005: declared :arr, got :seq`). Draft uses `[…]` for
  `expect-codes`. Not necessarily a bug — but worth a spec note since the two
  literals look interchangeable at the surface.
- **`cx validate` multidoc-detects `---` inside RawText.** A `---` line inside
  a `[#…#]` payload makes `cx validate` bail with "multi-document inputs not yet
  supported", even though `cx --ast` correctly parses the file as a single
  document. Repro: `[test-suite [case [in-cx [#⏎---⏎#]]]]`. Blocks `cx validate`
  on 5 suites (code, code_diagram, md, extended, xml) whose CX examples contain
  multidoc separators. The byte-exact `_audit_fixture.py` gate is unaffected
  (it uses `cx --ast`).
- **RawText `&rsqb;` escape not honored.** `grammar.ebnf` [31] says a literal
  `#]` inside RawText is written `#&rsqb;`, but cx 0.8.0 leaves `&rsqb;`
  literal (no entity resolution in RawText). **Converter workaround:** a `#]`
  in a payload is carried by splitting across adjacent RawText siblings
  (`split_raw`), which needs no escape.
- **Quoted string with brackets + escaped quotes mis-parses.** ~~A body like
  ``[title 'S008 … [pattern \'[a-z]+\']']`` (single-quoted string containing
  `[`, `]` and `\'`) parses as *unterminated quoted text*.~~ **Fixed:** the
  quoted-string readers now decode grammar [11] escape sequences (`\'` no
  longer terminates the string early; `[`/`]` were already atomic inside
  quotes), and the emitter round-trips an embedded `'` by switching to a
  double-quote wrapper. Conformance fixtures `046` / `047` (extended). The
  converter can now carry free text (`title`) as a quoted string instead of
  verbatim RawText `[#…#]`.

---

## 8 — Pilots: two families converted & audited

Both via `_convert_fixture.py` → validated against the
schema → audited byte-exact by `_audit_fixture.py` (which
re-parses the `.cxd` with the real `cx` binary, applies the §2 loader
normalization, and asserts every payload equals the original legacy body):

| family | files | cases | result |
| ------ | ----- | ----- | ------ |
| **stdlib** eval family (`in-cx`/`in-code`/`out-text`/`out-err`) | format, strings, env, uuid, hash, path, random, time, bytes | 456 | all validate clean · all payloads byte-exact |
| **schema_validate** (typed-assertion family) | schema_validate | 57 | validate clean · `114 payloads byte-exact, 57 typed sections match` |

Total: **513 cases across 10 files**, every payload byte-exact, every typed
section semantically equal. (`core.txt` — the `out-ast`/`out-xml`/`out-cx`
triple-payload family — is intentionally not yet converted; it's under
separate audit.)

```
$ python3 conformance/_convert_fixture.py conformance/schema_validate.txt schema-validate \
    > conformance/schema_validate.cxd
$ cx validate conformance/schema_validate.cxd --schema=conformance/fixtures.cxs   # exit 0
$ python3 conformance/_audit_fixture.py \
    conformance/schema_validate.txt conformance/schema_validate.cxd
OK: 57 cases — 114 payloads byte-exact, 57 typed sections match
```

The `schema_validate` family is the structural stress test: it exercised the
typed assertions (`expect-codes` atom arrays, `expect-valid` bool,
`expect-warn-codes`), forced the **`id`/`title` split** (legacy names carry
spaces *and* quotes/brackets), and surfaced the §7 quoted-string parser bug.
For typed sections the audit checks semantic equality (atom-list order,
bool value), not byte equality.

This audit is the gate every future conversion must pass before the legacy
`.txt` is retired.

### Files

| file | role |
| ---- | ---- |
| `fixtures.cxs` | the schema |
| `stdlib_format.cxd`, `schema_validate.cxd` | converted pilot suites |
| `_convert_fixture.py` | RETIRED — legacy `.txt` → `.cxd` (verbatim payloads, typed assertions) |
| `_audit_fixture.py` | RETIRED — byte-exact + semantic round-trip gate |
| `_sample_suite.cx` | hand-written two-case schema demo |

(The `_`-prefixed scripts were review-era scaffolding. The format was
accepted, every legacy `.txt` was converted and then removed — commit
`bed0ee85`, ".cxd is canonical" — so both scripts became spent one-shots
with no possible input left in the tree and were deleted 2026-08-23
(#922 / PYE-5) rather than ported: their only argument is a legacy `.txt`
path, and no Makefile/CI/script references them.)
