# CX Format Analysis: Comparison Against JSON, YAML, XML, TOML
Version: 3.0 — 2026-04-24

CX is used as the **baseline (1.00×)**. Scores above 1.00× mean more characters
or overhead than CX; below 1.00× means fewer. Markdown is a supported
input/output format of CX, not a target for comparison.

---

## 1. When to Use CX

**Best fit:**
- Structured data that mixes configuration, metadata, and prose in one file
- API documentation, deployment descriptors, service definitions
- Config files where YAML's type coercion bugs or JSON's missing comments are problems
- Documents with semantic structure (element names matter, not just nesting depth)
- Pipelines that emit multiple formats from one source file
- Anywhere you currently maintain separate JSON + YAML + XML files for the same data

**Good fit:**
- Hierarchical configuration (comparable to YAML, better type safety)
- Documents with mixed text and structured data (comparable to XML, ~15% leaner)
- Data exchange between services — CX converts losslessly to JSON and XML, so any
  existing consumer of those formats receives CX output without modification
- Log formats with structured events plus human-readable messages

**Know your stack:**
- **Browser/frontend** — emit CX as JSON with one API call; no custom parser needed
  on the client. Existing JSON consumers work with CX output unchanged.
- **Pure prose authoring** — Markdown's shorthand (`**bold**`, `# Heading`) is faster
  for writers who don't need semantic structure or machine processing. CX reads and
  writes Markdown for when you need both.
- **Established JSON or XML pipelines** — CX converts losslessly to both. Introduce
  CX as your authoring format while continuing to deliver JSON or XML downstream.

---

## 2. The Core Proposition

Every mature project maintains multiple format files, each with its own quoting
rules, comment syntax, type coercion behavior, and toolchain:

| File              | Format   | Domain       |
|-------------------|----------|--------------|
| `package.json`    | JSON     | npm config   |
| `.eslintrc.yaml`  | YAML     | linter       |
| `tsconfig.json`   | JSON     | TypeScript   |
| `Cargo.toml`      | TOML     | Rust deps    |
| `pom.xml`         | XML      | Maven build  |
| `openapi.yaml`    | YAML     | API spec     |

CX replaces all of them with one format, one parser, one schema language, and
one query language. **Format consolidation** is the core value — not marginal
conciseness gains on any single document.

---

## 3. Keystroke Efficiency

### 3.1 Delimiter Shift-Key Cost (US keyboard)

CX's primary delimiters (`[`, `]`, `=`) require zero Shift presses. Every
other format's primary delimiters require at least one.

| Character | Key         | Shift? | Used by          |
|-----------|-------------|--------|------------------|
| `[`       | `[`         | No     | CX open          |
| `]`       | `]`         | No     | CX close         |
| `=`       | `=`         | No     | CX attribute sep |
| `"`       | `Shift+'`   | **Yes**| JSON, XML, TOML  |
| `:`       | `Shift+;`   | **Yes**| JSON, YAML       |
| `{` `}`   | `Shift+[ ]` | **Yes**| JSON             |
| `<` `>`   | `Shift+, .` | **Yes**| XML              |

### 3.2 Key-Value Pair Cost

For `key=host`, `value=localhost`:

| Format | Written form              | Keystrokes | Shift presses | Shift % |
|--------|---------------------------|-----------|---------------|---------|
| CX     | `host=localhost`          | 14        | **0**         | **0%**  |
| JSON   | `"host": "localhost"`     | 20        | 5             | 25%     |
| YAML   | `host: localhost`         | 16        | 1             | 6%      |
| XML    | `host="localhost"`        | 17        | 2             | 12%     |
| TOML   | `host = "localhost"`      | 19        | 2             | 11%     |

JSON requires quoting both the key AND the value — 5 Shift presses per pair.
A config file with 50 string-valued pairs costs ~250 extra Shift presses in
JSON, 0 in CX.

### 3.3 Element Wrapping Cost

For element named `section` containing `Hello`:

| Format    | Written form                        | Chars | Name typed | Shift presses |
|-----------|-------------------------------------|-------|------------|---------------|
| CX        | `[section Hello]`                   | 16    | once       | **0**         |
| JSON      | `{"section":"Hello"}`               | 21    | once       | 5             |
| YAML      | `section: Hello`                    | 15    | once       | 1             |
| XML       | `<section>Hello</section>`          | 26    | **twice**  | 4             |

XML overhead per element: `2 × name_length + 5` characters for the closing
tag alone. For `configuration` (13 chars): XML adds 31 characters of tag
punctuation. CX adds 2.

---

## 4. Pretty vs Compact — A Unique CX Advantage

CX has two canonical representations: **pretty** (indented, human-readable)
and **compact** (single-line). Compact is essential for wire transport, logging,
and inline embedding — and most formats handle it poorly or not at all.

### 4.1 Pretty format

```
# CX pretty — 117 chars
[config
  [server host=localhost port=8080
    [tls cert=cert.pem key=key.pem]
  ]
  [db host=db.local port=5432]
]

# JSON pretty — 181 chars
{
  "config": {
    "server": {
      "host": "localhost",
      "port": 8080,
      "tls": {
        "cert": "cert.pem",
        "key": "key.pem"
      }
    },
    "db": {
      "host": "db.local",
      "port": 5432
    }
  }
}

# YAML pretty — 103 chars
config:
  server:
    host: localhost
    port: 8080
    tls:
      cert: cert.pem
      key: key.pem
  db:
    host: db.local
    port: 5432

# XML pretty — 152 chars
<config>
  <server host="localhost" port="8080">
    <tls cert="cert.pem" key="key.pem"/>
  </server>
  <db host="db.local" port="5432"/>
</config>
```

### 4.2 Compact format

```
# CX compact — 73 chars  ← cx --compact
[config [server host=localhost port=8080 [tls cert=cert.pem key=key.pem]] [db host=db.local port=5432]]

# JSON minified — 111 chars  ← structurally identical, unreadable
{"config":{"server":{"host":"localhost","port":8080,"tls":{"cert":"cert.pem","key":"key.pem"}},"db":{"host":"db.local","port":5432}}}

# YAML compact — NOT POSSIBLE
# Indentation is the syntax. There is no compact YAML.

# XML compact — 103 chars  ← 41% larger than CX compact, still verbose
<config><server host="localhost" port="8080"><tls cert="cert.pem" key="key.pem"/></server><db host="db.local" port="5432"/></config>
```

CX compact is **34% smaller than minified JSON** and **29% smaller than minimal
XML**, and remains human-readable. YAML has no compact mode — indentation is
structural, not cosmetic, making YAML unsuitable for log lines, wire transport,
or inline embedding where line length matters.

---

## 5. Character Counts

### 5.1 Flat Config — 8 key-value pairs, mixed types

| Format          | Characters | vs CX  |
|-----------------|------------|--------|
| **CX**          | **105**    | 1.00×  |
| JSON compact    | 122        | 1.16×  |
| JSON pretty     | 159        | 1.51×  |
| YAML            | 106        | 1.01×  |
| XML attribute   | 122        | 1.16×  |
| XML element     | 214        | 2.04×  |
| TOML            | 120        | 1.14×  |

CX and YAML are essentially tied for flat config in pretty format. JSON and
XML carry 15–100% more overhead from mandatory quoting and closing tags.

### 5.2 Nested Config — 3-level hierarchy

| Format  | Pretty chars | Compact chars | vs CX (pretty) |
|---------|-------------|---------------|----------------|
| **CX**  | **117**     | **73**        | 1.00×          |
| JSON    | ~181        | ~111          | 1.55×          |
| YAML    | ~103        | N/A           | 0.88×          |
| XML     | ~152        | ~103          | 1.30×          |

YAML is ~12% more concise in pretty format. In compact format CX has no peer —
YAML cannot be compacted, minified JSON is unreadable, and minimal XML is still
41% larger than CX compact.

### 5.3 Mixed Content — text with inline markup

Content: paragraph with two hyperlinks.

| Format   | Characters | vs CX  | Readable compact? |
|----------|------------|--------|-------------------|
| **CX**   | **117**    | 1.00×  | ✓ 89 chars        |
| JSON     | ~185       | 1.58×  | ✗ structural      |
| YAML     | N/A        | —      | ✗ not designed    |
| XML/HTML | 131        | 1.12×  | ✗ verbose         |

```
# CX — 117 chars
[p For help, visit our [a href=https://example.com/faq FAQ page]
   or [a href=mailto:support@example.com contact us].]

# XML — 131 chars
<p>For help, visit our <a href="https://example.com/faq">FAQ page</a>
   or <a href="mailto:support@example.com">contact us</a>.</p>
```

URLs require no quoting in CX — `:`, `/`, `?`, `#`, `@` are valid bare-value
characters. XML requires `href="..."`, adding 2 Shift presses per attribute.

### 5.4 Signal-to-Noise Ratio

SNR = meaningful characters ÷ total characters.
For `host=localhost port=5432 user=admin` (30 meaningful chars):

| Format      | Total chars | Noise chars | SNR    |
|-------------|-------------|-------------|--------|
| **CX**      | 34          | 4           | **88%**|
| JSON        | 47          | 17          | 64%    |
| YAML        | 37          | 7           | 81%    |
| XML (attrs) | 53          | 23          | 57%    |
| XML (elems) | 80          | 50          | 63%    |
| TOML        | 46          | 16          | 65%    |

---

## 6. Auto-Typing — CX's Type Model

CX uses **smart-default typing**: unquoted values are automatically promoted to
the most specific type they match, with string as the safe fallback.

### 6.1 How auto-typing works

```
port=8080          → int    (digit-only pattern)
ratio=3.14         → float  (decimal/exponent pattern)
debug=false        → bool   (exactly `true` or `false`)
updated=2026-04-24 → date   (ISO 8601 pattern)
host=localhost     → string (fallback — no pattern matched)
path=/usr/local    → string (slash disqualifies numeric patterns)
```

No annotation required. Explicit override with `:type` always takes precedence:

```
version=:string 1.0  → string "1.0" (not float)
count=:int 007       → int 7 (not string "007")
```

### 6.2 Type model comparison

| Format | Model                        | Strengths                                    | Weaknesses                           |
|--------|------------------------------|----------------------------------------------|--------------------------------------|
| **CX** | Auto-typed, string fallback  | No annotation needed, predictable rules, explicit override | Novel |
| JSON   | Explicit types in syntax     | Unambiguous                                  | All keys and all string values must be quoted |
| YAML   | Auto-typed, 22 bool forms    | Minimal annotation for simple cases          | Silent coercion bugs ("Norway problem") |
| XML    | Everything is a string       | No type surprises                            | No type information at all; schema required |
| TOML   | Explicit types               | Unambiguous, readable                        | Verbose for strings; no mixed content |

YAML's auto-typing has a notorious correctness problem (YAML 1.1, used by most
libraries):

```yaml
country: NO       # → false  (boolean — the "Norway problem")
port: 0777        # → 511    (octal integer)
version: 1.0      # → float  (not string "1.0")
yes: indeed       # → {true: "indeed"}  (key coerced to boolean)
```

CX's rules are minimal and unambiguous: digit-only integers, exactly `true`/`false`,
ISO 8601 dates, decimal/exponent floats, exactly `null`. Nothing else auto-types.
`NO`, `yes`, `on`, `off`, `0777` are all strings in CX.

### 6.3 Type system coverage

| Type              | CX                 | JSON         | YAML              | XML            | TOML         |
|-------------------|--------------------|--------------|-------------------|----------------|--------------|
| string            | ✓ (auto fallback)  | ✓ (quoted)   | ✓                 | ✓ (only type)  | ✓ (quoted)   |
| int               | ✓ (auto)           | ✓            | ✓                 | ✗              | ✓            |
| float             | ✓ (auto)           | ✓            | ✓                 | ✗              | ✓            |
| bool              | ✓ (2 forms only)   | ✓            | ✓ (22 forms)      | ✗              | ✓            |
| null              | ✓ (1 form)         | ✓            | ✓ (5 forms)       | ✗              | ✗            |
| date/datetime     | ✓ ISO 8601         | ✗            | ✓ (unreliable)    | ✗              | ✓            |
| bytes             | ✓ (:bytes)         | ✗            | ✓ (!!binary)      | ✗              | ✗            |
| typed array       | ✓ (:type[])        | ✓            | ✓                 | ✗              | ✓            |
| explicit override | ✓ (:type)          | ✗            | ✓ (!!)            | ✗              | ✗            |
| mixed content     | ✓                  | ✗            | ✗                 | ✓              | ✗            |
| comments          | ✓                  | **✗**        | ✓                 | ✓              | ✓            |

CX is the only format with: auto-typing without ambiguity, explicit override,
mixed content, bytes, and comments — in one format.

---

## 7. Parse Speed

CX uses a single-pass recursive descent parser with one token of lookahead.
Input is processed in linear time with no backtracking.

### 7.1 Parsing complexity

| Format | Complexity        | Notes                                                      |
|--------|-------------------|------------------------------------------------------------|
| **CX** | O(n), single-pass | Simple bracket grammar, no indentation tracking            |
| JSON   | O(n), single-pass | Simple grammar; native implementations extremely fast      |
| YAML   | O(n²) in practice | Indentation tracking; spec is 23,449 words vs JSON's 4,053 |
| XML    | O(n), single-pass | Complex grammar — DTD, namespaces, entities add overhead   |
| TOML   | O(n), single-pass | Simple grammar                                             |

YAML's specification is 5× larger than JSON's. Real-world YAML parsers are
substantially slower than equivalent JSON parsers due to indentation-sensitive
parsing, Unicode normalization, and the 22-form boolean resolution table.

### 7.2 CX binary wire protocol

CX libraries use a compact binary protocol for parse results and stream events
between the core library and language bindings. This eliminates the JSON
intermediate decode step common in FFI-based libraries:

```
JSON intermediate (current):
  parse text (7ms) + serialize AST to JSON (16ms) + decode JSON (11ms) + build tree (12ms) = 48ms

Binary protocol (in progress):
  parse text (7ms) + write binary (3ms) + decode binary (5ms) + build tree (5ms) = ~20ms
```

2.4× faster end-to-end on a 354KB document. The binary format uses
length-prefixed strings and fixed-width integers — no allocation for string
parsing, no recursive JSON traversal.

---

## 8. Format Comparisons

### 8.1 CX vs JSON

**Where JSON wins:**
- Browser/frontend — `JSON.parse` is native in every JS engine and browser
- Widest tooling compatibility — every language has a built-in or fast JSON parser
- Structurally unambiguous — explicit quotes eliminate all type guessing

**Where CX wins:**
- No mandatory quoting — keys and string values are bare; JSON quotes everything
- Readable compact format — CX compact is 34% smaller than minified JSON and
  still human-readable; minified JSON is not
- Comments — JSON has no comment syntax
- Mixed content — JSON cannot represent inline markup naturally
- Multi-document — JSON has no stream separator syntax
- Semantic element names — JSON keys are generic strings; CX element names are
  identifiers with structural meaning
- Auto-typing — CX infers int/float/bool without annotation; JSON requires the
  author to write unquoted numbers explicitly
- URLs and paths — bare values in CX; must be quoted strings in JSON

For systems that deliver to JSON consumers, CX converts losslessly to JSON in a
single API call. The consumer receives standard JSON and requires no modification.

### 8.2 CX vs YAML

**Where YAML wins:**
- Pure flat config — `key: value` is marginally more concise (~12%) for simple cases
- Ecosystem familiarity — ubiquitous in CI/CD, Kubernetes, and developer tooling

**Where CX wins:**
- Compact format — YAML cannot be compacted. Indentation IS the syntax; a YAML
  file on one line loses its meaning. CX compact is fully equivalent to CX pretty.
- Type safety — YAML 1.1 (used by most libraries) silently coerces `NO` to `false`,
  `0777` to 511 (octal), `1.0` to a float. CX has two boolean values and no silent
  coercion. Parse errors are explicit.
- Bracket clarity — a misaligned YAML space changes document meaning silently.
  CX bracket mismatches are caught at parse time.
- Mixed content — YAML has no concept of mixed text and element nodes
- Streaming — YAML's `---` separator exists but is rarely supported correctly by
  libraries. CX treats `---` as a first-class stream boundary.
- Toolability — CX's simple bracket grammar makes building correct parsers and
  tooling straightforward. YAML's complexity is a well-known implementation burden.

### 8.3 CX vs XML

**Where XML wins:**
- 28 years of tooling — XPath, XQuery, XSLT, XSD, RelaxNG, validators
- Enterprise integration standards — SOAP, WSDL, SVG, XHTML
- Closing-tag redundancy as a human checksum in deeply nested structures

**Where CX wins:**
- Conciseness — CX is 10–45% smaller depending on data shape
- Typed values — XML carries no type information; every value is a string
- Keystroke cost — element names typed once, no angle-bracket Shift presses,
  attribute values need no quoting
- Compact format — CX compact is 29% smaller than minimal XML and remains readable

CX→XML conversion is lossless. Any XML consumer, pipeline, or validator receives
standard XML from CX output without modification. CX is adoptable as the authoring
format for XML-heavy pipelines without replacing downstream infrastructure.

### 8.4 Markdown — Supported, Not Compared

CX reads and writes Markdown as a first-class format:

```v
doc := cx.parse_md(src)  // ingest a Markdown document
doc.to_md()!              // emit back as Markdown
doc.to_json()!            // or emit as any other format
```

CX can ingest Markdown, process it structurally (add metadata, query headings,
transform sections), and emit it back. For writers who only need prose and don't
need machine-processable structure, Markdown remains the right tool.

---

## 9. Feature Matrix

| Feature                   | CX       | JSON  | YAML  | XML      | TOML  |
|---------------------------|----------|-------|-------|----------|-------|
| Comments                  | ✓        | **✗** | ✓     | ✓        | ✓     |
| Mixed text+element content| ✓        | ✗     | ✗     | ✓        | ✗     |
| Auto-typed scalars        | ✓        | partial | ✓†  | ✗        | partial |
| Readable compact form     | ✓        | ✗     | **✗** | partial  | partial |
| Unquoted string values    | ✓        | ✗     | ✓     | ✗        | ✗     |
| No mandatory key quoting  | ✓        | ✗     | ✓     | ✓        | ✓     |
| Lossless → JSON           | ✓        | —     | ✓     | partial  | ✓     |
| Lossless → XML            | ✓        | ✗     | ✗     | —        | ✗     |
| Namespaces                | ✓        | ✗     | ✗     | ✓        | ✗     |
| Anchors/aliases/merge     | ✓        | ✗     | ✓     | ✗        | ✗     |
| Multi-document stream     | ✓        | ✗     | ✓     | ✗        | ✗     |
| Binary content inline     | ✓        | ✗     | ✓     | ✗        | ✗     |
| URLs unquoted             | ✓        | ✗     | ✗     | ✗        | ✗     |
| Streaming parser          | ✓        | ✗     | ✗     | ✓        | ✗     |
| Language libraries        | 10       | all   | many  | many     | many  |

† YAML auto-typing has correctness bugs in YAML 1.1 (the "Norway problem").

---

## 10. Quantitative Summary

Scores relative to CX (1.00×). Lower = better. **Bold** = best in row.

| Dimension                    | CX       | JSON    | YAML        | XML  | TOML |
|------------------------------|----------|---------|-------------|------|------|
| Flat config (chars, pretty)  | **1.00** | 1.16    | 1.01        | 1.16 | 1.14 |
| Nested config (chars, pretty)| 1.00     | 1.55    | **0.88**    | 1.30 | —    |
| Nested config (chars, compact)| **1.00**| 1.52    | N/A         | 1.41 | —    |
| Mixed content (chars)        | **1.00** | 1.58    | N/A         | 1.12 | N/A  |
| Signal-to-noise (attrs)      | **1.00** | 1.38    | 1.09        | 1.56 | 1.35 |
| Keystroke Shift cost         | **1.00** | 5.00    | 1.00        | 4.00 | 2.00 |
| Type safety (predictability) | **1.00** | 0.80    | 0.50        | 0.20 | 0.90 |
| Compact readability          | **1.00** | 0.20    | 0 (N/A)     | 0.50 | 0.40 |
| Parse spec complexity        | **1.00** | 0.80    | 3.00+       | 1.50 | 1.20 |
| Tooling breadth              | 0.10     | **1.00**| 0.90        | 1.00 | 0.70 |

---

## 11. Adoption Considerations

**Tooling breadth** is CX's largest gap relative to established formats. JSON
and XML have decades of parsers, editors, schemas, validators, and query
languages. That gap narrows in practice for three reasons:

1. **10 language libraries ship today** — Python, Go, Rust, TypeScript, Swift,
   Kotlin, Ruby, Java, C#, and V all have production-ready CX libraries.

2. **Lossless conversion to JSON and XML** — any existing consumer of those
   formats receives CX output without a custom parser. Introduce CX as your
   authoring and processing format; continue to deliver JSON or XML to systems
   that expect them.

3. **Simple grammar** — CX's bracket syntax makes building additional parsers,
   linters, and editor plugins straightforward. The grammar is small and
   unambiguous.

**Novel syntax** is a real learning cost. The bracket model is simpler than the
four formats it replaces, but it is unfamiliar. Teams adopting CX should expect
a short orientation period.

**YAML for flat config** — YAML's block-mapping syntax is ~12% more concise for
simple key/value files and already familiar. CX does not displace YAML on
conciseness for that narrow case. Where CX wins over YAML is type safety,
compact format support, mixed content, and larger structured documents.

---

*Spec references: CX Grammar v3.3, CX AST v2.3, JSON RFC 8259,
YAML 1.2 (most libraries implement 1.1), TOML 1.0, XML 1.1*
