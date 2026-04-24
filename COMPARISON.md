# CX Format Analysis: Comparison Against XML, JSON, YAML, TOML
Version: 2.0 — 2026-04-24

CX is used as the **baseline (1.00×)**. Scores above 1.00× mean more characters
or overhead than CX; below 1.00× means fewer. This document compares CX against
the four formats it most closely overlaps with. Markdown is a supported
input/output format of CX, not a competitor — it is included where relevant for
completeness but not as a primary target.

---

## 1. When to Use CX

**Best fit — use CX:**
- Structured data that mixes configuration, metadata, and prose in one file
- API documentation, deployment descriptors, service definitions
- Config files where YAML's type coercion bugs or comment-less JSON are problems
- Documents with semantic structure (element names matter, not just nesting depth)
- Pipelines that need to emit multiple formats from one source file
- Anywhere you currently maintain separate JSON + YAML + XML files for the same data

**Good fit — CX works well:**
- Hierarchical configuration (comparable to YAML, better type safety)
- Document formats with mixed text and structured data (comparable to XML, ~15% leaner)
- Data exchange between services that currently use XML
- Log formats with structured events plus human-readable messages

**Poor fit — use something else:**
- **Browser/frontend API transport** → use JSON. `JSON.parse` is native in every
  browser and JS runtime. CX cannot compete here until it has a widely bundled
  WASM parser.
- **Pure prose authoring** → use Markdown. `**bold**` is faster to type than
  `[b bold]` for writers who don't need semantic structure or machine processing.
- **Maximum interoperability today** → use JSON or YAML. Every tool chain
  already handles them. CX has zero pre-built ecosystem.

---

## 2. The Core Proposition

Every mature project currently maintains multiple format files:

| File              | Format   | Domain       |
|-------------------|----------|--------------|
| `package.json`    | JSON     | npm config   |
| `.eslintrc.yaml`  | YAML     | linter       |
| `tsconfig.json`   | JSON     | TypeScript   |
| `Cargo.toml`      | TOML     | Rust deps    |
| `pom.xml`         | XML      | Maven build  |
| `openapi.yaml`    | YAML     | API spec     |

Each format has its own quoting rules, comment syntax (JSON has none), type
coercion behavior, error vocabulary, and toolchain. CX's value proposition is
**format consolidation**: one format covering all domains with one mental model,
one parser, one schema language, one query language.

---

## 3. Keystroke Efficiency

### 3.1 Delimiter Shift-Key Cost (US keyboard)

| Character | Key         | Shift required? |
|-----------|-------------|-----------------|
| `[`       | `[`         | No              |
| `]`       | `]`         | No              |
| `=`       | `=`         | No              |
| `{`       | `Shift+[`   | **Yes**         |
| `}`       | `Shift+]`   | **Yes**         |
| `"`       | `Shift+'`   | **Yes**         |
| `:`       | `Shift+;`   | **Yes**         |
| `<`       | `Shift+,`   | **Yes**         |
| `>`       | `Shift+.`   | **Yes**         |

CX's primary delimiters (`[`, `]`, `=`) require zero Shift presses. Every
other format's primary delimiters require at least one.

### 3.2 Key-Value Pair Cost

For `key=host`, `value=localhost`:

| Format | Written form              | Keystrokes | Shift presses | Shift % |
|--------|---------------------------|-----------|---------------|---------|
| CX     | `host=localhost`          | 14        | 0             | 0%      |
| YAML   | `host: localhost`         | 16        | 1 (`:`)       | 6%      |
| TOML   | `host = "localhost"`      | 19        | 2             | 11%     |
| JSON   | `"host": "localhost"`     | 20        | 5             | 25%     |
| XML    | `host="localhost"`        | 17        | 2             | 12%     |

JSON requires quoting both the key AND the value — 5 Shift presses for a single
pair. CX requires none. At scale, across a config file with 50 key-value pairs,
JSON costs ~250 Shift presses that CX costs 0.

### 3.3 Element Wrapping Cost

For element named `section` containing `Hello`:

| Format    | Written form                        | Chars | Name typed | Shift presses |
|-----------|-------------------------------------|-------|------------|---------------|
| CX        | `[section Hello]`                   | 16    | once       | 0             |
| XML       | `<section>Hello</section>`          | 26    | **twice**  | 4             |
| JSON      | `{"section":"Hello"}`               | 21    | once       | 5             |
| YAML      | `section: Hello`                    | 15    | once       | 1             |

XML requires typing the element name twice. The overhead per XML element is
`2 × name_length + 5` characters just for the closing tag. For a 13-character
name like `configuration`: XML adds 31 characters of tag punctuation. CX adds 2.

---

## 4. Pretty vs Compact — A Unique CX Advantage

Most formats have one canonical representation. CX has two: **pretty** (indented,
human-readable) and **compact** (single-line, minimal whitespace). This matters
because compact format is essential for wire transport, logging, and inline
embedding — and most formats handle it poorly.

### 4.1 The same data in pretty format

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

### 4.2 The same data in compact format

```
# CX compact — 73 chars  ← cx --compact
[config [server host=localhost port=8080 [tls cert=cert.pem key=key.pem]] [db host=db.local port=5432]]

# JSON minified — 111 chars  ← still unreadable
{"config":{"server":{"host":"localhost","port":8080,"tls":{"cert":"cert.pem","key":"key.pem"}},"db":{"host":"db.local","port":5432}}}

# YAML compact — NOT POSSIBLE
# Indentation is the syntax. There is no compact YAML.

# XML compact — 103 chars  ← still requires closing tags or verbose self-close
<config><server host="localhost" port="8080"><tls cert="cert.pem" key="key.pem"/></server><db host="db.local" port="5432"/></config>
```

CX compact at 73 characters is **34% smaller than minified JSON** and **29% smaller
than minimal XML**, and remains human-readable. YAML has no compact mode at all —
indentation is structural, not cosmetic. This makes YAML unsuitable for log lines,
inline embedding, or wire transport where line length matters.

---

## 5. Character Counts — Pretty Format

### 5.1 Flat Config — 8 key-value pairs, mixed types

| Format          | Characters | vs CX  |
|-----------------|------------|--------|
| CX              | **105**    | 1.00×  |
| YAML            | 106        | 1.01×  |
| TOML            | 120        | 1.14×  |
| JSON compact    | 122        | 1.16×  |
| JSON pretty     | 159        | 1.51×  |
| XML attribute   | 122        | 1.16×  |
| XML element     | 214        | 2.04×  |

CX and YAML are essentially tied for flat config in pretty format. JSON and
XML carry 15–100% more overhead.

### 5.2 Nested Config — 3-level hierarchy

| Format  | Pretty chars | Compact chars | vs CX (pretty) |
|---------|-------------|---------------|----------------|
| CX      | **117**     | **73**        | 1.00×          |
| YAML    | ~103        | N/A           | 0.88×          |
| XML     | ~152        | ~103          | 1.30×          |
| JSON    | ~181        | ~111          | 1.55×          |

YAML is ~12% more concise than CX in pretty format. In compact format, CX has
no peer — YAML cannot be compacted, JSON minified is unreadable, XML minified
is still 41% larger than CX compact.

### 5.3 Mixed Content — text with inline markup

Content: paragraph with two hyperlinks.

| Format   | Characters | vs CX  | Readable compact? |
|----------|------------|--------|-------------------|
| CX       | **117**    | 1.00×  | ✓ 89 chars        |
| XML/HTML | 131        | 1.12×  | ✗ verbose         |
| JSON     | ~185       | 1.58×  | ✗ structural      |
| YAML     | N/A        | —      | ✗ not designed    |

```
# CX — 117 chars
[p For help, visit our [a href=https://example.com/faq FAQ page]
   or [a href=mailto:support@example.com contact us].]

# XML — 131 chars
<p>For help, visit our <a href="https://example.com/faq">FAQ page</a>
   or <a href="mailto:support@example.com">contact us</a>.</p>
```

Note: URLs require no quoting in CX — `:`, `/`, `?`, `#`, `@` are valid in
bare values. XML requires `href="..."`, adding 2 Shift presses per link.

### 5.4 Signal-to-Noise Ratio

SNR = meaningful characters ÷ total characters.
For `host=localhost port=5432 user=admin` (30 meaningful chars):

| Format      | Total chars | Noise chars | SNR    |
|-------------|-------------|-------------|--------|
| CX          | 34          | 4           | **88%**|
| YAML        | 37          | 7           | 81%    |
| TOML        | 46          | 16          | 65%    |
| JSON        | 47          | 17          | 64%    |
| XML (attrs) | 53          | 23          | 57%    |
| XML (elems) | 80          | 50          | 63%    |

---

## 6. Auto-Typing — CX's Type Model

CX's type system is often misunderstood. It is not "string by default with no
typing." It is **smart-default typing**: unquoted values are automatically
promoted to the most specific type they match, with string as the fallback.

### 6.1 How auto-typing works

```
port=8080          → int (digit-only pattern)
ratio=3.14         → float (decimal/exponent pattern)
debug=false        → bool (exactly `true` or `false`)
updated=2026-04-24 → date (ISO 8601 date pattern)
host=localhost     → string (nothing else matched)
path=/usr/local    → string (slash disqualifies other patterns)
```

No annotation required. The type is inferred from the value's shape, not its
position in the document. Explicit override with `:type` always takes precedence:

```
version=:string 1.0    → string "1.0" (not float)
count=:int 007         → int 7 (not "007")
```

### 6.2 Comparison to other formats

| Format | Type model                  | Strengths                          | Weaknesses |
|--------|-----------------------------|------------------------------------|------------|
| CX     | Auto-typed, string fallback | Minimal annotation, predictable rules, explicit override | Novel |
| XML    | Everything is a string      | No surprises                       | No types at all; schema required for types |
| JSON   | Explicit types in syntax    | Unambiguous                        | All keys and string values must be quoted |
| YAML   | Auto-typed, 22 bool forms   | Minimal annotation for simple cases | "Norway problem" — `NO` is `false`, `0777` is octal |
| TOML   | Explicit types              | Unambiguous, readable              | Verbose for strings; no mixed content |

XML carries zero type information — every attribute value and text node is a
string. Consumers must apply an external schema to get typed values. CX
produces typed values directly from the document.

YAML's auto-typing has a notorious correctness problem (YAML 1.1):

```yaml
country: NO       # → false (boolean — the "Norway problem")
port: 0777        # → 511 (octal integer!)
version: 1.0      # → float, not string "1.0"
yes: indeed       # → {true: "indeed"} (key coerced to boolean)
```

CX's rules are minimal and unambiguous: integer digits only, exact `true`/`false`,
ISO 8601 dates, decimal/exponent floats, exactly `null`. Nothing else is
auto-typed. `NO`, `yes`, `on`, `off`, `0777` are all strings in CX.

### 6.3 Type system coverage

| Type         | XML    | JSON  | YAML  | TOML  | CX           |
|--------------|--------|-------|-------|-------|--------------|
| string       | all values | ✓ (quoted) | ✓ | ✓ (quoted) | ✓ (auto fallback) |
| int          | ✗      | ✓     | ✓     | ✓     | ✓ (auto)     |
| float        | ✗      | ✓     | ✓     | ✓     | ✓ (auto)     |
| bool         | ✗      | ✓     | ✓ (22 forms) | ✓ | ✓ (2 forms only) |
| null         | ✗      | ✓     | ✓ (5 forms) | ✗  | ✓ (1 form)   |
| date/datetime| ✗      | ✗     | ✓ (unreliable) | ✓ | ✓ ISO 8601  |
| bytes        | ✗      | ✗     | ✓ (!!binary) | ✗ | ✓ (:bytes)  |
| typed array  | ✗      | ✓     | ✓     | ✓     | ✓ (:type[])  |
| explicit override | ✗ | ✗     | ✓ (!!) | ✗    | ✓ (:type)    |
| mixed content| ✓      | ✗     | ✗     | ✗     | ✓            |
| comments     | ✓      | **✗** | ✓     | ✓     | ✓            |

CX is the only format with: auto-typing without ambiguity, explicit override,
mixed content, bytes, and comments — all in one format.

---

## 7. Parse Speed

CX is designed for single-pass recursive descent parsing with no backtracking.
The parser maintains one token of lookahead and processes the input in linear
time.

### 7.1 Parsing complexity by format

| Format | Parser complexity | Notes |
|--------|------------------|-------|
| CX     | O(n), single-pass | Simple bracket grammar, no indentation tracking |
| JSON   | O(n), single-pass | Simple grammar; native implementations extremely fast |
| XML    | O(n), single-pass | Complex grammar (DTD, namespaces, entities add overhead) |
| TOML   | O(n), single-pass | Simple grammar |
| YAML   | O(n²) in practice | Indentation tracking, complex spec (23,449-word spec vs JSON's 4,053) |

YAML's specification is 5× larger than JSON's. Real-world YAML parsers are
substantially slower than JSON parsers for equivalent data volumes due to the
complexity of indentation-sensitive parsing, Unicode handling, and the 22-form
boolean resolution table.

### 7.2 CX binary wire protocol

When used as a wire format between a CX library and language bindings, CX uses
a compact binary protocol for parse results and stream events — not the text
format. This eliminates the JSON-intermediate decode step that most FFI-based
libraries use:

```
JSON intermediate path (current):
  parse text (7ms) → serialize AST to JSON (16ms) → language decode JSON (11ms) → build tree (12ms)
  total: 48ms for a 354KB document

Binary protocol path (in progress):
  parse text (7ms) → write binary AST (3ms) → language decode binary (5ms) → build tree (5ms)
  total: ~20ms — 2.4× faster end-to-end
```

The binary protocol uses length-prefixed strings, fixed-width integers, and
a flat event sequence — decoding requires no allocation for string parsing and
no recursive JSON traversal.

---

## 8. Detailed Format Comparisons

### 8.1 CX vs JSON

**JSON wins for:**
- Browser/frontend transport — `JSON.parse` is native in every JS engine
- Maximum tooling compatibility — every language has a JSON parser
- Unambiguous structure — explicit quotes eliminate all type guessing

**CX wins for:**
- Config files — no mandatory quoting of keys or string values
- Readable compact format — CX compact is 34% smaller than minified JSON and still readable
- Comments — JSON has no comment syntax whatsoever
- Mixed content — JSON cannot represent inline markup naturally
- Multi-document — JSON has no stream/separator syntax
- Element names — JSON's keys are generic; CX's element names are semantic identifiers
- Auto-typing — CX infers int/float/bool; JSON requires the author to write unquoted numbers
- URLs and paths — bare values in CX; must be quoted strings in JSON

The mandatory-quoting rule is JSON's largest ergonomic cost. Every key and
every string value requires two Shift presses for the surrounding `"..."`.
A config file with 50 string-valued keys costs 200 extra Shift presses in JSON
that CX costs 0. At scale, across a codebase, this is a meaningful difference
in typing effort.

### 8.2 CX vs YAML

**YAML wins for:**
- Pure flat config — YAML's `key: value` is marginally more concise than CX's attribute form
- Familiarity — YAML is ubiquitous in CI/CD, Kubernetes, and developer tooling

**CX wins for:**
- Compact format — YAML cannot be compact. Indentation is structural, not cosmetic.
  A YAML file cannot be put on one line without losing its meaning. CX compact
  is fully equivalent to CX pretty.
- Type safety — YAML 1.1 (used by most libraries) has 22 boolean forms and
  silent coercion. CX has exactly 2 (`true`/`false`) and fails explicitly on
  anything else.
- Mixed content — YAML has no concept of mixed text and element nodes
- Bracket clarity — YAML nesting errors (wrong indentation) are silent and
  semantically significant. CX bracket mismatches are caught at parse time.
- Streaming — YAML's `---` multi-document separator exists but is rarely
  supported correctly by libraries. CX treats `---` as a first-class stream boundary.
- Toolability — YAML's complex spec makes it hard to build correct parsers.
  CX's simple bracket grammar makes parsing and tooling straightforward.

YAML's indentation sensitivity is its most dangerous property for config files
in production. A single misaligned space changes the document's meaning
silently. Tabs vs spaces errors are caught by some parsers and silently accepted
by others. CX bracket syntax makes nesting explicit and error-detectable.

### 8.3 CX vs XML

**XML wins for:**
- 28 years of tooling — XPath, XQuery, XSLT, schemas (XSD, RelaxNG), validators
- Enterprise integration standards (SOAP, WSDL, SVG, XHTML)
- Closing-tag redundancy as a human checksum for deep nesting

**CX wins for:**
- Conciseness — CX is 10–45% smaller than XML depending on data shape
- Auto-typing — XML carries no types; every value is a string
- Keystroke overhead — XML requires closing tags (element name typed twice),
  mandatory quoting of all attribute values, angle-bracket Shift presses
- Compact format — CX compact is 29% smaller than minimal XML and readable
- Comments — CX comments use the same element syntax (`[-comment text]`);
  XML comments `<!-- -->` require Shift-heavy delimiter typing

CX is designed as an XML successor: any XML document can be expressed in CX
with equivalent semantics. CX→XML conversion is lossless. This makes CX
adoptable as a drop-in improvement for XML-heavy pipelines.

### 8.4 Markdown — Supported, Not Competed With

CX is not a Markdown replacement. CX supports Markdown as a first-class input
and output format. You can:

```v
doc := cx.parse_md(markdown_src)  // read Markdown into a CX document
doc.to_md()!                       // emit CX back to Markdown
doc.to_json()!                     // or emit to any other format
```

The intended relationship is: CX can ingest Markdown documents, process them
structurally (add metadata, query headings, transform sections), and emit them
back. For pure prose authoring by writers who don't need machine processing,
Markdown remains the right choice.

---

## 9. Feature Matrix

| Feature                   | CX  | XML | JSON | YAML | TOML |
|---------------------------|-----|-----|------|------|------|
| Comments                  | ✓   | ✓   | **✗**| ✓    | ✓    |
| Mixed text+element content| ✓   | ✓   | ✗    | ✗    | ✗    |
| Auto-typed scalars        | ✓   | ✗   | partial | ✓† | partial |
| Compact form (readable)   | ✓   | partial | ✗ | **✗** | partial |
| Unquoted string values    | ✓   | ✗   | ✗    | ✓    | ✗    |
| No mandatory key quoting  | ✓   | ✓   | ✗    | ✓    | ✓    |
| Namespaces                | ✓   | ✓   | ✗    | ✗    | ✗    |
| Anchors/aliases/merge     | ✓   | ✗   | ✗    | ✓    | ✗    |
| Multi-document stream     | ✓   | ✗   | ✗    | ✓    | ✗    |
| Processing instructions   | ✓   | ✓   | ✗    | ✗    | ✗    |
| Binary content inline     | ✓   | ✗   | ✗    | ✓    | ✗    |
| URLs unquoted             | ✓   | ✗   | ✗    | ✗    | ✗    |
| Streaming parser          | ✓   | ✓   | ✗    | ✗    | ✗    |
| Human writable            | ✓   | partial | ✓ | ✓  | ✓    |
| Native language support   | ✗   | ✓   | ✓    | lib  | lib  |

† YAML auto-typing has correctness bugs in YAML 1.1 (the "Norway problem").

CX is the only format with checkmarks in every achievable row.

---

## 10. Quantitative Summary

Scores relative to CX (1.00). Lower = better for that format. **Bold** = winner.

| Dimension                   | CX      | XML  | JSON | YAML    | TOML |
|-----------------------------|---------|------|------|---------|------|
| Flat config (chars, pretty) | **1.00**| 1.16 | 1.16 | 1.01    | 1.14 |
| Nested config (chars, pretty)| 1.00   | 1.30 | 1.55 | **0.88**| —    |
| Nested config (chars, compact)| **1.00**| 1.41| 1.52 | N/A    | —    |
| Mixed content (chars)       | **1.00**| 1.12 | 1.58 | N/A     | N/A  |
| Signal-to-noise (attrs)     | **1.00**| 1.56 | 1.38 | 1.09    | 1.35 |
| Keystroke Shift cost        | **1.00**| 4.00 | 5.00 | 1.00    | 2.00 |
| Type safety (predictability)| **1.00**| 0.20 | 0.80 | 0.50    | 0.90 |
| Compact readability         | **1.00**| 0.50 | 0.20 | 0 (N/A) | 0.40 |
| Parse spec complexity       | **1.00**| 1.50 | 0.80 | 3.00+   | 1.20 |
| Ecosystem (parser count)    | 0.00    | 1.00 |**1.00**| 0.90  | 0.70 |

---

## 11. Honest Weaknesses of CX

1. **Zero ecosystem.** This is the dominant barrier. Every comparison format
   has years of parsers, editors, schemas, validators, and query tools.
   CX has none. This is the primary engineering investment required for adoption.

2. **Novel syntax.** The bracket syntax is unfamiliar. Learning cost is real
   even though the mental model is simpler than the formats it replaces.

3. **JSON wins browser/API transport.** `JSON.parse` is in every browser
   and JS runtime. Until CX has a widely bundled WASM parser, it cannot
   compete for frontend data transport.

4. **YAML wins pure flat config by ~12%.** YAML's block mapping syntax is
   marginally more concise and already familiar. CX does not displace YAML
   for simple key/value config on conciseness alone.

5. **Markdown wins pure prose authoring.** Writers who don't need semantic
   structure or machine processing are better served by Markdown's shorthand.
   CX interoperates with Markdown rather than replacing it.

---

## 12. Spec Versions Referenced

- CX Grammar: v3.3 (2026-04-19)
- CX AST: v2.3 (2026-04-19)
- JSON: RFC 8259
- YAML: 1.2 (most libraries implement 1.1)
- TOML: 1.0
- XML: 1.1
