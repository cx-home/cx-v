# CX Conformance Test Suite
Version: 1.0 — 2026-04-19

Language-neutral tests for all CX implementations. Each test defines CX source
input and expected outputs for AST JSON, XML, and CX round-trip. Tests are
plain text, parseable in ~20 lines of any language.

---

## File Format

```
=== test: NNN-name
level: core|extended
tags: tag1 tag2
--- in_cx
<CX source>
--- out_ast
<expected AST as JSON>
--- out_xml
<expected XML output>
--- out_cx
<expected CX round-trip>
```

A section body runs from its `--- key` line to the next `--- key`, `=== test:`,
or EOF. Strip leading/trailing blank lines from section bodies before comparing.

---

## Parse Algorithm

```python
def parse_suite(path):
    tests, cur, section = [], None, None
    for raw in open(path):
        line = raw.rstrip("\n")
        if line.startswith("=== test:"):
            if cur: tests.append(cur)
            cur = {"name": line[9:].strip(), "sections": {}}
            section = None
        elif line.startswith("level:") and cur:
            cur["level"] = line[6:].strip()
        elif line.startswith("tags:") and cur:
            cur["tags"] = line[5:].strip().split()
        elif line.startswith("--- ") and cur:
            section = line[4:].strip()
            cur["sections"][section] = []
        elif section is not None and cur is not None:
            cur["sections"][section].append(line)
    if cur: tests.append(cur)
    for t in tests:
        for k, lines in t["sections"].items():
            while lines and not lines[0].strip(): lines.pop(0)
            while lines and not lines[-1].strip(): lines.pop()
            t["sections"][k] = "\n".join(lines)
    return tests
```

---

## Levels

**core** — Document, Element, Text, Comment, PI, XMLDecl, CXDirective,
EntityRef, RawText, EntityDecl, DoctypeDecl.
All conforming implementations MUST pass every core test.

**extended** — Scalar (auto-typed and explicit), TypeAnnotation, Alias, Anchor,
Merge, MultiDoc.
Implementations MUST pass all extended tests for each feature they claim.

---

## Comparison Rules

- **AST**: JSON key order is not significant. Compare semantically.
  Scalar numeric values must match type (int `30` ≠ float `30.0`).
- **XML**: Exact string match after stripping leading/trailing blank lines.
- **CX**: Exact string match after stripping leading/trailing blank lines.

---

## Target Languages

| Language      | Status      | Notes                              |
|---------------|-------------|------------------------------------|
| Rust          | Reference   | Primary implementation             |
| Go            | Planned     |                                    |
| TypeScript/JS | Planned     |                                    |
| Python        | In progress | Migrating from v2.0 to v2.1 AST    |
| Java          | Planned     |                                    |
| C#            | Planned     |                                    |
| Swift         | Planned     |                                    |
| C             | Planned     | Shared ABI / WASM bridge           |
| V (Vlang)     | Planned     |                                    |

---

## AST Quick Reference

Node types and their key fields (optional fields omitted when empty/absent):

| Type          | Key fields                                         |
|---------------|----------------------------------------------------|
| Document      | prolog[], doctype, elements[]                      |
| XMLDecl       | version, encoding?, standalone?                    |
| CXDirective   | attrs[]                                            |
| PI            | target, data?                                      |
| Comment       | value                                              |
| DoctypeDecl   | name, externalID?, intSubset[]                     |
| Element       | name, anchor?, merge?, dataType?, attrs[], items[] |
| Attribute     | name, value                                        |
| Text          | value                                              |
| Scalar        | dataType, value (native JSON type)                 |
| Alias         | name                                               |
| EntityRef     | name                                               |
| RawText       | value                                              |
| EntityDecl    | kind (GE/PE), name, def (string or ExternalEntityDef) |
| ElementDecl   | name, contentspec                                  |
| AttlistDecl   | name, defs[]                                       |
| NotationDecl  | name, publicID?, systemID?                         |
| ConditionalSect | kind (include/ignore), subset[]                  |

Scalar dataTypes: `int`, `float`, `bool`, `null`, `string`, `date`,
`datetime`, `bytes`. Values use native JSON types (number, boolean, null,
string).

Auto-typing applies ONLY when an element body has a single unquoted token and
no child elements. Priority: hex-int → int → float → bool → null → datetime →
date → Text.

---

## cx: Namespace

URI: `https://cxformat.org/ns`  
Reserved prefix: `cx`

| AST field          | XML attribute         |
|--------------------|-----------------------|
| element.anchor     | cx:anchor="name"      |
| element.merge      | cx:merge="name"       |
| element.dataType   | cx:type="string[]"    |
| alias node         | `<cx:alias name="…"/>` |

---

## Relation to test-case.txt

`test-case.txt` at the repo root is the legacy Python-only test harness (v2.0
AST format with `body: {kind, items}`). It will be retired once the Python
implementation migrates to the v2.1 AST. This conformance suite is canonical
for all language implementations.

---

## Conformance Contract

### Format conformance

The 122 format tests are distributed across 4 files:

| File | Tests | Level |
|------|-------|-------|
| `core.txt` | 34 | core |
| `extended.txt` | 39 | extended |
| `xml.txt` | 20 | core |
| `md.txt` | 29 | core (output) / extended (input parsing) |

**Core conformance** requires passing all 34 tests in `core.txt`, all 20 tests
in `xml.txt`, and all 29 tests in `md.txt` that test CX → Markdown output.
Core = 83 tests minimum.

**Extended conformance** (full) requires Core plus all 39 tests in `extended.txt`.
This adds: scalars, type annotations, aliases, anchors, merges, and multi-document
streams. Extended = 122 tests.

**Feature claims are all-or-nothing within each feature group.** A binding may
not claim "partial extended" for individual features. Once all tests for a feature
group pass, the feature may be claimed. Feature groups in extended.txt are tagged:

| Tag | Feature |
|-----|---------|
| `scalar` | Scalar auto-typing (int, float, bool, null) |
| `type_annotation` | Explicit `:type` annotations |
| `alias` | Anchor and alias nodes |
| `anchor` | Anchor declarations (`&name`) |
| `merge` | Merge directives (`<<name`) |
| `multidoc` | Multi-document streams (`---`) |
| `array` | Array types (`:type[]`) |

---

### Document API conformance

The Document API is tested against the shared fixtures in `fixtures/`. All
Document API tests read from these files; none generate input inline.

#### Fixture set

| Fixture | Contents | Tests |
|---------|----------|-------|
| `fixtures/api_config.cx` | Nested config with typed attrs (string, int, float, bool) | Navigation, attr extraction, transform |
| `fixtures/api_article.cx` | Document-style nesting (article/head/body/section) | Deep navigation, find_all, find_first |
| `fixtures/api_scalars.cx` | All scalar types: int, float, bool, null, string, date | Scalar extraction, attr typing |
| `fixtures/api_multi.cx` | Multiple top-level elements | root(), get_all(), multi-element navigation |
| `fixtures/errors/unclosed.cx` | Parse-must-fail: missing closing bracket | Error handling |
| `fixtures/errors/empty_name.cx` | Parse-must-fail: empty element name | Error handling |
| `fixtures/errors/nested_unclosed.cx` | Parse-must-fail: unclosed bracket in child | Error handling |

#### Minimum required API tests

A conformant binding must pass tests covering each of these behaviors:

**Navigation:**
- `at("config/server")` returns the server element
- `at("config/missing")` returns none (not error)
- `at("config/server/timeout")` returns none when path step is missing
- `get("server")` on config element returns the server element
- `get("missing")` returns none
- `find_first("p")` finds the first p anywhere in the document
- `find_all("p")` returns all p elements in depth-first order
- `root()` returns the first top-level element
- `children()` returns only direct child elements (not text/scalar nodes)

**Extraction:**
- `attr("host")` returns the string value `"localhost"`
- `attr("port")` returns the integer value `8080` (not the string `"8080"`)
- `attr("debug")` returns the boolean value `false`
- `attr("ratio")` returns the float value `1.5`
- `attr("missing")` returns none
- `text()` returns joined text content of element body
- `text()` returns `""` when element has no text (only child elements)
- `scalar()` returns the typed value of a single scalar child
- `scalar()` returns none for text (quoted string) body

**Mutation (build mode):**
- `set_attr("host", "newhost")` updates the attr value
- `remove_attr("debug")` removes the attr; subsequent `attr("debug")` returns none
- `append(child)` adds child as last item
- `prepend(child)` adds child as first item
- Mutations to an Element extracted from a Document do not modify the Document

**Transform mode:**
- `transform("config/server", fn)` returns a new Document with the change applied
- Original Document is unchanged after transform
- `transform("config/missing", fn)` returns the original Document unchanged
- Chained transforms: `doc.transform(...).transform(...)` works correctly
- `transform_all("//service[@active=false]", fn)` applies fn to every matching element

**Error cases:**
- Parsing `fixtures/errors/unclosed.cx` raises a parse error
- Parsing `fixtures/errors/empty_name.cx` raises a parse error

---

### CXPath conformance

CXPath tests use the same fixture documents as the Document API.

#### CXPath test format

CXPath tests use the Document API test suite (per-language) and are not in the
conformance `.txt` files. Each test specifies:
1. The fixture document to parse
2. The CXPath expression to evaluate
3. Whether `select` or `select_all` is called
4. The expected result (element name + attrs, or `none`, or `[]`)

#### Required expressions

A conformant CXPath implementation must correctly evaluate all of the following
expression patterns against the standard fixtures:

**Descendant axis (`//name`):**
- `//p` → all p elements anywhere in the document
- `//section//p` → all p elements inside any section

**Child axis (`name`, `a/b/c`):**
- `config/server` → direct child "config" then "server"
- `services/*` → all direct children of services

**Wildcard:**
- `//*` → every element in the document
- `config/*` → all direct children of config

**Attribute predicates:**
- `//server[@host=localhost]` → servers with host=localhost
- `//server[@port=8080]` → int comparison (typed, not string)
- `//server[@debug=false]` → bool comparison
- `//server[@active!=false]` → inequality
- `//server[@port>=8000]` → numeric range
- `//*[@id]` → elements that have an id attribute

**Boolean operators:**
- `//service[@active=true and @region=us]`
- `//service[@port=80 or @port=443]`

**not():**
- `//service[not(@active=false)]`
- `//*[not(@id)]`

**Child existence:**
- `//service[tags]` → services that have a tags child element

**Position:**
- `//p[1]` → first p element
- `//p[last()]` → last p element

**String functions:**
- `//p[contains(@class, note)]`
- `//service[starts-with(@name, auth)]`

**select on Element:**
- `services_el.select_all("service[@active=true]")` — relative to extracted element

#### CXPath error contract tests

A conformant implementation must demonstrate:
- An invalid CXPath expression (e.g., `"//["`) panics or throws (not a soft return)
- `select("//missing")` returns none (not error)
- `select_all("//missing")` returns `[]` (not error)
- `//service[@name>localhost]` (string vs `>`) panics (type mismatch)

---

### Streaming conformance

Streaming tests use the fixtures in `fixtures/stream/`.

#### Required event sequences

A conformant streaming implementation must produce the correct event sequence for
each stream fixture. "Correct" means:

1. First event is StartDoc
2. Last event is EndDoc
3. StartElement / EndElement are balanced with matching names
4. Events appear in depth-first document order
5. All 11 event types are produced when the corresponding node type appears

**`fixtures/stream/stream_events.cx`** contains all major node types (comment, PI,
text, scalar, raw text, entity ref, anchor, alias, nested elements). The streaming
test must verify that each produces the correct event type with the correct field values.

**`fixtures/stream/stream_nested.cx`** tests depth-first ordering and anchor/alias
handling in the event stream.

#### Event correctness per type

For each event type, the following fields must be correct:

| Event | Required correct fields |
|-------|------------------------|
| StartDoc | type only |
| EndDoc | type only |
| StartElement | name, attrs (name+value+type), anchor (if present), data_type (if present), merge (if present) |
| EndElement | name — must match the opening StartElement |
| Text | value (exact string) |
| Scalar | data_type (exact type name), value (raw string representation) |
| Comment | value (text without delimiters) |
| PI | target, data (if present) |
| EntityRef | value (entity name, without & and ;) |
| RawText | value (exact content including whitespace) |
| Alias | value (anchor name without *) |

#### Error contract

- `stream(malformed_cx)` raises a parse error; no partial event list is returned
- `stream(valid_cx)` returns a complete event list (the same content is accessible
  if the sequence is iterated more than once)
