# cx — CX for V

[![Version](https://img.shields.io/badge/version-v0.8.0-blue.svg)](#status)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-cx--home.github.io%2Fcx-brightgreen.svg)](https://cx-home.github.io/cx/)
[![Status](https://img.shields.io/badge/status-pre--1.0_experimental-orange.svg)](#status)

> **One concise syntax for data *and* code.** Configs, structured documents,
> tabular data, queries, transforms, and the programs that tie them together —
> one tree of `[...]` forms that round-trips losslessly through XML, JSON,
> YAML, TOML, and CSV.
>
> **The native V distribution.** This is the `v install` channel for CX — the
> `cx` data module (parse / navigate / emit / convert / stream), the `code`
> eval engine (CXPath, `[?match]`, `[?modify]`, `[?for]`, the module system),
> and the `cx` CLI. For the spec, the other language bindings (Python / Rust /
> Go), the conformance suite, and the full guide, see
> **[github.com/cx-home/cx](https://github.com/cx-home/cx)**.

CX is a homoiconic data language. Read it like XML, type it like TOML, query
it like XPath, program it like Lisp. As a format, CX round-trips losslessly
through JSON, YAML, TOML, XML, and CSV, so you can adopt it incrementally
without rewriting existing pipelines.

```cx
[service name=auth port=8443 tls=true
  [route path=/login  method=:post]
  [route path=/health method=:get]
  [active [?for [in $r //route] [yield $r@path]]]]
```

Same brackets, same parser. The `?` sigil is the only visible cue that a
subtree is executable — it's still CX data, queryable and transformable like
every other node. That's the homoiconic property, and it's why CX is one
product, not "a format plus a separate language."

> ⚠️ **Not production-ready — experimental, pre-1.0.** CX is already
> full-featured, but it's still hardening. Expect rough edges: single-core
> performance is strong (~135k HTTP requests/second) while multi-core scaling
> is still in progress, and a couple of build dependencies are on the way out.
> Pin a version, kick the tires, and file issues — but don't put it in front
> of customers yet.

## Requirements

This package builds with the **CX project's V fork**
([github.com/cx-home/v](https://github.com/cx-home/v)), **not** stock V: the
`code` module's HTTP/SSE engine uses picoev extensions that live only in the
fork, and the optimized build needs the fork's macOS GC fix. It also needs a
**C++ compiler** and **RE2** (the regex engine shim):

```sh
brew install re2          # macOS
apt install libre2-dev    # Debian / Ubuntu
```

## Install

```sh
v install --git https://github.com/cx-home/cx-v
```

Then import the data module:

```v
import cx
```

To install the `cx` CLI (builds the C++/RE2 shim and links it), point `make`
at your checkout of the V fork:

```sh
make -C ~/.vmodules/cx install V=/path/to/cx-home-v/v   # → ~/.local/bin/cx
```

Override the destination with `PREFIX` (e.g. `PREFIX=/usr/local/bin`).

## Library — parse, navigate, emit

```v
import cx

fn main() {
    doc := cx.parse('[config
  [server host=localhost port::u16=8080]
  [database host=db.local port::u16=5432]
]') or { panic(err) }

    server := doc.at('config/server') or { panic('not found') }
    println(server.attr('host')) // localhost
    println(server.attr('port')) // 8080
}
```

### Parse any format

```v
doc := cx.parse(cx_src)             or { panic(err) }
doc := cx.parse_to_doc('json', src) or { panic(err) } // lossless map/array/scalar read
doc := cx.parse_yaml(src)           or { panic(err) }
doc := cx.parse_toml(src)           or { panic(err) }
doc := cx.parse_xml(src)            or { panic(err) }
```

### Emit any format

```v
doc.to_cx()    // CX
doc.to_json()! // JSON
doc.to_yaml()! // YAML
doc.to_toml()! // TOML
doc.to_xml()!  // XML
```

### Navigate

```v
server := doc.at('config/server') or { panic('') } // by slash path
db     := doc.get('database') or { panic('') }      // top-level by name
for el in doc.find_all('server') { println(el.name) } // descendants
port   := server.attr('port')                        // attribute
```

### Conversion shortcuts

```v
json_str := cx.to_json(cx_src)!
yaml_str := cx.to_yaml(cx_src)!
cx_str   := cx.json_to_cx(json_src)!
cx_str   := cx.yaml_to_cx(yaml_src)!
cx_str   := cx.toml_to_cx(toml_src)!
cx_str   := cx.from_xml(xml_src)!
```

### Streaming

```v
mut s := cx.new_stream(src) or { panic(err) }
for ev in s.collect() {
    if ev is cx.StreamStartElement { println(ev.name) }
}
```

## Evaluate CX code (the `code` module)

v0.8.0 unifies selection and transformation under the CX **code** language
([`code.md`](https://github.com/cx-home/cx/blob/main/spec/03-approved/core/code.md)):
a CXPath `//path` is a first-class value, `[?for]` is the
comprehension/pattern-generator, `[?match]` dispatches, and `[?modify]` does
pure-functional updates. The `code` module's `eval_code` evaluates a program
against an input document and renders the result.

```v
import code

// Selection — a CXPath literal is a value:
result := code.eval_code(src, '//service[@active=true]', 'text') or { panic(err) }

// Numeric predicate, rendered as CX:
high := code.eval_code(src, '//service[@port>=8000]', 'cx') or { panic(err) }

// Comprehension — clause-child form (v0.8.0; no colon slots, prefix operators):
prog := '[?for [in \$s //service] [where [= \$s@active true]] [yield \$s]]'
out  := code.eval_code(src, prog, 'cx') or { panic(err) }
```

## CLI

A bare resource **evaluates** (the program reading): `cx file.cx` ≡ `cx eval
file.cx`; a pure-data document evaluates to itself. The result renders to the
requested target.

```sh
cx file.cx                  # evaluate; render canonical CX
cx --json file.cx           # evaluate; render JSON   (likewise --yaml/--xml/--toml/--csv)
cx canonical file.cx        # strict canonical CX (no eval)
cx fmt file.cx              # lossless re-format

cx --from=json --to=cx file.json    # convert JSON → CX (the data path)
cx --from=cx   --to=yaml file.cx    # convert CX → YAML
```

Input is a file argument or stdin; `--from` is auto-detected from the file
extension when omitted. (Prose-heavy markup documents should use the
`--from=cx --to=…` data path; the eval path reads the body as a program.)

## API reference

### Parse

| Function | Description |
|---|---|
| `parse(src) !Document` | Parse CX |
| `parse_to_doc('json', src) !Document` | Parse JSON (lossless; registry-backed) |
| `parse_yaml(src) !Document` | Parse YAML |
| `parse_toml(src) !Document` | Parse TOML |
| `parse_xml(src) !Document` | Parse XML |

### Document

| Method | Description |
|---|---|
| `root() ?Element` | First top-level element |
| `get(name) ?Element` | Top-level element by name |
| `at(path) ?Element` | Navigate by slash path (`'config/server'`) |
| `find_first(name) ?Element` | First matching descendant |
| `find_all(name) []Element` | All matching descendants |
| `append(node)` / `prepend(node)` | Add / insert a top-level node |
| `to_cx() string` / `to_json() !string` / `to_yaml() !string` / `to_toml() !string` / `to_xml() !string` | Emit |

### Element

| Method | Description |
|---|---|
| `get(name) ?Element` / `get_all(name) []Element` | Direct child(ren) by name |
| `at(path) ?Element` | Navigate relative path |
| `attr(name) string` / `has_attr(name) bool` | Read / test attribute |
| `text() string` | Concatenated text content |
| `scalar() ?ScalarValue` | First scalar child value |
| `children() []Element` | Direct child elements |
| `find_first(name) ?Element` / `find_all(name) []Element` | Descendants |
| `set_attr(name, ScalarValue)` / `remove_attr(name)` | Mutate attributes |
| `append(node)` / `prepend(node)` / `insert(index, node)` / `remove_at(index)` / `remove_child(name)` | Mutate children |

### Stream events

`StreamEvent` is a V sum type — dispatch with `match` or `if ev is T {}`.

| Type | Fields |
|---|---|
| `StreamStartElement` | `name`, `attrs []Attribute`, `anchor`, `merge`, `data_type` |
| `StreamEndElement` | `name` |
| `StreamText` | `value` |
| `StreamScalar` | `data_type`, `value ScalarValue` |
| `StreamComment` | `value` |
| `StreamPI` | `target`, `data ?string` |
| `StreamEntityRef` / `StreamAlias` / `StreamRawText` | `name` / `name` / `value` |
| `StreamStartDoc` / `StreamEndDoc` | — |

## Editor tooling

Syntax highlighting + the `cx lsp` language server (VS Code, Neovim) live in the
main repo: [cx-home/cx/tooling](https://github.com/cx-home/cx/tree/main/tooling).

## Documentation

The full documentation — overview, quickstart, tutorial, the data and code
tours, the standard-library reference, cookbook, every binding, and the
interactive playground — lives at:

**→ [cx-home.github.io/cx](https://cx-home.github.io/cx/)**

## Status

CX is **pre-1.0** and under active development; **v0.8.0** is the current line.
The grammar is stable and the C ABI is versioned and forward-compatible.
Formal security review, fuzz-testing, and the multi-core performance work are
still ahead — so pin a tested version and apply normal pre-1.0 caution.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
