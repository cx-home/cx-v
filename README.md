# cx

> **V package distribution** of CX. This repo is the `v install` channel.
> For the spec, all 10 language bindings, conformance suite, and full
> documentation, see **[github.com/cx-home/cx](https://github.com/cx-home/cx)**
> or the docs site at **[cx-home.github.io/cx](https://cx-home.github.io/cx/)**.

CX is a bracket-based markup and configuration format. This is the native V
implementation — no C dependencies, pure V.

```sh
v install --git https://github.com/cx-home/cx-v
```

## What is CX?

CX is a clean, readable format that can represent documents, configuration,
and data. It reads and writes JSON, YAML, TOML, and XML — parse any
of those formats and emit any other.

```
[config version='1.0'
  [server host=localhost port=8080]
  [database host=db.local port=5432]
]
```

See [COMPARISON.md](COMPARISON.md) for a detailed analysis of how CX compares
to JSON, YAML, XML, and TOML — keystroke cost, character counts, compact format,
type safety, and when to use CX vs. each alternative.

## Quick Start

```v
import cx

fn main() {
    doc := cx.parse('[config
  [server host=localhost port=8080]
  [database host=db.local port=5432]
]') or { panic(err) }

    server := doc.at('config/server') or { panic('not found') }
    println(server.attr('host')) // localhost
    println(server.attr('port')) // 8080
}
```

## Install

```sh
v install --git https://github.com/cx-home/cx-v
```

Then import:

```v
import cx
```

## Parse any format

```v
doc := cx.parse(cx_src)            or { panic(err) }
doc := cx.parse_to_doc('json', src) or { panic(err) } // lossless map/array/scalar read
doc := cx.parse_yaml(src)          or { panic(err) }
doc := cx.parse_toml(src)  or { panic(err) }
doc := cx.parse_xml(src)   or { panic(err) }
doc := cx.parse_md(src)    or { panic(err) }
```

## Emit any format

```v
doc.to_cx()           // CX
doc.to_json()!        // JSON
doc.to_yaml()!        // YAML
doc.to_toml()!        // TOML
doc.to_xml()!         // XML
```

## Navigate

```v
// By path
server := doc.at('config/server') or { panic('') }

// By name
db := doc.get('database') or { panic('') }

// Find descendants
for el in doc.find_all('server') {
    println(el.name)
}

// Read attribute
port := server.attr('port')
```

## Select and transform via CX code

At v0.8.0, selection and transformation use the unified CX code
language ([`spec/code.md`](../spec/code.md)) — CXPath `//path` literals
for selection, `[?for]` comprehensions for pattern-generators and
projection, combined with the V host data model.

```v
// All matches via a CXPath path value
result := code.eval_code(src, '//service[@active=true]', 'text') or {
    panic(err)
}
println(result)

// Numeric comparison via path predicate
high := code.eval_code(src, '//service[@port>=8000]', 'cx') or {
    panic(err)
}

// Position via [?for]
prog := '[?for \$s :in //service :limit 1 :yield \$s]'
```

Selection and comprehension both go through CX code: a CXPath
literal (`//path`) is itself a value, and `[?for]` is the
pattern-generator. See `spec/code.md` §5.5 for the surface map.

## Streaming

```v
events := cx.stream(src) or { panic(err) }
for ev in events {
    if ev is cx.StreamStartElement {
        println(ev.name)
    }
}
```

## CLI

Install the `cx` command-line tool:

```sh
v install --git https://github.com/cx-home/cx-v
make -C ~/.vmodules/cx install
```

This builds a production binary and places it in `~/.local/bin/cx`. Override
the destination with `PREFIX`:

```sh
make -C ~/.vmodules/cx install PREFIX=/usr/local/bin
```

Usage:

```sh
cx --json file.cx          # CX → JSON
cx --yaml file.cx          # CX → YAML
cx --xml  file.cx          # CX → XML
cx --toml file.cx          # CX → TOML
cx --cx   file.cx          # re-format as canonical CX
cx --cx --compact file.cx  # compact single-line CX

cx --from=json --to=cx file.json   # JSON → CX
cx --from=yaml --to=json file.yaml # YAML → JSON
```

Input is read from a file argument or stdin. Format is auto-detected from the
file extension when `--from` is omitted.

## Editor tooling

VS Code and Neovim syntax highlighting and completions are available in the
main CX repository: [cx-home/cx](https://github.com/cx-home/cx/tree/main/tooling)

Quick install from that repo:

```sh
# VS Code
make build-vscode
code --install-extension tooling/vscode/cx-language-0.1.0.vsix

# Neovim — see tooling/neovim/README.md for the full setup block
make build-lsp
```

## Conversion shortcuts

```v
json_str := cx.to_json(cx_src)!
yaml_str := cx.to_yaml(cx_src)!
cx_str   := cx.json_to_cx(json_src)!
cx_str   := cx.yaml_to_cx(yaml_src)!
cx_str   := cx.toml_to_cx(toml_src)!
cx_str   := cx.from_xml(xml_src)!
```

## API Reference

### Parse

| Function | Description |
|---|---|
| `parse(src) !Document` | Parse CX |
| `parse_to_doc('json', src) !Document` | Parse JSON (lossless map/array/scalar read; registry-backed) |
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
| `select(expr) ?Element` | First element matching CXPath |
| `select_all(expr) []Element` | All elements matching CXPath |
| `transform(path, fn) Document` | New doc with element at path replaced |
| `transform_all(expr, fn) Document` | New doc with all matching elements replaced |
| `append(node)` | Add a top-level node |
| `prepend(node)` | Insert a top-level node at position 0 |
| `to_cx() string` | Emit CX |
| `to_json() !string` | Emit JSON |
| `to_yaml() !string` | Emit YAML |
| `to_toml() !string` | Emit TOML |
| `to_xml() !string` | Emit XML |

### Element

| Method | Description |
|---|---|
| `get(name) ?Element` | First direct child by name |
| `get_all(name) []Element` | All direct children by name |
| `at(path) ?Element` | Navigate relative path |
| `attr(name) string` | Read attribute as string (`''` if absent) |
| `has_attr(name) bool` | True if attribute exists |
| `text() string` | Concatenated text content |
| `scalar() ?ScalarValue` | First scalar child value |
| `children() []Element` | All direct child elements |
| `find_first(name) ?Element` | First matching descendant |
| `find_all(name) []Element` | All matching descendants |
| `select(expr) ?Element` | First descendant matching CXPath |
| `select_all(expr) []Element` | All descendants matching CXPath |
| `set_attr(name, ScalarValue)` | Set or update attribute |
| `remove_attr(name)` | Remove attribute |
| `append(node)` | Add child node |
| `prepend(node)` | Insert child at position 0 |
| `insert(index, node)` | Insert child at index |
| `remove_at(index)` | Remove child at index |
| `remove_child(name)` | Remove all direct children with name |

### CX code (selection + transformation)

CXPath was retired at v0.7.6 — the v0.7.6 / v0.8.0 selection +
transformation surface is the CX code language. See
[`spec/code.md`](../spec/code.md) for the full reference
(grammar, semantics, fixtures). Quick map from the cxpath shapes
that lived here previously:

| Old cxpath | CX code equivalent (v0.8.0) |
|---|---|
| `//user` | `//user` (path-value literal) |
| `//user[@active=true]` | `//user[@active=true]` |
| `//service[@port>=8000]` | `//service[@port>=8000]` |
| `//user[2]` | `//user[2]` (positional predicate) |
| `//item[contains(@name, "x")]` | `//item[contains(@name, "x")]` |
| transform `//service` → modify | `[?for \$s :in //service :yield (update-attr \$s "active" true)]` |

### Stream events

`StreamEvent` is a V sum type. Use `match` or `if ev is T {}` to dispatch.

| Type | Fields |
|---|---|
| `StreamStartElement` | `name`, `attrs []Attribute`, `anchor`, `merge`, `data_type` |
| `StreamEndElement` | `name` |
| `StreamText` | `value` |
| `StreamScalar` | `data_type`, `value ScalarValue` |
| `StreamComment` | `value` |
| `StreamPI` | `target`, `data ?string` |
| `StreamEntityRef` | `name` |
| `StreamAlias` | `name` |
| `StreamRawText` | `value` |
| `StreamStartDoc` `StreamEndDoc` | — |

## License

MIT
