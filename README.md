# cx

CX is a bracket-based markup and configuration format. This is the native V
implementation — no C dependencies, pure V.

```sh
v install --git https://github.com/cx-home/cx-v
```

## What is CX?

CX is a clean, readable format that can represent documents, configuration,
and data. It reads and writes JSON, YAML, TOML, XML, and Markdown — parse any
of those formats and emit any other.

```
[config version='1.0'
  [server host=localhost port=8080]
  [database host=db.local port=5432]
]
```

## Quick Start

```v
import cx

fn main() {
    doc := cx.parse('[config
  [server host=localhost port=8080]
  [database host=db.local port=5432]
]') or { panic(err) }

    server := doc.at('config/server') or { panic('not found') }
    println(server.attr('host') or { '' }.str()) // localhost
    println(server.attr('port') or { '' }.str()) // 8080
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
doc := cx.parse(cx_src)    or { panic(err) }
doc := cx.parse_json(src)  or { panic(err) }
doc := cx.parse_yaml(src)  or { panic(err) }
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
doc.to_md()!          // Markdown
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
port := server.attr('port') or { '' }.str()
```

## CXPath

```v
// First match
svc := doc.select('//service') or { panic('') }

// All matches
for svc in doc.select_all('//service[@active=true]') {
    println(svc.attr('name') or { '' }.str())
}

// Numeric comparison
high := doc.select_all('//service[@port>=8000]')

// Position
second := doc.select('//service[2]') or { panic('') }
```

## Transform (immutable update)

Documents are immutable values. `transform` returns a new document — the
original is unchanged.

```v
updated := doc.transform('config/server', fn (el cx.Element) cx.Element {
    mut e := el
    e.set_attr('host', cx.ScalarVal('prod.example.com'))
    return e
})

// Original unchanged
println(doc.at('config/server') or { panic('') }.attr('host') or { '' }.str())
// localhost

// New document has the update
println(updated.at('config/server') or { panic('') }.attr('host') or { '' }.str())
// prod.example.com
```

## transform_all

```v
updated := doc.transform_all('//service', fn (el cx.Element) cx.Element {
    mut e := el
    e.set_attr('active', cx.ScalarVal(true))
    return e
})
```

## Streaming

```v
events := cx.stream(src) or { panic(err) }
for ev in events {
    if ev.typ == .start_element {
        println('${ev.name}')
    }
}
```

## Conversion shortcuts

```v
json_str := cx.to_json(cx_src)!
yaml_str := cx.to_yaml(cx_src)!
cx_str   := cx.json_to_cx(json_src)!
cx_str   := cx.yaml_to_cx(yaml_src)!
```

## API Reference

### Parse

| Function | Description |
|---|---|
| `parse(src) !Document` | Parse CX |
| `parse_json(src) !Document` | Parse JSON |
| `parse_yaml(src) !Document` | Parse YAML |
| `parse_toml(src) !Document` | Parse TOML |
| `parse_xml(src) !Document` | Parse XML |
| `parse_md(src) !Document` | Parse Markdown |

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
| `to_md() !string` | Emit Markdown |

### Element

| Method | Description |
|---|---|
| `get(name) ?Element` | First direct child by name |
| `get_all(name) []Element` | All direct children by name |
| `at(path) ?Element` | Navigate relative path |
| `attr(name) ?ScalarVal` | Read attribute |
| `text() string` | Concatenated text content |
| `scalar() ?ScalarVal` | First scalar child value |
| `children() []Element` | All direct child elements |
| `find_first(name) ?Element` | First matching descendant |
| `find_all(name) []Element` | All matching descendants |
| `select(expr) ?Element` | First descendant matching CXPath |
| `select_all(expr) []Element` | All descendants matching CXPath |
| `set_attr(name, ScalarVal)` | Set or update attribute |
| `remove_attr(name)` | Remove attribute |
| `append(node)` | Add child node |
| `prepend(node)` | Insert child at position 0 |
| `insert(index, node)` | Insert child at index |
| `remove_at(index)` | Remove child at index |
| `remove_child(name)` | Remove all direct children with name |

### CXPath syntax

| Expression | Matches |
|---|---|
| `//name` | All descendants named `name` |
| `a/b/c` | Child path |
| `*` | Any element |
| `[@attr]` | Has attribute |
| `[@attr=val]` | Attribute equals value |
| `[@attr>=val]` | Numeric comparison (`>` `<` `>=` `<=`) |
| `[@a=x and @b=y]` | Boolean `and` / `or` |
| `[not(@attr)]` | Negation |
| `[childname]` | Has direct child named `childname` |
| `[1]` `[last()]` | Position (1-based) |
| `[contains(@k, v)]` | Attribute contains substring |
| `[starts-with(@k, v)]` | Attribute starts with prefix |

### Stream events

| Type | Fields |
|---|---|
| `.start_element` | `name`, `attrs`, `anchor`, `merge`, `data_type` |
| `.end_element` | `name` |
| `.text` | `value` |
| `.scalar` | `value` |
| `.comment` | `value` |
| `.pi` | `target`, `data` |
| `.entity_ref` | `value` |
| `.start_doc` `.end_doc` | — |

## License

MIT
