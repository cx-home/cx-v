# CX API Test Fixtures

Shared test data for all language binding API test suites. Each language
reads from this directory rather than embedding CX inline.

## File layout

```
fixtures/
  api_config.cx          structured config — typed attrs, multiple top-level elements
  api_article.cx         nested document — traversal, find_all, mixed depth
  api_scalars.cx         all scalar types: int, float, bool, null, string, date
  api_multi.cx           multiple top-level elements (not a multi-doc stream)
  errors/
    unclosed.cx          missing closing bracket — parse must fail
    empty_name.cx        [] empty element name — parse must fail
    nested_unclosed.cx   unclosed bracket inside child — parse must fail
  stream/
    stream_events.cx     all 11 streaming event types in one document (~31 events)
    stream_nested.cx     6-level deep nesting + anchor/alias/siblings
  bench/
    bench_small.cx       20 services, ~3.4 KB  — latency baseline
    bench_medium.cx      200 services, ~34 KB  — mid-scale
    bench_large.cx       2000 services, ~354 KB — throughput scale
```

## Reading fixtures

Each language computes the path relative to this directory.

**Python** (`python/test_api.py`):
```python
_FIXTURES = os.path.join(os.path.dirname(__file__), '..', 'fixtures')
def fx(name): return open(os.path.join(_FIXTURES, name)).read()
```

**V** (`lang/v/tests/api_test.v`):
```v
const fixtures = os.join_path(os.dir(@FILE), '..', '..', 'fixtures')
fn fx(name string) string { return os.read_file(os.join_path(fixtures, name)) or { panic(err) } }
```

Future language bindings follow the same pattern — compute the path from the
test file location to the repo root, then append `fixtures/`.

## Adding fixtures

- Add a `.cx` file here when the same test data is needed in 2+ languages.
- Single-value inline tests (`[port 8080]`) are fine to keep inline.
- Error fixtures go in `errors/` and must be verified to actually fail parsing.
- Document expected structure in a comment at the top of the `.cx` file if
  non-obvious.

## Streaming fixtures (`stream/`)

Used by all language streaming test suites to verify conformance.

- `stream_events.cx` — covers all 11 event types: StartDoc, EndDoc,
  StartElement, EndElement, Text, Scalar, Comment, PI, EntityRef, RawText,
  Alias. Tests should assert all 11 types are present and spot-check values.
- `stream_nested.cx` — 6-level deep nesting with anchor (`&root`) and alias
  (`[*root]`). Tests should verify depth and anchor/alias handling.

## Benchmark fixtures (`bench/`)

Used by `python/bench.py` and future per-language benchmark runners to
measure throughput at three scales.

Each fixture contains service blocks of this shape:
```cx
[service id=N name=svc-N host=svc-N.example.com port=PORT active=BOOL ratio=FLOAT
  [tags :string[] web api backend]
  [meta created=2026-01-01 region=REGION]
]
```

Benchmarks cover: `parse` (CX → Document), `stream` (CX → all events),
`to_json`, `to_xml`, `to_yaml`, `to_toml`, `loads` (CX → native dict),
`dumps` (dict → CX), `xml→cx`.

## What these are NOT

These fixtures test the Document API (parse, navigate, query, mutate) and
streaming. They are separate from `conformance/*.txt`, which tests the
string-conversion layer (CX ↔ XML ↔ JSON ↔ YAML ↔ TOML ↔ Markdown). Don't
conflate the two.
