#!/usr/bin/env python3
"""Prove the .cxd round-trips: every section payload, after parsing with the
real `cx` binary + loader normalization, must equal the original legacy body
byte-for-byte. Exit non-zero on any mismatch."""
import sys, json, subprocess
import importlib.util

spec = importlib.util.spec_from_file_location("conv", sys.argv[0].replace("_audit_", "_convert_"))
conv = importlib.util.module_from_spec(spec); spec.loader.exec_module(conv)

SECTION_MAP = conv.SECTION_MAP
TYPED_MAP = conv.TYPED_MAP
legacy_path, cxd_path = sys.argv[1], sys.argv[2]


def scalar_of(elem):
    """Value of a single scalar/text child."""
    for it in elem.get("items", []):
        if it.get("type") in ("Scalar", "Text"):
            return it.get("value")
    return None


def atoms_of(elem):
    """Ordered atom values of an [a, b] array body."""
    for it in elem.get("items", []):
        if it.get("type") == "Array":
            return [x.get("value") for x in it.get("items", []) if x.get("type") == "Scalar"]
    return None


def typed_repr(tag, elem):
    """Render a typed section back to its legacy body string for comparison."""
    if tag == "expect-valid":
        return "1" if scalar_of(elem) is True else "0"
    if tag in ("expect-codes", "expect-warn-codes"):
        return ",".join(atoms_of(elem) or [])
    return None


def legacy_typed_repr(key, body):
    if key == "sv_assert_valid":
        return "1" if body.strip() == "1" else "0"
    return ",".join(t for t in conv.re.split(r"[,\s]+", body.strip()) if t)


def loader_normalize(raw):
    """Fixture-loader rule for a RawText payload: strip one leading newline and
    one trailing newline. Nothing else (no dedent)."""
    if raw.startswith("\n"):
        raw = raw[1:]
    if raw.endswith("\n"):
        raw = raw[:-1]
    return raw


def raw_text_of(elem):
    """Concatenate RawText item values of a section element (payload sections
    have exactly one)."""
    parts = []
    for it in elem.get("items", []):
        if it.get("type") == "RawText":
            parts.append(it["value"])
    return "".join(parts)


# 1. original
_, tests = conv.parse_suite(legacy_path)
orig = {t["name"]: dict(t["sections"]) for t in tests}
orig_meta = {t["name"]: {
    "level": t.get("level"),
    "tags": t.get("tags", ""),
    "extra_meta": list(t.get("extra_meta", [])),
} for t in tests}

# 2. parsed .cxd — re-key by reconstructed full name (id slug + title)
# cx --ast emits a bare Document object for single-doc input, or a JSON array
# of Documents otherwise. (A `---` inside a RawText payload makes cx wrap the
# parse in a 1-element array — harmless here; see FIXTURE_SCHEMA_DRAFT §7.)
ast = json.loads(subprocess.check_output(["cx", "--ast", "--compact", cxd_path]))
docs = ast if isinstance(ast, list) else [ast]
elements = [e for d in docs for e in d.get("elements", [])]
suite = next(e for e in elements if e["name"] == "test-suite")
got, got_payload, got_typed, got_meta = {}, {}, {}, {}
for case in suite.get("items", []):
    if case.get("name") != "case":
        continue
    attrs = {a["name"]: a["value"] for a in case.get("attrs", [])}
    slug = attrs["id"]
    level = attrs.get("level")  # None if absent
    title, tags, meta_lines, payloads, typed = "", "", [], {}, {}
    for child in case.get("items", []):
        nm = child.get("name")
        if nm == "tags":
            tags = scalar_of(child) or ""
            continue
        if nm == "title":
            title = raw_text_of(child)  # inline [#…#] — value is exact, no normalize
            continue
        if nm == "meta":
            body = loader_normalize(raw_text_of(child))
            meta_lines = body.split("\n") if body else []
            continue
        if nm in ("expect-valid", "expect-codes", "expect-warn-codes"):
            typed[nm] = typed_repr(nm, child)
        else:
            payloads[nm] = loader_normalize(raw_text_of(child))
    name = f"{slug} {title}".strip()
    got_payload[name] = payloads
    got_typed[name] = typed
    got_meta[name] = {"level": str(level) if level is not None else None,
                      "tags": tags, "extra_meta": meta_lines}

# 3. compare
fails = 0
n_payload = n_typed = 0
for name, osecs in orig.items():
    for key, body in osecs.items():
        if key in TYPED_MAP:
            n_typed += 1
            tag, _ = TYPED_MAP[key]
            g = got_typed.get(name, {}).get(tag)
            want = legacy_typed_repr(key, body)
            if g != want:
                fails += 1
                print(f"MISMATCH (typed) {name} / {key}->{tag}\n  want: {want!r}\n  got : {g!r}")
        else:
            n_payload += 1
            tag = SECTION_MAP.get(key, key.replace("_", "-"))
            g = got_payload.get(name, {}).get(tag)
            if g != body:
                fails += 1
                print(f"MISMATCH (payload) {name} / {key}->{tag}\n  orig: {body!r}\n  got : {g!r}")

# 3b. compare metadata (level / tags / extra header lines)
n_meta = 0
for name, om in orig_meta.items():
    gm = got_meta.get(name, {})
    n_meta += 1
    want_level = str(om["level"]) if om["level"] is not None else None
    if want_level != gm.get("level"):
        fails += 1
        print(f"MISMATCH (level) {name}\n  orig: {want_level!r}\n  got : {gm.get('level')!r}")
    if om["tags"] != gm.get("tags", ""):
        fails += 1
        print(f"MISMATCH (tags) {name}\n  orig: {om['tags']!r}\n  got : {gm.get('tags','')!r}")
    if om["extra_meta"] != gm.get("extra_meta", []):
        fails += 1
        print(f"MISMATCH (meta) {name}\n  orig: {om['extra_meta']!r}\n  got : {gm.get('extra_meta', [])!r}")

if fails:
    print(f"\nFAIL: {fails} differ")
    sys.exit(1)
print(f"OK: {len(orig)} cases — {n_payload} payloads byte-exact, {n_typed} typed, {n_meta} metadata match")
