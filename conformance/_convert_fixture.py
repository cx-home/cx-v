#!/usr/bin/env python3
"""Convert a legacy `=== test:` / `--- key` fixture file to a CX `.cxd` suite.

Reads the bespoke text format (NOT CX — hence a plain-text reader is correct
here) and emits a `[test-suite …]` CX document per conformance/fixtures.cxs.
Section *payloads are copied verbatim* into RawText `[# … #]`; no CX syntax is
rewritten. Payload lines are uniformly indented for readability — the fixture
loader's dedent rule restores the original bytes (proven by _audit_fixture.py).
"""
import sys, re

SECTION_MAP = {  # legacy snake key -> kebab tag (verbatim RawText payloads)
    "in_cx": "in-cx", "in_code": "in-code",
    "out_text": "out-text", "out_err": "out-err",
}


def attr_val(v):
    """Bare when it's a simple token; single-quoted (escaped) otherwise — for
    attr values that contain spaces/pipes/etc. (e.g. template `<a | b>` levels)."""
    if re.fullmatch(r"[A-Za-z0-9_.\-]+", v or ""):
        return v
    return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"


def split_name(name):
    """Legacy `name` = `<id-slug> <free description>`. Split on first
    whitespace; the slug becomes id, the rest (if any) the title."""
    parts = name.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def _atom_array(body):
    toks = [t for t in re.split(r"[,\s]+", body.strip()) if t]
    return "[" + ", ".join(":" + t for t in toks) + "]"


# legacy snake key -> (kebab tag, body->CX-value renderer). These become
# NATIVE typed CX values, not RawText payloads.
TYPED_MAP = {
    "sv_assert_valid":      ("expect-valid",      lambda b: "true" if b.strip() == "1" else "false"),
    "sv_expected_codes":    ("expect-codes",      _atom_array),
    "sv_expected_warn_codes": ("expect-warn-codes", _atom_array),
}


HEADER_META_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*:")


def parse_suite(path):
    """The README parse algorithm, plus capture of the file-header comment and
    ALL case-header metadata lines (level, tags, and any others — view, kind,
    note, chunk_at, pending, …) so the conversion is lossless."""
    tests, cur, section = [], None, None
    header = []
    seen_test = False
    in_fence = False
    for raw in open(path):
        line = raw.rstrip("\n")
        # ``` fenced regions OUTSIDE a section body are documentation (e.g. the
        # `=== test: <test-id>` format example in the file header) — skip them
        # so they aren't parsed as real fixtures. Inside a section body
        # (section is not None) ``` is literal payload content (markdown
        # fixtures legitimately contain fences), so it is left untouched.
        if section is None:
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
        if line.startswith("=== test:"):
            seen_test = True
            if cur:
                tests.append(cur)
            cur = {"name": line[9:].strip(), "sections": {}, "order": [], "extra_meta": []}
            section = None
        elif cur is not None and section is None and HEADER_META_RE.match(line):
            key = line.split(":", 1)[0]
            if key == "level":
                cur["level"] = line[len("level:"):].strip()
            elif key == "tags":
                cur["tags"] = line[len("tags:"):].strip()
            else:
                cur["extra_meta"].append(line)  # verbatim `key: value`
        elif line.startswith("--- ") and cur:
            section = line[4:].strip()
            cur["sections"][section] = []
            cur["order"].append(section)
        elif section is not None and cur is not None:
            cur["sections"][section].append(line)
        elif not seen_test:
            header.append(line)
    if cur:
        tests.append(cur)
    for t in tests:
        for k, lines in t["sections"].items():
            while lines and not lines[0].strip():
                lines.pop(0)
            while lines and not lines[-1].strip():
                lines.pop()
            t["sections"][k] = "\n".join(lines)
    return header, tests


def header_doc(header):
    """Pull the prose out of a leading [- … -] block comment, if present.

    Kept multi-line and verbatim; emitted as a RawText [doc …] (NOT a CX
    block comment, which would terminate at the first ']' in the prose).
    """
    text = "\n".join(header).strip()
    m = re.match(r"\[-\s*(.*?)\s*-\]\s*\Z", text, re.S)
    return (m.group(1) if m else text).strip()


def split_raw(s):
    """Split s into chunks none of which contains the RawText terminator '#]',
    by breaking between the '#' and ']'. Concatenating the chunks reconstructs
    s exactly. (cx 0.8.0 does not honor the spec's &rsqb; escape inside
    RawText, so adjacent RawText siblings are how a literal '#]' is carried.)"""
    chunks, cur, i = [], "", 0
    while i < len(s):
        if s[i:i + 2] == "#]":
            cur += "#"
            chunks.append(cur)
            cur = ""
            i += 1            # leave the ']' to start the next chunk
        else:
            cur += s[i]
            i += 1
    chunks.append(cur)
    return chunks


def emit_payload(tag, body):
    # Payloads sit flush-left so the loader's normalization is exactly two
    # edge-newline strips — byte-lossless for any content (no dedent, which
    # would clobber a payload's own indentation). Combined RawText value is
    # "\n" + body + "\n"; split across siblings only when body contains '#]'.
    if body == "":
        return f"  [{tag} [##]]"
    raw = "".join(f"[#{c}#]" for c in split_raw("\n" + body + "\n"))
    return f"  [{tag} {raw}]"


def emit(name, header, tests):
    out = []
    out.append(f"[test-suite name={name}")
    doc = header_doc(header)
    if doc:
        out.append(emit_payload("doc", doc))
    for t in tests:
        out.append("")
        slug, title = split_name(t["name"])
        # `level` is emitted only when the original had a `level:` line, so
        # absence round-trips (no synthetic default that would change behavior).
        case_attrs = f"id={attr_val(slug)}"
        if t.get("level") is not None:
            case_attrs += f" level={attr_val(t['level'])}"
        out.append(f" [case {case_attrs}")
        if title:
            # verbatim RawText — title is free text (quotes, brackets); a
            # quoted-string carrier hits a parser quote/bracket bug.
            out.append(f"  [title [#{title}#]]")
        if t.get("tags"):
            out.append(f"  [tags {t['tags']}]")
        if t.get("extra_meta"):
            # verbatim header lines (view/kind/note/chunk_at/pending/…)
            out.append(emit_payload("meta", "\n".join(t["extra_meta"])))
        for sec in t["order"]:
            body = t["sections"][sec]
            if sec in TYPED_MAP:
                tag, render = TYPED_MAP[sec]
                out.append(f"  [{tag} {render(body)}]")
            else:
                tag = SECTION_MAP.get(sec, sec.replace("_", "-"))
                out.append(emit_payload(tag, body))
        out.append(" ]")
    out.append("]")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    src, name = sys.argv[1], sys.argv[2]
    header, tests = parse_suite(src)
    sys.stdout.write(emit(name, header, tests))
