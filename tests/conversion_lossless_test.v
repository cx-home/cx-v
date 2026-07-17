module main

import cx
import code

// conversion_lossless_test.v — #444: the conversions.md §0.2 lossless
// encodings over the ONE codec registry (`code` is imported so its init()
// registers the canonical strict JSON parser — the same wiring the CLI and
// the C ABI use).
//
//   • JSON lossless emit = idiomatic values + per-object `cx:type` sidecar
//   • JSON import consumes the sidecar (unconditionally — reserved `cx:`
//     protocol, mirroring the XML importer) and re-types the named fields
//   • YAML lossless emit = `!!cx:T` native tags; the YAML importer is the
//     inverse
//   • CX→fmt(lossless)→CX is eq-stable at the canonical-CX level for value
//     documents carrying every §0.2 typed-scalar kind
//   • convert_by_name accepts lossless for json/yaml and still hard-errors
//     for toml/md (spec'd unsupported)
//

const typed_doc = '{status: :ok, when: 2023-01-15, at: 2023-01-15T10:00:00Z, wait: 1h30m, big: 99999999999999999999}'

fn canon(src string) string {
	doc := cx.parse(src) or { panic('parse: ${err}') }
	return cx.emit_cx(doc).trim_space()
}

fn convert(src string, from string, to string, lossless bool) string {
	return cx.convert_by_name(src, from, to, lossless) or { panic('convert ${from}→${to}: ${err}') }
}

fn test_json_lossless_emit_carries_sidecar() {
	// touch a `code` symbol so the import (whose init() registers the strict
	// JSON parser into the codec registry) is retained
	code.caps_set_all()
	out := convert(typed_doc, 'cx', 'json', true)
	assert out.contains('"cx:type"'), 'lossless JSON must carry the sidecar: ${out}'
	assert out.contains('"status": "atom"'), 'sidecar must name the atom field: ${out}'
	assert out.contains('"when": "date"'), 'sidecar must name the date field: ${out}'
	assert out.contains('"wait": "duration"'), 'sidecar must name the duration field: ${out}'
	assert out.contains('"big": "bigint"'), 'sidecar must name the bigint field: ${out}'
	// values stay the idiomatic default images
	assert out.contains('"status": ":ok"'), 'atom value stays the ":NAME" string: ${out}'
}

fn test_json_default_emit_has_no_sidecar() {
	out := convert(typed_doc, 'cx', 'json', false)
	assert !out.contains('cx:type'), 'default emit must NOT carry a sidecar: ${out}'
}

fn test_json_lossless_roundtrip_eq_stable() {
	js := convert(typed_doc, 'cx', 'json', true)
	back := convert(js, 'json', 'cx', false)
	assert back.trim_space() == canon(typed_doc), 'CX→json(lossless)→CX must be eq-stable:\n  orig: ${canon(typed_doc)}\n  back: ${back.trim_space()}'
}

fn test_yaml_lossless_roundtrip_eq_stable() {
	ym := convert(typed_doc, 'cx', 'yaml', true)
	back := convert(ym, 'yaml', 'cx', false)
	assert back.trim_space() == canon(typed_doc), 'CX→yaml(lossless)→CX must be eq-stable:\n  orig: ${canon(typed_doc)}\n  back: ${back.trim_space()}'
}

fn test_json_sidecar_import_retypes_fields() {
	js := '{"score": "3.14", "id": "99999999999999999999", "status": ":ok", "cx:type": {"score": "decimal", "id": "bigint", "status": "atom"}}'
	// the spec §0.2 example document — import, then YAML re-emit shows the
	// reconstructed types via their native tags
	back_yaml := convert(js, 'json', 'yaml', false)
	assert back_yaml.contains('score: !!cx:decimal "3.14"'), 'sidecar decimal must reconstruct: ${back_yaml}'
	assert back_yaml.contains('id: !!cx:bigint "99999999999999999999"'), 'sidecar bigint must reconstruct: ${back_yaml}'
	assert back_yaml.contains('status: !!cx:atom "ok"'), 'sidecar atom must reconstruct: ${back_yaml}'
	// and the sidecar itself is consumed
	assert !back_yaml.contains('cx:type'), 'the sidecar entry must be consumed on import: ${back_yaml}'
}

fn test_json_sidecar_unknown_and_missing_fields_pass_through() {
	js := '{"a": "x", "cx:type": {"a": "nosuchtype", "ghost": "date"}}'
	out := convert(js, 'json', 'json', false)
	assert out.contains('"a": "x"'), 'unknown type name leaves the value untouched: ${out}'
	assert !out.contains('cx:type'), 'sidecar consumed even when entries do not apply: ${out}'
}

fn test_nested_typed_attrs_ride_attr_types() {
	// #475: element docs emit the `$tag` envelope in lossless mode; typed
	// attrs list in `$attr-types` (the JSON image of XML's cx:attr-types)
	src := '[event kind=:click [meta when::date=2023-01-15]]'
	out := convert(src, 'cx', 'json', true)
	assert out.contains('"\$tag": "event"'), 'envelope root: ${out}'
	assert out.contains('"kind": "atom"'), 'outer \$attr-types: ${out}'
	assert out.contains('"when": "date"'), 'nested \$attr-types: ${out}'
	assert out.contains('"kind": "click"'), 'atom attr value is the bare name: ${out}'
	back := convert(out, 'json', 'cx', false)
	assert back.trim_space() == canon(src), 'envelope must reconstruct:\n  orig: ${canon(src)}\n  back: ${back.trim_space()}'
}

fn test_table_payload_present_in_lossless_lanes() {
	src := '[users [table[name::string age::int]]\n  alice 30\n  bob 25\n]'
	js := convert(src, 'cx', 'json', true)
	assert js.contains('"\$cols"') && js.contains('"name::string"'), 'table header must ride \$cols (json): ${js}'
	assert js.contains('"alice"') && js.contains('"bob"'), 'table rows must not be dropped (json): ${js}'
	ym := convert(src, 'cx', 'yaml', true)
	assert ym.contains('\$cols:') && ym.contains('- alice'), 'table rows must not be dropped (yaml): ${ym}'
	// and both lanes round-trip the table byte-identically
	assert convert(js, 'json', 'cx', false).trim_space() == canon(src)
	assert convert(ym, 'yaml', 'cx', false).trim_space() == canon(src)
}

// ── #458: bytes lanes ─────────────────────────────────────────────────────────

fn test_bytes_json_lossless_roundtrip() {
	src := '[hash::bytes 0x48656c6c6f]'
	js := convert(src, 'cx', 'json', true)
	assert js.contains('"SGVsbG8="'), 'bytes must emit base64, not 0x hex: ${js}'
	assert js.contains('"cx:bytes"'), 'the bytes child rides the per-item carrier: ${js}'
	assert js.contains('"\$type": "bytes"'), 'the ::bytes annotation rides \$type: ${js}'
	assert !js.contains('0x'), 'the 0x hex image must not leak into JSON: ${js}'
	// import inverse: carrier bytes + base64 → the 0x… bytes scalar
	back := convert(js, 'json', 'cx', false)
	assert back.trim_space() == canon(src), 'bytes element must round-trip: ${back}'
}

fn test_bytes_yaml_binary_roundtrip() {
	src := '[hash::bytes 0x48656c6c6f]'
	ym := convert(src, 'cx', 'yaml', false)
	assert ym.trim_space() == 'hash: !!binary "SGVsbG8="', 'YAML bytes = string with !!binary tag: ${ym}'
	back := convert(ym, 'yaml', 'cx', false)
	assert back.contains('0x48656c6c6f'), '!!binary import must reconstruct the bytes payload: ${back}'
}

fn test_bytes_toml_and_md_are_base64() {
	src := '[hash::bytes 0x48656c6c6f]'
	tm := convert(src, 'cx', 'toml', false)
	assert tm.contains('hash = "SGVsbG8="'), 'TOML bytes = base64 string: ${tm}'
	md := convert(src, 'cx', 'md', false)
	assert md.contains('SGVsbG8=') && !md.contains('0x48656c6c6f'), 'MD bytes = base64 text: ${md}'
}

fn test_lossless_flag_surface_via_registry() {
	// accepted lanes
	for target in ['cx', 'xml', 'json', 'yaml'] {
		_ := cx.convert_by_name('[a 1]', 'cx', target, true) or {
			assert false, 'lossless --to=${target} must be accepted (#444): ${err}'
			return
		}
	}
	// spec'd-unsupported lanes stay fail-loud (#416/#445)
	for target in ['toml', 'md'] {
		if _ := cx.convert_by_name('[a 1]', 'cx', target, true) {
			assert false, 'lossless --to=${target} must stay a hard error (§0.2: no extension protocol)'
		} else {
			assert err.msg().contains('--lossless is not supported for --to=${target}'), 'wrong rejection: ${err.msg()}'
		}
	}
}

// ── #473: type-shaped STRING map values must survive the CX TEXT lane ───────
// The value model already holds them as strings (the conversion lanes are
// fine); the loss was at CX-text emit: `{"i": "1937"}` printed `{i: 1937}`
// and re-imported as int. The map/sequence string emit now quotes whenever
// the bare image would auto-type (number / float / bool / null / atom /
// date / datetime / duration / period / bigint / hex shapes — mirroring
// cx_array_item_needs_quote) or would break the collection re-parse
// (quote chars, closers, commas).


// jflat normalizes the pretty-printed JSON emit to its compact one-line
// image for comparison (values never carry newlines in these fixtures).
fn jflat(s string) string {
	return s.trim_space().replace('\n  ', '').replace('\n', '')
}

const shape_flip_strings = ['1937', '3.14', '1e3', 'true', 'false', 'null', ':click',
	'2023-01-15', '2023-01-15T10:00:00Z', '1h30m', '3mo', '99999999999999999999999999',
	'0x1F', '-0x10', '1_000']

fn test_map_value_string_shapes_survive_cx_text_reimport() {
	code.caps_set_all()
	for s in shape_flip_strings {
		js := '{"k": "${s}"}'
		cxt := convert(js, 'json', 'cx', false)
		back := convert(cxt, 'cx', 'json', false)
		assert jflat(back) == js, '#473 type flip through the CX text lane for ${s}:\n  cx  : ${cxt.trim_space()}\n  back: ${back.trim_space()}'
	}
}

fn test_map_value_string_breakers_survive_cx_text_reimport() {
	// Structural breakers: a bare emit is not even re-parseable (mid-token
	// quote opens a string; `}` closes the map early; `)` a sequence; a
	// comma splits entries). They must quote too.
	code.caps_set_all()
	for s in ["it's", 'a}b', 'a)b', 'a, b'] {
		js := '{"k": "${s}"}'
		cxt := convert(js, 'json', 'cx', false)
		back := convert(cxt, 'cx', 'json', false)
		assert jflat(back) == js, '#473 collection re-parse break for ${s}:\n  cx  : ${cxt.trim_space()}\n  back: ${back.trim_space()}'
	}
}

fn test_map_value_safe_bare_strings_stay_bare() {
	// Bare-safe strings keep their bare image — no over-quoting churn on
	// the canonical surface (hash stability for existing documents).
	code.caps_set_all()
	// ('@ref' and '007' are NOT in this list: the `@` body-ref sigil and the
	// leading-zero numeric shape quote under the same rules a CX-authored
	// TextNode value always quoted under — cx_body_leading_sigil /
	// cx_would_autotype's long-standing over-approximation — so both lanes
	// agree on the quoted image.)
	for s in ['hello', 'hello world', 'a: b'] {
		js := '{"k": "${s}"}'
		cxt := convert(js, 'json', 'cx', false).trim_space()
		assert cxt == '{k: ${s}}', 'bare-safe string must stay bare: ${cxt}'
		back := convert(cxt, 'cx', 'json', false)
		assert jflat(back) == js, 'bare-safe string must still re-import as itself:\n  cx  : ${cxt}\n  back: ${back.trim_space()}'
	}
}

fn test_sequence_item_string_shapes_survive_reimport() {
	// The same rule covers sequence items (cx_emit_collection_item is the
	// shared emit path). A sequence only exists inside an element body, so
	// pin it at the node level: build the seq, emit, re-parse, compare types.
	seq := cx.SequenceNode{
		items: [
			cx.Node(cx.ScalarNode{ data_type: .string_type, value: cx.ScalarValue('1937') }),
			cx.Node(cx.ScalarNode{ data_type: .string_type, value: cx.ScalarValue('1h30m') }),
			cx.Node(cx.ScalarNode{ data_type: .int_type, value: cx.ScalarValue(i64(1)) }),
		]
	}
	emitted := cx.cx_emit_sequence_inline(seq, false)
	src := '[e ${emitted}]'
	doc := cx.parse(src) or { panic('re-parse of emitted sequence failed: ${emitted}: ${err}') }
	el := doc.elements[0]
	assert el is cx.Element
	e := el as cx.Element
	assert e.items.len == 1, 'expected one sequence child; got ${e.items.len} in ${emitted}'
	sq := e.items[0]
	assert sq is cx.SequenceNode, 'expected a sequence; got ${sq.type_name()} from ${emitted}'
	s2 := sq as cx.SequenceNode
	first := s2.items[0]
	second := s2.items[1]
	assert first is cx.TextNode, 'string item 1937 must re-parse as a string, not ${first.type_name()} (emit: ${emitted})'
	assert second is cx.TextNode, 'string item 1h30m must re-parse as a string, not ${second.type_name()} (emit: ${emitted})'
}

fn test_typed_map_values_keep_bare_images() {
	// conv-006's contract: GENUINE typed duration/bigint map values keep
	// their bare canonical image — the quoting rule is for STRING payloads
	// only.
	out := canon('{wait: 1h30m, big: 99999999999999999999}')
	assert out == '{wait: 1h30m, big: 99999999999999999999}', 'typed values must stay bare: ${out}'
}

// ── #485 item 1: table-cell string quoting shares the collection-string rule ──
//
// The cell context instantiates the #483 quote-when-would-re-read-differently
// rule: in a string-family column a bare token re-reads as the SAME string
// (grammar [29b]: untyped columns default to ::string — read_table_cell never
// auto-types them), so type-shaped text stays bare losslessly; what must quote
// is anything the cell reader dispatches AWAY from the bare-token path — a
// leading `[` / `{` / `(` (collection-literal cells), any quote char (a
// double-quoted-shaped image loses its quotes), whitespace (the cell
// separator) — plus `null` and every string in a NON-string column.

fn test_table_cell_type_shaped_strings_reimport_as_strings() {
	// Bare emit is correct AND lossless for these in an untyped column —
	// the pinned contract is emit→reimport type stability, not quoting.
	for s in shape_flip_strings {
		if s == 'null' { continue } // the null literal IS the null cell — quoted below
		src := "[t [table[w]]\n  '${s}'\n]"
		doc := cx.parse(src) or { panic('parse: ${err}') }
		emitted := cx.emit_cx(doc)
		doc2 := cx.parse(emitted) or { panic('reparse (${s}): ${err}; emit=${emitted}') }
		root := doc2.root() or { panic('no root') }
		td := root.table_opt() or { panic('no table data after reimport (${s}); emit=${emitted}') }
		cell := td.rows[0][0]
		assert cell is string, 'cell ${s} must reimport as string, got ${typeof(cell).name}; emit=${emitted}'
		assert cell as string == s, 'cell value churned for ${s}: got "${cell as string}"; emit=${emitted}'
	}
}

fn test_table_cell_collection_shaped_strings_quote_on_emit() {
	// Pre-#485 these bare-emitted and flipped type ({a:b} → Map, (x,y) →
	// Sequence) or lost content ("q" → q) on reimport.
	cases := ['{a:b}', '(x,y)', '"q"', '[not, an, array]', 'null']
	for s in cases {
		esc := s.replace("'", "\\'")
		src := "[t [table[w]]\n  '${esc}'\n]"
		doc := cx.parse(src) or { panic('parse (${s}): ${err}') }
		emitted := cx.emit_cx(doc)
		doc2 := cx.parse(emitted) or { panic('reparse (${s}): ${err}; emit=${emitted}') }
		root := doc2.root() or { panic('no root') }
		td := root.table_opt() or { panic('no table data after reimport (${s}); emit=${emitted}') }
		cell := td.rows[0][0]
		assert cell is string, 'cell ${s} must reimport as STRING, got ${typeof(cell).name}; emit=${emitted}'
		assert cell as string == s, 'cell content churned for ${s}: got "${cell as string}"; emit=${emitted}'
	}
}

fn test_table_cell_string_in_typed_column_quotes() {
	// A string cell in a NON-string column always quotes (#413) — bare
	// would coerce per the column type on reimport.
	src := "[t [table[n::int]]\n  'abc'\n]"
	doc := cx.parse(src) or { panic('parse: ${err}') }
	emitted := cx.emit_cx(doc)
	assert emitted.contains("'abc'"), 'string cell in ::int column must stay quoted; emit=${emitted}'
}

// ── #475: the `$tag` structure envelope — full-document lossless round-trips ──
//
// conversions.md §2.2.1 / §2.3.1: a `--lossless` CX→json|yaml→CX round-trip
// recovers an ELEMENT document byte-identically at the strict-canonical
// level. Each case asserts BOTH lanes via cx_text_canonical equality.

fn assert_envelope_roundtrip(src string) {
	orig := cx.cx_text_canonical(src) or { panic('canonical(orig): ${err}') }
	for lane in ['json', 'yaml'] {
		emitted := convert(src, 'cx', lane, true)
		back := convert(emitted, lane, 'cx', false)
		got := cx.cx_text_canonical(back) or {
			panic('canonical(back, ${lane}): ${err}\n  emitted:\n${emitted}\n  back:\n${back}')
		}
		assert got == orig, '#475 ${lane} round-trip not strict-canonical-eq:\n  orig: ${orig}\n  back: ${got}\n  wire:\n${emitted}'
	}
}

fn test_envelope_attrs_children_mixed() {
	assert_envelope_roundtrip('[server host=0.0.0.0 tls=true [port::u16 8080] [note prose body]]')
}

fn test_envelope_mixed_content_order() {
	assert_envelope_roundtrip("[p 'The function ' [code parse] ' returns a ' [em value] '.']")
}

fn test_envelope_meta_anchor_merge_id_ref() {
	assert_envelope_roundtrip('[defaults &base host=localhost [port::u16 8080]]\n[dev *base]\n[user #u-1 name=ann]\n[t assigned=@u-1]\n[link [ref @u-1]]')
}

fn test_envelope_attributed_table() {
	assert_envelope_roundtrip('[grid rows=2 [table[a b::bool]]\n  x true\n  \'1h30m\' false\n]')
}

fn test_envelope_collections_as_values() {
	assert_envelope_roundtrip("[cfg [tags ['web', 'api']] [meta {region: us-west, replicas: 3}] [seq (1, 2, 3)]]")
}

fn test_envelope_typed_map_and_array_values() {
	// #485 item 2: decimal / bigint / bytes / atom / duration values inside
	// maps (sidecar) and arrays (per-item carrier) survive both lanes
	assert_envelope_roundtrip('[m {score: 3.14, big: 99999999999999999999, when: 2023-01-15, wait: 1h30m}]')
	assert_envelope_roundtrip("[m ['a', 1h30m, 2023-01-15, 0x48656c6c6f, :ok]]")
}

fn test_envelope_namespaces() {
	assert_envelope_roundtrip('[doc xmlns:dc=http://purl.org/dc [dc:title Hello]]')
}

fn test_envelope_empty_vs_null_vs_empty_string() {
	// the §2.2 `[items]`-vs-`[items null]` one-bit loss disappears under the
	// envelope
	assert_envelope_roundtrip('[a]\n[b null]\n[c ""]')
}

fn test_envelope_deep_nesting() {
	assert_envelope_roundtrip('[a [b [c [d [e [f deep [g {k: [1, 2, {n: (x, y)}]}]]]]]]]')
}

fn test_envelope_reserved_key_escaping() {
	// user map keys that look reserved must NOT be misread as protocol
	src := "[m {'\$tag': weird, 'cx:seq': fake, '\$children': x, 'cx:k:pre': esc}]"
	assert_envelope_roundtrip(src)
	js := convert(src, 'cx', 'json', true)
	assert js.contains('"cx:k:\$tag"'), 'reserved-looking keys must escape: ${js}'
	assert js.contains('"cx:k:cx:k:pre"'), 'an already-escaped-looking key escapes again: ${js}'
}

fn test_envelope_nonstring_map_keys() {
	// §0.2 cx:key-type sidecar: int / date / bool keys re-type on import
	src := '[m {1: one, 2023-01-15: day, true: yes-key}]'
	assert_envelope_roundtrip(src)
	js := convert(src, 'cx', 'json', true)
	assert js.contains('"cx:key-type"'), 'non-string keys need the key-type sidecar: ${js}'
}

fn test_envelope_multi_root_doc() {
	src := '[server host=a]\n[logging level=info]'
	assert_envelope_roundtrip(src)
	js := convert(src, 'cx', 'json', true)
	assert js.contains('"\$doc"'), 'multi-root docs wrap in \$doc: ${js}'
}

fn test_envelope_typed_attr_battery() {
	assert_envelope_roundtrip('[event count::u16=5 score::decimal=1.5 tag::atom=urgent code=007 h::bytes=0x1f big::bigint=99999999999999999999 when=2023-01-15]')
}

fn test_envelope_string_pinning_children() {
	// number/date/bool-shaped STRING children survive (JSON strings are
	// native; the CX emitter re-quotes on the way out)
	assert_envelope_roundtrip("[a '007']\n[b 'true']\n[c '2023-01-15']\n[d '1h30m']")
}

fn test_envelope_typed_scalar_annotation() {
	assert_envelope_roundtrip('[version::string 1.0]\n[zip::string 90210]\n[xs::int[] 1 2 3]\n[tags::string[] admin user]')
}

fn test_envelope_default_lane_untouched() {
	// the envelope exists ONLY in lossless mode — the idiomatic projection is
	// byte-for-byte what it was
	src := '[data [status :paid] [total::decimal 19.99]]'
	out := convert(src, 'cx', 'json', false)
	assert !out.contains('\$tag'), 'default lane must not carry the envelope: ${out}'
	ym := convert(src, 'cx', 'yaml', false)
	assert !ym.contains('\$tag'), 'default YAML lane must not carry the envelope: ${ym}'
}
