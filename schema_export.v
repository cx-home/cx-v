module cx

// ── Schema export — `.cxs` → JSON Schema 2020-12 (shape_inference.md
// §9, L69; stream 16 W6 — the stream-18 MCP handoff) ─────────────────
//
// A Ring-0 CONVERSION: the exported schema describes the document's
// LOSSLESS JSON projection (the §2.2.1 `$tag` envelope — the shape
// `cx FILE --json`'s conversion lane and the MCP tool boundary carry),
// so a document that validates against the `.cxs` converts to JSON
// that validates against the export. Mapping:
//
//   element type   → object { $tag: const NAME, $attrs: object,
//                             $children: array }
//   attr ::T       → $attrs property (required per [req]/[opt])
//   [elem c [card "M..N"]] → $children allOf-contains with
//                             minContains/maxContains + $defs/$ref
//   scalar body    → $children items (minItems 1 when [req])
//   [list/seq T]   → $children items: array-of-T
//   [map K V]      → $children items: object w/ additionalProperties
//   [or …]/[enum …]/[tuple …] → anyOf / enum / prefixItems
//   decimal/bigint/temporals/bytes → string carriers (format /
//                             contentEncoding), matching the envelope
//
// Determinism: $defs and every property list are name-sorted; the
// root type rides first via $ref. Emission is pure string assembly —
// byte-identical output for identical schema identity (golden-file
// pinned).

pub fn schema_export_json_schema(schema_text string) !string {
	sm := parse_schema(schema_text)!
	if sm.root == '' {
		return error('schema export: schema has no root type')
	}
	mut names := sm.types.keys()
	names.sort()
	mut defs := []string{}
	for name in names {
		st := sm.types[name] or { continue }
		defs << '${json_key(name)}:${export_type_schema(st, sm)}'
	}
	mut b := []string{}
	b << '"\$schema":"https://json-schema.org/draft/2020-12/schema"'
	b << '"title":${json_key(sm.root)}'
	b << '"\$ref":"#/\$defs/${json_escape(sm.root)}"'
	b << '"\$defs":{${defs.join(',')}}'
	return '{' + b.join(',') + '}\n'
}

fn export_type_schema(st SchemaType, sm SchemaModel) string {
	mut props := []string{}
	mut req := []string{}
	req << '"\$tag"'
	props << '"\$tag":{"const":${json_key(st.name)}}'
	// ── attrs ──
	if st.attrs.len > 0 {
		mut anames := st.attrs.keys()
		anames.sort()
		mut aprops := []string{}
		mut areq := []string{}
		mut any_req := false
		for an in anames {
			ar := st.attrs[an] or { continue }
			aprops << '${json_key(an)}:${export_attr_schema(ar)}'
			if ar.required && !ar.has_def {
				areq << json_key(an)
				any_req = true
			}
		}
		mut aobj := []string{}
		aobj << '"type":"object"'
		aobj << '"properties":{${aprops.join(',')}}'
		if areq.len > 0 {
			aobj << '"required":[${areq.join(',')}]'
		}
		if sm.mode != .open {
			aobj << '"additionalProperties":false'
		}
		props << '"\$attrs":{${aobj.join(',')}}'
		if any_req {
			req << '"\$attrs"'
		}
	}
	// ── children: declared elems + body ──
	mut carr := []string{}
	carr << '"type":"array"'
	mut contains := []string{}
	mut any_child_req := false
	mut enames := st.elems.keys()
	enames.sort()
	for en in enames {
		er := st.elems[en] or { continue }
		target := if er.type_name != '' { er.type_name } else { en }
		mut c := []string{}
		c << '"contains":{"\$ref":"#/\$defs/${json_escape(target)}"}'
		c << '"minContains":${er.min}'
		if !er.max_unbounded {
			c << '"maxContains":${er.max}'
		}
		contains << '{' + c.join(',') + '}'
		if er.min >= 1 {
			any_child_req = true
		}
	}
	if contains.len > 0 {
		carr << '"allOf":[${contains.join(',')}]'
	}
	mut body_emitted := false
	if st.body.declared && st.elems.len == 0 {
		if bi := export_body_items_schema(st.body) {
			carr << '"items":${bi}'
			body_emitted = true
			if st.body.required {
				carr << '"minItems":1'
				any_child_req = true
			}
		}
		if st.body.kind == 'none' {
			carr << '"maxItems":0'
			body_emitted = true
		}
	}
	if contains.len > 0 || body_emitted {
		props << '"\$children":{${carr.join(',')}}'
		if any_child_req {
			req << '"\$children"'
		}
	}
	mut obj := []string{}
	obj << '"type":"object"'
	obj << '"properties":{${props.join(',')}}'
	obj << '"required":[${req.join(',')}]'
	return '{' + obj.join(',') + '}'
}

// export_body_items_schema maps a BodyRule to the JSON-Schema of ONE
// $children item. none when the kind carries no item constraint
// ('elem'/'mixed'/'any'/'scalar'/'' — open).
fn export_body_items_schema(br BodyRule) ?string {
	match br.kind {
		'', 'elem', 'mixed', 'any', 'scalar', 'none' {
			return none
		}
		'arr' {
			inner := export_kind_text_schema(br.item_kind)
			return '{"type":"array","items":${inner}}'
		}
		'seq' {
			// a sequence body rides the {"cx:seq": [...]} carrier.
			inner := export_kind_text_schema(br.item_kind)
			return export_carrier('cx:seq', '{"type":"array","items":${inner}}')
		}
		'map' {
			inner := export_kind_text_schema(br.item_kind)
			return '{"type":"object","additionalProperties":${inner}}'
		}
		'or' {
			mut ms := []string{}
			for m in br.members {
				ms << export_kind_text_schema(m)
			}
			return '{"anyOf":[${ms.join(',')}]}'
		}
		'tuple' {
			// tuple bodies are paren sequences → the cx:seq carrier
			// wrapping a fixed-arity prefixItems array.
			mut ms := []string{}
			for m in br.members {
				ms << export_kind_text_schema(m)
			}
			return export_carrier('cx:seq', '{"type":"array","prefixItems":[${ms.join(',')}],"items":false,"minItems":${ms.len},"maxItems":${ms.len}}')
		}
		'typeref' {
			return '{"\$ref":"#/\$defs/${json_escape(br.item_kind)}"}'
		}
		else {
			return export_child_scalar_schema(br.kind, br.enum_vals, br.pat, br.range_min,
				br.range_max, br.len_min, br.len_max)
		}
	}
}

// export_carrier wraps an inner schema in the {"cx:KEY": inner}
// single-key carrier object (conversions.md §0.2 — the JSON image of
// the XML <cx:T> carrier).
fn export_carrier(key string, inner string) string {
	return '{"type":"object","properties":{${json_key(key)}:${inner}},"required":[${json_key(key)}],"additionalProperties":false}'
}

// export_child_scalar_schema maps a scalar kind in CHILD position:
// type-bearing kinds ride their {"cx:T": "text"} carrier (the
// envelope's own emission — scalar_native); JSON-native kinds ride
// bare values. Refinements apply to the payload.
fn export_child_scalar_schema(kind string, enum_vals []string, pat string, range_min string,
	range_max string, len_min string, len_max string) string {
	if kind in ['atom', 'date', 'datetime', 'bytes', 'decimal', 'bigint', 'duration', 'period',
		'time'] {
		mut inner := ['"type":"string"']
		export_refinements(mut inner, enum_vals, pat, '', '', len_min, len_max, kind)
		return export_carrier('cx:${kind}', '{' + inner.join(',') + '}')
	}
	mut s := export_scalar_schema_parts(kind)
	export_refinements(mut s, enum_vals, pat, range_min, range_max, len_min, len_max, kind)
	return '{' + s.join(',') + '}'
}

fn export_attr_schema(ar AttrRule) string {
	if ar.members.len > 0 {
		mut ms := []string{}
		for m in ar.members {
			ms << export_kind_text_schema(m)
		}
		return '{"anyOf":[${ms.join(',')}]}'
	}
	if ar.type_name in ['arr', 'seq'] {
		inner := export_kind_text_schema(ar.item_kind)
		return '{"type":"array","items":${inner}}'
	}
	mut s := export_scalar_schema_parts(ar.type_name)
	export_refinements(mut s, ar.enum_vals, ar.pat, ar.range_min, ar.range_max,
		ar.len_min, ar.len_max, ar.type_name)
	return '{' + s.join(',') + '}'
}

// export_kind_text_schema maps a kind TEXT (scalar name or a verbatim
// bracket-prefix container / capitalized type name) to a schema.
fn export_kind_text_schema(kind_text string) string {
	t := kind_text.trim_space()
	if t.starts_with('[') && t.ends_with(']') && t.len > 2 {
		inner := t[1..t.len - 1].trim_space()
		toks := split_ws_quote_bracket(inner)
		if toks.len >= 2 {
			match toks[0] {
				'list', 'seq' {
					return '{"type":"array","items":${export_kind_text_schema(toks[1..].join(' '))}}'
				}
				'map' {
					if toks.len >= 3 {
						return '{"type":"object","additionalProperties":${export_kind_text_schema(toks[2..].join(' '))}}'
					}
				}
				'or' {
					mut ms := []string{}
					for m in toks[1..] {
						ms << export_kind_text_schema(m)
					}
					return '{"anyOf":[${ms.join(',')}]}'
				}
				'tuple' {
					mut ms := []string{}
					for m in toks[1..] {
						ms << export_kind_text_schema(m)
					}
					return '{"type":"array","prefixItems":[${ms.join(',')}],"items":false,"minItems":${ms.len},"maxItems":${ms.len}}'
				}
				'enum' {
					mut vs := []string{}
					for v in toks[1..] {
						vs << json_key(strip_quotes(v.trim_space().trim_left(':')))
					}
					return '{"enum":[${vs.join(',')}]}'
				}
				else {}
			}
		}
	}
	// A capitalized bareword is an element-name type → $defs reference.
	if t.len > 0 && t[0] >= `A` && t[0] <= `Z` {
		return '{"\$ref":"#/\$defs/${json_escape(t)}"}'
	}
	// kind texts appear in $children content — the child-position map
	// (type-bearing kinds ride their carriers, recursively).
	return export_child_scalar_schema(t, []string{}, '', '', '', '', '')
}

// export_scalar_schema_parts maps one scalar kind to its JSON-Schema
// fragments — string carriers for the kinds JSON numbers cannot hold
// exactly (matching the envelope's $attr-types treatment).
fn export_scalar_schema_parts(kind string) []string {
	return match kind {
		'string', 's', 'atom' {
			['"type":"string"']
		}
		'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
			['"type":"integer"']
		}
		'float', 'f16', 'f32', 'f64', 'number' {
			['"type":"number"']
		}
		'bool' {
			['"type":"boolean"']
		}
		'null' {
			['"type":"null"']
		}
		'date' {
			['"type":"string"', '"format":"date"']
		}
		'datetime' {
			['"type":"string"', '"format":"date-time"']
		}
		'time' {
			['"type":"string"', '"format":"time"']
		}
		'duration', 'period' {
			['"type":"string"', '"format":"duration"']
		}
		'bytes' {
			['"type":"string"', '"contentEncoding":"base64"']
		}
		'decimal', 'bigint' {
			// exact numerics ride their verbatim text (never a JSON
			// float — the envelope's own carriage).
			['"type":"string"']
		}
		else {
			[]string{}
		}
	}
}

fn export_refinements(mut s []string, enum_vals []string, pat string, range_min string,
	range_max string, len_min string, len_max string, kind string) {
	if enum_vals.len > 0 {
		mut vs := []string{}
		for v in enum_vals {
			vs << json_key(v)
		}
		s << '"enum":[${vs.join(',')}]'
	}
	if pat != '' {
		s << '"pattern":${json_key(pat)}'
	}
	numeric := kind in ['int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64', 'float',
		'f16', 'f32', 'f64', 'number']
	if range_min != '' {
		if numeric {
			s << '"minimum":${range_min}'
		}
	}
	if range_max != '' {
		if numeric {
			s << '"maximum":${range_max}'
		}
	}
	if len_min != '' {
		s << '"minLength":${len_min}'
	}
	if len_max != '' {
		s << '"maxLength":${len_max}'
	}
}

fn json_escape(s string) string {
	mut out := []u8{cap: s.len}
	for c in s {
		match c {
			`"` { out << `\\` out << `"` }
			`\\` { out << `\\` out << `\\` }
			else { out << c }
		}
	}
	return out.bytestr()
}

fn json_key(s string) string {
	return '"' + json_escape(s) + '"'
}
