module cx

// ── TOML Emitter ──────────────────────────────────────────────────────────────
// Hand-rolled TOML emitter using semantic JSON value.

pub fn emit_toml(doc Document) string {
	val := sem_document(doc)
	top := if val is map[string]JsonVal { val as map[string]JsonVal } else {
		mut m := map[string]JsonVal{}
		m['value'] = val
		m
	}
	return toml_table(top, '')
}

pub fn emit_toml_docs(docs []Document) string {
	return docs.map(emit_toml(it)).join('\n')
}

fn toml_table(obj map[string]JsonVal, prefix string) string {
	mut simple := []string{}
	mut subtables := []string{}

	for k, v in obj {
		full_key := if prefix.len > 0 { '${prefix}.${k}' } else { k }
		match v {
			map[string]JsonVal {
				// nested table
				header := '[${toml_key(full_key)}]'
				content := toml_table(v as map[string]JsonVal, full_key)
				subtables << '${header}\n${content}'
			}
			[]JsonVal {
				arr := v as []JsonVal
				if arr.len > 0 && arr[0] is map[string]JsonVal {
					// array of tables
					for item in arr {
						if item is map[string]JsonVal {
							header := '[[${toml_key(full_key)}]]'
							content := toml_table(item as map[string]JsonVal, full_key)
							subtables << '${header}\n${content}'
						}
					}
				} else {
					simple << '${toml_key(k)} = ${toml_array(arr)}'
				}
			}
			else {
				tv := toml_value(v)
				if tv.len > 0 {
					simple << '${toml_key(k)} = ${tv}'
				}
			}
		}
	}

	mut lines := []string{}
	for s in simple { lines << s }
	for st in subtables {
		if lines.len > 0 { lines << '' }
		lines << st
	}
	if lines.len > 0 { lines << '' }
	return lines.join('\n')
}

fn toml_value(v JsonVal) string {
	return match v {
		JsonNull    { '' } // TOML has no null — omit
		bool        { if v as bool { 'true' } else { 'false' } }
		i64         { (v as i64).str() }
		f64         { format_float(v as f64) }
		string      { toml_str(v as string) }
		[]JsonVal   { toml_array(v as []JsonVal) }
		map[string]JsonVal { toml_inline_table(v as map[string]JsonVal) }
	}
}

fn toml_str(s string) string {
	escaped := s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
	return '"${escaped}"'
}

fn toml_array(arr []JsonVal) string {
	items := arr.filter(!(it is JsonNull)).map(toml_value(it))
	return '[${items.join(', ')}]'
}

fn toml_inline_table(obj map[string]JsonVal) string {
	pairs := obj.keys().map('${toml_key(it)} = ${toml_value(obj[it] or { JsonVal(JsonNull{}) })}')
	return '{${pairs.join(', ')}}'
}

fn toml_key(k string) string {
	// Quote if key has special chars
	needs_quote := k.bytes().any(!(it >= `a` && it <= `z`) && !(it >= `A` && it <= `Z`) && !(it >= `0` && it <= `9`) && it != `_` && it != `-`)
	if needs_quote { return '"${k}"' }
	return k
}
