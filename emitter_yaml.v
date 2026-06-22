module cx

import strconv

// ── YAML Emitter ──────────────────────────────────────────────────────────────
// Hand-rolled YAML emitter using semantic JSON value.

pub fn emit_yaml(doc Document) string {
	val := sem_document(doc)
	return yaml_value(val, 0, false)
}

pub fn emit_yaml_docs(docs []Document) string {
	mut parts := []string{}
	for doc in docs {
		val := sem_document(doc)
		s := yaml_value(val, 0, false)
		if s.starts_with('---') { parts << s } else { parts << '---\n${s}' }
	}
	return parts.join('')
}

fn yaml_value(v JsonVal, depth int, _ bool) string {
	return match v {
		JsonNull    { 'null' }
		// Atom: YAML's native tag system carries the type even in
		// default mode (conversions.md atom row). The payload is the bare
		// name; readers that don't know `!!cx:atom` preserve it as a string.
		JsonAtom    { '!!cx:atom "${(v as JsonAtom).name}"' }
		bool        { if v as bool { 'true' } else { 'false' } }
		i64         { (v as i64).str() }
		f64         { format_float(v as f64) }
		string      { yaml_str(v as string) }
		[]JsonVal   { yaml_array(v as []JsonVal, depth) }
		map[string]JsonVal { yaml_object(v as map[string]JsonVal, depth) }
	}
}

fn yaml_str(s string) string {
	// Quote if needed
	if s.len == 0 { return '""' }
	// Check for values that need quoting
	needs_quote := s.starts_with(' ') || s.ends_with(' ')
		|| s.contains('\n') || s.contains('\r') || s.contains('\t')
		|| s.contains(': ') || s.contains(' #') || s.contains('[') || s.contains(']')
		|| s.contains('{') || s.contains('}') || s.contains(',')
		|| s.contains('*') || s.contains('&') || s.contains('|') || s.contains('>')
		|| s.contains('!') || s.contains('%') || s.contains('@') || s.contains('`')
		|| s.starts_with('"') || s.starts_with("'") || s.starts_with('-')
		|| s.starts_with('?') || s.starts_with(':') || s.starts_with('#')
		|| s == 'true' || s == 'false' || s == 'null' || s == 'yes' || s == 'no'
		|| s == 'on' || s == 'off'
	if needs_quote {
		escaped := s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
		return '"${escaped}"'
	}
	// Also quote if it looks like a number (to avoid re-interpretation)
	if _ := s.parse_int(10, 64) { return '"${s}"' }
	if s.contains('.') || s.contains('e') {
		_ := strconv.atof64(s) or { 0.0 }
		return '"${s}"'
	}
	return s
}

fn yaml_array(arr []JsonVal, depth int) string {
	if arr.len == 0 { return '[]' }
	ind := '  '.repeat(depth)
	mut lines := []string{}
	for v in arr {
		if v is map[string]JsonVal || v is []JsonVal {
			// A block item (mapping / nested sequence). Render the child at
			// depth+1 so its indentation equals the column just after "- ",
			// then splice the dash onto the first line and keep the rest
			// aligned. Previously the child's full indent was appended after
			// "- ", so the first key sat deeper than its siblings → invalid
			// YAML (#10).
			child := yaml_value(v, depth + 1, false)
			child_lines := child.split('\n')
			for i, cl in child_lines {
				if i == 0 {
					lines << '${ind}- ${cl.trim_left(' ')}'
				} else {
					lines << cl
				}
			}
		} else {
			lines << '${ind}- ${yaml_value(v, depth + 1, false)}'
		}
	}
	return lines.join('\n')
}

fn yaml_object(obj map[string]JsonVal, depth int) string {
	if obj.len == 0 { return '{}' }
	ind := '  '.repeat(depth)
	mut lines := []string{}
	for k, vv in obj {
		key_str := yaml_str(k)
		child := yaml_value(vv, depth + 1, false)
		if vv is map[string]JsonVal || vv is []JsonVal {
			lines << '${ind}${key_str}:'
			// Indent the child
			child_lines := child.split('\n')
			for cl in child_lines {
				if cl.len > 0 { lines << cl }
			}
		} else {
			lines << '${ind}${key_str}: ${child}'
		}
	}
	return lines.join('\n')
}
