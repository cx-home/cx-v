module cx

import strconv

// ── YAML Emitter ──────────────────────────────────────────────────────────────
// Hand-rolled YAML emitter using semantic JSON value.

pub fn emit_yaml(doc Document) string {
	val := sem_document(doc)
	return yaml_value(val, 0, false)
}

// emit_yaml_lossless is the conversions.md §0.2/§2.3.1 lossless YAML emit
// (#444, #475). Scalars ride YAML's native tag system (atom / decimal /
// bigint tag in both modes; dates are native; bytes ride `!!binary`;
// lossless additionally tags sized numerics and temporal spans) — tags are
// position-independent, so YAML needs no per-item carrier objects. The
// STRUCTURE layer is the same `$tag` envelope as the JSON lane (§2.2.1 /
// §2.3.1, one envelope — two renderings): elements emit as mappings over the
// reserved `$`-key set, with `cx:seq` / `cx:raw` / `cx:entity` /
// `cx:key-type` carriers and `cx:k:` key escaping shared verbatim.
pub fn emit_yaml_lossless(doc Document) string {
	val := sem_document_lossless(doc)
	return yaml_value(val, 0, true)
}

pub fn emit_yaml_docs(docs []Document) string {
	return yaml_docs_mode(docs, false)
}

pub fn emit_yaml_docs_lossless(docs []Document) string {
	return yaml_docs_mode(docs, true)
}

fn yaml_docs_mode(docs []Document, lossless bool) string {
	mut parts := []string{}
	for doc in docs {
		// lossless multi-document streams carry the same per-document
		// envelope projection as the single-document emit (#475)
		val := if lossless { sem_document_lossless(doc) } else { sem_document(doc) }
		s := yaml_value(val, 0, lossless)
		if s.starts_with('---') { parts << s } else { parts << '---\n${s}' }
	}
	return parts.join('')
}

fn yaml_value(v JsonVal, depth int, lossless bool) string {
	return match v {
		JsonNull    { 'null' }
		JsonTyped   { yaml_typed_scalar(v as JsonTyped, lossless) }
		bool        { if v as bool { 'true' } else { 'false' } }
		i64         { (v as i64).str() }
		f64         { format_float(v as f64) }
		string      { yaml_str(v as string) }
		[]JsonVal   { yaml_array(v as []JsonVal, depth, lossless) }
		map[string]JsonVal { yaml_object(v as map[string]JsonVal, depth, lossless) }
	}
}

// yaml_typed_scalar renders one typed CX scalar per the conversions.md §0.2
// YAML columns.
fn yaml_typed_scalar(t JsonTyped, lossless bool) string {
	return match t.typ {
		// Native tags in BOTH modes (default column already carries them).
		// The payload is quoted so the reader that strips the tag still sees
		// a string, never a re-typed number.
		'atom'    { '!!cx:atom "${t.text}"' }
		'decimal' { '!!cx:decimal "${t.text}"' }
		'bigint'  { '!!cx:bigint "${t.text}"' }
		// YAML-native forms in both modes ("(same — native)").
		'date', 'datetime' { t.text }
		// bytes → `!!binary` in both modes (§0.2 bytes row, #458).
		'bytes' { '!!binary "${bytes_hex_to_base64(t.text)}"' }
		// Temporal spans: idiomatic plain scalar by default (the importer's
		// auto-typing recovers them, mirroring dates); tagged in lossless mode.
		'duration', 'period' {
			if lossless { '!!cx:${t.typ} "${t.text}"' } else { t.text }
		}
		// Sized numerics: native number by default; `+ !!cx:i32 etc.` in
		// lossless mode per the §0.2 sized rows.
		else {
			if lossless { '!!cx:${t.typ} "${t.text}"' } else { t.text }
		}
	}
}

fn yaml_str(s string) string {
	// Quote if needed
	if s.len == 0 { return '""' }
	// Check for values that need quoting
	needs_quote := s.starts_with(' ') || s.ends_with(' ')
		|| s.contains('\n') || s.contains('\r') || s.contains('\t')
		// a trailing ':' re-reads as a `key:` mapping entry (block context)
		|| s.ends_with(':')
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
	// Also quote if it would RE-READ as another type (to avoid
	// re-interpretation).
	// #441: only when the whole token actually parses — the old check swallowed
	// the atof64 error, so ANY string containing `.` or `e` (most English
	// words: "The Hobbit", "year") was quoted. `E` is included so `1E5` cannot
	// re-import as a float. The has-digit guard mirrors the lexicon [L20b]
	// float rule (atof64 leniently returns 0.0 for digit-less `e` / `.`).
	if _ := s.parse_int(10, 64) { return '"${s}"' }
	// Over-i64 digit runs re-read as bigint (the importer mirrors the [L20]
	// D-H auto-promotion), so a well-formed integer STRING always quotes.
	if is_v34_decimal_int(s) { return '"${s}"' }
	if (s.contains('.') || s.contains('e') || s.contains('E')) && has_ascii_digit(s) {
		if _ := strconv.atof64(s) {
			return '"${s}"'
		}
	}
	// Shapes the importer auto-types per conversions.md §5.1 (dates) and the
	// CX lexicon (temporal spans): a plain STRING of that shape must quote to
	// stay a string (#444 — typed round-trip protection).
	if is_date(s) || is_datetime(s) { return '"${s}"' }
	if _ := temporal_span_kind(s) { return '"${s}"' }
	return s
}

fn yaml_array(arr []JsonVal, depth int, lossless bool) string {
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
			child := yaml_value(v, depth + 1, lossless)
			child_lines := child.split('\n')
			for i, cl in child_lines {
				if i == 0 {
					lines << '${ind}- ${cl.trim_left(' ')}'
				} else {
					lines << cl
				}
			}
		} else {
			lines << '${ind}- ${yaml_value(v, depth + 1, lossless)}'
		}
	}
	return lines.join('\n')
}

fn yaml_object(obj map[string]JsonVal, depth int, lossless bool) string {
	if obj.len == 0 { return '{}' }
	ind := '  '.repeat(depth)
	mut lines := []string{}
	for k, vv in obj {
		key_str := yaml_str(k)
		child := yaml_value(vv, depth + 1, lossless)
		if vv is map[string]JsonVal || vv is []JsonVal {
			// Empty containers render as inline flow (`k: []` / `k: {}`).
			// Emitting them as a dangling `[]`/`{}` block line put them at
			// column 0 under the key — invalid YAML that re-imported as null
			// (data loss on the round trip, #412).
			if child == '[]' || child == '{}' {
				lines << '${ind}${key_str}: ${child}'
				continue
			}
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
