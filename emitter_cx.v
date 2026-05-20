module cx

import strconv

// ── CX Emitter ────────────────────────────────────────────────────────────────

pub fn emit_cx(doc Document) string {
	return cx_emit(doc, false)
}

pub fn emit_cx_compact(doc Document) string {
	return cx_emit(doc, true)
}

pub fn emit_cx_docs(docs []Document) string {
	parts := docs.map(emit_cx(it))
	return parts.join('\n---\n')
}

pub fn emit_cx_compact_docs(docs []Document) string {
	parts := docs.map(emit_cx_compact(it))
	return parts.join('\n---\n')
}

fn cx_emit(doc Document, compact bool) string {
	mut out := []string{}
	for n in doc.prolog { cx_emit_node(n, 0, compact, mut out) }
	if dt := doc.doctype { emit_cx_doctype(dt, mut out) }
	for n in doc.elements { cx_emit_node(n, 0, compact, mut out) }
	result := out.join('')
	return result.trim_right('\n')
}

fn cx_ind(depth int, compact bool) string {
	if compact { return '' }
	mut s := ''
	for _ in 0..depth { s += '  ' }
	return s
}

fn cx_emit_node(n Node, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	match n {
		Element          { cx_emit_element(n, depth, compact, mut out) }
		TextNode         { out << cx_quote_text_if_needed(n.value) }
		ScalarNode       { out << cx_scalar(n) }
		CommentNode      {
			if n.is_line {
				out << '${ind}# ${n.value}${nl}'
			} else {
				out << '${ind}[-${n.value}]${nl}'
			}
		}
		PINode           { cx_emit_pi(n, depth, compact, mut out) }
		XMLDeclNode      { emit_cx_xml_decl(n, mut out) }
		CXDirectiveNode  { emit_cx_directive(n, mut out) }
		EntityRefNode    { out << '&${n.name};' }
		RawTextNode      { out << '[#${n.value}#]${nl}' }
		AliasNode        { out << '${ind}[*${n.name}]${nl}' }
		EntityDeclNode   { cx_emit_entity_decl(n, depth, compact, mut out) }
		ElementDeclNode  { out << '${ind}[!ELEMENT ${n.name} ${n.contentspec}]${nl}' }
		AttlistDeclNode  { cx_emit_attlist_decl(n, depth, compact, mut out) }
		NotationDeclNode { cx_emit_notation_decl(n, depth, compact, mut out) }
		ConditionalSectNode { cx_emit_conditional_sect(n, depth, compact, mut out) }
		BlockContentNode { cx_emit_block_content(n, depth, compact, mut out) }
		InterpolationNode { cx_emit_interpolation(n, depth, compact, mut out) }
		EvalDirectiveNode { cx_emit_eval_directive(n, depth, compact, mut out) }
		SequenceNode      { out << '${ind}${cx_emit_sequence_inline(n, compact)}${nl}' }
		ArrayNode         { out << '${ind}${cx_emit_array_inline(n, compact)}${nl}' }
		MapNode           { out << '${ind}${cx_emit_map_inline(n, compact)}${nl}' }
	}
}

// cx_emit_sequence_inline renders a `(a, b, c)` literal using canonical
// form per ADR 0017 §D14: parens, single space after comma, trailing comma
// omitted. Empty sequence: `()`.
fn cx_emit_sequence_inline(n SequenceNode, compact bool) string {
	if n.items.len == 0 { return '()' }
	parts := n.items.map(cx_emit_collection_item(it, compact))
	return '(${parts.join(', ')})'
}

// cx_emit_array_inline renders a `[a, b, c]` literal per ADR 0017 §D14.
// Empty array: `[]`. Trailing commas are omitted per §D14 canonical.
// Single-element arrays emit as `[a]` and rely on context-aware parse
// (EvalDirective ArgArray per resolution 2.i; :table cell per
// read_table_cell's force-array rule) to preserve Array semantics on
// re-parse. In contexts where neither rule applies (raw expression
// position), `[a]` parses as Element per §D1's comma-marker rule —
// this is consistent with the cell-parser's force-array policy
// keeping the canonical-form invariant clean.
fn cx_emit_array_inline(n ArrayNode, compact bool) string {
	if n.items.len == 0 { return '[]' }
	parts := n.items.map(cx_emit_collection_item(it, compact))
	return '[${parts.join(', ')}]'
}

// cx_emit_map_inline renders a `{k: v, k: v}` literal per ADR 0017 §D14:
// single space after `:` and after `,`. Entries emit in insertion order
// (runtime preservation); canonical mode handled by the caller / hash path
// when lexicographic ordering is required. Empty map: `{}`.
fn cx_emit_map_inline(n MapNode, compact bool) string {
	if n.entries.len == 0 { return '{}' }
	mut parts := []string{cap: n.entries.len}
	for entry in n.entries {
		key_str := cx_emit_map_key(entry.key_type, entry.key_value)
		val_str := cx_emit_collection_item(entry.value, compact)
		parts << '${key_str}: ${val_str}'
	}
	return '{${parts.join(', ')}}'
}

// cx_emit_collection_item renders one item inside a sequence / array / map
// value. Reuses the existing emitter helpers; for nested collections it
// recurses through cx_emit_*_inline to keep the inline-canonical form.
fn cx_emit_collection_item(n Node, compact bool) string {
	return match n {
		TextNode      { cx_quote_text_if_needed(n.value) }
		ScalarNode    { cx_scalar(n) }
		EntityRefNode { '&${n.name};' }
		RawTextNode   { '[#${n.value}#]' }
		SequenceNode  { cx_emit_sequence_inline(n, compact) }
		ArrayNode     { cx_emit_array_inline(n, compact) }
		MapNode       { cx_emit_map_inline(n, compact) }
		InterpolationNode { '[?=${n.expr}]' }
		Element {
			mut tmp := []string{}
			cx_emit_element(n, 0, compact, mut tmp)
			tmp.join('').trim_right('\n')
		}
		EvalDirectiveNode {
			mut tmp := []string{}
			cx_emit_eval_directive(n, 0, true, mut tmp)
			tmp.join('').trim_right('\n')
		}
		else { '' }
	}
}

// cx_emit_map_key renders an atomic map key in source-text form. Bare-name
// strings emit unquoted when they would re-parse as the same name; other
// strings (and all non-string keys) emit in their typed scalar form.
fn cx_emit_map_key(kt ScalarType, kv ScalarValue) string {
	if kt == .string_type {
		s := match kv { string { kv } else { scalar_value_str(kv) } }
		if cx_is_bare_name(s) { return s }
		return cx_choose_quote(s)
	}
	return cx_scalar(ScalarNode{ data_type: kt, value: kv })
}

fn cx_is_bare_name(s string) bool {
	if s.len == 0 { return false }
	if !is_name_start(s[0]) { return false }
	for i in 1 .. s.len {
		if !is_name_char(s[i]) { return false }
	}
	return true
}

fn cx_emit_element(e Element, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }

	// v3.4 (ADR 0003 D1 second bullet): body-position [ref @id] form.
	// Emitted as `[ref @<body_ref>]`, no anchors / merge / id meta /
	// attrs / items per the parser's rule that body_ref is set only
	// when the source had exactly that shape.
	if br := e.body_ref {
		out << '${ind}[ref @${br}]${nl}'
		return
	}

	// v3.4: emit :table form when this Element carries TableData.
	if td := e.table {
		cx_emit_table_element(e.name, td, depth, compact, mut out)
		return
	}

	has_child_elements := e.items.any(it is Element)
	has_text := e.items.any(it is TextNode || it is ScalarNode || it is EntityRefNode || it is RawTextNode)
	is_multiline := !compact && has_child_elements && !has_text

	if is_multiline {
		meta := cx_build_meta(e)
		out << '${ind}[${e.name}${meta}${nl}'
		for item in e.items { cx_emit_node(item, depth + 1, compact, mut out) }
		out << '${ind}]${nl}'
	} else if e.items.len == 0 && e.attrs.len == 0 && e.anchor == none && e.merge == none && e.data_type == none {
		out << '${ind}[${e.name}]${nl}'
	} else {
		meta := cx_build_meta(e)
		body := cx_build_inline_body(e.items, compact)
		body_sep := if body.len > 0 { ' ' } else { '' }
		out << '${ind}[${e.name}${meta}${body_sep}${body}]${nl}'
	}
}

// v3.4: emit a :table block. Header columns are emitted as
// `name:type` pairs (untyped columns drop the `:type` suffix); rows
// are space-separated cells. Cells use canonical scalar formatting:
// quoted iff the value is empty, contains whitespace, or would
// auto-type differently from its declared column type.
fn cx_emit_table_element(name string, td TableData, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }
	row_ind := cx_ind(depth + 1, compact)

	mut header_parts := []string{}
	for col in td.cols {
		if col.type_name == '' {
			header_parts << col.name
		} else {
			header_parts << '${col.name}:${col.type_name}'
		}
	}
	header := header_parts.join(' ')

	if compact || td.rows.len == 0 {
		mut all := []string{}
		for row in td.rows {
			for i, cell in row {
				ct := if i < td.cols.len { td.cols[i].type_name } else { '' }
				all << cx_format_table_cell(cell, ct)
			}
		}
		body := all.join(' ')
		body_sep := if body.len > 0 { ' ' } else { '' }
		out << '${ind}[${name} :table[${header}]${body_sep}${body}]${nl}'
		return
	}

	out << '${ind}[${name} :table[${header}]${nl}'
	for row in td.rows {
		mut cells := []string{}
		for i, cell in row {
			ct := if i < td.cols.len { td.cols[i].type_name } else { '' }
			cells << cx_format_table_cell(cell, ct)
		}
		out << '${row_ind}${cells.join(' ')}${nl}'
	}
	out << '${ind}]${nl}'
}

// cx_format_table_cell formats one cell value for emission. Bare
// when the value matches the column's declared type and contains
// no whitespace; quoted otherwise. col_type is reserved for future
// per-column-type formatting (e.g., float-precision matching the
// declared :f32 width); currently unused.
fn cx_format_table_cell(v TableCellValue, _col_type string) string {
	return match v {
		i64       { v.str() }
		f64       { format_float(v) }
		bool      { if v { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    {
			if v.len == 0 || v.contains(' ') || v.contains('\t')
				|| v.contains('\n') || v.contains("'")
				|| v.contains('[') || v.contains(']') {
				cx_choose_quote(v)
			} else {
				v
			}
		}
		// ADR 0018 §D4 + ADR 0017 §D14: collection-typed cells emit
		// in canonical CX literal form. Reuses the existing inline
		// emitters for ArrayNode / MapNode / SequenceNode so the
		// canonical-form rules (lex-sorted map keys, single-space
		// after comma, etc.) apply identically inside a :table cell.
		ArrayNode    { cx_emit_array_inline(v, true) }
		MapNode      { cx_emit_map_inline(v, true) }
		SequenceNode { cx_emit_sequence_inline(v, true) }
	}
}

fn cx_build_meta(e Element) string {
	mut s := ''
	if a := e.anchor  { s += ' &${a}' }
	if m := e.merge   { s += ' *${m}' }
	if id := e.id     { s += ' #${id}' }
	if dt := e.data_type { s += ' :${dt}' }
	for a in e.attrs {
		// v3.5 (ADR 0016): BracketBody attribute values round-trip as
		// `name=[body]`. The body is emitted inline as a body sequence.
		// v0.7.0 (multi-line-text symmetry): single-item body whose
		// node is RawTextNode or BlockContentNode emits as the direct
		// form `name=[# ... #]` / `name=[| ... |]` — dropping the
		// redundant outer BracketBody wrap. Parses back to the same AST.
		if body_items := a.body {
			if body_items.len == 1 {
				it := body_items[0]
				if it is RawTextNode {
					s += ' ${a.name}=[#${(it as RawTextNode).value}#]'
					continue
				}
				if it is BlockContentNode {
					block := it as BlockContentNode
					mut inner := []string{}
					for sub in block.items {
						if sub is TextNode {
							inner << (sub as TextNode).value
						}
					}
					s += ' ${a.name}=[|${inner.join('')}|]'
					continue
				}
			}
			body_str := cx_build_inline_body(body_items, true)
			s += ' ${a.name}=[${body_str}]'
			continue
		}
		val_str := a.str_value()
		emitted := if a.is_ref {
			// ADR 0003 D1: bare `@id` round-trips verbatim. The
			// stored value is the bare ID string (no '@' prefix).
			'@${val_str}'
		} else if a.data_type == none && cx_would_autotype(val_str) {
			"'${val_str}'"
		} else {
			cx_quote_attr_if_needed(val_str)
		}
		s += ' ${a.name}=${emitted}'
	}
	return s
}

fn cx_build_inline_body(items []Node, compact bool) string {
	mut parts := []string{}
	for item in items {
		match item {
			TextNode {
				if item.value.trim_space().len == 0 { continue }
				parts << cx_quote_text_if_needed(item.value)
			}
			ScalarNode    { parts << cx_scalar(item) }
			EntityRefNode { parts << '&${item.name};' }
			RawTextNode   { parts << '[#${item.value}#]' }
			Element {
				mut tmp := []string{}
				cx_emit_element(item, 0, compact, mut tmp)
				parts << tmp.join('').trim_right('\n')
			}
			BlockContentNode {
				mut s := '[|'
				for bi in item.items {
					match bi {
						TextNode { s += bi.value }
						Element  {
							mut tmp := []string{}
							cx_emit_element(bi, 0, compact, mut tmp)
							s += tmp.join('').trim_right('\n')
						}
						else {}
					}
				}
				s += '|]'
				parts << s
			}
			InterpolationNode {
				parts << '[?=${item.expr}]'
			}
			EvalDirectiveNode {
				mut tmp := []string{}
				cx_emit_eval_directive(item, 0, true, mut tmp)
				parts << tmp.join('').trim_right('\n')
			}
			SequenceNode { parts << cx_emit_sequence_inline(item, compact) }
			ArrayNode    { parts << cx_emit_array_inline(item, compact) }
			MapNode      { parts << cx_emit_map_inline(item, compact) }
			else {}
		}
	}
	return parts.join(' ')
}

fn cx_quote_text_if_needed(s string) string {
	needs_quote := s.starts_with(' ') || s.ends_with(' ')
		|| s.contains('  ') || s.contains('\n') || s.contains('\t')
		|| s.contains('[') || s.contains(']') || s.contains('&')
		|| s.starts_with(':') || s.starts_with("'") || s.starts_with('"')
		|| cx_would_autotype(s)
	if !needs_quote { return s }
	return cx_choose_quote(s)
}

fn cx_choose_quote(s string) string {
	has_single := s.contains("'")
	has_double := s.contains('"')
	if !has_single { return "'${s}'" }
	if !has_double { return '"${s}"' }
	if !s.contains("'''") { return "'''${s}'''" }
	return '"${s}"'
}

fn cx_would_autotype(s string) bool {
	if s.contains(' ') { return false }
	if s.starts_with('0x') || s.starts_with('0X') { return true }
	if s == 'true' || s == 'false' || s == 'null' { return true }
	if _ := s.parse_int(10, 64) { return true }
	if s.contains('.') || s.contains('e') || s.contains('E') {
		if _ := strconv.atof64(s) { return true }
	}
	if is_datetime(s) { return true }
	if is_date(s) { return true }
	return false
}

fn cx_quote_attr_if_needed(s string) string {
	// v0.7.0 (multi-line-text symmetry): newline-bearing string values
	// cannot be emitted as bare / single-quote / double-quote (all
	// single-line) without invalidating the round-trip. Triquote is
	// now valid in AttValue position per [55a] amendment, so use it.
	if s.contains('\n') {
		return "'''${s}'''"
	}
	if s.contains(' ') || s.contains("'") || s.contains('"') || s.len == 0 {
		return "'${s}'"
	}
	// ADR 0003: bare `@id` at attribute-value position is a syntactic
	// reference. A literal string starting with '@' must be quoted to
	// preserve the round-trip distinction between is_ref=true (emit as
	// `@id` via cx_build_meta's is_ref branch) and is_ref=false (emit
	// here, must NOT look like a reference token).
	if s.len > 0 && s[0] == `@` {
		return "'${s}'"
	}
	return s
}

// cx_quote_body_if_needed wraps a substituted scalar that is about to
// be emitted into element-body position with the cheapest quote form
// that survives a re-parse. CXL's `[?=]` and filter directives emit
// their result text into the surrounding element body, and downstream
// tools (e.g. `cx --md`, `cx --xml`) re-parse the emit; bytes like
// `[` `]` `'` `"` or a leading sigil would re-tokenize as structure
// instead of staying as text. Bare-safe strings are returned verbatim
// so the common case (`[h2 [?= sec/@id]]` → `[h2 first]`) does not
// noise up the output with redundant quotes.
fn cx_quote_body_if_needed(s string) string {
	if s.len == 0 {
		return s
	}
	// Structural delimiters anywhere in the value would re-parse as
	// child elements or quoted-string items. Newlines collapse to
	// inter-token whitespace in a bare body and only survive inside a
	// triple-quoted scalar — so multi-line values count as hazardous
	// even when no other structural byte is present. `#` at any
	// position triggers a line-comment scan that eats through the
	// next newline — including a trailing `]` — so a value like
	// `cx hash menu.cx # comment` re-parses as a runaway comment.
	mut needs := s.contains('[') || s.contains(']') || s.contains("'") ||
		s.contains('"') || s.contains('\n') || s.contains('#') ||
		s.contains('&')
	if !needs {
		// Sigil at the start would re-parse as ref / anchor / merge /
		// id / data-type marker (`@id`, `&a`, `*m`, `#i`, `:t`).
		c := s[0]
		if c == `@` || c == `&` || c == `*` || c == `#` || c == `:` {
			needs = true
		}
	}
	if !needs {
		// `name=value` at the head re-parses as an attribute on the
		// containing element. Detect a leading bare-ident followed by
		// `=` and treat it as hazardous.
		mut i := 0
		for i < s.len && (is_ident_cont_byte(s[i])) { i++ }
		if i > 0 && i < s.len && s[i] == `=` {
			needs = true
		}
	}
	if !needs {
		return s
	}
	if s.contains('\n') || s.contains("'") {
		return "'''${s}'''"
	}
	return "'${s}'"
}

// Local byte-classifier matching the CX identifier-continue set,
// scoped to this helper. Keeping it private avoids tangling with the
// parser's identifier scanner in another module.
fn is_ident_cont_byte(c u8) bool {
	if c >= `a` && c <= `z` { return true }
	if c >= `A` && c <= `Z` { return true }
	if c >= `0` && c <= `9` { return true }
	return c == `_` || c == `-` || c == `.`
}

fn cx_scalar(s ScalarNode) string {
	return match s.value {
		i64       { s.value.str() }
		f64       { format_float(s.value as f64) }
		bool      { if s.value as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { s.value as string }
	}
}

fn cx_emit_pi(p PINode, depth int, compact bool, mut out []string) {
	data := p.data or { '' }
	sep  := if data.len > 0 { ' ' } else { '' }
	nl   := if compact { '' } else { '\n' }
	ind  := cx_ind(depth, compact)
	out << '${ind}[?${p.target}${sep}${data}]${nl}'
}

fn emit_cx_xml_decl(x XMLDeclNode, mut out []string) {
	mut s := '[?xml version=${x.version}'
	if enc := x.encoding   { s += ' encoding=${enc}' }
	if sa  := x.standalone  { s += ' standalone=${sa}' }
	s += ']'
	out << '${s}\n'
}

// v3.5 (ADR 0016): emit `[?=EXPR]` interpolation. The captured
// expression text round-trips verbatim; no quoting is added because
// the body is opaque to the CX layer (parsed as CXPath by the CXL
// evaluator at v0.7.0+).
fn cx_emit_interpolation(n InterpolationNode, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	out << '${ind}[?=${n.expr}]${nl}'
}

// v3.5 (ADR 0016): emit `[?Name ... ]` evaluation directive. Attrs
// and body items are emitted in source-like form. BracketBody attrs
// (`:then=[…]`) round-trip via cx_build_meta's body-aware branch is
// not reused here because EvalDirective attrs always emit inline.
fn cx_emit_eval_directive(n EvalDirectiveNode, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	mut s := '${ind}[?${n.name}'
	for a in n.attrs {
		if body_items := a.body {
			body_str := cx_build_inline_body(body_items, true)
			s += ' ${a.name}=[${body_str}]'
			continue
		}
		val_str := a.str_value()
		if val_str.len == 0 {
			s += ' ${a.name}'
		} else {
			emitted := if a.data_type == none && cx_would_autotype(val_str) {
				"'${val_str}'"
			} else {
				cx_quote_attr_if_needed(val_str)
			}
			s += ' ${a.name}=${emitted}'
		}
	}
	if n.items.len > 0 {
		body := cx_build_inline_body(n.items, true)
		if body.len > 0 { s += ' ${body}' }
	}
	s += ']${nl}'
	out << s
}

fn emit_cx_directive(cx2 CXDirectiveNode, mut out []string) {
	mut parts := []string{cap: cx2.attrs.len}
	for a in cx2.attrs {
		v := a.str_value()
		if v == '' {
			parts << ' ${a.name}'
		} else {
			parts << ' ${a.name}=${cx_quote_attr_if_needed(v)}'
		}
	}
	out << '[?cx${parts.join('')}]\n'
}

fn cx_emit_block_content(bc BlockContentNode, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }
	out << '${ind}[|'
	for item in bc.items {
		match item {
			TextNode { out << item.value }
			Element  {
				mut tmp := []string{}
				cx_emit_element(item, 0, compact, mut tmp)
				out << tmp.join('').trim_right('\n')
			}
			else {}
		}
	}
	out << '|]${nl}'
}

fn emit_cx_doctype(d DoctypeDecl, mut out []string) {
	mut header := '[!DOCTYPE ${d.name}'
	if ext := d.external_id {
		if pub_id := ext.public {
			sys := ext.system or { '' }
			header += " PUBLIC '${pub_id}' '${sys}'"
		} else if sys := ext.system {
			header += " SYSTEM '${sys}'"
		}
	}
	if d.int_subset.len == 0 {
		header += ']'
		out << '${header}\n'
	} else {
		header += ' [\n'
		out << header
		for n in d.int_subset { cx_emit_node(n, 1, false, mut out) }
		out << ']]\n'
	}
}

fn cx_emit_entity_decl(e EntityDeclNode, depth int, compact bool, mut out []string) {
	ind         := cx_ind(depth, compact)
	nl          := if compact { '' } else { '\n' }
	kind_marker := if e.kind == .pe { '% ' } else { '' }
	def_str     := match e.def {
		string { "'${e.def}'" }
		ExternalEntityDef {
			ext := e.def as ExternalEntityDef
			mut s := if pub_id := ext.external_id.public {
				sys := ext.external_id.system or { '' }
				"PUBLIC '${pub_id}' '${sys}'"
			} else {
				sys := ext.external_id.system or { '' }
				"SYSTEM '${sys}'"
			}
			if ndata := ext.ndata { s += ' NDATA ${ndata}' }
			s
		}
	}
	out << '${ind}[!ENTITY ${kind_marker}${e.name} ${def_str}]${nl}'
}

fn cx_emit_attlist_decl(a AttlistDeclNode, depth int, compact bool, mut out []string) {
	ind  := cx_ind(depth, compact)
	nl   := if compact { '' } else { '\n' }
	defs := a.defs.map(' ${it.name} ${it.att_type} ${it.default}').join('')
	out << '${ind}[!ATTLIST ${a.name}${defs}]${nl}'
}

fn cx_emit_notation_decl(n NotationDeclNode, depth int, compact bool, mut out []string) {
	ind    := cx_ind(depth, compact)
	nl     := if compact { '' } else { '\n' }
	id_str := if pub_id := n.public_id {
		if sys := n.system_id { "PUBLIC '${pub_id}' '${sys}'" } else { "PUBLIC '${pub_id}'" }
	} else if sys := n.system_id {
		"SYSTEM '${sys}'"
	} else {
		''
	}
	out << '${ind}[!NOTATION ${n.name} ${id_str}]${nl}'
}

fn cx_emit_conditional_sect(c ConditionalSectNode, depth int, compact bool, mut out []string) {
	ind  := cx_ind(depth, compact)
	nl   := if compact { '' } else { '\n' }
	kind := if c.kind == .include { 'INCLUDE' } else { 'IGNORE' }
	out << '${ind}[![${kind}[${nl}'
	for n in c.subset { cx_emit_node(n, depth + 1, compact, mut out) }
	out << '${ind}]]]${nl}'
}
