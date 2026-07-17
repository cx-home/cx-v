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

// cx_emit_node_str renders a SINGLE node to canonical CX text. Used by the
// program-result renderer (code/render.v) so an embedded data-node value
// (raw text `[#…#]`, entity ref `&…;`, a DTD declaration, or `[!DOCTYPE …]`)
// produced by a `node_lit` literal renders identically to the data reading —
// the DATA↔PROGRAM seam. Any trailing newline the node emitter appends is
// trimmed so the caller controls layout.
pub fn cx_emit_node_str(n Node, compact bool) string {
	mut out := []string{}
	cx_emit_node(n, 0, compact, mut out)
	return out.join('').trim_right('\n')
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
				out << '${ind}[;${n.value}]${nl}'
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
		PEReferenceNode  { out << '${ind}%${n.name};${nl}' }
		DoctypeDecl      { emit_cx_doctype(n, mut out) }
		ConditionalSectNode { cx_emit_conditional_sect(n, depth, compact, mut out) }
		BlockContentNode { cx_emit_block_content(n, depth, compact, mut out) }
		InterpolationNode { cx_emit_interpolation(n, depth, compact, mut out) }
		EvalDirectiveNode { cx_emit_eval_directive(n, depth, compact, mut out) }
		SequenceNode      { out << '${ind}${cx_emit_sequence_inline(n, compact)}${nl}' }
		ArrayNode         { out << '${ind}${cx_emit_array_inline(n, compact)}${nl}' }
		MapNode           { out << '${ind}${cx_emit_map_inline(n, compact)}${nl}' }
		IteratorNode      {
			// lazy iterators materialize to eager
			// Sequences at the host boundary. The eval pipeline is
			// responsible for pulling the source before render; this
			// arm renders whatever has accumulated in `memo` (paren-
			// comma form, matching SequenceNode).
			seq := iterator_to_sequence(n)
			out << '${ind}${cx_emit_sequence_inline(seq, compact)}${nl}'
		}
		MatchNode         {
			// First-class `[?match]` AST. The
			// terse-CX emit here uses the MatchNode `source` snippet
			// when available (the parser populates it with the full
			// verbatim `[?match …]` form); a structural pretty-printer
			// is a follow-up alongside the ProgramExpr graft.
			src := n.source or { '' }
			out << '${ind}${src}${nl}'
		}
		ModifyNode        {
			// First-class `[?modify]` AST. Same
			// verbatim-source convention as MatchNode at this graft.
			src := n.source or { '' }
			out << '${ind}${src}${nl}'
		}
		DocumentNode      {
			// D7 — transparent document carrier: emit prolog, doctype,
			// then elements as bare top-level nodes, exactly as `cx_emit`
			// does for a `Document`. Round-trips multi-root by construction.
			for c in n.prolog { cx_emit_node(c, depth, compact, mut out) }
			if dt := n.doctype { emit_cx_doctype(dt, mut out) }
			for c in n.elements { cx_emit_node(c, depth, compact, mut out) }
		}
	}
}

// cx_emit_sequence_inline renders a `(a, b, c)` literal using canonical
// form: parens, single space after comma, trailing comma
// omitted. Empty sequence: `()`.
pub fn cx_emit_sequence_inline(n SequenceNode, compact bool) string {
	if n.items.len == 0 { return '()' }
	parts := n.items.map(cx_emit_collection_item(it, compact))
	return '(${parts.join(', ')})'
}

// cx_emit_array_inline renders a `[a, b, c]` literal.
// Empty array: `[]`. Trailing commas are omitted per §D14 canonical.
// Single-element arrays emit as `[a]` and rely on context-aware parse
// (EvalDirective ArgArray per resolution 2.i; :table cell per
// read_table_cell's force-array rule) to preserve Array semantics on
// re-parse. In contexts where neither rule applies (raw expression
// position), `[a]` parses as Element per §D1's comma-marker rule —
// this is consistent with the cell-parser's force-array policy
// keeping the canonical-form invariant clean.
pub fn cx_emit_array_inline(n ArrayNode, compact bool) string {
	if n.items.len == 0 { return '[]' }
	parts := n.items.map(cx_emit_array_item_literal(it, compact))
	return '[${parts.join(', ')}]'
}

// cx_emit_array_item_literal renders one item of a BARE ArrayLiteral `[…]`.
// It differs from cx_emit_collection_item in ONE way: a bare-name string item
// (`web`, `admin`) is QUOTED. In ArrayLiteral position an unquoted leading
// bareword re-opens the element-head disambiguation (`[web, prod]` → CXER0100,
// 3a / lexicon §collections [L83]) and a lone `[web]` re-parses as the element
// `web`, so a bare string item would not round-trip. Quoting every bareword
// item keeps the canonical form uniform (`['admin', 'user']`) and bijective.
// Sequence `( … )` and map values are unambiguous, so they keep the bare form
// via cx_emit_collection_item.
fn cx_emit_array_item_literal(n Node, compact bool) string {
	match n {
		TextNode {
			// In an array literal a comma / whitespace splits items, so a text
			// item is quoted when it is a bare NAME (3a — else it re-parses as a
			// bareword head) OR carries any item-boundary char (comma, whitespace,
			// bracket, quote) OR would auto-type. A safe single bare token — e.g.
			// a program path `//variant` — stays bare. (Data comma string items
			// arrive as string ScalarNodes, handled below.)
			if cx_is_bare_name(n.value) || cx_array_item_needs_quote(n.value) {
				return cx_choose_quote(n.value)
			}
			return n.value
		}
		ScalarNode {
			if n.data_type == .string_type {
				sv := match n.value {
					string { n.value as string }
					else   { scalar_value_str(n.value) }
				}
				// A string array item quotes under the SAME rule as the TextNode
				// branch above — bare-eligible (canonical.md §2.3) values emit bare,
				// quoting only when the value is a bare NAME (`web` → re-parses as an
				// element head, 3a) or carries an item-boundary / auto-typing char
				// (`a, b`, `80`). This is the idempotency fixpoint: a comma-body
				// string item (which finalize_comma_array materialises as a string
				// ScalarNode) and the SAME item re-parsed from `[ … ]` literal form
				// (a TextNode) must canonicalise identically, or `cx fmt` oscillates
				// quoted⇄bare on every save. A safe token (`https://a.com`,
				// `//variant`) stays bare in both representations.
				if cx_is_bare_name(sv) || cx_array_item_needs_quote(sv) {
					return cx_choose_quote(sv)
				}
				return sv
			}
			return cx_scalar(n)
		}
		else {
			return cx_emit_collection_item(n, compact)
		}
	}
}

// cx_emit_map_inline renders a `{k: v, k: v}` literal:
// single space after `:` and after `,`. Entries emit in insertion order
// (runtime preservation); canonical mode handled by the caller / hash path
// when lexicographic ordering is required. Empty map: `{}`.
pub fn cx_emit_map_inline(n MapNode, compact bool) string {
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
		TextNode      { cx_collection_string(n.value) }
		ScalarNode    {
			// #473: a STRING scalar (imported / runtime-built — a CX-source
			// quoted value arrives as a TextNode) quotes under the same rule
			// as the TextNode arm; cx_scalar's verbatim string arm let a
			// number-shaped payload emit bare and re-import as int.
			if n.data_type == .string_type {
				sv := match n.value {
					string { n.value as string }
					else   { scalar_value_str(n.value) }
				}
				cx_collection_string(sv)
			} else {
				cx_scalar(n)
			}
		}
		EntityRefNode { '&${n.name};' }
		RawTextNode   { '[#${n.value}#]' }
		SequenceNode  { cx_emit_sequence_inline(n, compact) }
		ArrayNode     { cx_emit_array_inline(n, compact) }
		MapNode       { cx_emit_map_inline(n, compact) }
		IteratorNode  { cx_emit_sequence_inline(iterator_to_sequence(n), compact) }
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
		// A ':' inside a bare STRING key mis-lexes on re-parse (`{cx:seq: v}`
		// splits at the first colon → key `cx`), breaking the §1 emit/parse
		// fixpoint — QName chars are bare-name chars, so cx_is_bare_name
		// alone admits it. Quote such keys.
		if cx_is_bare_name(s) && !s.contains(':') { return s }
		return cx_choose_quote(s)
	}
	return cx_scalar(ScalarNode{ data_type: kt, value: kv })
}

// cx_emit_envelope_map_key renders a map key whose TYPE was erased to its
// string image — the program-side `__cx_map__` envelope (vcx/code/eval.v
// eval_map) stores every key as the entry element's name. This is the
// single home for the envelope-lane key rule; the program renderer's
// `__cx_map__` paths (vcx/code/render.v, #495) delegate here so the two
// lanes cannot drift.
//
// The rule intentionally DIFFERS from cx_emit_map_key's string arm: in the
// typed data lane a number-shaped STRING key must quote (else it re-imports
// as int), but in the envelope a number image is just as likely a genuine
// int/float/bool/date key (`{7: v}`, program-dc-entry-int-key) — quoting it
// would flip it to a string on re-parse. So an auto-typing image stays BARE
// (its text re-parses to the same key image) and quoting is forced only
// when the bare image would structurally mis-parse: a `:` anywhere (a bare
// `cx:seq` key splits at the first colon; QName chars are bare-name chars),
// a `$`-leading name (reads as a binding reference / reserved-envelope
// key, e.g. `$tag`), or an image that is neither a bare name nor an
// auto-typing scalar (spaces, quotes, delimiters, empty, `@`/`#` sigils…).
pub fn cx_emit_envelope_map_key(s string) string {
	if !s.contains(':') && (cx_is_bare_name(s) || cx_would_autotype(s)) {
		return s
	}
	return cx_choose_quote(s)
}

// cx_array_item_needs_quote reports whether a bare text item inside an array
// literal `[…, …]` must be quoted to round-trip as the same string: any
// item-boundary char (whitespace, comma, bracket, quote, `&`), a value that
// would auto-type (number/date/…), or a leading `@`/`:`/`#` sigil forces a
// quote. (Mirrors the program renderer's needs_quote_string_item; the cx module
// cannot import code, so the rule is defined once on each side.)
fn cx_array_item_needs_quote(s string) bool {
	if s.len == 0 {
		return true
	}
	for c in s {
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` || c == `,`
			|| c == `[` || c == `]` || c == `(` || c == `)` || c == `{`
			|| c == `}` || c == `'` || c == `"` || c == `&` {
			return true
		}
	}
	if cx_would_autotype(s) {
		return true
	}
	return s[0] == `@` || s[0] == `:` || s[0] == `#`
}

fn cx_is_bare_name(s string) bool {
	if s.len == 0 { return false }
	if !is_name_start(s[0]) { return false }
	for i in 1 .. s.len {
		if !is_name_char(s[i]) { return false }
	}
	return true
}

// array_render_plan decides the canonical surface for a typed-array element
// body of element-type `base` with `n` scalar items (lexicon.ebnf §9 — D1).
// It is the SINGLE home for the rule — both this canonical-CX emitter and the
// programs renderer (code.render_canonical) call it, so the two renderers
// cannot drift.
//   returns (drop_annotation, use_comma_separator, force_trailing_comma)
//
// A TYPED array ALWAYS keeps its `::T[]` head and emits its items
// whitespace-separated — `[tags::string[] admin user]`, `[scores::int[] 80
// 443]`. This is both LOSSLESS and IDEMPOTENT, which the old drop-annotation
// scheme was not:
//   - dropping `::T[]` and re-signalling the type via the body never recovered
//     the array — a bare comma body `[tags admin, user]` re-parses to an
//     UNTYPED ArrayNode (so `fmt` oscillated typed→comma→bracketed every save),
//     and a whitespace body `[scores 80 443]` re-parses to DISCRETE children,
//     not an array at all (§9: whitespace never auto-arrays);
//   - dropping `::T[]` is also a silent TYPE LOSS whenever the items don't
//     self-identify the declared type — `[xs::float[] 1 2 3]` would re-infer
//     `int`. The explicit `::T[]` head is what makes the whitespace body an
//     array (§9: a `::[]`/`::T[]` head makes an array), so keeping it is the
//     only form that round-trips for every element-type and arity.
// UNTYPED comma arrays (`[tags web, prod]`) are a different AST (a sole
// ArrayNode child) and canonicalise to the bracketed literal `[tags ['web',
// 'prod']]` via the generic element path — unaffected by this plan.
pub fn array_render_plan(base string, n int) (bool, bool, bool) {
	return false, false, false
}

// cx_emit_array_item renders one item of a typed-array body. Dates emit
// unquoted (cx_scalar already does); a dropped-annotation string item quotes
// only when a bare token would split or re-type (cx_quote_text_if_needed).
fn cx_emit_array_item(s ScalarNode, string_item bool) string {
	if string_item && s.value is string {
		return cx_quote_text_if_needed(s.value as string)
	}
	return cx_scalar(s)
}

// try_cx_emit_array_element emits a typed-array element body per decision (a),
// or returns none if `e` is not an all-scalar typed array (caller falls
// through to the generic element emit).
fn try_cx_emit_array_element(e Element) ?string {
	dt := e.data_type() or { return none }
	if !dt.ends_with('[]') { return none }
	if e.attrs.len > 0 { return none }
	base := dt#[..-2]
	mut scalars := []ScalarNode{}
	for it in e.items {
		if it is ScalarNode {
			scalars << it
		} else {
			return none
		}
	}
	cnt := scalars.len
	drop_ann, use_comma, trailing := array_render_plan(base, cnt)
	mut s := '[${e.name}'
	if a := e.anchor() { s += ' &${a}' }
	if m := e.merge()  { s += ' *${m}' }
	if id := e.id()    { s += ' #${id}' }
	if !drop_ann { s += '::${dt}' }
	if cnt > 0 {
		sep := if use_comma { ', ' } else { ' ' }
		mut parts := []string{cap: cnt}
		for sc in scalars {
			parts << cx_emit_array_item(sc, base == 'string')
		}
		s += ' ' + parts.join(sep)
		if trailing { s += ',' }
	}
	s += ']'
	return s
}

fn cx_emit_element(e Element, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }

	// v3.4 (second bullet): body-position [ref @id] form.
	// Emitted as `[ref @<body_ref>]`, no anchors / merge / id meta /
	// attrs / items per the parser's rule that body_ref is set only
	// when the source had exactly that shape.
	if br := e.body_ref() {
		out << '${ind}[ref @${br}]${nl}'
		return
	}

	// v3.4: emit :table form when this Element carries TableData.
	// #469: e.items carries the comments the parser retained between the
	// element name and the `[table[` head — passed through so the pooled
	// emitter re-emits them (they were retained but silently dropped here).
	if td := e.table_opt() {
		cx_emit_table_element(e, td, depth, compact, mut out)
		return
	}

	// §9 / decision (a): typed-array body canonical render.
	if rendered := try_cx_emit_array_element(e) {
		out << '${ind}${rendered}${nl}'
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
	} else if e.items.len == 0 && e.attrs.len == 0 && e.anchor() == none && e.merge() == none && e.data_type() == none {
		out << '${ind}[${e.name}]${nl}'
	} else {
		meta := cx_build_meta(e)
		parent_scalar_typed := if dt := e.data_type() { !dt.ends_with('[]') } else { false }
		body := cx_build_inline_body(e.items, compact, parent_scalar_typed)
		body_sep := if body.len > 0 { ' ' } else { '' }
		out << '${ind}[${e.name}${meta}${body_sep}${body}]${nl}'
	}
}

// v3.4: emit a :table block. Header columns are emitted as
// `name:type` pairs (untyped columns drop the `:type` suffix); rows
// are space-separated cells. Cells use canonical scalar formatting:
// quoted iff the value is empty, contains whitespace, or would
// auto-type differently from its declared column type.
//
// #478: the element's head meta — anchor, merge, id, attributes — is
// ElementMeta like on any other element (grammar [29]: the TableBlock
// occupies only the TypeAnnotation slot) and MUST be re-emitted; this
// lane previously rendered the bare name, dropping every head meta on
// round-trip. The `table` data_type is implied by the `[table[…]]`
// clause and is never rendered as a glued `::table` (the parser rejects
// an explicit annotation on a table-block element). The TableBlock
// closes the head — it always follows the attributes, since the parser
// treats the `[table[` opener as the transition into the row body.
// #469: comments the parser retained (the element's only possible
// items) re-emit between the head meta and the `[table[…]]` clause.
fn cx_emit_table_element(e Element, td TableData, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }
	row_ind := cx_ind(depth + 1, compact)
	name := e.name

	mut meta := ''
	if a := e.anchor() { meta += ' &${a}' }
	if m := e.merge()  { meta += ' *${m}' }
	if id := e.id()    { meta += ' #${id}' }
	for a in e.attrs {
		meta += ' ${cx_attr_scalar(a)}'
	}

	mut header_parts := []string{}
	for col in td.cols {
		if col.type_name == '' {
			header_parts << col.name
		} else {
			header_parts << '${col.name}::${col.type_name}'
		}
	}
	header := header_parts.join(' ')

	// #469: comments the parser retained between the element name and the
	// `[table[` head (its only possible items) re-emit ahead of the head —
	// the reader's ElementMeta loop collects them back into the same slot,
	// so the emit is a fixpoint and `cx fmt` is lossless for them.
	items := e.items
	has_comments := items.any(it is CommentNode)

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
		mut cparts := ''
		if has_comments {
			// Inline position: block spelling only — a bare `# …` here
			// would comment out the rest of the record, so a retained
			// line comment normalizes to `[;…]` (content preserved).
			for item in items {
				if item is CommentNode {
					cparts += '[;${item.value}] '
				}
			}
		}
		out << '${ind}[${name}${meta} ${cparts}[table[${header}]]${body_sep}${body}]${nl}'
		return
	}

	if has_comments {
		// Multiline home: each retained comment on its own line between
		// the head meta and the `[table[…]]` clause, in its own spelling
		// (`[; … ]` block / `# …` line — cx_emit_node keeps both).
		out << '${ind}[${name}${meta}${nl}'
		for item in items {
			if item is CommentNode {
				cx_emit_node(item, depth + 1, compact, mut out)
			}
		}
		out << '${row_ind}[table[${header}]]${nl}'
		for row in td.rows {
			mut cells := []string{}
			for i, cell in row {
				ct := if i < td.cols.len { td.cols[i].type_name } else { '' }
				cells << cx_format_table_cell(cell, ct)
			}
			out << '${row_ind}${cells.join(' ')}${nl}'
		}
		out << '${ind}]${nl}'
		return
	}

	out << '${ind}[${name}${meta} [table[${header}]]${nl}'
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
fn cx_format_table_cell(v TableCellValue, col_type string) string {
	return match v {
		i64       { v.str() }
		f64       { format_float(v) }
		bool      { if v { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    {
			// #485: the cell context's instantiation of the shared #483
			// collection-string rule (cx_collection_string): quote exactly
			// when the bare image would re-read as a DIFFERENT value in
			// cell position. In a string-family column a bare token
			// re-reads as the same string — grammar [29b]: untyped columns
			// default to ::string, read_table_cell never auto-types them —
			// so type-shaped text (`1h30m`, `36`) stays bare losslessly.
			// What MUST quote is anything the cell reader dispatches away
			// from the bare-token path or that derails the row re-parse:
			//   • a NON-string column (#413: bare coerces per column type),
			//   • the literal `null` (the null cell in ANY column),
			//   • whitespace (the cell separator) and `]` (the row closer),
			//   • a leading collection opener `[` / `{` / `(`
			//     (read_table_cell dispatches array / map / sequence
			//     literals on the first byte — `{a:b}` flipped string→map),
			//   • any quote char, either kind (`"q"` re-read as `q` — the
			//     same both-quote rule cx_collection_string carries).
			string_col := col_type == '' || col_type == 'string' || col_type == 's'
			if v.len == 0 || !string_col || v == 'null'
				|| v.contains(' ') || v.contains('\t')
				|| v.contains('\n') || v.contains('\r')
				|| v.contains("'") || v.contains('"')
				|| v.contains(']')
				|| v.starts_with('[') || v.starts_with('{') || v.starts_with('(') {
				cx_choose_quote(v)
			} else {
				v
			}
		}
		// collection-typed cells emit
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
	if a := e.anchor()    { s += ' &${a}' }
	if m := e.merge()     { s += ' *${m}' }
	if id := e.id()       { s += ' #${id}' }
	if dt := e.data_type() { s += '::${dt}' }
	for a in e.attrs {
		// Attributes are strictly scalar (D2 / #396 ruling 1b) — the v3.5
		// BracketBody round-trip branch is gone with the body channel.
		s += ' ${cx_attr_scalar(a)}'
	}
	return s
}

fn cx_build_inline_body(items []Node, compact bool, parent_scalar_typed bool) string {
	mut parts := []string{}
	for item in items {
		match item {
			TextNode {
				if item.value.trim_space().len == 0 { continue }
				parts << cx_quote_text_if_needed(item.value)
			}
			ScalarNode {
				// A plain (non-atom) string scalar in mixed / untyped body
				// position quotes under the SAME bijective rule as a TextNode
				// — otherwise `cx fmt` re-parses `'CX is a '` (a string
				// ScalarNode here) and re-emits it BARE, dropping the boundary
				// spaces and oscillating quoted⇄bare. When the parent element
				// carries a disambiguating scalar `::T` head (`[zip::string
				// 90210]`), the annotation already pins the type, so the value
				// stays bare via cx_scalar.
				if !parent_scalar_typed && item.data_type == .string_type && item.value is string {
					parts << cx_quote_text_if_needed(item.value as string)
				} else {
					parts << cx_scalar(item)
				}
			}
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
			IteratorNode { parts << cx_emit_sequence_inline(iterator_to_sequence(item), compact) }
			else {}
		}
	}
	return parts.join(' ')
}

fn cx_text_needs_quote(s string) bool {
	return s.starts_with(' ') || s.ends_with(' ')
		|| s.contains('  ') || s.contains('\n') || s.contains('\t')
		|| s.contains('[') || s.contains(']') || s.contains('&')
		|| s.contains('\\')
		|| s.contains(',')               // a bare comma is the array signal (§9)
		|| s.starts_with(':')
		|| cx_body_leading_sigil(s)       // `+tls` / `-debug` / `*a` / `@r` …
		|| cx_text_has_boundary_quote(s)
		|| cx_would_autotype(s)
}

fn cx_quote_text_if_needed(s string) string {
	if !cx_text_needs_quote(s) { return s }
	return cx_choose_quote(s)
}

// cx_collection_string renders a STRING payload in map-value / sequence-item
// position (#473). Beyond the element-body rule (cx_text_needs_quote — which
// carries the would-autotype protection: number / float / bool / null / atom /
// date / datetime / duration / period / bigint / hex shaped strings quote so
// the text lane re-imports them as strings), a collection item must also
// quote when the bare image would derail the COLLECTION re-parse: any quote
// char (a mid-token `'` is safe bare prose in element-body position — core
// 035 — but opens quoted text in `{k: it's}`), or a closer that ends the
// collection early (`}` / `)`). Applied to BOTH TextNode and string-
// ScalarNode payloads so a CX-authored value and the same value imported
// from JSON/YAML canonicalize identically (the idempotency fixpoint).
fn cx_collection_string(s string) string {
	if cx_text_needs_quote(s) || s.contains("'") || s.contains('"')
		|| s.contains('}') || s.contains(')') {
		return cx_choose_quote(s)
	}
	return s
}

// cx_body_leading_sigil reports whether a bare-emitted body text would be
// re-lexed as a NON-text token because of its first character. At a body /
// head item boundary these sigils introduce structure rather than prose:
// `+`/`-` (retired boolean-flag sigils — grammar [55b]), `*` (alias), `@`
// (body @id ref), `#` (line comment), `%` (PE reference), `$` (binding ref),
// and the collection / grouping openers+closers `( ) { } =`. A string whose
// value starts with one of these MUST be quoted or `cx fmt` would emit syntax
// the parser then rejects or re-reads as a different node (e.g. `[code '+tls']`
// → bare `[code +tls]` → "retired flag sigil"). `[`/`]`/`&`/`:`/quotes are
// already covered by the caller's checks. NOTE: `$`/`%`/`=`/parens are NOT in
// the set — `$v`/`%x` are program binding/PE references and grouping is opened
// by `(`/`{` which begin a structured value, not prose; a data text run that
// genuinely starts with `(`/`{` is rare and the collection openers are handled
// by the parser's structural dispatch, so quoting only the unambiguous prose-
// breaking sigils avoids mangling embedded program expressions (e.g. the
// `[in $v //variant]` body of a `[?for]`).
fn cx_body_leading_sigil(s string) bool {
	if s.len == 0 { return false }
	return s[0] in [`+`, `-`, `*`, `@`, `#`]
}

// cx_text_has_boundary_quote reports whether a bare-emitted body text
// would re-open a quoted string on re-parse. A `'` or `"` at the start of
// a body item — position 0 or immediately after whitespace — is parsed as
// a quoted-string opener (parse_body boundary rule), so the value must be
// wrapped to survive a round-trip. A mid-token quote (a contraction such
// as `it's`, or `Bob's`) is literal bare prose and stays unquoted — see
// conformance core 035-apostrophe-in-bare-prose.
fn cx_text_has_boundary_quote(s string) bool {
	for i := 0; i < s.len; i++ {
		c := s[i]
		if c == `'` || c == `"` {
			if i == 0 { return true }
			pc := s[i - 1]
			if pc == ` ` || pc == `\t` || pc == `\n` || pc == `\r` {
				return true
			}
		}
	}
	return false
}

pub fn cx_choose_quote(s string) string {
	has_single := s.contains("'")
	has_double := s.contains('"')
	if !has_single { return "'" + cx_escape_quoted(s, `'`) + "'" }
	if !has_double { return '"' + cx_escape_quoted(s, `"`) + '"' }
	// Both quote styles present. Triple-quoted is VERBATIM (lexicon §5 [L31],
	// canonical.md §2.10.1) — no escape pass — so it is the cheapest lossless
	// container when the content has no '''-terminator run. Otherwise fall to a
	// double-quoted form with the minimal escape pass.
	if !s.contains("'''") { return "'''${s}'''" }
	return '"' + cx_escape_quoted(s, `"`) + '"'
}

// cx_escape_quoted escapes the content of a single/double-quoted CX string
// scalar so it round-trips through the parser's escape decode (lexicon.ebnf §5
// [L32], canonical.md §2.4). The decode is LENIENT: a backslash followed by a
// byte that is NOT a recognized escape initial is kept verbatim (both bytes),
// so regex patterns such as `\d` / `\.` / `\w` survive without doubling.
// Therefore a literal backslash is doubled ONLY when it would otherwise be
// consumed as the start of a recognized escape (`\ ' " n r t u U`) or it is the
// final byte (where it would pair with the closing delimiter). The active
// delimiter byte, if present in the content, is backslash-escaped. This is the
// minimal re-escape that makes parse(emit(x)) ≡ x (conversions.md §1) without
// churning the verbatim regex surface. Triple-quoted emission does NOT use this
// pass — its content is verbatim.
pub fn cx_escape_quoted(s string, delim u8) string {
	mut out := []u8{cap: s.len + 4}
	for i := 0; i < s.len; i++ {
		c := s[i]
		if c == `\\` {
			if i + 1 >= s.len || cx_is_escape_initial(s[i + 1]) {
				out << `\\`
				out << `\\`
			} else {
				out << c
			}
		} else if c == delim {
			out << `\\`
			out << c
		} else {
			out << c
		}
	}
	return out.bytestr()
}

// cx_is_escape_initial reports whether `c` is the byte that, when it follows a
// backslash, forms one of the recognized escape sequences in lexicon §5 [L32]
// (`\\ \' \" \n \r \t \uXXXX \UXXXXXXXX`).
fn cx_is_escape_initial(c u8) bool {
	return c == `\\` || c == `'` || c == `"` || c == `n` || c == `r` || c == `t`
		|| c == `u` || c == `U`
}

// cx_attr_scalar renders a scalar-valued attribute to its canonical CX
// surface token `name…=value` (no leading space). It is the single source
// of truth for typed-attribute emission (D3), shared by the element-attr
// and eval-directive emit paths. Forms, in priority order:
//   • bare `@id` reference                          → `name=@id`
//   • atom                                          → `name=:click`  (sigil)
//   • auto-recoverable type (int/float/bool/date/datetime) → `name=value` (bare;
//     the lexical form re-types it on XML→CX import, no sidecar needed)
//   • a type the lexical form can't recover (u16/i32/f32/decimal/bigint/bytes)
//                                                    → `name::T=value`  (glued)
//   • explicit / default string                     → `name=value`, quoting when
//     the value would otherwise auto-type (`code='007'`)
pub fn cx_attr_scalar(a Attribute) string {
	val_str := a.str_value()
	if a.is_ref {
		return '${a.name}=@${val_str}'
	}
	if dt := a.data_type() {
		if dt == 'atom' {
			// The atom name is stored bare; the `:` sigil is the canonical
			// surface and round-trips losslessly, so atoms keep it rather
			// than the glued `::atom=` form.
			return '${a.name}=:${val_str}'
		}
		if dt == 'string' {
			v := if cx_would_autotype(val_str) { "'${val_str}'" } else { cx_quote_attr_if_needed(val_str) }
			return '${a.name}=${v}'
		}
		if type_name_is_auto_recoverable(dt) {
			return '${a.name}=${cx_quote_attr_if_needed(val_str)}'
		}
		// Sized numerics / decimal / bigint / bytes — no self-evident
		// lexical form, so carry the glued annotation.
		return '${a.name}::${dt}=${cx_quote_attr_if_needed(val_str)}'
	}
	v := if cx_would_autotype(val_str) { "'${val_str}'" } else { cx_quote_attr_if_needed(val_str) }
	return '${a.name}=${v}'
}

pub fn cx_would_autotype(s string) bool {
	if s.contains(' ') { return false }
	if s.starts_with('0x') || s.starts_with('0X')
		|| s.starts_with('-0x') || s.starts_with('-0X') { return true }
	if s == 'true' || s == 'false' || s == 'null' { return true }
	if _ := s.parse_int(10, 64) { return true }
	// #473: align with try_autotype's full shape set — a bare image that
	// re-parses as ANY typed scalar must count, or a string payload with
	// that shape silently type-flips through the CX text lane.
	//   • over-i64 decimal ints auto-promote to bigint ([L20]/D-H) and
	//     underscore-grouped numerics type after strip_underscores. (The
	//     leading-zero `007` class stays covered by parse_int above:
	//     over-reporting quotes a token that would stay text — the safe
	//     direction, and the long-standing surface.)
	if cleaned := strip_underscores(s) {
		if is_v34_decimal_int(cleaned) { return true }
		if cleaned != s && (cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E')) {
			if has_ascii_digit(cleaned) {
				if _ := strconv.atof64(cleaned) { return true }
			}
		}
	}
	if s.contains('.') || s.contains('e') || s.contains('E') {
		if _ := strconv.atof64(s) { return true }
	}
	if is_datetime(s) { return true }
	if is_date(s) { return true }
	//   • duration / period spans ([L25]/[L26]): `1h30m`, `100ms`, `3mo`.
	if _ := temporal_span_kind(s) { return true }
	//   • atom literals ([L40]): `:click`. The reserved `:true`/`:false`/
	//     `:null` are rejected by the auto-typer and re-parse as text.
	if s.len >= 2 && s[0] == `:` && is_atom_pattern_name(s[1..]) {
		name := s[1..]
		if name != 'true' && name != 'false' && name != 'null' { return true }
	}
	return false
}

fn cx_quote_attr_if_needed(s string) string {
	// Multi-line-text symmetry: newline-bearing string values
	// cannot be emitted as bare / single-quote / double-quote (all
	// single-line) without invalidating the round-trip. Triquote is
	// now valid in AttValue position per [55a] amendment, so use it.
	if s.contains('\n') {
		return "'''${s}'''"
	}
	if s.contains(' ') || s.contains("'") || s.contains('"') || s.len == 0 {
		return "'${s}'"
	}
	// bare `@id` at attribute-value position is a syntactic
	// reference. A literal string starting with '@' must be quoted to
	// preserve the round-trip distinction between is_ref=true (emit as
	// `@id` via cx_build_meta's is_ref branch) and is_ref=false (emit
	// here, must NOT look like a reference token).
	if s.len > 0 && s[0] == `@` {
		return "'${s}'"
	}
	// a string value of the form `:NAME` would re-parse as an
	// atom literal on round-trip; quote it to preserve the string kind.
	// (Applies symmetrically with the @id case above.) Reserved-name
	// strings (`:true` / `:false` / `:null`) follow the same rule — the
	// auto-typer rejects them as atoms, but the surface text still
	// looks atom-shaped and must be quoted.
	if s.len > 1 && s[0] == `:` && is_atom_pattern_name(s[1..]) {
		return "'${s}'"
	}
	return s
}

// cx_quote_body_if_needed wraps a substituted scalar that is about to
// be emitted into element-body position with the cheapest quote form
// that survives a re-parse. CX code's `[?=]` and filter directives emit
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

pub fn cx_scalar(s ScalarNode) string {
	// Atom scalar — renders with leading `:`. The payload
	// `value` is the atom's name (UTF-8) stored as a string; the
	// canonical surface is `:NAME`, never bare or quoted.
	if s.data_type == .atom_type {
		name := match s.value {
			string { s.value as string }
			else   { scalar_value_str(s.value) }
		}
		return ':${name}'
	}
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

// v3.5: emit `[?=EXPR]` interpolation. The captured
// expression text round-trips verbatim; no quoting is added because
// the body is opaque to the CX layer (parsed as CXPath by the CX code
// evaluator).
fn cx_emit_interpolation(n InterpolationNode, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	out << '${ind}[?=${n.expr}]${nl}'
}

// v3.5: emit `[?Name ... ]` evaluation directive. Attrs
// and body items are emitted in source-like form. BracketBody attrs
// (`:then=[…]`) round-trip via cx_build_meta's body-aware branch is
// not reused here because EvalDirective attrs always emit inline.
fn cx_emit_eval_directive(n EvalDirectiveNode, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	mut s := '${ind}[?${n.name}'
	for a in n.attrs {
		val_str := a.str_value()
		if val_str.len == 0 {
			s += ' ${a.name}'
		} else {
			s += ' ${cx_attr_scalar(a)}'
		}
	}
	if n.items.len > 0 {
		body := cx_build_inline_body(n.items, true, false)
		if body.len > 0 { s += ' ${body}' }
	}
	s += ']${nl}'
	out << s
}

fn emit_cx_directive(cx2 CXDirectiveNode, mut out []string) {
	mut parts := []string{cap: cx2.attrs.len}
	for a in cx2.attrs {
		v := a.str_value()
		if a.name == '' {
			// Quoted positional argument (e.g. the `schema-name` title) —
			// re-quote so it round-trips as a single token.
			parts << ' ${cx_quote_attr_if_needed(v)}'
		} else if v == '' {
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
