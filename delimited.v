module cx

// ── Delimited (CSV / TSV / PSV / arbitrary single-char) ──────────────────────
//
// Per internal design record () and
// spec/conversions.md §8. Delimited conversion is documented as
// well-defined and reasonable (not lossless): delimited fields are
// inherently string-typed, type metadata is lost on emit and recovered
// on parse via auto-typing or caller schema (D5).
//
// Emit (CX → delimited):
// - D2 shape detection: `:table` block uses declared columns; an
// element with 2+ same-named child siblings uses repeated-row
// mode; otherwise dotted-path mode flattens the hierarchy.
// - D3 default emit: RFC 4180 — quote iff the field contains the
// delimiter, `"`, CR, or LF; embedded `"` doubled to `""`. Line
// terminator `\r\n` (RFC 4180); pass `lf` style for `\n` instead.
// - D6 arbitrary single-char delimiters (excluding `\r \n " ' \\`).
//
// Parse (delimited → CX):
// - D4 multi-quote acceptance: each field may be unquoted, double-
// quoted with `""` doubling, or single-quoted with `''` doubling.
// Six escape sequences honored in any context: `\\ \n \t \r \" \'`.
// Any other `\X` is a parse error.
// - D5 type recovery: auto-typing per try_autotype() (the same
// rules CX uses for unquoted element bodies). Fields parsed under
// quotes are forced to :string regardless of pattern.

// EmitOptions carries the configurable knobs for the emitter per
// D3.
pub struct EmitOptions {
pub mut:
	delimiter u8 = `,`
	line_ending string = '\r\n' // 'crlf' default; pass '\n' for lf
	// quote_style: 'double' (default), 'single', 'none'
	// 'none' uses backslash-escapes for the delimiter and line
	// terminators (no field-wrapping quotes); deferred to a later
	// release per the v0 scope. Currently 'double' and 'single' ship.
	quote_style string = 'double'
}

pub fn default_emit_options() EmitOptions {
	return EmitOptions{}
}

// ParseOptions for the delimited parser D5.
pub struct ParseOptions {
pub mut:
	delimiter u8 = `,`
	auto_type bool = true
	// table_name overrides the default `table` element name on output.
	table_name string = 'table'
}

pub fn default_parse_options() ParseOptions {
	return ParseOptions{}
}

// ── public entry points ──────────────────────────────────────────────────────

// to_csv parses CX source text and emits CSV (RFC 4180, comma).
pub fn to_csv(src string) !string {
	return to_delimited(src, `,`)
}

// to_tsv parses CX source text and emits TSV (tab).
pub fn to_tsv(src string) !string {
	return to_delimited(src, u8(`\t`))
}

// to_psv parses CX source text and emits PSV (pipe).
pub fn to_psv(src string) !string {
	return to_delimited(src, `|`)
}

// to_delimited parses CX source and emits delimited text using the
// supplied single-char delimiter. The delimiter must not be `\r`,
// `\n`, `"`, `'`, or `\\` (D6).
pub fn to_delimited(src string, delim u8) !string {
	doc := parse(src)!
	mut opts := default_emit_options()
	opts.delimiter = delim
	return emit_delimited(doc, opts)
}

// from_csv parses CSV text and emits canonical CX text.
pub fn from_csv(src string) !string {
	return from_delimited(src, `,`)
}

// from_tsv parses TSV text and emits canonical CX text.
pub fn from_tsv(src string) !string {
	return from_delimited(src, u8(`\t`))
}

// from_psv parses PSV text and emits canonical CX text.
pub fn from_psv(src string) !string {
	return from_delimited(src, `|`)
}

pub fn from_delimited(src string, delim u8) !string {
	mut opts := default_parse_options()
	opts.delimiter = delim
	doc := parse_delimited(src, opts)!
	return emit_cx(doc)
}

// ── Emitter ──────────────────────────────────────────────────────────────────

// emit_delimited renders a Document to delimited text
// D2/D3/D6/D7. The shape (`:table`, repeated-row, dotted-path) is
// auto-detected; mixed shapes return an error.
pub fn emit_delimited(doc Document, opts EmitOptions) !string {
	if !is_valid_delimiter(opts.delimiter) {
		return error('emit_delimited: delimiter byte 0x${opts.delimiter:02x} is reserved (CR/LF/quote/backslash)')
	}
	if doc.elements.len == 0 {
		return ''
	}
	// Find the first top-level Element; ignore comments / PIs / etc.
	mut root := ?Element(none)
	for n in doc.elements {
		if n is Element {
			root = n as Element
			break
		}
	}
	r := root or { return error('emit_delimited: no top-level element') }

	if td := r.table_opt() {
		return emit_table_delimited(td, opts)
	}
	// Inspect children of `r`. Repeated-row mode iff any child name
	// occurs 2+ times among Element children; otherwise dotted-path
	// mode (single row).
	mut child_elems := []Element{}
	for n in r.items {
		if n is Element { child_elems << n as Element }
	}
	if child_elems.len == 0 {
		return error('emit_delimited: top-level element <${r.name}> has no element children to flatten')
	}
	mut name_count := map[string]int{}
	for c in child_elems {
		name_count[c.name] = name_count[c.name] + 1
	}
	mut has_repeated := false
	for _, count in name_count {
		if count >= 2 {
			has_repeated = true
			break
		}
	}
	if has_repeated {
		// All children must share the same name in repeated-row v0.
		// Mixed shapes (some repeated + some unique) are an error per
		// D2.
		first_name := child_elems[0].name
		for c in child_elems {
			if c.name != first_name {
				return error('emit_delimited: mixed shape — element <${r.name}> contains both repeated <${first_name}> and singleton <${c.name}>; not supported in v0')
			}
		}
		return emit_repeated_row(child_elems, r.name, opts)
	}
	return emit_dotted_path(child_elems, r.name, opts)
}

fn emit_table_delimited(td TableData, opts EmitOptions) string {
	mut lines := []string{}
	mut header_cells := []string{}
	for col in td.cols {
		header_cells << encode_field(col.name, opts)
	}
	lines << header_cells.join(opts.delimiter.ascii_str())
	for row in td.rows {
		mut cells := []string{}
		for i, cell in row {
			t := if i < td.cols.len { td.cols[i].type_name } else { '' }
			// Phase 2.1: CSV/TSV/PSV emit of collection cells per
			// = JSON-encoded string §D7
			// lands in Phase 2.3 (emitters). For now scalars use the
			// existing path; collection cells emit a TODO marker
			// (W024 reserved for collection-cell JSON-encoded CSV).
			val := scalar_value_from_cell(cell) or {
				cells << encode_field('[collection-cell pending Phase 2.3]', opts)
				continue
			}
			cells << encode_field(scalar_to_text(val, t), opts)
		}
		lines << cells.join(opts.delimiter.ascii_str())
	}
	return lines.join(opts.line_ending) + opts.line_ending
}

fn emit_repeated_row(siblings []Element, root_name string, opts EmitOptions) !string {
	// Columns: first-occurrence order across all siblings.
	mut cols := []string{}
	mut col_seen := map[string]bool{}
	for s in siblings {
		for a in s.attrs {
			if !col_seen[a.name] {
				col_seen[a.name] = true
				cols << a.name
			}
		}
	}
	// #416: zero columns means the document does not flatten to a tabular
	// shape — emitting a blank header + blank rows was silent data loss
	// (and the blank output then failed reimport with "empty input").
	if cols.len == 0 {
		return error('emit_delimited: element <${root_name}> does not flatten to a tabular shape — its repeated <${siblings[0].name}> children carry no attributes; delimited emit needs a [table[...]] block, repeated attribute-bearing children, or leaf attributes (conversions.md §8.1)')
	}
	mut lines := []string{}
	mut header_cells := []string{}
	for c in cols { header_cells << encode_field(c, opts) }
	lines << header_cells.join(opts.delimiter.ascii_str())
	for s in siblings {
		mut row_cells := []string{}
		for col_name in cols {
			mut v := ''
			mut found := false
			for a in s.attrs {
				if a.name == col_name {
					v = scalar_value_str(a.value)
					found = true
					break
				}
			}
			_ = found
			row_cells << encode_field(v, opts)
		}
		lines << row_cells.join(opts.delimiter.ascii_str())
	}
	return lines.join(opts.line_ending) + opts.line_ending
}

fn emit_dotted_path(children []Element, root_name string, opts EmitOptions) !string {
	// Walk each child recursively; emit a column per leaf attribute
	// at path `<child>.<...>.<attr>` (the root element name is not
	// in the path D2 example).
	mut cols := []string{}
	mut vals := []string{}
	for c in children {
		walk_dotted(c, c.name, mut cols, mut vals)
	}
	// #416: no leaf attributes anywhere means the flattening found
	// nothing tabular — before this the emitter produced a blank header
	// line + blank row (rc=0), which then failed reimport with
	// "parse_delimited: empty input".
	if cols.len == 0 {
		return error('emit_delimited: element <${root_name}> does not flatten to a tabular shape — no leaf attributes found under its children; delimited emit needs a [table[...]] block, repeated attribute-bearing children, or leaf attributes (conversions.md §8.1)')
	}
	mut lines := []string{}
	mut header_cells := []string{}
	for c in cols { header_cells << encode_field(c, opts) }
	lines << header_cells.join(opts.delimiter.ascii_str())
	mut row_cells := []string{}
	for v in vals { row_cells << encode_field(v, opts) }
	lines << row_cells.join(opts.delimiter.ascii_str())
	return lines.join(opts.line_ending) + opts.line_ending
}

fn walk_dotted(e Element, prefix string, mut cols []string, mut vals []string) {
	for a in e.attrs {
		cols << '${prefix}.${a.name}'
		vals << scalar_value_str(a.value)
	}
	for n in e.items {
		if n is Element {
			child := n as Element
			walk_dotted(child, '${prefix}.${child.name}', mut cols, mut vals)
		}
	}
}

// scalar_to_text renders a column-typed cell to its delimited form.
// For typed columns the textual form is canonical; for untyped/string
// columns the value is passed through verbatim (still subject to
// encode_field quoting).
fn scalar_to_text(v ScalarValue, col_type string) string {
	match v {
		i64 { return v.str() }
		f64 { return format_float(v) }
		bool { return if v { 'true' } else { 'false' } }
		NullValue { return '' } // RFC 4180 has no null; empty cell is the convention
		string {
			_ = col_type
			return v
		}
	}
}

fn is_valid_delimiter(d u8) bool {
	if d == `\r` || d == `\n` || d == `"` || d == `'` || d == `\\` {
		return false
	}
	return true
}

// encode_field applies RFC 4180 quoting D3. A field is
// quoted only when it contains the delimiter, the active quote char,
// CR, or LF.
fn encode_field(field string, opts EmitOptions) string {
	if opts.quote_style == 'single' {
		return encode_field_quoted(field, `'`, opts.delimiter)
	}
	return encode_field_quoted(field, `"`, opts.delimiter)
}

fn encode_field_quoted(field string, quote u8, delim u8) string {
	mut needs_quote := false
	for i in 0..field.len {
		c := field[i]
		if c == delim || c == quote || c == `\r` || c == `\n` {
			needs_quote = true
			break
		}
	}
	if !needs_quote {
		return field
	}
	mut out := strings_builder_new(field.len + 2)
	out.write_string(quote.ascii_str())
	for i in 0..field.len {
		c := field[i]
		if c == quote {
			out.write_string(quote.ascii_str())
			out.write_string(quote.ascii_str())
		} else {
			out.write_string(c.ascii_str())
		}
	}
	out.write_string(quote.ascii_str())
	return out.str()
}

// helper because cx package doesn't import strings.Builder elsewhere
// uniformly — using a small local builder via byte append.
struct DelimitedSB {
mut:
	buf []u8
}

fn strings_builder_new(cap int) DelimitedSB {
	return DelimitedSB{ buf: []u8{cap: cap} }
}

fn (mut b DelimitedSB) write_string(s string) {
	for i in 0..s.len { b.buf << s[i] }
}

fn (b DelimitedSB) str() string {
	return b.buf.bytestr()
}

// ── Parser ───────────────────────────────────────────────────────────────────

// parse_delimited reads delimited text and returns a Document with a
// single `:table`-shaped Element (`<table_name>`).
pub fn parse_delimited(src string, opts ParseOptions) !Document {
	if !is_valid_delimiter(opts.delimiter) {
		return error('parse_delimited: delimiter byte 0x${opts.delimiter:02x} is reserved')
	}
	rows := tokenize_rows(src, opts.delimiter)!
	if rows.len == 0 {
		return error('parse_delimited: empty input')
	}
	header := rows[0]
	mut cols := []TableColumn{}
	for h in header {
		cols << TableColumn{ name: h.text, type_name: '' }
	}
	mut data_rows := [][]ScalarValue{}
	for ri in 1..rows.len {
		row := rows[ri]
		mut cells := []ScalarValue{}
		for ci in 0..cols.len {
			if ci < row.len {
				field := row[ci]
				cells << recover_value(field, opts.auto_type)
			} else {
				cells << ScalarValue('')
			}
		}
		// Tighten column types when the whole column auto-typed
		// uniformly. Done after rows are populated below.
		data_rows << cells
	}
	// Type-narrowing pass: if every value in a column auto-typed to
	// the same scalar type, promote the column's declared type. Only
	// runs when auto_type is enabled.
	if opts.auto_type {
		mut new_cols := []TableColumn{cap: cols.len}
		for ci in 0..cols.len {
			mut col_type := ScalarType.string_type
			mut col_type_set := false
			mut all_match := true
			mut any_typed := false
			for r in data_rows {
				if ci >= r.len { continue }
				v := r[ci]
				mut cur := ScalarType.string_type
				if v is i64 {
					cur = .int_type
				} else if v is f64 {
					cur = .float_type
				} else if v is bool {
					cur = .bool_type
				} else if v is NullValue {
					continue // null doesn't constrain
				} else if v is string {
					cur = .string_type
				}
				any_typed = true
				if col_type_set {
					if col_type != cur {
						all_match = false
						break
					}
				} else {
					col_type = cur
					col_type_set = true
				}
			}
			mut col := cols[ci]
			if all_match && any_typed && col_type_set && col_type != .string_type {
				col.type_name = scalar_type_name(col_type)
			}
			new_cols << col
		}
		cols = new_cols.clone()
	}
	td := &TableData{ cols: cols, rows: cell_rows_from_scalars(data_rows) }
	root := Element{
		name: opts.table_name
		table: td
	}
	return Document{ elements: [Node(root)] }
}

// Field carries the raw text of one parsed field plus a flag noting
// whether it was quoted. Quoted fields skip auto-typing per D5 — the
// quotes are an explicit signal "this is a string."
struct DelimField {
	text string
	quoted bool
}

fn recover_value(f DelimField, auto_type bool) ScalarValue {
	if f.quoted {
		return ScalarValue(f.text)
	}
	// Empty unquoted cell → null literal per spec/conversions.md §8.2.
	if f.text.len == 0 {
		return ScalarValue(NullValue{})
	}
	if !auto_type {
		return ScalarValue(f.text)
	}
	if sn := try_autotype(f.text) {
		return sn.value
	}
	return ScalarValue(f.text)
}

// tokenize_rows splits src into rows of fields. Handles three quote
// styles (none / `"` / `'`) plus the six universal escape sequences
// D4. CR/LF/CRLF row terminators are accepted on input.
// A trailing delimiter at row-end implies an empty final field
// (`a,b,\n` → 3 fields). Truly empty lines are skipped.
fn tokenize_rows(src string, delim u8) ![][]DelimField {
	mut rows := [][]DelimField{}
	mut i := 0
	// Skip an optional UTF-8 BOM at the very start.
	if src.len >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF {
		i = 3
	}
	for i < src.len {
		// Skip empty line (a row terminator with no preceding field).
		if src[i] == `\r` || src[i] == `\n` {
			if src[i] == `\r` && i + 1 < src.len && src[i + 1] == `\n` {
				i += 2
			} else {
				i++
			}
			continue
		}
		// Read one row: at least one field (possibly empty), with
		// further fields after each delimiter encountered.
		mut row := []DelimField{}
		for {
			field, next := read_field(src, i, delim)!
			row << field
			i = next
			if i >= src.len { break }
			if src[i] == delim {
				i++
				continue
			}
			if src[i] == `\r` || src[i] == `\n` {
				if src[i] == `\r` && i + 1 < src.len && src[i + 1] == `\n` {
					i += 2
				} else {
					i++
				}
				break
			}
			return error('parse_delimited: unexpected byte 0x${src[i]:02x} at offset ${i} after field')
		}
		rows << row
	}
	return rows
}

fn read_field(src string, start int, delim u8) !(DelimField, int) {
	mut i := start
	if i >= src.len {
		return DelimField{ text: '', quoted: false }, i
	}
	c := src[i]
	if c == `"` {
		return read_quoted(src, i + 1, `"`, delim)!
	}
	if c == `'` {
		return read_quoted(src, i + 1, `'`, delim)!
	}
	return read_bare(src, i, delim)!
}

fn read_quoted(src string, start int, quote u8, delim u8) !(DelimField, int) {
	_ = delim
	mut i := start
	mut buf := []u8{}
	for i < src.len {
		c := src[i]
		if c == quote {
			// Doubled quote = literal quote.
			if i + 1 < src.len && src[i + 1] == quote {
				buf << quote
				i += 2
				continue
			}
			return DelimField{ text: buf.bytestr(), quoted: true }, i + 1
		}
		if c == `\\` {
			if i + 1 >= src.len {
				return error('parse_delimited: trailing \\ at offset ${i}')
			}
			esc := src[i + 1]
			match esc {
				`\\` { buf << `\\` }
				`n` { buf << `\n` }
				`t` { buf << `\t` }
				`r` { buf << `\r` }
				`"` { buf << `"` }
				`\'` { buf << `'` }
				else { return error('parse_delimited: unknown escape \\${esc.ascii_str()} at offset ${i}') }
			}
			i += 2
			continue
		}
		buf << c
		i++
	}
	return error('parse_delimited: unterminated quoted field starting at offset ${start - 1}')
}

fn read_bare(src string, start int, delim u8) !(DelimField, int) {
	mut i := start
	mut buf := []u8{}
	for i < src.len {
		c := src[i]
		if c == delim || c == `\r` || c == `\n` { break }
		if c == `\\` {
			if i + 1 >= src.len {
				return error('parse_delimited: trailing \\ at offset ${i}')
			}
			esc := src[i + 1]
			match esc {
				`\\` { buf << `\\` }
				`n` { buf << `\n` }
				`t` { buf << `\t` }
				`r` { buf << `\r` }
				`"` { buf << `"` }
				`\'` { buf << `'` }
				else { return error('parse_delimited: unknown escape \\${esc.ascii_str()} at offset ${i}') }
			}
			i += 2
			continue
		}
		buf << c
		i++
	}
	return DelimField{ text: buf.bytestr(), quoted: false }, i
}
