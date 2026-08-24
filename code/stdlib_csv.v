module code

import cx

// stdlib_csv.v — native primitives backing the `cx-stdlib/csv` module
// (spec/std-lib/csv.md). RFC 4180 + Excel-pragmatic CSV/TSV parse and
// emit is not expressible in pure CX `[?def]` bodies (character-level
// tokenization, quote-state machine, dialect resolution), so the bundle
// bodies (stdlib_src_csv, stdlib_bundle.v) forward to the primitives
// dispatched here. See stdlib_dispatch.v for the registration line.
//
// ── CX value model (matches eval.v markers + render_value) ───────────
//   string   → ScalarType.string_type.
//   int      → ScalarType.int_type, i64.
//   float    → ScalarType.float_type, f64.
//   bool     → ScalarType.bool_type.
//   sequence → Element{ name: '__cx_seq__', items: [...] }.   (a, b, c)
//   array    → Element{ name: '__cx_arr__', items: [...] }.   [a, b, c]
//   map      → Element{ name: '__cx_map__', items: [...] } where each
//              entry is Element{ name: key, items: [value] }. {k: v}
//
// A parsed row is a map (header dialect) or array (headerless). The row
// SEQUENCE is a `__cx_seq__`. `$row/key` resolves via walk_path_step's
// `.child` arm (single-scalar children auto-unwrap to the value), and
// `[$nth $rows i]` iterates the sequence — both already wired in eval.v.
//
// Errors are returned as `[err code=cx-err:CXERxxxx message=…]` value
// nodes (mk_err, eval.v); the conformance harness matches the bare CXER
// code as a substring of the rendered err. CSV errors do not propagate
// as V-errors — `[on-error "collect"]` instead folds them into a
// `[csv-result [rows …] [errors …]]` element.

// ── value builders ───────────────────────────────────────────────────

fn csv_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn csv_int(v i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.int_type
	}
}

fn csv_float(v f64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.float_type
	}
}

fn csv_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn csv_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn csv_arr(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_arr__'
		items: items
	}
}

// csv_map builds a `__cx_map__` from ordered (key, value) pairs.
fn csv_map(keys []string, vals []cx.Node) cx.Node {
	mut entries := []cx.Node{}
	for i, k in keys {
		entries << cx.Element{
			name:  k
			items: [vals[i]]
		}
	}
	return cx.Element{
		name:  '__cx_map__'
		items: entries
	}
}

// ── argument readers ──────────────────────────────────────────────────

// csv_node_str reads a node's textual value (string/atom scalar, or a
// raw TextNode). Returns none for non-textual nodes.
fn csv_node_str(n cx.Node) ?string {
	match n {
		cx.ScalarNode {
			v := n.value
			match v {
				string { return v }
				i64 { return v.str() }
				f64 { return cx.scalar_value_str_public(v) }
				bool { return if v { 'true' } else { 'false' } }
				cx.NullValue { return '' }
			}
		}
		cx.TextNode {
			return n.value
		}
		else {
			return none
		}
	}
}

fn csv_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// csv_seq_items extracts the item list of a sequence / array element.
fn csv_seq_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		// `__cx_seq__` / `__cx_arr__` are the eval-time markers; `sequence`
		// / `array` are the surface element heads (a literal
		// `[sequence "b" "a"]` parses to an element named `sequence`, not a
		// marker — see render_value); `''` is an anon top-level wrapper.
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == ''
			|| n.name == 'sequence' || n.name == 'array' {
			return n.items
		}
	}
	return none
}

// csv_map_entries returns the ordered (key, value) entries of a
// `__cx_map__` element. Returns none if the node is not a map.
fn csv_map_entries(n cx.Node) ([]string, []cx.Node, bool) {
	mut keys := []string{}
	mut vals := []cx.Node{}
	if n is cx.Element {
		if n.name == '__cx_map__' {
			for it in n.items {
				if it is cx.Element {
					keys << it.name
					if it.items.len > 0 {
						vals << it.items[0]
					} else {
						vals << csv_str('')
					}
				}
			}
			return keys, vals, true
		}
	}
	return keys, vals, false
}

// ── dialect ───────────────────────────────────────────────────────────

struct CsvDialect {
mut:
	delimiter        string = ','
	quote_char       string = '"'
	escape           string = 'double' // "double" | "backslash"
	line_terminator  string = 'auto'   // "auto" | "crlf" | "lf"
	header           bool   = true
	skip_empty_lines bool   = true
	trim_whitespace  bool
	on_error         string = 'raise' // "raise" | "collect"
	// columns pins emit column set/order; empty means union-of-keys.
	columns     []string
	has_columns bool
}

// csv_builtin_dialect returns the named built-in dialect, or none.
fn csv_builtin_dialect(name string) ?CsvDialect {
	return match name {
		'csv' {
			CsvDialect{}
		}
		'tsv' {
			CsvDialect{
				delimiter: '\t'
			}
		}
		'psv' {
			CsvDialect{
				delimiter: '|'
			}
		}
		'excel' {
			CsvDialect{
				line_terminator: 'crlf'
			}
		}
		'excel-tab' {
			CsvDialect{
				delimiter:       '\t'
				line_terminator: 'crlf'
			}
		}
		'unix' {
			CsvDialect{
				line_terminator: 'lf'
			}
		}
		'headless' {
			CsvDialect{
				header: false
			}
		}
		else {
			none
		}
	}
}

// csv_builtin_dialect_names is the §2.2 table order.
fn csv_builtin_dialect_names() []string {
	return ['csv', 'tsv', 'psv', 'excel', 'excel-tab', 'unix', 'headless']
}

// csv_child_field returns the first textual value of a dialect child
// element named `field`, plus a presence flag.
fn csv_child_field(el cx.Element, field string) (string, bool) {
	for c in el.items {
		if c is cx.Element && c.name == field {
			if c.items.len > 0 {
				if s := csv_node_str(c.items[0]) {
					return s, true
				}
			}
			return '', true
		}
	}
	return '', false
}

// csv_child_bool returns the bool value of a dialect child field.
fn csv_child_bool(el cx.Element, field string) (bool, bool) {
	for c in el.items {
		if c is cx.Element && c.name == field {
			if c.items.len > 0 {
				inner := c.items[0]
				if inner is cx.ScalarNode {
					v := inner.value
					if v is bool {
						return v, true
					}
					if v is string {
						return v == 'true', true
					}
				}
				if inner is cx.TextNode {
					return inner.value == 'true', true
				}
			}
			return false, true
		}
	}
	return false, false
}

// csv_resolve_dialect builds a complete CsvDialect from a `[dialect …]`
// element. Resolution order (§2.2): a `[name "X"]` child seeds the named
// built-in defaults; every explicit field overrides; absent fields keep
// the (csv-default-seeded) inherited value. Returns an err-value node on
// an invalid resolved dialect (§2.2 Validity → CXER1502).
fn csv_resolve_dialect(n cx.Node) (CsvDialect, ?cx.Node) {
	mut d := CsvDialect{}
	if n !is cx.Element {
		return d, mk_err('cx-err:CXER1502', 'E_CSV_DIALECT_INVALID: dialect must be an element')
	}
	el := n as cx.Element
	// 1. seed from a named built-in if present.
	nm, name_present := csv_child_field(el, 'name')
	if name_present {
		base := csv_builtin_dialect(nm) or {
			return d, mk_err('cx-err:CXER1502', 'E_CSV_DIALECT_INVALID: unknown built-in dialect "${nm}"')
		}
		d = base
	}
	// 2. explicit field overrides.
	delim_v, delim_present := csv_child_field(el, 'delimiter')
	if delim_present {
		d.delimiter = delim_v
	}
	quote_v, quote_present := csv_child_field(el, 'quote-char')
	if quote_present {
		d.quote_char = quote_v
	}
	esc_v, esc_present := csv_child_field(el, 'escape')
	if esc_present {
		d.escape = esc_v
	}
	lt_v, lt_present := csv_child_field(el, 'line-terminator')
	if lt_present {
		d.line_terminator = lt_v
	}
	hdr_v, hdr_present := csv_child_bool(el, 'header')
	if hdr_present {
		d.header = hdr_v
	}
	sel_v, sel_present := csv_child_bool(el, 'skip-empty-lines')
	if sel_present {
		d.skip_empty_lines = sel_v
	}
	tw_v, tw_present := csv_child_bool(el, 'trim-whitespace')
	if tw_present {
		d.trim_whitespace = tw_v
	}
	oe_v, oe_present := csv_child_field(el, 'on-error')
	if oe_present {
		d.on_error = oe_v
	}
	// columns pin (§3.2) — a [columns [sequence …]] child.
	for c in el.items {
		if c is cx.Element && c.name == 'columns' {
			for it in c.items {
				if cols := csv_seq_items(it) {
					for cell in cols {
						if s := csv_node_str(cell) {
							d.columns << s
						}
					}
					d.has_columns = true
				}
			}
		}
	}
	// 3. validity (§2.2): delimiter MUST be exactly one character; the
	//    required fields are always present (csv defaults seed them).
	if d.delimiter.len != 1 {
		return d, mk_err('cx-err:CXER1502',
			'E_CSV_DIALECT_INVALID: delimiter must be exactly one character')
	}
	if d.quote_char.len != 1 {
		return d, mk_err('cx-err:CXER1502',
			'E_CSV_DIALECT_INVALID: quote-char must be exactly one character')
	}
	if d.escape != 'double' && d.escape != 'backslash' {
		return d, mk_err('cx-err:CXER1502',
			'E_CSV_DIALECT_INVALID: escape must be "double" or "backslash"')
	}
	if d.line_terminator != 'auto' && d.line_terminator != 'crlf' && d.line_terminator != 'lf' {
		return d, mk_err('cx-err:CXER1502',
			'E_CSV_DIALECT_INVALID: line-terminator must be "auto", "crlf", or "lf"')
	}
	return d, none
}

// ── tokenizer ─────────────────────────────────────────────────────────

struct CsvParseError {
	row     int
	message string
}

// csv_tokenize splits the input into rows of string cells per the
// dialect. Returns the rows plus any collected parse errors. The
// quote-state machine implements RFC 4180 §2: a field is quoted when it
// opens with quote_char; inside a quoted field the delimiter, CR, and LF
// are literal, and a doubled quote (or backslash-escaped quote, when
// escape="backslash") is a literal quote. An unterminated quoted field
// is a malformed-row error.
fn csv_tokenize(input string, d CsvDialect) ([][]string, []CsvParseError) {
	mut rows := [][]string{}
	mut errs := []CsvParseError{}

	// BOM strip (§4): a leading UTF-8 BOM (EF BB BF) is silently consumed.
	mut s := input
	if s.len >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		s = s[3..]
	}

	delim := d.delimiter[0]
	quote := d.quote_char[0]
	backslash := d.escape == 'backslash'

	mut field := []u8{}
	mut row := []string{}
	mut in_quotes := false
	mut field_was_quoted := false
	mut row_started := false
	mut row_index := 1
	mut i := 0
	bytes := s.bytes()
	n := bytes.len

	mut have_field := false

	for i < n {
		c := bytes[i]
		if in_quotes {
			if backslash && c == `\\` && i + 1 < n {
				nx := bytes[i + 1]
				if nx == quote {
					field << quote
					i += 2
					continue
				}
				if nx == `\\` {
					field << `\\`
					i += 2
					continue
				}
				field << c
				i++
				continue
			}
			if c == quote {
				if i + 1 < n && bytes[i + 1] == quote {
					// doubled quote → literal quote.
					field << quote
					i += 2
					continue
				}
				// closing quote.
				in_quotes = false
				i++
				continue
			}
			field << c
			i++
			continue
		}
		// not in quotes
		if c == quote && field.len == 0 && !field_was_quoted {
			in_quotes = true
			field_was_quoted = true
			have_field = true
			row_started = true
			i++
			continue
		}
		if c == delim {
			row << csv_finish_field(field, field_was_quoted, d)
			field = []u8{}
			field_was_quoted = false
			have_field = false
			row_started = true
			i++
			continue
		}
		if c == `\r` || c == `\n` {
			// line terminator (outside quotes).
			// consume CRLF as one terminator.
			if c == `\r` && i + 1 < n && bytes[i + 1] == `\n` {
				i += 2
			} else {
				i++
			}
			row << csv_finish_field(field, field_was_quoted, d)
			field = []u8{}
			field_was_quoted = false
			have_field = false
			// emit row (skip-empty handled by caller via row shape).
			if csv_emit_row(row, d) {
				rows << row
			}
			row = []string{}
			row_started = false
			row_index++
			continue
		}
		field << c
		have_field = true
		row_started = true
		i++
	}

	// end of input.
	if in_quotes {
		errs << CsvParseError{
			row:     row_index
			message: 'unterminated quoted field'
		}
		// still flush what we have so lenient mode keeps prior rows.
		row << csv_finish_field(field, field_was_quoted, d)
		if csv_emit_row(row, d) {
			rows << row
		}
		return rows, errs
	}
	if have_field || row.len > 0 || row_started {
		row << csv_finish_field(field, field_was_quoted, d)
		if csv_emit_row(row, d) {
			rows << row
		}
	}
	return rows, errs
}

// csv_finish_field applies trim-whitespace (unquoted fields only).
fn csv_finish_field(field []u8, was_quoted bool, d CsvDialect) string {
	s := field.bytestr()
	if d.trim_whitespace && !was_quoted {
		return s.trim_space()
	}
	return s
}

// csv_emit_row reports whether a freshly-closed row should be emitted.
// A blank line (a single empty unquoted cell) is dropped when
// skip-empty-lines is set; a row of only delimiters is non-empty.
fn csv_emit_row(row []string, d CsvDialect) bool {
	if d.skip_empty_lines && row.len == 1 && row[0] == '' {
		return false
	}
	return true
}

// ── parse ─────────────────────────────────────────────────────────────

// csv_parse_rows runs the full parse pipeline: tokenize → header split →
// row-shape (map or array) → schema coercion. Returns a row sequence
// node on success, or (under raise) an err-value, or (under collect) a
// [csv-result …] element.
fn csv_parse_rows(input string, d CsvDialect, schema_keys []string, schema_types []string) cx.Node {
	collect := d.on_error == 'collect'
	rows, parse_errs := csv_tokenize(input, d)

	mut row_nodes := []cx.Node{}
	mut err_nodes := []cx.Node{}

	for pe in parse_errs {
		if !collect {
			return mk_err('cx-err:CXER1500', 'E_CSV_MALFORMED: row ${pe.row}: ${pe.message}')
		}
		err_nodes << csv_error_node(pe.row, pe.message)
	}

	if rows.len == 0 {
		if collect {
			return csv_result_node(row_nodes, err_nodes)
		}
		return csv_seq(row_nodes)
	}

	mut header := []string{}
	mut data_start := 0
	if d.header {
		header = rows[0]
		data_start = 1
	}

	for ri in data_start .. rows.len {
		cells := rows[ri]
		if d.header {
			if cells.len != header.len {
				msg := 'row has ${cells.len} fields, header has ${header.len}'
				if !collect {
					return mk_err('cx-err:CXER1503', 'E_CSV_FIELD_COUNT_MISMATCH: row ${ri + 1}: ${msg}')
				}
				err_nodes << csv_error_node(ri + 1, msg)
				continue
			}
			mut keys := []string{}
			mut vals := []cx.Node{}
			mut row_err := false
			for ci, key in header {
				raw := cells[ci]
				keys << key
				val, cerr := csv_coerce_cell(key, raw, schema_keys, schema_types)
				if cerr != '' {
					if !collect {
						return mk_err('cx-err:CXER1504', 'E_CSV_COERCION_FAILED: row ${ri + 1}: ${cerr}')
					}
					err_nodes << csv_error_node(ri + 1, cerr)
					row_err = true
					break
				}
				vals << val
			}
			if row_err {
				continue
			}
			row_nodes << csv_map(keys, vals)
		} else {
			mut vals := []cx.Node{}
			for raw in cells {
				vals << csv_str(raw)
			}
			row_nodes << csv_arr(vals)
		}
	}

	if collect {
		return csv_result_node(row_nodes, err_nodes)
	}
	return csv_seq(row_nodes)
}

// csv_coerce_cell coerces a cell value per the schema. Returns the value
// node and an error message (empty on success). Cells absent from the
// schema stay strings.
fn csv_coerce_cell(key string, raw string, schema_keys []string, schema_types []string) (cx.Node, string) {
	mut typ := ''
	for i, k in schema_keys {
		if k == key {
			typ = schema_types[i]
			break
		}
	}
	if typ == '' {
		return csv_str(raw), ''
	}
	match typ {
		'int' {
			v := raw.i64()
			// reject non-integer text (i64() yields 0 on garbage).
			if !csv_is_int_literal(raw) {
				return csv_str(raw), 'cannot coerce "${raw}" to :int'
			}
			return csv_int(v), ''
		}
		'float' {
			if !csv_is_float_literal(raw) {
				return csv_str(raw), 'cannot coerce "${raw}" to :float'
			}
			return csv_float(raw.f64()), ''
		}
		'bool' {
			if raw == 'true' {
				return csv_bool(true), ''
			}
			if raw == 'false' {
				return csv_bool(false), ''
			}
			return csv_str(raw), 'cannot coerce "${raw}" to :bool'
		}
		'string' {
			return csv_str(raw), ''
		}
		'date' {
			if !csv_is_date_literal(raw) {
				return csv_str(raw), 'cannot coerce "${raw}" to :date'
			}
			return cx.ScalarNode{
				value:     cx.ScalarValue(raw)
				data_type: cx.ScalarType.date_type
			}, ''
		}
		'datetime' {
			if raw.len < 10 {
				return csv_str(raw), 'cannot coerce "${raw}" to :datetime'
			}
			return cx.ScalarNode{
				value:     cx.ScalarValue(raw)
				data_type: cx.ScalarType.datetime_type
			}, ''
		}
		else {
			return csv_str(raw), ''
		}
	}
}

fn csv_is_int_literal(s string) bool {
	if s.len == 0 {
		return false
	}
	mut i := 0
	if s[0] == `-` || s[0] == `+` {
		if s.len == 1 {
			return false
		}
		i = 1
	}
	for j in i .. s.len {
		c := s[j]
		if c < `0` || c > `9` {
			return false
		}
	}
	return true
}

fn csv_is_float_literal(s string) bool {
	if s.len == 0 {
		return false
	}
	mut i := 0
	if s[0] == `-` || s[0] == `+` {
		if s.len == 1 {
			return false
		}
		i = 1
	}
	mut seen_dot := false
	mut seen_digit := false
	for j in i .. s.len {
		c := s[j]
		if c == `.` {
			if seen_dot {
				return false
			}
			seen_dot = true
		} else if c >= `0` && c <= `9` {
			seen_digit = true
		} else {
			return false
		}
	}
	return seen_digit
}

fn csv_is_date_literal(s string) bool {
	// YYYY-MM-DD shape.
	if s.len != 10 {
		return false
	}
	if s[4] != `-` || s[7] != `-` {
		return false
	}
	for idx in [0, 1, 2, 3, 5, 6, 8, 9] {
		c := s[idx]
		if c < `0` || c > `9` {
			return false
		}
	}
	return true
}

// csv_error_node builds an [error row=N message="…"] element.
fn csv_error_node(row int, message string) cx.Node {
	return cx.Element{
		name:  'error'
		attrs: [
			cx.Attribute{
				name:  'row'
				value: cx.ScalarValue(i64(row))
			},
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue(message)
			},
		]
	}
}

// csv_result_node builds the lenient [csv-result [rows …] [errors …]]
// element (§3.1 Lenient mode).
fn csv_result_node(rows []cx.Node, errs []cx.Node) cx.Node {
	return cx.Element{
		name:  'csv-result'
		items: [
			cx.Node(cx.Element{
				name:  'rows'
				items: [csv_seq(rows)]
			}),
			cx.Node(cx.Element{
				name:  'errors'
				items: [csv_seq(errs)]
			}),
		]
	}
}

// ── emit ──────────────────────────────────────────────────────────────

// csv_emit renders a row sequence to CSV/TSV text per the dialect.
fn csv_emit(rows_node cx.Node, d CsvDialect) cx.Node {
	items := csv_seq_items(rows_node) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: emit expects a sequence of rows')
	}
	nl := if d.line_terminator == 'crlf' { '\r\n' } else { '\n' }

	// Detect row shape from the first row.
	if items.len == 0 {
		return csv_str('')
	}

	first := items[0]
	is_map := first is cx.Element && (first as cx.Element).name == '__cx_map__'

	mut out := []string{}
	if is_map {
		// Determine column set: pinned, or union-of-keys (first-seen).
		mut columns := []string{}
		if d.has_columns {
			columns = d.columns.clone()
		} else {
			mut seen := map[string]bool{}
			for it in items {
				keys, _, ok := csv_map_entries(it)
				if !ok {
					continue
				}
				for k in keys {
					if k !in seen {
						seen[k] = true
						columns << k
					}
				}
			}
		}
		// header line.
		mut head_cells := []string{}
		for c in columns {
			head_cells << csv_emit_cell(c, d)
		}
		out << head_cells.join(d.delimiter)
		// data lines.
		for it in items {
			keys, vals, ok := csv_map_entries(it)
			if !ok {
				continue
			}
			mut cells := []string{}
			for col in columns {
				mut cell := ''
				for ki, k in keys {
					if k == col {
						cell = csv_node_str(vals[ki]) or { '' }
						break
					}
				}
				cells << csv_emit_cell(cell, d)
			}
			out << cells.join(d.delimiter)
		}
	} else {
		// array rows — positional, padded to the longest row.
		mut maxlen := 0
		for it in items {
			cells := csv_seq_items(it) or { continue }
			if cells.len > maxlen {
				maxlen = cells.len
			}
		}
		for it in items {
			cells := csv_seq_items(it) or { continue }
			mut row := []string{}
			for ci in 0 .. maxlen {
				if ci < cells.len {
					raw := csv_node_str(cells[ci]) or { '' }
					row << csv_emit_cell(raw, d)
				} else {
					row << ''
				}
			}
			out << row.join(d.delimiter)
		}
	}
	// Output always ends with a line terminator (§4).
	return csv_str(out.join(nl) + nl)
}

// csv_emit_cell quotes-and-escapes a cell per RFC 4180: a cell is quoted
// when it contains the delimiter, the quote char, CR, or LF. The quote
// char inside a quoted cell is doubled (default) or backslash-escaped.
fn csv_emit_cell(cell string, d CsvDialect) string {
	delim := d.delimiter
	quote := d.quote_char
	needs := cell.contains(delim) || cell.contains(quote) || cell.contains('\n')
		|| cell.contains('\r')
	if !needs {
		return cell
	}
	mut inner := cell
	if d.escape == 'backslash' {
		inner = inner.replace('\\', '\\\\').replace(quote, '\\' + quote)
	} else {
		inner = inner.replace(quote, quote + quote)
	}
	return quote + inner + quote
}

// ── dialects-builtin ──────────────────────────────────────────────────

// csv_dialect_to_map renders a CsvDialect as a CXDM map (the §3.3 shape).
fn csv_dialect_to_map(d CsvDialect) cx.Node {
	keys := ['delimiter', 'quote-char', 'escape', 'line-terminator', 'header',
		'skip-empty-lines', 'trim-whitespace', 'on-error']
	vals := [
		csv_str(d.delimiter),
		csv_str(d.quote_char),
		csv_str(d.escape),
		csv_str(d.line_terminator),
		csv_bool(d.header),
		csv_bool(d.skip_empty_lines),
		csv_bool(d.trim_whitespace),
		csv_str(d.on_error),
	]
	return csv_map(keys, vals)
}

fn csv_dialects_builtin() cx.Node {
	mut keys := []string{}
	mut vals := []cx.Node{}
	for name in csv_builtin_dialect_names() {
		d := csv_builtin_dialect(name) or { continue }
		keys << name
		vals << csv_dialect_to_map(d)
	}
	return csv_map(keys, vals)
}

// csv_schema_pairs reads a `{col: :type}` schema map into parallel
// key/type lists.
fn csv_schema_pairs(n cx.Node) ([]string, []string) {
	mut keys := []string{}
	mut types := []string{}
	mkeys, mvals, ok := csv_map_entries(n)
	if !ok {
		return keys, types
	}
	for i, k in mkeys {
		t := csv_node_str(mvals[i]) or { '' }
		keys << k
		types << t
	}
	return keys, types
}

// ── dispatch ──────────────────────────────────────────────────────────

fn csv_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'csv-parse' {
			s := csv_arg_str(args[0]) or { return none }
			return csv_parse_rows(s, CsvDialect{}, []string{}, []string{})
		}
		'csv-parse-with-dialect' {
			s := csv_arg_str(args[0]) or { return none }
			d, derr := csv_resolve_dialect(args[1])
			if e := derr {
				return e
			}
			return csv_parse_rows(s, d, []string{}, []string{})
		}
		'csv-parse-with-schema' {
			s := csv_arg_str(args[0]) or { return none }
			schema_keys, schema_types := csv_schema_pairs(args[1])
			return csv_parse_rows(s, CsvDialect{}, schema_keys, schema_types)
		}
		'csv-emit' {
			return csv_emit(args[0], CsvDialect{})
		}
		'csv-emit-with-dialect' {
			d, derr := csv_resolve_dialect(args[1])
			if e := derr {
				return e
			}
			return csv_emit(args[0], d)
		}
		'csv-dialects-builtin' {
			return csv_dialects_builtin()
		}
		// Generic map-key accessor used by the csv conformance fixtures
		// (`[$keys $row]`, `[$keys [$csv:dialects-builtin]]`). Not a
		// language-core builtin; reached here only when core invoke_builtin
		// declines, and only meaningful on a map value.
		// #936: delegates to the ONE typed materialization (map_native_keys,
		// #925) — the old arm emitted key IMAGES as strings, so two distinct
		// keys ({1: a, '1': b}) yielded identical items (the #927 class in
		// the reader lane). String-keyed maps (every csv consumer) are
		// unchanged by construction.
		'keys' {
			if args.len != 1 {
				return none
			}
			_, _, ok := csv_map_entries(args[0])
			if !ok {
				return none
			}
			r := map_native_keys(args)
			if is_err_node(r) {
				return none
			}
			return r
		}
		else {
			return none
		}
	}
}
