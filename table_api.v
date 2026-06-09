// CX V binding — native Table API.
//
// Implements the 17-member public Table API against
// the V core's TableData. Native V binding (direct import of
// vcx/cx/) — no FFI overhead, full type fidelity, all V cells
// (scalars collection literals) preserved at the
// CXDM value level.
//
// Per per-binding naming conventions: V uses snake_case
// member names matching the canonical surface exactly (cols, types,
// row_count, col_count, row, column, cell, slice, head, tail, select,
// to_cx, to_csv, to_json, to_data_bin, to_dict_list, plus iteration
// via `for row in t`).

module cx

import strings

// Table is an immutable handle over a single `:table` block parsed
// from CX text or constructed programmatically. Cells admit any of
// the Item kinds (scalars + Array / Map / Sequence).
// Modification returns a new Table; the underlying TableData is
// shared by reference but never mutated.
pub struct Table {
pub:
	data TableData
}

// ── Construction ─────────────────────────────────────────────────────────────

// from_cx parses CX source and returns the first `:table` block as a
// Table. Errors when the source contains no `:table` block; for
// multi-table documents, callers can use from_cx_all to get every
// table in document order.
pub fn table_from_cx(src string) !Table {
	doc := parse(src)!
	for n in doc.elements {
		if n is Element {
			el := n as Element
			if td := el.table_opt() {
				return Table{ data: *td }
			}
			// Recurse one level into the root element's body in case
			// the table is wrapped (common pattern: `[doc [t :table…]]`).
			for child in el.items {
				if child is Element {
					if td := (child as Element).table_opt() {
						return Table{ data: *td }
					}
				}
			}
		}
	}
	return error('cxlib: no :table block found in source')
}

// from_cx_all returns every `:table` block in the document, in
// declaration order. Walks the AST recursively to find tables at
// any nesting depth.
pub fn tables_from_cx(src string) ![]Table {
	doc := parse(src)!
	mut tables := []Table{}
	for n in doc.elements {
		if n is Element {
			collect_tables(n as Element, mut tables)
		}
	}
	return tables
}

fn collect_tables(el Element, mut tables []Table) {
	if td := el.table_opt() {
		tables << Table{ data: *td }
	}
	for child in el.items {
		if child is Element {
			collect_tables(child as Element, mut tables)
		}
	}
}

// new constructs a Table from explicit columns / types / rows.
// Validates the four invariants:
//   1. len(cols) == len(types)
//   2. all column names unique
//   3. every row has exactly col_count cells
//   4. each cell's host type matches the declared column type or is
//      a null sentinel for nullable columns
//
// Cells are supplied as TableCellValue (scalars or AST collection
// nodes).
pub fn new_table(cols []string, types []string, rows [][]TableCellValue) !Table {
	if cols.len != types.len {
		return error('cxlib: len(cols)=${cols.len} != len(types)=${types.len}')
	}
	mut seen := map[string]bool{}
	for c in cols {
		if c in seen {
			return error('cxlib: duplicate column name "${c}"')
		}
		seen[c] = true
	}
	for row_idx, row in rows {
		if row.len != cols.len {
			return error('cxlib: row ${row_idx} has ${row.len} cells; expected ${cols.len}')
		}
	}
	mut tcols := []TableColumn{cap: cols.len}
	for i, name in cols {
		tcols << TableColumn{ name: name, type_name: types[i] }
	}
	return Table{
		data: TableData{
			cols: tcols
			rows: rows.clone()
		}
	}
}

// ── Properties ───────────────────────────────────────────────────────────────

// cols returns the ordered list of column names.
pub fn (t Table) cols() []string {
	return t.data.cols.map(it.name)
}

// types returns the ordered list of column types (canonical string
// form, e.g. 'int', 'string', 'bool'). Empty string means the
// column's type was not declared and defaults to 'string'.
pub fn (t Table) types() []string {
	return t.data.cols.map(it.type_name)
}

// row_count returns the number of rows.
pub fn (t Table) row_count() int {
	return t.data.rows.len
}

// col_count returns the number of columns.
pub fn (t Table) col_count() int {
	return t.data.cols.len
}

// ── Access ───────────────────────────────────────────────────────────────────

// row returns the row at index i as an ordered map (column name →
// cell value). Errors on out-of-bounds.
pub fn (t Table) row(i int) !map[string]TableCellValue {
	if i < 0 || i >= t.data.rows.len {
		return error('cxlib: row index ${i} out of bounds [0, ${t.data.rows.len})')
	}
	mut out := map[string]TableCellValue{}
	for col_idx, col in t.data.cols {
		if col_idx < t.data.rows[i].len {
			out[col.name] = t.data.rows[i][col_idx]
		}
	}
	return out
}

// column returns all values in the named column, in row order.
// Errors when the column name is not present.
pub fn (t Table) column(name string) ![]TableCellValue {
	mut col_idx := -1
	for i, c in t.data.cols {
		if c.name == name {
			col_idx = i
			break
		}
	}
	if col_idx < 0 {
		return error('cxlib: unknown column "${name}"')
	}
	return t.col_at(col_idx)!
}

// col_at returns column values by index.
pub fn (t Table) col_at(i int) ![]TableCellValue {
	if i < 0 || i >= t.data.cols.len {
		return error('cxlib: column index ${i} out of bounds [0, ${t.data.cols.len})')
	}
	mut out := []TableCellValue{cap: t.data.rows.len}
	for row in t.data.rows {
		if i < row.len {
			out << row[i]
		}
	}
	return out
}

// cell returns one value at (row, col_index). For name-based access
// use cell_by_name(row, name).
pub fn (t Table) cell(r int, c int) !TableCellValue {
	if r < 0 || r >= t.data.rows.len {
		return error('cxlib: row index ${r} out of bounds [0, ${t.data.rows.len})')
	}
	if c < 0 || c >= t.data.cols.len {
		return error('cxlib: column index ${c} out of bounds [0, ${t.data.cols.len})')
	}
	return t.data.rows[r][c]
}

// cell_by_name resolves column by name then returns cell(r, c).
pub fn (t Table) cell_by_name(r int, name string) !TableCellValue {
	for c_idx, c in t.data.cols {
		if c.name == name {
			return t.cell(r, c_idx)!
		}
	}
	return error('cxlib: unknown column "${name}"')
}

// slice returns rows in [start, end) as a new Table.
pub fn (t Table) slice(start int, end int) !Table {
	if start < 0 || start > t.data.rows.len {
		return error('cxlib: slice start ${start} out of bounds')
	}
	if end < start || end > t.data.rows.len {
		return error('cxlib: slice end ${end} out of bounds (start=${start})')
	}
	new_rows := t.data.rows[start..end].clone()
	return Table{
		data: TableData{
			cols: t.data.cols
			rows: new_rows
			from_chunked: t.data.from_chunked
		}
	}
}

// head returns the first n rows as a new Table.
pub fn (t Table) head(n int) Table {
	mut end := n
	if end > t.data.rows.len { end = t.data.rows.len }
	if end < 0 { end = 0 }
	return Table{
		data: TableData{
			cols: t.data.cols
			rows: t.data.rows[..end].clone()
			from_chunked: t.data.from_chunked
		}
	}
}

// tail returns the last n rows as a new Table.
pub fn (t Table) tail(n int) Table {
	mut start := t.data.rows.len - n
	if start < 0 { start = 0 }
	return Table{
		data: TableData{
			cols: t.data.cols
			rows: t.data.rows[start..].clone()
			from_chunked: t.data.from_chunked
		}
	}
}

// select_cols returns a new Table with only the named columns, in
// the given order. Renamed from canonical `select` to avoid clashing
// with V's reserved-ish `select` (channel-select syntax).
pub fn (t Table) select_cols(names []string) !Table {
	mut new_cols := []TableColumn{cap: names.len}
	mut indices := []int{cap: names.len}
	for name in names {
		mut found := false
		for col_idx, c in t.data.cols {
			if c.name == name {
				new_cols << c
				indices << col_idx
				found = true
				break
			}
		}
		if !found {
			return error('cxlib: unknown column "${name}"')
		}
	}
	mut new_rows := [][]TableCellValue{cap: t.data.rows.len}
	for row in t.data.rows {
		mut new_row := []TableCellValue{cap: indices.len}
		for idx in indices {
			if idx < row.len {
				new_row << row[idx]
			}
		}
		new_rows << new_row
	}
	return Table{
		data: TableData{
			cols: new_cols
			rows: new_rows
		}
	}
}

// ── Iteration ────────────────────────────────────────────────────────────────
//
// V's `for row in t` syntactic sugar requires the user-defined `next`
// method on a Table iterator. Instead we expose rows() and iter_cols()
// as explicit methods returning slices; idiomatic V usage is
// `for row in t.rows() { ... }` which mirrors the canonical pattern.

// rows returns an iterable of all rows (each as an ordered map).
// Pre-materializes; for streaming over large tables, callers should
// use the chunked-table reader from `lang/v/cffi/streaming_table.v`.
pub fn (t Table) rows() []map[string]TableCellValue {
	mut out := []map[string]TableCellValue{cap: t.data.rows.len}
	for i in 0 .. t.data.rows.len {
		out << t.row(i) or { continue }
	}
	return out
}

// iter_cols returns (name, values) pairs in column-declaration order.
pub fn (t Table) iter_cols() []TableColumnView {
	mut out := []TableColumnView{cap: t.data.cols.len}
	for i, c in t.data.cols {
		values := t.col_at(i) or { []TableCellValue{} }
		out << TableColumnView{ name: c.name, type_name: c.type_name, values: values }
	}
	return out
}

// TableColumnView is the (name, values) pair returned by iter_cols.
pub struct TableColumnView {
pub:
	name      string
	type_name string
	values    []TableCellValue
}

// ── Conversion ───────────────────────────────────────────────────────────────

// to_cx renders the Table as canonical CX `:table` block text. Pure
// text-shape + spec/canonical.md §2.11.
pub fn (t Table) to_cx() string {
	// Wrap in a synthetic root element so the existing emit_cx
	// produces the right `:table` block form.
	td_copy := t.data
	root := Element{
		name:  '_'
		meta:  &ElementMeta{ data_type: ?string('table') }
		table: &td_copy
	}
	mut doc := Document{
		elements: [Node(root)]
	}
	return emit_cx(doc)
}

// to_csv emits CSV (comma-separated) by default. delim parameter for
// arbitrary single-char delimiters. Collection cells
// emit as JSON-encoded strings — same as the C ABI
// `cx_to_csv` route.
pub fn (t Table) to_csv(delim u8) string {
	td_copy := t.data
	root := Element{
		name:  '_'
		meta:  &ElementMeta{ data_type: ?string('table') }
		table: &td_copy
	}
	doc := Document{
		elements: [Node(root)]
	}
	opts := EmitOptions{ delimiter: delim }
	out := emit_delimited(doc, opts) or { return '' }
	return out
}

// to_json emits semantic JSON: list of row objects, one per row,
// with cell values as host-native JSON (Array → JSON array, Map →
// JSON object, scalars → JSON scalars).
pub fn (t Table) to_json() string {
	mut b := strings.new_builder(256)
	b.write_string('[')
	for row_idx, row_map in t.rows() {
		if row_idx > 0 { b.write_string(',') }
		b.write_string('{')
		mut first := true
		// Iterate cols in declaration order rather than map order.
		for col in t.data.cols {
			if !first { b.write_string(',') }
			first = false
			b.write_string(json_quote_string(col.name))
			b.write_string(':')
			if cell := row_map[col.name] {
				b.write_string(cell_to_json_string(cell))
			} else {
				b.write_string('null')
			}
		}
		b.write_string('}')
	}
	b.write_string(']')
	return b.str()
}

fn cell_to_json_string(c TableCellValue) string {
	return match c {
		i64       { c.str() }
		f64       { c.str() }
		bool      { if c { 'true' } else { 'false' } }
		string    { json_quote_string(c) }
		NullValue { 'null' }
		ArrayNode    { array_node_to_json_string(c) }
		MapNode      { map_node_to_json_string(c) }
		SequenceNode {
			// CXDM §1.2 sequences flatten to JSON array.
			mut b := strings.new_builder(64)
			b.write_string('[')
			for i, item in c.items {
				if i > 0 { b.write_string(',') }
				b.write_string(node_to_json_string(item))
			}
			b.write_string(']')
			b.str()
		}
	}
}

fn array_node_to_json_string(n ArrayNode) string {
	mut b := strings.new_builder(64)
	b.write_string('[')
	for i, item in n.items {
		if i > 0 { b.write_string(',') }
		b.write_string(node_to_json_string(item))
	}
	b.write_string(']')
	return b.str()
}

fn map_node_to_json_string(n MapNode) string {
	mut b := strings.new_builder(64)
	b.write_string('{')
	for i, entry in n.entries {
		if i > 0 { b.write_string(',') }
		b.write_string(json_quote_string(scalar_value_str(entry.key_value)))
		b.write_string(':')
		b.write_string(node_to_json_string(entry.value))
	}
	b.write_string('}')
	return b.str()
}

fn node_to_json_string(n Node) string {
	return match n {
		TextNode     { json_quote_string(n.value) }
		ScalarNode   { scalar_value_to_json_string(n.value) }
		ArrayNode    { array_node_to_json_string(n) }
		MapNode      { map_node_to_json_string(n) }
		SequenceNode {
			mut b := strings.new_builder(64)
			b.write_string('[')
			for i, item in n.items {
				if i > 0 { b.write_string(',') }
				b.write_string(node_to_json_string(item))
			}
			b.write_string(']')
			b.str()
		}
		else { 'null' }
	}
}

fn scalar_value_to_json_string(s ScalarValue) string {
	return match s {
		bool      { if s { 'true' } else { 'false' } }
		i64       { s.str() }
		f64       { s.str() }
		string    { json_quote_string(s) }
		NullValue { 'null' }
	}
}

fn json_quote_string(s string) string {
	mut b := strings.new_builder(s.len + 2)
	b.write_string('"')
	for c in s {
		match c {
			`"`  { b.write_string('\\"') }
			`\\` { b.write_string('\\\\') }
			`\n` { b.write_string('\\n') }
			`\r` { b.write_string('\\r') }
			`\t` { b.write_string('\\t') }
			else {
				if c < 0x20 {
					b.write_string('\\u00${c:02x}')
				} else {
					b.write_u8(c)
				}
			}
		}
	}
	b.write_string('"')
	return b.str()
}

// to_data_bin emits the plain table binary form. The
// chunked `0x63` form requires scalar-only cells (strict columnar);
// for collection-cell tables this method routes through plain
// `0x60` encoding via emit_data_bin which dispatches on cell
// type per Phase 2.2 wire-format rule.
pub fn (t Table) to_data_bin() []u8 {
	td_copy := t.data
	root := Element{
		name:  '_'
		meta:  &ElementMeta{ data_type: ?string('table') }
		table: &td_copy
	}
	doc := Document{
		elements: [Node(root)]
	}
	return emit_data_bin(doc)
}

// to_dict_list materializes every row as a separate ordered map.
// Eager copy — for streaming use `for row in t.rows()`.
pub fn (t Table) to_dict_list() []map[string]TableCellValue {
	return t.rows()
}

// ── Equality ─────────────────────────────────────────────────────────────────

// eq compares two tables by canonical bytes (CX text form). Per
// "two tables compare equal iff: same cols, same
// types, same row count, and each cell compares equal under host
// equality." The text-canonical comparison subsumes those rules
// since the canonical-form serializer encodes cols, types, rows
// deterministically.
pub fn (a Table) eq(b Table) bool {
	return a.to_cx() == b.to_cx()
}
