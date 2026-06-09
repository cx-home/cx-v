module cx

// CX streaming-write writer (+ spec/streaming.md §6).
//
// The writer is the symmetric counterpart to the read-side streaming
// API (§3 / stream.v): adopters construct an event sequence
// programmatically and the writer emits format-targeted bytes with
// validation at emit time and no full-document buffering.
//
// Phase 7.74g landed the V core + 25 C ABI symbols + capability bit
// 27 (0x8000000). Phase 7.74h-7.74i landed CX + XML end-to-end across
// Tier 1 + Tier 2 bindings. Phase 7.74j lands JSON + YAML end-to-end
// using the **AST shape** locked in spec/streaming.md §6.6.1 (every
// event maps to its canonical AST node — the same shape produced by
// `cx_to_ast_json`). TOML and MD remain W009 by design (structural
// mismatch — see §6.6.2 and the format_unsupported message below);
// adopters needing TOML or MD output use the non-streaming
// `cx_to_toml` / `cx_to_md` surfaces.
//
// State machine and W001-W013 validation are normative per §6.5;
// per-event format-coverage rules are normative per §6.6. The writer
// "fails closed" — a single error puts the writer in an unrecoverable
// state and subsequent emits return the same diagnostic without
// effect.

// ── libc fd I/O ──────────────────────────────────────────────────────────────
//
// `C.write` is declared in V's `builtin/cfns.c.v`; reused (not
// redeclared) — same convention as data_bin_streaming.v. fd_write_all
// is also already provided by data_bin_streaming.v; we reuse it
// directly.

// ── Output formats ───────────────────────────────────────────────────────────

enum WriterFormat {
	cx
	xml
	json
	yaml
	toml
	md
}

fn parse_writer_format(s string) ?WriterFormat {
	return match s {
		'cx'   { WriterFormat.cx }
		'xml'  { WriterFormat.xml }
		'json' { WriterFormat.json }
		'yaml' { WriterFormat.yaml }
		'toml' { WriterFormat.toml }
		'md'   { WriterFormat.md }
		else   { none }
	}
}

fn (f WriterFormat) name() string {
	return match f {
		.cx   { 'cx' }
		.xml  { 'xml' }
		.json { 'json' }
		.yaml { 'yaml' }
		.toml { 'toml' }
		.md   { 'md' }
	}
}

// ── Writer handle ────────────────────────────────────────────────────────────

@[heap]
pub struct CxEventsWriter {
mut:
	format     WriterFormat
	bytes_mode bool
	buf        []u8
	fd         int = -1
	// State machine — per §6.5.
	start_doc_emitted bool
	end_doc_emitted   bool
	// Element nesting — names are pushed at StartElement and matched
	// at EndElement (LIFO).
	elem_stack []string
	// Table state — only one open table at a time (W010
	// rejects nested StartTable).
	in_table        bool
	table_name      string
	table_col_count u32
	table_cols      []TableColumn  // cached col-spec for row-group decode
	// Error state — after the first W-code, the writer fails closed.
	// Subsequent emits return the same code without effect.
	err_code   string // e.g. "W005"; empty when no error
	err_msg    string
	closed     bool
	// CX output mode — pretty-printed by default (newlines + indents).
	// Pretty mode only; compact-mode toggle is a follow-up.
	cx_pretty bool = true
	// JSON / YAML AST-shape state — stack of per-level "first child of
	// this array?" flags. Index 0 = Document.elements[] array; index N
	// (N>=1) = the open Element at elem_stack[N-1]'s items[] array.
	// Pushed at StartDoc / StartElement; popped at EndElement / EndDoc.
	// Used to decide whether to emit a leading comma (JSON) or extra
	// blank line / indent (YAML) before the next child.
	json_arr_first []bool
}

// ── Public open / close ──────────────────────────────────────────────────────

// new_events_writer_bytes opens an in-memory event writer for the
// given output format. The returned handle accumulates bytes via
// per-event emit calls; close_get_bytes returns the heap-allocated
// frame-less output buffer (caller frees with cx_free).
pub fn new_events_writer_bytes(output_format string) !&CxEventsWriter {
	fmt := parse_writer_format(output_format) or {
		return error('cx events writer: unknown format "${output_format}"')
	}
	return &CxEventsWriter{
		format:     fmt
		bytes_mode: true
	}
}

// new_events_writer_fd opens an fd-streaming event writer. Each emit
// call writes the event's bytes to `fd` (caller owns the fd).
pub fn new_events_writer_fd(output_format string, fd int) !&CxEventsWriter {
	fmt := parse_writer_format(output_format) or {
		return error('cx events writer: unknown format "${output_format}"')
	}
	return &CxEventsWriter{
		format:     fmt
		bytes_mode: false
		fd:         fd
	}
}

// (The `_shaped` open variants documented in earlier drafts of
// were removed 2026-05-10 when was
// superseded. CX code is the only output-shape mechanism;
// see `vcx/cx/cxl.v` and `spec/abi.md §2.16`.)

// close_get_bytes finalises an in-memory writer and returns its
// accumulated buffer. Implicitly emits EndDoc (with W004 if elements
// remain unclosed). For fd writers the buffer is empty (output is
// already flushed); the symbol still returns a 0-byte heap-allocated
// buffer so the per-binding wrapper has a uniform shape
// (locked 2026-05-10). The caller frees the returned bytes via
// cx_free.
pub fn (mut w CxEventsWriter) close_get_bytes() ![]u8 {
	if w.closed {
		if w.err_code != '' {
			return error('${w.err_code}: ${w.err_msg}')
		}
		return w.buf.clone()
	}
	// Implicit EndDoc — surfaces W004 if elements / table remain open.
	if w.start_doc_emitted && !w.end_doc_emitted {
		w.emit_end_doc() or {
			w.closed = true
			return error(err.msg())
		}
	}
	w.closed = true
	if w.err_code != '' {
		return error('${w.err_code}: ${w.err_msg}')
	}
	return w.buf.clone()
}

// writer_close releases the writer without returning bytes. Suitable
// for fd writers (where close_get_bytes would return an empty slice
// anyway) or when the adopter wants to abort and discard accumulated
// output. Idempotent.
pub fn (mut w CxEventsWriter) writer_close() {
	w.closed = true
}

// ── Internal — error / output helpers ────────────────────────────────────────

fn (mut w CxEventsWriter) fail(code string, msg string) string {
	if w.err_code == '' {
		w.err_code = code
		w.err_msg = msg
	}
	return '${code}: ${msg}'
}

fn (mut w CxEventsWriter) write_bytes(bs []u8) ! {
	if w.bytes_mode {
		w.buf << bs
	} else {
		fd_write_all(w.fd, bs)!
	}
}

fn (mut w CxEventsWriter) write_str(s string) ! {
	w.write_bytes(s.bytes())!
}

// ── Per-event emit (public V API; cabi.v wraps these for C ABI) ──────────────

// emit_start_doc: signals the document open. W001 if already emitted;
// W003 if EndDoc already emitted.
pub fn (mut w CxEventsWriter) emit_start_doc() ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if w.end_doc_emitted {
		return error(w.fail('W003', 'StartDoc after EndDoc'))
	}
	if w.start_doc_emitted {
		return error(w.fail('W001', 'StartDoc emitted twice'))
	}
	w.start_doc_emitted = true
	match w.format {
		.cx { /* no header */ }
		.xml { w.write_str('<?xml version="1.0"?>\n')! }
		.json {
			w.write_str('{"type":"Document","elements":[')!
			w.json_arr_first << true
		}
		.yaml {
			w.write_str('type: Document\nelements:\n')!
			w.json_arr_first << true
		}
		.toml, .md {
			return error(w.format_unsupported('StartDoc'))
		}
	}
}

// emit_end_doc: closes the document. W004 if elements / table still
// open; W002 if StartDoc never emitted.
pub fn (mut w CxEventsWriter) emit_end_doc() ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if !w.start_doc_emitted {
		return error(w.fail('W002', 'EndDoc before StartDoc'))
	}
	if w.end_doc_emitted {
		return error(w.fail('W003', 'EndDoc emitted twice'))
	}
	if w.in_table {
		return error(w.fail('W004', 'EndDoc with open table "${w.table_name}"'))
	}
	if w.elem_stack.len > 0 {
		top := w.elem_stack[w.elem_stack.len - 1]
		return error(w.fail('W004', 'EndDoc with ${w.elem_stack.len} unclosed element(s); top="${top}"'))
	}
	match w.format {
		.cx, .xml { /* no closing emit */ }
		.json {
			// Close Document.elements[] and the Document object.
			if w.json_arr_first.len > 0 { w.json_arr_first.delete_last() }
			w.write_str(']}')!
		}
		.yaml {
			if w.json_arr_first.len > 0 { w.json_arr_first.delete_last() }
			// YAML uses implicit document end; no explicit close needed.
		}
		.toml, .md { /* unreachable — StartDoc already returned W009 */ }
	}
	w.end_doc_emitted = true
}

// emit_start_element: opens an element. attrs_payload is the
// length-prefixed attribute payload matching the read-side §1.2
// shape (u16:count + attrs[]); NULL/empty == zero attrs.
pub fn (mut w CxEventsWriter) emit_start_element(name string, anchor ?string, data_type ?string, merge ?string, attrs_payload []u8) ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if !w.start_doc_emitted {
		return error(w.fail('W002', 'StartElement before StartDoc'))
	}
	if w.end_doc_emitted {
		return error(w.fail('W003', 'StartElement after EndDoc'))
	}
	if w.in_table {
		return error(w.fail('W007', 'StartElement inside open table'))
	}
	if name.len == 0 {
		return error(w.fail('W007', 'StartElement with empty name'))
	}
	attrs := parse_attrs_payload(attrs_payload) or {
		return error(w.fail('W007', 'malformed attrs_payload: ${err.msg()}'))
	}
	match w.format {
		.cx   { w.cx_emit_start_element(name, anchor, data_type, merge, attrs)! }
		.xml  { w.xml_emit_start_element(name, anchor, data_type, merge, attrs)! }
		.json { w.json_emit_start_element(name, anchor, data_type, merge, attrs)! }
		.yaml { w.yaml_emit_start_element(name, anchor, data_type, merge, attrs)! }
		.toml, .md { return error(w.format_unsupported('StartElement')) }
	}
	w.elem_stack << name
}

// emit_end_element: closes the most recent open element.
pub fn (mut w CxEventsWriter) emit_end_element(name string) ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if !w.start_doc_emitted {
		return error(w.fail('W002', 'EndElement before StartDoc'))
	}
	if w.end_doc_emitted {
		return error(w.fail('W003', 'EndElement after EndDoc'))
	}
	if w.elem_stack.len == 0 {
		return error(w.fail('W006', 'EndElement "${name}" without matching StartElement'))
	}
	top := w.elem_stack[w.elem_stack.len - 1]
	if top != name {
		return error(w.fail('W005', 'EndElement "${name}" does not match open "${top}"'))
	}
	w.elem_stack.delete_last()
	match w.format {
		.cx   { w.cx_emit_end_element(name)! }
		.xml  { w.xml_emit_end_element(name)! }
		.json { w.json_emit_end_element(name)! }
		.yaml { w.yaml_emit_end_element(name)! }
		.toml, .md { return error(w.format_unsupported('EndElement')) }
	}
}

pub fn (mut w CxEventsWriter) emit_text(value string) ! {
	if e := w.guard_content_event() { return error(e) }
	match w.format {
		.cx   { w.cx_emit_text(value)! }
		.xml  { w.xml_emit_text(value)! }
		.json { w.json_emit_text(value)! }
		.yaml { w.yaml_emit_text(value)! }
		.toml, .md { return error(w.format_unsupported('Text')) }
	}
}

pub fn (mut w CxEventsWriter) emit_scalar(data_type ?string, value string) ! {
	if e := w.guard_content_event() { return error(e) }
	if dt := data_type {
		if !is_known_scalar_type(dt) {
			return error(w.fail('W008', 'invalid data_type "${dt}"'))
		}
	}
	match w.format {
		.cx   { w.cx_emit_scalar(data_type, value)! }
		.xml  { w.xml_emit_scalar(data_type, value)! }
		.json { w.json_emit_scalar(data_type, value)! }
		.yaml { w.yaml_emit_scalar(data_type, value)! }
		.toml, .md { return error(w.format_unsupported('Scalar')) }
	}
}

pub fn (mut w CxEventsWriter) emit_comment(value string) ! {
	if e := w.guard_content_event() { return error(e) }
	match w.format {
		.cx   { w.cx_emit_comment(value)! }
		.xml  { w.xml_emit_comment(value)! }
		.json { w.json_emit_comment(value)! }
		.yaml { w.yaml_emit_comment(value)! }
		.toml, .md { return error(w.format_unsupported('Comment')) }
	}
}

pub fn (mut w CxEventsWriter) emit_pi(target string, data ?string) ! {
	if e := w.guard_content_event() { return error(e) }
	if target.len == 0 {
		return error(w.fail('W007', 'PI with empty target'))
	}
	match w.format {
		.cx   { w.cx_emit_pi(target, data)! }
		.xml  { w.xml_emit_pi(target, data)! }
		.json { w.json_emit_pi(target, data)! }
		.yaml { w.yaml_emit_pi(target, data)! }
		.toml, .md { return error(w.format_unsupported('PI')) }
	}
}

pub fn (mut w CxEventsWriter) emit_entity_ref(name string) ! {
	if e := w.guard_content_event() { return error(e) }
	if name.len == 0 {
		return error(w.fail('W007', 'EntityRef with empty name'))
	}
	match w.format {
		.cx   { w.cx_emit_entity_ref(name)! }
		.xml  { w.xml_emit_entity_ref(name)! }
		.json { w.json_emit_entity_ref(name)! }
		.yaml { w.yaml_emit_entity_ref(name)! }
		.toml, .md { return error(w.format_unsupported('EntityRef')) }
	}
}

pub fn (mut w CxEventsWriter) emit_raw_text(value string) ! {
	if e := w.guard_content_event() { return error(e) }
	match w.format {
		.cx   { w.cx_emit_raw_text(value)! }
		.xml  { w.xml_emit_raw_text(value)! }
		.json { w.json_emit_raw_text(value)! }
		.yaml { w.yaml_emit_raw_text(value)! }
		.toml, .md { return error(w.format_unsupported('RawText')) }
	}
}

pub fn (mut w CxEventsWriter) emit_alias(name string) ! {
	if e := w.guard_content_event() { return error(e) }
	if name.len == 0 {
		return error(w.fail('W007', 'Alias with empty name'))
	}
	match w.format {
		.cx   { w.cx_emit_alias(name)! }
		// xml has no canonical alias representation — §6.6 says W009.
		.xml  { return error(w.format_unsupported('Alias')) }
		.json { w.json_emit_alias(name)! }
		.yaml { w.yaml_emit_alias(name)! }
		.toml, .md { return error(w.format_unsupported('Alias')) }
	}
}

// ── Chunked-table emit (only valid for cx output) ────────────────────────────

pub fn (mut w CxEventsWriter) emit_start_table(col_spec_payload []u8) ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if !w.start_doc_emitted {
		return error(w.fail('W002', 'StartTable before StartDoc'))
	}
	if w.end_doc_emitted {
		return error(w.fail('W003', 'StartTable after EndDoc'))
	}
	if w.format != .cx {
		return error(w.fail('W009', 'StartTable on non-CX output format "${w.format.name()}"'))
	}
	if w.in_table {
		return error(w.fail('W010', 'nested StartTable (current open: "${w.table_name}")'))
	}
	cols := parse_event_col_spec(col_spec_payload) or {
		return error(w.fail('W007', 'malformed col_spec: ${err.msg()}'))
	}
	if cols.len == 0 {
		return error(w.fail('W007', 'StartTable with empty col_spec'))
	}
	// CX-format chunked tables emit as a `:table` element. The element
	// name is conventionally the most recent open StartElement; if no
	// element is open the table is anonymous (uses `_`). The writer keeps
	// this simple and uses an anonymous-name '_' if elem_stack is empty.
	name := if w.elem_stack.len > 0 { w.elem_stack[w.elem_stack.len - 1] } else { '_' }
	w.in_table = true
	w.table_name = name
	w.table_col_count = u32(cols.len)
	w.table_cols = cols
	w.cx_emit_table_open(name, cols)!
}

pub fn (mut w CxEventsWriter) emit_row_group(payload []u8) ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if !w.in_table {
		return error(w.fail('W012', 'RowGroup without open StartTable'))
	}
	if payload.len == 0 {
		return error(w.fail('W007', 'empty RowGroup payload'))
	}
	w.cx_emit_table_row_group(payload)!
}

pub fn (mut w CxEventsWriter) emit_end_table() ! {
	if w.err_code != '' { return error('${w.err_code}: ${w.err_msg}') }
	if !w.in_table {
		return error(w.fail('W013', 'EndTable without open StartTable'))
	}
	w.cx_emit_table_close()!
	w.in_table = false
	w.table_name = ''
	w.table_col_count = 0
}

// ── Validation helpers ───────────────────────────────────────────────────────

fn (mut w CxEventsWriter) guard_content_event() ?string {
	if w.err_code != '' {
		return '${w.err_code}: ${w.err_msg}'
	}
	if !w.start_doc_emitted {
		return w.fail('W002', 'content event before StartDoc')
	}
	if w.end_doc_emitted {
		return w.fail('W003', 'content event after EndDoc')
	}
	if w.in_table {
		return w.fail('W007', 'content event inside open table')
	}
	return none
}

fn (mut w CxEventsWriter) format_unsupported(event string) string {
	fmt_name := w.format.name()
	// TOML and MD return W009 for the entire format per
	// spec/streaming.md §6.6.2 (structural mismatch — not yet-to-be-
	// implemented but a deliberate non-fit). Distinguish the message so
	// adopters debugging mid-document W009s see a clear next step.
	if w.format == .toml || w.format == .md {
		return w.fail('W009', '${fmt_name} output not supported by streaming-write (structural mismatch; use cx_to_${fmt_name} for this format)')
	}
	// XML's single W009 case (Alias — §6.6) and any future per-format
	// gaps land here.
	return w.fail('W009', '${event} on output format "${fmt_name}" has no canonical representation')
}

fn is_known_scalar_type(dt string) bool {
	return match dt {
		'int', 'i8', 'i16', 'i32', 'i64',
		'u8', 'u16', 'u32', 'u64',
		'float', 'f32', 'f64', 'decimal', 'f16',
		'bool', 'null', 'string', 's',
		'date', 'datetime', 'bytes' { true }
		else { false }
	}
}

// ── attrs_payload parsing ────────────────────────────────────────────────────
//
// The attrs payload mirrors the binary attribute layout used by
// cx_to_events_bin (binary.v): u16:count followed by Attr structs:
//   String:name  String:value  String:inferred_type  u8:is_ref
// Bindings construct this from their idiomatic attribute representation
// before calling start_element_with_len.

fn parse_attrs_payload(payload []u8) ![]Attribute {
	if payload.len == 0 {
		return []Attribute{}
	}
	mut p := 0
	if payload.len < 2 {
		return error('attrs_payload truncated reading u16 count')
	}
	count := u16(payload[0]) | (u16(payload[1]) << 8)
	p += 2
	mut out := []Attribute{cap: int(count)}
	for _ in 0 .. int(count) {
		name, p1 := read_u32_prefixed_string(payload, p)!
		value, p2 := read_u32_prefixed_string(payload, p1)!
		typ, p3 := read_u32_prefixed_string(payload, p2)!
		p = p3
		if p >= payload.len {
			return error('attrs_payload truncated reading is_ref byte')
		}
		is_ref := payload[p] == u8(1)
		p += 1
		// Coerce value back into a typed ScalarValue so the CX emitter
		// can render it canonically. For unknown types fall back to
		// string.
		sv := coerce_attr_value(typ, value)
		// D3: the carrier is the canonical type NAME; `string`/empty/unknown
		// carry no annotation.
		dt := if typ == '' || typ == 'string' || !is_valid_type_tag(typ) {
			?string(none)
		} else {
			?string(typ)
		}
		mut a := new_attribute(name, sv, AttributeMeta{ data_type: dt })
		a.is_ref = is_ref
		out << a
	}
	return out
}

// read_u32_prefixed_string reads a u32-LE-length-prefixed UTF-8
// string from `buf` at `p`, returning (value, new_pos). Returns an
// error on truncation.
fn read_u32_prefixed_string(buf []u8, p int) !(string, int) {
	if p + 4 > buf.len {
		return error('truncated reading u32-len header')
	}
	n := u32(buf[p]) | (u32(buf[p+1]) << 8) | (u32(buf[p+2]) << 16) | (u32(buf[p+3]) << 24)
	mut np := p + 4
	if u64(np) + u64(n) > u64(buf.len) {
		return error('truncated reading ${n}-byte string')
	}
	out := buf[np .. np + int(n)].bytestr()
	np += int(n)
	return out, np
}

fn coerce_attr_value(typ string, value string) ScalarValue {
	return match typ {
		'int'   { ScalarValue(value.i64()) }
		'float' { ScalarValue(value.f64()) }
		'bool'  { ScalarValue(value == 'true') }
		'null'  { ScalarValue(NullValue{}) }
		else    { ScalarValue(value) }
	}
}

// ── col_spec parsing (events-layer §1.1) ─────────────────────────────────────

fn parse_event_col_spec(payload []u8) ![]TableColumn {
	if payload.len < 4 {
		return error('col_spec truncated reading u32 count')
	}
	count := u32(payload[0]) | (u32(payload[1]) << 8) | (u32(payload[2]) << 16) | (u32(payload[3]) << 24)
	mut p := 4
	mut cols := []TableColumn{cap: int(count)}
	for _ in 0 .. int(count) {
		name, np := read_u32_prefixed_string(payload, p)!
		p = np
		if p >= payload.len {
			return error('col_spec truncated reading type code')
		}
		code := payload[p]
		p += 1
		cols << TableColumn{ name: name, type_name: column_type_name_from_code(code) }
	}
	return cols
}

// ── CX format emission ───────────────────────────────────────────────────────

fn (mut w CxEventsWriter) cx_indent() string {
	if !w.cx_pretty { return '' }
	mut s := ''
	for _ in 0 .. w.elem_stack.len { s += '  ' }
	return s
}

fn (mut w CxEventsWriter) cx_nl() string {
	return if w.cx_pretty { '\n' } else { '' }
}

fn (mut w CxEventsWriter) cx_emit_start_element(name string, anchor ?string, data_type ?string, merge ?string, attrs []Attribute) ! {
	mut s := w.cx_indent() + '['
	s += name
	if a := anchor    { s += ' &${a}' }
	if m := merge     { s += ' *${m}' }
	if dt := data_type { s += ' :${dt}' }
	for a in attrs {
		val_str := scalar_value_str(a.value)
		emitted := if a.is_ref {
			'@${val_str}'
		} else if a.data_type() == none && cx_would_autotype(val_str) {
			"'${val_str}'"
		} else {
			cx_quote_attr_if_needed(val_str)
		}
		s += ' ${a.name}=${emitted}'
	}
	s += w.cx_nl()
	w.write_str(s)!
}

fn (mut w CxEventsWriter) cx_emit_end_element(name string) ! {
	// Note: name validation happened at the public emit_end_element
	// boundary — by the time we get here, we know name matches the
	// element being closed (which has already been popped from
	// elem_stack). cx_indent uses the new (post-pop) depth. The
	// name parameter is reserved for future support of self-closing
	// or named-EndElement output formats (XML-style, when implemented).
	_ = name
	w.write_str(w.cx_indent() + ']' + w.cx_nl())!
}

fn (mut w CxEventsWriter) cx_emit_text(value string) ! {
	w.write_str(w.cx_indent() + cx_quote_text_if_needed(value) + w.cx_nl())!
}

fn (mut w CxEventsWriter) cx_emit_scalar(data_type ?string, value string) ! {
	// Render the canonical scalar form. For typed scalars use the bare
	// representation (e.g. `42`, `true`, `null`); for untyped strings
	// quote when needed.
	rendered := if dt := data_type {
		// Typed scalar: emit the value as-is (caller-provided string
		// representation is canonical per §1.1's "value is always the
		// raw string representation").
		if dt == 'string' || dt == '' { cx_quote_text_if_needed(value) } else { value }
	} else {
		cx_quote_text_if_needed(value)
	}
	w.write_str(w.cx_indent() + rendered + w.cx_nl())!
}

fn (mut w CxEventsWriter) cx_emit_comment(value string) ! {
	w.write_str(w.cx_indent() + '[-${value}]' + w.cx_nl())!
}

fn (mut w CxEventsWriter) cx_emit_pi(target string, data ?string) ! {
	mut s := w.cx_indent() + '[?${target}'
	if d := data { s += ' ${d}' }
	s += '?]' + w.cx_nl()
	w.write_str(s)!
}

fn (mut w CxEventsWriter) cx_emit_entity_ref(name string) ! {
	w.write_str(w.cx_indent() + '&${name};' + w.cx_nl())!
}

fn (mut w CxEventsWriter) cx_emit_raw_text(value string) ! {
	w.write_str(w.cx_indent() + '[#${value}#]' + w.cx_nl())!
}

fn (mut w CxEventsWriter) cx_emit_alias(name string) ! {
	w.write_str(w.cx_indent() + '[*${name}]' + w.cx_nl())!
}

// ── CX chunked-table emission ────────────────────────────────────────────────

fn (mut w CxEventsWriter) cx_emit_table_open(name string, cols []TableColumn) ! {
	mut header_parts := []string{cap: cols.len}
	for c in cols {
		if c.type_name == '' {
			header_parts << c.name
		} else {
			header_parts << '${c.name}:${c.type_name}'
		}
	}
	header := header_parts.join(' ')
	w.write_str(w.cx_indent() + '[${name} :table[${header}]' + w.cx_nl())!
}

// cx_emit_table_row_group decodes the §3.11.2 plain-body bytes
// (uvarint(row_count) + col-payload[col_count]) and emits each row as
// a CX row line. Reuses BinReader / read_strict_cell from
// data_bin_chunked.v for byte-for-byte agreement with the canonical
// chunked encoder.
fn (mut w CxEventsWriter) cx_emit_table_row_group(payload []u8) ! {
	mut br := BinReader{ buf: payload, pos: 0, depth: 0, max_depth: int(cxcol_default_depth) }
	row_count := br.read_uvarint()!
	if row_count == 0 { return }
	if w.table_col_count == 0 {
		return error(w.fail('W007', 'RowGroup with no col-spec context'))
	}
	col_count := int(w.table_col_count)
	// Resolve column types — re-parse from elem stack? No, we don't
	// keep cols cached. Instead, we need them — store at StartTable.
	// Keep it simple: re-decode types from stored col-spec context.
	// We keep a small cache on the writer.
	cols := w.table_cols
	if cols.len != col_count {
		return error(w.fail('W007', 'RowGroup col count mismatch'))
	}
	// Each row is emitted as space-separated cells per cx_emit_table_element.
	mut group := [][]ScalarValue{cap: int(row_count)}
	for _ in 0 .. int(row_count) {
		group << []ScalarValue{cap: col_count}
	}
	for col_idx, col in cols {
		code := column_type_code(col.type_name)
		for row_idx in 0 .. int(row_count) {
			val := br.read_strict_cell(code)!
			group[row_idx] << val
			_ = col_idx
		}
	}
	if br.pos != br.buf.len {
		return error(w.fail('W007', 'trailing bytes in row-group payload (${br.buf.len - br.pos})'))
	}
	row_indent := if w.cx_pretty {
		mut s := ''
		for _ in 0 .. w.elem_stack.len + 1 { s += '  ' }
		s
	} else {
		''
	}
	for row in group {
		mut cells := []string{cap: col_count}
		for i, cell in row {
			ct := if i < cols.len { cols[i].type_name } else { '' }
			// row groups decoded from the chunked-table binary payload
			// are scalar-only in the wire format (Phase 2.2 wire-
			// extension lands later). Wrap each ScalarValue cell as a
			// TableCellValue for cx_format_table_cell.
			cells << cx_format_table_cell(cell_value_from_scalar(cell), ct)
		}
		w.write_str(row_indent + cells.join(' ') + w.cx_nl())!
	}
}

fn (mut w CxEventsWriter) cx_emit_table_close() ! {
	w.write_str(w.cx_indent() + ']' + w.cx_nl())!
	w.table_cols = []TableColumn{}
}

// ── XML format emission (per spec/streaming.md §6.6) ─────────────────────────
//
// StartDoc emits the XML declaration <?xml version="1.0"?>. StartElement /
// EndElement emit pretty-printed open/close tags. Attribute payload follows
// the same wire shape as CX. Alias and chunked-table events fall through to
// W009 (§6.6).

fn (mut w CxEventsWriter) xml_indent() string {
	mut s := ''
	for _ in 0 .. w.elem_stack.len { s += '  ' }
	return s
}

fn xml_attr_str_value(v ScalarValue) string {
	return match v {
		i64       { v.str() }
		f64       { format_float(v as f64) }
		bool      { if v as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { v as string }
	}
}

fn (mut w CxEventsWriter) xml_emit_start_element(name string, anchor ?string, data_type ?string, merge ?string, attrs []Attribute) ! {
	mut s := w.xml_indent() + '<' + name
	if a := anchor    { s += ' cx:anchor="${xml_escape_attr(a)}"' }
	if m := merge     { s += ' cx:merge="${xml_escape_attr(m)}"' }
	if dt := data_type { s += ' cx:type="${xml_escape_attr(dt)}"' }
	for a in attrs {
		s += ' ${a.name}="${xml_escape_attr(xml_attr_str_value(a.value))}"'
	}
	s += '>\n'
	w.write_str(s)!
}

fn (mut w CxEventsWriter) xml_emit_end_element(name string) ! {
	w.write_str(w.xml_indent() + '</' + name + '>\n')!
}

fn (mut w CxEventsWriter) xml_emit_text(value string) ! {
	w.write_str(w.xml_indent() + xml_escape_text(value) + '\n')!
}

fn (mut w CxEventsWriter) xml_emit_scalar(data_type ?string, value string) ! {
	// §6.6: XML emits typed scalars as plain text content. The data_type
	// itself does not surface in the output (XML has no per-value type
	// annotation; consumers infer from schema or element wrapping).
	_ = data_type
	w.write_str(w.xml_indent() + xml_escape_text(value) + '\n')!
}

fn (mut w CxEventsWriter) xml_emit_comment(value string) ! {
	w.write_str(w.xml_indent() + '<!--' + value + '-->\n')!
}

fn (mut w CxEventsWriter) xml_emit_pi(target string, data ?string) ! {
	mut s := w.xml_indent() + '<?' + target
	if d := data { if d.len > 0 { s += ' ' + d } }
	s += '?>\n'
	w.write_str(s)!
}

fn (mut w CxEventsWriter) xml_emit_entity_ref(name string) ! {
	w.write_str(w.xml_indent() + '&' + name + ';\n')!
}

fn (mut w CxEventsWriter) xml_emit_raw_text(value string) ! {
	// CDATA split rule: ]]> → ]]><![CDATA[> (mirrors emitter_xml.v).
	content := value.replace(']]>', ']]><![CDATA[>')
	w.write_str(w.xml_indent() + '<![CDATA[' + content + ']]>\n')!
}

// ── JSON AST emission (per spec/streaming.md §6.6.1) ─────────────────────────
//
// Compact, stream-local AST shape — the same per-node JSON produced by
// emitter_json.v (`cx_to_ast_json`), wired to fire one node at a time
// against the event stream. The writer maintains `json_arr_first`, a
// per-array-level "is the next child the first in this array?" stack,
// so that sibling separators (`,`) can be inserted without lookahead.
// StartDoc opens `{"type":"Document","elements":[` and pushes; each
// StartElement opens `{"type":"Element",...,"items":[` and pushes;
// EndElement closes `]}`; EndDoc closes `]}`.

fn (mut w CxEventsWriter) json_write_sibling_comma() ! {
	if w.json_arr_first.len == 0 { return }
	last := w.json_arr_first.len - 1
	if !w.json_arr_first[last] {
		w.write_str(',')!
	}
	w.json_arr_first[last] = false
}

fn json_attr_v(a Attribute) string {
	mut pairs := []string{}
	pairs << '"name":${json_str(a.name)}'
	pairs << '"value":${json_scalar_value(a.value)}'
	if dt := a.data_type() {
		pairs << '"dataType":"${dt}"'
	}
	if a.is_ref {
		pairs << '"isRef":true'
	}
	return '{${pairs.join(',')}}'
}

fn (mut w CxEventsWriter) json_emit_start_element(name string, anchor ?string, data_type ?string, merge ?string, attrs []Attribute) ! {
	w.json_write_sibling_comma()!
	mut s := '{"type":"Element","name":${json_str(name)}'
	if a := anchor     { s += ',"anchor":${json_str(a)}' }
	if m := merge      { s += ',"merge":${json_str(m)}' }
	if dt := data_type { s += ',"dataType":${json_str(dt)}' }
	if attrs.len > 0 {
		attr_strs := attrs.map(json_attr_v(it))
		s += ',"attrs":[${attr_strs.join(',')}]'
	}
	// "items" is always emitted (possibly []) per §6.6.1, so EndElement
	// can close with a uniform `]}` without per-element lookahead.
	s += ',"items":['
	w.write_str(s)!
	w.json_arr_first << true
}

fn (mut w CxEventsWriter) json_emit_end_element(name string) ! {
	_ = name
	if w.json_arr_first.len > 0 { w.json_arr_first.delete_last() }
	w.write_str(']}')!
}

fn (mut w CxEventsWriter) json_emit_text(value string) ! {
	w.json_write_sibling_comma()!
	w.write_str('{"type":"Text","value":${json_str(value)}}')!
}

fn (mut w CxEventsWriter) json_emit_scalar(data_type ?string, value string) ! {
	w.json_write_sibling_comma()!
	dt := data_type or { 'string' }
	val_json := match dt {
		'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' { value }
		'float', 'f32', 'f64', 'decimal', 'f16' { value }
		'bool' { value }
		'null' { 'null' }
		else { json_str(value) }
	}
	w.write_str('{"type":"Scalar","dataType":"${dt}","value":${val_json}}')!
}

fn (mut w CxEventsWriter) json_emit_comment(value string) ! {
	w.json_write_sibling_comma()!
	w.write_str('{"type":"Comment","value":${json_str(value)}}')!
}

fn (mut w CxEventsWriter) json_emit_pi(target string, data ?string) ! {
	w.json_write_sibling_comma()!
	mut s := '{"type":"PI","target":${json_str(target)}'
	if d := data { s += ',"data":${json_str(d)}' }
	s += '}'
	w.write_str(s)!
}

fn (mut w CxEventsWriter) json_emit_entity_ref(name string) ! {
	w.json_write_sibling_comma()!
	w.write_str('{"type":"EntityRef","name":${json_str(name)}}')!
}

fn (mut w CxEventsWriter) json_emit_raw_text(value string) ! {
	w.json_write_sibling_comma()!
	w.write_str('{"type":"RawText","value":${json_str(value)}}')!
}

fn (mut w CxEventsWriter) json_emit_alias(name string) ! {
	w.json_write_sibling_comma()!
	w.write_str('{"type":"Alias","name":${json_str(name)}}')!
}

// ── YAML AST emission (per spec/streaming.md §6.6.1) ─────────────────────────
//
// YAML representation of the same AST shape: every event emits a YAML
// mapping under the enclosing array. The YAML depth at the moment of
// emit is `elem_stack.len + 1` (1 = inside Document.elements; deeper
// when inside an open Element's items array). Each mapping starts with
// `- type: ...` at the array-item position; subsequent keys indent one
// level deeper. We reuse `json_arr_first` to track the "this array has
// at least one item" state, but YAML doesn't need explicit separators
// (newlines + indentation carry the structure) — the flag is set so
// EndDoc / EndElement can decrement the stack symmetrically with JSON.

fn yaml_indent_n(n int) string {
	mut s := ''
	for _ in 0 .. n { s += '  ' }
	return s
}

// yaml_quote returns a double-quoted, escaped form. We always quote to
// keep the emit byte-deterministic — adopters who want unquoted YAML
// scalars use the non-streaming `cx_to_yaml` surface (which inspects
// values for needs-quote).
fn yaml_quote(s string) string {
	mut out := '"'
	for b in s.bytes() {
		match b {
			`"`  { out += '\\"' }
			`\\` { out += '\\\\' }
			`\n` { out += '\\n' }
			`\r` { out += '\\r' }
			`\t` { out += '\\t' }
			else {
				if b < 0x20 {
					out += '\\u${b:04x}'
				} else {
					out += b.ascii_str()
				}
			}
		}
	}
	out += '"'
	return out
}

fn (mut w CxEventsWriter) yaml_mark_arr_used() {
	if w.json_arr_first.len > 0 {
		w.json_arr_first[w.json_arr_first.len - 1] = false
	}
}

// yaml_event_depth returns the YAML indentation depth at which the
// next event is emitted. 1 = top-level (under `elements:`); 2+ = inside
// an open Element at elem_stack.len = depth-1.
fn (w &CxEventsWriter) yaml_event_depth() int {
	return w.elem_stack.len + 1
}

fn (mut w CxEventsWriter) yaml_emit_start_element(name string, anchor ?string, data_type ?string, merge ?string, attrs []Attribute) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := yaml_indent_n(depth) + '  '
	mut s := '${item_ind}- type: Element\n'
	s += '${key_ind}name: ${yaml_quote(name)}\n'
	if a := anchor     { s += '${key_ind}anchor: ${yaml_quote(a)}\n' }
	if m := merge      { s += '${key_ind}merge: ${yaml_quote(m)}\n' }
	if dt := data_type { s += '${key_ind}dataType: ${yaml_quote(dt)}\n' }
	if attrs.len > 0 {
		s += '${key_ind}attrs:\n'
		attr_item_ind := key_ind + '  '
		attr_key_ind  := attr_item_ind + '  '
		for a in attrs {
			s += '${attr_item_ind}- name: ${yaml_quote(a.name)}\n'
			s += '${attr_key_ind}value: ${yaml_scalar_value(a.value)}\n'
			if dt := a.data_type() {
				s += '${attr_key_ind}dataType: ${yaml_quote(dt)}\n'
			}
			if a.is_ref {
				s += '${attr_key_ind}isRef: true\n'
			}
		}
	}
	s += '${key_ind}items:\n'
	w.write_str(s)!
	w.yaml_mark_arr_used()
	w.json_arr_first << true
}

fn (mut w CxEventsWriter) yaml_emit_end_element(name string) ! {
	_ = name
	// YAML uses indentation for structure; no closing bytes. Pop the
	// items[] level.
	if w.json_arr_first.len > 0 { w.json_arr_first.delete_last() }
	// If no children were emitted under this element's items:, the
	// `items:` key has an empty mapping; YAML accepts this implicitly
	// (the line `items:` with no following indented content reads as
	// `items: null`). We choose not to back-patch with `[]` to keep
	// the emit purely append-only.
}

fn yaml_scalar_value(v ScalarValue) string {
	return match v {
		i64       { (v as i64).str() }
		f64       { format_float(v as f64) }
		bool      { if v as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { yaml_quote(v as string) }
	}
}

fn (mut w CxEventsWriter) yaml_emit_text(value string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	w.write_str('${item_ind}- type: Text\n${key_ind}value: ${yaml_quote(value)}\n')!
	w.yaml_mark_arr_used()
}

fn (mut w CxEventsWriter) yaml_emit_scalar(data_type ?string, value string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	dt := data_type or { 'string' }
	val_yaml := match dt {
		'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' { value }
		'float', 'f32', 'f64', 'decimal', 'f16' { value }
		'bool' { value }
		'null' { 'null' }
		else { yaml_quote(value) }
	}
	w.write_str('${item_ind}- type: Scalar\n${key_ind}dataType: ${yaml_quote(dt)}\n${key_ind}value: ${val_yaml}\n')!
	w.yaml_mark_arr_used()
}

fn (mut w CxEventsWriter) yaml_emit_comment(value string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	w.write_str('${item_ind}- type: Comment\n${key_ind}value: ${yaml_quote(value)}\n')!
	w.yaml_mark_arr_used()
}

fn (mut w CxEventsWriter) yaml_emit_pi(target string, data ?string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	mut s := '${item_ind}- type: PI\n${key_ind}target: ${yaml_quote(target)}\n'
	if d := data { s += '${key_ind}data: ${yaml_quote(d)}\n' }
	w.write_str(s)!
	w.yaml_mark_arr_used()
}

fn (mut w CxEventsWriter) yaml_emit_entity_ref(name string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	w.write_str('${item_ind}- type: EntityRef\n${key_ind}name: ${yaml_quote(name)}\n')!
	w.yaml_mark_arr_used()
}

fn (mut w CxEventsWriter) yaml_emit_raw_text(value string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	w.write_str('${item_ind}- type: RawText\n${key_ind}value: ${yaml_quote(value)}\n')!
	w.yaml_mark_arr_used()
}

fn (mut w CxEventsWriter) yaml_emit_alias(name string) ! {
	depth := w.yaml_event_depth()
	item_ind := yaml_indent_n(depth)
	key_ind  := item_ind + '  '
	w.write_str('${item_ind}- type: Alias\n${key_ind}name: ${yaml_quote(name)}\n')!
	w.yaml_mark_arr_used()
}
