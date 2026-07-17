@[has_globals]
module code

import cx
import os
import time as vtime

// stdlib_io.v — native primitives backing the `cx-stdlib/io` module
// (spec/std-lib/io.md). File and stream I/O — whole-file reads/writes,
// streaming handles, line iteration, filesystem queries, directory
// operations, globbing, tempfiles, locking.
//
// ── CAPABILITY ENFORCEMENT (the core of this module, §7) ────────────
//   io is a Tier-B, necessarily-impure module: every public function is
//   `:impure` and every effect point is capability-gated (security.md §2,
//   deny-by-default). The FIRST thing every effectful primitive does is
//   `cap_guard(<cap>, resource)` — BEFORE any os.* touch or domain
//   validation (fail-closed, §4). Under the runner's empty capability set
//   the guard returns the CXER0271 err VALUE and the function short-
//   circuits, so the deterministic conformance suite (all deny cases)
//   sees CXER0271. `close` requires NO capability (§7) — it only releases
//   an already-granted handle.
//
//   §7 capability table:
//     read  → read-file / read-file-bytes / read-file-lines / read-all /
//             read-all-bytes / read-bytes / read-line / line-iter / stat /
//             exists / is-file / is-directory / is-symlink / is-eof /
//             list-dir / glob / glob-iter / walk / readlink / size /
//             created-time / modified-time / tell / seek / system-temp-dir /
//             temp-dir / open (read mode)
//     write → open (write/append mode) / open-with-opts / write-bytes /
//             write-file / write-file-bytes / write-file-lines /
//             write-line / write-string / append-file / append-file-bytes /
//             make-dir / make-dirs / remove / remove-dir / remove-tree /
//             rename / copy / copy-tree / symlink / lock / unlock / flush /
//             temp-file
//     (none)→ close
//
// ── CX value model ──────────────────────────────────────────────────
//   int/string/bool/bytes/null scalars; sequence = Element{'__cx_seq__'};
//   a file handle is an opaque `[file handle=N path=… mode=…]` element
//   carrying an integer registry id (the proven store/random handle form).
//
// Behind the guard the operations are REAL (V's `os`), not stubs; OS-level
// failures map to the §5 codes as err VALUES via mk_err.

// ── open-file handle registry (§2.1) ────────────────────────────────
//
// Process-global registry behind a nil-default voidptr (the proven
// store/random pattern; `@[has_globals]` enables module state without the
// -enable-globals flag). Each open handle holds its os.File plus mode and
// buffered-read cursor state for read-line / seek / tell.

@[heap]
struct IoHandle {
mut:
	path     string
	mode     string
	file     os.File
	is_open  bool
	readable bool
	writable bool
	// is_std marks a handle that wraps a standard stream (stdin/stdout/
	// stderr from cx-stdlib/env). Such handles are flushed after every
	// write so output appears promptly, matching CLI expectations.
	is_std bool
	// child_fd >= 0 marks a handle backed by a RAW pipe fd (a spawned
	// child's stdin/stdout/stderr, process.md §2.4) rather than an os.File.
	// read/write/close route through POSIX read(2)/write(2)/close(2) on this
	// fd; -1 (the default) means the os.File `file` field backs the handle.
	child_fd int = -1
}

@[heap]
struct IoRegistry {
mut:
	handles map[int]&IoHandle
	next_id int
}

__global (
	g_io_reg voidptr
)

fn io_reg() &IoRegistry {
	if g_io_reg == unsafe { nil } {
		r := &IoRegistry{
			handles: map[int]&IoHandle{}
		}
		g_io_reg = voidptr(r)
	}
	return unsafe { &IoRegistry(g_io_reg) }
}

fn io_register(h &IoHandle) int {
	mut reg := io_reg()
	reg.next_id++
	id := reg.next_id
	reg.handles[id] = h
	return id
}

fn io_lookup(id int) ?&IoHandle {
	reg := io_reg()
	return reg.handles[id] or { return none }
}

// ── value builders ──────────────────────────────────────────────────

fn io_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn io_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn io_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn io_bytes(b string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bytes_type
	}
}

fn io_datetime(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.datetime_type
	}
}

fn io_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

fn io_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// ── argument readers ────────────────────────────────────────────────

fn io_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn io_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	return none
}

// io_arg_bytes accepts both bytes-typed and string-typed scalar payloads
// (both carry their octets in a V string).
fn io_arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	return none
}

// io_arg_atom reads an atom scalar's name (e.g. :start / :exclusive).
fn io_arg_atom(n cx.Node) ?string {
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.atom_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	return none
}

// io_seq_strings collects a sequence element into a []string.
fn io_seq_strings(n cx.Node) ?[]string {
	if n is cx.Element {
		if n.name in ['__cx_seq__', '__cx_arr__', ''] {
			mut out := []string{cap: n.items.len}
			for it in n.items {
				out << io_arg_str(it) or { return none }
			}
			return out
		}
	}
	return none
}

// io_opts collects a `__cx_map__` opts element into a key→node map.
fn io_opts(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

fn io_opt_str(m map[string]cx.Node, key string, def string) string {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return def
}

fn io_opt_bool(m map[string]cx.Node, key string, def bool) bool {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return def
}

// io_handle_of reads the integer handle id off a `[file handle=N …]` element.
fn io_handle_of(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return int(cx.scalar_value_str_public(a.value).int())
			}
		}
	}
	return none
}

// ── error mapping (§5) ──────────────────────────────────────────────
//
// Maps a V os error message to the closest §5 io error code. Best-effort
// classification on the message text since V's os does not expose errno
// uniformly across platforms.

fn io_os_err(op string, path string, msg string) cx.Node {
	low := msg.to_lower()
	if low.contains('no such file') || low.contains('not found')
		|| low.contains('cannot find') {
		return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: ${op} ${path}: ${msg}')
	}
	if low.contains('permission denied') || low.contains('access is denied') {
		return mk_err('cx-err:CXER3402', 'E_IO_PERMISSION_DENIED: ${op} ${path}: ${msg}')
	}
	if low.contains('exists') {
		return mk_err('cx-err:CXER3403', 'E_IO_ALREADY_EXISTS: ${op} ${path}: ${msg}')
	}
	if low.contains('not a directory') {
		return mk_err('cx-err:CXER3404', 'E_IO_NOT_A_DIRECTORY: ${op} ${path}: ${msg}')
	}
	if low.contains('is a directory') {
		return mk_err('cx-err:CXER3405', 'E_IO_IS_A_DIRECTORY: ${op} ${path}: ${msg}')
	}
	if low.contains('broken pipe') {
		return mk_err('cx-err:CXER3406', 'E_IO_BROKEN_PIPE: ${op} ${path}: ${msg}')
	}
	if low.contains('no space') || low.contains('disk full') {
		return mk_err('cx-err:CXER3407', 'E_IO_DISK_FULL: ${op} ${path}: ${msg}')
	}
	if low.contains('too long') {
		return mk_err('cx-err:CXER3408', 'E_IO_NAME_TOO_LONG: ${op} ${path}: ${msg}')
	}
	// Default to NOT_FOUND for unclassified read/query failures.
	return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: ${op} ${path}: ${msg}')
}

const io_handle_closed = 'E_IO_HANDLE_CLOSED: operation on an already-closed handle'

// io_std_handle resolves a `[std-stream name=… fd=N]` element — the handle
// shape produced by cx-stdlib/env's stdin/stdout/stderr — to a live IoHandle
// over the matching C stdio stream, so the ordinary read/write surface
// (read-line, write-line, write-string, flush, …) works on the standard
// streams. Returns none for any other element shape.
fn io_std_handle(n cx.Node) ?&IoHandle {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	if el.name != 'std-stream' {
		return none
	}
	mut fd := -1
	mut sname := ''
	for a in el.attrs {
		match a.name {
			'fd' { fd = int(cx.scalar_value_str_public(a.value).int()) }
			'name' { sname = cx.scalar_value_str_public(a.value) }
			else {}
		}
	}
	mut file := os.File{}
	mut readable := false
	mut writable := false
	match fd {
		0 {
			file = os.stdin()
			readable = true
		}
		1 {
			file = os.stdout()
			writable = true
		}
		2 {
			file = os.stderr()
			writable = true
		}
		else {
			return none
		}
	}
	return &IoHandle{
		path:     '<${sname}>'
		mode:     if readable { 'r' } else { 'w' }
		file:     file
		is_open:  true
		readable: readable
		writable: writable
		is_std:   true
	}
}

// io_h_read reads up to buf.len bytes from a handle, routing to the raw child
// pipe fd (os.fd_read → read(2)) when child_fd >= 0, else the os.File. Returns
// bytes read (0 = EOF).
fn io_h_read(mut h IoHandle, mut buf []u8) !int {
	if h.child_fd >= 0 {
		s, nb := os.fd_read(h.child_fd, buf.len)
		if nb <= 0 {
			return 0
		}
		for i in 0 .. nb {
			buf[i] = s[i]
		}
		return nb
	}
	return h.file.read(mut buf)
}

// io_h_write writes all of data, routing to the raw child pipe fd (os.fd_write
// → blocks until fully written) when child_fd >= 0, else the os.File.
fn io_h_write(mut h IoHandle, data []u8) ! {
	if h.child_fd >= 0 {
		os.fd_write(h.child_fd, data.bytestr())
		return
	}
	h.file.write(data)!
}

// io_drain_child reads a raw child fd to EOF (for read-all / read-all-bytes,
// which are path-based for file handles but must stream-drain a pipe).
fn io_drain_child(mut h IoHandle) []u8 {
	mut out := []u8{}
	for {
		mut tmp := []u8{len: 8192}
		n := io_h_read(mut h, mut tmp) or { break }
		if n <= 0 {
			break
		}
		out << tmp[..n]
	}
	return out
}

// io_register_child_fd registers a raw child-stdio fd as an io handle and
// returns its `[file handle=N role=…]` element (process.md §2.4). Called by
// cx-stdlib/process's stdin/stdout/stderr/pty accessors.
pub fn io_register_child_fd(fd int, role string, readable bool, writable bool) cx.Node {
	h := &IoHandle{
		path:     '<${role}>'
		mode:     if readable { 'r' } else { 'w' }
		is_open:  true
		readable: readable
		writable: writable
		child_fd: fd
	}
	id := io_register(h)
	return cx.Element{
		name:  'file'
		attrs: [
			cx.Attribute{ name: 'handle', value: cx.ScalarValue(i64(id)) },
			cx.Attribute{ name: 'role', value: cx.ScalarValue(role) },
		]
	}
}

// io_get_open resolves a handle argument to its live IoHandle. On failure
// returns (_, err_node, false) with CXER3409 (closed/unknown handle).
fn io_get_open(arg cx.Node) (&IoHandle, cx.Node, bool) {
	if sh := io_std_handle(arg) {
		return sh, io_null(), true
	}
	id := io_handle_of(arg) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: expected a file handle element'), false
	}
	h := io_lookup(id) or {
		return unsafe { nil }, mk_err('cx-err:CXER3409', io_handle_closed), false
	}
	if !h.is_open {
		return unsafe { nil }, mk_err('cx-err:CXER3409', io_handle_closed), false
	}
	return h, io_null(), true
}

// ── handle element (§2.1) ───────────────────────────────────────────

fn io_handle_element(id int, h &IoHandle) cx.Node {
	return cx.Element{
		name:  'file'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(h.path)
			},
			cx.Attribute{
				name:  'mode'
				value: cx.ScalarValue(h.mode)
			},
		]
	}
}

// ── stat element (§3.5) ─────────────────────────────────────────────

fn io_stat_element(path string) cx.Node {
	is_dir := os.is_dir(path)
	is_link := os.is_link(path)
	mut sz := i64(0)
	if !is_dir {
		sz = i64(os.file_size(path))
	}
	mtime := os.file_last_mod_unix(path)
	return cx.Element{
		name:  'stat'
		attrs: [
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(path)
			},
			cx.Attribute{
				name:  'size'
				value: cx.ScalarValue(sz)
			},
			cx.Attribute{
				name:  'is-file'
				value: cx.ScalarValue(os.is_file(path))
			},
			cx.Attribute{
				name:  'is-directory'
				value: cx.ScalarValue(is_dir)
			},
			cx.Attribute{
				name:  'is-symlink'
				value: cx.ScalarValue(is_link)
			},
			cx.Attribute{
				name:  'modified'
				value: cx.ScalarValue(i64(mtime))
			},
		]
	}
}

// ── mode → open flags + capability ──────────────────────────────────

// io_mode_cap returns the capability ('read'/'write') required for an open
// in the given mode (§7). Read mode → read; write/append → write.
fn io_mode_cap(mode string) string {
	return match mode {
		'r' { 'read' }
		else { 'write' }
	}
}

fn io_mode_readable(mode string) bool {
	return mode in ['r', 'r+', 'w+', 'a+']
}

fn io_mode_writable(mode string) bool {
	return mode != 'r'
}

// io_open_impl performs the real os open (behind the cap_guard) and
// registers the handle. Returns the handle element or an err value.
fn io_open_impl(path string, mode string) cx.Node {
	mut f := os.File{}
	match mode {
		'r' {
			f = os.open(path) or { return io_os_err('open', path, err.msg()) }
		}
		'w', 'w+' {
			f = os.create(path) or { return io_os_err('open', path, err.msg()) }
		}
		'a', 'a+' {
			f = os.open_append(path) or { return io_os_err('open', path, err.msg()) }
		}
		'r+' {
			f = os.open_file(path, 'r+') or { return io_os_err('open', path, err.msg()) }
		}
		'x' {
			if os.exists(path) {
				return mk_err('cx-err:CXER3403', 'E_IO_ALREADY_EXISTS: open ${path}')
			}
			f = os.create(path) or { return io_os_err('open', path, err.msg()) }
		}
		else {
			f = os.open(path) or { return io_os_err('open', path, err.msg()) }
		}
	}
	h := &IoHandle{
		path:     path
		mode:     mode
		file:     f
		is_open:  true
		readable: io_mode_readable(mode)
		writable: io_mode_writable(mode)
	}
	id := io_register(h)
	return io_handle_element(id, h)
}

// io_is_fs_root reports whether the resolved path is a filesystem root or
// drive/volume root (§4.6 remove-tree root guard).
fn io_is_fs_root(resolved string) bool {
	if resolved == '/' || resolved == '' {
		return true
	}
	// Windows drive root: "C:\" / "C:/" or bare "C:".
	if resolved.len <= 3 && resolved.len >= 2 && resolved[1] == `:` {
		return true
	}
	return false
}

// ── primitive dispatch ──────────────────────────────────────────────

// io_read_caps / io_write_caps name the read-path / write-path primitives
// (the §7 table, minus open which is mode-derived, and close which needs
// none). The cap_guard at the top of dispatch fail-closes BEFORE any work.
const io_read_caps = ['io-read-file', 'io-read-file-bytes', 'io-read-file-lines',
	'io-read-all', 'io-read-all-bytes', 'io-read-bytes', 'io-read-line', 'io-line-iter',
	'io-stat', 'io-exists', 'io-is-file', 'io-is-directory', 'io-is-symlink', 'io-is-eof',
	'io-list-dir', 'io-glob', 'io-glob-iter', 'io-walk', 'io-readlink', 'io-size',
	'io-created-time', 'io-modified-time', 'io-tell', 'io-seek', 'io-system-temp-dir',
	'io-temp-dir', 'io-watch', 'io-watch-next']

const io_write_caps = ['io-open-with-opts', 'io-write-bytes', 'io-write-file',
	'io-write-file-bytes', 'io-write-file-lines', 'io-write-line', 'io-write-string',
	'io-append-file', 'io-append-file-bytes', 'io-make-dir', 'io-make-dirs', 'io-remove',
	'io-remove-dir', 'io-remove-tree', 'io-rename', 'io-copy', 'io-copy-tree', 'io-symlink',
	'io-lock', 'io-unlock', 'io-flush', 'io-temp-file']

fn io_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// ── capability gate (§7), fail-closed BEFORE any effect ─────────────
	// `open` derives its capability from the requested mode; every other
	// effectful primitive maps statically. `close` (io-close) requires no
	// capability and is intentionally absent from both lists.
	if name == 'io-open' {
		mode := io_arg_str(args[1]) or { 'r' }
		if d := cap_guard(io_mode_cap(mode), 'open ${mode}') {
			return d
		}
	} else if name in io_read_caps {
		if d := cap_guard('read', name) {
			return d
		}
	} else if name in io_write_caps {
		if d := cap_guard('write', name) {
			return d
		}
	}

	// ── §3.7 continuous filesystem watch (#128-B) ───────────────────────
	// The watch verbs live in stdlib_iowatch.v (+ platform backends); their
	// read-path caps are gated above (watch / watch-next), and watch-close
	// — like close — needs none.
	if r := iowatch_dispatch(name, args) {
		return r
	}

	match name {
		// ── §3.1 whole-file convenience ─────────────────────────────
		'io-read-file' {
			path := io_arg_str(args[0]) or { return none }
			if !os.exists(path) {
				return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: read-file ${path}')
			}
			content := os.read_file(path) or { return io_os_err('read-file', path, err.msg()) }
			if !utf8_validate(content.bytes()) {
				return mk_err('cx-err:CXER3400', 'E_IO_ENCODING_INVALID: read-file ${path}: invalid UTF-8')
			}
			return io_str(content)
		}
		'io-read-file-bytes' {
			path := io_arg_str(args[0]) or { return none }
			b := os.read_bytes(path) or { return io_os_err('read-file-bytes', path, err.msg()) }
			return io_bytes(b.bytestr())
		}
		'io-read-file-lines' {
			path := io_arg_str(args[0]) or { return none }
			content := os.read_file(path) or {
				return io_os_err('read-file-lines', path, err.msg())
			}
			lines := content.split_into_lines()
			mut out := []cx.Node{cap: lines.len}
			for l in lines {
				out << io_str(l)
			}
			return io_seq(out)
		}
		'io-write-file' {
			path := io_arg_str(args[0]) or { return none }
			content := io_arg_str(args[1]) or { return none }
			os.write_file(path, content) or { return io_os_err('write-file', path, err.msg()) }
			return io_null()
		}
		'io-edit-file' {
			// Surgical file edit (#93): read → replace-exactly → write. `from`
			// MUST occur exactly once (else CXER2903, no write) — the in-CX
			// equivalent of the harness Edit tool, so you don't drop to sed/awk.
			// Needs BOTH read and write caps (gated here, not via the static
			// lists, since it is the one primitive spanning both).
			if d := cap_guard('read', 'edit-file') {
				return d
			}
			if d := cap_guard('write', 'edit-file') {
				return d
			}
			path := io_arg_str(args[0]) or { return none }
			from := io_arg_str(args[1]) or { return none }
			to := io_arg_str(args[2]) or { return none }
			if !os.exists(path) {
				return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: edit-file ${path}')
			}
			content := os.read_file(path) or { return io_os_err('edit-file', path, err.msg()) }
			if !utf8_validate(content.bytes()) {
				return mk_err('cx-err:CXER3400', 'E_IO_ENCODING_INVALID: edit-file ${path}: invalid UTF-8')
			}
			if from == '' {
				return mk_err('cx-err:CXER2903', 'E_STRINGS_REPLACE_NOT_UNIQUE: edit-file requires a non-empty "from"')
			}
			cnt := rune_find_all(content, from).len
			if cnt != 1 {
				return mk_err('cx-err:CXER2903', 'E_STRINGS_REPLACE_NOT_UNIQUE: edit-file "from" must occur exactly once in ${path}, found ${cnt}')
			}
			edited := str_replace_n(content, from, to, 1)
			os.write_file(path, edited) or { return io_os_err('edit-file', path, err.msg()) }
			return io_null()
		}
		'io-write-file-bytes' {
			path := io_arg_str(args[0]) or { return none }
			b := io_arg_bytes(args[1]) or { return none }
			mut f := os.create(path) or { return io_os_err('write-file-bytes', path, err.msg()) }
			f.write(b) or {
				f.close()
				return io_os_err('write-file-bytes', path, err.msg())
			}
			f.close()
			return io_null()
		}
		'io-write-file-lines' {
			path := io_arg_str(args[0]) or { return none }
			lines := io_seq_strings(args[1]) or { return none }
			os.write_file(path, lines.join('\n')) or {
				return io_os_err('write-file-lines', path, err.msg())
			}
			return io_null()
		}
		'io-append-file' {
			path := io_arg_str(args[0]) or { return none }
			content := io_arg_str(args[1]) or { return none }
			mut f := os.open_append(path) or { return io_os_err('append-file', path, err.msg()) }
			f.write_string(content) or {
				f.close()
				return io_os_err('append-file', path, err.msg())
			}
			f.close()
			return io_null()
		}
		'io-append-file-bytes' {
			path := io_arg_str(args[0]) or { return none }
			b := io_arg_bytes(args[1]) or { return none }
			mut f := os.open_append(path) or {
				return io_os_err('append-file-bytes', path, err.msg())
			}
			f.write(b) or {
				f.close()
				return io_os_err('append-file-bytes', path, err.msg())
			}
			f.close()
			return io_null()
		}

		// ── §3.2 streaming handles ──────────────────────────────────
		'io-open' {
			path := io_arg_str(args[0]) or { return none }
			mode := io_arg_str(args[1]) or { 'r' }
			return io_open_impl(path, mode)
		}
		'io-open-with-opts' {
			path := io_arg_str(args[0]) or { return none }
			opts := io_opts(args[1])
			mode := io_opt_str(opts, 'mode', 'r')
			want_atomic := io_opt_bool(opts, 'atomic', false)
			if want_atomic {
				// §4.2 / §3.2: with atomic=true, raise CXER3410 when the
				// platform/filesystem cannot guarantee an atomic replace.
				// best-effort policy keeps atomic=false silent.
				return mk_err('cx-err:CXER3410', 'E_IO_ATOMIC_UNSUPPORTED: atomic open ${path}')
			}
			return io_open_impl(path, mode)
		}
		'io-close' {
			// §7: no capability. Idempotent — double close is well-defined
			// and never raises CXER3409.
			id := io_handle_of(args[0]) or { return io_null() }
			mut h := io_lookup(id) or { return io_null() }
			if h.is_open {
				if h.child_fd >= 0 {
					// closing a child's stdin signals EOF (process.md §2.4).
					os.fd_close(h.child_fd)
					h.child_fd = -1
				} else {
					h.file.close()
				}
				h.is_open = false
			}
			return io_null()
		}

		// ── §3.3 stream operations ──────────────────────────────────
		'io-read-bytes' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			n := io_arg_int(args[1]) or { return none }
			mut buf := []u8{len: int(n)}
			nread := io_h_read(mut h, mut buf) or {
				return io_os_err('read-bytes', h.path, err.msg())
			}
			return io_bytes(buf[..nread].bytestr())
		}
		'io-read-line' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			mut line := []u8{}
			mut one := []u8{len: 1}
			for {
				nread := io_h_read(mut h, mut one) or { break }
				if nread == 0 {
					break
				}
				if one[0] == `\n` {
					break
				}
				line << one[0]
			}
			mut s := line.bytestr()
			if s.ends_with('\r') {
				s = s[..s.len - 1]
			}
			return io_str(s)
		}
		'io-read-all' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			if h.child_fd >= 0 {
				return io_str(io_drain_child(mut h).bytestr())
			}
			content := os.read_file(h.path) or { return io_os_err('read-all', h.path, err.msg()) }
			return io_str(content)
		}
		'io-read-all-bytes' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			if h.child_fd >= 0 {
				return io_bytes(io_drain_child(mut h).bytestr())
			}
			b := os.read_bytes(h.path) or { return io_os_err('read-all-bytes', h.path, err.msg()) }
			return io_bytes(b.bytestr())
		}
		'io-write-bytes' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			b := io_arg_bytes(args[1]) or { return none }
			io_h_write(mut h, b) or { return io_os_err('write-bytes', h.path, err.msg()) }
			if h.is_std && h.child_fd < 0 {
				h.file.flush()
			}
			return io_null()
		}
		'io-write-string' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			s := io_arg_str(args[1]) or { return none }
			io_h_write(mut h, s.bytes()) or { return io_os_err('write-string', h.path, err.msg()) }
			if h.is_std && h.child_fd < 0 {
				h.file.flush()
			}
			return io_null()
		}
		'io-write-line' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			s := io_arg_str(args[1]) or { return none }
			io_h_write(mut h, (s + '\n').bytes()) or { return io_os_err('write-line', h.path, err.msg()) }
			if h.is_std && h.child_fd < 0 {
				h.file.flush()
			}
			return io_null()
		}
		'io-flush' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			h.file.flush()
			return io_null()
		}
		'io-seek' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			offset := io_arg_int(args[1]) or { return none }
			whence := io_arg_atom(args[2]) or { 'start' }
			seek_from := match whence {
				'current' { os.SeekMode.current }
				'end' { os.SeekMode.end }
				else { os.SeekMode.start }
			}
			h.file.seek(offset, seek_from) or { return io_os_err('seek', h.path, err.msg()) }
			return io_null()
		}
		'io-tell' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			pos := h.file.tell() or { return io_os_err('tell', h.path, err.msg()) }
			return io_int(i64(pos))
		}
		'io-is-eof' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			pos := h.file.tell() or { return io_os_err('is-eof', h.path, err.msg()) }
			sz := os.file_size(h.path)
			return io_bool(u64(pos) >= sz)
		}

		// ── §3.4 lazy line iteration ────────────────────────────────
		'io-line-iter' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			// Eager materialization behind the guard (the runner harness
			// never reaches this path; the granted harness can consume it
			// as a sequence). True lazy iteration is a streaming-events
			// concern (§8) layered above this primitive.
			content := os.read_file(h.path) or { return io_os_err('line-iter', h.path, err.msg()) }
			lines := content.split_into_lines()
			mut out := []cx.Node{cap: lines.len}
			for l in lines {
				out << io_str(l)
			}
			return io_seq(out)
		}

		// ── §3.5 filesystem queries ─────────────────────────────────
		'io-exists' {
			path := io_arg_str(args[0]) or { return none }
			return io_bool(os.exists(path))
		}
		'io-is-file' {
			path := io_arg_str(args[0]) or { return none }
			return io_bool(os.is_file(path))
		}
		'io-is-directory' {
			path := io_arg_str(args[0]) or { return none }
			return io_bool(os.is_dir(path))
		}
		'io-is-symlink' {
			path := io_arg_str(args[0]) or { return none }
			return io_bool(os.is_link(path))
		}
		'io-stat' {
			path := io_arg_str(args[0]) or { return none }
			if !os.exists(path) {
				return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: stat ${path}')
			}
			return io_stat_element(path)
		}
		'io-size' {
			path := io_arg_str(args[0]) or { return none }
			if !os.exists(path) {
				return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: size ${path}')
			}
			return io_int(i64(os.file_size(path)))
		}
		'io-modified-time' {
			path := io_arg_str(args[0]) or { return none }
			if !os.exists(path) {
				return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: modified-time ${path}')
			}
			mtime := os.file_last_mod_unix(path)
			return io_datetime(io_unix_to_iso(mtime))
		}
		'io-created-time' {
			path := io_arg_str(args[0]) or { return none }
			if !os.exists(path) {
				return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: created-time ${path}')
			}
			// V's os exposes last-modified portably; creation time is not
			// portable, so we surface the modified time as the available
			// timestamp behind the guard.
			mtime := os.file_last_mod_unix(path)
			return io_datetime(io_unix_to_iso(mtime))
		}

		// ── §3.6 directory operations ───────────────────────────────
		'io-list-dir' {
			path := io_arg_str(args[0]) or { return none }
			if !os.is_dir(path) {
				return mk_err('cx-err:CXER3404', 'E_IO_NOT_A_DIRECTORY: list-dir ${path}')
			}
			entries := os.ls(path) or { return io_os_err('list-dir', path, err.msg()) }
			mut out := []cx.Node{cap: entries.len}
			for e in entries {
				out << io_str(e)
			}
			return io_seq(out)
		}
		'io-make-dir' {
			path := io_arg_str(args[0]) or { return none }
			os.mkdir(path) or { return io_os_err('make-dir', path, err.msg()) }
			return io_null()
		}
		'io-make-dirs' {
			path := io_arg_str(args[0]) or { return none }
			os.mkdir_all(path) or { return io_os_err('make-dirs', path, err.msg()) }
			return io_null()
		}
		'io-remove' {
			path := io_arg_str(args[0]) or { return none }
			os.rm(path) or { return io_os_err('remove', path, err.msg()) }
			return io_null()
		}
		'io-remove-dir' {
			path := io_arg_str(args[0]) or { return none }
			os.rmdir(path) or { return io_os_err('remove-dir', path, err.msg()) }
			return io_null()
		}
		'io-remove-tree' {
			path := io_arg_str(args[0]) or { return none }
			// §4.6 root guard — resolve, then refuse a filesystem/drive root
			// BEFORE deleting anything.
			resolved := os.real_path(path)
			if io_is_fs_root(resolved) || io_is_fs_root(path) {
				return mk_err('cx-err:CXER3411', 'E_IO_REFUSED_ROOT_DELETE: remove-tree ${path} resolved to ${resolved}')
			}
			os.rmdir_all(path) or { return io_os_err('remove-tree', path, err.msg()) }
			return io_null()
		}
		'io-rename' {
			from := io_arg_str(args[0]) or { return none }
			to := io_arg_str(args[1]) or { return none }
			os.mv(from, to) or { return io_os_err('rename', from, err.msg()) }
			return io_null()
		}
		'io-copy' {
			from := io_arg_str(args[0]) or { return none }
			to := io_arg_str(args[1]) or { return none }
			os.cp(from, to) or { return io_os_err('copy', from, err.msg()) }
			return io_null()
		}
		'io-copy-tree' {
			from := io_arg_str(args[0]) or { return none }
			to := io_arg_str(args[1]) or { return none }
			os.cp_all(from, to, true) or { return io_os_err('copy-tree', from, err.msg()) }
			return io_null()
		}
		'io-symlink' {
			target := io_arg_str(args[0]) or { return none }
			link := io_arg_str(args[1]) or { return none }
			os.symlink(target, link) or { return io_os_err('symlink', link, err.msg()) }
			return io_null()
		}
		'io-readlink' {
			path := io_arg_str(args[0]) or { return none }
			real := os.real_path(path)
			return io_str(real)
		}

		// ── §3.7 globbing ───────────────────────────────────────────
		'io-glob' {
			pattern := io_arg_str(args[0]) or { return none }
			matches := os.glob(pattern) or { return io_os_err('glob', pattern, err.msg()) }
			mut out := []cx.Node{cap: matches.len}
			for m in matches {
				out << io_str(m)
			}
			return io_seq(out)
		}
		'io-glob-iter' {
			pattern := io_arg_str(args[0]) or { return none }
			matches := os.glob(pattern) or { return io_os_err('glob-iter', pattern, err.msg()) }
			mut out := []cx.Node{cap: matches.len}
			for m in matches {
				out << io_str(m)
			}
			return io_seq(out)
		}
		'io-walk' {
			root := io_arg_str(args[0]) or { return none }
			mut out := []cx.Node{}
			io_walk_collect(root, 0, mut out)
			return io_seq(out)
		}

		// ── §3.8 tempfile ───────────────────────────────────────────
		'io-temp-file' {
			prefix := io_arg_str(args[0]) or { return none }
			suffix := io_arg_str(args[1]) or { '' }
			dir := os.temp_dir()
			path := os.join_path(dir, '${prefix}${io_temp_token()}${suffix}')
			return io_open_impl(path, 'w+')
		}
		'io-temp-dir' {
			prefix := io_arg_str(args[0]) or { return none }
			base := os.temp_dir()
			path := os.join_path(base, '${prefix}${io_temp_token()}')
			os.mkdir_all(path) or { return io_os_err('temp-dir', path, err.msg()) }
			return io_str(path)
		}
		'io-system-temp-dir' {
			return io_str(os.temp_dir())
		}

		// ── §3.9 file locking ───────────────────────────────────────
		'io-lock' {
			mut h, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			// Advisory locking is not portably exposed by V's os; behind the
			// granted guard we return the handle (best-effort, §3.9). The
			// deterministic suite never reaches here (cap denied first).
			id := io_handle_of(args[0]) or { return errn }
			return io_handle_element(id, h)
		}
		'io-unlock' {
			_, errn, ok := io_get_open(args[0])
			if !ok {
				return errn
			}
			return io_null()
		}
		else {
			return none
		}
	}
}

// io_walk_collect recursively appends [dir-entry …] elements (§3.7).
fn io_walk_collect(dir string, depth int, mut out []cx.Node) {
	entries := os.ls(dir) or { return }
	for e in entries {
		full := os.join_path(dir, e)
		is_dir := os.is_dir(full)
		out << cx.Element{
			name:  'dir-entry'
			attrs: [
				cx.Attribute{
					name:  'path'
					value: cx.ScalarValue(full)
				},
				cx.Attribute{
					name:  'is-file'
					value: cx.ScalarValue(os.is_file(full))
				},
				cx.Attribute{
					name:  'is-directory'
					value: cx.ScalarValue(is_dir)
				},
				cx.Attribute{
					name:  'depth'
					value: cx.ScalarValue(i64(depth))
				},
			]
		}
		if is_dir {
			io_walk_collect(full, depth + 1, mut out)
		}
	}
}

// io_temp_token returns a process-unique suffix token for temp names,
// drawn from a monotonic counter (uniqueness within the process; the
// granted harness wraps real creation).
__global g_io_temp_counter int

fn io_temp_token() string {
	g_io_temp_counter++
	return '${os.getpid()}-${g_io_temp_counter}'
}

// io_unix_to_iso renders a Unix timestamp as an ISO-8601 UTC string for
// the datetime-typed return of modified-time / created-time (§3.5).
fn io_unix_to_iso(unix_secs i64) string {
	t := vtime.unix(unix_secs).as_utc()
	return '${t.year:04d}-${t.month:02d}-${t.day:02d}T${t.hour:02d}:${t.minute:02d}:${t.second:02d}Z'
}
