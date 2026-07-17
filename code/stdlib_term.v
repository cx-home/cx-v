@[has_globals]
module code

import cx

// stdlib_term.v — native primitives for cx-x/term (issue #30): raw-mode terminal
// input on the program's own tty (fd 0). The termios / winsize / poll-gated read
// machinery lives in the cx_term.h C shim (sibling of cx_pty.h); a VT/ANSI key
// decoder (cx_term_decode, below — pure + pub so it is unit-testable without a
// tty) turns the raw byte stream into `[key …]` / `[resize …]` / `[timeout]`
// event elements. Experimental tier (cx-x/), POSIX only.

#flag linux -lutil
#include "cx_term.c"

fn C.cx_term_is_tty(fd int) int
fn C.cx_term_enter_raw(fd int) voidptr
fn C.cx_term_restore(fd int, saved voidptr) int
fn C.cx_term_get_size(fd int, rows &u16, cols &u16) int
fn C.cx_term_read(fd int, buf &char, n int, timeout_ms int) int
fn C.cx_term_poll_first(fds &int, n int, timeout_ms int) int
fn C.cx_term_pipe(wr &int) int
fn C.cx_term_openpty(slave &int) int
fn C.cx_term_write(fd int, buf &char, n int) int
fn C.cx_term_close(fd int)

// Saved termios pointer for the active raw fd 0 (cooked-mode restores from it).
__global (
	g_term_saved voidptr
)

const term_err_not_tty = 'cx-err:CXER3450' // E_TERM_NOT_A_TTY
const term_err_io = 'cx-err:CXER3451' // E_TERM_IO

// ── value helpers ────────────────────────────────────────────────────────────

fn term_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn term_atom(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.atom_type
	}
}

fn term_int(i int) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i64(i))
		data_type: cx.ScalarType.int_type
	}
}

fn term_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// term_key builds a `[key name=NAME mods=(…)]` event. `mods` is the (possibly
// empty) list of modifier atoms (:ctrl / :alt / :shift).
fn term_key(name string, mods []string) cx.Node {
	mut mod_items := []cx.Node{}
	for m in mods {
		mod_items << term_atom(m)
	}
	return cx.Element{
		name:  'key'
		attrs: [cx.Attribute{ name: 'name', value: cx.ScalarValue(name) }]
		items: [
			cx.Node(cx.Element{
				name:  'mods'
				items: [cx.Node(cx.Element{ name: seq_marker_name, items: mod_items })]
			}),
		]
	}
}

// ── VT/ANSI key decoder (pure, pub for unit tests) ───────────────────────────
//
// cx_term_decode decodes ONE event from the front of `b` and returns
// (event, bytes_consumed). bytes_consumed == 0 means `b` is empty. The decoder
// targets VT/ANSI (xterm-256color) — no terminfo DB — covering printable keys,
// enter/tab/backspace/escape, ctrl-letters, alt-<char>, the arrow / nav cluster,
// and F1–F4. An unrecognised CSI/SS3 sequence decodes to an `[key name="unknown"]`
// consuming the whole recognised prefix so the stream never wedges.
pub fn cx_term_decode(b []u8) (cx.Node, int) {
	if b.len == 0 {
		return term_null(), 0
	}
	c := b[0]
	// ESC-led sequences.
	if c == 0x1b {
		if b.len == 1 {
			return term_key('escape', []), 1
		}
		// CSI: ESC [ …
		if b[1] == `[` {
			return decode_csi(b)
		}
		// SS3: ESC O <P|Q|R|S> → F1–F4
		if b[1] == `O` && b.len >= 3 {
			f := match b[2] {
				`P` { 'f1' }
				`Q` { 'f2' }
				`R` { 'f3' }
				`S` { 'f4' }
				else { '' }
			}
			if f != '' {
				return term_key(f, []), 3
			}
			return term_key('unknown', []), 3
		}
		// ESC <char> → alt-<char>.
		return term_key(rune_str(b[1]), ['alt']), 2
	}
	// Control bytes.
	if c == `\r` || c == `\n` {
		return term_key('enter', []), 1
	}
	if c == `\t` {
		return term_key('tab', []), 1
	}
	if c == 0x7f || c == 0x08 {
		return term_key('backspace', []), 1
	}
	if c >= 0x01 && c <= 0x1a {
		// ctrl-a .. ctrl-z (0x01='a'). Excludes \r(0x0d)/\n/\t handled above.
		letter := u8(`a`) + (c - 1)
		return term_key(rune_str(letter), ['ctrl']), 1
	}
	// Printable (incl. UTF-8 lead bytes — emit the byte run as one key name).
	if c >= 0x20 {
		// consume a single UTF-8 codepoint
		n := utf8_seq_len(c)
		mut end := 1
		if n > 1 && b.len >= n {
			end = n
		}
		return term_key(b[..end].bytestr(), []), end
	}
	// Other control byte → unknown, consume one.
	return term_key('unknown', []), 1
}

fn decode_csi(b []u8) (cx.Node, int) {
	// b[0]=ESC b[1]='['. Final byte after optional digits/;.
	if b.len < 3 {
		return term_key('escape', []), 1
	}
	// Simple single-final arrows / home / end.
	match b[2] {
		`A` { return term_key('up', []), 3 }
		`B` { return term_key('down', []), 3 }
		`C` { return term_key('right', []), 3 }
		`D` { return term_key('left', []), 3 }
		`H` { return term_key('home', []), 3 }
		`F` { return term_key('end', []), 3 }
		`Z` { return term_key('tab', ['shift']), 3 }
		else {}
	}
	// Numeric `ESC [ <digits> ~` nav keys.
	mut i := 2
	mut num := 0
	for i < b.len && b[i] >= `0` && b[i] <= `9` {
		num = num * 10 + int(b[i] - `0`)
		i++
	}
	if i < b.len && b[i] == `~` {
		name := match num {
			1, 7 { 'home' }
			2 { 'insert' }
			3 { 'delete' }
			4, 8 { 'end' }
			5 { 'pageup' }
			6 { 'pagedown' }
			15 { 'f5' }
			17 { 'f6' }
			18 { 'f7' }
			19 { 'f8' }
			20 { 'f9' }
			21 { 'f10' }
			23 { 'f11' }
			24 { 'f12' }
			else { 'unknown' }
		}
		return term_key(name, []), i + 1
	}
	// Unrecognised CSI — consume through the final byte (0x40–0x7e) so we don't wedge.
	mut j := 2
	for j < b.len && !(b[j] >= 0x40 && b[j] <= 0x7e) {
		j++
	}
	consumed := if j < b.len { j + 1 } else { b.len }
	return term_key('unknown', []), consumed
}

fn rune_str(c u8) string {
	return [c].bytestr()
}

fn utf8_seq_len(c u8) int {
	if c < 0x80 {
		return 1
	}
	if c & 0xe0 == 0xc0 {
		return 2
	}
	if c & 0xf0 == 0xe0 {
		return 3
	}
	if c & 0xf8 == 0xf0 {
		return 4
	}
	return 1
}

// ── builtins ─────────────────────────────────────────────────────────────────

fn term_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// All terminal effects read/mutate the program's controlling tty → gate on
	// the `read` capability (consistent with stdin read-line, io.md §7).
	match name {
		'term-is-tty' {
			return cx.ScalarNode{
				value:     cx.ScalarValue(C.cx_term_is_tty(0) == 1)
				data_type: cx.ScalarType.bool_type
			}
		}
		'term-raw-mode' {
			if d := cap_guard('read', 'term raw-mode') {
				return d
			}
			if C.cx_term_is_tty(0) != 1 {
				return mk_err(term_err_not_tty, 'E_TERM_NOT_A_TTY: raw-mode requires a terminal on stdin')
			}
			saved := C.cx_term_enter_raw(0)
			if saved == unsafe { nil } {
				return mk_err(term_err_io, 'E_TERM_IO: tcsetattr failed entering raw mode')
			}
			g_term_saved = saved
			return term_null()
		}
		'term-cooked-mode' {
			if d := cap_guard('read', 'term cooked-mode') {
				return d
			}
			if g_term_saved == unsafe { nil } {
				return term_null() // not in raw mode → nothing to restore
			}
			C.cx_term_restore(0, g_term_saved)
			g_term_saved = unsafe { nil }
			return term_null()
		}
		'term-size' {
			if d := cap_guard('read', 'term size') {
				return d
			}
			mut rows := u16(0)
			mut cols := u16(0)
			if C.cx_term_get_size(0, &rows, &cols) != 0 {
				return mk_err(term_err_not_tty, 'E_TERM_NOT_A_TTY: size requires a terminal on stdin')
			}
			return cx.Element{
				name:  'size'
				attrs: [
					cx.Attribute{ name: 'rows', value: cx.ScalarValue(i64(rows)) },
					cx.Attribute{ name: 'cols', value: cx.ScalarValue(i64(cols)) },
				]
			}
		}
		'term-select' {
			if d := cap_guard('read', 'term select') {
				return d
			}
			// opts map: {keys: bool  sources: (handle …)  timeout: ms}. Wait for
			// the FIRST ready of: a keystroke on stdin (keys:true), or any source
			// handle's fd becoming readable, or the timer. Returns the decoded
			// `[key …]`, `[ready index=N <handle>]` (caller reads the source via
			// its own module — term stays decoupled from each source's framing),
			// or `[timeout]`.
			mut want_keys := false
			mut sources := []cx.Node{}
			mut timeout_ms := -1
			if args.len >= 1 {
				opts := args[0]
				if kv := term_map_get(opts, 'keys') {
					if kv is cx.ScalarNode {
						bv := kv.value
						if bv is bool {
							want_keys = bv
						}
					}
				}
				if tv := term_map_get(opts, 'timeout') {
					if ms := term_duration_ms(tv) {
						timeout_ms = ms
					}
				}
				if sv := term_map_get(opts, 'sources') {
					sources = term_seq_items(sv)
				}
			}
			mut fds := []int{}
			mut src_at := []int{} // -1 = keys/stdin, else index into `sources`
			if want_keys {
				fds << 0
				src_at << -1
			}
			for si, s in sources {
				if fd := term_handle_fd(s) {
					fds << fd
					src_at << si
				}
			}
			if fds.len == 0 {
				// nothing to wait on but the timer.
				C.cx_term_poll_first(unsafe { nil }, 0, timeout_ms)
				return cx.Element{
					name: 'timeout'
				}
			}
			idx := C.cx_term_poll_first(unsafe { &fds[0] }, fds.len, timeout_ms)
			if idx == -2 {
				return mk_err(term_err_io, 'E_TERM_IO: poll failed')
			}
			if idx < 0 {
				return cx.Element{
					name: 'timeout'
				}
			}
			which := src_at[idx]
			if which < 0 {
				// keystroke ready → read (non-blocking) + decode.
				mut buf := [32]char{}
				n := C.cx_term_read(0, &buf[0], 32, 0)
				if n <= 0 {
					return cx.Element{
						name: 'timeout'
					}
				}
				mut bytes := []u8{cap: n}
				for k in 0 .. n {
					bytes << u8(buf[k])
				}
				ev, _ := cx_term_decode(bytes)
				return ev
			}
			return cx.Element{
				name:  'ready'
				attrs: [cx.Attribute{
					name:  'index'
					value: cx.ScalarValue(i64(which))
				}]
				items: [sources[which]]
			}
		}
		'term-read-event' {
			if d := cap_guard('read', 'term read-event') {
				return d
			}
			// optional positional: timeout duration (ms); default -1 (block).
			mut timeout_ms := -1
			if args.len >= 1 {
				if ms := term_duration_ms(args[0]) {
					timeout_ms = ms
				}
			}
			mut buf := [32]char{}
			n := C.cx_term_read(0, &buf[0], 32, timeout_ms)
			if n < 0 {
				return mk_err(term_err_io, 'E_TERM_IO: read failed')
			}
			if n == 0 {
				return cx.Element{ name: 'timeout' }
			}
			mut bytes := []u8{cap: n}
			for k in 0 .. n {
				bytes << u8(buf[k])
			}
			ev, _ := cx_term_decode(bytes)
			return ev
		}
		else {
			return none
		}
	}
}

// term_map_get reads a key's value node from a `{k: v …}` map literal (a
// `__cx_map__` marker element whose entries are child elements named by key,
// eval.v eval_map), or none when absent / not a map.
fn term_map_get(opts cx.Node, key string) ?cx.Node {
	if opts is cx.Element && opts.name == map_marker_name {
		for it in opts.items {
			if it is cx.Element && it.name == key && it.items.len > 0 {
				return it.items[0]
			}
		}
	}
	return none
}

// term_seq_items unwraps a `(…)` sequence (a `__cx_seq__` marker element) to its
// item list; a lone non-sequence value becomes a one-element list.
fn term_seq_items(n cx.Node) []cx.Node {
	if n is cx.Element && n.name == seq_marker_name {
		return n.items
	}
	return [n]
}

// term_handle_fd extracts the `fd=N` attribute from a source handle element
// ([socket fd=N] / [exchange fd=N] / an SSE stream handle), or none.
fn term_handle_fd(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'fd' {
				v := a.value
				if v is i64 {
					return int(v)
				}
				s := cx.scalar_value_str_public(v)
				if s != '' {
					return s.int()
				}
			}
		}
	}
	return none
}

// term_duration_ms extracts a millisecond count from a duration/int arg.
fn term_duration_ms(n cx.Node) ?int {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return int(v)
		}
	}
	return none
}

// ── pty self-test (headless behavioral coverage of the native path) ──────────
//
// Drives the REAL termios + poll-read + decoder path over a pseudo-terminal so
// the tty-dependent native code is testable without a controlling terminal:
// open a pty, enter raw on the slave, write a byte sequence to the master, read
// it back through cx_term_read on the slave, decode it, and report the decoded
// key name. Returns '' on any setup failure.
// term_select_selftest drives the term:select poll shim over two real pipes
// headlessly: create both, optionally write one byte to `write_idx` to make it
// readable, then cx_term_poll_first both. Returns which fd the shim reported
// ready ('src0'/'src1') or 'timeout' (write_idx < 0 writes nothing). Verifies
// the multi-source readiness + first-ready selection that term:select rests on.
pub fn term_select_selftest(write_idx int) string {
	mut w0 := 0
	r0 := C.cx_term_pipe(&w0)
	mut w1 := 0
	r1 := C.cx_term_pipe(&w1)
	if r0 < 0 || r1 < 0 {
		return 'pipe-fail'
	}
	defer {
		C.cx_term_close(r0)
		C.cx_term_close(w0)
		C.cx_term_close(r1)
		C.cx_term_close(w1)
	}
	if write_idx >= 0 {
		wfd := if write_idx == 0 { w0 } else { w1 }
		msg := [u8(`x`)]
		C.cx_term_write(wfd, &char(msg.data), msg.len)
	}
	timeout := if write_idx < 0 { 50 } else { 500 }
	mut fds := [r0, r1]
	idx := C.cx_term_poll_first(unsafe { &fds[0] }, 2, timeout)
	return match idx {
		0 { 'src0' }
		1 { 'src1' }
		-1 { 'timeout' }
		else { 'err' }
	}
}

pub fn term_pty_selftest(inject string) string {
	mut slave := 0
	master := C.cx_term_openpty(&slave)
	if master < 0 {
		return ''
	}
	defer {
		C.cx_term_close(master)
		C.cx_term_close(slave)
	}
	saved := C.cx_term_enter_raw(slave)
	if saved == unsafe { nil } {
		return ''
	}
	ib := inject.bytes()
	C.cx_term_write(master, &char(ib.data), ib.len)
	mut buf := [32]char{}
	n := C.cx_term_read(slave, &buf[0], 32, 500)
	C.cx_term_restore(slave, saved)
	if n <= 0 {
		return ''
	}
	mut bytes := []u8{cap: n}
	for k in 0 .. n {
		bytes << u8(buf[k])
	}
	ev, _ := cx_term_decode(bytes)
	if ev is cx.Element {
		for a in ev.attrs {
			if a.name == 'name' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}
