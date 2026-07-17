module main

import cx
import code
import os
import testenv

// term_test.v — #30 cx-x/term (Stage 1): the VT/ANSI key decoder (unit-tested
// directly with byte sequences — no tty needed), the real termios + poll-read
// path (exercised over a pseudo-terminal via term_pty_selftest), and the
// capability / non-tty error paths (via the CLI).

fn key_name(ev cx.Node) string {
	if ev is cx.Element {
		for a in ev.attrs {
			if a.name == 'name' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

fn decode_name(bytes string) string {
	ev, _ := code.cx_term_decode(bytes.bytes())
	return key_name(ev)
}

// ── VT/ANSI decoder (pure, no tty) ───────────────────────────────────────────

fn test_decode_arrows() {
	assert decode_name('\x1b[A') == 'up', 'up'
	assert decode_name('\x1b[B') == 'down', 'down'
	assert decode_name('\x1b[C') == 'right', 'right'
	assert decode_name('\x1b[D') == 'left', 'left'
}

fn test_decode_nav_and_fn() {
	assert decode_name('\x1b[H') == 'home', 'home'
	assert decode_name('\x1b[3~') == 'delete', 'delete'
	assert decode_name('\x1b[5~') == 'pageup', 'pageup'
	assert decode_name('\x1b[6~') == 'pagedown', 'pagedown'
	assert decode_name('\x1bOP') == 'f1', 'f1'
	assert decode_name('\x1b[15~') == 'f5', 'f5'
}

fn test_decode_controls() {
	assert decode_name('\r') == 'enter', 'enter (CR)'
	assert decode_name('\n') == 'enter', 'enter (LF)'
	assert decode_name('\t') == 'tab', 'tab'
	assert decode_name('\x7f') == 'backspace', 'backspace'
	assert decode_name('\x1b') == 'escape', 'lone escape'
}

fn test_decode_printable_and_chords() {
	assert decode_name('a') == 'a', 'printable a'
	assert decode_name('Z') == 'Z', 'printable Z'
	// ctrl-a is byte 0x01 → name "a" with the ctrl modifier.
	ev, _ := code.cx_term_decode('\x01'.bytes())
	assert key_name(ev) == 'a', 'ctrl-a name'
	// alt-a is ESC then 'a'.
	assert decode_name('\x1ba') == 'a', 'alt-a name'
}

fn test_decode_consumes_bytes() {
	_, n := code.cx_term_decode('\x1b[A'.bytes())
	assert n == 3, 'arrow consumes 3 bytes, got ${n}'
	_, n2 := code.cx_term_decode('ab'.bytes())
	assert n2 == 1, 'single printable consumes 1 byte, got ${n2}'
}

// ── real termios + poll-read path over a pseudo-terminal ─────────────────────

fn test_pty_roundtrip_real_termios() {
	// term_pty_selftest opens a pty, enters raw on the slave, writes the bytes
	// to the master, reads them back via the poll-gated cx_term_read, decodes.
	assert code.term_pty_selftest('\x1b[A') == 'up', 'pty: arrow up did not round-trip raw read+decode'
	assert code.term_pty_selftest('a') == 'a', 'pty: printable did not round-trip'
	assert code.term_pty_selftest('\r') == 'enter', 'pty: enter did not round-trip'
}

// ── term:select multi-source poll shim (real pipes, headless) ────────────────

fn test_select_first_ready_source() {
	// Two pipes; write to the second → the shim must report index 1 ready.
	assert code.term_select_selftest(1) == 'src1', 'select: did not pick the ready (2nd) source'
	// Write to the first → index 0.
	assert code.term_select_selftest(0) == 'src0', 'select: did not pick the ready (1st) source'
}

fn test_select_timeout_when_idle() {
	// Neither pipe written → the shim times out rather than blocking.
	assert code.term_select_selftest(-1) == 'timeout', 'select: should time out when no source is ready'
}

// ── capability / non-tty error paths (CLI) ───────────────────────────────────

fn cx_bin_tm() string {
	return testenv.cx_bin()
}

fn run_tm(src string, allow bool) os.Result {
	f := os.join_path(os.temp_dir(), 'cx_tm_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	cap := if allow { '--allow-read ' } else { '' }
	return os.execute('${cx_bin_tm()} ${cap}${f}')
}

fn test_is_tty_false_headless() {
	r := run_tm("[?lib 'cx-x/term'] [\$term:is-tty]", false)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.trim_space() == 'false', 'headless is-tty should be false: ${r.output}'
}

fn test_size_cap_denied() {
	r := run_tm("[?lib 'cx-x/term'] [\$term:size]", false)
	assert r.output.contains('CXER0271'), 'no `read` cap → CXER0271: ${r.output}'
}

fn test_size_non_tty_errs() {
	r := run_tm("[?lib 'cx-x/term'] [\$term:size]", true)
	assert r.output.contains('CXER3450'), 'non-tty size → CXER3450: ${r.output}'
}

fn test_raw_mode_cap_denied() {
	r := run_tm("[?lib 'cx-x/term'] [\$term:raw-mode]", false)
	assert r.output.contains('CXER0271'), 'no `read` cap → CXER0271: ${r.output}'
}

fn test_select_cap_denied() {
	r := run_tm("[?lib 'cx-x/term'] [\$term:select {timeout: 10}]", false)
	assert r.output.contains('CXER0271'), 'no `read` cap → CXER0271: ${r.output}'
}

fn test_select_timer_only_returns_timeout() {
	// keys:false, no sources, a short timer → a deterministic `[timeout]`.
	r := run_tm("[?lib 'cx-x/term'] [\$term:select {keys: false timeout: 10}]", true)
	assert r.exit_code == 0, 'errored: ${r.output}'
	assert r.output.contains('timeout'), 'timer-only select should yield [timeout]: ${r.output}'
}
