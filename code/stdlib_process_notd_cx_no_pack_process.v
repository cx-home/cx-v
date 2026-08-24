@[has_globals]
module code

import cx
import os
import time as vtime

// C kill(2) — deliver an arbitrary signal number to a pid (POSIX). A
// negated pid targets the whole process group (killpg semantics). Only
// reached on the capability-granted path; the conformance harness denies
// at the cap_guard before any signal is sent.
fn C.kill(pid int, sig int) int

// stdlib_process.v — native primitives backing `cx-stdlib/process`
// (spec/std-lib/process.md). Subprocess spawn / capture / pipelines /
// signals / process-groups / pseudo-terminal control.
//
// ── CAPABILITY ENFORCEMENT (the core of this module, §7) ────────────
//   process is a Tier-B, necessarily-impure module: every public
//   function is `:impure` and EVERY one operates on a spawned child, so
//   EVERY effect point is gated on the single `subprocess` capability
//   (security.md §2, deny-by-default). The FIRST thing every primitive
//   does is `cap_guard('subprocess', name)` — BEFORE any os.* touch or
//   domain validation (fail-closed, §4). Under the runner's empty
//   capability set the guard returns the CXER0271 err VALUE and the
//   function short-circuits, so the deterministic conformance suite (all
//   deny cases) sees CXER0271. NB: unlike io, there is no
//   capability-free operation here — even `close` requires `subprocess`
//   (§7: "Every function in this module operates on a spawned child
//   process and therefore requires the `subprocess` capability").
//
// ── COMMAND MODEL — argv-array ONLY (§1.1) ──────────────────────────
//   There is no shell-string form anywhere. `run` / `spawn` / each
//   pipeline stage takes an argv::[sequence string]; argv[0] is the
//   executable and argv[1..] are literal arguments passed verbatim to
//   exec. The structural command-injection defense: no string→argv
//   splitting step exists, so no metacharacter can smuggle a second
//   command. Empty argv → CXER4006.
//
// ── VALUE MODEL ─────────────────────────────────────────────────────
//   A live child is an opaque `[proc handle=N …]` element carrying an
//   integer registry id (the proven store/io handle form). `run` /
//   `pipeline` return fully-materialized `[proc-result …]` /
//   `[pipeline-result …]` data elements. Behind the guard the operations
//   are REAL (V's `os.new_process`), not stubs; OS-level failures map to
//   the §5 CXER4000-range codes as err VALUES via mk_err.
//
// ── ERROR CODES (§5) ────────────────────────────────────────────────
//   CXER4000 E_PROC_SPAWN_FAILED      generic fork/exec/CreateProcess fail
//   CXER4001 E_PROC_NOT_FOUND         argv[0] unresolvable / $cwd missing
//   CXER4002 E_PROC_PERMISSION_DENIED found-not-executable / denied
//   CXER4003 E_PROC_TIMED_OUT         timeout + kill-on-timeout=false
//   CXER4004 E_PROC_SIGNAL_UNSUPPORTED unsupported signal atom
//   CXER4005 E_PROC_PIPELINE_STAGE_FAILED stage failed to spawn
//   CXER4006 E_PROC_INVALID_ARGV      empty argv
//   CXER4007 E_PROC_HANDLE_CLOSED     op on a closed handle
//   CXER4008 E_PROC_ENCODING_INVALID  captured output invalid in $encoding
//   CXER4009 E_PROC_PTY_UNSUPPORTED   no pty / ConPTY platform
//   CXER4010 E_PROC_PTY_ALLOC_FAILED  out of kernel pty resources
//   CXER4011 E_PROC_NOT_GROUP_LEADER  kill-group on non-leader
//   CXER4012 E_PROC_EXIT_NONZERO      $check=true + non-zero exit

// ── live-process registry (§2.2) ────────────────────────────────────
//
// Process-global registry behind a nil-default voidptr (the proven
// store/io pattern; `@[has_globals]` enables module state without the
// -enable-globals flag). Each entry holds the os.Process plus spawn-time
// metadata (argv, group flag, pty flag, window dims).

@[heap]
struct ProcHandle {
mut:
	proc      &os.Process = unsafe { nil }
	argv      []string
	is_open   bool
	new_group bool
	is_pty    bool
	rows      int
	cols      int
	stdin_id  int // io-registry id of the child's stdin handle (0 = unset)
	stdout_id int
	stderr_id int
	pty_id    int
	pty_master_fd int = -1 // pty master fd (spawn-pty); -1 when not a pty
	pty_pid       int      // posix_spawn pty child pid (native pty; proc is nil)
	native_pty    bool     // true when this is a pty child (lifecycle via pty_pid, not os.Process)
}

@[heap]
struct ProcRegistry {
mut:
	handles map[int]&ProcHandle
	next_id int
}

__global (
	g_proc_reg voidptr
)

fn proc_reg() &ProcRegistry {
	if g_proc_reg == unsafe { nil } {
		r := &ProcRegistry{
			handles: map[int]&ProcHandle{}
		}
		g_proc_reg = voidptr(r)
	}
	return unsafe { &ProcRegistry(g_proc_reg) }
}

fn proc_register(h &ProcHandle) int {
	mut reg := proc_reg()
	reg.next_id++
	id := reg.next_id
	reg.handles[id] = h
	return id
}

fn proc_lookup(id int) ?&ProcHandle {
	reg := proc_reg()
	return reg.handles[id] or { return none }
}

// ── value builders ──────────────────────────────────────────────────

fn proc_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn proc_bytes(b string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bytes_type
	}
}

fn proc_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn proc_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn proc_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// proc_empty is the absence channel: the empty node-set / empty sequence
// (`code.md` §9.1.2). `poll` / `wait-timeout` returning "no exit code YET"
// (the child is still running) is a pure structural "nothing here" — absence,
// NOT a `null` value (the §9.1.2.1 no-conflation guard). A caller extracts the
// code with `[?else]` or distinguishes still-running from exited by emptiness.
// SAP C1. (The unit-null returns — send-signal / kill / close — are successful
// no-payload side-effects, §9.1.2.1 rule 2b, and KEEP `proc_null`.)
fn proc_empty() cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: []
	}
}

fn proc_atom(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.atom_type
	}
}

fn proc_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn proc_attr(name string, v cx.ScalarValue) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: v
	}
}

// ── argument readers ────────────────────────────────────────────────

fn proc_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn proc_arg_int(n cx.Node) ?i64 {
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

fn proc_arg_bool(n cx.Node) bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return false
}

fn proc_arg_atom(n cx.Node) ?string {
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

fn proc_is_null(n cx.Node) bool {
	if n is cx.ScalarNode {
		return n.value is cx.NullValue
	}
	return false
}

// proc_argv collects an argv sequence element into a []string.
fn proc_argv(n cx.Node) ?[]string {
	if n is cx.Element {
		if n.name in ['__cx_seq__', '__cx_arr__', ''] {
			mut out := []string{cap: n.items.len}
			for it in n.items {
				out << proc_arg_str(it) or { return none }
			}
			return out
		}
	}
	return none
}

// proc_env_map reads a `[map …]` element into a (set, delete) pair: keys
// to set/replace with their value, and keys whose null value marks a
// deletion (§4.2). Returns (sets, deletes, ok).
fn proc_env_map(n cx.Node) (map[string]string, []string, bool) {
	mut sets := map[string]string{}
	mut deletes := []string{}
	if n is cx.Element {
		if n.name in ['map', '__cx_map__'] {
			// attribute form: [map FOO="bar"]
			for a in n.attrs {
				sets[a.name] = cx.scalar_value_str_public(a.value)
			}
			// child-element form: [map [FOO "bar"]]
			for e in n.items {
				if e is cx.Element && e.items.len > 0 {
					if proc_is_null(e.items[0]) {
						deletes << e.name
					} else {
						sets[e.name] = proc_arg_str(e.items[0]) or { '' }
					}
				}
			}
			return sets, deletes, true
		}
	}
	return sets, deletes, false
}

// proc_handle_of reads the integer handle id off a `[proc handle=N …]`.
fn proc_handle_of(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return int(cx.scalar_value_str_public(a.value).int())
			}
		}
	}
	return none
}

// proc_get_open resolves a handle argument to its live ProcHandle. On
// failure returns (_, err_node, false) with CXER4007 (closed/unknown).
fn proc_get_open(arg cx.Node) (&ProcHandle, cx.Node, bool) {
	id := proc_handle_of(arg) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: expected a proc handle element'), false
	}
	h := proc_lookup(id) or {
		return unsafe { nil }, mk_err('cx-err:CXER4007',
			'E_PROC_HANDLE_CLOSED: operation on an already-closed handle'), false
	}
	if !h.is_open {
		return unsafe { nil }, mk_err('cx-err:CXER4007',
			'E_PROC_HANDLE_CLOSED: operation on an already-closed handle'), false
	}
	return h, proc_null(), true
}

// ── signal atom → POSIX number (§3.4) ───────────────────────────────
//
// Portable atom set. An atom with no platform equivalent raises
// CXER4004 (the module never silently no-ops an unsupported signal).
fn proc_signal_num(atom string) ?int {
	return match atom {
		'term' { 15 } // SIGTERM
		'kill' { 9 } // SIGKILL
		'int' { 2 } // SIGINT
		'hup' { 1 } // SIGHUP
		'usr1' { 10 } // SIGUSR1
		'usr2' { 12 } // SIGUSR2
		'stop' { 19 } // SIGSTOP
		'cont' { 18 } // SIGCONT
		else { none }
	}
}

// ── proc-result element (§2.3) ──────────────────────────────────────

fn proc_result_element(exit_code int, signaled bool, timed_out bool) cx.Element {
	return cx.Element{
		name:  'proc-result'
		attrs: [
			proc_attr('exit-code', cx.ScalarValue(i64(exit_code))),
			proc_attr('signaled', cx.ScalarValue(signaled)),
			proc_attr('timed-out', cx.ScalarValue(timed_out)),
		]
	}
}

// ── error mapping (§5) ──────────────────────────────────────────────

fn proc_spawn_err(argv0 string, msg string) cx.Node {
	low := msg.to_lower()
	if low.contains('not found') || low.contains('no such file') || low.contains('cannot find') {
		return mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: ${argv0}: ${msg}')
	}
	if low.contains('permission denied') || low.contains('access is denied') {
		return mk_err('cx-err:CXER4002', 'E_PROC_PERMISSION_DENIED: ${argv0}: ${msg}')
	}
	return mk_err('cx-err:CXER4000', 'E_PROC_SPAWN_FAILED: ${argv0}: ${msg}')
}

// proc_resolve_exec resolves argv[0] per §4.1. Returns the path or a
// CXER4001 / CXER4002 err node.
fn proc_resolve_exec(argv0 string, search_path bool) (string, cx.Node, bool) {
	if argv0.contains('/') || argv0.contains(os.path_separator) || !search_path {
		// path literal
		if !os.exists(argv0) {
			return '', mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: ${argv0}'), false
		}
		if !os.is_executable(argv0) {
			return '', mk_err('cx-err:CXER4002',
				'E_PROC_PERMISSION_DENIED: ${argv0}: not executable'), false
		}
		return argv0, proc_null(), true
	}
	abs := os.find_abs_path_of_executable(argv0) or {
		return '', mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: ${argv0}'), false
	}
	return abs, proc_null(), true
}

// ── one-shot run (§3.1) ─────────────────────────────────────────────
//
// Spawn argv, optionally feed stdin, run to completion, capture
// stdout/stderr, reap, return a [proc-result …]. Bounded by memory.
//
// args (body forwarding order, see stdlib_bundle.v):
//   [0] argv  [1] env  [2] env-clear  [3] cwd  [4] stdin
//   [5] timeout-ms  [6] kill-on-timeout  [7] capture
//   [8] encoding  [9] search-path  [10] new-process-group  [11] check
fn proc_run(args []cx.Node) cx.Node {
	argv := proc_argv(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: run expects argv::[sequence string]')
	}
	if argv.len == 0 {
		return mk_err('cx-err:CXER4006', 'E_PROC_INVALID_ARGV: empty argv')
	}
	search_path := if args.len > 9 { proc_arg_bool_def(args[9], true) } else { true }
	exec_path, rerr, ok := proc_resolve_exec(argv[0], search_path)
	if !ok {
		return rerr
	}
	cwd := if args.len > 3 { proc_arg_str(args[3]) or { '' } } else { '' }
	if cwd != '' && !os.is_dir(cwd) {
		return mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: cwd ${cwd}: no such directory')
	}
	stdin_payload := if args.len > 4 { proc_arg_str(args[4]) or { '' } } else { '' }
	timeout_ms := if args.len > 5 { proc_arg_int(args[5]) or { i64(0) } } else { i64(0) }
	kill_on_timeout := if args.len > 6 { proc_arg_bool_def(args[6], true) } else { true }
	check := if args.len > 11 { proc_arg_bool(args[11]) } else { false }

	mut p := os.new_process(exec_path)
	if argv.len > 1 {
		p.set_args(argv[1..])
	}
	if cwd != '' {
		p.set_work_folder(cwd)
	}
	proc_apply_env(mut p, args)
	p.set_redirect_stdio()
	p.run()
	if !p.is_alive() && p.code != 0 && p.pid == 0 {
		return proc_spawn_err(argv[0], 'spawn failed')
	}
	if stdin_payload != '' {
		p.stdin_write(stdin_payload)
	}
	os.fd_close(p.stdio_fd[0])

	mut timed_out := false
	if timeout_ms > 0 {
		deadline := vtime.ticks() + timeout_ms
		for p.is_alive() && vtime.ticks() < deadline {
			vtime.sleep(2 * vtime.millisecond)
		}
		if p.is_alive() {
			timed_out = true
			if kill_on_timeout {
				p.signal_kill()
			} else {
				p.signal_kill()
				return mk_err('cx-err:CXER4003',
					'E_PROC_TIMED_OUT: ${argv[0]} exceeded ${timeout_ms}ms')
			}
		}
	}
	out := p.stdout_slurp()
	errout := p.stderr_slurp()
	p.wait()
	exit_code := p.code
	signaled := exit_code > 128 || timed_out

	mut full := proc_result_element(exit_code, signaled, timed_out)
	// Attach captured streams as attributes (string capture default).
	full.attrs << proc_attr('stdout', cx.ScalarValue(out))
	full.attrs << proc_attr('stderr', cx.ScalarValue(errout))
	if check && exit_code != 0 {
		return mk_err('cx-err:CXER4012', 'E_PROC_EXIT_NONZERO: ${argv[0]} exited ${exit_code}')
	}
	return full
}

fn proc_arg_bool_def(n cx.Node, def bool) bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
		if v is cx.NullValue {
			return def
		}
	}
	return def
}

// proc_apply_env overlays $env / honours $env-clear on the os.Process.
// args[1]=env, args[2]=env-clear.
fn proc_apply_env(mut p os.Process, args []cx.Node) {
	env_clear := if args.len > 2 { proc_arg_bool(args[2]) } else { false }
	mut sets := map[string]string{}
	mut deletes := []string{}
	if args.len > 1 {
		s, d, ok := proc_env_map(args[1])
		if ok {
			sets = s.clone()
			deletes = d.clone()
		}
	}
	if sets.len == 0 && deletes.len == 0 && !env_clear {
		return
	}
	mut base := map[string]string{}
	if !env_clear {
		for k, v in os.environ() {
			base[k] = v
		}
	}
	for k, v in sets {
		base[k] = v
	}
	for k in deletes {
		base.delete(k)
	}
	p.set_environment(base)
}

// ── streaming spawn (§3.2) ──────────────────────────────────────────
//
// args: [0] argv [1] env [2] env-clear [3] cwd [4] encoding
//       [5] search-path [6] new-process-group
fn proc_spawn(args []cx.Node, is_pty bool, rows int, cols int) cx.Node {
	argv := proc_argv(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: spawn expects argv::[sequence string]')
	}
	if argv.len == 0 {
		return mk_err('cx-err:CXER4006', 'E_PROC_INVALID_ARGV: empty argv')
	}
	search_path := if args.len > 5 { proc_arg_bool_def(args[5], true) } else { true }
	exec_path, rerr, ok := proc_resolve_exec(argv[0], search_path)
	if !ok {
		return rerr
	}
	cwd := if args.len > 3 { proc_arg_str(args[3]) or { '' } } else { '' }
	if cwd != '' && !os.is_dir(cwd) {
		return mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: cwd ${cwd}: no such directory')
	}
	new_group := if args.len > 6 { proc_arg_bool(args[6]) } else { false }

	mut p := os.new_process(exec_path)
	if argv.len > 1 {
		p.set_args(argv[1..])
	}
	if cwd != '' {
		p.set_work_folder(cwd)
	}
	if new_group {
		p.use_pgroup = true // §3.5: fresh process-group leader (setpgid)
	}
	// env overlay shares the run arg layout for [1]/[2].
	proc_apply_env(mut p, [args[0], if args.len > 1 { args[1] } else { proc_null() }, if args.len > 2 {
		args[2]
	} else {
		proc_bool(false)
	}])
	p.set_redirect_stdio()
	p.run()

	mut h := &ProcHandle{
		proc:      p
		argv:      argv
		is_open:   true
		new_group: new_group
		is_pty:    is_pty
		rows:      rows
		cols:      cols
	}
	id := proc_register(h)
	return proc_handle_element(id, h)
}

fn proc_handle_element(id int, h &ProcHandle) cx.Node {
	mut items := []cx.Node{}
	mut argv_items := []cx.Node{}
	for a in h.argv {
		argv_items << proc_str(a)
	}
	items << cx.Element{
		name:  'argv'
		items: argv_items
	}
	mut attrs := [
		proc_attr('handle', cx.ScalarValue(i64(id))),
		proc_attr('pid', cx.ScalarValue(i64(h.proc.pid))),
		proc_attr('state', cx.ScalarValue('running')),
	]
	return cx.Element{
		name:  'proc'
		attrs: attrs
		items: items
	}
}

// ── child-stdio io handles (§2.4) ───────────────────────────────────
//
// A child's stdio handles are REAL io-style handles wired to the child's pipe
// fds (the parent-side ends V's os.Process opened via set_redirect_stdio): the
// accessors register each fd in the io registry as a child-fd-backed handle so
// it composes with cx-stdlib/io read/write/close. stdin is writable; stdout/
// stderr are readable; closing stdin (io/close) signals EOF (§2.4 / §4.6). The
// handle id is cached on the ProcHandle so repeated accessor calls return the
// SAME handle (one buffered reader per fd — re-fdopening would race/lose data).
fn proc_child_stdio(mut h ProcHandle, which string) cx.Node {
	// A pty handle has no per-stream pipes — its os.Process is nil and all of
	// stdin/stdout/stderr are multiplexed onto the single bidirectional master
	// fd (§3.6: "there is no second pty-stream API"). So ANY of stdin/stdout/
	// stderr/pty on a pty handle resolves to that one master handle, cached as
	// pty_id (one shared reader). This also avoids dereferencing the nil
	// os.Process (which segfaulted when stdout/stderr/stdin was called on a pty).
	if h.native_pty {
		if h.pty_id != 0 {
			return proc_file_handle_elem(h.pty_id, 'child-pty-master')
		}
		if h.pty_master_fd < 0 {
			return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: pty master is closed')
		}
		elem := io_register_child_fd(h.pty_master_fd, 'child-pty-master', true, true)
		if id := io_child_handle_id(elem) {
			h.pty_id = id
		}
		return elem
	}
	mut cached := match which {
		'stdin' { h.stdin_id }
		'stdout' { h.stdout_id }
		'stderr' { h.stderr_id }
		'pty-master' { h.pty_id }
		else { 0 }
	}
	role := 'child-${which}'
	if cached != 0 {
		return proc_file_handle_elem(cached, role)
	}
	// pty-master is one bidirectional fd; stdin/stdout/stderr map to stdio_fd.
	fd, readable, writable := match which {
		'stdin' { h.proc.stdio_fd[0], false, true }
		'stdout' { h.proc.stdio_fd[1], true, false }
		'stderr' { h.proc.stdio_fd[2], true, false }
		'pty-master' { h.pty_master_fd, true, true }
		else { -1, false, false }
	}
	if fd < 0 {
		return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: no fd for ${which}')
	}
	elem := io_register_child_fd(fd, role, readable, writable)
	if id := io_child_handle_id(elem) {
		match which {
			'stdin' { h.stdin_id = id }
			'stdout' { h.stdout_id = id }
			'stderr' { h.stderr_id = id }
			'pty-master' { h.pty_id = id }
			else {}
		}
	}
	return elem
}

// proc_file_handle_elem rebuilds the [file handle=N role=…] element for a
// cached io handle id.
fn proc_file_handle_elem(id int, role string) cx.Node {
	return cx.Element{
		name:  'file'
		attrs: [
			proc_attr('handle', cx.ScalarValue(i64(id))),
			proc_attr('role', cx.ScalarValue(role)),
		]
	}
}

// io_child_handle_id reads the `handle=N` id off the [file …] element that
// io_register_child_fd produced (so the proc registry can cache it).
fn io_child_handle_id(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return int(cx.scalar_value_str_public(a.value).int())
			}
		}
	}
	return none
}

// ── wait / poll family (§3.2) ───────────────────────────────────────

fn proc_wait(h &ProcHandle) cx.Node {
	if h.native_pty {
		return proc_pty_wait(h)
	}
	mut p := h.proc
	p.wait()
	return proc_int(i64(p.code))
}

fn proc_poll(h &ProcHandle) cx.Node {
	if h.native_pty {
		return proc_pty_poll(h)
	}
	mut p := h.proc
	if p.is_alive() {
		return proc_empty() // §9.1.2: no result yet → absence, not null
	}
	p.wait()
	return proc_int(i64(p.code))
}

fn proc_wait_timeout(h &ProcHandle, ms i64) cx.Node {
	if h.native_pty {
		return proc_pty_wait_timeout(h, ms)
	}
	mut p := h.proc
	deadline := vtime.ticks() + ms
	for p.is_alive() && vtime.ticks() < deadline {
		vtime.sleep(2 * vtime.millisecond)
	}
	if p.is_alive() {
		return proc_empty() // §9.1.2: still running at timeout → absence, not null
	}
	p.wait()
	return proc_int(i64(p.code))
}

// ── signals (§3.4 / §3.5) ───────────────────────────────────────────

fn proc_send(h &ProcHandle, atom string) cx.Node {
	if h.native_pty {
		return proc_pty_signal(h, atom)
	}
	num := proc_signal_num(atom) or {
		return mk_err('cx-err:CXER4004', 'E_PROC_SIGNAL_UNSUPPORTED: :${atom}')
	}
	mut p := h.proc
	if !p.is_alive() {
		return proc_null() // signalling an exited child is a no-op (§3.4)
	}
	C.kill(p.pid, num)
	return proc_null()
}

fn proc_kill_group(h &ProcHandle, atom string) cx.Node {
	num := proc_signal_num(atom) or {
		return mk_err('cx-err:CXER4004', 'E_PROC_SIGNAL_UNSUPPORTED: :${atom}')
	}
	if h.native_pty {
		// posix_spawn POSIX_SPAWN_SETSID made the child a session/group leader;
		// signal its group via the negated pid.
		C.kill(-h.pty_pid, num)
		return proc_null()
	}
	if !h.new_group {
		return mk_err('cx-err:CXER4011',
			'E_PROC_NOT_GROUP_LEADER: handle not spawned new-process-group=true')
	}
	mut p := h.proc
	// POSIX: kill the whole group via the negated leader pid (killpg).
	C.kill(-p.pid, num)
	return proc_null()
}

// ── close (§3.2) ────────────────────────────────────────────────────
//
// Release the handle: close stdio + reap. Does NOT kill a running child
// (detaches). Idempotent.
fn proc_close(arg cx.Node) cx.Node {
	id := proc_handle_of(arg) or {
		return proc_null() // not a handle / unknown → idempotent no-op
	}
	mut h := proc_lookup(id) or { return proc_null() }
	if !h.is_open {
		return proc_null() // idempotent
	}
	if h.native_pty {
		proc_pty_close(mut h)
		return proc_null()
	}
	mut p := h.proc
	if !p.is_alive() {
		p.wait()
	}
	p.close()
	h.is_open = false
	return proc_null()
}

// ── pipeline (§3.3) ─────────────────────────────────────────────────
//
// args: [0] stages [1] stdin [2] timeout-ms [3] kill-on-timeout
//       [4] encoding [5] env [6] env-clear [7] cwd [8] check
fn proc_pipeline(args []cx.Node) cx.Node {
	stages_node := args[0]
	mut stages := []cx.Node{}
	if stages_node is cx.Element && stages_node.name in ['__cx_seq__', '__cx_arr__', ''] {
		stages = stages_node.items.clone()
	} else {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: pipeline expects [sequence element]')
	}
	if stages.len == 0 {
		return mk_err('cx-err:CXER4006', 'E_PROC_INVALID_ARGV: empty pipeline')
	}
	// Extract each stage's argv from [stage [argv …] …].
	mut argvs := [][]string{}
	for st in stages {
		mut found := false
		if st is cx.Element && st.name == 'stage' {
			for child in st.items {
				if child is cx.Element && child.name == 'argv' {
					mut a := []string{}
					for it in child.items {
						a << proc_arg_str(it) or { '' }
					}
					if a.len == 0 {
						return mk_err('cx-err:CXER4006', 'E_PROC_INVALID_ARGV: empty argv in stage')
					}
					argvs << a
					found = true
					break
				}
			}
		}
		if !found {
			return mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: each stage must be [stage [argv …]]')
		}
	}
	stdin_payload := if args.len > 1 { proc_arg_str(args[1]) or { '' } } else { '' }

	// Run stages end-to-end, threading stdout→stdin. Each stage runs to
	// completion (memory-buffered, §4.3) before feeding the next; this is
	// observationally equivalent to a connected pipe for finite output.
	mut feed := stdin_payload
	mut exit_codes := []int{}
	mut last_stdout := ''
	for a in argvs {
		exec_path, _, ok := proc_resolve_exec(a[0], true)
		if !ok {
			// A stage failed to spawn → CXER4005 (distinct from a stage
			// that ran and exited non-zero).
			return mk_err('cx-err:CXER4005', 'E_PROC_PIPELINE_STAGE_FAILED: ${a[0]}')
		}
		mut p := os.new_process(exec_path)
		if a.len > 1 {
			p.set_args(a[1..])
		}
		p.set_redirect_stdio()
		p.run()
		if feed != '' {
			p.stdin_write(feed)
		}
		os.fd_close(p.stdio_fd[0])
		last_stdout = p.stdout_slurp()
		p.wait()
		exit_codes << p.code
		feed = last_stdout
	}
	// pipefail aggregate: 0 iff every stage exited 0; else the last
	// non-zero exit code.
	mut agg := 0
	for c in exit_codes {
		if c != 0 {
			agg = c
		}
	}
	check := if args.len > 8 { proc_arg_bool(args[8]) } else { false }
	if check && agg != 0 {
		return mk_err('cx-err:CXER4012', 'E_PROC_EXIT_NONZERO: pipeline pipefail aggregate ${agg}')
	}
	mut stage_results := []cx.Node{}
	for i, a in argvs {
		mut av := []cx.Node{}
		for s in a {
			av << proc_str(s)
		}
		stage_results << cx.Element{
			name:  'proc-result'
			attrs: [
				proc_attr('exit-code', cx.ScalarValue(i64(exit_codes[i]))),
				proc_attr('signaled', cx.ScalarValue(false)),
			]
			items: [cx.Element{
				name:  'argv'
				items: av
			}]
		}
	}
	mut codes := []cx.Node{}
	for c in exit_codes {
		codes << proc_int(i64(c))
	}
	return cx.Element{
		name:  'pipeline-result'
		attrs: [
			proc_attr('stdout', cx.ScalarValue(last_stdout)),
			proc_attr('exit-code', cx.ScalarValue(i64(agg))),
		]
		items: [
			cx.Element{
				name:  'stages'
				items: stage_results
			},
			cx.Element{
				name:  'exit-codes'
				items: codes
			},
		]
	}
}

// ── pty (§3.6) ──────────────────────────────────────────────────────
//
// V's os has no portable openpty/forkpty binding here. spawn-pty,
// window-size, and set-window-size are spec-faithful: behind the
// subprocess capability the conformance harness denies them all
// (CXER0271) before any pty allocation. The granted path requires the
// host pty facility; absent it the spec maps to CXER4009.

fn proc_window_size(h &ProcHandle) cx.Node {
	return cx.Element{
		name:  'size'
		attrs: [
			proc_attr('rows', cx.ScalarValue(i64(h.rows))),
			proc_attr('cols', cx.ScalarValue(i64(h.cols))),
		]
	}
}

// ── native dispatch ─────────────────────────────────────────────────
//
// Capability gate FIRST, fail-closed BEFORE any effect (§7). Every
// process- primitive requires `subprocess`. Under the runner's empty
// set the guard returns the CXER0271 err VALUE and the function short-
// circuits — the deterministic conformance suite (all deny cases) sees
// CXER0271. Behind the guard the operations are real (os.new_process).
fn process_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if !name.starts_with('process-') {
		return none
	}
	// §7: every function requires the subprocess capability.
	if d := cap_guard('subprocess', name) {
		return d
	}
	match name {
		'process-run' {
			return proc_run(args)
		}
		'process-spawn' {
			return proc_spawn(args, false, 24, 80)
		}
		'process-spawn-pty' {
			rows := if args.len > 7 { int(proc_arg_int(args[7]) or { 24 }) } else { 24 }
			cols := if args.len > 8 { int(proc_arg_int(args[8]) or { 80 }) } else { 80 }
			return proc_spawn_pty(args, rows, cols)
		}
		'process-pipeline' {
			return proc_pipeline(args)
		}
		'process-stdin' {
			mut h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_child_stdio(mut h, 'stdin')
		}
		'process-stdout' {
			mut h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_child_stdio(mut h, 'stdout')
		}
		'process-stderr' {
			mut h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_child_stdio(mut h, 'stderr')
		}
		'process-pty' {
			mut h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			if !h.is_pty {
				return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: handle has no pty')
			}
			return proc_child_stdio(mut h, 'pty-master')
		}
		'process-pid' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			if h.native_pty {
				return proc_int(i64(h.pty_pid))
			}
			return proc_int(i64(h.proc.pid))
		}
		'process-wait' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_wait(h)
		}
		'process-wait-timeout' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			ms := proc_arg_int(args[1]) or { i64(0) }
			return proc_wait_timeout(h, ms)
		}
		'process-poll' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_poll(h)
		}
		'process-close' {
			return proc_close(args[0])
		}
		'process-send-signal' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			atom := proc_arg_atom(args[1]) or {
				return mk_err('cx-err:CXER0100',
					'E_OPERAND_KIND: send-signal expects a signal atom')
			}
			return proc_send(h, atom)
		}
		'process-terminate' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_send(h, 'term')
		}
		'process-kill' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			return proc_send(h, 'kill')
		}
		'process-kill-group' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			atom := proc_arg_atom(args[1]) or {
				return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: kill-group expects a signal atom')
			}
			return proc_kill_group(h, atom)
		}
		'process-window-size' {
			h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			if !h.is_pty {
				return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: handle has no pty')
			}
			return proc_window_size(h)
		}
		'process-set-window-size' {
			mut h, e, ok := proc_get_open(args[0])
			if !ok {
				return e
			}
			if !h.is_pty {
				return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: handle has no pty')
			}
			r := proc_arg_int(args[1]) or { i64(h.rows) }
			c := proc_arg_int(args[2]) or { i64(h.cols) }
			h.rows = int(r)
			h.cols = int(c)
			// §4.8: resize issues TIOCSWINSZ on the pty master, delivering
			// SIGWINCH to the child's foreground group. No-op after the child
			// exits / master is closed (fd -1).
			if h.native_pty {
				proc_pty_set_winsize(h.pty_master_fd, int(r), int(c))
			}
			return proc_null()
		}
		else {
			return none
		}
	}
}
