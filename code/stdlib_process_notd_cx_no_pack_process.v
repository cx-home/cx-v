@[has_globals]
module code

import cx
import os
import strings
import time as vtime

// fcntl(2) F_SETFL/O_NONBLOCK for the #1027 pipeline feed, and errno's
// EAGAIN/EWOULDBLOCK/EPIPE/EINTR for classifying a partial write. `C.fcntl` and
// `C.write` are already declared by `builtin` (cfns.c.v); only the headers
// carrying the constants are needed here.
#include <fcntl.h>
#include <errno.h>

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
//   CXER4013 E_PROC_STREAM_NOT_PIPED  stdio accessor on a non-:pipe stream

// ── per-stream stdio disposition (§3.2 / §4.3) ──────────────────────
//
// `spawn` used to call set_redirect_stdio() unconditionally: all three of the
// child's streams became pipes of ours, and a pipe nobody drains fills and stops
// the child dead. The capacity is small and the boundary is exact — bisected on
// darwin at 65536 bytes: a child writing 65536 bytes to an undrained stderr
// completes, 65537 blocks forever, and the parent blocked in read() on the OTHER
// stream never gets to drain it (#1014, from #1003 / CO-13). So a caller that
// only wants stdout had no way to say so, and there is no timeout anywhere on
// the read path to turn the deadlock into an error.
//
// The fix is to let the caller state each stream's disposition (#972 landed the
// enabling per-stream V API):
//
//   .pipe     a pipe of ours — the only disposition with a stdio handle. Default,
//             so every pre-#1014 caller keeps exactly today's behaviour.
//   .inherit  not redirected at all: the child writes to OUR descriptor.
//   .discard  the null device. Spelled `:discard` and NOT `:null`, because
//             `:null` is a RESERVED atom literal in CX (the parser rejects it in
//             favour of the bare `null` scalar) — measured, not assumed.
//   .file     a path: created/truncated for an output stream, opened for reading
//             for stdin.
enum ProcRedirect {
	pipe
	inherit
	discard
	file
}

fn proc_redirect_name(k ProcRedirect) string {
	return match k {
		.pipe { ':pipe' }
		.inherit { ':inherit' }
		.discard { ':discard' }
		.file { 'a file path' }
	}
}

// proc_stream_opt_name maps a ChildProcessPipeKind index to the option's name,
// for error messages that have to say WHICH stream was misspelled.
fn proc_stream_opt_name(i int) string {
	return match i {
		0 { 'stdin' }
		1 { 'stdout' }
		else { 'stderr' }
	}
}

// proc_redirect_of reads ONE disposition value, from whichever entry point owns
// it: `spawn`'s `$stdin` / `$stdout` / `$stderr`, or a per-stream entry of
// `run`'s `$capture` (#1023 / CO-16). `null` (the parameter default) is `.pipe`,
// so the arity growing does not move any existing behaviour. An atom selects a
// disposition; a string is a file path. Anything else is an operand fault naming
// the stream — never a silent fallback to the default (the #793
// silent-acceptance class).
//
// `who` names the entry point in the message and is the ONLY thing that differs
// between them: CO-16 ruled ONE disposition vocabulary across all entry points,
// so there is one reader for it, and `run` cannot drift from `spawn` on what
// `:discard` spells or which values are accepted (#598 — reuse, never restate).
fn proc_redirect_of(n cx.Node, i int, who string) (ProcRedirect, string, cx.Node, bool) {
	if n is cx.ScalarNode {
		v := n.value
		if v is cx.NullValue {
			return ProcRedirect.pipe, '', proc_null(), true
		}
		if n.data_type == cx.ScalarType.atom_type && v is string {
			match v {
				'pipe' { return ProcRedirect.pipe, '', proc_null(), true }
				'inherit' { return ProcRedirect.inherit, '', proc_null(), true }
				'discard' { return ProcRedirect.discard, '', proc_null(), true }
				else {}
			}
			return ProcRedirect.pipe, '', mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: ${who} expects ${proc_stream_opt_name(i)}=:pipe/:inherit/:discard or a file path, got :${v}'), false
		}
		if v is string {
			if v == '' {
				return ProcRedirect.pipe, '', mk_err('cx-err:CXER0100',
					'E_OPERAND_KIND: ${who} ${proc_stream_opt_name(i)} file path is empty'), false
			}
			return ProcRedirect.file, v, proc_null(), true
		}
	}
	return ProcRedirect.pipe, '', mk_err('cx-err:CXER0100',
		'E_OPERAND_KIND: ${who} expects ${proc_stream_opt_name(i)}=:pipe/:inherit/:discard or a file path'), false
}

// ── `run`'s `$capture`, in the SAME vocabulary (#1023 / RULED: CO-16) ────
//
// Before this, `$capture` was a closed set of four atoms — `:both` / `:stdout` /
// `:stderr` / `:none` — that could say only capture-or-inherit, per stream. §4.3
// said so outright ("`run`'s only per-stream choice is capture-or-inherit … it
// has no file target"), and the consequence was the harm #1023 was filed for:
// a bounded run whose output has to land in a FILE was not expressible, so
// probe.cx had to shell out to `sh -c '… > file'` and lose the `$timeout-ms`
// bound that `run` exists to provide. Meanwhile `spawn` had had the full
// vocabulary since #1014. Two entry points, two vocabularies, one of them a
// strict subset for no stated reason — the orthogonality objective's exact
// complaint, and CO-16 ruled it closed.
//
// `$capture` now accepts, for EACH output stream, the same four dispositions
// §3.2 gives `spawn`, read by the same proc_redirect_of above:
//
//   :pipe     capture it into the [proc-result …] — `run`'s reading of "a pipe
//             held by the parent", since `run` IS the drain. This is what the
//             four legacy atoms have always meant by "captured".
//   :inherit  the child writes to OUR descriptor. What the legacy atoms have
//             always meant by "uncaptured" (§3.1: "Uncaptured streams inherit
//             the parent's").
//   :discard  the null device.
//   a path    a file, created-or-truncated, opened BEFORE the fork so an
//             unopenable path is CXER4001/CXER4002 with no child left behind.
//
// The four shipped atoms are kept, and they are kept as ABBREVIATIONS — not as a
// parallel mechanism. Each is exactly one pair of the above, which is what §3.1
// already said they were:
//
//   :both   ≡ {stdout: :pipe,    stderr: :pipe}      (the default)
//   :stdout ≡ {stdout: :pipe,    stderr: :inherit}
//   :stderr ≡ {stdout: :inherit, stderr: :pipe}
//   :none   ≡ {stdout: :inherit, stderr: :inherit}
//
// so nothing shipped moves, and nothing has to be un-said. `:pipe` and
// `:inherit` are additionally accepted BARE, meaning both output streams — they
// are then synonyms for `:both` and `:none`, which is the price of one
// vocabulary and is cheaper than a caller having to remember which entry point
// wants which word. `:discard` bare is the one genuinely new whole-capture
// value.
//
// A BARE FILE PATH IS REFUSED BY NAME, and that refusal is deliberate — see
// proc_capture_of below.
//
// The map's unnamed keys keep the DEFAULT for their stream, which is `:pipe`:
// `capture={stderr: "/tmp/err.log"}` still captures stdout. That is CO-15's
// per-KEY layering rule (a stage naming only `cwd` still receives the pipeline's
// `$env`) applied to the same shape one section over, not a new rule.
//
// `stdin` is NOT a key here. §3.1 gives `run` a `$stdin` that is a PAYLOAD
// STRING, not a disposition, and §4.3 turns that payload into a non-blocking
// feed the deadline governs. A `stdin` key would be a second, contradictory
// account of the same stream, so it refuses by name and says where the payload
// lives — the refusal-by-name mechanism CO-15 ratified, not a shortfall.
fn proc_capture_of(n cx.Node) ([3]ProcRedirect, [3]string, cx.Node, bool) {
	mut kinds := [ProcRedirect.pipe, ProcRedirect.pipe, ProcRedirect.pipe]!
	mut paths := ['', '', '']!
	if proc_is_null(n) {
		return kinds, paths, proc_null(), true
	}
	if n is cx.ScalarNode {
		v := n.value
		if n.data_type == cx.ScalarType.atom_type && v is string {
			match v {
				// The four shipped abbreviations (§3.1), stated as the pairs they are.
				'both' {
					return kinds, paths, proc_null(), true
				}
				'stdout' {
					kinds[2] = .inherit
					return kinds, paths, proc_null(), true
				}
				'stderr' {
					kinds[1] = .inherit
					return kinds, paths, proc_null(), true
				}
				'none' {
					kinds[1] = .inherit
					kinds[2] = .inherit
					return kinds, paths, proc_null(), true
				}
				// The vocabulary's own atoms, applied to both output streams.
				'pipe' {
					return kinds, paths, proc_null(), true
				}
				'inherit' {
					kinds[1] = .inherit
					kinds[2] = .inherit
					return kinds, paths, proc_null(), true
				}
				'discard' {
					kinds[1] = .discard
					kinds[2] = .discard
					return kinds, paths, proc_null(), true
				}
				else {}
			}
			return kinds, paths, mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: run expects capture=:both/:stdout/:stderr/:none, a disposition (:pipe/:inherit/:discard), or a per-stream map {stdout: …, stderr: …}, got :${v}'),
				false
		}
		// A BARE PATH would have to mean "both output streams into this one file",
		// and that is a MERGE — POSIX's `>f 2>&1`, one shared file offset between
		// two independent writers. §3.2's file disposition is stated PER STREAM
		// ("an output stream creates-or-truncates it"), so applying it to two
		// streams is either two create-or-truncates racing to overwrite each other
		// or a shared-offset semantic this module has never defined. CO-16 ruled
		// the vocabulary, not a merge. So this refuses BY NAME and says where a
		// path IS unambiguous — the per-stream map, which is what #1023's
		// bounded-run-with-file-output actually needs. Refusal-by-name is the
		// forward-compatible shape: a ruled merge can land here later without
		// breaking a caller, whereas guessing one now could not be taken back.
		if v is string {
			return kinds, paths, mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: run capture=${v}: a bare file path would put BOTH output streams in one file, which is a merge this module does not define — name the stream instead, e.g. capture={stdout: "${v}"} (§3.1)'),
				false
		}
	}
	if n is cx.Element {
		if n.name !in ['map', '__cx_map__'] {
			return kinds, paths, mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: run capture is `[${n.name} …]`, not a map — spell a per-stream capture `{stdout: …, stderr: …}` (§3.1)'),
				false
		}
		// A map attribute (`{stdout: :pipe}` parsed to the attribute form) loses the
		// atom-vs-string distinction the vocabulary is built on, so the entry form
		// is the one read here and the attribute form refuses rather than guessing.
		for a in n.attrs {
			return kinds, paths, mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: run capture key `${a.name}` carries no readable disposition — spell it `{${a.name}: :pipe}` / `{${a.name}: "/path"}` (§3.1)'),
				false
		}
		mut seen := []string{}
		for e in n.items {
			if e !is cx.Element {
				return kinds, paths, mk_err('cx-err:CXER0100',
					'E_OPERAND_KIND: run capture map has a non-entry item — spell it `{stdout: …, stderr: …}` (§3.1)'),
					false
			}
			if e is cx.Element {
				idx := match e.name {
					'stdout' { 1 }
					'stderr' { 2 }
					// Named by the caller, refused by name: `run`'s stdin is a payload.
					'stdin' { -2 }
					else { -1 }
				}
				if idx == -2 {
					return kinds, paths, mk_err('cx-err:CXER0100',
						'E_OPERAND_KIND: run capture has no `stdin` key — `run`\'s stdin is the `\$stdin` PAYLOAD (§3.1), fed non-blockingly under `\$timeout-ms` (§4.3); a stdin DISPOSITION is `spawn`\'s (§3.2)'),
						false
				}
				if idx == -1 {
					return kinds, paths, mk_err('cx-err:CXER0100',
						'E_OPERAND_KIND: run capture has no `${e.name}` key — the per-stream keys are `stdout` and `stderr` (§3.1)'),
						false
				}
				if e.name in seen {
					return kinds, paths, mk_err('cx-err:CXER0100',
						'E_OPERAND_KIND: run capture names `${e.name}` twice (§3.1)'), false
				}
				seen << e.name
				if e.items.len != 1 {
					return kinds, paths, mk_err('cx-err:CXER0100',
						'E_OPERAND_KIND: run capture key `${e.name}` needs exactly one disposition — :pipe/:inherit/:discard or a file path (§3.1)'),
						false
				}
				k, path, oerr, ok := proc_redirect_of(e.items[0], idx, 'run capture')
				if !ok {
					return kinds, paths, oerr, false
				}
				kinds[idx] = k
				paths[idx] = path
			}
		}
		return kinds, paths, proc_null(), true
	}
	return kinds, paths, mk_err('cx-err:CXER0100',
		'E_OPERAND_KIND: run expects capture=:both/:stdout/:stderr/:none, a disposition (:pipe/:inherit/:discard), or a per-stream map {stdout: …, stderr: …}'),
		false
}

// ProcStdioStaged records the parent descriptors that were temporarily replaced
// so the forked child would inherit a file / the null device.
//
// WHY the parent's own fd: the fork's per-stream control (#972) is pipe-or-
// inherit. "Inherit" means the child keeps the descriptor the PARENT holds at
// fork time, and that is the only injection point available without changing the
// fork again — so for `.discard` and `.file` we open the target, dup2 it onto
// our fd N across `p.run()`, and put ours back immediately after. `p.run()`
// forks and execs synchronously (os.Process._spawn), so the window is the fork
// itself, not the child's lifetime. Stdout/stderr are flushed first, so no
// buffered parent output lands in the child's file.
struct ProcStdioStaged {
mut:
	saved   [3]int = [-1, -1, -1]!
	touched [3]bool
}

// proc_stdio_stage installs the `.discard` / `.file` dispositions on the
// parent's descriptors. On any failure it unwinds what it already staged and
// returns the err node, so a half-redirected parent can never escape.
fn proc_stdio_stage(kinds [3]ProcRedirect, paths [3]string) (ProcStdioStaged, cx.Node, bool) {
	mut st := ProcStdioStaged{}
	for i in 0 .. 3 {
		k := kinds[i]
		if k == .pipe || k == .inherit {
			continue
		}
		$if windows {
			proc_stdio_unstage(mut st)
			return st, mk_err('cx-err:CXER4000',
				'E_PROC_SPAWN_FAILED: spawn ${proc_stream_opt_name(i)}=${proc_redirect_name(k)} needs POSIX descriptor staging; on Windows the CRT fd does not move GetStdHandle, so it is not backed here (process.md §4.9)'),
				false
		} $else {
			target := if k == .discard { '/dev/null' } else { paths[i] }
			mode := if i == 0 { 'r' } else { 'w' }
			f := os.open_file(target, mode) or {
				proc_stdio_unstage(mut st)
				return st, proc_stdio_open_err(i, target, err.msg()), false
			}
			// Our own buffered output must not end up in the child's file.
			flush_stdout()
			flush_stderr()
			st.saved[i] = os.fd_dup(i)
			if os.fd_dup2(f.fd, i) == -1 {
				os.fd_close(f.fd)
				if st.saved[i] >= 0 {
					os.fd_close(st.saved[i])
					st.saved[i] = -1
				}
				proc_stdio_unstage(mut st)
				return st, mk_err('cx-err:CXER4000',
					'E_PROC_SPAWN_FAILED: cannot redirect ${proc_stream_opt_name(i)} to ${target}'),
					false
			}
			st.touched[i] = true
			// fd i now names the file; our own copy is redundant.
			os.fd_close(f.fd)
		}
	}
	return st, proc_null(), true
}

// proc_stdio_open_err maps a failed redirect-target open onto the §5 codes,
// distinguishing "no such path" from "denied" the way argv[0] resolution does.
fn proc_stdio_open_err(i int, target string, msg string) cx.Node {
	low := msg.to_lower()
	if low.contains('permission') || low.contains('denied') {
		return mk_err('cx-err:CXER4002',
			'E_PROC_PERMISSION_DENIED: ${proc_stream_opt_name(i)} redirect ${target}: ${msg}')
	}
	return mk_err('cx-err:CXER4001',
		'E_PROC_NOT_FOUND: ${proc_stream_opt_name(i)} redirect ${target}: ${msg}')
}

// proc_stdio_unstage puts the parent's own descriptors back. A parent that had
// nothing on fd N (a detached process) is left with nothing there again rather
// than silently keeping the child's file open.
fn proc_stdio_unstage(mut st ProcStdioStaged) {
	for i in 0 .. 3 {
		if !st.touched[i] {
			continue
		}
		if st.saved[i] >= 0 {
			os.fd_dup2(st.saved[i], i)
			os.fd_close(st.saved[i])
			st.saved[i] = -1
		} else {
			os.fd_close(i)
		}
		st.touched[i] = false
	}
}

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
	// §3.2 per-stream stdio disposition, indexed by ChildProcessPipeKind. Only
	// a `.pipe` stream has a parent-side fd, so the stdio accessors consult this
	// to refuse a non-piped stream BY NAME (CXER4013) rather than handing back a
	// handle over the -1 that stdio_fd carries for an unredirected stream.
	stdio_kind [3]ProcRedirect = [ProcRedirect.pipe, ProcRedirect.pipe, ProcRedirect.pipe]!
	stdio_path [3]string
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
	note_operand_fault('process', 'process-', 'string', n)
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
	note_operand_fault('process', 'process-', 'int', n)
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
	note_operand_fault('process', 'process-', 'atom', n)
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

// proc_exe_suffixes mirrors `os.executable_suffixes` — a PRIVATE const of vlib,
// so the one name in that module this file cannot reach. Windows resolves a
// separator-free argv[0] through PATHEXT (§5's platform table: "PATH + PATHEXT,
// `;` separator"); POSIX has the bare name and nothing else. Kept byte-identical
// to os_windows.c.v / os_nix.c.v so a child-PATH search and a parent-PATH search
// (os.find_abs_path_of_executable, which reads that same const) agree on what
// counts as a hit.
fn proc_exe_suffixes() []string {
	mut suffixes := ['']
	$if windows {
		suffixes = ['.exe', '.bat', '.cmd', '']
	}
	return suffixes
}

// proc_find_in_path is os.find_abs_path_of_executable's search against an
// EXPLICIT path string rather than the parent's `PATH` env var. vlib has exactly
// this (find_abs_path_of_executable_in_path_env) and does not export it, so the
// separator-free half of it lives here — the abs-path and contains-a-separator
// branches are already handled by proc_resolve_exec's path-literal arm above,
// which is the only caller.
//
// An EMPTY path string is not "search nowhere and fall back"; it is "the child's
// PATH names no directory", so nothing is findable and the caller raises
// CXER4001. That is the honest answer for `env-clear=true` + `[env {PATH: null}]`
// and for `env={"PATH" ""}` alike.
fn proc_find_in_path(argv0 string, path_value string) ?string {
	if path_value == '' {
		return none
	}
	dirs := path_value.split(os.path_delimiter)
	for suffix in proc_exe_suffixes() {
		name := argv0 + suffix
		for dir in dirs {
			if dir == '' {
				continue
			}
			cand := os.join_path_single(dir, name)
			if os.is_file(cand) && os.is_executable(cand) {
				return os.abs_path(cand)
			}
		}
	}
	return none
}

// proc_resolve_exec resolves argv[0] per §4.1. Returns the path or a
// CXER4001 / CXER4002 err node.
//
// §4.1 has TWO gates and they are ordered, not weighed against each other:
//
//  1. `$search-path=false` — or an argv[0] carrying a separator — makes argv[0] a
//     PATH LITERAL. §4.1: "With `$search-path=false`, `argv[0]` is always a path
//     literal." No `PATH` of any provenance is consulted, so an explicit
//     `search-path=false` beats a child `PATH` by making the search not happen.
//  2. Otherwise the name is resolved against `PATH` — and §4.1 says WHOSE:
//     "(the child's when `$env` overrides it, else the parent's)". The pronoun is
//     `PATH`. So the child's PATH governs exactly when an `$env` layer NAMES the
//     key (`ProcChildEnv.path_named`), and the parent's governs otherwise —
//     including under a bare `env-clear=true` that never mentions `PATH`, which
//     is what the granted hermetic fixtures (process-050 / -051 / -067) have
//     always relied on to find `env` for a child that will have no `PATH`. That
//     is coherent, not a contradiction: resolution yields an ABSOLUTE path and
//     the child execs THAT, so a hermetic child never needs a `PATH` to start.
//     §4.1 is describing where the PARENT's resolver looks.
//
// Before #1052 this function took no environment at all and always called
// os.find_abs_path_of_executable, i.e. always the PARENT's PATH — clause 2's
// first half was unimplemented and no fixture named the cell.
fn proc_resolve_exec(argv0 string, search_path bool, env ProcChildEnv) (string, cx.Node, bool) {
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
	if env.path_named {
		abs := proc_find_in_path(argv0, env.vars['PATH']) or {
			return '', mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: ${argv0}'), false
		}
		return abs, proc_null(), true
	}
	abs := os.find_abs_path_of_executable(argv0) or {
		return '', mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: ${argv0}'), false
	}
	return abs, proc_null(), true
}

// Bounds on the post-timeout tail read (see proc_run). The quiet period only
// has to cover kernel delivery of bytes already written, so it is short; the
// cap is the absolute ceiling a killed child's leftovers may add to a run.
const proc_run_tail_quiet_ms = i64(150)
const proc_run_tail_cap_ms = i64(1000)

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
	// §4.1 resolves a separator-free argv[0] against the CHILD's PATH when `$env`
	// names it, so the child environment is composed HERE — before resolution —
	// and the SAME value is what the spawn below installs. One composition, two
	// readers (#1052).
	child_env := proc_child_env_args(args)
	exec_path, rerr, ok := proc_resolve_exec(argv[0], search_path, child_env)
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

	// §3.1's `$encoding`, §4.7's semantics. Forwarded by stdlib/process.cx since
	// the module existed and read by NOTHING on this path (#1035): `run` accepted
	// `encoding="latin-1"` silently, and `encoding=:bytes` returned a decoded
	// `string`. #1028 fixed the same inertness for `pipeline` and left the entry
	// point most callers actually reach for still inert — which is the shape of a
	// per-entry-point fix, and the reason this one covers `spawn` in the same
	// commit. Read BEFORE anything is spawned: a misspelled encoding must not
	// leave a child behind, the same fail-closed discipline §3.2's dispositions
	// carry.
	want_bytes, enc_err, enc_ok := proc_encoding_mode(if args.len > 8 {
		args[8]
	} else {
		proc_null()
	}, 'run')
	if !enc_ok {
		return enc_err
	}

	// §3.1 `$capture` — ":both / :stdout / :stderr / :none. Uncaptured streams
	// inherit the parent's." Read from args[7] (layout pinned by the forwarding
	// site, stdlib/process.cx:23). Before #956 this was never read: `run`
	// redirected and slurped unconditionally, so every value was inert.
	// All four values are honored per stream (#972). Under #956 the two
	// single-stream values REFUSED by name: "capture one stream, let the other
	// inherit the parent's" needs per-stream stdio control, and V's os.Process
	// then carried a single all-or-nothing `use_stdio_ctl` with both backends
	// piping all three descriptors together. The fork now has
	// `p.set_redirect_pipe(pkind)` alongside `p.set_redirect_stdio()`, so a
	// stream is piped ONLY when this call is capturing it; every other stream is
	// left alone and the child inherits the parent's descriptor for it — which
	// is what §3.1's "Uncaptured streams inherit the parent's" says, and is now
	// observable rather than declared. The spec was deliberately never amended
	// to the old shortfall, so nothing here has to be un-said.
	//
	// #1023 / CO-16 widened the value set from those four atoms to `spawn`'s FULL
	// disposition vocabulary, per stream — see proc_capture_of above for the
	// vocabulary, the abbreviation table the four atoms became, and the one cell
	// (a bare file path) that refuses by name. Read BEFORE anything is spawned:
	// a misspelled disposition must not leave a child behind, the same
	// fail-closed discipline §3.2's dispositions and `$encoding` carry.
	mut kinds, mut paths, cap_err_node, cap_ok := proc_capture_of(if args.len > 7 {
		args[7]
	} else {
		proc_null()
	})
	if !cap_ok {
		return cap_err_node
	}
	// "Captured" is now exactly "`.pipe`", because `run` IS the drain for a pipe
	// it holds. Every other disposition means the bytes were never ours: they
	// went to our own descriptor, the null device, or a file. Each of the three
	// reads below keyed off these two booleans already — the tail drain, §4.7's
	// decode, and the result attributes — and each stays correct unchanged,
	// which is the point of expressing the new vocabulary in the old two flags
	// rather than threading a third state through them.
	cap_out := kinds[1] == .pipe
	cap_err := kinds[2] == .pipe
	// `$stdin` is an independent decision from `$capture`: it needs the stdin
	// pipe and nothing else, so `capture=:none` with a payload is now an
	// ordinary combination (stdin piped, both output streams inherited) rather
	// than the refusal the all-or-nothing flag forced.
	feed_stdin := stdin_payload != ''
	// §3.5: fresh process-group leader, so §4.5's escalation can target the
	// whole group. args[10] is the same value the spawn path already reads.
	new_group := if args.len > 10 { proc_arg_bool(args[10]) } else { false }

	mut p := os.new_process(exec_path)
	if argv.len > 1 {
		p.set_args(argv[1..])
	}
	if cwd != '' {
		p.set_work_folder(cwd)
	}
	if new_group {
		p.use_pgroup = true
	}
	proc_child_env_apply(mut p, child_env)
	// `run`'s stdin is the `$stdin` PAYLOAD, never a disposition (§3.1 / §4.3):
	// a pipe when there is something to feed, otherwise our own descriptor. It is
	// recorded in `kinds[0]` only so the shared staging helper below sees all
	// three streams — neither `.pipe` nor `.inherit` is ever staged, so this
	// index is a no-op there by construction.
	kinds[0] = if feed_stdin { ProcRedirect.pipe } else { ProcRedirect.inherit }
	if feed_stdin {
		p.set_redirect_pipe(.stdin)
	}
	if cap_out {
		p.set_redirect_pipe(.stdout)
	}
	if cap_err {
		p.set_redirect_pipe(.stderr)
	}
	// `.discard` / `.file` ride the parent-descriptor staging the fork inherits —
	// `spawn`'s helper, called the same way from here (#598: one implementation
	// behind one vocabulary). An unopenable target is CXER4001/CXER4002 raised
	// HERE, before `p.run()`, so a bad path leaves no child behind; and the
	// parent's own descriptors are put back the instant the fork returns, so the
	// window is the fork itself and not the child's lifetime.
	mut staged, stage_err, stage_ok := proc_stdio_stage(kinds, paths)
	if !stage_ok {
		return stage_err
	}
	p.run()
	proc_stdio_unstage(mut staged)
	if !p.is_alive() && p.code != 0 && p.pid == 0 {
		// No child to reap — the spawn itself failed and `pid` is 0, and
		// `waitpid(0, …)` means "any child in OUR process group", never this one.
		// The pipes, however, were created before the fork, so their parent ends
		// are still ours to close (#1034).
		proc_fd_release_all(mut p)
		return proc_spawn_err(argv[0], 'spawn failed')
	}
	// ── the FEED is ARMED here and DELIVERED in the loop (#1030) ─────────
	//
	// This was one BLOCKING `p.stdin_write(stdin_payload)` of the whole payload,
	// issued BEFORE the drain loop below — the same shape, in the same file, that
	// #1027 fixed for `pipeline`'s inter-stage feed, and carrying both of the same
	// defects (measured; the numbers are on the shared helpers above).
	//
	//  (1) THE DEADLOCK THE BUDGET CANNOT SEE. `[$run ('cat') stdin=<200 KB>]`:
	//      we block in write() once the child's stdin pipe fills, the child blocks
	//      in write() once its own CAPTURED stdout pipe fills, and neither moves —
	//      and because the block is inside our own write() rather than in the wait
	//      loop, `$timeout-ms` structurally could not fire on it. #1002 narrowed
	//      the budget's job to "bound a child that will not FINISH" and made the
	//      reads honest; this was the write side of the same obligation, still
	//      outstanding.
	//  (2) THE SILENT DEATH. A child is entitled to stop reading — `head -c 10`
	//      takes ten bytes and exits — and the next write then lands on a pipe with
	//      no reader, raising SIGPIPE, whose DEFAULT ACTION TERMINATES THE PROCESS
	//      SILENTLY. `cx` only takes SIGPIPE off its default in the picoev serve
	//      plane, which a script run never enters, so `[$run ('head' '-c' '10')
	//      stdin=<200 KB>]` killed the interpreter: no result, no error, nothing.
	//
	// The fix is #1027's, reused rather than restated (proc_nb_arm /
	// proc_feed_pass / proc_feed_arm above): arm the child's stdin O_NONBLOCK, move
	// the delivery INSIDE the loop the deadline already governs, and take SIGPIPE
	// off its default for this call's duration so EPIPE becomes a value the loop
	// can act on. The two cheaper shapes stay rejected for the reasons recorded on
	// those helpers — chunked BLOCKING writes only make the deadlock rarer, and
	// staging through a temp file is what §4.6 offers a CALLER who asks for it, not
	// something to impose on every payload.
	//
	// NOTE ON §3.2's DISPOSITIONS: #1023 / CO-16 gave `run`'s `$capture` the whole
	// vocabulary for its OUTPUT streams, so "they are spawn's, not run's" is no
	// longer true of stdout/stderr. It remains true of STDIN, and for a reason
	// that is not a shortfall: §3.1 gives `run` a single `$stdin` that is a
	// PAYLOAD STRING, so there is no `stdin=<path>` disposition on this path to
	// bypass the feed — the payload path is the only path here, and it is the
	// only thing the #1030 feed touches. A caller who wants a file on stdin
	// without a caller-side write already has `spawn` (§4.6), and that route is
	// untouched; `$capture` refuses a `stdin` key by name and says so.
	//
	// The SIGPIPE swap is armed only when there IS a payload: a `run` with nothing
	// to feed writes to no pipe and has no business rearranging the process's
	// signal state. It is restored on EVERY exit path — a `defer`, because there
	// are four returns below this point.
	mut feed_off := 0
	mut stdin_open := false
	mut sigpipe_prev := os.SignalHandler(proc_sigpipe_absorb)
	mut sigpipe_armed := false
	if feed_stdin {
		sigpipe_prev, sigpipe_armed = proc_feed_arm()
	}
	defer {
		if sigpipe_armed {
			os.signal_opt(.pipe, sigpipe_prev) or {}
		}
	}
	if feed_stdin {
		if !proc_nb_arm(p.stdio_fd[0]) {
			// Not reachable on a pipe fd we created a few statements ago — but the
			// fallback to a blocking write is the very deadlock being fixed, so this
			// refuses BY NAME instead of quietly reinstating it. The child is already
			// running; kill it rather than leak it.
			proc_run_escalate(mut p, new_group)
			proc_reap_release(mut p)
			return mk_err('cx-err:CXER4000',
				'E_PROC_SPAWN_FAILED: ${argv[0]} stdin could not be set non-blocking')
		}
		stdin_open = true
	}

	// ── the capture pipes are DRAINED WHILE THE CHILD RUNS (#1002) ───────
	//
	// This loop used to be `for p.is_alive() && ticks < deadline { sleep }`
	// with both slurps AFTERWARDS, and that made the budget a lie: a child
	// whose output exceeds what the pipe can hold BLOCKS in write(), stays
	// alive because nobody is reading, and burns the whole budget. The call
	// then reported `timed-out=true` — naming the fixture, not the harness —
	// and handed back a stdout TRUNCATED at the pipe capacity as though it
	// were the child's whole answer. Two non-facts from one missing read.
	//
	// Measured on this platform (2026-08-26): a child writing 262,144 bytes
	// under a 3,000 ms budget reported timed-out=true with got=65536 — the
	// pipe capacity, exactly. That is the ceiling when the machine is idle;
	// under pipe-memory pressure XNU hands out 512-byte buffers instead
	// (#993 measured that figure on this same platform), which is why #1002's
	// five `full-code-cfg-*` diagram fixtures went red together and only
	// together: their renders are 802–889 bytes and the sixth-largest in the
	// corpus is 451. Every one of the 52 renders in 0.08 s. Not one was ever
	// slow; five were over 512 bytes.
	//
	// So the budget's job is narrowed back to what a budget can honestly do —
	// bound a child that will not FINISH — and it can no longer be consumed
	// by this function's own refusal to read. Note what that means for the
	// three obvious "fixes" this defect invites: a CPU-time budget would
	// never fire at all (a child blocked in write() accrues no CPU, so the
	// deadlock becomes permanent), and neither retrying nor scaling the
	// budget helps, because a deadlock is perfectly reproducible and no
	// budget is long enough for one. Draining is the only fix.
	//
	// Both streams are drained on EVERY iteration, and this is load-bearing
	// rather than tidiness: draining stdout to EOF first and stderr after —
	// which is what the old code did whenever there was no budget at all —
	// deadlocks the moment a child fills stderr while stdout is still open.
	// Same bug, no timeout involved, and it would have outlived a fix aimed
	// only at the budget path.
	//
	// stdout_read/stderr_read are the fork's non-blocking reads (they answer
	// '' when nothing is pending), so this stays on ONE thread. Deliberately:
	// a reader thread per stream is the textbook shape here and it is not
	// available to us — under `-gc e` a thread blocked in a read() syscall
	// deadlocks vgc's stop-the-world against any allocating thread (#973).
	mut timed_out := false
	mut out_buf := strings.new_builder(4096)
	mut err_buf := strings.new_builder(1024)
	// `feed_stdin` joins the guard (#1030): the loop is now where the payload is
	// DELIVERED, not just where output is drained, so a `run` with a payload needs
	// it even when nothing is captured and no budget is set. On that combination
	// (`capture=:none`, no `$timeout-ms`) the loop feeds, closes stdin, and then
	// polls `is_alive()` until the child exits — where the pre-#1030 code blocked in
	// `p.wait()` below. Same observable result, and the loop's exit invariant is
	// left alone deliberately: it still ends ONLY on child-exit or deadline, which
	// is what lets the `p.is_alive()` test after it mean "the budget expired" and
	// nothing else. An early break for this case would make that test lie and kill
	// a healthy child.
	if cap_out || cap_err || timeout_ms > 0 || feed_stdin {
		deadline := vtime.ticks() + timeout_ms
		for {
			// Drain BEFORE the liveness test, every pass: a child that has
			// already exited can still have bytes sitting in the pipe, and
			// testing first would leave the last chunk to the final slurp.
			mut moved := false
			// ── FEED first, then drain (#1030, the shape #1027 settled) ─────────
			//
			// The write goes first because it is what unblocks the child: a child
			// waiting on input produces nothing to read, so a pass that read before
			// it wrote would find both streams empty, conclude the child was idle,
			// and sleep. Order within a pass costs nothing and reads as the
			// dependency it is.
			//
			// This is the whole of the fix: the write now lives INSIDE the loop the
			// deadline governs, so a child that never reads is bounded by
			// `$timeout-ms` exactly like a child that never exits, and a child that
			// reads while we write takes turns with us instead of deadlocking
			// against us.
			if stdin_open {
				n, step := proc_feed_pass(p.stdio_fd[0], stdin_payload, feed_off)
				if n > feed_off {
					feed_off = n
					moved = true
				}
				if step != .more {
					// End of payload, or the reader is gone. Either way the child is
					// owed its EOF and this fd has no further use (§4.6) — without the
					// close a reader like `cat` waits for more input and the budget is
					// the only thing that ends the run.
					//
					// `.gone` gets no field on the result, deliberately, and this is
					// the same judgement §4.3 records for a pipeline stage: a child
					// that stopped reading has already SAID what it thinks of the
					// input, in its exit status. `head -c 10` exits 0 and the run
					// succeeded; a child that died mid-feed exits non-zero and
					// `exit-code` (and `$check`) carry that. A `stdin-truncated`
					// attribute would be a second, weaker account of the same fact —
					// and for `head` a misleading one.
					proc_fd_release(mut p, 0)
					stdin_open = false
				}
			}
			if cap_out {
				chunk := p.stdout_read()
				if chunk.len > 0 {
					out_buf.write_string(chunk)
					moved = true
				}
			}
			if cap_err {
				chunk := p.stderr_read()
				if chunk.len > 0 {
					err_buf.write_string(chunk)
					moved = true
				}
			}
			if !p.is_alive() {
				break
			}
			if timeout_ms > 0 && vtime.ticks() >= deadline {
				break
			}
			// Only idle when the child gave us nothing; while it is producing,
			// spinning through the reads is what keeps the pipe from filling.
			if !moved {
				vtime.sleep(2 * vtime.millisecond)
			}
		}
		// The liveness verdict is SAMPLED before the feed's EOF is sent, and the
		// order is load-bearing (#1030, the same discipline #1027 records for a
		// stage): closing stdin first could let a child that was blocked on input
		// exit cleanly in the microsecond before `is_alive()` runs, and the call
		// would then report no timeout for a budget that demonstrably expired.
		alive_at_deadline := p.is_alive()
		// The EOF the child is owed on the paths that left the feed open: the budget
		// expired mid-feed, or the child exited before we finished talking. One
		// close, covering both the ordinary return and the `$kill-on-timeout=false`
		// error return below — the fd is this function's to close on every path.
		if stdin_open {
			proc_fd_release(mut p, 0)
			stdin_open = false
		}
		if alive_at_deadline {
			timed_out = true
			// §4.5: "SIGTERM, then a short fixed grace, then SIGKILL. For
			// $new-process-group=true, the escalation targets the whole group."
			// The old code sent SIGKILL to the direct pid only — which is why a
			// budget was unenforceable: a surviving GRANDCHILD kept the captured
			// pipe open and the slurp below blocked on it (measured: a 60,000 ms
			// budget ran 5m07s, sampled at 9m40s).
			proc_run_escalate(mut p, new_group)
			if !kill_on_timeout {
				// §3.1's "`run` reaps the child before returning" and §4.4's "`run`
				// and `pipeline` reap before returning" are UNQUALIFIED: they are
				// obligations of the CALL, not of its success path, and this refusal
				// is still a return from `run`. Before #1034 this line returned past
				// both of them — the captured pipes stayed open in the parent and a
				// child that had survived SIGTERM long enough to need §4.5's SIGKILL
				// was never waited on. A bounded probe taking this branch in a loop
				// therefore leaked two descriptors and one zombie per iteration until
				// the interpreter exited, which is the shape a probe loop has.
				proc_reap_release(mut p)
				return mk_err('cx-err:CXER4003',
					'E_PROC_TIMED_OUT: ${argv[0]} exceeded ${timeout_ms}ms')
			}
		}
	}
	// The tail. Only a captured stream has a pipe to read; slurping an
	// inherited descriptor would be reading a stream that was never ours (the
	// fork's per-stream guard panics on it rather than letting it pass).
	//
	// On the ORDINARY path the child exited of its own accord, so slurping to
	// EOF is both safe and correct: the stream ends when the last writer
	// closes it, and waiting for that is what "capture the child's output"
	// means.
	//
	// After a TIMEOUT it is neither. We have already killed the child and
	// declared the budget spent — blocking here on EOF would hand the budget
	// straight back to whatever still holds the write end. That is not
	// hypothetical: `sh -c 'while true; do sleep 3600; done'` without
	// $new-process-group leaves the SIGKILLed shell's `sleep` grandchild
	// holding stdout, and a slurp to EOF then waits an hour on a 2,000 ms
	// budget — measured 2026-08-26, and the same #956 harm ("a bound that
	// cannot be enforced is the vacuous-gate class one layer down") coming
	// back through the one door the group escalation does not cover. So the
	// tail is drained with the same non-blocking reads, bounded: it ends on a
	// short quiet period, or on a hard cap, whichever comes first. Bytes still
	// in flight arrive; a held-open pipe cannot extend the run.
	if timed_out {
		tail_deadline := vtime.ticks() + proc_run_tail_cap_ms
		mut quiet_since := vtime.ticks()
		for vtime.ticks() < tail_deadline {
			mut moved := false
			if cap_out {
				chunk := p.stdout_read()
				if chunk.len > 0 {
					out_buf.write_string(chunk)
					moved = true
				}
			}
			if cap_err {
				chunk := p.stderr_read()
				if chunk.len > 0 {
					err_buf.write_string(chunk)
					moved = true
				}
			}
			if moved {
				quiet_since = vtime.ticks()
				continue
			}
			if vtime.ticks() - quiet_since >= proc_run_tail_quiet_ms {
				break
			}
			vtime.sleep(2 * vtime.millisecond)
		}
	} else {
		if cap_out {
			out_buf.write_string(p.stdout_slurp())
		}
		if cap_err {
			err_buf.write_string(p.stderr_slurp())
		}
	}
	out := out_buf.str()
	errout := err_buf.str()
	// Both captured streams have given us everything they will, so this is where
	// `run` stops owning the child: the parent ends go, then the reap (#1034).
	// One call, placed above `$check`'s CXER4012 raise, so the refusal path leaves
	// exactly as little behind as the ordinary return does.
	proc_reap_release(mut p)
	exit_code := p.code
	signaled := exit_code > 128 || timed_out

	// §4.7, applied to everything this call CAPTURED — and only to that, because
	// an uncaptured stream went to the parent's own descriptor and was never ours
	// to decode. The check runs BEFORE `$check`'s CXER4012 raise below, the same
	// ordering #1028 settled for the pipeline: a binary-output child should report
	// the encoding fault it actually hit rather than an exit code that happens to
	// be zero.
	if cap_out {
		oerr, ook := proc_encoding_check('run', 'stdout', out, want_bytes)
		if !ook {
			return oerr
		}
	}
	if cap_err {
		eerr, eok := proc_encoding_check('run', 'stderr', errout, want_bytes)
		if !eok {
			return eerr
		}
	}

	mut full := proc_result_element(exit_code, signaled, timed_out)
	// Attach captured streams as attributes (string capture default). A stream
	// that was NOT captured is ABSENT rather than empty — per stream, so
	// `capture=:stdout` reports `stdout` and no `stderr` at all. `stderr=''`
	// would assert "captured, and it was empty", which is a non-fact. Same rule
	// #908 settled for an unreported cause — never default to "" when nothing
	// was observed.
	if cap_out {
		full.attrs << proc_encoded_attr('stdout', out, want_bytes)
	}
	if cap_err {
		full.attrs << proc_encoded_attr('stderr', errout, want_bytes)
	}
	if check && exit_code != 0 {
		return mk_err('cx-err:CXER4012', 'E_PROC_EXIT_NONZERO: ${argv[0]} exited ${exit_code}')
	}
	return full
}

// proc_run_escalate implements §4.5's timeout kill: SIGTERM, a short fixed
// grace, then SIGKILL — targeting the whole GROUP when the child leads one, so
// a grandchild cannot outlive the budget while holding a captured pipe open
// (the #956 harm: a 60,000 ms budget ran 5m07s).
//
// Signalling goes through `C.kill(…)` — the same idiom proc_kill_group uses for
// §3.5 — NOT V's p.signal_pgkill() / p.signal_kill(), for three reasons that
// each bit in turn. The first two are about the GROUP form; the third (#1034) is
// about the direct one, and is stated at its call site below:
//
//  1. V's wrapper is guarded by `p.status in [.running, .stopped]`, so once the
//     leader exits the wrapper silently no-ops.
//  2. **A dead leader does not mean a dead group.** The first version of this
//     returned early on `!p.is_alive()` after SIGTERM — and the measured result
//     was the original bug intact: `sh -c 'sleep 30 & sleep 30'` takes SIGTERM,
//     the shell dies, both `sleep` grandchildren survive holding stdout, and
//     the slurp blocks past a 20 s probe bound. The forced phase must therefore
//     fire for the group REGARDLESS of the leader's state.
//
// Safe by construction: the child is not reaped until the caller's p.wait()
// below, so it is a zombie here and the kernel cannot recycle its pid — the
// negated pid cannot name some other process's group. An empty group yields a
// harmless ESRCH.
const proc_kill_grace_ms = 250

fn proc_run_escalate(mut p os.Process, new_group bool) {
	sigterm := proc_signal_num('term') or { 15 }
	sigkill := proc_signal_num('kill') or { 9 }
	if new_group {
		C.kill(-p.pid, sigterm)
	} else {
		p.signal_term()
	}
	deadline := vtime.ticks() + proc_kill_grace_ms
	for p.is_alive() && vtime.ticks() < deadline {
		vtime.sleep(5 * vtime.millisecond)
	}
	if new_group {
		C.kill(-p.pid, sigkill)
	} else if p.is_alive() {
		// `C.kill(p.pid, …)`, NOT `p.signal_kill()` — reason (3), found by #1034
		// and belonging with the two above because it is the same wrapper trap.
		//
		//  3. **V's `signal_kill()` DISQUALIFIES ITS OWN VICTIM FROM BEING
		//     REAPED.** Its last act is `p.status = .aborted`, and `p.wait()`
		//     returns without a syscall for any status outside
		//     `[.running, .stopped]`. So the forced phase — the phase that exists
		//     precisely for a child which ignored SIGTERM — guaranteed that the
		//     child it killed became a permanent zombie: every later `p.wait()`
		//     was a no-op. Measured pre-fix, and on BOTH timeout paths, not only
		//     the `$kill-on-timeout=false` one #1034 names.
		//
		//     This hid for the usual reason: a child that DIES on SIGTERM never
		//     reaches this branch, and it gets reaped incidentally anyway, because
		//     the grace loop above polls `p.is_alive()` and V implements that as a
		//     `waitpid(WNOHANG)` which reaps a zombie as a side effect. Every
		//     well-behaved fixture therefore came out clean.
		//
		// Going direct leaves `p.status` at `.running`, so the caller's
		// proc_reap_release actually waits, and `p.code` still comes back from V's
		// own bookkeeping rather than being second-guessed here.
		C.kill(p.pid, sigkill)
	}
}

// ── ending this call's ownership of a child (§4.4, #1034) ───────────
//
// proc_fd_release closes ONE parent-side stdio fd and stamps back the -1 that
// os.new_process starts every stream on. The sentinel is the point rather than
// tidiness: V's os.Process never clears a closed fd, and every `os.fd_*` helper
// treats -1 as a no-op, so a released stream is IDEMPOTENTLY released. That is
// what lets the sites which used to hand-roll `os.fd_close(p.stdio_fd[0])` share
// one exit path with the whole-stdio release below without ever risking a double
// close — a second close of a descriptor number the kernel has since recycled is
// not a leak, it is silent corruption of whatever file now holds that number.
fn proc_fd_release(mut p os.Process, pkind int) {
	if p.stdio_fd[pkind] >= 0 {
		os.fd_close(p.stdio_fd[pkind])
		p.stdio_fd[pkind] = -1
	}
}

fn proc_fd_release_all(mut p os.Process) {
	for i in 0 .. 3 {
		proc_fd_release(mut p, i)
	}
}

// proc_reap_release ends this call's ownership of a child: the PARENT ends of
// every pipe it opened are closed, and then the child is reaped — §4.4's "`run`
// and `pipeline` reap before returning", with the descriptor half that sentence
// assumes and never says.
//
// Both halves were missing, and NOT only on the path #1034 names. Nothing in V
// closes a parent-side capture fd: `p.wait()` is a bare `waitpid`, and
// `fd_slurp` reads to EOF and returns the bytes. So EVERY `run` that captured a
// stream — the ordinary success path included — leaked two descriptors for the
// life of the interpreter. Measured on the pre-fix binary (2026-08-26), a script
// counting the parent's open fds from inside successive children reported
// 5, 7, 9, 11, 13, 15: exactly +2 per call, monotonic, with no timeout involved.
// The `$kill-on-timeout=false` refusal then carried a second, worse defect on
// top of that one: it returned before `p.wait()` as well, so a child that had
// ignored SIGTERM and taken §4.5's SIGKILL was never waited on — the same script
// went from 0 to 2 zombies over two refusals.
//
// (A child that DIES on SIGTERM is reaped incidentally, because the
// `for p.is_alive()` grace loop in proc_run_escalate calls `waitpid(WNOHANG)`
// and that reaps a zombie as a side effect. Which is precisely why the leak
// hid: the shapes a fixture reaches for first are the ones the accident covers.)
//
// Order is close-then-reap, deliberately. The read ends go first so that
// anything still holding a write end — a killed child's surviving grandchild,
// §4.3 — takes an EPIPE instead of being able to keep the descriptor alive, and
// only then do we wait on the direct child. That wait is bounded on every path
// that reaches here: each has either observed the child exit or run §4.5's
// escalation through SIGKILL, which is uncatchable.
fn proc_reap_release(mut p os.Process) {
	proc_fd_release_all(mut p)
	p.wait()
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

// ProcChildEnv is the composed child environment — §4.2's layers resolved ONCE
// per child, BEFORE argv[0] is resolved, because §4.1 resolves against it.
//
// It exists because the composition has two readers that used to be strangers:
// the spawn (which hands the map to set_environment / an envp block) and the
// RESOLVER (which needs the child's `PATH`, #1052). Composing twice would be two
// chances to disagree about what the child's environment is, on a question where
// disagreeing means running a different binary than the one the child would find.
//
//   - `vars` is always the full composed environment, including the plain
//     inherit-the-parent case. It is what a caller that must hand over an
//     explicit block either way (spawn-pty's envp) reads.
//   - `explicit` is whether any §4.2 LAYER applied, and it alone gates
//     set_environment. The distinction is not cosmetic: with no layer to apply,
//     the process is left with NO explicit environment and INHERITS the parent's,
//     which is not the same thing as being handed a copy of it. `has_env` counts
//     as a layer even when the map is empty — `[env {}]` is a caller saying
//     something, and saying it about a hermetic stage (`env-clear=true`) is how
//     you spell "no environment at all".
//   - `path_named` is §4.1's "when `$env` overrides it": whether some layer NAMED
//     `PATH`, by setting it or by deleting it. A bare `env-clear=true` does not
//     name it, so it does not move resolution off the parent's PATH.
struct ProcChildEnv {
	vars       map[string]string
	explicit   bool
	path_named bool
}

// proc_child_env composes §4.2's layers in CO-15's RULED order: `env-clear`
// picks the base, the call's `$env` overlays it, and a pipeline stage's own
// `[env {…}]` overlays that. Each overlay is per KEY, so a stage that names one
// variable keeps every variable it did not name — `FOO=1 cmd1 | BAR=2 cmd2`, with
// the pipeline's own environment underneath both.
//
// `run` and `spawn` have no third layer and pass an empty ProcStageOpts; they are
// the same composition with one layer missing, not a second implementation of it.
fn proc_child_env(env_node cx.Node, env_clear bool, o ProcStageOpts) ProcChildEnv {
	sets, deletes, _ := proc_env_map(env_node)
	mut vars := proc_env_base(env_clear)
	proc_env_overlay(mut vars, sets, deletes)
	proc_env_overlay(mut vars, o.env_sets, o.env_deletes)
	explicit := sets.len > 0 || deletes.len > 0 || env_clear || o.has_env
	// §4.1's "when `$env` overrides it": NAMED by a layer, set or deleted. A bare
	// `env-clear=true` names nothing, so it does not move resolution off the
	// parent's PATH — which is what process-050 / -051 / -067 have relied on since
	// they were written.
	mut path_named := 'PATH' in sets || 'PATH' in deletes
	if 'PATH' in o.env_sets || 'PATH' in o.env_deletes {
		path_named = true
	}
	return ProcChildEnv{
		vars:       vars
		explicit:   explicit
		path_named: path_named
	}
}

// proc_child_env_args reads `run`'s / `spawn`'s argument layout — `$env` at
// args[1], `$env-clear` at args[2] — and composes. `pipeline` forwards the same
// two options at different indices (§3.3: args[5] / args[6]) and calls
// proc_child_env directly with its stage layer.
fn proc_child_env_args(args []cx.Node) ProcChildEnv {
	env_node := if args.len > 1 { args[1] } else { proc_null() }
	env_clear := if args.len > 2 { proc_arg_bool(args[2]) } else { false }
	return proc_child_env(env_node, env_clear, ProcStageOpts{})
}

// proc_child_env_apply installs the composed environment on the os.Process — and
// only when a layer actually applied, so the no-layer child keeps INHERITING
// rather than receiving a copy (see ProcChildEnv.explicit).
fn proc_child_env_apply(mut p os.Process, e ProcChildEnv) {
	if !e.explicit {
		return
	}
	p.set_environment(e.vars)
}

// proc_env_base is §4.2's augment-vs-hermetic switch, and nothing else: the
// parent's environment when augmenting, an empty map when `env-clear` makes the
// child hermetic. Every layer that follows is an overlay ON this.
fn proc_env_base(env_clear bool) map[string]string {
	mut base := map[string]string{}
	if !env_clear {
		for k, v in os.environ() {
			base[k] = v
		}
	}
	return base
}

// proc_env_overlay applies ONE §4.2 layer over `base`, per KEY: a set writes
// that key, a null-valued entry deletes it, and every key the layer does not
// name is left exactly as the layer beneath it left it. Per-KEY is the whole
// point — it is what lets CO-15's stage `[env …]` override one pipeline `$env`
// key while the rest of the pipeline environment flows through untouched.
fn proc_env_overlay(mut base map[string]string, sets map[string]string, deletes []string) {
	for k, v in sets {
		base[k] = v
	}
	for k in deletes {
		base.delete(k)
	}
}

// ── streaming spawn (§3.2) ──────────────────────────────────────────
//
// args: [0] argv [1] env [2] env-clear [3] cwd [4] encoding
//       [5] search-path [6] new-process-group
//       [7] stdin [8] stdout [9] stderr   (§3.2 per-stream stdio, #1014)
//
// The three stdio options are appended, so [0]..[6] keep the layout every
// pre-#1014 forwarding site used and their `null` default is `.pipe` — today's
// all-pipes behaviour, byte for byte.
fn proc_spawn(args []cx.Node, is_pty bool, rows int, cols int) cx.Node {
	argv := proc_argv(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: spawn expects argv::[sequence string]')
	}
	if argv.len == 0 {
		return mk_err('cx-err:CXER4006', 'E_PROC_INVALID_ARGV: empty argv')
	}
	search_path := if args.len > 5 { proc_arg_bool_def(args[5], true) } else { true }
	// Composed before resolution and reused by the spawn below — §4.1 / #1052, the
	// same discipline `run` follows above. `spawn` shares run's [1]/[2] env layout.
	child_env := proc_child_env_args(args)
	exec_path, rerr, ok := proc_resolve_exec(argv[0], search_path, child_env)
	if !ok {
		return rerr
	}
	cwd := if args.len > 3 { proc_arg_str(args[3]) or { '' } } else { '' }
	if cwd != '' && !os.is_dir(cwd) {
		return mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: cwd ${cwd}: no such directory')
	}
	new_group := if args.len > 6 { proc_arg_bool(args[6]) } else { false }

	// §3.2 (and §3.6, same layout) declare `$encoding`, and §4.7 gives it exactly
	// two values. Before #1035 `spawn` read neither: `[$spawn … encoding=:latin-1]`
	// was accepted in silence. It is validated here on the same footing as §3.2's
	// dispositions — "a misspelled disposition is never silently the default" —
	// and BEFORE the spawn, so a bad value leaves no child behind.
	//
	// The VALUE is deliberately discarded, and that is not an oversight. §4.7
	// scopes encoding to "captured stdout/stderr", and `spawn` captures nothing:
	// its streams are §2.4 io handles, and io.md §4.1 puts the text-vs-bytes
	// choice on the READ (`io/read-line` vs `io/read-bytes`), per call, not on the
	// handle. So there is no byte on this path for `$encoding` to decode. Making
	// it decide a handle's default read kind would be a new contract spanning
	// process.md and io.md, which is an owner ruling, not an implementation
	// detail — filed rather than invented. Refusing a value the spec does not
	// define is the half that needs no ruling, and it is the half that was
	// actively wrong.
	_, senc_err, senc_ok := proc_encoding_mode(if args.len > 4 {
		args[4]
	} else {
		proc_null()
	}, if is_pty { 'spawn-pty' } else { 'spawn' })
	if !senc_ok {
		return senc_err
	}

	// §3.2 per-stream stdio. Read BEFORE any spawn effect, so a misspelled
	// disposition faults with no child left behind (fail-closed, §4).
	mut kinds := [ProcRedirect.pipe, ProcRedirect.pipe, ProcRedirect.pipe]!
	mut paths := ['', '', '']!
	for i in 0 .. 3 {
		idx := 7 + i
		node := if args.len > idx { args[idx] } else { proc_null() }
		k, path, oerr, ok2 := proc_redirect_of(node, i, if is_pty { 'spawn-pty' } else { 'spawn' })
		if !ok2 {
			return oerr
		}
		kinds[i] = k
		paths[i] = path
	}

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
	proc_child_env_apply(mut p, child_env)
	// Only a `.pipe` stream gets a pipe of ours (#972's per-stream API). An
	// `.inherit` stream is not redirected at all; `.discard` / `.file` ride the
	// parent-descriptor staging below, which the child inherits across the fork.
	if kinds[0] == .pipe {
		p.set_redirect_pipe(.stdin)
	}
	if kinds[1] == .pipe {
		p.set_redirect_pipe(.stdout)
	}
	if kinds[2] == .pipe {
		p.set_redirect_pipe(.stderr)
	}
	mut staged, serr, sok := proc_stdio_stage(kinds, paths)
	if !sok {
		return serr
	}
	p.run()
	proc_stdio_unstage(mut staged)

	mut h := &ProcHandle{
		proc:       p
		argv:       argv
		is_open:    true
		new_group:  new_group
		is_pty:     is_pty
		rows:       rows
		cols:       cols
		stdio_kind: kinds
		stdio_path: paths
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
	// §3.2: only a `:pipe` stream has a parent-side descriptor. On `:inherit`
	// the child writes to OUR fd, on `:discard`/a file path it writes to that
	// target — in every one of those cases there is no pipe of ours to hand
	// back, and stdio_fd carries -1. Refuse BY NAME rather than return a handle
	// over -1 (which read as EBADF and looked like an empty stream): the caller
	// asked for a stream it explicitly redirected elsewhere.
	stream_idx := match which {
		'stdin' { 0 }
		'stdout' { 1 }
		'stderr' { 2 }
		else { -1 }
	}
	if stream_idx >= 0 {
		k := h.stdio_kind[stream_idx]
		if k != .pipe {
			where := if k == .file { "'${h.stdio_path[stream_idx]}'" } else { proc_redirect_name(k) }
			return mk_err('cx-err:CXER4013',
				'E_PROC_STREAM_NOT_PIPED: ${which} was spawned ${which}=${where}, so there is no pipe of ours to read or write; spawn it ${which}=:pipe to get a handle')
		}
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

// ── the stdin FEED, shared by `pipeline` and `run` (#1027, #1030) ────
//
// The helpers below are the whole mechanism for "this module owes a child a
// payload it cannot deliver in one write". #1027 built them for `pipeline`'s
// inter-stage feed; #1030 measured the SAME TWO DEFECTS at `run`'s
// `p.stdin_write(stdin_payload)` — the other blocking write in this file, sitting
// in front of #1002's drain loop exactly as the pipeline's sat in front of
// #1022's — and reuses them verbatim rather than re-spelling them. Nothing below
// is pipeline-specific: `fd` is a child's stdin pipe, `s` is the payload owed,
// and the caller is whichever entry point holds the deadline.
//
// The two entry points differ only in what the payload IS — stage N's captured
// stdout for `pipeline`, §3.1's `$stdin` string for `run` — and neither differs
// in the hazard. `run`'s measured numbers (2026-08-26, pre-fix binary at
// ab7f9b6d9, all three at the issue's named shapes):
//
//   [$process:run ('cat') stdin=<200,000 B> timeout-ms=5000]
//       killed at a 15 s EXTERNAL bound, 0 bytes printed — the 5 s budget
//       structurally could not fire, because the block was in our own write().
//   [$process:run ('head' '-c' '10') stdin=<200,000 B>]
//       exit 141 in 0.065 s, zero bytes, no diagnostic: the SIGPIPE death.
//   [$process:run ('sh' '-c' 'sleep 3600') stdin=<200,000 B> timeout-ms=600]
//       killed at the same 15 s bound — while the SAME child with NO payload
//       returned timed-out=true in 0.834 s. One added payload is the whole
//       difference, which is what makes this the same mechanism and not a
//       remainder of #1002.
//
// AND THE ORIGINAL DERIVATION, kept because it is where the shape was argued and
// where the rejected alternatives are recorded:
//
// #1022 drained every stage's OUTPUT streams and made `$timeout-ms` a real
// bound. It left the fourth blocking site in the same function standing: the
// feed of stage N's stdout into stage N+1's stdin was one blocking
// `p.stdin_write(feed)` of the whole payload, issued BEFORE the drain loop
// started. That is the same mutual deadlock as #1002/#1014/#1022 with the roles
// reversed — the parent blocks in write() once the stage's stdin pipe is full,
// the stage blocks in write() once its own stdout pipe is full, and neither can
// move — and it is strictly worse to diagnose, because the block is inside OUR
// OWN write() rather than in the wait loop, so the newly-honored budget
// structurally could not fire on it. MEASURED on this platform: the most
// ordinary large-payload pipeline imaginable,
//
//   [$process:pipeline ([stage [argv 'sh' '-c' "printf '%0200000d' 1"]],
//                       [stage [argv 'cat']])]
//
// never returned (probe killed at 12 s).
//
// Two cheaper shapes were considered and REJECTED, and they stay rejected:
// chunked BLOCKING writes only make the deadlock rarer, which is worse than
// leaving it findable (#1002's dead-ends register: "a deadlock is perfectly
// reproducible and no budget is long enough for one"); and staging the payload
// through a temp file — which §4.6 blesses for a CALLER choosing `stdin=<path>`
// — writes intermediate pipeline data to disk inside a module whose entire
// framing is a security stance (§1.1), and would do it for every pipeline
// whether or not the caller asked.
//
// So the feed becomes non-blocking and is interleaved into #1022's drain loop:
// the stage's stdin fd is armed O_NONBLOCK, each pass writes what fits and
// advances an offset, and the fd is closed at end-of-feed to give the stage its
// EOF (§4.6). The budget then bounds the feed for free, because the feed now
// happens in the loop the deadline already governs.

// proc_nb_arm makes `fd` non-blocking. The in-tree idiom
// (transport/picoev/socket_util.c.v): F_SETFL takes the whole flag word, and for
// a pipe fd we have just created there is nothing else in it to preserve —
// F_SETFL ignores the access-mode bits, and V's pipe fds carry no O_APPEND.
fn proc_nb_arm(fd int) bool {
	if fd < 0 {
		return false
	}
	return C.fcntl(fd, C.F_SETFL, C.O_NONBLOCK) == 0
}

// ProcFeedStep is the outcome of ONE non-blocking feed pass.
enum ProcFeedStep {
	more  // bytes remain and the pipe is full for now — come back next pass
	done  // every byte of the payload is in the pipe
	gone  // the reader is gone (EPIPE / EBADF): the feed is over, honestly
}

// proc_feed_pass writes as much of `s[off..]` into `fd` as the kernel will take
// right now, without ever blocking, and reports where that left the feed.
//
// The inner loop keeps writing until EAGAIN rather than stopping after one
// write(), and that is deliberate: on a stage that is actively reading, one
// pass moves the whole payload; on a stage whose own stdout has filled, the
// stage stops reading, the pipe fills, EAGAIN returns control to the caller's
// drain, and the two halves take turns. THAT alternation is the fix — writing
// one fixed-size chunk per pass would work too, but only by accident of the
// chunk being smaller than the pipe.
//
// EPIPE is the honest end of a feed, not a failure: a child like `head -c 10`
// reads what it wants and exits, and its own exit status — not our inability to
// finish talking to it — is the verdict (§4.3 for a pipeline stage, §3.1's
// `exit-code` for a `run`). The caller must have SIGPIPE off its default
// disposition first (proc_pipeline and proc_run each arm that for their own
// duration), or the signal kills the process before write() can return the error.
fn proc_feed_pass(fd int, s string, off int) (int, ProcFeedStep) {
	mut cur := off
	for cur < s.len {
		C.errno = 0
		n := unsafe { C.write(fd, voidptr(s.str + cur), usize(s.len - cur)) }
		if n > 0 {
			cur += int(n)
			continue
		}
		if n == 0 {
			// A zero-length write on a non-empty request makes no progress and
			// never will; treat the fd as dead rather than spin on it.
			return cur, ProcFeedStep.gone
		}
		e := C.errno
		if e == C.EINTR {
			continue
		}
		if e == C.EAGAIN || e == C.EWOULDBLOCK {
			// The loop condition guarantees bytes remain, so this is always
			// `.more`: the pipe is full for now and the caller's next pass, after
			// it has drained some of the stage's output, will find room.
			return cur, ProcFeedStep.more
		}
		// EPIPE (reader exited), EBADF, anything else: the feed ends here.
		return cur, ProcFeedStep.gone
	}
	return cur, ProcFeedStep.done
}

// proc_sigpipe_absorb is the no-op SIGPIPE handler installed for the duration of
// a feeding call — a pipeline (proc_pipeline) or a `run` with a `$stdin` payload
// (proc_run). A HANDLER rather than SIG_IGN, and that choice is load-bearing: an
// ignored disposition is INHERITED ACROSS exec, so SIG_IGN here would silently
// change every child's own SIGPIPE behaviour, while a handler is reset to
// SIG_DFL by exec and the children stay untouched.
//
// Both entry points save the PREVIOUS disposition and restore it on every exit
// path, so the two compose in either order and in sequence within one program: a
// `run` inside a program that also runs a `pipeline` restores whatever it found,
// which is the process default in the ordinary case and this same absorber in the
// (currently unreachable) nested one. That composition is pinned, not assumed —
// a shared save/restore is exactly the kind of discipline that decays silently.
fn proc_sigpipe_absorb(sig os.Signal) {}

// proc_feed_arm takes SIGPIPE off its default disposition and answers the
// previous handler plus whether the swap took. The two feeding entry points call
// this rather than each spelling the os.signal_opt dance, so there is ONE place
// the handler-not-SIG_IGN choice above is enacted.
fn proc_feed_arm() (os.SignalHandler, bool) {
	mut prev := os.SignalHandler(proc_sigpipe_absorb)
	if p := os.signal_opt(.pipe, proc_sigpipe_absorb) {
		prev = p
		return prev, true
	}
	return prev, false
}

// ── pipeline (§3.3) ─────────────────────────────────────────────────
//
// args: [0] stages [1] stdin [2] timeout-ms [3] kill-on-timeout
//       [4] encoding [5] env [6] env-clear [7] cwd [8] check
//
// Every one of the nine is now READ. Before #1022 the two budget options were
// inert; before #1028 so were [4] encoding, [5] env, [6] env-clear and [7] cwd.
//
// ── §3.3's per-stage `[opts …]` element (#1028) ──────────────────────
//
// §3.3 names a per-stage options element and puts it in its own example
// (`[stage [argv "sort" "-u"] [opts cwd="/tmp"]]`). NO code read it: the
// stage loop looked for the `argv` child, `break`ed, and dropped every other
// child on the floor. A stage written to the spec ran in the parent's cwd and
// said nothing — the #793 silent-acceptance shape, and invisible because the
// only fixture covering it (process-019) is a DENY case whose body never runs.
//
// §3.3 describes the key set in one clause — "same keys as `run` except
// `$stdin`/`$capture`, which the pipeline owns" — and that clause does not
// survive contact with the rest of the document. FIVE of the nine keys it
// thereby names are either contradicted elsewhere in the same spec or have no
// stated composition with their pipeline-level twin, so they are REFUSED BY
// NAME here rather than implemented on a guess (#956/#986 discipline: a
// documented option is honored or refused by name, never accepted-and-inert)
// and the contradiction is reported rather than papered over. CO-15 RATIFIED
// exactly this narrowing, and refusal-by-name is its forward-compatibility
// mechanism — a key refused today can be granted tomorrow without any caller
// having been silently misled in between, which is precisely how `env` below
// went from the sixth refusal to the fourth honored key:
//
//   timeout-ms / kill-on-timeout  §4.3 scopes the budget to the WHOLE pipeline
//                                ("one deadline for the run", "not each
//                                stage"). A per-stage budget has no defined
//                                relation to that one deadline.
//   new-process-group            §4.3 states flatly that `pipeline` has no
//                                such option, and #1022 depends on it: the
//                                escalation signals each stage leader
//                                DIRECTLY, so making a stage a group leader
//                                would move signal delivery underneath it.
//   encoding                     §4.7 decodes the PIPELINE's captured output.
//                                The last stage's stdout IS the pipeline's, so
//                                a per-stage encoding and the pipeline-level
//                                one would both claim the same bytes.
//   check                        §3.3 defines `$check` on the pipefail
//                                AGGREGATE. A stage-local raise would report a
//                                failure the aggregate is specified to carry.
// The three that survive are exactly the per-spawn properties with no
// pipeline-level twin to contradict: `cwd` (§3.3's own example), `env-clear`
// (a bool, so representable, and §4.2's hermetic switch is per-child), and
// `search-path` (§4.1's argv[0] resolution is per-spawn, and §3.3's signature
// has no pipeline-level `$search-path` for it to fight with).
//
// ── per-stage env is the FOURTH key (#1047, RULED: CO-15) ────────────
//
// `env` was the sixth refusal above, and it was the odd one out: the other five
// are refused because a per-stage form CONTRADICTS a rule stated elsewhere in
// the spec, but per-stage env contradicts nothing — POSIX has spelled it
// `FOO=1 cmd1 | BAR=2 cmd2` for decades. Its blocker was purely SPELLING: an
// attribute is scalar-only (code.md §6.4.1 — #396 owner ruling 1b removed the
// attribute BracketBody channel), so `env=[map …]` inside `[opts …]` is refused
// by the PARSER before this code sees it, and §3.3 named no child-element form
// to reach for instead. CO-15 rules that spelling:
//
//   [stage (…) [opts [env {KEY: "value", …}]]]
//
// — a CHILD ELEMENT of the stage's opts carrying a map value, which is legal
// under the frozen matrix and leaves the scalar-only-attribute rule untouched.
// The `env=` ATTRIBUTE stays refused (it is still representationally
// impossible), but the refusal now points at the child-element form rather than
// at a dead end.
//
// RULED composition (three layers, applied in this order, each overriding the
// one beneath it PER KEY):
//
//   1. env-clear   §4.2's hermetic switch decides the BASE — the parent's
//                  environment, or nothing. Per-stage `env-clear=` still
//                  overrides the pipeline's, so the stage's own base is chosen
//                  before either env layer lands on it.
//   2. pipeline $env   the pipeline-wide overlay, on every stage.
//   3. stage [env …]   the stage's own overlay, last.
//
// Per KEY at every layer: a stage naming one key still receives the pipeline's
// other keys, which is what makes "pipeline-wide environment plus one stage
// with one variable different" expressible — the shape POSIX gives for free and
// the reason this was worth not deferring.
struct ProcStageOpts {
mut:
	cwd             string
	has_cwd         bool
	env_clear       bool
	has_env_clear   bool
	search_path     bool
	has_search_path bool
	// CO-15's `[env {…}]` overlay, pre-parsed at stage-parse time so a
	// malformed body refuses BEFORE any stage spawns rather than half-way
	// down a pipeline (the same discipline `cwd` gets below).
	env_sets    map[string]string
	env_deletes []string
	has_env     bool
}

// proc_stage_opts_refusal names the key AND why it is refused. The message
// carries the spec clause because "unknown key" would be a lie for six of
// these: they ARE named by §3.3, and the caller needs to know the refusal is
// a spec contradiction rather than their typo.
fn proc_stage_opts_refusal(key string, stage_no int) cx.Node {
	reason := match key {
		'stdin', 'capture' {
			'the pipeline owns it (§3.3 excludes it by name: only the first stage reads pipeline \$stdin, only the last stage stdout is captured)'
		}
		'timeout-ms', 'kill-on-timeout' {
			'§4.3 scopes the budget to the WHOLE pipeline (one deadline for the run, not one per stage), so a per-stage budget has no defined composition with it — use pipeline-level timeout-ms'
		}
		'new-process-group' {
			'§4.3 states that pipeline has no \$new-process-group (the timeout escalation signals each stage leader directly)'
		}
		'encoding' {
			'§4.7 decodes the pipeline captured output, and the last stage stdout IS that output — use pipeline-level encoding'
		}
		'check' {
			'§3.3 defines \$check on the pipefail AGGREGATE, not on one stage — use pipeline-level check'
		}
		'env' {
			'an attribute is scalar-only (code.md §6.4.1), so a map-valued env has no ATTRIBUTE form — spell it as the child element `[opts [env {KEY: "value"}]]`, which IS honored (§3.3)'
		}
		'argv' {
			'argv is the stage own sibling element, not an [opts …] key'
		}
		else {
			'§3.3 names no such key for [opts …]'
		}
	}
	return mk_err('cx-err:CXER0100',
		'E_OPERAND_KIND: pipeline stage ${stage_no} [opts …]: `${key}` is REFUSED — ${reason}. Honored per-stage keys: cwd, env-clear, search-path, and the [env {…}] child element')
}

// proc_attr_bool_strict reads a bool-valued `[opts …]` attribute. A value that
// is neither true nor false is an operand fault rather than a silent false —
// `env-clear="yes"` must not read as "augment" (#793).
fn proc_attr_bool_strict(v cx.ScalarValue) ?bool {
	if v is bool {
		return v
	}
	if v is string {
		if v == 'true' {
			return true
		}
		if v == 'false' {
			return false
		}
	}
	return none
}

// proc_stage_env_parse reads CO-15's `[env {…}]` body: exactly one item, and
// that item a map. Returns the same (sets, deletes) pair proc_env_map yields
// for pipeline-level `$env`, so the two layers compose through one overlay rule
// rather than two.
//
// It VALIDATES before it extracts, which proc_env_map does not: that extractor
// is shared with `run` and `spawn`, where a non-scalar entry value has read as
// the empty string since long before this issue. CO-15 rules the per-stage form
// refuses by name instead, so the strictness lives HERE — tightening the shared
// extractor would change `run`'s behaviour under an issue that did not rule on
// `run`, which is the kind of silent widening #793 exists to prevent.
//
// The refusals use CXER0100 / E_OPERAND_KIND, the band every other shape fault
// in `[opts …]` already uses: this is a malformed operand, not a spawn failure
// (CXER4005) or a missing path (CXER4001).
fn proc_stage_env_parse(gc cx.Element, stage_no int) (map[string]string, []string, cx.Node, bool) {
	empty := map[string]string{}
	if gc.items.len != 1 {
		return empty, []string{}, mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: pipeline stage ${stage_no} [opts [env …]]: expects exactly one map body — spell it `[env {KEY: "value"}]` (§3.3); found ${gc.items.len} items'), false
	}
	body := gc.items[0]
	if body !is cx.Element {
		return empty, []string{}, mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: pipeline stage ${stage_no} [opts [env …]]: body is a scalar, not a map — spell it `[env {KEY: "value"}]` (§3.3)'), false
	}
	if body is cx.Element {
		if body.name !in ['map', '__cx_map__'] {
			return empty, []string{}, mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: pipeline stage ${stage_no} [opts [env …]]: body is `[${body.name} …]`, not a map — spell it `[env {KEY: "value"}]` (§3.3)'), false
		}
		// Each entry's value must be a SCALAR. A nested map or sequence has no
		// environment meaning — an environment variable is a string — and the
		// shared extractor would flatten it to '' without a word.
		for e in body.items {
			if e is cx.Element {
				if e.items.len == 0 {
					return empty, []string{}, mk_err('cx-err:CXER0100',
						'E_OPERAND_KIND: pipeline stage ${stage_no} [opts [env …]]: key `${e.name}` has no value — give it a string, or null to delete it (§4.2)'), false
				}
				if e.items[0] !is cx.ScalarNode {
					return empty, []string{}, mk_err('cx-err:CXER0100',
						'E_OPERAND_KIND: pipeline stage ${stage_no} [opts [env …]]: key `${e.name}` has a non-scalar value — an environment variable is a string (§4.2), so a map or sequence has no meaning here'), false
				}
			}
		}
	}
	sets, deletes, ok := proc_env_map(body)
	if !ok {
		return empty, []string{}, mk_err('cx-err:CXER0100',
			'E_OPERAND_KIND: pipeline stage ${stage_no} [opts [env …]]: unreadable map body (§3.3)'), false
	}
	return sets, deletes, proc_null(), true
}

// proc_parse_stage_opts walks ONE stage element and returns its honored
// per-stage options. It also enforces the stage's own shape: a stage carries
// `[argv …]` and at most one `[opts …]`, and any other child is a fault rather
// than the silent drop that hid this whole surface.
fn proc_parse_stage_opts(st cx.Element, stage_no int) (ProcStageOpts, cx.Node, bool) {
	mut o := ProcStageOpts{}
	for child in st.items {
		if child !is cx.Element {
			continue
		}
		if child is cx.Element {
			if child.name == 'argv' {
				continue
			}
			if child.name != 'opts' {
				return o, mk_err('cx-err:CXER0100',
					'E_OPERAND_KIND: pipeline stage ${stage_no}: unexpected child element `${child.name}` — a stage carries [argv …] and an optional [opts …] (§3.3)'), false
			}
			for a in child.attrs {
				match a.name {
					'cwd' {
						o.cwd = cx.scalar_value_str_public(a.value)
						o.has_cwd = true
					}
					'env-clear' {
						b := proc_attr_bool_strict(a.value) or {
							return o, mk_err('cx-err:CXER0100',
								'E_OPERAND_KIND: pipeline stage ${stage_no} [opts env-clear=…] expects true/false'), false
						}
						o.env_clear = b
						o.has_env_clear = true
					}
					'search-path' {
						b := proc_attr_bool_strict(a.value) or {
							return o, mk_err('cx-err:CXER0100',
								'E_OPERAND_KIND: pipeline stage ${stage_no} [opts search-path=…] expects true/false'), false
						}
						o.search_path = b
						o.has_search_path = true
					}
					else {
						return o, proc_stage_opts_refusal(a.name, stage_no), false
					}
				}
			}
			// A child element inside `[opts …]` is the shape a caller reaches for
			// after the parser refuses `env=[map …]`. Since CO-15 exactly ONE such
			// child is honored — `[env {…}]`, the ruled spelling — and every other
			// name is refused by the same name it would be refused under as an
			// attribute, so the answer does not depend on which spelling was tried.
			for gc in child.items {
				if gc is cx.Element {
					if gc.name != 'env' {
						return o, proc_stage_opts_refusal(gc.name, stage_no), false
					}
					if o.has_env {
						return o, mk_err('cx-err:CXER0100',
							'E_OPERAND_KIND: pipeline stage ${stage_no} [opts …]: two [env {…}] children — one stage carries at most one env overlay, so which one wins has no answer (§3.3)'), false
					}
					s, d, eerr, eok := proc_stage_env_parse(gc, stage_no)
					if !eok {
						return o, eerr, false
					}
					o.env_sets = s.clone()
					o.env_deletes = d.clone()
					o.has_env = true
				}
			}
		}
	}
	return o, proc_null(), true
}

// proc_encoding_mode reads `$encoding` — §3.1's, §3.2's or §3.3's; it is the
// same option with the same §4.7 semantics at all three entry points, so `who`
// only names the one that is refusing. Before #1028 the option was read by NO
// entry point in the module: `run`, `spawn` and `pipeline` all accepted it and
// none looked at it, so CXER4008 was raised nowhere in the tree and
// `encoding=:bytes` returned a `string`. #1028 wired `pipeline`; #1035 wired the
// other two and made this shared rather than pipeline-shaped — the message used
// to say "pipeline" unconditionally, which is why it could not simply be called
// from `run`.
//
// Accepted values are §4.7's two: the default `"utf-8"` and the atom `:bytes`.
// Anything else is refused by name rather than silently treated as the default,
// because the default is a DECODE and the caller who spelled it wrong asked for
// raw bytes. Returns (want_bytes, err, ok).

fn proc_encoding_mode(n cx.Node, who string) (bool, cx.Node, bool) {
	if proc_is_null(n) {
		return false, proc_null(), true
	}
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			is_atom := n.data_type == cx.ScalarType.atom_type
			if is_atom && v == 'bytes' {
				return true, proc_null(), true
			}
			if !is_atom && v.to_lower() == 'utf-8' {
				return false, proc_null(), true
			}
			return false, mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: ${who} expects encoding="utf-8" or encoding=:bytes, got ${if is_atom {
				':'
			} else {
				''
			}}${v}'), false
		}
	}
	return false, mk_err('cx-err:CXER0100',
		'E_OPERAND_KIND: ${who} expects encoding="utf-8" or encoding=:bytes'), false
}

// proc_encoding_check applies §4.7 to ONE captured stream: under `:bytes`
// nothing is decoded and nothing can fault; under the default `"utf-8"` an
// invalid sequence raises CXER4008 naming the stream and the byte offset, with
// the fix in the message. Extracted from #1028's two inline pipeline checks
// (#1035) so `run` raises the same error from the same code rather than growing
// a second copy that drifts. Returns (err, ok).
fn proc_encoding_check(who string, stream string, payload string, want_bytes bool) (cx.Node, bool) {
	if want_bytes {
		return proc_null(), true
	}
	if off := cx.validate_utf8(payload.bytes()) {
		return mk_err('cx-err:CXER4008',
			'E_PROC_ENCODING_INVALID: ${who} ${stream} is not valid utf-8 at byte ${off} — use encoding=:bytes for binary output'), false
	}
	return proc_null(), true
}

// proc_encoded_attr builds a captured-stream attribute under the resolved
// encoding. §4.7: `:bytes` returns the raw bytes with no decode; `"utf-8"`
// decodes and raises CXER4008 on an invalid sequence. Bytes ride a string
// ScalarValue with the `bytes` data-type ascribed — the same representation
// proc_bytes uses for a bytes NODE, carried on the attribute channel.
fn proc_encoded_attr(name string, payload string, want_bytes bool) cx.Attribute {
	mut a := proc_attr(name, cx.ScalarValue(payload))
	if want_bytes {
		a.set_data_type('bytes')
	}
	return a
}

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
	// Extract each stage's argv from [stage [argv …] …], AND — since #1028 —
	// its `[opts …]`. The loop used to `break` on the argv child, which is
	// exactly how §3.3's options element came to be dropped on the floor.
	mut argvs := [][]string{}
	mut stage_opts := []ProcStageOpts{}
	for si, st in stages {
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
			if found {
				o, oerr, ook := proc_parse_stage_opts(st, si + 1)
				if !ook {
					return oerr
				}
				stage_opts << o
			}
		}
		if !found {
			return mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: each stage must be [stage [argv …]]')
		}
	}
	stdin_payload := if args.len > 1 { proc_arg_str(args[1]) or { '' } } else { '' }
	// §3.3's pipeline-level `$timeout-ms` / `$kill-on-timeout`. Both were
	// FORWARDED by stdlib/process.cx and never read here (#1022) — the #793
	// silent-acceptance shape, and the harm was not merely a no-op: a pipeline
	// had NO bound of any kind, so the deadlock below had nothing to end it.
	timeout_ms := if args.len > 2 { proc_arg_int(args[2]) or { i64(0) } } else { i64(0) }
	kill_on_timeout := if args.len > 3 { proc_arg_bool_def(args[3], true) } else { true }

	// ── §3.3's remaining pipeline-level options (#1028) ──────────────────
	//
	// `$encoding` / `$env` / `$env-clear` / `$cwd` were forwarded by
	// stdlib/process.cx and read by NOTHING here. `run` already honored the
	// last three (proc_apply_env, p.set_work_folder), so a pipeline written to
	// §3.3 silently ran in the parent's cwd with the parent's environment while
	// the same options on `run` worked — the divergence was invisible because
	// process-019, the one fixture covering this surface, is a deny case.
	want_bytes, enc_err, enc_ok := proc_encoding_mode(if args.len > 4 {
		args[4]
	} else {
		proc_null()
	}, 'pipeline')
	if !enc_ok {
		return enc_err
	}
	env_node := if args.len > 5 { args[5] } else { proc_null() }
	env_clear := if args.len > 6 { proc_arg_bool(args[6]) } else { false }
	pipeline_cwd := if args.len > 7 { proc_arg_str(args[7]) or { '' } } else { '' }
	// §4.1/§5: a missing `$cwd` is CXER4001, and it is checked BEFORE any stage
	// spawns — a pipeline that would run half its stages in the wrong directory
	// and then fault is worse than one that never starts.
	if pipeline_cwd != '' && !os.is_dir(pipeline_cwd) {
		return mk_err('cx-err:CXER4001', 'E_PROC_NOT_FOUND: cwd ${pipeline_cwd}: no such directory')
	}
	for si, o in stage_opts {
		if o.has_cwd && o.cwd != '' && !os.is_dir(o.cwd) {
			return mk_err('cx-err:CXER4001',
				'E_PROC_NOT_FOUND: pipeline stage ${si + 1} [opts cwd=${o.cwd}]: no such directory')
		}
	}

	// ── the budget covers the WHOLE pipeline (§4.5) ──────────────────────
	//
	// ONE deadline, computed once, shared by every stage — not a fresh budget
	// per stage. `$timeout-ms` is a pipeline-level option (§3.3: "Pipeline-level
	// options mirror `run` where they apply to the whole pipeline"), so an
	// n-stage pipeline under a 1,000 ms budget must finish inside 1,000 ms and
	// not inside n × 1,000. The ACCOUNTING is still per stage: whichever stage is
	// alive when the shared deadline passes is the one killed and the one whose
	// `[proc-result …]` row carries `timed-out=true`, and no later stage starts.
	deadline := vtime.ticks() + timeout_ms

	// ── SIGPIPE discipline for the feed (#1027) ──────────────────────────
	//
	// The feed writes into a pipe whose reader is a process we do not control,
	// and a stage is entitled to stop reading and exit (`head -c 10` is the
	// canonical shape, and it is a legitimate pipeline stage, not a fault). A
	// write to a pipe with no reader raises SIGPIPE, whose DEFAULT ACTION
	// TERMINATES THE PROCESS SILENTLY — and the cx binary only takes SIGPIPE off
	// its default outside this path in the picoev serve plane
	// (transport/picoev/picoev.v new()), which a `cx` script run never enters.
	// So `printf … | head -c 10` would kill the interpreter, not report a
	// pipeline: no result, no error, no exit code that says why.
	//
	// The disposition is moved for the pipeline's duration and RESTORED on every
	// exit path (a `defer`, because this function has eight returns), so a
	// pipeline does not leave the process's signal state rearranged behind it.
	// With the signal absorbed, the honest EPIPE from the non-blocking write is
	// what ends the feed — an error value the loop can act on rather than a
	// death it cannot.
	sigpipe_prev, sigpipe_armed := proc_feed_arm()
	defer {
		if sigpipe_armed {
			os.signal_opt(.pipe, sigpipe_prev) or {}
		}
	}

	// Run stages end-to-end, threading stdout→stdin. Each stage runs to
	// completion (memory-buffered, §4.3) before feeding the next; this is
	// observationally equivalent to a connected pipe for finite output.
	mut feed := stdin_payload
	mut exit_codes := []int{}
	mut stage_stderr := []string{}
	mut stage_timed_out := []bool{}
	mut last_stdout := ''
	mut timed_out_stage := -1
	for si, a in argvs {
		// The stage's effective options: its own `[opts …]` where it names a key,
		// the pipeline-level value otherwise. "Per-stage overrides pipeline-level"
		// is decided per KEY, not per stage — a stage that sets only `cwd` still
		// gets the pipeline's `$env`, which is what makes a pipeline-wide
		// environment plus one stage in a different directory expressible.
		//
		// `env` is the one key whose override is per-key WITHIN the key too: the
		// stage's `[env {…}]` is an OVERLAY on the pipeline's `$env`, not a
		// replacement for it (CO-15), so proc_child_env composes the three layers
		// rather than choosing between two values the way the scalars here do.
		o := stage_opts[si]
		eff_cwd := if o.has_cwd { o.cwd } else { pipeline_cwd }
		eff_env_clear := if o.has_env_clear { o.env_clear } else { env_clear }
		// §3.3's signature has no pipeline-level `$search-path`, so the default is
		// §3.1's `true` and only a stage can change it.
		eff_search_path := if o.has_search_path { o.search_path } else { true }
		// The composition is PER STAGE and it happens BEFORE that stage's argv[0] is
		// resolved, because §4.1 resolves against it (#1052): a stage whose own
		// `[env {PATH: …}]` overlays the pipeline's is resolved against ITS PATH, not
		// the pipeline's and not the parent's. The same value is installed on the
		// stage below — composed once, read twice.
		stage_env := proc_child_env(env_node, eff_env_clear, o)
		exec_path, rerr, ok := proc_resolve_exec(a[0], eff_search_path, stage_env)
		if !ok {
			// A stage failed to spawn → CXER4005 (distinct from a stage
			// that ran and exited non-zero). The resolver's own code is folded
			// into the message so `search-path=false` on a name with no separator
			// does not report as a bare "stage failed".
			_ = rerr
			return mk_err('cx-err:CXER4005', 'E_PROC_PIPELINE_STAGE_FAILED: ${a[0]}')
		}
		mut p := os.new_process(exec_path)
		if a.len > 1 {
			p.set_args(a[1..])
		}
		if eff_cwd != '' {
			p.set_work_folder(eff_cwd)
		}
		proc_child_env_apply(mut p, stage_env)
		// All three of the stage's streams are pipes of OURS, and — unlike before
		// #1022 — every one of them is now read or closed by us. §4.3: "Leaving a
		// stream `:pipe` is a promise to drain it." The pipeline OWNS all three
		// (§3.3: `$stdin` / `$capture` are not per-stage keys), so there is no
		// caller to hand the obligation to; it is this function's.
		p.set_redirect_pipe(.stdin)
		p.set_redirect_pipe(.stdout)
		p.set_redirect_pipe(.stderr)
		p.run()

		// ── the FEED is armed here and DELIVERED in the loop (#1027) ─────────
		//
		// An empty payload owes the stage an immediate EOF (§4.6) and needs no
		// feed machinery at all. A non-empty one arms the stdin pipe O_NONBLOCK
		// and hands the delivery to the drain loop below.
		mut feed_off := 0
		mut stdin_open := true
		if feed.len == 0 {
			proc_fd_release(mut p, 0)
			stdin_open = false
		} else if !proc_nb_arm(p.stdio_fd[0]) {
			// Not reachable on a pipe fd we created two statements ago — but the
			// fallback to a blocking write is the very deadlock being fixed, so
			// this refuses BY NAME instead of quietly reinstating it. The stage is
			// already running; kill it rather than leak it.
			proc_run_escalate(mut p, false)
			proc_reap_release(mut p)
			return mk_err('cx-err:CXER4005',
				'E_PROC_PIPELINE_STAGE_FAILED: ${a[0]} stdin could not be set non-blocking')
		}

		// ── BOTH output streams are drained WHILE THE STAGE RUNS (#1002) ─────
		//
		// This used to be `last_stdout = p.stdout_slurp()` with stderr never read
		// at all, and that made a chatty stage an UNBOUNDED deadlock: the stage
		// blocks in write() once its stderr pipe is full, so it never exits and
		// never closes stdout, so our slurp never reaches EOF. Measured on this
		// platform against the shipped binary: a two-stage pipeline whose first
		// stage writes 100,000 bytes to stderr never returned (probe killed at
		// 12 s; before #1022 there was no `$timeout-ms` to end it either).
		//
		// It is the same defect #1002 fixed on `run` and #1014 fixed on `spawn`,
		// on the third entry point, and the same fix: drain both streams on EVERY
		// pass, non-blockingly, on ONE thread. Both-every-pass is load-bearing
		// rather than tidiness — draining stdout to EOF first and stderr after is
		// exactly what deadlocked, and a fix aimed only at the budget path would
		// have left it standing.
		//
		// One thread deliberately: a reader thread per stream is the textbook
		// shape and is not available to us, because under `-gc e` a thread blocked
		// in a read() syscall deadlocks vgc's stop-the-world against any
		// allocating thread (#973).
		mut out_buf := strings.new_builder(4096)
		mut err_buf := strings.new_builder(1024)
		mut t_out := false
		for {
			// Drain BEFORE the liveness test, every pass: a stage that has already
			// exited can still have bytes sitting in its pipes.
			mut moved := false
			// ── FEED first, then drain (#1027) ─────────────────────────────────
			//
			// The write goes first because it is what unblocks the stage: a stage
			// waiting on input produces nothing to read, so a pass that read before
			// it wrote would find both streams empty, conclude the stage was idle,
			// and sleep. Order within a pass costs nothing and reads as the
			// dependency it is.
			//
			// This is the whole of the #1027 fix: the parent's write now lives
			// INSIDE the loop the deadline governs, so a stage that never reads is
			// bounded by `$timeout-ms` exactly like a stage that never exits, and a
			// stage that reads while we write takes turns with us instead of
			// deadlocking against us.
			if stdin_open {
				n, step := proc_feed_pass(p.stdio_fd[0], feed, feed_off)
				if n > feed_off {
					feed_off = n
					moved = true
				}
				if step != .more {
					// End of payload, or the reader is gone. Either way the stage is
					// owed its EOF and this fd has no further use (§4.6).
					//
					// `.gone` gets no field on the stage row, deliberately: a stage that
					// stopped reading has already SAID what it thinks of the input, in
					// its exit status. `head -c 10` exits 0 and the pipeline is a
					// success; a stage that died mid-feed exits non-zero and the
					// pipefail aggregate carries it. A `feed-truncated` flag would be a
					// second, weaker account of the same fact — and for `head` a
					// misleading one.
					proc_fd_release(mut p, 0)
					stdin_open = false
				}
			}
			ochunk := p.stdout_read()
			if ochunk.len > 0 {
				out_buf.write_string(ochunk)
				moved = true
			}
			echunk := p.stderr_read()
			if echunk.len > 0 {
				err_buf.write_string(echunk)
				moved = true
			}
			if !p.is_alive() {
				break
			}
			if timeout_ms > 0 && vtime.ticks() >= deadline {
				break
			}
			// Only idle when the stage gave us nothing; while it is producing,
			// spinning through the reads is what keeps its pipes from filling.
			if !moved {
				vtime.sleep(2 * vtime.millisecond)
			}
		}
		// The liveness verdict is SAMPLED INTO A NAME before the feed's EOF is
		// sent — `run`'s `alive_at_deadline` shape, reused here rather than
		// restated (#1034's hygiene fold-in). Both entry points already sampled on
		// the correct side of the close, so nothing observable moves; what was
		// different is that a stage read `p.is_alive()` inline and acted on it in
		// the same breath, leaving the ordering an accident of statement order on
		// one of the two deadlines and a stated invariant on the other. The
		// invariant: closing stdin first could let a stage blocked on input exit
		// cleanly in the microsecond before the test runs, and the pipeline would
		// then report no timeout for a budget that demonstrably expired.
		alive_at_deadline := p.is_alive()
		// The EOF the stage is owed, on the paths the loop left the feed open: the
		// budget expired mid-feed, or the stage exited before we finished talking.
		if stdin_open {
			proc_fd_release(mut p, 0)
			stdin_open = false
		}
		if alive_at_deadline {
			t_out = true
			// §4.5's escalation: SIGTERM, a short fixed grace, then SIGKILL.
			// NOT the group form: §3.3 gives `pipeline` no `$new-process-group`
			// option, and quietly making every stage a group leader would move
			// signal delivery for every existing pipeline (a terminal SIGINT would
			// stop reaching the stages). So the leader is signalled directly and
			// the tail read below is what keeps a surviving GRANDCHILD from
			// handing the budget back — the same division #1002 settled for `run`
			// on the no-group path.
			proc_run_escalate(mut p, false)
		}
		if t_out {
			// The tail, bounded. Slurping to EOF here would hand the budget
			// straight back to whatever still holds the write end: `sh -c 'sleep
			// 3600'` leaves the SIGKILLed shell's `sleep` grandchild holding this
			// stage's stdout, and an unbounded slurp then waits an hour on a
			// 600 ms budget. Bytes already in flight arrive; a held-open pipe
			// cannot extend the pipeline.
			tail_deadline := vtime.ticks() + proc_run_tail_cap_ms
			mut quiet_since := vtime.ticks()
			for vtime.ticks() < tail_deadline {
				mut moved := false
				ochunk := p.stdout_read()
				if ochunk.len > 0 {
					out_buf.write_string(ochunk)
					moved = true
				}
				echunk := p.stderr_read()
				if echunk.len > 0 {
					err_buf.write_string(echunk)
					moved = true
				}
				if moved {
					quiet_since = vtime.ticks()
					continue
				}
				if vtime.ticks() - quiet_since >= proc_run_tail_quiet_ms {
					break
				}
				vtime.sleep(2 * vtime.millisecond)
			}
		} else {
			// The stage exited of its own accord, so slurping to EOF is both safe
			// and correct: the stream ends when its last writer closes it.
			out_buf.write_string(p.stdout_slurp())
			err_buf.write_string(p.stderr_slurp())
		}
		// This stage is finished with: parent ends closed, then reaped (#1034).
		// A pipeline leaked the same two descriptors per STAGE that `run` leaked
		// per call, so an n-stage pipeline in a loop leaked 2n at a time.
		proc_reap_release(mut p)
		exit_codes << p.code
		stage_stderr << err_buf.str()
		stage_timed_out << t_out
		last_stdout = out_buf.str()
		feed = last_stdout
		if t_out {
			// The budget is spent. A later stage would start with no budget left
			// and be killed on its first pass, which reports a timeout against a
			// stage that never had a chance to run — a non-fact. The pipeline
			// stops here, and `stages` / `exit-codes` carry only the stages that
			// actually ran.
			timed_out_stage = si
			break
		}
	}
	if timed_out_stage >= 0 && !kill_on_timeout {
		// Same contract as `run`: the child is killed either way — leaving a
		// runaway stage behind is not an option — and `$kill-on-timeout=false`
		// selects the ERR VALUE over a `timed-out=true` result.
		return mk_err('cx-err:CXER4003',
			'E_PROC_TIMED_OUT: pipeline stage ${timed_out_stage + 1} (${argvs[timed_out_stage][0]}) exceeded ${timeout_ms}ms')
	}
	// pipefail aggregate: 0 iff every stage exited 0; else the last
	// non-zero exit code.
	mut agg := 0
	for c in exit_codes {
		if c != 0 {
			agg = c
		}
	}
	// §4.7, applied to everything this call CAPTURED — the pipeline's stdout and
	// every stage's stderr row. Uniform because §4.7 says "Captured
	// stdout/stderr", and for a pipeline both of those are ours (§4.3: "there is
	// no caller to hand the drain obligation to"). Under `"utf-8"` an invalid
	// sequence is CXER4008; under `:bytes` nothing is decoded and nothing can
	// fault. The check runs BEFORE `$check`'s pipefail raise so a binary-output
	// pipeline reports the encoding fault it actually hit rather than an exit
	// code that happens to be zero.
	oerr, ook := proc_encoding_check('pipeline', 'stdout', last_stdout, want_bytes)
	if !ook {
		return oerr
	}
	for i, se in stage_stderr {
		serr, sok := proc_encoding_check('pipeline', 'stage ${i + 1} (${argvs[i][0]}) stderr',
			se, want_bytes)
		if !sok {
			return serr
		}
	}
	check := if args.len > 8 { proc_arg_bool(args[8]) } else { false }
	if check && agg != 0 {
		return mk_err('cx-err:CXER4012', 'E_PROC_EXIT_NONZERO: pipeline pipefail aggregate ${agg}')
	}
	mut stage_results := []cx.Node{}
	for i in 0 .. exit_codes.len {
		a := argvs[i]
		mut av := []cx.Node{}
		for s in a {
			av << proc_str(s)
		}
		// The stage rows are §2.3 `[proc-result …]` elements, so they carry what
		// that element is defined to carry. `signaled` used to be hard-coded
		// `false` — a stated non-fact for a stage killed by a signal — and
		// `stderr` was absent because it was never read at all. Now both are
		// observed: `stderr` is this stage's captured diagnostics (§4.3 — a
		// dropped stderr is a dropped diagnostic, so the pipeline captures rather
		// than discards), and `timed-out` names the one stage the budget caught.
		stage_results << cx.Element{
			name:  'proc-result'
			attrs: [
				proc_attr('exit-code', cx.ScalarValue(i64(exit_codes[i]))),
				proc_attr('signaled', cx.ScalarValue(exit_codes[i] > 128 || stage_timed_out[i])),
				proc_attr('timed-out', cx.ScalarValue(stage_timed_out[i])),
				proc_encoded_attr('stderr', stage_stderr[i], want_bytes),
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
			proc_encoded_attr('stdout', last_stdout, want_bytes),
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
