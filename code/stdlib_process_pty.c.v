@[has_globals]
module code

import cx
import os
import time as vtime

// stdlib_process_pty.c.v — real pseudo-terminal support (process.md §3.6),
// built on openpty(3) + posix_spawn(3).
//
// spawn-pty allocates a fresh pty with openpty() (master+slave), then launches
// the child with posix_spawn(): file actions dup2 the slave onto the child's
// stdin/stdout/stderr (so the child sees a real tty — isatty is true) and the
// POSIX_SPAWN_SETSID attribute makes the child a new session leader. The parent
// keeps the bidirectional master fd; the `pty` accessor returns one io-style
// handle over it. A posix_spawn child is launched WITHOUT the parent ever being
// in a forked-without-exec state (posix_spawn forks+execs internally in libc),
// so — unlike a raw forkpty() from V — it does not perturb the V/Boehm runtime
// (no SIGTRAP, no GC marker fixup, no _exit hook). The child's lifecycle runs on
// the bare pid (waitpid/kill), since it is not an os.Process.
//
// POSIX only. openpty lives in libutil (darwin: libSystem; linux: -lutil);
// posix_spawn is in libc. On a platform without these (windows / wasm) the call
// site is comptime-excluded and spawn-pty raises CXER4009 (process.md §4.9).

#flag linux -lutil
#include "cx_pty.h"

// The openpty + posix_spawn machinery lives in the cx_pty.h C shim (it uses the
// real system types internally); V calls just these two uniquely-named wrappers.
// cx_spawn_pty returns the child pid (>0), or -1 (openpty) / -2 (posix_spawn) /
// -3 (no pty facility on this platform); it writes the master fd to out_master.
fn C.cx_spawn_pty(path &char, argv voidptr, envp voidptr, rows u16, cols u16, cwd &char, out_master &int) int
fn C.cx_pty_set_winsize(fd int, rows u16, cols u16)

const wnohang = 1

// proc_pty_supported reports whether this build target has the pty facility.
fn proc_pty_supported() bool {
	$if linux || macos || freebsd || openbsd || netbsd || dragonfly {
		return true
	} $else {
		return false
	}
}

// proc_spawn_pty spawns argv attached to a fresh pty (process.md §3.6). Returns
// the [proc] handle element, or CXER4009 (no pty facility) / CXER4010 (pty
// alloc / spawn failed) / the argv/cwd faults shared with spawn. args layout
// matches spawn: [0]=argv [1]=env [2]=env-clear [3]=cwd [5]=search-path
// [7]=rows [8]=cols.
fn proc_spawn_pty(args []cx.Node, rows int, cols int) cx.Node {
	if !proc_pty_supported() {
		return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: no pty facility on this platform')
	}
	argv := proc_argv(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: spawn-pty expects argv::[sequence string]')
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
	// C argv + envp arrays (NULL-terminated char* vectors). V strings are
	// NUL-terminated, and they outlive the posix_spawn call.
	mut cargv := []&char{}
	for a in argv {
		cargv << &char(a.str)
	}
	cargv << &char(unsafe { nil })
	envp := proc_build_envp(args)
	mut cenvp := []&char{}
	for e in envp {
		cenvp << &char(e.str)
	}
	cenvp << &char(unsafe { nil })

	cwd_c := if cwd != '' { &char(cwd.str) } else { &char(unsafe { nil }) }
	mut master := -1
	pid := C.cx_spawn_pty(&char(exec_path.str), voidptr(cargv.data), voidptr(cenvp.data),
		u16(rows), u16(cols), cwd_c, &master)
	if pid == -3 {
		return mk_err('cx-err:CXER4009', 'E_PROC_PTY_UNSUPPORTED: no pty facility on this platform')
	}
	if pid < 0 {
		return mk_err('cx-err:CXER4010', 'E_PROC_PTY_ALLOC_FAILED: pty spawn failed (rc=${pid})')
	}
	mut h := &ProcHandle{
		proc:          unsafe { nil }
		argv:          argv
		is_open:       true
		is_pty:        true
		native_pty:    true
		pty_pid:       pid
		pty_master_fd: master
		rows:          rows
		cols:          cols
	}
	id := proc_register(h)
	return proc_handle_element_pty(id, h)
}

// proc_build_envp builds the child's environment block ("KEY=VALUE" strings)
// from the env opts: env-clear=true starts empty, else the parent's environ;
// then the [map …] overlay applies (a null value deletes a key). Mirrors
// proc_apply_env's semantics for the os.Process path.
fn proc_build_envp(args []cx.Node) []string {
	mut env := map[string]string{}
	env_clear := if args.len > 2 { proc_arg_bool(args[2]) } else { false }
	if !env_clear {
		for k, v in os.environ() {
			env[k] = v
		}
	}
	if args.len > 1 {
		sets, dels, ok := proc_env_map(args[1])
		if ok {
			for k, v in sets {
				env[k] = v
			}
			for k in dels {
				env.delete(k)
			}
		}
	}
	mut out := []string{}
	for k, v in env {
		out << '${k}=${v}'
	}
	return out
}

// proc_handle_element_pty builds the [proc] handle element for a pty child.
fn proc_handle_element_pty(id int, h &ProcHandle) cx.Node {
	mut argv_items := []cx.Node{}
	for a in h.argv {
		argv_items << proc_str(a)
	}
	return cx.Element{
		name:  'proc'
		attrs: [
			proc_attr('handle', cx.ScalarValue(i64(id))),
			proc_attr('pid', cx.ScalarValue(i64(h.pty_pid))),
			proc_attr('state', cx.ScalarValue('running')),
			proc_attr('pty', cx.ScalarValue(true)),
		]
		items: [cx.Node(cx.Element{ name: 'argv', items: argv_items })]
	}
}

// proc_pty_status_code decodes a waitpid status into an exit code: a normal
// exit yields WEXITSTATUS; a signalled child the 128+signal convention.
fn proc_pty_status_code(status int) int {
	if (status & 0x7f) == 0 {
		return (status >> 8) & 0xff
	}
	return 128 + (status & 0x7f)
}

// proc_pty_wait blocks on the pty child and returns its exit code.
fn proc_pty_wait(h &ProcHandle) cx.Node {
	mut status := 0
	C.waitpid(h.pty_pid, &status, 0)
	return proc_int(i64(proc_pty_status_code(status)))
}

// proc_pty_poll is non-blocking: absence (still running) or the exit code.
fn proc_pty_poll(h &ProcHandle) cx.Node {
	mut status := 0
	r := C.waitpid(h.pty_pid, &status, wnohang)
	if r == 0 {
		return proc_empty() // still running → absence (§9.1.2), not null
	}
	return proc_int(i64(proc_pty_status_code(status)))
}

// proc_pty_wait_timeout blocks up to ms; exit code or absence.
fn proc_pty_wait_timeout(h &ProcHandle, ms i64) cx.Node {
	deadline := vtime.ticks() + ms
	for vtime.ticks() < deadline {
		mut status := 0
		r := C.waitpid(h.pty_pid, &status, wnohang)
		if r != 0 {
			return proc_int(i64(proc_pty_status_code(status)))
		}
		vtime.sleep(2 * vtime.millisecond)
	}
	return proc_empty()
}

// proc_pty_signal delivers a signal to the pty child by pid (§3.4).
fn proc_pty_signal(h &ProcHandle, atom string) cx.Node {
	num := proc_signal_num(atom) or {
		return mk_err('cx-err:CXER4004', 'E_PROC_SIGNAL_UNSUPPORTED: :${atom}')
	}
	C.kill(h.pty_pid, num)
	return proc_null()
}

// proc_pty_set_winsize resizes the pty via TIOCSWINSZ on the master fd, which
// delivers SIGWINCH to the child's foreground group (process.md §4.8). The
// ioctl request number is platform-specific.
fn proc_pty_set_winsize(fd int, rows int, cols int) {
	C.cx_pty_set_winsize(fd, u16(rows), u16(cols))
}

// proc_pty_close closes the master fd and reaps the child (idempotent).
fn proc_pty_close(mut h ProcHandle) {
	if h.pty_master_fd >= 0 {
		os.fd_close(h.pty_master_fd)
		h.pty_master_fd = -1
	}
	mut status := 0
	C.waitpid(h.pty_pid, &status, wnohang)
	h.is_open = false
}
