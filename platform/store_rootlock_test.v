module platform

import code { caps_set_all, is_err_value, render_canonical }
import cx
import os
import testenv
import time

// store_rootlock_test.v — #1005: the CROSS-PROCESS writable-open guard.
//
// #628 (file/cxobj/cxpack) and #891 (columnar/sqlite) made a second WRITABLE
// open of one root sound IN-PROCESS. Across processes it stayed unenforced, and
// #993 measured what that costs: a publisher process plus an acking consumer
// process on one `file://` root left the root STRUCTURALLY DEAD — the next open
// refused `CXER1120` with a segment missing from the pack sequence, 5 runs of 5
// — while both processes reported success. Silent destruction on a misuse the
// docs forbid is still silent destruction.
//
// These pins are REAL two-process pins. The holder is a separate `cx` process
// with the root genuinely open writable; the refusal is measured in THIS
// process. flock's conflict domain is the open file DESCRIPTION, so that is the
// same conflict a third process would hit — nothing here simulates the other
// side.
//
// Red-proof (recorded on the commit): with `store_root_lock_take` reverted to a
// no-op, the second writable open SUCCEEDS, both writers go live on one root,
// and the assertions below fail on their first line.

fn rl_root(tag string) string {
	return os.join_path(os.temp_dir(), 'cx_rl_${tag}_${os.getpid()}')
}

fn rl_open(url string, read_only bool) cx.Node {
	return store_open_impl(url, '', '', read_only, true, map[string]string{})
}

fn rl_close(h cx.Node) {
	store_stdlib_builtin_inner('store-close', [h]) or { panic('close: ${err}') }
}

// rl_flock_taken probes whether the sentinel's flock is HELD, from a fresh
// descriptor. This is exactly the question a second process asks: an flock
// conflicts between distinct open file descriptions, so a fresh descriptor
// here answers for any process anywhere. Used as the readiness signal (no
// stdout parsing) and as the release check.
fn rl_flock_taken(path string) bool {
	if !os.exists(path) {
		return false
	}
	mut f := os.open_file(path, 'a+', 0o644) or { return false }
	defer {
		f.close()
	}
	if C.flock(f.fd, C.LOCK_EX | C.LOCK_NB) != 0 {
		return true
	}
	C.flock(f.fd, C.LOCK_UN)
	return false
}

// rl_await_holder waits until the holder process is REALLY writing the root —
// BOUNDED at 10s, because a probe that can hang is a probe that wedges the lane.
//
// Readiness is deliberately NOT "the lock is taken": that would make the
// readiness probe itself guard-dependent, and a red-proof run (guard reverted)
// would then fail here instead of on the assertion that matters. The holder's
// first pack segment landing is guard-independent evidence that it is a live
// writer on this root, so under a reverted guard the pin reaches — and reds on
// — `a second-PROCESS writable open was ADMITTED`.
fn rl_await_holder(root string, sentinel string) bool {
	manifest := os.join_path(root, '.cxpack-manifest')
	for _ in 0 .. 100 {
		if rl_flock_taken(sentinel) || os.exists(manifest) {
			return true
		}
		time.sleep(100 * time.millisecond)
	}
	return false
}

fn rl_await_free(path string) bool {
	for _ in 0 .. 100 {
		if !rl_flock_taken(path) {
			return true
		}
		time.sleep(100 * time.millisecond)
	}
	return false
}

// rl_holder_prog: a real writer. Opens the root writable, lands a doc, then
// sits on the handle. The sleep is the window the pins measure in; the process
// is killed in a defer, so it never outlives the lane.
fn rl_holder_prog(root string) string {
	return "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"file://${root}\"]]
  [= \$h [\$store:put-doc \$s [doc [holder 1]]]]
  [= \$_ [?sleep 60s]]
  \$h]
"
}

// rl_writer_prog: a second writer that must be REFUSED. It opens writable and
// puts — with the guard reverted this is the process that corrupts the root.
fn rl_writer_prog(root string) string {
	return "[?lib 'cx-stdlib/store']
[?let [= \$s [\$store:open \"file://${root}\"]]
  [\$store:put-doc \$s [doc [intruder 1]]]]
"
}

fn rl_write_prog(dir string, name string, src string) string {
	p := os.join_path(dir, name)
	os.write_file(p, src) or { panic('write ${name}: ${err}') }
	return p
}

// rl_spawn is the xap-lane idiom (#993): `/bin/sh -c 'exec cx … > LOG 2>&1'`.
// `exec` is load-bearing — the returned pid IS the cx process, so signal_kill
// reaches it instead of orphaning it behind a wrapper — and the redirect goes
// to a FILE, never an undrained pipe (a 512-byte pipe deadlocks the child).
fn rl_spawn(cxbin string, prog string, log string) &os.Process {
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c', 'exec ${cxbin} --allow-all ${prog} > ${log} 2>&1'])
	proc.run()
	return proc
}

// THE PIN. A second process holds the root writable; this process is refused
// CXER1143 with the holder NAMED; a read-only open of the same root is
// admitted (the discipline's exemption); and SIGKILLing the holder — a crash,
// no cleanup path runs — frees the root immediately.
fn test_rootlock_second_process_writable_open_refuses_and_names_the_holder() {
	caps_set_all()
	cxbin := testenv.cx_bin()
	root := rl_root('conflict')
	os.rmdir_all(root) or {}
	os.mkdir_all(root) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(root) or {}
	}
	sentinel := os.join_path(root, store_root_lock_name)
	mut holder := rl_spawn(cxbin, rl_write_prog(root, 'holder.cx', rl_holder_prog(root)),
		os.join_path(root, 'holder.log'))
	mut killed := false
	defer {
		if !killed {
			holder.signal_kill()
		}
	}
	assert rl_await_holder(root, sentinel), 'the holder process never opened the root in 10s; holder log: ${os.read_file(os.join_path(root,
		'holder.log')) or {
		''
	}}'
	hpid := holder.pid

	// (1) the refusal itself, and everything it must SAY.
	bad := rl_open('file://${root}', false)
	assert is_err_value(bad), 'a second-PROCESS writable open was ADMITTED — #1005 regressed: ${render_canonical(bad)}'
	msg := render_canonical(bad)
	assert msg.contains('CXER1143'), 'wrong code for a cross-process open conflict: ${msg}'
	assert msg.contains('E_STORE_OPEN_CONFLICT'), 'refusal does not name its class: ${msg}'
	assert msg.contains('pid=${hpid}'), 'the refusal does not NAME the holder (expected pid=${hpid}): ${msg}'
	assert msg.contains('ONE writer + N READ-ONLY readers'), 'the refusal does not state the discipline it enforces: ${msg}'
	assert msg.contains('RECOVERY:'), 'the refusal names no recovery path: ${msg}'

	// (2) the READ-ONLY exemption: N readers alongside the one writer IS the
	// supported shape, so a read-only open of a root held writable elsewhere
	// must be admitted — gating it would break the only sound arrangement.
	ro := rl_open('file://${root}', true)
	assert !is_err_value(ro), 'the read-only exemption was lost — a reader alongside the one writer is the SUPPORTED shape: ${render_canonical(ro)}'
	rl_close(ro)
	assert rl_flock_taken(sentinel), 'a read-only open must take NOTHING; the holder still owns the lock'

	// (3) the staleness story: SIGKILL runs no cleanup, closes no handle and
	// unlinks nothing. The lock still has to go, or a crashed writer bricks
	// the root — the failure this guard must never introduce.
	holder.signal_kill()
	holder.wait()
	killed = true
	assert rl_await_free(sentinel), 'a SIGKILLed writer kept the root lock — a crash must NEVER brick a root'
	after := rl_open('file://${root}', false)
	assert !is_err_value(after), 'the root stayed refused after its writer was killed — this is the brick #1005 must not create: ${render_canonical(after)}'
	rl_close(after)
}

// The corruption end-to-end, with two real cx processes: the intruder is
// refused rather than admitted, and the root the pair leaves behind still
// verifies. This is the #993 measurement's shape with the guard in place.
fn test_rootlock_leaves_the_two_process_root_verifiable() {
	caps_set_all()
	cxbin := testenv.cx_bin()
	root := rl_root('verify')
	os.rmdir_all(root) or {}
	os.mkdir_all(root) or { panic('mkdir: ${err}') }
	defer {
		os.rmdir_all(root) or {}
	}
	sentinel := os.join_path(root, store_root_lock_name)
	mut holder := rl_spawn(cxbin, rl_write_prog(root, 'holder.cx', rl_holder_prog(root)),
		os.join_path(root, 'holder.log'))
	mut killed := false
	defer {
		if !killed {
			holder.signal_kill()
		}
	}
	assert rl_await_holder(root, sentinel), 'the holder process never opened the root in 10s'

	// the INTRUDER — a whole second cx process, opening writable and writing.
	ilog := os.join_path(root, 'intruder.log')
	mut intruder := rl_spawn(cxbin, rl_write_prog(root, 'intruder.cx', rl_writer_prog(root)),
		ilog)
	intruder.wait()
	iout := os.read_file(ilog) or { '' }
	assert iout.contains('CXER1143'), 'the intruder process was not refused — two live writers on one root (#993): ${iout}'

	holder.signal_kill()
	holder.wait()
	killed = true
	assert rl_await_free(sentinel), 'the lock outlived its holder'

	// The root the pair leaves behind: openable, and structurally whole. Under
	// the pre-guard arrangement this is where CXER1120 landed, with a segment
	// missing from the pack sequence.
	h := rl_open('file://${root}', false)
	assert !is_err_value(h), 'the root did not survive the two-process arrangement: ${render_canonical(h)}'
	v := store_stdlib_builtin_inner('store-verify', [h]) or { panic('verify: ${err}') }
	vs := render_canonical(v)
	assert !is_err_value(v), 'verify refused after the two-process arrangement: ${vs}'
	assert !vs.contains('false'), 'the root verifies UNCLEAN after the two-process arrangement: ${vs}'
	rl_close(h)
}

// The guard must not turn #628/#891 same-root SHARING into a refusal: an
// in-process second writable open of one root still returns a second handle
// over the live store, and the lock is released only when the LAST of them
// closes. (flock is per-description, so a naive guard would refuse here.)
fn test_rootlock_leaves_in_process_sharing_alone() {
	caps_set_all()
	root := rl_root('share')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	sentinel := os.join_path(root, store_root_lock_name)
	a := rl_open('file://${root}', false)
	assert !is_err_value(a), 'first open: ${render_canonical(a)}'
	assert rl_flock_taken(sentinel), 'a writable open must HOLD the root lock, not merely leave a marker'
	b := rl_open('file://${root}', false)
	assert !is_err_value(b), 'the #628 same-root share became a refusal — the guard reaches inside the process it must not: ${render_canonical(b)}'
	rl_close(b)
	assert rl_flock_taken(sentinel), 'the lock was released while a sibling handle was still open'
	rl_close(a)
	assert rl_await_free(sentinel), 'the last close did not release the root lock'
	// Never unlinked: unlinking races a peer that already holds the file open.
	assert os.exists(sentinel), 'the sentinel was unlinked at close — that races a peer holding it open'
}

// A read-only open takes NOTHING, on a root nobody else holds either. The
// exemption is structural, not a side effect of contention.
fn test_rootlock_read_only_open_takes_nothing() {
	caps_set_all()
	root := rl_root('ro')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	sentinel := os.join_path(root, store_root_lock_name)
	w := rl_open('file://${root}', false)
	assert !is_err_value(w), 'seed open: ${render_canonical(w)}'
	rl_close(w)
	assert rl_await_free(sentinel), 'seed close did not release'
	r := rl_open('file://${root}', true)
	assert !is_err_value(r), 'read-only open: ${render_canonical(r)}'
	assert !rl_flock_taken(sentinel), 'a read-only open took the writer lock — N readers could then not coexist'
	rl_close(r)
}
