module platform

// stdlib_iowatch_darwin.c.v — the FSEvents backend for cx-stdlib/io's
// continuous filesystem watch (io.md §3.7; cxstore #128-B). Compiled only on
// macOS. The CFRunLoop machinery lives in cx_iowatch_darwin.h; this file owns
// the V-side thread lifecycle and the two @[export] callbacks the C shim
// invokes. The &Watcher pointer is handed to FSEvents as its context `info`, so
// the backend thread only ever touches the watcher's thread-safe channel — the
// registry map stays single-threaded (eval-thread-only).

#flag darwin -framework CoreServices
#include "cx_iowatch_darwin.c"

fn C.cx_iowatch_fse_run(watcher voidptr, root &char)
fn C.cx_iowatch_fse_stop(runloop voidptr)

// cx_iowatch_emit (called from the FSEvents callback on the run-loop thread)
// pushes one change onto the watcher's channel. watch_emit is non-blocking, so
// the run loop is never wedged.
@[export: 'cx_iowatch_emit']
fn cx_iowatch_emit(watcher voidptr, path &char, op int) {
	mut w := unsafe { &Watcher(watcher) }
	if op == 4 {
		watch_signal_overflow(mut w)
		return
	}
	opname := match op {
		1 { 'created' }
		2 { 'modified' }
		3 { 'deleted' }
		else { '' }
	}

	if opname == '' {
		return
	}
	p := unsafe { cstring_to_vstring(path) }
	watch_emit(mut w, WatchChange{
		path: p
		op:   opname
	})
}

// cx_iowatch_publish_runloop (called once from the backend thread before
// CFRunLoopRun, or on setup failure with runloop == nil) records the run loop
// ref and releases the start gate. The channel send happens-before watch-open
// reads w.runloop, so no lock is needed for the ref.
@[export: 'cx_iowatch_publish_runloop']
fn cx_iowatch_publish_runloop(watcher voidptr, runloop voidptr) {
	mut w := unsafe { &Watcher(watcher) }
	w.runloop = runloop
	w.started <- true
}

// macos_watcher_start spawns the run-loop thread and blocks until it publishes
// the run loop (success) or nil (FSEvents setup failure).
fn macos_watcher_start(mut w Watcher) ! {
	spawn macos_watcher_thread(mut w)
	_ := <-w.started
	if w.runloop == unsafe { nil } {
		// the thread already returned and closed the channel; nothing to do
		return error('FSEventStream setup failed for ${w.root}')
	}
}

// macos_watcher_thread is the dedicated CFRunLoop thread. cx_iowatch_fse_run
// blocks until watch-close stops the loop; then we close the channel, waking
// any parked watch-next as absence.
fn macos_watcher_thread(mut w Watcher) {
	C.cx_iowatch_fse_run(voidptr(&w), &char(w.root.str))
	w.events.close()
}

// macos_watcher_close breaks the CFRunLoop from the eval thread; the backend
// thread then closes the channel. Idempotent via `closing`.
fn macos_watcher_close(mut w Watcher) {
	if w.closing {
		return
	}
	w.closing = true
	C.cx_iowatch_fse_stop(w.runloop)
}
