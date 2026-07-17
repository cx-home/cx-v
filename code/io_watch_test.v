module code

import os
import time
import cx

// io_watch_test.v — BEHAVIORAL coverage for cx-stdlib/io's continuous watch
// (io.md §3.7; cxstore #128-B). White-box (module code) so it drives the real
// inotify / FSEvents primitive directly, below the capability layer (the
// cap-denied path is covered by conformance/stdlib/io.cxd io-105..107). Proves
// the three locked correctness requirements:
//   1. a real change under the tree is reported by watch-next with the path;
//   2. watch-next with a timeout returns ABSENCE on expiry (no busy-wait);
//   3. watch-close UNBLOCKS a watch-next parked (blocking, no timeout) on
//      another thread.

fn iowatch_mktmp(tag string) string {
	base := os.join_path(os.temp_dir(), 'cx_iowatch_${tag}_${time.now().unix_nano()}')
	os.mkdir_all(base) or { panic('mkdir ${base}: ${err}') }
	return os.real_path(base)
}

fn iowatch_change_attr(n cx.Node, attr string) string {
	if n is cx.Element {
		if n.name == 'change' {
			for a in n.attrs {
				if a.name == attr {
					return cx.scalar_value_str_public(a.value)
				}
			}
		}
	}
	return ''
}

// iowatch_collect drains watch-next for up to budget_ms, returning every
// [change] event seen (FSEvents/inotify may coalesce or emit several).
fn iowatch_collect(mut w Watcher, budget_ms i64) []cx.Node {
	mut out := []cx.Node{}
	deadline := time.now().add(time.Duration(budget_ms * i64(time.millisecond)))
	for time.now() < deadline {
		ev := watcher_next(mut w, 200)
		if iowatch_change_attr(ev, 'op') != '' {
			out << ev
		}
	}
	return out
}

// iowatch_drain_quiet consumes any startup events until a watch-next returns
// absence (no event within `quiet_ms`). macOS FSEvents replays the watched
// directory's own recent creation when armed on a just-created path (an
// artifact absent on a pre-existing tree, and on Linux inotify); draining to
// quiet makes the timeout / close assertions deterministic.
fn iowatch_drain_quiet(mut w Watcher, quiet_ms i64) {
	for {
		ev := watcher_next(mut w, quiet_ms)
		if is_empty_absence(ev) {
			return
		}
	}
}

fn test_io_watch_reports_a_real_change() {
	dir := iowatch_mktmp('detect')
	defer {
		os.rmdir_all(dir) or {}
	}
	h := watcher_open(dir)
	id := watch_id_of(h) or { panic('watch did not return a handle: ${h}') }
	mut w := watch_lookup(id) or { panic('watcher ${id} not registered') }
	time.sleep(400 * time.millisecond) // let the backend arm
	fpath := os.join_path(dir, 'a.txt')
	os.write_file(fpath, 'hello') or { panic('write ${fpath}: ${err}') }
	changes := iowatch_collect(mut w, 5000)
	watcher_close(id)
	mut saw := false
	for c in changes {
		p := iowatch_change_attr(c, 'path')
		op := iowatch_change_attr(c, 'op')
		if p.ends_with('a.txt') && op in ['created', 'modified'] {
			saw = true
		}
	}
	assert saw, 'expected a created/modified change for a.txt; saw ${changes.len} changes'
}

fn test_io_watch_timeout_returns_absence() {
	dir := iowatch_mktmp('timeout')
	defer {
		os.rmdir_all(dir) or {}
	}
	h := watcher_open(dir)
	id := watch_id_of(h) or { panic('watch did not return a handle: ${h}') }
	mut w := watch_lookup(id) or { panic('watcher ${id} not registered') }
	time.sleep(400 * time.millisecond)
	iowatch_drain_quiet(mut w, 700) // consume startup self-events
	// Nothing changes → watch-next must return the §9.1.2 absence channel.
	ev := watcher_next(mut w, 300)
	watcher_close(id)
	assert is_empty_absence(ev), 'expected absence on timeout, got ${ev}'
}

// test_io_watch_overflow_surfaces is deterministic (no OS, no threads): it
// drives the overflow machinery directly. A full buffer must surface
// [change op=overflow] rather than silently dropping changes (the contract's
// "you missed some — rescan"); and an OS-reported overflow on a buffer with
// room must queue a real overflow event. This is the white-box proof of the
// req-2 path that an end-to-end test cannot trigger deterministically (forcing
// a real inotify IN_Q_OVERFLOW / FSEvents coalesce is inherently racy).
fn test_io_watch_overflow_surfaces() {
	mut w := &Watcher{
		root:    '/tmp'
		events:  chan WatchChange{cap: 2}
		started: chan bool{cap: 1}
		wds:     map[int]string{}
	}
	// Fill the 2-slot buffer, then emit a third change that cannot be queued —
	// it must arm the overflow latch instead of vanishing.
	watch_emit(mut w, WatchChange{ path: '/x/a', op: 'created' })
	watch_emit(mut w, WatchChange{ path: '/x/b', op: 'created' })
	watch_emit(mut w, WatchChange{ path: '/x/c', op: 'modified' })
	mut ops := []string{}
	for _ in 0 .. 4 {
		op := iowatch_change_attr(watcher_next(mut w, 100), 'op')
		if op != '' {
			ops << op
		}
	}
	assert 'overflow' in ops, 'a full buffer must surface overflow, not drop changes; got ${ops}'
	// An OS-reported overflow when the buffer has room queues a real event
	// (so a consumer parked on an empty channel is woken).
	watch_signal_overflow(mut w)
	assert iowatch_change_attr(watcher_next(mut w, 100), 'op') == 'overflow', 'watch_signal_overflow must surface an overflow change'
}

// iowatch_park blocks indefinitely in watch-next and reports whether the
// result was absence (the expected outcome once watch-close fires).
fn iowatch_park(mut w Watcher, result chan bool) {
	ev := watcher_next(mut w, -1)
	result <- is_empty_absence(ev)
}

fn test_io_watch_close_unblocks_parked_next() {
	dir := iowatch_mktmp('close')
	defer {
		os.rmdir_all(dir) or {}
	}
	h := watcher_open(dir)
	id := watch_id_of(h) or { panic('watch did not return a handle: ${h}') }
	mut w := watch_lookup(id) or { panic('watcher ${id} not registered') }
	time.sleep(400 * time.millisecond)
	iowatch_drain_quiet(mut w, 700) // reach a quiet state before parking
	result := chan bool{cap: 1}
	spawn iowatch_park(mut w, result)
	time.sleep(400 * time.millisecond) // ensure the parked next is blocked
	watcher_close(id)
	select {
		ok := <-result {
			assert ok, 'parked watch-next returned a value, not absence, after close'
		}
		5 * time.second {
			assert false, 'watch-close failed to unblock a parked watch-next'
		}
	}
}
