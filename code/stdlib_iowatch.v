@[has_globals]
module code

import cx
import os
import time as vtime
import sync.stdatomic

// stdlib_iowatch.v — the continuous filesystem-watch primitive backing
// cx-stdlib/io's `[io:watch]` / `[io:watch-next]` / `[io:watch-close]`
// (spec/std-lib/io.md §3.7; cxstore #128-B). This is the REAL primitive a
// directory-sync recipe builds on so a content-addressed store stays live
// as files change — NOT a poll-as-watch facade.
//
// ── contract (the three correctness requirements) ───────────────────
//   1. `watch-next handle timeout?` BLOCKS until the next change and
//      returns a `[change path=… op=created|modified|deleted]` element.
//      With an OPTIONAL `timeout` (ms) it returns the §9.1.2 ABSENCE
//      channel (empty sequence) on expiry — so a watcher can poll a
//      shutdown flag without busy-waiting. Without a timeout it blocks
//      indefinitely.
//   2. When the OS event queue overflows (inotify `IN_Q_OVERFLOW`, or
//      FSEvents coalescing under load), watch-next surfaces an explicit
//      `[change op=overflow]` event with NO path: the contract is "you
//      missed some — RESCAN the tree". The recipe answers overflow with a
//      full re-ingest, because a missed change == a stale store == the
//      bug #128-B exists to prevent.
//   3. `watch-close handle` UNBLOCKS a watch-next currently parked in
//      another task (self-pipe on Linux; CFRunLoopStop on macOS), then
//      tears down the OS watch. A parked watch-next then returns absence.
//
// ── architecture ────────────────────────────────────────────────────
//   The OS backend (inotify / FSEvents) runs on a dedicated thread and
//   feeds a single `chan WatchChange`. The blocking facade is therefore
//   platform-agnostic: `watcher_next` is a channel receive with optional
//   select-timeout; channel close (driven by watch-close) wakes a parked
//   receive and is read as absence. Backends live in the platform-guarded
//   files stdlib_iowatch_linux.c.v / stdlib_iowatch_darwin.c.v, each
//   defining `<plat>_watcher_start` / `<plat>_watcher_close`. Recursive by
//   default (the store mirrors a whole subtree).

// watch_queue_cap bounds the in-flight change buffer between the backend
// thread and watch-next. A burst beyond this is the overflow case the
// contract handles explicitly (req 2) — the backend pushes a single
// `overflow` change rather than blocking the OS reader.
const watch_queue_cap = 4096

// WatchChange is one filesystem change as the backend reports it. `op` is
// one of created / modified / deleted / overflow; `path` is absolute and
// empty for overflow. An all-empty WatchChange (op == '') is the closed
// sentinel a drained, closed channel yields — read as absence.
struct WatchChange {
mut:
	path string
	op   string
}

// Watcher holds the live OS watch plus the channel its backend thread
// feeds. Platform fields are inert on the other platform (a -1 fd / nil
// ptr), so the struct is shared across backends without per-OS variants.
@[heap]
struct Watcher {
mut:
	id     int
	root   string
	events chan WatchChange
	// pending_overflow is a level-triggered overflow latch. It is set (never
	// blocking) when a change cannot be queued because the buffer is full, and
	// is read-and-cleared by watch-next, which then surfaces a single
	// [change op=overflow]. A latch — not a queued event — because the queue
	// being full is exactly when an overflow event itself could not be queued;
	// dropping it there is the bug this guards against. Set by the backend
	// thread and cleared by the consumer thread, so it is touched only through
	// sync.stdatomic load/store; the tiny set/clear race is benign under
	// level-triggered semantics (a fresh overflow simply re-sets it).
	pending_overflow u64
	// Linux (inotify): the inotify fd, plus a self-pipe whose read end the
	// poll loop also waits on so watch-close can unblock a parked read by
	// writing one byte. `wds` maps each watch descriptor to its directory
	// for path reconstruction and recursive add-on-create.
	inotify_fd int = -1
	wake_r     int = -1
	wake_w     int = -1
	wds        map[int]string
	closing    bool
	// macOS (FSEvents): the run-loop ref (to CFRunLoopStop) and stream ref
	// (to stop/invalidate/release). `started` gates watch-close until the
	// backend thread has published `runloop`, so close never races setup.
	runloop voidptr = unsafe { nil }
	stream  voidptr = unsafe { nil }
	started chan bool
}

@[heap]
struct WatchRegistry {
mut:
	watchers map[int]&Watcher
	next_id  int
}

__global (
	g_watch_reg voidptr
)

fn watch_reg() &WatchRegistry {
	if g_watch_reg == unsafe { nil } {
		r := &WatchRegistry{
			watchers: map[int]&Watcher{}
		}
		g_watch_reg = voidptr(r)
	}
	return unsafe { &WatchRegistry(g_watch_reg) }
}

fn watch_register(w &Watcher) int {
	mut reg := watch_reg()
	reg.next_id++
	id := reg.next_id
	reg.watchers[id] = w
	return id
}

fn watch_lookup(id int) ?&Watcher {
	reg := watch_reg()
	return reg.watchers[id] or { return none }
}

fn watch_unregister(id int) {
	mut reg := watch_reg()
	reg.watchers.delete(id)
}

// watch_emit hands one change from a backend thread to watch-next over the
// channel WITHOUT ever blocking the OS reader: a non-blocking send. If the
// buffer is full (the consumer is behind) the change is dropped and the
// overflow latch is set instead — the consumer is told "you missed some,
// rescan" rather than the reader wedging (which could prevent it observing a
// close). The latch (not a queued overflow event) is essential: a full buffer
// is precisely when an overflow event could not be queued either.
fn watch_emit(mut w Watcher, c WatchChange) {
	select {
		w.events <- c {}
		else {
			stdatomic.store_u64(&w.pending_overflow, 1)
		}
	}
}

// watch_signal_overflow surfaces an OS-reported overflow (inotify
// IN_Q_OVERFLOW / FSEvents MustScanSubDirs). It prefers to queue a real
// [change op=overflow] (which wakes a consumer parked on an empty channel);
// if the buffer is full it falls back to the latch, which watch-next reads
// while draining. Either way the consumer is guaranteed to learn it must
// rescan.
fn watch_signal_overflow(mut w Watcher) {
	select {
		w.events <- WatchChange{
			op: 'overflow'
		} {}
		else {
			stdatomic.store_u64(&w.pending_overflow, 1)
		}
	}
}

// watch_take_overflow reports whether an overflow latch is pending and clears
// it. Called by watch-next before touching the channel.
fn watch_take_overflow(mut w Watcher) bool {
	if stdatomic.load_u64(&w.pending_overflow) != 0 {
		stdatomic.store_u64(&w.pending_overflow, 0)
		return true
	}
	return false
}

// ── handle element + resolver ───────────────────────────────────────

// watch_handle_element is the opaque handle returned by `watch`: a
// `[watch handle=N path=…]` element carrying the registry id (the proven
// io/store handle form).
fn watch_handle_element(id int, root string) cx.Node {
	return cx.Element{
		name:  'watch'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(root)
			},
		]
	}
}

// watch_id_of resolves a handle argument to its registry id, requiring the
// `watch` element shape so an io `file` handle of the same numeric id is
// never mistaken for a watcher (the two registries number independently).
fn watch_id_of(n cx.Node) ?int {
	if n is cx.Element {
		if n.name != 'watch' {
			return none
		}
		for a in n.attrs {
			if a.name == 'handle' {
				return int(cx.scalar_value_str_public(a.value).int())
			}
		}
	}
	return none
}

// ── change-event value builders ─────────────────────────────────────

fn watch_change_element(c WatchChange) cx.Node {
	if c.op == 'overflow' {
		// Overflow carries no path — the contract is "rescan everything".
		return cx.Element{
			name:  'change'
			attrs: [
				cx.Attribute{
					name:  'op'
					value: cx.ScalarValue('overflow')
				},
			]
		}
	}
	return cx.Element{
		name:  'change'
		attrs: [
			cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(c.path)
			},
			cx.Attribute{
				name:  'op'
				value: cx.ScalarValue(c.op)
			},
		]
	}
}

// watch_absence is the §9.1.2 absence channel (empty sequence) returned by
// watch-next on timeout-expiry or on a closed watcher — distinct from a
// `null` value, caught by `[?else]`.
fn watch_absence() cx.Node {
	return cx.Element{
		name:  seq_marker_name
		items: []
	}
}

// ── facade ──────────────────────────────────────────────────────────

// watcher_open validates the path, starts the platform backend, and
// registers the live watcher. Recursive by default.
fn watcher_open(root string) cx.Node {
	if !os.exists(root) {
		return mk_err('cx-err:CXER3401', 'E_IO_NOT_FOUND: watch ${root}')
	}
	if !os.is_dir(root) {
		return mk_err('cx-err:CXER3404', 'E_IO_NOT_A_DIRECTORY: watch ${root}')
	}
	resolved := os.real_path(root)
	mut w := &Watcher{
		root:    resolved
		events:  chan WatchChange{cap: watch_queue_cap}
		started: chan bool{cap: 1}
		wds:     map[int]string{}
	}
	$if linux {
		linux_watcher_start(mut w) or {
			return mk_err('cx-err:CXER3400', 'E_IO: watch ${root}: ${err.msg()}')
		}
	} $else $if macos {
		macos_watcher_start(mut w) or {
			return mk_err('cx-err:CXER3400', 'E_IO: watch ${root}: ${err.msg()}')
		}
	} $else {
		return mk_err('cx-err:CXER3412',
			'E_IO_UNSUPPORTED: watch is not supported on this platform')
	}
	id := watch_register(w)
	w.id = id
	return watch_handle_element(id, resolved)
}

// watcher_next blocks until the next change, or returns absence on
// timeout-expiry (timeout_ms >= 0) or on a closed watcher. timeout_ms < 0
// means block indefinitely.
fn watcher_next(mut w Watcher, timeout_ms i64) cx.Node {
	// A pending overflow latch takes priority: surface it before any queued
	// change so a consumer draining a backed-up buffer learns to rescan even
	// when the latch (not a queued event) carried the signal.
	if watch_take_overflow(mut w) {
		return watch_change_element(WatchChange{ op: 'overflow' })
	}
	if timeout_ms < 0 {
		ev := <-w.events or { return watch_absence() } // closed → absence
		if ev.op == '' {
			return watch_absence()
		}
		return watch_change_element(ev)
	}
	timeout := vtime.Duration(timeout_ms * i64(vtime.millisecond))
	mut got := WatchChange{}
	mut ok := false
	select {
		ev := <-w.events {
			got = ev
			ok = true
		}
		timeout {
			ok = false
		}
	}
	if !ok || got.op == '' {
		return watch_absence() // timeout, or closed-channel zero value
	}
	return watch_change_element(got)
}

// watcher_close tears down the OS watch and unblocks any parked
// watch-next. Idempotent — closing an already-closed/unknown watcher is a
// well-defined no-op (no CXER3409), matching io-close.
fn watcher_close(id int) cx.Node {
	mut w := watch_lookup(id) or { return io_null() }
	$if linux {
		linux_watcher_close(mut w)
	} $else $if macos {
		macos_watcher_close(mut w)
	}
	watch_unregister(id)
	return io_null()
}

// ── dispatch entry (called from io_stdlib_builtin's match) ──────────

// iowatch_dispatch handles the three watch verbs. Returns none for any
// other name so the io match falls through unchanged.
fn iowatch_dispatch(name string, args []cx.Node) ?cx.Node {
	match name {
		'io-watch' {
			path := io_arg_str(args[0]) or { return none }
			return watcher_open(path)
		}
		'io-watch-next' {
			id := watch_id_of(args[0]) or {
				return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: expected a watch handle element')
			}
			mut w := watch_lookup(id) or {
				return mk_err('cx-err:CXER3409', 'E_IO_HANDLE_CLOSED: watch-next')
			}
			timeout := if args.len > 1 { io_arg_int(args[1]) or { i64(-1) } } else { i64(-1) }
			return watcher_next(mut w, timeout)
		}
		'io-watch-close' {
			id := watch_id_of(args[0]) or { return io_null() }
			return watcher_close(id)
		}
		else {
			return none
		}
	}
}
