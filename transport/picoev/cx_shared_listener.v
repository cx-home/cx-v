@[has_globals]
module picoev

import os
import sync

// ── cx patch — held-open fds for SSE (§24) ───────────────────────────────────
//
// An SSE feed keeps its connection fd open across many pushes, fed from OTHER
// reactors' request handlers (a `/intent/sign` POST on reactor B pushes a frame
// to a held `/events` fd accepted by reactor A — a raw write to the socket fd
// works regardless of which loop owns it). picoev's per-fd idle timeout would
// otherwise close a held SSE fd, and an fd closed by picoev could have its
// number reused for a fresh connection before the next push (a cross-reactor
// write-to-wrong-socket race).
//
// The fix is a small, lock-guarded held-fd set the request callback marks via
// `cx_hold_fd` (no Picoev instance needed — the callback only has the fd):
// `handle_timeout` skips held fds, and `close_conn` notifies the cx layer (so it
// drops the fd from its subscriber set under the push lock) BEFORE the socket is
// closed, closing the reuse race. `cx_release_fd` clears the mark.
type CxSseCloseFn = fn (int)

// Up to this many independent SSE registries may register a close hook
// (the generic topic registry and the XAP feed registry are two TODAY —
// the original single global slot meant whichever registered last silently
// disconnected the other from close notifications, leaving stale fds whose
// numbers the OS then recycled onto fresh connections: cross-connection
// frame writes and swallowed requests, #873).
const cx_sse_close_cap = 4

// CxDeferCloseFn — cx-private #275 (handlers off reactors): consulted by
// close_conn BEFORE closing a socket. Returning true means a dispatch job for
// this fd is in flight on an executor thread: picoev deregisters the fd from
// its loop but LEAVES THE SOCKET OPEN — the executor performs the final
// cx_close_socket_fd when the job completes. Keeping the fd number allocated
// until then is what makes a late response write unable to land on a recycled
// fd (the same reuse race the SSE held-set closes for pushes).
type CxDeferCloseFn = fn (int) bool

__global (
	cx_held_fds             [max_fds]u8
	cx_sse_on_close         [cx_sse_close_cap]CxSseCloseFn
	cx_sse_on_close_n       int
	cx_dispatch_defer_close CxDeferCloseFn
)

fn C.atomic_load_byte(voidptr) u8
fn C.atomic_store_byte(voidptr, u8)

// The held set is per-fd byte ATOMICS, not a lock-guarded bool array: the
// marks are set/cleared on every dispatched request (#275) as well as per SSE
// stream, from reactors and executor threads alike — and the original
// VALUE-typed sync.Mutex global was a zeroed (non-functional on Darwin)
// pthread mutex anyway. Single-flag reads/writes have no compound invariant
// across fds; seq_cst byte atomics give the ordering the close path needs.

// cx_hold_fd marks `fd` as held open: exempt from the idle timeout, owned by
// the cx layer (an SSE stream, or an in-flight dispatch job) until released.
pub fn cx_hold_fd(fd int) {
	if fd < 0 || fd >= max_fds {
		return
	}
	C.atomic_store_byte(&cx_held_fds[fd], 1)
}

// cx_release_fd clears the held mark for `fd`.
pub fn cx_release_fd(fd int) {
	if fd < 0 || fd >= max_fds {
		return
	}
	C.atomic_store_byte(&cx_held_fds[fd], 0)
}

// cx_is_held reports whether `fd` is currently held open.
pub fn cx_is_held(fd int) bool {
	if fd < 0 || fd >= max_fds {
		return false
	}
	return C.atomic_load_byte(&cx_held_fds[fd]) != 0
}

// cx_set_sse_on_close registers a cx callback invoked (with the fd) just
// before a held SSE connection is closed by picoev, so the cx layer can drop it
// from its subscriber set synchronously and avoid pushing to a reused fd.
// APPEND semantics (#873): every SSE registry in the process gets notified;
// re-registering the same fn pointer is a no-op. Registration happens at
// serve setup (single-threaded per listener boot), before any close can fire.
pub fn cx_set_sse_on_close(cb CxSseCloseFn) {
	for i in 0 .. cx_sse_on_close_n {
		if cx_sse_on_close[i] == cb {
			return
		}
	}
	if cx_sse_on_close_n < cx_sse_close_cap {
		cx_sse_on_close[cx_sse_on_close_n] = cb
		cx_sse_on_close_n++
	}
}

// cx_notify_sse_close runs every registered SSE close hook for `fd` — the
// one purge point every socket-close path must pass through BEFORE the fd
// number can be recycled (#873). Idempotent: a registry without the fd
// drops nothing.
pub fn cx_notify_sse_close(fd int) {
	for i in 0 .. cx_sse_on_close_n {
		cx_sse_on_close[i](fd)
	}
}

// cx_set_dispatch_defer_close registers the #275 in-flight-dispatch probe —
// see CxDeferCloseFn.
pub fn cx_set_dispatch_defer_close(cb CxDeferCloseFn) {
	cx_dispatch_defer_close = cb
}

// cx_close_socket_fd is the executor-side final close for a deferred-close fd
// (already deregistered from every loop by close_conn).
pub fn cx_close_socket_fd(fd int) {
	close_socket(fd)
}

// cx patch — shared-listener multi-reactor support.
//
// macOS SO_REUSEPORT does NOT load-balance connections across separately
// bound sockets (only Linux does), so the per-worker-bind model pins all
// traffic to one core on macOS. The portable alternative is the classic
// shared-listener model: bind ONE socket, then run N picoev event loops
// (one per core, each on its own thread) that all watch that SAME listen
// fd. When a connection arrives, the kernel hands the accept() to one of
// the waiting worker loops; over many connections the load spreads across
// all workers — true multicore, no dependency on REUSEPORT semantics.
//
// listen_socket() binds the shared socket; new_with_listen_fd() builds a
// worker bound to it. Everything downstream (accept_callback, raw_callback,
// serve) is picoev's existing machinery.

// listen_socket binds a listening socket per `config` (host/port/family)
// and returns its raw fd, to be shared across new_with_listen_fd workers.
pub fn listen_socket(config Config) !int {
	return listen(config)
}

// new_with_listen_fd creates a Picoev worker that SHARES an existing
// listening socket (from listen_socket) instead of binding its own.
// Identical to new() except the bind step is skipped and the provided
// `listen_fd` is registered with the standard accept_callback. Run N of
// these, each on its own thread via serve(), for a multi-reactor server.
pub fn new_with_listen_fd(config Config, listen_fd int) !&Picoev {
	// Same SIGPIPE immunity as new() — this is the constructor the cx serve
	// path ACTUALLY uses (spawn_shared_reactors), so the process-wide ignore
	// must live here too. It also covers CLIENT-side writes with no
	// per-socket guard: mbedtls opens its own raw C socket (no SO_NOSIGPIPE,
	// no MSG_NOSIGNAL), so a TLS fetch whose peer reset the connection —
	// e.g. the weather fetch against a keep-alive server — killed the whole
	// process silently despite the server-side fd guards.
	$if !windows {
		os.signal_ignore(.pipe)
	}
	mut pv := &Picoev{
		num_loops:      1
		cb:             config.cb
		error_callback: config.err_cb
		raw_callback:   config.raw_cb
		user_data:      config.user_data
		timeout_secs:   config.timeout_secs
		max_headers:    config.max_headers
		max_read:       config.max_read
		max_write:      config.max_write
	}
	if isnil(pv.raw_callback) {
		pv.buf = unsafe { malloc_noscan(max_fds * config.max_read + 1) }
		pv.out = unsafe { malloc_noscan(max_fds * config.max_write + 1) }
	}
	$if linux || termux {
		pv.loop = create_epoll_loop(0) or { panic(err) }
	} $else $if freebsd || macos || openbsd {
		pv.loop = create_kqueue_loop(0) or { panic(err) }
	} $else {
		pv.loop = create_select_loop(0) or { panic(err) }
	}
	if pv.loop == unsafe { nil } {
		elog('Failed to create loop')
		return unsafe { nil }
	}
	pv.init()
	pv.add(listen_fd, picoev_read, 0, accept_callback)
	return pv
}
