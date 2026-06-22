@[has_globals]
module picoev

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

__global (
	cx_held_fds     [max_fds]bool
	cx_held_lock    sync.Mutex
	cx_sse_on_close CxSseCloseFn
)

// cx_hold_fd marks `fd` as a held-open (SSE) connection: exempt from the idle
// timeout, owned by the cx SSE layer until it closes.
pub fn cx_hold_fd(fd int) {
	if fd < 0 || fd >= max_fds {
		return
	}
	cx_held_lock.lock()
	cx_held_fds[fd] = true
	cx_held_lock.unlock()
}

// cx_release_fd clears the held mark for `fd`.
pub fn cx_release_fd(fd int) {
	if fd < 0 || fd >= max_fds {
		return
	}
	cx_held_lock.lock()
	cx_held_fds[fd] = false
	cx_held_lock.unlock()
}

// cx_is_held reports whether `fd` is a held-open SSE connection.
pub fn cx_is_held(fd int) bool {
	if fd < 0 || fd >= max_fds {
		return false
	}
	cx_held_lock.lock()
	held := cx_held_fds[fd]
	cx_held_lock.unlock()
	return held
}

// cx_set_sse_on_close registers the cx callback invoked (with the fd) just
// before a held SSE connection is closed by picoev, so the cx layer can drop it
// from its subscriber set synchronously and avoid pushing to a reused fd.
pub fn cx_set_sse_on_close(cb CxSseCloseFn) {
	cx_sse_on_close = cb
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
