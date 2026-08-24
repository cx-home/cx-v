module platform

import os

// stdlib_iowatch_linux.c.v — the inotify backend for cx-stdlib/io's continuous
// filesystem watch (io.md §3.7; cxstore #128-B). Compiled only on Linux.
//
// A dedicated thread (linux_watcher_loop) blocks in poll(2) over the inotify fd
// and a self-pipe. inotify events are translated to WatchChange and handed to
// watch-next over the watcher's channel; the self-pipe lets watch-close unblock
// a parked poll. inotify is not recursive, so we add a watch per directory and
// add new watches as subdirectories appear (linux_watch_tree). The libc calls
// live behind uniquely-named wrappers in cx_iowatch_linux.h to avoid clashing
// with V's builtin/os externs.

#include "cx_iowatch_linux.c"

fn C.cx_iowatch_init() int
fn C.cx_iowatch_add(fd int, path &char) int
fn C.cx_iowatch_pipe(rw &int) int
fn C.cx_iowatch_wake(wfd int)
fn C.cx_iowatch_close_fd(fd int)
fn C.cx_iowatch_wait(ifd int, wfd int, buf voidptr, buflen u64) i64
fn C.cx_iowatch_evt_wd(buf voidptr, off int) int
fn C.cx_iowatch_evt_mask(buf voidptr, off int) u32
fn C.cx_iowatch_evt_len(buf voidptr, off int) u32
fn C.cx_iowatch_evt_name(buf voidptr, off int) &char
fn C.cx_iowatch_evt_size(buf voidptr, off int) int
fn C.cx_iowatch_op(mask u32) int
fn C.cx_iowatch_isdir(mask u32) int
fn C.cx_iowatch_ignored(mask u32) int

// linux_watcher_start opens the inotify fd + self-pipe, adds watches over the
// whole tree, and spawns the reader thread. Errors before any watch registers
// are fatal; a partial subtree (e.g. a permission-denied child) is tolerated.
fn linux_watcher_start(mut w Watcher) ! {
	ifd := C.cx_iowatch_init()
	if ifd < 0 {
		return error('inotify_init failed')
	}
	w.inotify_fd = ifd
	mut rw := [2]int{init: -1}
	if C.cx_iowatch_pipe(&rw[0]) != 0 {
		C.cx_iowatch_close_fd(ifd)
		return error('self-pipe creation failed')
	}
	w.wake_r = rw[0]
	w.wake_w = rw[1]
	linux_watch_tree(mut w, w.root, false)
	if w.wds.len == 0 {
		C.cx_iowatch_close_fd(ifd)
		C.cx_iowatch_close_fd(w.wake_r)
		C.cx_iowatch_close_fd(w.wake_w)
		w.inotify_fd = -1
		return error('inotify_add_watch failed on ${w.root}')
	}
	spawn linux_watcher_loop(mut w)
}

// linux_watch_tree adds an inotify watch on `dir` and recurses into every
// subdirectory (skipping symlinked dirs to avoid cycles). When `emit` is true
// (a freshly-created subtree), it also emits a `created` change for each entry
// it finds — closing the race window between a directory appearing and our
// watch landing on it, during which inotify would otherwise miss new files.
fn linux_watch_tree(mut w Watcher, dir string, emit bool) {
	wd := C.cx_iowatch_add(w.inotify_fd, &char(dir.str))
	if wd >= 0 {
		w.wds[wd] = dir
	}
	entries := os.ls(dir) or { return }
	for e in entries {
		full := os.join_path(dir, e)
		is_dir := os.is_dir(full)
		if emit {
			watch_emit(mut w, WatchChange{
				path: full
				op:   'created'
			})
		}
		if is_dir && !os.is_link(full) {
			linux_watch_tree(mut w, full, emit)
		}
	}
}

// linux_watcher_loop is the backend thread: poll → read → translate → emit,
// until woken by the self-pipe (close) or a hard error. On exit it tears down
// the fds and closes the channel, which wakes any parked watch-next as absence.
fn linux_watcher_loop(mut w Watcher) {
	mut buf := []u8{len: 65536}
	for {
		n := C.cx_iowatch_wait(w.inotify_fd, w.wake_r, buf.data, u64(buf.len))
		if n <= 0 {
			break // 0 = woken (close requested); -1 = hard error
		}
		mut off := 0
		for off < int(n) {
			wd := C.cx_iowatch_evt_wd(buf.data, off)
			mask := C.cx_iowatch_evt_mask(buf.data, off)
			nlen := C.cx_iowatch_evt_len(buf.data, off)
			evsize := C.cx_iowatch_evt_size(buf.data, off)
			mut name := ''
			if nlen > 0 {
				name = unsafe { cstring_to_vstring(C.cx_iowatch_evt_name(buf.data, off)) }
			}
			off += evsize
			if C.cx_iowatch_op(mask) == 4 {
				watch_signal_overflow(mut w)
				continue
			}
			if C.cx_iowatch_ignored(mask) == 1 {
				w.wds.delete(wd) // kernel auto-removed this watch
				continue
			}
			op := C.cx_iowatch_op(mask)
			if op == 0 {
				continue
			}
			dir := w.wds[wd] or { continue }
			full := if name != '' { os.join_path(dir, name) } else { dir }
			opname := match op {
				1 { 'created' }
				2 { 'modified' }
				3 { 'deleted' }
				else { '' }
			}

			if opname == '' {
				continue
			}
			// A newly-created subdirectory needs its own watch (inotify is not
			// recursive); emit created for anything already inside it.
			if op == 1 && C.cx_iowatch_isdir(mask) == 1 {
				linux_watch_tree(mut w, full, true)
			}
			watch_emit(mut w, WatchChange{
				path: full
				op:   opname
			})
		}
	}
	C.cx_iowatch_close_fd(w.inotify_fd)
	C.cx_iowatch_close_fd(w.wake_r)
	C.cx_iowatch_close_fd(w.wake_w)
	w.inotify_fd = -1
	w.events.close()
}

// linux_watcher_close signals the backend thread to stop by writing to the
// self-pipe; the thread then closes the channel (unblocking a parked
// watch-next as absence) and releases the fds. Idempotent via `closing`.
fn linux_watcher_close(mut w Watcher) {
	if w.closing {
		return
	}
	w.closing = true
	if w.wake_w >= 0 {
		C.cx_iowatch_wake(w.wake_w)
	}
}
