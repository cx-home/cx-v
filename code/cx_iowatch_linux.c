// cx_iowatch_linux.h — C shim for cx-stdlib/io's continuous filesystem watch
// (io.md §3.7; cxstore #128-B), built on inotify(7).
//
// Wraps inotify + the self-pipe poll loop behind uniquely-named functions so the
// V side never declares the libc prototypes (read/poll/pipe/close), which clash
// with V's own builtin/os externs. The real system types and the inotify_event
// struct layout live entirely in C here; V works only with field accessors and
// byte offsets. inotify is Linux-only — this header is compiled only by the
// _linux-guarded .c.v.
#ifndef CX_IOWATCH_LINUX_H
#define CX_IOWATCH_LINUX_H

#if defined(__linux__)

#include <sys/inotify.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdint.h>

// The event set we register on every watched directory. IN_CLOSE_WRITE +
// IN_MODIFY catch content writes; IN_CREATE/IN_MOVED_TO catch new entries (and
// drive recursive watch-add); IN_DELETE/IN_MOVED_FROM/IN_DELETE_SELF catch
// removals. IN_ATTRIB is intentionally omitted (chmod is not a content change).
#define CX_IOWATCH_MASK (IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM | \
                         IN_DELETE_SELF | IN_MODIFY | IN_CLOSE_WRITE)

// inotify_init1(0) — a BLOCKING inotify fd (the poll loop owns the blocking).
static inline int cx_iowatch_init(void) { return inotify_init1(0); }

// Add a recursive-relevant watch on one directory. Returns the wd, or -1.
static inline int cx_iowatch_add(int fd, const char *path) {
    return inotify_add_watch(fd, path, CX_IOWATCH_MASK);
}

// Create the self-pipe used to unblock the poll loop on close. rw[0]=read end
// (added to the poll set), rw[1]=write end (cx_iowatch_wake writes here).
static inline int cx_iowatch_pipe(int *rw) { return pipe(rw); }

// Wake a parked cx_iowatch_wait by writing one byte to the self-pipe.
static inline void cx_iowatch_wake(int wfd) {
    char b = 1;
    ssize_t r = write(wfd, &b, 1);
    (void)r;
}

static inline void cx_iowatch_close_fd(int fd) { if (fd >= 0) close(fd); }

// Block until the inotify fd OR the wake fd is readable. Returns the number of
// bytes read from the inotify fd (>0), 0 when woken via the self-pipe (close
// requested → caller stops), or -1 on a hard error. EINTR is retried.
static inline long cx_iowatch_wait(int ifd, int wfd, void *buf, unsigned long buflen) {
    struct pollfd fds[2];
    fds[0].fd = ifd; fds[0].events = POLLIN; fds[0].revents = 0;
    fds[1].fd = wfd; fds[1].events = POLLIN; fds[1].revents = 0;
    for (;;) {
        int pr = poll(fds, 2, -1);
        if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (fds[1].revents & POLLIN) return 0;       // wake → stop
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(ifd, buf, buflen);
            if (n < 0) { if (errno == EINTR) continue; return -1; }
            return (long)n;
        }
        // POLLERR/HUP or spurious wakeup → loop
    }
}

// ── inotify_event field accessors (layout lives here, not in V) ──────
// The kernel returns a packed stream of `struct inotify_event` records; `off`
// is the byte offset of the current record within the read buffer.
static inline int cx_iowatch_evt_wd(void *buf, int off) {
    return ((struct inotify_event *)((char *)buf + off))->wd;
}
static inline unsigned int cx_iowatch_evt_mask(void *buf, int off) {
    return ((struct inotify_event *)((char *)buf + off))->mask;
}
static inline unsigned int cx_iowatch_evt_len(void *buf, int off) {
    return ((struct inotify_event *)((char *)buf + off))->len;
}
static inline char *cx_iowatch_evt_name(void *buf, int off) {
    return ((struct inotify_event *)((char *)buf + off))->name;
}
// Total record size = header + name field (already includes NUL padding).
static inline int cx_iowatch_evt_size(void *buf, int off) {
    return (int)(sizeof(struct inotify_event) +
                 ((struct inotify_event *)((char *)buf + off))->len);
}

// Classify a mask into the contract's op codes:
//   1 created  2 modified  3 deleted  4 overflow  0 ignore
static inline int cx_iowatch_op(unsigned int mask) {
    if (mask & IN_Q_OVERFLOW) return 4;
    if (mask & (IN_CREATE | IN_MOVED_TO)) return 1;
    if (mask & (IN_DELETE | IN_MOVED_FROM | IN_DELETE_SELF)) return 3;
    if (mask & (IN_MODIFY | IN_CLOSE_WRITE)) return 2;
    return 0;
}
static inline int cx_iowatch_isdir(unsigned int mask) {
    return (mask & IN_ISDIR) ? 1 : 0;
}
// IN_IGNORED: the kernel auto-removed this watch (its dir was deleted/moved) —
// the V side drops the wd so it stops reconstructing paths for it.
static inline int cx_iowatch_ignored(unsigned int mask) {
    return (mask & IN_IGNORED) ? 1 : 0;
}

#endif // __linux__
#endif // CX_IOWATCH_LINUX_H
