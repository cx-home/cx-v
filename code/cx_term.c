// cx_term.h - C shim for cx-x/term raw-mode terminal I/O (issue #30).
//
// Sibling of cx_pty.h: termios (raw/cooked) + winsize + a poll-gated read on the
// program's own tty, behind uniquely-named functions so the V side declares only
// cx_term_* and never the system termios/poll prototypes. POSIX only; where the
// terminal APIs are absent (windows/wasm) the bodies compile away and the
// functions return error sentinels (the V caller maps those to a CXER err value).
#ifndef CX_TERM_H
#define CX_TERM_H

#include <stdlib.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__linux__)

#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#if defined(__linux__)
#include <pty.h>
#else
#include <util.h>
#endif

// 1 if fd is a terminal, else 0.
int cx_term_is_tty(int fd) { return isatty(fd) ? 1 : 0; }

// Save fd's current termios, switch it to raw (cfmakeraw + VMIN=0/VTIME=0 so
// reads are poll-gated, not blocking). Returns a malloc'd opaque saved-termios
// pointer to pass to cx_term_restore, or NULL on error (not a tty / tcsetattr).
void *cx_term_enter_raw(int fd) {
    struct termios *saved = (struct termios *)malloc(sizeof(struct termios));
    if (!saved) return NULL;
    if (tcgetattr(fd, saved) != 0) { free(saved); return NULL; }
    struct termios raw = *saved;
    cfmakeraw(&raw);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &raw) != 0) { free(saved); return NULL; }
    return (void *)saved;
}

// Restore fd's termios from a saved pointer (from cx_term_enter_raw) and free it.
// Returns 0 ok, -1 on a null pointer / tcsetattr error.
int cx_term_restore(int fd, void *saved) {
    if (!saved) return -1;
    int rc = tcsetattr(fd, TCSANOW, (struct termios *)saved);
    free(saved);
    return rc;
}

// Write fd's terminal size into *rows/*cols. Returns 0 ok, -1 on ioctl error.
int cx_term_get_size(int fd, unsigned short *rows, unsigned short *cols) {
    struct winsize ws;
    if (ioctl(fd, TIOCGWINSZ, &ws) != 0) return -1;
    *rows = ws.ws_row;
    *cols = ws.ws_col;
    return 0;
}

// Poll-gated read: wait up to timeout_ms (<0 = block) for input on fd, then read
// up to n bytes into buf. Returns bytes read (>0), 0 on timeout, -1 on error.
int cx_term_read(int fd, char *buf, int n, int timeout_ms) {
    struct pollfd p;
    p.fd = fd;
    p.events = POLLIN;
    p.revents = 0;
    int pr = poll(&p, 1, timeout_ms);
    if (pr <= 0) return pr; // 0 = timeout, -1 = error
    return (int)read(fd, buf, n);
}

// Poll n fds for readability up to timeout_ms (<0 = block). Returns the index
// (0..n-1) of the FIRST ready fd, -1 on timeout, -2 on error. n==0 with a
// positive timeout just sleeps (a pure timer). This is the term:select shim:
// one wait over keystrokes (fd 0) ∪ source fds (sockets / SSE streams) ∪ a timer.
int cx_term_poll_first(int *fds, int n, int timeout_ms) {
    if (n <= 0) { poll(NULL, 0, timeout_ms < 0 ? 0 : timeout_ms); return -1; }
    struct pollfd *ps = (struct pollfd *)malloc(sizeof(struct pollfd) * n);
    if (!ps) return -2;
    for (int i = 0; i < n; i++) { ps[i].fd = fds[i]; ps[i].events = POLLIN; ps[i].revents = 0; }
    int pr = poll(ps, n, timeout_ms);
    int result = -1; // timeout
    if (pr < 0) result = -2;
    else if (pr > 0) {
        for (int i = 0; i < n; i++) {
            if (ps[i].revents & (POLLIN | POLLHUP | POLLERR)) { result = i; break; }
        }
    }
    free(ps);
    return result;
}

// Test helper: create a pipe, return the read fd (>=0) and write the write fd to
// *wr, or -1 on failure. Lets the V test drive multi-source readiness headlessly.
int cx_term_pipe(int *wr) {
    int fds[2];
    if (pipe(fds) != 0) return -1;
    *wr = fds[1];
    return fds[0];
}

// Test helper: open a pty, return the master fd (>=0) and write the slave fd to
// *slave, or -1 on failure. Lets the V test drive raw-mode/read-event on a real
// pseudo-terminal headlessly.
int cx_term_openpty(int *slave) {
    int master = -1, sl = -1;
    if (openpty(&master, &sl, NULL, NULL, NULL) != 0) return -1;
    *slave = sl;
    return master;
}

// Test helper: blocking write of n bytes to fd (the pty master). Returns bytes
// written or -1.
int cx_term_write(int fd, char *buf, int n) { return (int)write(fd, buf, n); }

// Test helper: close an fd.
void cx_term_close(int fd) { close(fd); }

#else // non-POSIX (windows / wasm): compile-away stubs returning error sentinels

int cx_term_is_tty(int fd) { (void)fd; return 0; }
void *cx_term_enter_raw(int fd) { (void)fd; return 0; }
int cx_term_restore(int fd, void *saved) { (void)fd; (void)saved; return -1; }
int cx_term_get_size(int fd, unsigned short *rows, unsigned short *cols) { (void)fd; (void)rows; (void)cols; return -1; }
int cx_term_read(int fd, char *buf, int n, int timeout_ms) { (void)fd; (void)buf; (void)n; (void)timeout_ms; return -1; }
int cx_term_poll_first(int *fds, int n, int timeout_ms) { (void)fds; (void)n; (void)timeout_ms; return -2; }
int cx_term_pipe(int *wr) { (void)wr; return -1; }
int cx_term_openpty(int *slave) { (void)slave; return -1; }
int cx_term_write(int fd, char *buf, int n) { (void)fd; (void)buf; (void)n; return -1; }
void cx_term_close(int fd) { (void)fd; }

#endif

#endif // CX_TERM_H
