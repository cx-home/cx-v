// cx_pty.h - C shim for cx-stdlib/process spawn-pty (process.md section 3.6).
//
// Wraps openpty(3) + posix_spawn(3) behind two uniquely-named functions so the
// V side declares only cx_spawn_pty / cx_pty_set_winsize and never the system
// posix_spawn/openpty prototypes (declaring those from V clashes with the SDK
// headers' restrict/const-qualified signatures). The opaque posix_spawn types
// and the real system types live entirely in C here. Parameter types are plain
// (char*/void*/int) to match V's emitted extern prototype exactly.
//
// POSIX only; where openpty/posix_spawn are absent (windows/wasm) the bodies
// compile away and cx_spawn_pty returns -3 (the V caller maps that to CXER4009).
#ifndef CX_PTY_H
#define CX_PTY_H

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__linux__)

#if defined(__linux__)
#include <pty.h>
#else
#include <util.h>
#endif
#include <spawn.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

// Launch argv attached to a fresh pty. Returns the child pid (>0) and writes the
// master fd to out_master, or -1 (openpty failed) / -2 (posix_spawn failed).
// argv/envp are NULL-terminated char* vectors.
int cx_spawn_pty(char *path, void *argv, void *envp,
                 unsigned short rows, unsigned short cols,
                 char *cwd, int *out_master) {
    int master = -1, slave = -1;
    struct winsize ws;
    ws.ws_row = rows;
    ws.ws_col = cols;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    if (openpty(&master, &slave, NULL, NULL, &ws) != 0)
        return -1;
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, slave, 0);
    posix_spawn_file_actions_adddup2(&fa, slave, 1);
    posix_spawn_file_actions_adddup2(&fa, slave, 2);
    posix_spawn_file_actions_addclose(&fa, master);
    posix_spawn_file_actions_addclose(&fa, slave);
#if defined(__APPLE__) || defined(__GLIBC__)
    if (cwd && cwd[0])
        posix_spawn_file_actions_addchdir_np(&fa, cwd);
#endif
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
    pid_t pid = 0;
    int rc = posix_spawn(&pid, path, &fa, &attr,
                         (char *const *)argv, (char *const *)envp);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    close(slave);
    if (rc != 0) {
        close(master);
        return -2;
    }
    *out_master = master;
    return (int)pid;
}

// Resize the pty (delivers SIGWINCH to the child foreground group, section 4.8).
void cx_pty_set_winsize(int fd, unsigned short rows, unsigned short cols) {
    if (fd < 0)
        return;
    struct winsize ws;
    ws.ws_row = rows;
    ws.ws_col = cols;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    ioctl(fd, TIOCSWINSZ, &ws);
}

#else // no pty facility (windows / wasm)

int cx_spawn_pty(char *path, void *argv, void *envp,
                 unsigned short rows, unsigned short cols,
                 char *cwd, int *out_master) {
    (void)path; (void)argv; (void)envp; (void)rows; (void)cols; (void)cwd; (void)out_master;
    return -3;
}
void cx_pty_set_winsize(int fd, unsigned short rows, unsigned short cols) {
    (void)fd; (void)rows; (void)cols;
}

#endif
#endif // CX_PTY_H
