// cx_iowatch_darwin.h — C shim for cx-stdlib/io's continuous filesystem watch
// (io.md §3.7; cxstore #128-B), built on the macOS FSEvents API.
//
// FSEvents is the only macOS facility that watches a whole subtree recursively
// AND sees files created in subdirectories after the watch begins (a per-fd
// kqueue does not — hence FSEvents, per the locked contract). It requires a
// dedicated thread running a CFRunLoop: cx_iowatch_fse_run creates the stream,
// publishes the run loop ref back to V (so watch-close can stop it), then blocks
// in CFRunLoopRun until cx_iowatch_fse_stop breaks it from the V eval thread.
//
// The stream callback classifies each event and calls back into V
// (cx_iowatch_emit, an @[export] V function) to push it onto the watcher's
// channel — the channel is thread-safe, so no lock crosses the thread boundary.
// CoreServices-only; compiled solely by the _darwin-guarded .c.v.
#ifndef CX_IOWATCH_DARWIN_H
#define CX_IOWATCH_DARWIN_H

#if defined(__APPLE__)

#include <CoreServices/CoreServices.h>
#include <sys/stat.h>
#include <string.h>

// Implemented in V (@[export]). `watcher` is the &Watcher pointer passed as the
// FSEvents context info; `op`: 1 created, 2 modified, 3 deleted, 4 overflow.
// `path` is non-const to match V's emitted `char*` signature exactly (a const
// mismatch is a hard C type conflict).
extern void cx_iowatch_emit(void *watcher, char *path, int op);
// Implemented in V (@[export]). Publishes the run loop ref (NULL on setup
// failure) and signals the `started` gate so watch-open can return.
extern void cx_iowatch_publish_runloop(void *watcher, void *runloop);

// Classify FSEvents flags into the contract's op codes. Overflow
// (MustScanSubDirs) wins. Otherwise filesystem existence is ground truth — a
// path that no longer exists is a deletion regardless of which flags coalesced;
// a created/renamed-in path that exists is a creation; everything else that
// still exists is treated as a modification.
static int cx_fse_op(FSEventStreamEventFlags f, const char *path) {
    if (f & kFSEventStreamEventFlagMustScanSubDirs) return 4;
    struct stat st;
    if (lstat(path, &st) != 0) return 3;
    if (f & (kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemRenamed))
        return 1;
    return 2;
}

static void cx_fse_cb(ConstFSEventStreamRef stream, void *info,
                      size_t n, void *paths,
                      const FSEventStreamEventFlags flags[],
                      const FSEventStreamEventId ids[]) {
    (void)stream;
    (void)ids;
    char **pp = (char **)paths;
    for (size_t i = 0; i < n; i++) {
        int op = cx_fse_op(flags[i], pp[i]);
        if (op == 4) {
            cx_iowatch_emit(info, (char *)"", 4); // overflow → no path; rescan
            continue;
        }
        cx_iowatch_emit(info, pp[i], op);
    }
}

// Backend thread body (spawned from V). Blocks in CFRunLoopRun until stopped.
void cx_iowatch_fse_run(void *watcher, const char *root) {
    CFStringRef cfpath = CFStringCreateWithCString(NULL, root, kCFStringEncodingUTF8);
    if (!cfpath) { cx_iowatch_publish_runloop(watcher, NULL); return; }
    CFArrayRef paths = CFArrayCreate(NULL, (const void **)&cfpath, 1, &kCFTypeArrayCallBacks);
    FSEventStreamContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.info = watcher;
    FSEventStreamRef stream = FSEventStreamCreate(
        NULL, &cx_fse_cb, &ctx, paths, kFSEventStreamEventIdSinceNow, 0.05,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |
        kFSEventStreamCreateFlagWatchRoot);
    CFRelease(paths);
    CFRelease(cfpath);
    if (!stream) { cx_iowatch_publish_runloop(watcher, NULL); return; }
    CFRunLoopRef rl = CFRunLoopGetCurrent();
    FSEventStreamScheduleWithRunLoop(stream, rl, kCFRunLoopDefaultMode);
    if (!FSEventStreamStart(stream)) {
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
        cx_iowatch_publish_runloop(watcher, NULL);
        return;
    }
    cx_iowatch_publish_runloop(watcher, (void *)rl);
    CFRunLoopRun(); // blocks until cx_iowatch_fse_stop
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
}

// Called from the V eval thread (watch-close) to break CFRunLoopRun.
void cx_iowatch_fse_stop(void *runloop) {
    if (!runloop) return;
    CFRunLoopRef rl = (CFRunLoopRef)runloop;
    CFRunLoopStop(rl);
    CFRunLoopWakeUp(rl);
}

#endif // __APPLE__
#endif // CX_IOWATCH_DARWIN_H
