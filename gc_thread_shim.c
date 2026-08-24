/* Thread-registration shim around libgc (Boehm GC).
 *
 * Bound to libcx's `cx_init` / `cx_thread_register` / `cx_thread_unregister`
 * exports via vcx/cx/cabi.v. Bindings whose host runtime spawns OS threads
 * outside V's control (Rust cargo workers, C# tasks, Java JNI threads) MUST
 * call cx_init once at module load and cx_thread_register on every host
 * thread that calls into libcx, otherwise libgc aborts with "Collecting
 * from unknown thread" when a collection is triggered from an unregistered
 * thread.
 *
 * See spec/abi.md §1.6 for the public contract. */

/* The top-level `<gc.h>` wrapper is legal standalone C since the fork
 * fix for vlang/v#27179 (GC_word, no V-only types) — the old
 * subdirectory-path workaround (#755) is retired; this include is the
 * live witness that plain-C shims can use the wrapper directly. */
#include <gc.h>

#include "gc_thread_shim.h"

void cx_gc_allow_register_threads(void) {
    /* Idempotent at the libgc level: GC_allow_register_threads simply
     * sets the internal GC_thr_initialized flag to TRUE. Repeat calls
     * are harmless plain stores. */
    GC_allow_register_threads();
}

int cx_gc_register_my_thread(void) {
    struct GC_stack_base sb;
    if (GC_get_stack_base(&sb) != GC_SUCCESS) {
        return -1;
    }
    int rc = GC_register_my_thread(&sb);
    if (rc == GC_SUCCESS || rc == GC_DUPLICATE) {
        return 0;
    }
    return -1;
}

int cx_gc_unregister_my_thread(void) {
    return GC_unregister_my_thread() == GC_SUCCESS ? 0 : -1;
}
