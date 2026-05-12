#ifndef CX_GC_THREAD_SHIM_H
#define CX_GC_THREAD_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Internal helpers that wrap libgc's thread-registration API. Kept in
 * a C header rather than declared straight from V because V's C-typedef
 * codegen for `struct GC_stack_base` collides with the upstream
 * declaration in <gc.h>. These helpers expose a nullary, struct-free
 * surface the V code can call without seeing libgc's types. */

void cx_gc_allow_register_threads(void);
int  cx_gc_register_my_thread(void);
int  cx_gc_unregister_my_thread(void);

#ifdef __cplusplus
}
#endif

#endif
