module cx

// Boehm-GC thread-registration shim impls (see cabi.v cx_init/cx_thread_*).
// Compiled ONLY under a Boehm `-gc` mode (V's `_d_gcboehm` filename gate); the C
// shim links libgc's GC_*_thread symbols, which exist only with a Boehm
// collector. Non-Boehm modes use the no-op fallback in
// gc_thread_shim_notd_gcboehm.v.

#flag -I@VMODROOT/cx
#flag @VMODROOT/cx/gc_thread_shim.c
#include "gc_thread_shim.h"

fn C.cx_gc_allow_register_threads()
fn C.cx_gc_register_my_thread() int
fn C.cx_gc_unregister_my_thread() int

fn cx_gc_allow_register_threads_impl() {
	C.cx_gc_allow_register_threads()
}

fn cx_gc_register_my_thread_impl() int {
	return C.cx_gc_register_my_thread()
}

fn cx_gc_unregister_my_thread_impl() int {
	return C.cx_gc_unregister_my_thread()
}
