module cx

// Non-Boehm thread-registration fallback (see cabi.v cx_init/cx_thread_*).
// Compiled when no Boehm `-gc` mode is active (V's `_notd_gcboehm` gate):
// `-gc vgc`, `-gc e`, `-gc none`. The Boehm shim's GC_register_my_thread
// surface does not exist in these builds, so these are no-ops (the runtime
// registers mutator threads on first allocation).

fn cx_gc_allow_register_threads_impl() {}

fn cx_gc_register_my_thread_impl() int {
	return 0
}

fn cx_gc_unregister_my_thread_impl() int {
	return 0
}
