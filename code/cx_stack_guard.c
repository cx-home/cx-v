// cx_stack_guard.c — native-stack headroom probe for the CX evaluator (#319).
//
// Non-tail cx eval recursion consumes C stack per level (the evaluator is a
// tree-walker; only tail calls are trampolined — see run_closure_body). Before
// this guard, ~120 levels of non-tail recursion overflowed the default 8 MB
// thread stack and died by SIGSEGV. The evaluator now probes the remaining
// stack at every eval_node entry and raises a catchable coded error
// (cx-err:CXER0272 E_STACK_EXHAUSTED) while there is still ample headroom to
// unwind — see eval_stack_guard.c.v for the V-side wiring and margin.
//
// Mechanism: a per-thread stack watermark. On the first probe in a thread we
// resolve the thread's stack bounds once into TLS; every probe is then one
// TLS load + a pointer subtraction — build-mode agnostic (dev -O0 frames are
// ~8x prod frames, so a depth COUNTER would need a per-build bound; a
// watermark measures the real thing).
//
// Bounds resolution is per-platform:
//   macOS   — pthread_get_stackaddr_np/pthread_get_stacksize_np. For the MAIN
//             thread pthread_get_stacksize_np reports the 8 MB default even
//             when the rlimit was raised at exec (e.g. the #282 arena test
//             runs under `ulimit -s 65520`), so the main thread sizes from
//             getrlimit(RLIMIT_STACK) instead.
//   Linux   — pthread_getattr_np/pthread_attr_getstack (glibc and musl both
//             derive the main thread's extent from the stack rlimit — glibc
//             resolves an `unlimited` rlimit against the neighbouring mapping,
//             so the result is always finite; worker threads report the size
//             pthread_create was given — V's `spawn` sets it explicitly,
//             8 MB default).
//   wasm    — emscripten_stack_get_free()/emscripten_stack_get_base/end are
//             the direct equivalents.
//
// Worker threads ([?worker] bodies spawn V threads) arm lazily on their own
// first probe, so every eval thread is guarded with its own bounds.
//
// If the bounds cannot be resolved (unknown platform, API failure) the guard
// stays DISABLED on that thread (probe reports "plenty") — behaviour is then
// exactly the pre-#319 status quo, never a false CXER0272.

#include <stddef.h>
#include <stdint.h>

#if defined(__EMSCRIPTEN__)
#include <emscripten/stack.h>

/* #353: wasm call frames live on the HOST-JS engine stack (~1 MB under V8),
   NOT the 8 MB linear-memory stack — only aggregates/spills go to linear
   memory. Probing emscripten_stack_get_free() therefore measured the wrong
   stack: deep non-tail recursion died as an uncatchable host RangeError at
   depth ~94-100 (node v22, default stack) long before the linear watermark
   approached the 1 MiB margin, wedging the module (#329 verification).

   Wasm has exactly ONE build mode, so linear-bytes-per-level is a fixed
   constant and linear CONSUMPTION is a faithful DEPTH COUNTER (the #319
   objection to depth proxies — 8x frame variance across native build modes —
   does not apply). The guard presents a synthetic budget through the same
   remaining()/stack_size() interface, so the shared V-side margin math
   (eval_stack_guard.c.v, incl. its small-stack proportional trip at
   remaining < total/4) is unchanged.

   CX_WASM_HOST_BUDGET is CALIBRATED, not derived: with the V-side trip at
   used > 3/4 * budget, the budget is sized so the guard raises catchable
   CXER0272 at roughly HALF the measured host RangeError depth. Calibration
   method + numbers: scripts/wasm/check_stack_guard.mjs and issue #353. */
/* Calibrated 2026-07-11 (emcc via scripts/wasm/build_libcx_wasm.sh, node
   v22): linear consumption ≈ 21 KB/level on the deep non-tail shape, host
   RangeError at depth ~94-100 → 1.25 MiB budget trips the guard (V-side
   proportional rule: used > 3/4 x budget) at depth ~46 — half the host
   window, with the deep/fallback/tail lanes verified by
   scripts/wasm/check_stack_guard.mjs. */
#ifndef CX_WASM_HOST_BUDGET
#define CX_WASM_HOST_BUDGET ((size_t)(1280 * 1024))
#endif

size_t cx_stack_guard_used(void) {
	size_t total = (size_t)(emscripten_stack_get_base() - emscripten_stack_get_end());
	size_t freeb = (size_t)emscripten_stack_get_free();
	return total > freeb ? total - freeb : 0;
}

size_t cx_stack_guard_remaining(void) {
	size_t used = cx_stack_guard_used();
	if (used >= (size_t)CX_WASM_HOST_BUDGET) {
		return 0;
	}
	return (size_t)CX_WASM_HOST_BUDGET - used;
}

size_t cx_stack_guard_stack_size(void) {
	return (size_t)CX_WASM_HOST_BUDGET;
}

#else /* native: macOS + Linux (pthread) */

#include <pthread.h>
#if defined(__APPLE__)
#include <sys/resource.h>
#endif
#if defined(__linux__) && !defined(__USE_GNU)
/* pthread_getattr_np is _GNU_SOURCE-gated in glibc's pthread.h; declare it
   directly so this file does not force _GNU_SOURCE on the whole translation
   unit (V concatenates all C into one TU). musl exports it too. */
extern int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr);
#endif

/* Lowest legal stack address for this thread; 0 = not yet armed,
   1 = resolution failed, guard disabled on this thread. */
static __thread uintptr_t cx_stack_guard_floor = 0;
/* Total stack size of this thread (bytes); 0 until armed / when disabled. */
static __thread size_t cx_stack_guard_size = 0;

static void cx_stack_guard_arm(void) {
#if defined(__APPLE__)
	pthread_t self = pthread_self();
	uintptr_t top = (uintptr_t)pthread_get_stackaddr_np(self);
	size_t size = pthread_get_stacksize_np(self);
	if (pthread_main_np()) {
		/* Main thread: size from the exec-time rlimit (see header note). */
		struct rlimit rl;
		if (getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY
			&& rl.rlim_cur > 0) {
			size = (size_t)rl.rlim_cur;
		}
	}
	if (top == 0 || size == 0) {
		cx_stack_guard_floor = 1; /* disabled */
		return;
	}
	cx_stack_guard_floor = top - (uintptr_t)size;
	cx_stack_guard_size = size;
#elif defined(__linux__)
	pthread_attr_t attr;
	void *stack_lo = 0;
	size_t size = 0;
	if (pthread_getattr_np(pthread_self(), &attr) != 0) {
		cx_stack_guard_floor = 1; /* disabled */
		return;
	}
	int rc = pthread_attr_getstack(&attr, &stack_lo, &size);
	pthread_attr_destroy(&attr);
	if (rc != 0 || stack_lo == 0 || size == 0) {
		cx_stack_guard_floor = 1; /* disabled */
		return;
	}
	cx_stack_guard_floor = (uintptr_t)stack_lo;
	cx_stack_guard_size = size;
#else
	cx_stack_guard_floor = 1; /* unknown platform: guard disabled */
#endif
}

/* Bytes of stack left below the caller's frame, or SIZE_MAX when the guard is
   disabled on this thread. One TLS load + subtraction on the armed path. */
size_t cx_stack_guard_remaining(void) {
	char probe;
	if (cx_stack_guard_floor == 0) {
		cx_stack_guard_arm();
	}
	if (cx_stack_guard_floor == 1) {
		return SIZE_MAX; /* disabled */
	}
	uintptr_t sp = (uintptr_t)&probe;
	if (sp <= cx_stack_guard_floor) {
		return 0; /* already past the floor (should be unreachable) */
	}
	return (size_t)(sp - cx_stack_guard_floor);
}

/* Total stack size of the current thread, 0 when unknown/disabled. */
size_t cx_stack_guard_stack_size(void) {
	if (cx_stack_guard_floor == 0) {
		cx_stack_guard_arm();
	}
	return cx_stack_guard_size;
}

#endif /* native */
