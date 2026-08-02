@[has_globals]
module code

import cx
import os
import net
import runtime
import transport.picoev
import transport.picohttpparser
import strings
import sync
import time

#include <errno.h>

// services_listener.v — real-socket HTTP/1.1 listener for [?http-service]
//
// This file owns the picoev + picohttpparser surface (the cx-native
// server-leg backend; spec/02-inprogress/stdlib_http.md §9). Keeping it
// isolated from services.v (otherwise pure data-plumbing) lets the
// substrate compile under build modes that don't link the event-loop
// stack (the `_d_wasm32_emcc` sibling stubs it out), and makes the wire
// emitter a single grep target.
//
// The isolation bench (fe99c6ea) settled the backend question
// empirically: the request path is transport-bound (~93.5% of
// wall-clock on V's blocking net.http serve), so this listener runs a
// picoev event loop driving picohttpparser instead of a
// thread-per-request accept-loop.
//
// Spawned by `start_http_listener` when the trigger fires. The loop:
//   1. binds an OS socket on `bind_host:port` (defaulting to 0.0.0.0
//      when bind_host is empty) — picoev.new() binds synchronously,
//   2. accepts + reads + parses each HTTP/1.1 request via picohttpparser
//      inside the event loop,
//   3. looks up the matching resource via match_resource, evaluates the
//      handler body in a per-request MatchEnv clone (with $request bound
//      and cx-service-root stashed into dyn_context), maps the
//      [response …] envelope onto the wire,
//   4. sends the response directly on the connection fd (C.send) so a
//      large static-file body is NOT capped by picoev's per-fd write
//      buffer (max_write).
//
// Concurrency model mirrors par_eval.v: each request-handler clones
// bindings + closures, shares `&ProgramState` via pointer. The
// `state_locks.v` mutexes already cover concurrent map mutations.
//
// KNOWN LIMITATION (increment-2): picoev exposes only an infinite
// `serve()` (no `loop_once`/break). In-process `[?stop]` therefore
// flips the service to `stopped` (subsequent requests get 503) but does
// NOT close the listening socket until process exit — the serve thread
// leaks. A clean stop (and SSE held-open fds) needs a small picoev fork
// patch, deferred to a single later increment. No test exercises
// in-process stop-then-continue; `[block true]` programs are killed by
// signal, which tears the socket down with the process.

// ListenerMode selects how a parsed request is dispatched:
//   .service — directive `[?http-service]`: route via match_resource over
//              the service's [resource] table (path-params, HEAD→GET).
//   .handler — module `[$http:serve url $handler]`: invoke a single CX
//              handler closure with the built [request].
// Both modes share the picoev engine, the per-request env clone, and the
// [response]→wire mapping (the "one HTTP stack" the spec requires —
// spec/02-inprogress/stdlib_http.md §3.5/§6).
enum ListenerMode {
	service
	handler
	xap // cx-xap `[$xap:serve]` — dispatch via xap_dispatch_http (V, no CX closure)
}

// ListenerHandler carries the env snapshot (bindings + closures + state
// pointer) plus either the service name (.service) or the handler
// closure value (.handler) across the picoev C-callback boundary via the
// `user_data voidptr`. Per-request env clones happen in dispatch_request.
// One picoev instance (hence one handler) per listener, so the pointer is
// stable for the listener's life. @[heap] — always created via `&ListenerHandler{}`
// and shared by reference (picoev voidptr + the cx_http_live_handlers vgc root, #57);
// the attribute lets the reference be stored in that global retainer.
@[heap]
struct ListenerHandler {
	mode         ListenerMode
	service_name string
mut:
	handler            cx.Node = cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue('')
		data_type: cx.ScalarType.string_type
	})
	enclosing_bindings map[string]cx.Node
	enclosing_closures map[string]Closure
	enclosing_dyn      []cx.Node
	// enclosing_scope is the program's lexical Scope at serve time. Per-request
	// envs carry it so a caller-supplied handler closure (a top-level [?def]/[?fn]
	// passed into the lib `[$http:serve …]`) resolves via the program scope —
	// `serve`'s own call env only sees the http module's scope (#19 higher-order).
	enclosing_scope    &Scope = unsafe { nil }
	state              &ProgramState = unsafe { nil }
	xap_rt             int // .xap mode: the cx-xap runtime id this listener serves
}

// WireHeader / WireResp are the transport-neutral response shape the CX
// dispatch pipeline produces; serialize_wire turns one into HTTP/1.1
// bytes. (Replaces the former dependency on V's http.Response.)
struct WireHeader {
	name  string
	value string
}

struct WireResp {
	status  int
	headers []WireHeader
	body    string
	// §24 SSE: when sse=true the dispatcher is promoting this connection to a
	// held-open event-stream — `body` is the initial frame and `sse_rt` is the
	// runtime whose subscriber set this fd joins. listener_callback writes the
	// prelude, holds the fd, and subscribes it instead of a one-shot response.
	sse    bool
	sse_rt int
	// #609 changed-panel SSE: the fd opted into delta frames; sse_seq is its
	// initial high-water commit_seq (the initial full frame covers it).
	sse_delta bool
	sse_seq   u64
	// Generic SSE topic (#28): when sse=true and sse_topic is non-empty, the fd
	// joins the named string-keyed topic in the generic registry instead of an
	// xap runtime's set — the concurrent-SSE path for `[$http:serve]` handlers
	// (a handler returns `[sse-subscribe topic="…" [event …]?]`; any other
	// handler fans out with `[$http:sse-publish "…" [event …]]`).
	sse_topic string
}

// listener_callback is the picoev request callback — a TOP-LEVEL fn (no
// closure) so V's C-callback ABI gets a clean function pointer. picoev
// has already accepted, read, and parsed the request via picohttpparser
// by the time we are called.
__global (
	cx_http_gc_lock   &sync.Mutex
	cx_http_gc_count  u64
	cx_http_gc_every  u64
	cx_http_gc_bytes  u64
	cx_http_gc_metric GcChurnMetric
	cx_http_gc_init   bool
)

// ── #57 reactor UAF fix: retain &ListenerHandler as a vgc root ───────────────
// picoev stores the handler only as a `voidptr` (Config/Picoev.user_data),
// which vgc cannot trace. The only V-typed reference is the local `h` in
// start_*_listener, which goes dead after spawn (and during the block-loop).
// So the collector frees the handler AND its enclosing_bindings strings while
// the reactor threads still read them via the voidptr — under concurrent
// multi-reactor load a reactor's per-request `env.clone()` then reads a freed
// binding string and crashes in builtin__string_clone (#57: the residual
// "vgc frees a live object" UAF; boehm was clean because its conservative scan
// kept the handler alive). Retaining each handler here roots it: the fixed
// array's pointer slots live in the __DATA segment, which vgc scans
// conservatively (vgc_data_segments), so the handler + its bindings stay
// marked. Handlers live for the process lifetime (no stop path — see the
// KNOWN LIMITATION), so retaining forever is correct and bounded (a handful
// per process, capped well under the slot count).
__global (
	cx_http_live_handlers [256]&ListenerHandler
	cx_http_live_count    int
	cx_http_live_lock     &sync.Mutex
	cx_stackcheck_done    bool // #145 deep-fix A: one-shot guard for the cx_stackcheck STACKMISS probe
)

// retain_listener_handler pins `h` so vgc never reclaims it while reactors hold
// it only through picoev's untraced voidptr user_data (#57).
fn retain_listener_handler(h &ListenerHandler) {
	cx_http_live_lock.lock()
	if cx_http_live_count < 256 {
		cx_http_live_handlers[cx_http_live_count] = h
		cx_http_live_count++
	}
	cx_http_live_lock.unlock()
}

// http_reactor_maybe_collect drives a periodic GC collection from the reactor
// request loop (#57). The per-request path allocates transient garbage — the
// parsed [request], the handler's comprehension results and cx:parse ASTs, the
// [response] tree — that is dead once the response is written. vgc's auto-collect
// (the heap-doubling trigger) does NOT fire on the reactor's allocation pattern,
// so this garbage accumulates monotonically until malloc returns null →
// `V panic: memory allocation failure` (the reported OOM). It is genuinely
// reclaimable, not rooted: forcing a collect holds RSS to the working set
// (verified — a 200-item `[?for]` handler grows unbounded past 1.4 GB at 2000
// requests without this; with periodic collects it plateaus near baseline,
// ~50 MB).
//
// The collect is gated by CHURN GROWTH, not request count. A request-count gate
// cannot serve both handler shapes: a small count (the old default 64) fires a
// global STW collect ~hundreds of times/sec under load, which serialized every
// reactor thread and cut throughput ~3x (125k→61k single, and NEGATIVE
// multi-reactor scaling); a large count would OOM a heavy handler. Instead we
// collect once a churn metric has grown by `cx_http_gc_bytes` since the last
// collect: a light handler barely allocates so it almost never trips (full
// throughput + multi-reactor scaling restored), while a heavy value-building
// handler trips every few requests so committed pages — and thus RSS — stay
// bounded (#57/#131).
//
// The metric defaults to .allocated (the total_alloc churn delta). MEASURED on
// the #131 repro (single reactor, 20 s of /heavy churn): .allocated holds RSS
// dead flat at ~49 MB, while .committed climbs unbounded at EVERY threshold
// (512 KB → 138 MB and rising, 1 MB → 149 MB and rising) — committed bytes are
// monotonic on new carves and never returned, so gating on their delta cannot
// flatten RSS once carves outpace the gate. Collecting on allocation churn
// instead keeps the free-span pool ahead of demand, so no new spans carve and
// RSS sits at the working-set floor. CX_HTTP_GC_METRIC=committed opts back to the
// committed delta (cheaper read, but does not bound RSS for #131-shaped loads).
// The mechanics (metric read, single-collector window claim, collect, rebase)
// live in builtin.gc_collect_if_churned; only policy stays here.
//
// DEFAULT = DISABLED (#71): vgc's adaptive pacer (third_party/v, cx #71) now
// reclaims request transients by construction — a churn-heavy handler with a
// small live set collects every few MB at the collector's own trigger, holding
// RSS at the working-set floor without any host-side drive (guard:
// http_reactor_rss_bound_test.v runs the #131 heavy shape with this gate off).
// The churn gate stays available as an ops override for workloads that need a
// HOST-CHOSEN pace: CX_HTTP_GC_KB sets the threshold in KB, CX_HTTP_GC_MB in MB
// (precedence; 1 MB — the vgc accounting flush granularity — is the useful
// floor for .allocated). Legacy CX_HTTP_GC_EVERY (request count) is likewise
// honored only when explicitly set.
fn http_reactor_maybe_collect() {
	cx_http_gc_lock.lock()
	if !cx_http_gc_init {
		cx_http_gc_init = true
		cx_http_gc_bytes = 0 // disabled by default — the vgc adaptive pacer owns pacing (#71)
		if ov := os.getenv_opt('CX_HTTP_GC_KB') {
			k := ov.i64()
			if k >= 0 {
				cx_http_gc_bytes = u64(k) * 1024 // 0 ⇒ disabled
			}
		}
		if ov := os.getenv_opt('CX_HTTP_GC_MB') {
			k := ov.i64()
			if k >= 0 {
				cx_http_gc_bytes = u64(k) * 1024 * 1024 // precedence; 0 ⇒ disabled
			}
		}
		cx_http_gc_metric = .allocated
		if os.getenv('CX_HTTP_GC_METRIC') == 'committed' {
			cx_http_gc_metric = .committed
		}
		// Legacy request-count gate — only when explicitly set; takes precedence.
		if ov := os.getenv_opt('CX_HTTP_GC_EVERY') {
			k := ov.i64()
			if k >= 0 {
				cx_http_gc_every = u64(k)
			}
		}
	}
	every := cx_http_gc_every
	threshold := cx_http_gc_bytes
	metric := cx_http_gc_metric
	mut count_hit := false
	if every > 0 {
		cx_http_gc_count++
		if cx_http_gc_count >= every {
			cx_http_gc_count = 0
			count_hit = true
		}
	}
	cx_http_gc_lock.unlock()
	// Collect outside the lock; the STW pause must not serialize other reactor
	// threads behind a held mutex. The churn seam does its own atomic window
	// claim, so concurrent reactors won't double-collect.
	if count_hit {
		gc_collect()
	} else {
		gc_collect_if_churned(threshold, metric)
	}
}

// ── #275: handlers off reactors — the bounded dispatch-executor pool ─────────
//
// A request handler is arbitrary cx code: it may sleep, dial upstreams, or call
// a model whose generation takes minutes. Evaluating it ON a picoev reactor
// thread parks that reactor; at the default min(4, cores) fan-out, four slow
// upstream calls froze the ENTIRE HTTP plane — health checks and SSE pushes
// included, so supervised deployments were wedge-killed (the third marine-helm
// wedge mechanism; forensics on the issue). The client whole-request timeout
// (http §4.5) bounds each park at the request budget; it cannot remove the class.
//
// Model (xap_architecture §11): reactors own sockets — accept, read, parse,
// disconnect reaping — and never evaluation. A parsed request is COPIED off the
// reactor's per-fd read buffer and enqueued; K executor threads dequeue, run
// dispatch_request, and write the response to the fd directly (fd writes are
// cross-thread-safe, backpressure-correct and SIGPIPE-immune — write_all_fd).
// When the queue is full the REACTOR answers 503 inline (a constant string, no
// evaluation): saturation degrades loudly, a wedge is impossible by construction.
//
// Fd lifecycle: a job holds its fd (the §24 held-fd set — idle-timeout-exempt)
// for the dispatch duration. A peer disconnect mid-dispatch defers the socket
// close to the executor (close_conn deregisters the fd, the number stays
// allocated), so a late response write can never land on a recycled fd. A
// pipelined request arriving while one is in flight queues per-fd and runs in
// order — one in-flight dispatch per connection.
//
// Sizing (env knobs, deploy-time ops config like CX_HTTP_N): CX_HTTP_EXEC
// executor threads (default 16 — deliberately ABOVE the reactor count: an
// executor parked on a bounded upstream call is cheap, a frozen serve plane is
// not; eval-side GC-lock contention only involves RUNNING mutators, so parked
// executors don't pay it) and CX_HTTP_QUEUE pending jobs (default 1024).
// XspReqHdrs carries the three §4.8 rule-2 possession-proof headers (and the
// handshake's channel locator) from the reactor to the dispatcher. Empty on
// every request that doesn't send them — the common case costs three empty
// strings, nothing else.
struct XspReqHdrs {
mut:
	channel string
	counter string
	proof   string
}

struct DispatchJob {
mut:
	h      &ListenerHandler = unsafe { nil }
	method string
	path   string
	body   string
	xsp    XspReqHdrs
	// every wire header (cloned off the reactor's read buffer) — the
	// module-serve `.handler` mode surfaces them on the [request] element
	// per the http.md locked server-received shape (a handler reads e.g.
	// the Authorization bearer; previously [headers] was always empty).
	hdrs []WireHeader
	fd   int
}

// Initialized in the module init() (stdlib_codec.v — one init per module,
// before any thread): a zero-valued VALUE-typed sync.Mutex global is not a
// usable pthread mutex on Darwin, so it MUST be a reference created by
// sync.new_mutex(), and the maps need their explicit empty-map init.
//
// cx_disp_flags is the LOCK-FREE fast path: one atomic flags byte per fd
// (bit0 in-flight, bit1 close-pending, bit2 has-pending). The common request
// cycle is two CASes — admit 0->1 on the reactor, finish 1->0 on the executor
// — with no mutex and no kernel sync (a mutex pair per request across 16
// executors + reactors measured as a hard serialization point). The mutex
// guards only the RARE states: a pipelined request queuing behind an
// in-flight one (bit2 + cx_disp_pending) and a peer disconnect mid-dispatch
// (bit1 + the deferred close). Flag-state invariants: bit1/bit2 are only ever
// set while bit0 is set; every terminal path clears to 0.
__global (
	cx_disp_mu      &sync.Mutex
	cx_disp_started bool
	cx_disp_flags   [1024]u8 // picoev max_fds mirror (accept rejects fds >= 1024)
	cx_disp_pending map[int][]DispatchJob
)

// ── #280: the handoff queue — bounded MPMC ring + parked-executor tokens ─────
//
// The queue between reactors and executors was a V `chan DispatchJob`. On the
// serve57/no-op microbench that chan WAS the dispatch tax; sampled under wrk
// load (12t/200c, no-op handler, this box):
//
//   - 48% of a reactor's busy samples sat inside `channel_select_lang`: the
//     `select … else` enqueue heap-allocates three arrays + a Subscription
//     list, inits AND destroys a pthread mutex+cond Semaphore, takes the
//     subscriber spinlock twice and calls rand.intn — per request, even
//     though the else-arm never waits. Its allocations also tripped GC
//     safepoints mid-enqueue (vgc_park_spill from inside the select).
//   - The chan's ONE readsem backs every parked executor. Semaphore.post
//     takes the internal pthread mutex whenever count <= 1 — i.e. on nearly
//     every push at steady load (queue oscillates empty<->one) — so 16
//     executors + all reactors serialize on a single pthread mutex
//     (__psynch_mutexwait was the top reactor-side kernel cost). Worse, each
//     GC cycle signal-interrupts all 16 parked cond_waits, and every one of
//     them re-acquires that same shared mutex on wake — a contention spike
//     per collection.
//
// Measured effect: no-op rps scaled INVERSELY with pool size (default 16
// executors ≈ 86k rps; 4 ≈ 128k; reactor-inline reference ≈ 125k). The pool
// default stays deliberately large for blocking tolerance (#275/#279), so the
// queue must make idle executors FREE instead of shrinking the pool.
//
// Replacement (issue #280 candidate (a)):
//   - A bounded MPMC ring (Vyukov sequence counters, power-of-two capacity,
//     cursors on their own cache lines). Push and pop are one CAS + two
//     seq_cst loads/stores each — no mutex, no semaphore, no allocation.
//     The ring array is a __global, so vgc roots the queued jobs' payloads
//     (same conservative DATA-segment scan that roots cx_http_live_handlers).
//   - Parking: each executor owns a PRIVATE semaphore; parked executors push
//     their id onto a LIFO stack (cx_disp_park_mu guards the stack — parking
//     is the idle path, never the loaded path). A reactor that pushed a job
//     wakes at most ONE executor, and only when the ring backlog exceeds the
//     count of executors already spinning for work (see cx_dispatch_wake_one)
//     — at steady load that gate is two atomic loads and the reactor never
//     touches a lock or the kernel. LIFO keeps the same few executors hot
//     (cache-warm) while the reserve stays parked and contention-free.
//
// No-lost-wake protocol (eventcount): the executor REGISTERS (stack push +
// atomic count store), RE-CHECKS the ring, and only then sleeps; the producer
// PUSHES, then reads the parked count. All ring/count operations are seq_cst,
// so either the producer's count-read sees the registration (and posts a
// token), or the executor's re-check sees the pushed job. A token posted to
// an executor that deregistered after consuming work on the re-check is
// retained by its private semaphore and surfaces as one spurious re-check on
// its NEXT park — harmless. Shutdown/drain is unchanged: executors live for
// the process (the listener has no stop path — see KNOWN LIMITATION), and a
// shed on ring-full stays the reactor-inline 503.
struct DispatchSlot {
mut:
	seq u64
	job DispatchJob
}

__global (
	cx_disp_ring    []DispatchSlot // pow2 capacity (≥ 2 — see try_push); slot.seq per Vyukov MPMC
	cx_disp_qcap    u64 // the REQUESTED logical capacity (CX_HTTP_QUEUE) — shed above this
	cx_disp_qmask   u64
	cx_disp_enq_pad [16]u64 // [0] = enqueue cursor, alone on its cache line
	cx_disp_deq_pad [16]u64 // [0] = dequeue cursor, alone on its cache line
	cx_disp_sems    []&sync.Semaphore // one PRIVATE semaphore per executor
	cx_disp_parked  []int // LIFO stack of parked executor ids (under cx_disp_park_mu)
	cx_disp_park_n  u32   // atomic mirror of cx_disp_parked.len (producer fast path)
	cx_disp_spin_n  u32   // atomic count of executors currently in the try_pop spin
	cx_disp_nexec   int   // pool size K (set once at start, read-only after)
	cx_disp_hot_w   int   // instant-wake width W (set once at start; see sentinel doc)
	cx_disp_boost   u32   // outstanding sentinel escalations (bypass demotion once each)
	cx_disp_park_mu &sync.Mutex
)

fn C.atomic_load_byte(voidptr) u8
fn C.atomic_store_byte(voidptr, u8)
fn C.atomic_compare_exchange_strong_byte(voidptr, voidptr, u8) bool
fn C.atomic_load_u32(voidptr) u32
fn C.atomic_store_u32(voidptr, u32)
fn C.atomic_fetch_add_u32(voidptr, u32) u32
fn C.atomic_fetch_sub_u32(voidptr, u32) u32
fn C.atomic_compare_exchange_strong_u32(voidptr, voidptr, u32) bool
fn C.atomic_load_u64(voidptr) u64
fn C.atomic_store_u64(voidptr, u64)
fn C.atomic_compare_exchange_weak_u64(voidptr, voidptr, u64) bool

// cx_disp_ring_try_push enqueues one job (multi-producer safe). Returns false
// when the queue is full — the caller sheds 503, exactly like the old
// select-else. One weak CAS on the enqueue cursor + a release-ordered (seq_cst
// here) sequence publish; no locks, no kernel, no allocation.
fn cx_disp_ring_try_push(job DispatchJob) bool {
	// Logical-capacity shed (#355). The PHYSICAL ring is floored at 2 slots
	// because Vyukov MPMC degenerates at capacity 1: with qmask == 0 the
	// producer's post-write marker (seq = pos+1) is numerically identical to
	// the consumer's post-pop marker (seq = pos + qmask + 1), so a second
	// producer saw the UNCONSUMED slot as writable — it overwrote the pending
	// job (request silently lost, never answered), full-detection never
	// returned false (the 503 shed never fired), and a consumer whose
	// expected seq was skipped span forever in the reload branch. The
	// CX_HTTP_QUEUE contract (at most qcap pending jobs, shed beyond) is
	// therefore enforced HERE against the cursors. Read order enq-then-deq:
	// a push or pop completing between the loads only makes the computed
	// depth SMALLER than the instantaneous truth (stale-small enq, fresh
	// deq), so a race can transiently over-admit (bounded by the producer
	// count; the physical ring still bounds it, and the next push sheds) but
	// the check never falsely 503s a request the queue had room for.
	enq := C.atomic_load_u64(&cx_disp_enq_pad[0])
	deq := C.atomic_load_u64(&cx_disp_deq_pad[0])
	if enq - deq >= cx_disp_qcap {
		return false
	}
	mut pos := C.atomic_load_u64(&cx_disp_enq_pad[0])
	for {
		idx := int(pos & cx_disp_qmask)
		seq := C.atomic_load_u64(&cx_disp_ring[idx].seq)
		if seq == pos {
			mut expected := pos
			if C.atomic_compare_exchange_weak_u64(&cx_disp_enq_pad[0], &expected, pos + 1) {
				cx_disp_ring[idx].job = job
				C.atomic_store_u64(&cx_disp_ring[idx].seq, pos + 1)
				return true
			}
			pos = expected
		} else if seq < pos {
			return false // slot still holds an unconsumed lap — ring full
		} else {
			pos = C.atomic_load_u64(&cx_disp_enq_pad[0])
		}
	}
	return false
}

// cx_disp_ring_try_pop dequeues one job (multi-consumer safe). Returns false
// when the ring is empty.
fn cx_disp_ring_try_pop(mut job DispatchJob) bool {
	mut pos := C.atomic_load_u64(&cx_disp_deq_pad[0])
	for {
		idx := int(pos & cx_disp_qmask)
		seq := C.atomic_load_u64(&cx_disp_ring[idx].seq)
		if seq == pos + 1 {
			mut expected := pos
			if C.atomic_compare_exchange_weak_u64(&cx_disp_deq_pad[0], &expected, pos + 1) {
				job = cx_disp_ring[idx].job
				// Release the payload's string refs from the slot so vgc's
				// conservative scan of the (rooted) ring cannot keep a
				// completed request's buffers alive for a whole lap.
				cx_disp_ring[idx].job = DispatchJob{}
				C.atomic_store_u64(&cx_disp_ring[idx].seq, pos + cx_disp_qmask + 1)
				return true
			}
			pos = expected
		} else if seq <= pos {
			return false // slot not yet published — ring empty
		} else {
			pos = C.atomic_load_u64(&cx_disp_deq_pad[0])
		}
	}
	return false
}

// cx_dispatch_wake_one hands a park token to one parked executor — but ONLY
// when the ring backlog exceeds the number of executors currently spinning
// for work. An unconditional wake-on-push re-created the kernel round-trip
// this ring exists to remove: with a deliberately-large pool (#279) some
// executors are parked at ANY load level, so `parked > 0` alone woke one per
// request, and the woken executor usually lost the race to a hot spinner and
// re-parked — measured as a park/wake churn that ate the ring's win (and
// degraded over runtime). The `depth > spinning` gate adapts by itself:
//   - no-op flood: the hot subset spins between requests, depth stays at or
//     under the spinner count, the reserve stays parked and untouched;
//   - slow handlers (#275): occupied executors are not spinning, so depth
//     immediately exceeds the spinner count and the reserve is woken 1:1
//     with the backlog — the isolation property is unchanged.
// A pusher that skips the wake because a spinner was up can never strand the
// job: a spinner only parks after RE-CHECKING the ring post-registration, so
// the job is either drained by the spinner or collected at that re-check.
//
// HOT-WIDTH CAP (W = cx_disp_hot_w): instant wakes stop once W executors are
// already awake. Uncapped, a saturating CPU-bound handler (serve57's 64 KB
// body build) grew the awake set to the full pool and COLLAPSED throughput —
// 16 concurrent allocation-heavy mutators cost more in GC stop-the-world
// rendezvous + allocator contention than their parallelism returns (measured:
// serve57 12.8k rps at width 16 vs 21.9k at width 8, reactor-inline 21.3k;
// the old chan produced ~20.5k at K=16 only because its serialized handoff
// ACCIDENTALLY throttled the awake set). The reserve beyond W still exists
// for what #279 sized it for — absorbing BLOCKED handlers — and is grown by
// the progress sentinel below, which distinguishes "stuck" from "busy"
// without any handler-cost oracle. All gate reads are approximate (racy)
// heuristics — correctness lives in the register→re-check→sleep protocol
// plus the sentinel's periodic re-check, not here.
fn cx_dispatch_wake_one() {
	depth := C.atomic_load_u64(&cx_disp_enq_pad[0]) - C.atomic_load_u64(&cx_disp_deq_pad[0])
	if depth <= u64(C.atomic_load_u32(&cx_disp_spin_n)) {
		return
	}
	parked := C.atomic_load_u32(&cx_disp_park_n)
	if parked == 0 {
		return
	}
	if cx_disp_nexec - int(parked) >= cx_disp_hot_w {
		return // W already awake — growth belongs to the progress sentinel
	}
	cx_dispatch_post_token()
}

// cx_dispatch_post_token pops one parked executor and posts its private
// semaphore. Shared by the capped instant-wake and the sentinel escalation.
fn cx_dispatch_post_token() {
	cx_disp_park_mu.lock()
	if cx_disp_parked.len == 0 {
		cx_disp_park_mu.unlock()
		return
	}
	id := cx_disp_parked.pop()
	C.atomic_store_u32(&cx_disp_park_n, u32(cx_disp_parked.len))
	cx_disp_park_mu.unlock()
	mut sem := cx_disp_sems[id]
	sem.post()
}

// cx_dispatch_sentinel — the oracle-free escalation that lets the pool grow
// past the hot width W exactly when growing helps. Every tick it compares the
// dequeue cursor against the previous tick: jobs queued AND zero dequeues in
// a whole tick means every awake executor is STUCK inside a handler (parked
// on an upstream, a lock, a sleep — the #275 wedge shape), so one more
// reserve is woken; repeated stuck ticks keep escalating, one per tick, up to
// the full pool. A CPU-bound saturating handler NEVER trips it — its cursor
// advances every few hundred µs — so the awake set stays at W and the GC
// collapse above cannot re-form. The discriminator is PROGRESS, not demand
// and not handler-cost prediction (issue #280's non-goal): a queue can be
// deep forever under saturation, but it can only be FROZEN when dispatch has
// genuinely stalled. Worst-case added latency for a fast request behind W
// blocked handlers is one tick (2 ms) per additional blocked handler —
// invisible against the §4.5 request budgets and the isolation contract
// (http_slow_handler_isolation_test asserts ~20 ms probes). The sentinel is
// also a belt-and-braces backstop for any missed wake: ANY queued job with
// a fully-parked pool is dispatched within a tick.
fn cx_dispatch_sentinel() {
	mut prev_deq := u64(0)
	for {
		// #316: the tick sleep is a GC-safe region — the sentinel would otherwise
		// be a mach-suspend straggler on every collection (it never reaches an
		// alloc poll while sleeping). nanosleep allocates nothing and stores no
		// GC pointers; prev_deq and the globals it reads on wake are covered.
		gc_safe_region_enter()
		time.sleep(2 * time.millisecond)
		gc_safe_region_exit()
		deq := C.atomic_load_u64(&cx_disp_deq_pad[0])
		depth := C.atomic_load_u64(&cx_disp_enq_pad[0]) - deq
		if depth > 0 && deq == prev_deq && C.atomic_load_u32(&cx_disp_park_n) > 0 {
			// The boost credit lets the woken reserve bypass width demotion
			// for exactly ONE collect — otherwise it would hand its slot
			// straight back (awake > W) before it could reach the stuck-
			// behind job this escalation exists for.
			C.atomic_fetch_add_u32(&cx_disp_boost, 1)
			cx_dispatch_post_token()
		}
		prev_deq = deq
	}
}

// cx_dispatch_deregister removes executor `id`'s park registration, if a
// producer has not already popped it. Called on every exit from the park
// cycle so an executor never leaves a live entry behind (see the executor's
// re-park loop).
fn cx_dispatch_deregister(id int) {
	cx_disp_park_mu.lock()
	for i, pid in cx_disp_parked {
		if pid == id {
			cx_disp_parked.delete(i)
			C.atomic_store_u32(&cx_disp_park_n, u32(cx_disp_parked.len))
			break
		}
	}
	cx_disp_park_mu.unlock()
}

const cx_disp_503 = 'HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nserver busy - try again\n'

// cx_dispatch_defer_close_probe — called by picoev's close_conn (reactor
// thread) when a connection dies. In-flight fd: set the close-pending bit and
// tell picoev to defer (the executor closes after the job). Also drop any
// queued pipeline jobs — their client is gone.
fn cx_dispatch_defer_close_probe(fd int) bool {
	if fd < 0 || fd >= 1024 {
		return false
	}
	for {
		f := C.atomic_load_byte(&cx_disp_flags[fd])
		if f & 1 == 0 {
			return false // not in flight — close normally
		}
		mut expected := f
		if C.atomic_compare_exchange_strong_byte(&cx_disp_flags[fd], &expected, f | 2) {
			// Deferred. Drop queued pipeline jobs under the mutex — the
			// executor's slow path takes the same mutex before reading them.
			cx_disp_mu.lock()
			cx_disp_pending.delete(fd)
			cx_disp_mu.unlock()
			return true
		}
		// Lost the race (executor finished and cleared, or a pending bit
		// flipped) — reload and re-decide.
	}
	return false
}

// cx_dispatch_start_executors spawns the pool once (called at listener start,
// before any reactor can enqueue).
fn cx_dispatch_start_executors() {
	cx_disp_mu.lock()
	defer {
		cx_disp_mu.unlock()
	}
	if cx_disp_started {
		return
	}
	cx_disp_started = true
	mut nexec := 16
	if ov := os.getenv_opt('CX_HTTP_EXEC') {
		k := ov.int()
		if k >= 1 {
			nexec = k
		}
	}
	mut qcap := 1024
	if ov := os.getenv_opt('CX_HTTP_QUEUE') {
		k := ov.int()
		if k >= 1 {
			qcap = k
		}
	}
	// The MPMC ring indexes with a mask, so the PHYSICAL capacity is rounded
	// UP to the next power of two (1024 default stays 1024) — never silently
	// reduced — and floored at 2: Vyukov sequence arithmetic degenerates at
	// capacity 1 (#355; see cx_disp_ring_try_push). The REQUESTED capacity is
	// kept in cx_disp_qcap and enforced at push, so CX_HTTP_QUEUE=1 still
	// means exactly one pending job.
	cx_disp_qcap = u64(qcap)
	mut cap2 := u64(2)
	for cap2 < u64(qcap) {
		cap2 <<= 1
	}
	cx_disp_ring = []DispatchSlot{len: int(cap2)}
	for i in 0 .. int(cap2) {
		cx_disp_ring[i].seq = u64(i) // slot i is writable at lap cursor i (Vyukov init)
	}
	cx_disp_qmask = cap2 - 1
	cx_disp_enq_pad[0] = 0
	cx_disp_deq_pad[0] = 0
	cx_disp_park_mu = sync.new_mutex()
	cx_disp_parked = []int{cap: nexec}
	cx_disp_park_n = 0
	cx_disp_nexec = nexec
	// Hot width W: how many executors the dispatcher keeps awake for
	// THROUGHPUT; the rest are the blocking reserve, grown only by the
	// progress sentinel. min(K, 8) measured best for both bench shapes
	// (no-op AND the serve57 heavy body) on a multi-core box — wider only
	// adds GC-rendezvous cost. CX_HTTP_HOT overrides (deploy-time ops
	// config like CX_HTTP_EXEC; capped at K, floor 1 — never silently
	// reinterpreted).
	mut hotw := if nexec < 8 { nexec } else { 8 }
	if ov := os.getenv_opt('CX_HTTP_HOT') {
		k := ov.int()
		if k >= 1 {
			hotw = if k > nexec { nexec } else { k }
		}
	}
	cx_disp_hot_w = hotw
	cx_disp_sems = []&sync.Semaphore{cap: nexec}
	for _ in 0 .. nexec {
		cx_disp_sems << sync.new_semaphore()
	}
	picoev.cx_set_dispatch_defer_close(cx_dispatch_defer_close_probe)
	for i in 0 .. nexec {
		spawn cx_dispatch_executor(i)
	}
	spawn cx_dispatch_sentinel()
	if os.getenv('CX_HTTP_EXEC_TRACE') != '' {
		eprintln('cx http: dispatch pool up — ${nexec} executors (hot width ${hotw}), ring cap ${cap2}')
	}
}

// cx_dispatch_finish releases a completed job's fd — or hands back the next
// pipelined job for it. Returns the follow-on job when one is queued.
// `keep_hold` (SSE promotion) transfers the held mark to the SSE layer instead
// of releasing it — the fd stays out of the idle-timeout reaper for the
// stream's life, exactly as the reactor-inline path did.
// Fast path: flags == 1 (in-flight, nothing pending) -> one CAS, no mutex.
fn cx_dispatch_finish(fd int, keep_hold bool) ?DispatchJob {
	if !keep_hold {
		mut expected := u8(1)
		if C.atomic_compare_exchange_strong_byte(&cx_disp_flags[fd], &expected, 0) {
			picoev.cx_release_fd(fd)
			return none
		}
	}
	// Slow path: close-pending and/or pipelined jobs (or an SSE promotion,
	// which always resolves state under the mutex).
	cx_disp_mu.lock()
	f := C.atomic_load_byte(&cx_disp_flags[fd])
	if f & 2 != 0 {
		// The peer vanished mid-dispatch; picoev deferred the close to us.
		cx_disp_pending.delete(fd)
		C.atomic_store_byte(&cx_disp_flags[fd], 0)
		cx_disp_mu.unlock()
		picoev.cx_release_fd(fd)
		picoev.cx_close_socket_fd(fd)
		return none
	}
	if !keep_hold {
		// Absent key == empty queue (nothing pipelined for this fd).
		mut q := cx_disp_pending[fd] or { []DispatchJob{} }
		if q.len > 0 {
			next := q[0]
			q.delete(0)
			if q.len == 0 {
				cx_disp_pending.delete(fd)
				C.atomic_store_byte(&cx_disp_flags[fd], 1) // in-flight, drained
			} else {
				cx_disp_pending[fd] = q
			}
			cx_disp_mu.unlock()
			return next
		}
	}
	cx_disp_pending.delete(fd)
	C.atomic_store_byte(&cx_disp_flags[fd], 0)
	cx_disp_mu.unlock()
	if !keep_hold {
		picoev.cx_release_fd(fd)
	}
	return none
}

// cx_dispatch_executor — one pool thread: dequeue, evaluate, respond, repeat.
//
// SPIN-THEN-PARK dequeue on the #280 MPMC ring: a short try_pop spin (~µs
// budget) keeps executors hot under load — a push then finds no parked
// receiver and both sides stay userspace CAS + copy — while an idle executor
// parks on its PRIVATE semaphore after one budget, costing nothing until a
// reactor hands it a token (cx_dispatch_wake_one). The register → re-check →
// sleep order is the no-lost-wake protocol documented at the ring globals; a
// stale token (producer popped us right as the re-check found work) is
// retained by the semaphore and shows up as one spurious re-check on the next
// park — never a lost job.
fn cx_dispatch_executor(id int) {
	mut sem := cx_disp_sems[id]
	for {
		mut job := DispatchJob{}
		mut got := false
		// WIDTH DEMOTION: if more than W executors are awake (a sentinel
		// escalation, or a spurious one after a long GC pause froze the
		// cursor across a tick), hand the slot back BETWEEN jobs — park
		// without collecting. Collecting here instead would keep the
		// oversized awake set working under a saturating backlog forever
		// (the width could never shrink — measured as a permanent GC-
		// rendezvous ratchet). Deliberately no ring re-check before this
		// park: a job pushed into the registration window is covered by the
		// sentinel within one tick, and the instant-wake gate refills the
		// set to W (LIFO — the just-parked, cache-warm executor) at once. A
		// boost credit (sentinel escalation for a genuinely STUCK pool)
		// bypasses one demotion so the escalated reserve actually reaches
		// the stuck-behind job.
		for cx_disp_nexec - int(C.atomic_load_u32(&cx_disp_park_n)) > cx_disp_hot_w {
			mut bo := C.atomic_load_u32(&cx_disp_boost)
			mut boosted := false
			for bo > 0 {
				mut exp := bo
				if C.atomic_compare_exchange_strong_u32(&cx_disp_boost, &exp, bo - 1) {
					boosted = true
					break
				}
				bo = exp
			}
			if boosted {
				break
			}
			cx_disp_park_mu.lock()
			cx_disp_parked << id
			C.atomic_store_u32(&cx_disp_park_n, u32(cx_disp_parked.len))
			cx_disp_park_mu.unlock()
			// #316: park inside a GC-safe region so the STW rendezvous skips this
			// thread (no mach suspend/resume, no park-wait burn, no signal-
			// interrupted cond_wait) — the suspend set is the AWAKE set. Contract
			// holds: Semaphore.wait is pure atomics + pthread (no allocation, no
			// GC-pointer stores), and everything this frame uses afterwards (sem,
			// id, job) was live in the frame/registers at enter. Exit blocks if a
			// collection is mid-flight (world-resume handshake). try_wait first:
			// a token already posted (wake churn under load) consumes WITHOUT the
			// region — the register spill is only worth paying for a real sleep
			// (measured: always-wrapping cost ~8-10% at the CX_HTTP_HOT=16
			// maximal-churn extreme, where every push wakes a parked executor).
			if !sem.try_wait() {
				gc_safe_region_enter()
				sem.wait()
				gc_safe_region_exit()
			}
			cx_dispatch_deregister(id)
		}
		// Advertise the spin so pushers skip the wake while we are collecting
		// (the cx_dispatch_wake_one gate); cleared before parking OR running.
		C.atomic_fetch_add_u32(&cx_disp_spin_n, 1)
		for _ in 0 .. 500 {
			if cx_disp_ring_try_pop(mut job) {
				got = true
				break
			}
		}
		C.atomic_fetch_sub_u32(&cx_disp_spin_n, 1)
		for !got {
			// Register as parked, then RE-CHECK the ring before sleeping.
			cx_disp_park_mu.lock()
			cx_disp_parked << id
			C.atomic_store_u32(&cx_disp_park_n, u32(cx_disp_parked.len))
			cx_disp_park_mu.unlock()
			if cx_disp_ring_try_pop(mut job) {
				got = true
			} else {
				// #316: same GC-safe park as the width-demotion path above,
				// including the try_wait churn fast path.
				if !sem.try_wait() {
					gc_safe_region_enter()
					sem.wait()
					gc_safe_region_exit()
				}
			}
			// Deregister our entry if still present — the producer that woke us
			// popped it, but on the found-work-at-re-check path (and on a wake
			// by a STALE token from an earlier cycle) the entry is still there.
			// Always clearing it here keeps the invariant: one stack entry per
			// parked executor, none for a running one — so a token can never
			// target a running executor twice.
			cx_dispatch_deregister(id)
			if !got && cx_disp_ring_try_pop(mut job) {
				got = true
			}
			// !got: raced away by a spinning executor (or stale token) — re-park.
		}
		for {
			$if cx_disp_trace ? {
				eprintln('disp: t=${time.ticks() % 1000000} run fd=${job.fd} ${job.method} ${job.path}')
			}
			w := dispatch_request(mut job.h, job.method, job.path, job.body, job.xsp,
				job.hdrs)
			if w.sse {
				// §24 SSE promotion — subscribe is atomic under the registry
				// lock; the initial frame is the readiness ack (see the topic
				// subscribe doc). The held mark transfers to the SSE layer.
				prelude := 'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n'
				if w.sse_topic != '' {
					cx_sse_topic_subscribe(w.sse_topic, job.fd, prelude + w.body)
				} else {
					xap_sse_subscribe(w.sse_rt, job.fd, prelude + w.body, w.sse_delta,
						w.sse_seq)
				}
				cx_dispatch_finish(job.fd, true)
				break
			}
			is_head := job.method.to_upper() == 'HEAD'
			send_all(job.fd, serialize_wire(w, is_head))
			// Reclaim this request's transients before the next one (#57). Runs
			// after the response is on the wire, so the collect never delays it.
			http_reactor_maybe_collect()
			if next := cx_dispatch_finish(job.fd, false) {
				job = next
				continue
			}
			break
		}
	}
}

fn listener_callback(data voidptr, req picohttpparser.Request, mut res picohttpparser.Response) {
	mut h := unsafe { &ListenerHandler(data) }
	// COPY the request strings: req.* are views into this reactor's per-fd read
	// buffer, which is reset/reused the moment this callback returns — the
	// executor must own its bytes.
	mut xsp := XspReqHdrs{}
	mut all_hdrs := []WireHeader{cap: int(req.num_headers)}
	for i in 0 .. req.num_headers {
		hn := req.headers[i].name
		all_hdrs << WireHeader{
			name:  hn.clone()
			value: req.headers[i].value.clone()
		}
		if hn.len < 9 || (hn[0] != `x` && hn[0] != `X`) {
			continue
		}
		lo := hn.to_lower()
		if lo == 'xsp-channel' {
			xsp.channel = req.headers[i].value.clone()
		} else if lo == 'xsp-counter' {
			xsp.counter = req.headers[i].value.clone()
		} else if lo == 'xsp-proof' {
			xsp.proof = req.headers[i].value.clone()
		}
	}
	job := DispatchJob{
		h:      h
		method: req.method.clone()
		path:   req.path.clone()
		body:   req.body.clone()
		xsp:    xsp
		hdrs:   all_hdrs
		fd:     res.fd
	}
	// Lock-free admit: CAS the fd's flags 0 -> in-flight. All admit/close events
	// for one fd run on its OWNING reactor loop (picoev per-loop fd ownership),
	// so this reactor is the only admitter for job.fd; the CAS races only the
	// executor's finish.
	mut expected := u8(0)
	if !C.atomic_compare_exchange_strong_byte(&cx_disp_flags[job.fd], &expected, 1) {
		// Busy: a pipelined request while one is in flight (rare) — queue it
		// per-fd under the mutex; the executor drains in order.
		cx_disp_mu.lock()
		mut exp2 := u8(0)
		if C.atomic_compare_exchange_strong_byte(&cx_disp_flags[job.fd], &exp2, 1) {
			// The in-flight job finished between the CAS and the lock —
			// admitted after all; fall through to the enqueue below.
			cx_disp_mu.unlock()
		} else {
			// Absent key == empty queue; append and write back under the mutex.
			mut q := cx_disp_pending[job.fd] or { []DispatchJob{} }
			if q.len < 64 {
				q << job
				cx_disp_pending[job.fd] = q
				// Publish the has-pending bit so the executor's finish takes the
				// mutex-guarded slow path. If the executor fast-finished while we
				// appended (bit0 gone), recover: this job is ours again.
				mut orphaned := false
				for {
					f := C.atomic_load_byte(&cx_disp_flags[job.fd])
					if f & 1 == 0 {
						orphaned = true
						break
					}
					mut e := f
					if C.atomic_compare_exchange_strong_byte(&cx_disp_flags[job.fd], &e, f | 4) {
						break
					}
				}
				if !orphaned {
					cx_disp_mu.unlock()
					return
				}
				cx_disp_pending.delete(job.fd)
				mut exp3 := u8(0)
				C.atomic_compare_exchange_strong_byte(&cx_disp_flags[job.fd], &exp3, 1)
				cx_disp_mu.unlock()
				// fall through to the enqueue below
			} else {
				cx_disp_mu.unlock()
				send_all(res.fd, cx_disp_503)
				return
			}
		}
	}
	// Hold BEFORE enqueue: the executor may complete (and release) the job the
	// instant it is queued; holding after would strand the mark. The hold makes
	// the fd idle-timeout-exempt for the dispatch and routes a mid-dispatch
	// disconnect through the deferred-close probe.
	picoev.cx_hold_fd(job.fd)
	$if cx_disp_trace ? {
		qlen := C.atomic_load_u64(&cx_disp_enq_pad[0]) - C.atomic_load_u64(&cx_disp_deq_pad[0])
		eprintln('disp: t=${time.ticks() % 1000000} enq fd=${job.fd} ${job.method} ${job.path} qlen=${qlen}/${cx_disp_qmask + 1}')
	}
	// #280: one CAS-push on the MPMC ring, then a wake only if the backlog
	// outruns the executors already spinning for work (cx_dispatch_wake_one)
	// — at steady load the whole enqueue is userspace and lock-free (the old
	// `select … else` paid three array allocations, a Semaphore init+destroy
	// and a contended pthread mutex per request; see the ring doc above).
	if cx_disp_ring_try_push(job) {
		cx_dispatch_wake_one()
	} else {
		// Ring full: shed load LOUDLY from the reactor — a constant
		// response, no evaluation. The plane stays responsive no matter
		// what handlers are doing (#275). Safe as a plain store: only this
		// reactor admits/sheds this fd, and no executor owns it (the job
		// never entered the queue).
		$if cx_disp_trace ? {
			eprintln('disp: t=${time.ticks() % 1000000} SHED fd=${job.fd} queue full')
		}
		C.atomic_store_byte(&cx_disp_flags[job.fd], 0)
		picoev.cx_release_fd(job.fd)
		send_all(res.fd, cx_disp_503)
	}
}

// send_all writes the full response on the connection fd, bypassing
// picoev's bounded per-fd write buffer (max_write) so a large static-file
// body is not capped. Delegates to write_all_fd; a false return means the
// peer is gone — picoev reaps the fd on its own disconnect read event.
fn send_all(fd int, data string) {
	write_all_fd(fd, data)
}

// write_all_fd writes `data` fully to a picoev-held NON-BLOCKING socket fd.
// The old `n <= 0 → break` loop had two failure modes on O_NONBLOCK fds:
// EAGAIN (peer not draining, buffer full) silently TRUNCATED the response
// mid-wire — a pane fetch under backpressure rendered blank — and EINTR
// dropped it entirely. EAGAIN now waits and retries (bounded: a peer that
// drains nothing for ~5s is treated as gone); EINTR retries immediately;
// EPIPE/ECONNRESET/anything else reports false and the caller drops the fd
// (with SIGPIPE ignored at the listener, a post-RST write is an EPIPE error,
// not a process kill — transport.picoev new()/setup_sock own that).
fn write_all_fd(fd int, data string) bool {
	mut off := 0
	mut stalled_ms := 0
	for off < data.len {
		n := unsafe { C.write(fd, voidptr(data.str + off), usize(data.len - off)) }
		if n > 0 {
			off += int(n)
			stalled_ms = 0
			continue
		}
		if n == 0 {
			return false
		}
		e := C.errno
		if e == C.EINTR {
			continue
		}
		if e == C.EAGAIN || e == C.EWOULDBLOCK {
			if stalled_ms >= 5000 {
				return false
			}
			time.sleep(1 * time.millisecond)
			stalled_ms += 1
			continue
		}
		return false
	}
	return true
}

// dispatch_request routes one request to its resource handler and
// returns the wire-ready response. Mirrors the former net.http
// `ListenerHandler.handle`, retargeted onto picohttpparser inputs.
fn dispatch_request(mut h ListenerHandler, raw_method string, raw_path string, raw_body string, xsp_hdrs XspReqHdrs, wire_hdrs []WireHeader) WireResp {
	// cx-xap `[$xap:serve]` — dispatch the request against the runtime in V
	// (no CX closure). Renders the surface as text/html on GET, runs the
	// cascade on POST, and re-renders the swapped fragment (xap.md §9/§13.2).
	if h.mode == .xap {
		$if cx_envclone_trace ? {
			// #272 measurement probe: size + wall cost of the per-request env
			// clone, one line per request on stderr. Dev-diagnostic build only.
			ct0 := time.sys_mono_now()
			cb := h.enclosing_bindings.clone()
			cc := h.enclosing_closures.clone()
			cd := h.enclosing_dyn.clone()
			eprintln('cx#272 envclone: bindings=${cb.len} closures=${cc.len} dyn=${cd.len} clone_us=${(time.sys_mono_now() - ct0) / 1000}')
		}
		// #317: per-request TEMPLATE-ALIAS env — bindings + closures alias the
		// immutable listener-start snapshot read-only (bindings_shared /
		// closures_shared); a request that actually writes a binding realizes a
		// private copy via cow_bindings()/cow_closures() first. The former
		// unconditional map_clone pair here was ~30% of executor wall time on
		// trivial handlers (#280 profile). dyn_context follows the
		// build_param_call_env pattern: alias only when empty (an append to an
		// aliased empty array allocates fresh; a non-empty alias would share
		// spare capacity across executor threads).
		mut xenv := MatchEnv{
			bindings:        h.enclosing_bindings
			bindings_shared: true
			closures:        h.enclosing_closures
			closures_shared: true
			state:           unsafe { h.state }
			anon_counter:    0
			dyn_context:     if h.enclosing_dyn.len > 0 { h.enclosing_dyn.clone() } else { h.enclosing_dyn }
			scope:           h.enclosing_scope
		}
		return xap_dispatch_http(h.xap_rt, raw_method.to_upper(), raw_path, raw_body, xsp_hdrs, mut xenv)
	}
	// Module `[$http:serve url $handler]` — invoke the single CX handler
	// closure with the built [request] in a per-request env clone. No
	// resource table / routing (that is the directive's .service layer).
	if h.mode == .handler {
		method := raw_method.to_upper()
		mut path := raw_path
		mut query_nodes := []cx.Node{}
		if q := path.index('?') {
			// #627: the query rides the request as parsed [query-params].
			query_nodes = http_parse_query(path[q + 1..])
			path = path[..q]
		}
		// #317 template-alias request env (see the .xap branch above): zero
		// map clones on this hot path — the handler closure's call frame is
		// built fresh by build_param_call_env, and any in-place request-scope
		// write realizes a private copy first (cow_bindings/cow_closures).
		mut renv := MatchEnv{
			bindings:        h.enclosing_bindings
			bindings_shared: true
			closures:        h.enclosing_closures
			closures_shared: true
			state:           unsafe { h.state }
			anon_counter:    0
			dyn_context:     if h.enclosing_dyn.len > 0 { h.enclosing_dyn.clone() } else { h.enclosing_dyn }
			scope:           h.enclosing_scope
		}
		$if cx_stackcheck ? {
			// #145 deep-fix A: is renv's stack frame within the conservative root
			// scan's [sp, stack_base]? If &renv exceeds the registered stack_base it
			// sits ABOVE the recorded stack top -> never scanned -> the per-request
			// env root (and its key buffers) are swept-while-live. One-shot per
			// reactor (cx_stackcheck_done guard) to avoid log spam; non-masking.
			base := vgc_my_stack_base()
			renv_addr := usize(voidptr(&renv))
			if !cx_stackcheck_done {
				cx_stackcheck_done = true
				if base == 0 {
					eprintln('cx#145 STACKMISS: reactor UNREGISTERED (stack_base=0) — whole stack unscanned')
				} else if renv_addr > base {
					eprintln('cx#145 STACKMISS: &renv=0x${u64(renv_addr).hex()} > stack_base=0x${u64(base).hex()} (renv ABOVE scanned top — unscanned root)')
				} else {
					eprintln('cx#145 stackcheck OK: &renv=0x${u64(renv_addr).hex()} <= stack_base=0x${u64(base).hex()} (renv within scan top; miss is NOT a stack-bounds issue)')
				}
			}
		}
		// Forward the request body as a string scalar so the handler can read
		// `$request/body` for POST/PUT payloads (form-encoded or raw).
		body_node := cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(raw_body)
			data_type: cx.ScalarType.string_type
		})
		mut hdr_nodes := []cx.Node{cap: wire_hdrs.len}
		for wh in wire_hdrs {
			hdr_nodes << cx.Node(cx.Element{
				name:  'header'
				attrs: [
					cx.Attribute{
						name:  'name'
						value: cx.ScalarValue(wh.name)
					},
					cx.Attribute{
						name:  'value'
						value: cx.ScalarValue(wh.value)
					},
				]
			})
		}
		reqnode := build_request_node(method, path, []cx.Node{}, ?cx.Node(body_node),
			hdr_nodes, query_nodes)
		result := apply_fn_value(h.handler, [reqnode], mut renv) or {
			return mk_wire(500, [], 'handler error: ${err.msg()}\n')
		}
		return cx_response_to_wire(result, [])
	}
	// Snapshot the service record; a [?stop] races in-flight requests
	// gracefully — we keep serving with the current handler table.
	svc := h.state.service_get(h.service_name) or {
		return mk_wire(503, [], 'service vanished\n')
	}
	// Post-stop: socket may still be open (see KNOWN LIMITATION) — answer
	// 503 so a draining service does not serve stale content.
	if svc.status == 'stopped' {
		return mk_wire(503, svc.default_headers, 'service stopping\n')
	}
	method := raw_method.to_upper()
	// req path is the request-target; strip the query for path matching and
	// carry it as parsed [query-params] (#627).
	mut path := raw_path
	mut query_nodes := []cx.Node{}
	if q := path.index('?') {
		query_nodes = http_parse_query(path[q + 1..])
		path = path[..q]
	}
	// HEAD falls back to GET so static-file routes Just Work under
	// `curl -I` (HTTP/1.1 §9.4 — HEAD MUST be supported by any
	// GET-supporting resource). serialize_wire drops the body for HEAD.
	res, path_params := match_resource(svc, method, path) or {
		if method == 'HEAD' {
			r2, p2 := match_resource(svc, 'GET', path) or {
				return mk_wire(404, svc.default_headers, 'not found: ${method} ${path}\n')
			}
			return invoke_handler(svc, r2, p2, 'HEAD', path, query_nodes, mut h)
		}
		return mk_wire(404, svc.default_headers, 'not found: ${method} ${path}\n')
	}
	return invoke_handler(svc, res, path_params, method, path, query_nodes, mut h)
}

// ServeFileSpec marks a resource body that is a bare static `[$serve-file]`
// / `[$serve-file "PATH"]` call, eligible for the allocation-cheap fast path.
struct ServeFileSpec {
	has_literal bool   // true for `[$serve-file "PATH"]`, false for `[$serve-file]`
	literal     string // the literal path arg (only when has_literal)
}

// static_serve_file_spec returns a ServeFileSpec iff `body` is exactly a
// bare `[$serve-file]` or `[$serve-file "PATH"]` call (no `?`/`!` postfix,
// at most one plain string-literal arg) AND `serve-file` is not shadowed by
// an enclosing closure / closure-valued binding (in which case the slow path
// would invoke that instead of the builtin). Returns none otherwise so the
// caller falls back to the general eval path. The check is purely structural
// (AST + the per-service enclosing scope), so the fast path can NEVER change
// behaviour for a non-static-file handler.
fn static_serve_file_spec(body cx.ProgramNode, closures map[string]Closure, bindings map[string]cx.Node) ?ServeFileSpec {
	if body !is cx.ProgramCall {
		return none
	}
	call := body as cx.ProgramCall
	if call.name != 'serve-file' || call.fallible || call.must_succeed {
		return none
	}
	// serve-file shadowed by a user closure / closure-valued binding → the
	// eval path would call that, not the builtin; do not fast-path.
	if _ := closures['serve-file'] {
		return none
	}
	if v := bindings['serve-file'] {
		if is_fn_value(v) {
			return none
		}
	}
	if call.args.len == 0 {
		return ServeFileSpec{ has_literal: false }
	}
	if call.args.len == 1 {
		a := call.args[0]
		if a is cx.ProgramLiteral {
			al := a as cx.ProgramLiteral
			if al.kind == .string_lit {
				return ServeFileSpec{ has_literal: true, literal: al.str_val }
			}
		}
	}
	return none
}

// serve_file_fast_wire produces the WireResp for a static `[$serve-file]`
// resource WITHOUT the per-request env clone, `$request` node, or call
// dispatch — the dominant per-request allocation (see the alloc attribution
// in the http multicore work). It deliberately reuses the SAME
// serve_file_outcome (cache + resolution), mk_serve_response, and
// cx_response_to_wire the eval path uses, so its wire output is byte-identical
// to evaluating `[$serve-file]` through the handler — only the wasteful
// allocation is skipped. Verified by v08_http_serve_file_fastpath_test.v.
fn serve_file_fast_wire(spec ServeFileSpec, svc &ServiceRecord, req_path string) WireResp {
	// invoke_handler stashes svc.root into dyn_context only when non-empty,
	// so an empty root means "no service root in scope" (500) — match it.
	if svc.root == '' {
		return cx_response_to_wire(mk_serve_response(500, '', 'no service root in scope'),
			svc.default_headers)
	}
	rp := if spec.has_literal { spec.literal } else { req_path }
	o := serve_file_outcome(rp, svc.root, svc.cache)
	return cx_response_to_wire(mk_serve_response(o.status, o.ct, o.body), svc.default_headers)
}

// invoke_handler runs a matched resource handler in a per-request env
// clone and maps the [response …] envelope to a WireResp. Factored out
// so the HEAD-falls-back-to-GET branch reuses the eval + wire pipeline.
fn invoke_handler(svc &ServiceRecord, res ResourceRecord, path_params []cx.Node,
	method string, path string, query_nodes []cx.Node, mut h ListenerHandler) WireResp {
	// Static-file fast path: a bare `[$serve-file]` resource skips the
	// per-request env clone + `$request` node (the bulk of per-request
	// allocation) while producing byte-identical wire output.
	if spec := static_serve_file_spec(res.body, h.enclosing_closures, h.enclosing_bindings) {
		return serve_file_fast_wire(spec, svc, path)
	}
	// #317 template-alias request env: closures stay aliased for the whole
	// request (pure savings — the big table); the `request` write below
	// realizes the private bindings copy via cow_bindings(), so the bindings
	// cost is unchanged from the former unconditional clone while the
	// closures + map-header allocations are gone.
	mut env := MatchEnv{
		bindings:        h.enclosing_bindings
		bindings_shared: true
		closures:        h.enclosing_closures
		closures_shared: true
		state:           unsafe { h.state }
		anon_counter:    0
		// dyn stays an unconditional (tiny) clone: the service-root append
		// below writes it in place, and an aliased array with spare capacity
		// would share that write across executor threads.
		dyn_context:     h.enclosing_dyn.clone()
		scope:           h.enclosing_scope
	}
	env.cow_bindings()
	env.bindings['request'] = build_request_node(method, path, path_params, ?cx.Node(none),
		[]cx.Node{}, query_nodes)
	if svc.root != '' {
		env.dyn_context << cx.Node(cx.Element{
			name:  'cx-service-root'
			// `cache` attr carries the service's static-file cache opt-in
			// to [$serve-file] (read via serve_file_lookup_cache).
			attrs: [
				cx.new_attribute('cache', cx.ScalarValue(svc.cache), cx.AttributeMeta{
					data_type: ?string('bool')
				}),
			]
			items: [
				cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(svc.root)
					data_type: cx.ScalarType.string_type
				}),
			]
		})
	}
	body_result := eval_node(res.body, mut env) or {
		msg := err.msg()
		return mk_wire(500, svc.default_headers, 'handler error: ${msg}\n')
	}
	wire := cx_response_to_wire(body_result, svc.default_headers)
	return wire
}

// cx_response_to_wire converts a CX response envelope (cx.Element named
// 'response') to a WireResp, applying default headers where the handler
// did not override (per-key, per-response overrides win).
// ── generic SSE topic registry (#28) ─────────────────────────────────────────
//
// The concurrent-SSE path for `[$http:serve]`. Mirrors the proven XAP SSE
// machinery (xap_sse_subs) but keyed by a generic STRING topic instead of an
// xap runtime id, so a plain CX handler can promote a connection to a live feed
// and any other handler can fan-out to it WITHOUT blocking a reactor thread:
//
//   - A handler returns `[sse-subscribe topic="…" [event …]?]`; listener_callback
//     holds the fd (exempt from the idle timeout), then — atomically under this
//     lock — writes the SSE prelude + the optional initial frame and adds the fd
//     to `cx_sse_topic_subs[topic]`. The atomicity makes the initial frame a
//     readiness ack a client can rely on (see cx_sse_topic_subscribe).
//   - Any handler (on any reactor) calls `[$http:sse-publish "…" [event …]]`,
//     which renders one SSE frame and writes it to every subscriber fd.
//
// Cleanup is synchronous: picoev's close_conn invokes cx_sse_topic_on_close_fd
// (registered via cx_set_sse_on_close at handler-listener startup) under this
// lock BEFORE the socket closes, so a push from another reactor can never write
// to a reused fd. Same safety model as the XAP feed.
//
// #303: the lock is REFERENCE-typed, initialized in the module init()
// (stdlib_codec.v) — a VALUE-typed zeroed sync.Mutex global is NOT a usable
// pthread mutex on Darwin (PTHREAD_MUTEX_INITIALIZER is not all-zeros):
// .lock() failed silently and provided NO mutual exclusion, so two concurrent
// subscribes raced the `subs << fd` append and lost a registration — the
// pushed=1 flake this registry's ack barrier exists to prevent. Same latent
// class as cx_disp_mu / cx_http_gc_lock / cx_http_live_lock (#275).
__global (
	cx_sse_topic_subs map[string][]int
	cx_sse_topic_lock &sync.Mutex
)

// cx_sse_topic_subscribe writes the SSE prelude + initial frame (`ack`) to a
// held fd and adds the fd to `topic`'s subscriber set — atomically, under the
// registry lock. The lock makes the ack a readiness barrier: a concurrent
// cx_sse_topic_publish either acquires the lock first (its snapshot misses this
// fd — but the client cannot have read its ack yet, so no acknowledged
// subscriber is skipped) or acquires it after (its snapshot has the fd, and its
// frame follows the fully-written prelude on the wire, since a publisher can
// only learn the fd once the ack write completed and the lock was released).
// A failed ack write (peer already gone) still registers the fd; the next
// publish's failed write or picoev's disconnect event drops it, same as any
// dead subscriber.
fn cx_sse_topic_subscribe(topic string, fd int, ack string) {
	cx_sse_topic_lock.lock()
	send_all(fd, ack)
	cx_sse_topic_subs[topic] << fd
	cx_sse_topic_lock.unlock()
}

// cx_sse_topic_on_close_fd drops `fd` from every topic. Invoked by picoev's
// close_conn (held-fd close) and by a failed publish write; idempotent.
fn cx_sse_topic_on_close_fd(fd int) {
	cx_sse_topic_lock.lock()
	for topic, fds in cx_sse_topic_subs {
		mut kept := []int{}
		for f in fds {
			if f != fd {
				kept << f
			}
		}
		cx_sse_topic_subs[topic] = kept
	}
	cx_sse_topic_lock.unlock()
}

// cx_sse_topic_publish writes `frame` to every subscriber of `topic` and returns
// the number of fds that accepted the write. A fd whose write fails (peer gone)
// is dropped (picoev closes the socket on its own disconnect read event).
fn cx_sse_topic_publish(topic string, frame string) int {
	cx_sse_topic_lock.lock()
	fds := (cx_sse_topic_subs[topic] or { []int{} }).clone()
	cx_sse_topic_lock.unlock()
	mut dead := []int{}
	mut delivered := 0
	for fd in fds {
		if write_all_fd(fd, frame) {
			delivered++
		} else {
			dead << fd
		}
	}
	for fd in dead {
		cx_sse_topic_on_close_fd(fd)
	}
	return delivered
}

fn cx_response_to_wire(node cx.Node, defaults []cx.Attribute) WireResp {
	// #28 concurrent-SSE: a handler promotes its connection to a live feed by
	// returning `[sse-subscribe topic="…" [event …]?]`. The reactor holds the fd
	// and subscribes it to the topic; pushes arrive via [$http:sse-publish] from
	// other handlers. The optional `[event …]` child is the initial frame.
	if node is cx.Element {
		sub := node as cx.Element
		if sub.name == 'sse-subscribe' {
			topic := sub.attr('topic')
			if topic == '' {
				return mk_wire(500, defaults, 'sse-subscribe requires a non-empty topic="…" attribute\n')
			}
			mut frame := ''
			for it in sub.items {
				if it is cx.Element && (it as cx.Element).name == 'event' {
					fr := http_sse_frame_event(it as cx.Element)
					if fr is cx.Element && (fr as cx.Element).name == 'err' {
						// malformed initial [event] — surface it instead of holding a feed
						return mk_wire(500, defaults, 'sse-subscribe initial event invalid\n')
					}
					frame = http_node_str(fr)
					break
				}
			}
			return WireResp{
				status:    200
				sse:       true
				sse_topic: topic
				body:      frame
			}
		}
	}
	if node !is cx.Element {
		return mk_wire(200, defaults, render_node_text(node))
	}
	el := node as cx.Element
	if el.name != 'response' {
		return mk_wire(200, defaults, render_node_text(node))
	}
	mut status := 200
	if s_attr := el.attr_val('status') {
		match s_attr {
			i64 { status = int(s_attr) }
			string { status = s_attr.int() }
			else {}
		}
	}
	// Defaults first (ordered), then per-response headers override per key.
	mut hdr := map[string]string{}
	mut order := []string{}
	for a in defaults {
		v := match a.value {
			string { a.value as string }
			else { '' }
		}
		if a.name !in hdr {
			order << a.name
		}
		hdr[a.name] = v
	}
	mut body_str := ''
	for it in el.items {
		if it is cx.Element {
			ce := it as cx.Element
			if ce.name == 'headers' {
				for h_it in ce.items {
					if h_it is cx.Element && (h_it as cx.Element).name == 'header' {
						he := h_it as cx.Element
						hname := he.attr('name')
						hval := he.attr('value')
						if hname != '' {
							if hname !in hdr {
								order << hname
							}
							hdr[hname] = hval
						}
					}
				}
				continue
			}
			if ce.name == 'body' {
				body_str = render_response_body(ce)
				continue
			}
		}
	}
	// Alternate: body as a direct attribute on the response element.
	if body_str == '' {
		if b := el.attr_val('body') {
			match b {
				string { body_str = b }
				else {}
			}
		}
	}
	mut headers := []WireHeader{}
	for name in order {
		headers << WireHeader{
			name:  name
			value: hdr[name]
		}
	}
	return WireResp{
		status:  status
		headers: headers
		body:    body_str
	}
}

// mk_wire builds a minimal text/plain WireResp with default headers
// (the 404/500/503 fallback shape).
fn mk_wire(status int, defaults []cx.Attribute, body string) WireResp {
	mut headers := []WireHeader{}
	for a in defaults {
		v := match a.value {
			string { a.value as string }
			else { '' }
		}
		headers << WireHeader{
			name:  a.name
			value: v
		}
	}
	headers << WireHeader{
		name:  'Content-Type'
		value: 'text/plain; charset=utf-8'
	}
	return WireResp{
		status:  status
		headers: headers
		body:    body
	}
}

// serialize_wire emits HTTP/1.1 response bytes. Content-Length is always
// computed from the body length (the GET body length, even for HEAD);
// any handler-supplied Content-Length is dropped. For HEAD the body
// bytes are omitted but Content-Length is preserved (HTTP/1.1 §9.4).
fn serialize_wire(w WireResp, is_head bool) string {
	mut sb := strings.new_builder(256 + w.body.len)
	sb.write_string('HTTP/1.1 ${w.status} ${reason_phrase(w.status)}\r\n')
	for hkv in w.headers {
		if hkv.name.to_lower() == 'content-length' {
			continue
		}
		sb.write_string('${hkv.name}: ${hkv.value}\r\n')
	}
	sb.write_string('Content-Length: ${w.body.len}\r\n')
	sb.write_string('\r\n')
	if is_head {
		return sb.str()
	}
	sb.write_string(w.body)
	return sb.str()
}

// reason_phrase maps the status codes this listener emits to RFC 9110
// reason phrases; unknown codes fall back to a class-generic phrase.
fn reason_phrase(status int) string {
	return match status {
		200 { 'OK' }
		201 { 'Created' }
		204 { 'No Content' }
		301 { 'Moved Permanently' }
		302 { 'Found' }
		304 { 'Not Modified' }
		400 { 'Bad Request' }
		403 { 'Forbidden' }
		404 { 'Not Found' }
		405 { 'Method Not Allowed' }
		408 { 'Request Timeout' }
		500 { 'Internal Server Error' }
		503 { 'Service Unavailable' }
		else {
			match status / 100 {
				2 { 'OK' }
				3 { 'Redirect' }
				4 { 'Client Error' }
				5 { 'Server Error' }
				else { 'Status' }
			}
		}
	}
}

// render_response_body produces the wire body string from a `[body …]`
// element. Scalar string → verbatim; scalar non-string → stringified;
// structured child → re-rendered via CX text-render.
fn render_response_body(body_el cx.Element) string {
	if body_el.items.len == 0 {
		if body_el.attrs.len > 0 {
			b := body_el.attrs[0]
			match b.value {
				string { return b.value as string }
				else {}
			}
		}
		return ''
	}
	first := body_el.items[0]
	return render_node_text(first)
}

// render_node_text — simple text rendering for response bodies. A
// ScalarNode string is returned verbatim; other node kinds run through
// the standard render pipeline.
fn render_node_text(n cx.Node) string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
		return scalar_to_text(v)
	}
	return render(n, 'text') or { '' }
}

// spawn_shared_reactors binds ONE listening socket and spawns N picoev
// worker loops (one per core) that all watch that shared fd — the kernel
// distributes accept()s across the worker threads (the shared-listener
// multi-reactor model; picoev cx_shared_listener patch). macOS
// SO_REUSEPORT does not load-balance, but shared-fd accept does. All
// workers share the read-only &ListenerHandler; per-request env clones +
// the &ProgramState locks keep concurrent handler eval safe.
fn spawn_shared_reactors(mut h ListenerHandler, host string, port int) ! {
	bind_host := if host == '' { '0.0.0.0' } else { host }
	family := if bind_host.contains(':') { net.AddrFamily.ip6 } else { net.AddrFamily.ip }
	config := picoev.Config{
		port:      port
		host:      bind_host
		family:    family
		cb:        listener_callback
		user_data: h
	}
	// Warm the static-file cache singleton before workers spawn (the
	// cache fills concurrently afterward under its own rwlock).
	serve_file_cache_init()
	// #275: the dispatch-executor pool must exist before any reactor can
	// enqueue (idempotent; shared by every listener in the process).
	cx_dispatch_start_executors()
	listen_fd := picoev.listen_socket(config)!
	// Default to a SINGLE reactor for soundness. The multi-reactor model exposes a
	// residual macOS-specific vgc allocator concurrency corruption (#57): under >=2
	// concurrent reactor mutators a small-object span slot can be reissued while live,
	// crashing ~3% of heavy-load runs. Single-reactor is sound BY CONSTRUCTION — one
	// mutator on the HTTP request path means the race's >=2-mutator precondition cannot
	// occur (verified: 0 crashes single-reactor vs ~3% multi; Linux 0/92, i.e. the bug
	// is in the macOS mach-suspend-STW interaction, not the request logic). That residual
	// is fixed on the cooperative-safepoint collector (the default -gc e; #63/#58 — the
	// concurrency-soundness gate passes on it), so the listener now DEFAULTS to a small
	// multi-core fan-out (min(4, cores)); CX_HTTP_WORKERS tunes it. The #37 own-vs-rent
	// allocator rework remains a perf follow-up. The #57 OOM is addressed in three parts: the vgc_alloc_large wait
	// (large-span path), the per-iteration closures-table aliasing in the [?for] walker
	// (eval.v / matcher.v clone_frame_sharing_closures), and http_reactor_maybe_collect()
	// below, which bounds the per-request transient heap (the large-span fix alone left a
	// linear small-object leak that still OOM'd under sustained polling).
	// Reactor (worker) count. Default: a small multi-core fan-out — min(4, cores).
	// 4 is where the per-request global GC lock starts to dominate on a many-core
	// box, so the default doesn't fan out to every core (it scales sensibly from a
	// laptop to a big server without tuning). CX_HTTP_N overrides (#97):
	//   - an integer → that many workers (HONORED, incl. > cores — a 64-core test
	//                  gets 64). > cores oversubscribes (kernel time-slices,
	//                  usually slower) — honored but flagged, never silently shrunk.
	//   - `max`      → one worker per core.
	// `CX_HTTP_WORKERS` is the retired (verbose) name, still read as a DEPRECATED
	// alias (CX_HTTP_N wins if both are set). HTTP worker count stays an env var
	// by design (deploy-time ops config, not source syntax — #95).
	ncpu := runtime.nr_cpus()
	// #145 RESOLVED: the multi-reactor vgc sweep-while-live residual was a macOS-only
	// async mach-suspend register/SP capture gap (Linux's signal-suspend was always
	// sound). Fixed by switching the darwin STW to a signal-based suspend (precise,
	// kernel-delivered capture) — third_party/v vgc_platform.h. Gate-green bf1=0 +
	// crash=0 on macOS AND Linux Docker at the #144 churn cadence, comparable/higher
	// throughput. So the default returns to the multi-core fan-out min(4, cores).
	// Evidence + gate: vcx/tests/soundness/ISSUE-145-NOTES.md
	// (make test-vcx-concurrency-soundness).
	mut n := if ncpu < 1 { 1 } else if ncpu < 4 { ncpu } else { 4 }
	mut requested := 0 // >0 when the user asked for an explicit count
	mut wname := 'CX_HTTP_N'
	mut ovopt := os.getenv_opt('CX_HTTP_N')
	if ovopt == none {
		if legacy := os.getenv_opt('CX_HTTP_WORKERS') {
			eprintln('cx http: CX_HTTP_WORKERS is deprecated — use CX_HTTP_N (honoring it for now)')
			ovopt = legacy
			wname = 'CX_HTTP_WORKERS'
		}
	}
	if ov := ovopt {
		s := ov.trim_space().to_lower()
		if s == 'max' {
			n = ncpu
		} else {
			k := s.int()
			if k >= 1 {
				n = k
				requested = k
			}
		}
	}
	if n < 1 {
		n = 1
	}
	// Fail-loud worker cap (#94): an explicit count over 64×ncpu is a typo /
	// resource error, raised loudly — never silently clamped (the old behaviour).
	// Mirrors the `[par]` CXER0153 sanity cap; `max` / the default never trip it.
	http_worker_cap := 64 * (if ncpu < 1 { 1 } else { ncpu })
	if n > http_worker_cap {
		return error('cx-err:CXER0153: E_PAR_WIDTH_TOO_LARGE: ${wname}=${n} exceeds the fail-loud cap of 64×ncpu (${http_worker_cap}) — lower it; cx http never silently clamps the worker count')
	}
	if requested > ncpu && n > ncpu {
		// Guidance, not a cap: more workers than cores time-slice and usually run
		// SLOWER on this workload. Honored as asked.
		eprintln('cx http: ${n} workers on ${ncpu} cores — oversubscribed (usually slower than ~${ncpu})')
	}
	for _ in 0 .. n {
		mut w := picoev.new_with_listen_fd(config, listen_fd)!
		spawn w.serve()
	}
}

// start_http_listener binds + spawns the real-socket picoev listener for
// the service. listen_socket() binds synchronously, so the socket is
// listening (backlog queued) by the time we return — callers may issue
// requests immediately. When `rec.block` is true, blocks until [?stop]
// or process termination flips the service status.
fn start_http_listener(mut rec ServiceRecord, mut env MatchEnv) ! {
	host := if rec.bind_host == '' { '0.0.0.0' } else { rec.bind_host }
	mut h := &ListenerHandler{
		mode:               .service
		service_name:       rec.name
		enclosing_bindings: env.bindings.clone()
		enclosing_closures: env.closures.clone()
		enclosing_dyn:      env.dyn_context.clone()
		enclosing_scope:    env.scope
		state:              unsafe { env.state }
	}
	// Stash the handler pointer (no stoppable server handle exists — see
	// KNOWN LIMITATION). stop is observed via the service `status`.
	rec.listener_handle = voidptr(h)
	retain_listener_handler(h) // vgc root — picoev holds h only as voidptr (#57)
	spawn_shared_reactors(mut h, host, rec.port)!
	if rec.block {
		// Block until [?stop] or process termination flips status. Polls
		// every 100ms — coarse but ample for a static-file host.
		for {
			cur := env.state.service_get(rec.name) or { break }
			if cur.status == 'stopped' {
				break
			}
			time.sleep(100 * time.millisecond)
		}
	}
}

// start_handler_listener is the module `[$http:serve url $handler $opts]`
// entry (env-aware dispatch in stdlib_http.v). It runs the SAME picoev
// engine as the directive, dispatching each request to the single CX
// handler closure (.handler mode). picoev.new() binds synchronously.
// When `block` is true, serve() runs on the calling fiber and does not
// return (until process termination — picoev has no break path, see
// KNOWN LIMITATION); otherwise the listener is spawned and an
// [http-server] handle is returned.
fn start_handler_listener(handler cx.Node, host string, port int, block bool, mut env MatchEnv) !cx.Node {
	mut h := &ListenerHandler{
		mode:               .handler
		service_name:       ''
		handler:            handler
		enclosing_bindings: env.bindings.clone()
		enclosing_closures: env.closures.clone()
		enclosing_dyn:      env.dyn_context.clone()
		enclosing_scope:    env.scope
		state:              unsafe { env.state }
	}
	// #28: register the generic-topic SSE close hook so a held feed fd is dropped
	// from every topic synchronously when picoev closes the socket (under the
	// publish lock), preventing a concurrent [$http:sse-publish] from writing to
	// a reused fd. Matches the XAP feed's cx_set_sse_on_close discipline.
	picoev.cx_set_sse_on_close(cx_sse_topic_on_close_fd)
	retain_listener_handler(h) // vgc root — picoev holds h only as voidptr (#57)
	spawn_shared_reactors(mut h, host, port)!
	bind_host := if host == '' { '0.0.0.0' } else { host }
	url := 'tcp://${bind_host}:${port}'
	if block {
		// All worker loops spawned on their own threads; keep the calling
		// fiber alive (no in-process stop pre-fork-patch — a signal tears
		// it down with the process).
		for {
			time.sleep(time.hour)
		}
		return http_server_handle(url) // unreachable; satisfies the return type
	}
	return http_server_handle(url)
}

// stop_http_listener_for marks the listener bound to `rec` as drained.
// picoev has no break path (see KNOWN LIMITATION), so the listening
// socket is freed only at process exit; until then dispatch_request
// answers 503 for the stopped service. The service-status flip is owned
// by eval_stop (services.v); this hook exists for symmetry with the
// wasm stub and future fork-patched teardown.
fn stop_http_listener_for(rec &ServiceRecord) {
	// No socket-level teardown available pre-fork-patch; intentional no-op.
}

// services_listener_init_globals — module-init hook called from
// stdlib_codec.v's init(): this file's dispatch/gc/SSE globals need REAL
// reference mutexes (a zero-valued value-typed sync.Mutex is NOT a usable
// pthread mutex on Darwin — #275), and the init must live per-variant so
// the wasm build (which excludes this file) still compiles (#329).
fn services_listener_init_globals() {
	// #275: dispatch-executor bookkeeping — 16 executors corrupt the maps
	// without real mutual exclusion (map_delete/rehash crashes in the
	// concurrency-soundness gate).
	cx_disp_mu = sync.new_mutex()
	cx_disp_pending = map[int][]DispatchJob{}
	// Same latent class, pre-existing: silently non-locking value-typed
	// globals; the gc-churn counters and the handler retainer tolerated it
	// by luck (rare/benign collisions).
	cx_http_gc_lock = sync.new_mutex()
	cx_http_live_lock = sync.new_mutex()
	// #303: the SSE subscriber registries did NOT tolerate it by luck —
	// concurrent subscribes raced the `subs << fd` append and lost a
	// registration (pushed=1 under load). The subscribe-ack readiness
	// barrier (#124/#176) depends on these locks actually locking.
	cx_sse_topic_lock = sync.new_mutex()
	cx_sse_topic_subs = map[string][]int{}
	xap_sse_lock = sync.new_mutex()
	xap_sse_subs = map[int][]int{}
	xap_sse_delta = map[int]bool{}
	xap_sse_fdseq = map[int]u64{}
	// #594: the render cache + push coalescer share the same real-mutex
	// requirement (reactor threads + source pumps + trailing pushers).
	xap_render_lock = sync.new_mutex()
	xap_render_cache = map[int]map[string]string{}
	xap_render_cache_seq = map[int]u64{}
	xap_push_lock = sync.new_mutex()
	xap_push_last = map[int]i64{}
	xap_push_waiting = map[int]bool{}
}
