@[has_globals]
module code

import sync

// ── The effect trace — the `out-effects` witness channel (stream 22
// W1, L73; clean_room_implementability.md §6/§9) ─────────────────────
//
// One ordered, process-global record of every EXECUTED effect point:
// an entry is appended exactly where the capability gate ADMITS the
// effect (cap_guard's pass branch — the §2.1 closed effect-point
// table's one choke point), spelled `capability:resource`. Denied
// effects never execute and never trace (the denial is observable on
// the error channel instead). Reset per program (new_env — the
// prof/sched reset posture); read by the conformance runner to grade
// `[out-effects …]` sections, which makes effect ORDER and COUNT
// corpus-checkable — the blind spot §1 names.
//
// Concurrency: workers cross cap_guard concurrently — the log is
// mutex-guarded. Interleaving across concurrent tasks is genuinely
// nondeterministic; ordering witnesses over concurrent programs must
// assert per-task subsequences or use `out-multiset`-style matchers,
// never a total order.

__global (
	g_effects_trace       []string
	g_effects_trace_mu    &sync.Mutex
	g_effects_trace_ready bool
	// the [?select] tiebreak PRNG state (EV-SELECT-FAIR; eval.v
	// select_tiebreak_index — scheduling nondeterminism, ungated).
	g_select_rng_state    u64
)

fn effects_trace_mu() &sync.Mutex {
	if !g_effects_trace_ready {
		g_effects_trace_mu = sync.new_mutex()
		g_effects_trace_ready = true
	}
	return g_effects_trace_mu
}

// effects_trace_reset clears the trace (per-program; called by
// new_env alongside the other process-global resets).
pub fn effects_trace_reset() {
	mut mu := effects_trace_mu()
	mu.lock()
	g_effects_trace = []string{}
	mu.unlock()
}

// effects_trace_record appends one ADMITTED effect point.
fn effects_trace_record(capability string, resource string) {
	mut mu := effects_trace_mu()
	mu.lock()
	g_effects_trace << '${capability}:${resource}'
	mu.unlock()
}

// effects_trace_snapshot returns the ordered trace as recorded.
pub fn effects_trace_snapshot() []string {
	mut mu := effects_trace_mu()
	mu.lock()
	s := g_effects_trace.clone()
	mu.unlock()
	return s
}
