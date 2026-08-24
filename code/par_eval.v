module code

import cx
import os
import sync
import runtime

// ── Parallel map / reduce execution ─────────────────────
//
// Implements the actual `spawn`-based parallel substrate that
// `[?map ... :par]` and `[?reduce ... :par]` dispatch to. The
// sequential paths in `eval_map_directive` / `eval_reduce_directive`
// fall through to these when `:par` is present.
//
// Concurrency model:
//
//   * Each input item gets its own V `spawn`ed worker thread.
//   * Each worker builds a private `MatchEnv` clone (independent
//     `bindings` + `closures` maps) but shares the program-global
//     `&ProgramState` pointer — so resilience-state directives nested
//     in the `:using` body (e.g. `[?circuit-breaker]`) observe the
//     single shared state instance per `spec/code.md §10.2.7`.
// * Per-field `sync.RwMutex` on `ProgramState`
//     serializes concurrent reads / writes to the resilience-state
//     and scheduler-bound maps. Workers acquire the appropriate
//     write-lock at every mutation site; readers acquire the
//     read-lock. Wall-clock `[?sleep DUR]` does not touch state and
//     so does not contend.
//
// Result delivery:
//
//   * One `ParResult` per completion arrives on a shared
//     `chan ParResult`; the driver drains exactly N values and
//     reassembles by `idx` before returning. The output sequence is
//     SOURCE order regardless of completion timing — ALWAYS
//     (code.md §6.5.1 `pure ⇒ deterministic`, stream-5 ruling L105).
//     `[ordered]` is a tombstoned no-op: it remains grammatically
//     valid where it was valid (paired with `[par]`) and changes
//     nothing.
//
// Errors: the first error observed wins. We drain every channel
// message (workers are already in flight; we can't cancel them) but
// surface the lowest-index error to the caller, matching sequential
// `[?map]`'s behavior of failing at the first item to raise. Other
// errors are dropped silently.

// ParResult is the per-worker outcome envelope. `err_message != ''`
// signals a failed worker.
struct ParResult {
	idx         int
	value       cx.Node
	err_code    string
	err_message string
	// err_cause carries EvalError.cause across the worker channel VERBATIM
	// (§9.2 cause chains + the #348 err-guard passthrough both ride here);
	// without it a worker error's attached err-value was silently dropped
	// at the channel boundary and only code+message survived.
	err_cause     cx.Node
	err_cause_set bool
}

// ── [par] width (#94) ───────────────────────────────────────────────────────
//
// `[par]` owns its degree of concurrency: `[par]` (default), `[par N]`, or
// `[par max]`. Width = the MAX number of concurrent workers (a bounded pool),
// not one thread per item. Default = min(4, ncpu) (the HTTP fan-out formula);
// `max` = ncpu. An explicit N > 64×ncpu is a fail-loud sanity error (CXER0153),
// never a silent clamp.

// par_default_width is the unspecified-`[par]` worker bound: min(4, ncpu).
fn par_default_width() int {
	ncpu := runtime.nr_cpus()
	w := if ncpu < 4 { ncpu } else { 4 }
	return if w < 1 { 1 } else { w }
}

// resolve_par_width turns the parsed (width, is_max) into the actual worker
// bound. width == 0 means unspecified (default); is_max means ncpu. An explicit
// width must be ≥ 1 and ≤ 64×ncpu, else a loud error (no clamp).
fn resolve_par_width(width int, is_max bool) !int {
	if is_max {
		n := runtime.nr_cpus()
		return if n < 1 { 1 } else { n }
	}
	if width == 0 {
		return par_default_width()
	}
	if width < 1 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[par] width must be ≥ 1, got ${width}'
		}
	}
	ncpu := runtime.nr_cpus()
	cap := 64 * (if ncpu < 1 { 1 } else { ncpu })
	if width > cap {
		return EvalError{
			code:    'cx-err:CXER0153'
			message: 'E_PAR_WIDTH_TOO_LARGE: [par ${width}] exceeds the fail-loud cap of 64×ncpu (${cap}) — shard the work or lower the width; [par] never silently clamps'
		}
	}
	return width
}

// par_width_from_items reads the `[par …]` width off the clause's body items
// for the map/reduce directive forms (the for-comprehension form carries it on
// the parsed ProgramForClause instead). Returns (0,false) for a bare `[par]`
// (→ default), (0,true) for `[par max]`, (N,false) for `[par N]` with N≥1.
// An explicit non-positive / non-integer / non-`max` width, or more than one
// width token, is a CXER0100 — matching the for-clause parser's edges.
fn par_width_from_items(items []cx.ProgramNode, mut env MatchEnv) !(int, bool) {
	if items.len == 0 {
		return 0, false
	}
	if items.len > 1 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[par] takes at most one width token, got ${items.len}'
		}
	}
	v := eval_node(items[0], mut env)!
	if v is cx.ScalarNode {
		val := v.value
		if val is i64 {
			w := int(val)
			if w < 1 {
				return EvalError{
					code:    'cx-err:CXER0100'
					message: '[par] width must be ≥ 1, got ${w}'
				}
			}
			return w, false
		}
		if val is string {
			if val == 'max' {
				return 0, true
			}
		}
	}
	if v is cx.TextNode {
		if v.value == 'max' {
			return 0, true
		}
	}
	return EvalError{
		code:    'cx-err:CXER0100'
		message: '[par] width must be a positive integer or `max`'
	}
}

// ParPeak instruments the worker pool: the peak number of simultaneously
// in-flight workers. This is the AUTHORITATIVE parallelism gate (#94 §5) —
// deterministic, unlike wall-clock timing. Workers bracket their actual work
// (the `:using` body) with enter()/leave(); the driver reads `peak` after
// draining and, under CX_PAR_PEAK, reports it on stderr for the conformance/V
// tests to assert `peak ≤ W` and `peak == min(W, n)`.
@[heap]
struct ParPeak {
mut:
	lock &sync.Mutex = unsafe { nil }
	cur  int
	peak int
}

fn new_par_peak() &ParPeak {
	return &ParPeak{
		lock: sync.new_mutex()
	}
}

fn (mut pp ParPeak) enter() {
	pp.lock.lock()
	pp.cur++
	if pp.cur > pp.peak {
		pp.peak = pp.cur
	}
	pp.lock.unlock()
}

fn (mut pp ParPeak) leave() {
	pp.lock.lock()
	pp.cur--
	pp.lock.unlock()
}

// par_peak_report emits the instrumented peak-worker count when CX_PAR_PEAK is
// set, so tests can assert the bound deterministically (the primary #94 gate).
fn par_peak_report(form string, pp &ParPeak, width int, n int) {
	if os.getenv('CX_PAR_PEAK') != '' {
		eprintln('cx-par-peak: form=${form} width=${width} n=${n} peak=${pp.peak}')
	}
}

// par_map_pool_worker is one worker in the bounded pool (#94): it pulls item
// indices off the shared `work` channel until the channel is closed and
// drained, evaluating the `:using` closure for each. Each item gets a private
// MatchEnv clone (worker-local rebinds don't race the parent / sibling items);
// the program-global &ProgramState is shared so resilience-state directives see
// one instance (§10.2.7). enter()/leave() bracket the actual work so ParPeak
// measures the true concurrency bound.
fn par_map_pool_worker(closure Closure, items []cx.Node, state_ptr &ProgramState,
                       enclosing_bindings map[string]cx.Node,
                       enclosing_closures map[string]Closure, work chan int,
                       ch chan ParResult, mut pp ParPeak) {
	for {
		idx := <-work or { break } // channel closed + drained → worker exits
		mut env := MatchEnv{
			bindings:     enclosing_bindings.clone()
			closures:     enclosing_closures.clone()
			state:        unsafe { state_ptr }
			anon_counter: 0
			frame_pool:   &FramePool{} // fresh per-call frame pool (#36); thread-local
		}
		pp.enter()
		val := invoke_closure(closure, [items[idx]], mut env) or {
			pp.leave()
			if err is EvalError {
				ch <- ParResult{idx: idx, err_code: err.code, err_message: err.message, err_cause: err.cause, err_cause_set: err.cause_set}
			} else {
				ch <- ParResult{idx: idx, err_code: 'cx-err:CXER0001', err_message: err.msg()}
			}
			continue
		}
		pp.leave()
		ch <- ParResult{idx: idx, value: val}
	}
}

// par_map runs `closure` over each item in `items` through a BOUNDED pool of at
// most `width` workers (#94 — replaces the prior one-thread-per-item spawn).
// Returns results in SOURCE order always (L105 — completion-order delivery is
// retired). Propagates the earliest-index worker error if any worker raises.
fn par_map(closure Closure, items []cx.Node, width int, mut env MatchEnv) ![]cx.Node {
	n := items.len
	if n == 0 {
		return []cx.Node{}
	}
	// Wasm-async (no pthreads): V's `spawn` aborts the program because
	// the emscripten build wasn't linked with pthread runtime. Fall back
	// to inline sequential evaluation; output is source-ordered and
	// correct, just not actually parallel. The HTTP-served pthreads
	// build of libcx takes the spawn path below..
	$if wasm32_emcc ? {
		mut seq := []cx.Node{cap: n}
		for item in items {
			seq << invoke_closure(closure, [item], mut env)!
		}
		_ = width
		return seq
	}
	// Pool size = min(width, n): never more workers than items.
	mut w := if width < n { width } else { n }
	if w < 1 {
		w = 1
	}
	mut pp := new_par_peak()
	work := chan int{cap: n}
	ch := chan ParResult{cap: n}
	for i in 0 .. n {
		work <- i
	}
	work.close()
	for _ in 0 .. w {
		spawn par_map_pool_worker(closure, items, env.state, env.bindings, env.closures,
			work, ch, mut pp)
	}
	mut received := []ParResult{cap: n}
	for _ in 0 .. n {
		received << <-ch
	}
	par_peak_report('map', pp, w, n)
	// Surface the lowest-index error if any worker failed.
	mut first_err_idx := -1
	for r in received {
		if r.err_message != '' {
			if first_err_idx < 0 || r.idx < first_err_idx {
				first_err_idx = r.idx
			}
		}
	}
	if first_err_idx >= 0 {
		for r in received {
			if r.idx == first_err_idx {
				return EvalError{ code: r.err_code, message: r.err_message, cause: r.err_cause, cause_set: r.err_cause_set }
			}
		}
	}
	// Source order ALWAYS (L105): reassemble by index.
	mut by_idx := []cx.Node{len: n, init: cx.Node(cx.Element{ name: '' })}
	for r in received {
		by_idx[r.idx] = r.value
	}
	return by_idx
}

// ── for-par (#94 Stage 2) ────────────────────────────────────────────────────
//
// `[?for … [par]]` parallelizes the OUTERMOST generator: its items are
// distributed across a bounded pool of `width` workers, and each worker runs the
// DOWNSTREAM clause pipeline (where / let / nested generators / yield) for its
// item, producing that item's yield list. The per-item lists are concatenated in
// SOURCE order always (L105). Inner generators run
// sequentially within the worker — only the outermost loop is parallel, per
// spec §7.3. The caller (eval_for_comp) post-applies take/drop/limit on the
// assembled list and only takes this path when it is semantics-safe (no
// order-by/group-by, no takewhile/dropwhile, a materialised sequence source, and
// no `$_position` reference) — otherwise it falls back to the sequential walk.

// ParListResult is the per-item outcome for for-par: a worker yields a LIST of
// nodes (an item may yield zero, one, or many), not a single value.
struct ParListResult {
	idx         int
	values      []cx.Node
	err_code    string
	err_message string
	// err_cause: see ParResult — cause survives the channel verbatim.
	err_cause     cx.Node
	err_cause_set bool
}

fn par_for_worker(clauses []cx.ProgramForClause, gen cx.ProgramForClause, gen_idx int,
                  spec YieldSpec, state_ptr &ProgramState,
                  enclosing_bindings map[string]cx.Node,
                  enclosing_closures map[string]Closure, work chan int, items []cx.Node,
                  ch chan ParListResult, mut pp ParPeak) {
	for {
		i := <-work or { break }
		mut env := MatchEnv{
			bindings:     enclosing_bindings.clone()
			closures:     enclosing_closures.clone()
			state:        unsafe { state_ptr }
			anon_counter: 0
			frame_pool:   &FramePool{}
		}
		// Bind the outermost generator's item (pattern-destructure or simple).
		mut skip := false
		if expr_pat := gen.expr {
			if expr_pat is cx.ProgramPattern {
				if matched := match_pattern(expr_pat, items[i]) {
					for k, v in matched.bindings {
						env.bindings[k] = v
					}
				} else {
					// pattern mismatch → this item contributes nothing
					skip = true
				}
			}
		} else {
			env.bindings[gen.bind] = items[i]
		}
		if skip {
			ch <- ParListResult{idx: i, values: []cx.Node{}}
			continue
		}
		// Fresh UNLIMITED limit state: take/drop/while are post-applied on the
		// assembled list, so per-worker pipelines never short-circuit.
		mut ls := ForLimitState{
			remaining:      -1
			drop_remaining: 0
		}
		mut local := []cx.Node{}
		pp.enter()
		run_for_clauses(clauses, gen_idx + 1, spec, mut env, mut local, mut ls) or {
			pp.leave()
			if err is EvalError {
				ch <- ParListResult{idx: i, err_code: err.code, err_message: err.message, err_cause: err.cause, err_cause_set: err.cause_set}
			} else {
				ch <- ParListResult{idx: i, err_code: 'cx-err:CXER0001', err_message: err.msg()}
			}
			continue
		}
		pp.leave()
		ch <- ParListResult{idx: i, values: local}
	}
}

// par_for_run distributes `items` (the outermost generator's items) across a
// bounded pool of `width` workers and concatenates the per-item yield lists.
fn par_for_run(clauses []cx.ProgramForClause, gen cx.ProgramForClause, gen_idx int,
               spec YieldSpec, items []cx.Node, width int, fail_fast bool, mut env MatchEnv) ![]cx.Node {
	n := items.len
	if n == 0 {
		return []cx.Node{}
	}
	$if wasm32_emcc ? {
		// No pthreads: sequential, but still correct (source order).
		mut seq := []cx.Node{}
		for it in items {
			mut wenv := env.clone_frame_sharing_closures()
			if expr_pat := gen.expr {
				if expr_pat is cx.ProgramPattern {
					matched := match_pattern(expr_pat, it) or { continue }
					for k, v in matched.bindings {
						wenv.bindings[k] = v
					}
				}
			} else {
				wenv.bindings[gen.bind] = it
			}
			mut ls := ForLimitState{
				remaining:      -1
				drop_remaining: 0
			}
			run_for_clauses(clauses, gen_idx + 1, spec, mut wenv, mut seq, mut ls)!
		}
		_ = width
		return seq
	}
	mut w := if width < n { width } else { n }
	if w < 1 {
		w = 1
	}
	mut pp := new_par_peak()
	work := chan int{cap: n}
	ch := chan ParListResult{cap: n}
	for i in 0 .. n {
		work <- i
	}
	work.close()
	for _ in 0 .. w {
		spawn par_for_worker(clauses, gen, gen_idx, spec, env.state, env.bindings,
			env.closures, work, items, ch, mut pp)
	}
	mut received := []ParListResult{cap: n}
	mut expected := n
	mut ff_first := -1 // received[] slot of the first OBSERVED err (fail-fast)
	mut got := 0
	for got < expected {
		r := <-ch
		received << r
		got++
		if fail_fast && r.err_message != '' && ff_first < 0 {
			ff_first = received.len - 1
			// [fail-fast] (grammar [129r], code.md §7.3 — stream-2 W1,
			// #711 item 3): short-circuit on the FIRST observed err —
			// drain the queued work so idle workers stop starting new
			// items. Each pulled index sends exactly one result, so the
			// expected count shrinks by exactly what the drain consumed;
			// in-flight items still report and are discarded below.
			mut drained := 0
			for {
				dr := <-work or { break }
				_ = dr
				drained++
			}
			expected -= drained
		}
	}
	par_peak_report('for', pp, w, n)
	if fail_fast && ff_first >= 0 {
		fr := received[ff_first]
		return EvalError{ code: fr.err_code, message: fr.err_message, cause: fr.err_cause, cause_set: fr.err_cause_set }
	}
	// earliest-index error wins (matches sequential first-failure semantics).
	mut first_err_idx := -1
	for r in received {
		if r.err_message != '' && (first_err_idx < 0 || r.idx < first_err_idx) {
			first_err_idx = r.idx
		}
	}
	if first_err_idx >= 0 {
		for r in received {
			if r.idx == first_err_idx {
				return EvalError{ code: r.err_code, message: r.err_message, cause: r.err_cause, cause_set: r.err_cause_set }
			}
		}
	}
	// Source order ALWAYS (L105): reassemble the per-item yield lists by index.
	mut out := []cx.Node{}
	mut by_idx := [][]cx.Node{len: n, init: []cx.Node{}}
	for r in received {
		by_idx[r.idx] = r.values
	}
	for lst in by_idx {
		out << lst
	}
	return out
}

// par_reduce runs the associative two-argument `closure` over `items`
// using `init` as the identity. The implementation splits the work into K chunks
// where K is bounded by `max_workers`; each chunk is folded left-to-
// right sequentially in a `spawn`ed worker; the K partial results are
// then combined sequentially on the caller thread. This satisfies
// `spec/code.md §8.10.6` ("any associative parenthesization") without
// the implementation complexity of a full pairwise-tree reduce, and
// gives a real wall-clock speedup when the `:using` body itself
// blocks (e.g. on `[?sleep DUR]`) — which is the demonstrated case.
//
// `:init` MUST be the identity for `:using` per the §8.10.6
// associative contract; we use it both as the per-chunk seed and as
// the combine seed.
fn par_reduce(closure Closure, items []cx.Node, init cx.Node, width int, mut env MatchEnv) !cx.Node {
	n := items.len
	if n == 0 {
		return init
	}
	// Wasm-async fallback (see par_map for context): sequential left-
	// fold. Correct for associative `:using` per §8.10.6.
	$if wasm32_emcc ? {
		mut acc := init
		for item in items {
			acc = invoke_closure(closure, [acc, item], mut env)!
		}
		_ = width
		return acc
	}
	// Chunk count = min(n, width) (#94 — the bounded `[par]` worker count;
	// was a magic 32). Each chunk is one worker; the partials combine on the
	// caller. Associativity makes the result independent of the split (§8.10.6).
	mut k := if n < width { n } else { width }
	if k < 1 {
		k = 1
	}
	mut pp := new_par_peak()
	chunk_size := (n + k - 1) / k
	ch := chan ParResult{cap: k}
	mut spawned := 0
	for ci := 0; ci < k; ci++ {
		start := ci * chunk_size
		if start >= n {
			break
		}
		mut end := start + chunk_size
		if end > n {
			end = n
		}
		chunk := items[start..end].clone()
		spawn par_reduce_chunk_worker(closure, chunk, init, ci, env.state,
			env.bindings, env.closures, ch, mut pp)
		spawned++
	}
	mut received := []ParResult{cap: spawned}
	for _ in 0 .. spawned {
		received << <-ch
	}
	par_peak_report('reduce', pp, k, n)
	mut first_err_idx := -1
	for r in received {
		if r.err_message != '' && (first_err_idx < 0 || r.idx < first_err_idx) {
			first_err_idx = r.idx
		}
	}
	if first_err_idx >= 0 {
		for r in received {
			if r.idx == first_err_idx {
				return EvalError{ code: r.err_code, message: r.err_message, cause: r.err_cause, cause_set: r.err_cause_set }
			}
		}
	}
	// Reassemble partial results in chunk order and combine
	// sequentially on this thread. Associativity guarantees the
	// final value is independent of split points (§8.10.6).
	mut partials := []cx.Node{len: spawned, init: cx.Node(cx.Element{ name: '' })}
	for r in received {
		partials[r.idx] = r.value
	}
	mut acc := init
	for p in partials {
		acc = invoke_closure(closure, [acc, p], mut env)!
	}
	return acc
}

// par_reduce_range folds a bounded integer range in parallel WITHOUT
// materialising it. The index domain [0,count) is split into K contiguous
// chunks; each worker streams its sub-range (generate→fold→drop, O(1) live
// set) seeded with `init`, and the K partials combine sequentially on the
// caller. Same §8.10.6 associativity contract as par_reduce (`init` =
// identity, `closure` associative — not validated at runtime). This is the
// `:par` arm of the streaming reduce-over-range fast-path (lever 1): a
// parallel reduce over a multi-million range never materialises the range,
// unlike the items-array path par_reduce takes.
fn par_reduce_range(closure Closure, start i64, end i64, step i64, init cx.Node, width int, mut env MatchEnv) !cx.Node {
	mut count := i64(0)
	if step > 0 {
		if end >= start {
			count = (end - start) / step + 1
		}
	} else {
		if end <= start {
			count = (start - end) / (-step) + 1
		}
	}
	if count <= 0 {
		return init
	}
	// Wasm-async fallback (no pthreads — see par_map): sequential streaming
	// left-fold. Correct for associative `:using` per §8.10.6.
	$if wasm32_emcc ? {
		mut acc := init
		mut argbuf := [init, init]
		mut i := start
		for _ in 0 .. count {
			argbuf[0] = acc
			argbuf[1] = cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(i)
				data_type: cx.ScalarType.int_type
			})
			acc = invoke_closure(closure, argbuf, mut env)!
			i += step
		}
		_ = width
		return acc
	}
	// Chunk count = min(count, width) (#94 bounded `[par]` workers; was 32).
	mut k := if count < i64(width) { int(count) } else { width }
	if k < 1 {
		k = 1
	}
	mut pp := new_par_peak()
	chunk := (count + i64(k) - 1) / i64(k) // indices per chunk
	ch := chan ParResult{cap: k}
	mut spawned := 0
	for ci := 0; i64(ci) * chunk < count; ci++ {
		idx_start := i64(ci) * chunk
		mut idx_end := idx_start + chunk
		if idx_end > count {
			idx_end = count
		}
		c_start := start + idx_start * step
		c_n := idx_end - idx_start
		spawn par_reduce_range_worker(closure, c_start, step, c_n, init, ci, env.state,
			env.bindings, env.closures, ch, mut pp)
		spawned++
	}
	mut received := []ParResult{cap: spawned}
	for _ in 0 .. spawned {
		received << <-ch
	}
	par_peak_report('reduce-range', pp, k, int(count))
	mut first_err_idx := -1
	for r in received {
		if r.err_message != '' && (first_err_idx < 0 || r.idx < first_err_idx) {
			first_err_idx = r.idx
		}
	}
	if first_err_idx >= 0 {
		for r in received {
			if r.idx == first_err_idx {
				return EvalError{ code: r.err_code, message: r.err_message, cause: r.err_cause, cause_set: r.err_cause_set }
			}
		}
	}
	mut partials := []cx.Node{len: spawned, init: cx.Node(cx.Element{ name: '' })}
	for r in received {
		partials[r.idx] = r.value
	}
	mut acc := init
	for p in partials {
		acc = invoke_closure(closure, [acc, p], mut env)!
	}
	return acc
}

// par_reduce_range_worker streams a contiguous integer sub-range
// [c_start, c_start + (c_n-1)*step] (c_n elements) into a left-fold seeded
// with `init`, posting the partial to `ch`. Mirrors par_reduce_chunk_worker
// but generates its inputs instead of receiving a materialised chunk.
fn par_reduce_range_worker(closure Closure, c_start i64, step i64, c_n i64, init cx.Node, idx int,
	state_ptr &ProgramState, enclosing_bindings map[string]cx.Node,
	enclosing_closures map[string]Closure, ch chan ParResult, mut pp ParPeak) {
	mut env := MatchEnv{
		bindings:     enclosing_bindings.clone()
		closures:     enclosing_closures.clone()
		state:        unsafe { state_ptr }
		anon_counter: 0
		frame_pool:   &FramePool{} // fresh per-worker frame pool (#36); thread-local, no sharing
	}
	pp.enter()
	defer {
		pp.leave()
	}
	mut acc := init
	mut argbuf := [init, init]
	mut i := c_start
	for _ in 0 .. c_n {
		argbuf[0] = acc
		argbuf[1] = cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(i)
			data_type: cx.ScalarType.int_type
		})
		acc = invoke_closure(closure, argbuf, mut env) or {
			if err is EvalError {
				ch <- ParResult{
					idx:         idx
					err_code:    err.code
					err_message: err.message
				}
			} else {
				ch <- ParResult{
					idx:         idx
					err_code:    'cx-err:CXER0001'
					err_message: err.msg()
				}
			}
			return
		}
		i += step
	}
	ch <- ParResult{
		idx:   idx
		value: acc
	}
}

// eval_map_directive_streamed mirrors `eval_map_directive` but emits
// each result into the streaming context as it materializes. Used by
// `eval_code_streaming_opts` when the top-level program is a `[?map]`
// directive — the playground gets per-completion visibility instead
// of a single end-of-eval flush. Slot parsing + closure resolution is
// duplicated rather than refactored to avoid touching the non-
// streaming hot path's call shape.
// MapSlots is the parsed slot shape of a `[?map …]` directive. ONE authority:
// both the evaluator and the streamed-INPUT precondition check (#845,
// code/streamed_input.v) read the program's shape through this, so the fast
// path can never disagree with the evaluator about what a `[?map]` says — the
// two-spellings drift the streaming predicate authority already guards
// against for stream_mode_of.
struct MapSlots {
	source     cx.ProgramNode
	using_slot cx.ProgramNode
	par        bool
	ordered    bool
	par_width  int
	par_max    bool
}

fn parse_map_slots(d cx.ProgramDirective, mut env MatchEnv) !MapSlots {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires positional source slot' }
	}
	mut source_node := d.slots[0].value
	mut using_slot := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut have_using := false
	mut par_flag := false
	mut ordered_flag := false
	mut par_width := 0
	mut par_max := false
	mut have_source := false
	for slot in d.slots {
		if slot.kind == .labeled {
			match slot.label {
				'using' {
					using_slot = slot.value
					have_using = true
				}
				'par' { par_flag = true }
				'ordered' { ordered_flag = true }
				else {
					return EvalError{ code: 'cx-err:CXER0100',
						message: "[?map] unknown slot ':${slot.label}'" }
				}
			}
			continue
		}
		v := slot.value
		if v is cx.ProgramLiteral && v.kind == .cx_element {
			match v.name {
				'using' {
					using_slot = if v.items.len == 1 {
						v.items[0]
					} else {
						cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: v.items, pos: v.pos })
					}
					have_using = true
					continue
				}
				'par' {
					par_flag = true
					par_width, par_max = par_width_from_items(v.items, mut env)!
					continue
				}
				'ordered' { ordered_flag = true; continue }
				else {}
			}
		}
		if have_source {
			return EvalError{ code: 'cx-err:CXER0100',
				message: '[?map] takes a single positional source slot' }
		}
		source_node = slot.value
		have_source = true
	}
	if !have_source {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires positional source slot' }
	}
	if !have_using {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires :using slot' }
	}
	if ordered_flag && !par_flag {
		return EvalError{ code: 'cx-err:CXER0100',
			message: '[?map] [ordered] requires [par] (a tombstoned no-op when paired — L105)' }
	}
	return MapSlots{
		source:     source_node
		using_slot: using_slot
		par:        par_flag
		ordered:    ordered_flag
		par_width:  par_width
		par_max:    par_max
	}
}

pub fn eval_map_directive_streamed(d cx.ProgramDirective, mut env MatchEnv, mut ctx StreamCtx) ! {
	sl := parse_map_slots(d, mut env)!
	source_node := sl.source
	using_slot := sl.using_slot
	par_flag := sl.par
	par_width := sl.par_width
	par_max := sl.par_max
	source_val := eval_node(source_node, mut env)!
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0106', message: '[?map] :using must evaluate to a closure (E_USING_NOT_CLOSURE)' }
	}
	items := iterate(source_val)
	if par_flag {
		width := resolve_par_width(par_width, par_max)!
		par_map_streamed(closure, items, width, mut env, mut ctx)!
		return
	}
	// Sequential: emit one per iteration; each completes before the
	// next starts, so the user sees deterministic per-item progress.
	//
	// Delivery cadence is the StreamCtx's threshold, NOT a flush per item
	// (#823). While this path existed only for playground visibility a
	// per-item flush was free; now that [?map] streams for throughput too,
	// an unconditional flush meant one sink call per mapped value — ~110 K
	// of them on a 10 MB document. A caller that genuinely wants per-item
	// cadence asks for it: `eval_code_streaming_opts(unbuffered: true)`
	// sets threshold = 1 and emit_node flushes on every item by itself.
	for item in items {
		mapped := invoke_closure(closure, [item], mut env)!
		ctx.emit_node(mapped)!
	}
}

// par_map_streamed fans workers out through a BOUNDED pool of `width` workers
// (#94) and emits results in SOURCE order always (L105): results buffer by
// index and the contiguous prefix streams out as it becomes complete — the
// user still sees incremental progress, just never a reordering. An error
// propagates when the emission frontier reaches its index (earliest-index
// error wins, matching sequential first-failure semantics); later-index
// results already received are discarded with it.
fn par_map_streamed(closure Closure, items []cx.Node, width int,
                    mut env MatchEnv, mut ctx StreamCtx) ! {
	n := items.len
	if n == 0 {
		return
	}
	// Wasm-async fallback: sequential, but still per-item streamed —
	// the user sees results appear one at a time as each invocation
	// completes (visible cadence under [?sleep DUR] in the body).
	$if wasm32_emcc ? {
		_ = width
		for item in items {
			v := invoke_closure(closure, [item], mut env)!
			ctx.emit_node(v)!
		}
		return
	}
	mut w := if width < n { width } else { n }
	if w < 1 {
		w = 1
	}
	mut pp := new_par_peak()
	work := chan int{cap: n}
	ch := chan ParResult{cap: n}
	for i in 0 .. n {
		work <- i
	}
	work.close()
	for _ in 0 .. w {
		spawn par_map_pool_worker(closure, items, env.state, env.bindings, env.closures,
			work, ch, mut pp)
	}
	// Source order ALWAYS (L105), streamed incrementally: buffer by index,
	// emit the contiguous prefix as it completes. `frontier` = the next
	// source index to emit; an error result is held in the buffer and
	// propagates only when the frontier reaches it, so a lower-index
	// success still emits and a lower-index error still wins.
	mut by_idx := []ParResult{len: n}
	mut have := []bool{len: n}
	mut frontier := 0
	for _ in 0 .. n {
		r := <-ch
		by_idx[r.idx] = r
		have[r.idx] = true
		for frontier < n && have[frontier] {
			fr := by_idx[frontier]
			if fr.err_message != '' {
				par_peak_report('map-streamed', pp, w, n)
				return EvalError{ code: fr.err_code, message: fr.err_message, cause: fr.err_cause, cause_set: fr.err_cause_set }
			}
			// Threshold-paced, like the sequential arm — see there.
			ctx.emit_node(fr.value)!
			frontier++
		}
	}
	par_peak_report('map-streamed', pp, w, n)
}

fn par_reduce_chunk_worker(closure Closure, chunk []cx.Node, init cx.Node, idx int,
                           state_ptr &ProgramState,
                           enclosing_bindings map[string]cx.Node,
                           enclosing_closures map[string]Closure, ch chan ParResult, mut pp ParPeak) {
	mut env := MatchEnv{
		bindings:     enclosing_bindings.clone()
		closures:     enclosing_closures.clone()
		state:        unsafe { state_ptr }
		anon_counter: 0
		frame_pool:   &FramePool{} // fresh per-worker frame pool (#36); thread-local, no sharing
	}
	pp.enter()
	defer {
		pp.leave()
	}
	mut acc := init
	for item in chunk {
		next := invoke_closure(closure, [acc, item], mut env) or {
			if err is EvalError {
				ch <- ParResult{idx: idx, err_code: err.code, err_message: err.message}
			} else {
				ch <- ParResult{idx: idx, err_code: 'cx-err:CXER0001', err_message: err.msg()}
			}
			return
		}
		acc = next
	}
	ch <- ParResult{idx: idx, value: acc}
}
