module code

import cx

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
//   * Unordered (`:par` without `:ordered`): one `ParResult` per
//     completion arrives on a shared `chan ParResult`; the driver
//     drains exactly N values. The output sequence reflects
//     completion order. The matched conformance section type is
// `--- out_multiset`.
//   * Ordered (`:par :ordered`): drained the same way but reassembled
//     by `idx` before returning. The output sequence reflects source
//     order regardless of completion timing.
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
}

// par_map_worker is the V `spawn`'d body that evaluates one
// `:using` closure call for `[?map ... :par]`. The state pointer is
// shared with the enclosing env; the bindings/closures maps are
// clones so worker-local binding rebinds don't race the parent.
fn par_map_worker(closure Closure, item cx.Node, idx int, state_ptr &ProgramState,
                  enclosing_bindings map[string]cx.Node,
                  enclosing_closures map[string]Closure, ch chan ParResult) {
	mut env := MatchEnv{
		bindings:     enclosing_bindings.clone()
		closures:     enclosing_closures.clone()
		state:        unsafe { state_ptr }
		anon_counter: 0
		frame_pool:   &FramePool{} // fresh per-worker frame pool (#36); thread-local, no sharing
	}
	val := invoke_closure(closure, [item], mut env) or {
		if err is EvalError {
			ch <- ParResult{idx: idx, err_code: err.code, err_message: err.message}
		} else {
			ch <- ParResult{idx: idx, err_code: 'cx-err:CXER0001', err_message: err.msg()}
		}
		return
	}
	ch <- ParResult{idx: idx, value: val}
}

// par_map runs `closure` over each item in `items` in parallel.
// Returns results in completion order when `ordered == false`, in
// source order when `ordered == true`. Propagates the earliest-index
// worker error if any worker raises.
fn par_map(closure Closure, items []cx.Node, ordered bool, mut env MatchEnv) ![]cx.Node {
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
		_ = ordered
		return seq
	}
	ch := chan ParResult{cap: n}
	for i, item in items {
		spawn par_map_worker(closure, item, i, env.state, env.bindings, env.closures, ch)
	}
	mut received := []ParResult{cap: n}
	for _ in 0 .. n {
		received << <-ch
	}
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
				return EvalError{ code: r.err_code, message: r.err_message }
			}
		}
	}
	if ordered {
		mut by_idx := []cx.Node{len: n, init: cx.Node(cx.Element{ name: '' })}
		for r in received {
			by_idx[r.idx] = r.value
		}
		return by_idx
	}
	// Unordered: return in completion order. Strip indices.
	mut out := []cx.Node{cap: n}
	for r in received {
		out << r.value
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
fn par_reduce(closure Closure, items []cx.Node, init cx.Node, mut env MatchEnv) !cx.Node {
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
		return acc
	}
	// Pick chunk count: one chunk per item up to a small ceiling so
	// we don't spawn 100k threads for a 100k-item input. The demo
	// workloads are tiny; the cap is generous.
	max_workers := 32
	mut k := if n < max_workers { n } else { max_workers }
	if k < 1 {
		k = 1
	}
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
			env.bindings, env.closures, ch)
		spawned++
	}
	mut received := []ParResult{cap: spawned}
	for _ in 0 .. spawned {
		received << <-ch
	}
	mut first_err_idx := -1
	for r in received {
		if r.err_message != '' && (first_err_idx < 0 || r.idx < first_err_idx) {
			first_err_idx = r.idx
		}
	}
	if first_err_idx >= 0 {
		for r in received {
			if r.idx == first_err_idx {
				return EvalError{ code: r.err_code, message: r.err_message }
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
fn par_reduce_range(closure Closure, start i64, end i64, step i64, init cx.Node, mut env MatchEnv) !cx.Node {
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
		return acc
	}
	max_workers := 32
	mut k := if count < i64(max_workers) { int(count) } else { max_workers }
	if k < 1 {
		k = 1
	}
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
			env.bindings, env.closures, ch)
		spawned++
	}
	mut received := []ParResult{cap: spawned}
	for _ in 0 .. spawned {
		received << <-ch
	}
	mut first_err_idx := -1
	for r in received {
		if r.err_message != '' && (first_err_idx < 0 || r.idx < first_err_idx) {
			first_err_idx = r.idx
		}
	}
	if first_err_idx >= 0 {
		for r in received {
			if r.idx == first_err_idx {
				return EvalError{ code: r.err_code, message: r.err_message }
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
	enclosing_closures map[string]Closure, ch chan ParResult) {
	mut env := MatchEnv{
		bindings:     enclosing_bindings.clone()
		closures:     enclosing_closures.clone()
		state:        unsafe { state_ptr }
		anon_counter: 0
		frame_pool:   &FramePool{} // fresh per-worker frame pool (#36); thread-local, no sharing
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
pub fn eval_map_directive_streamed(d cx.ProgramDirective, mut env MatchEnv, mut ctx StreamCtx) ! {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] requires positional source slot' }
	}
	mut source_node := d.slots[0].value
	mut using_slot := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit })
	mut have_using := false
	mut par_flag := false
	mut ordered_flag := false
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
			message: '[?map] :ordered requires :par' }
	}
	source_val := eval_node(source_node, mut env)!
	using_val := eval_node(using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?map] :using must evaluate to a closure' }
	}
	items := iterate(source_val)
	if par_flag {
		par_map_streamed(closure, items, ordered_flag, mut env, mut ctx)!
		return
	}
	// Sequential: emit one per iteration; each completes before the
	// next starts, so the user sees deterministic per-item progress.
	for item in items {
		mapped := invoke_closure(closure, [item], mut env)!
		ctx.emit_node(mapped)!
		ctx.flush()!
	}
}

// par_map_streamed fans workers out via `par_map_worker` and emits
// results as they arrive on the completion channel. Unordered: each
// result emitted in completion order. Ordered: buffer until all
// arrive, then emit in source order. Errors abort + propagate the
// lowest-index failure.
fn par_map_streamed(closure Closure, items []cx.Node, ordered bool,
                    mut env MatchEnv, mut ctx StreamCtx) ! {
	n := items.len
	if n == 0 {
		return
	}
	// Wasm-async fallback: sequential, but still per-item streamed —
	// the user sees results appear one at a time as each invocation
	// completes (visible cadence under [?sleep DUR] in the body).
	$if wasm32_emcc ? {
		_ = ordered
		for item in items {
			v := invoke_closure(closure, [item], mut env)!
			ctx.emit_node(v)!
			ctx.flush()!
		}
		return
	}
	ch := chan ParResult{cap: n}
	for i, item in items {
		spawn par_map_worker(closure, item, i, env.state, env.bindings, env.closures, ch)
	}
	mut received := []ParResult{cap: n}
	if ordered {
		for _ in 0 .. n {
			received << <-ch
		}
		mut first_err_idx := -1
		for r in received {
			if r.err_message != '' && (first_err_idx < 0 || r.idx < first_err_idx) {
				first_err_idx = r.idx
			}
		}
		if first_err_idx >= 0 {
			for r in received {
				if r.idx == first_err_idx {
					return EvalError{ code: r.err_code, message: r.err_message }
				}
			}
		}
		mut by_idx := []cx.Node{len: n, init: cx.Node(cx.Element{ name: '' })}
		for r in received {
			by_idx[r.idx] = r.value
		}
		for v in by_idx {
			ctx.emit_node(v)!
			ctx.flush()!
		}
		return
	}
	// Unordered: stream as each worker completes.
	for _ in 0 .. n {
		r := <-ch
		if r.err_message != '' {
			return EvalError{ code: r.err_code, message: r.err_message }
		}
		ctx.emit_node(r.value)!
		ctx.flush()!
	}
}

fn par_reduce_chunk_worker(closure Closure, chunk []cx.Node, init cx.Node, idx int,
                           state_ptr &ProgramState,
                           enclosing_bindings map[string]cx.Node,
                           enclosing_closures map[string]Closure, ch chan ParResult) {
	mut env := MatchEnv{
		bindings:     enclosing_bindings.clone()
		closures:     enclosing_closures.clone()
		state:        unsafe { state_ptr }
		anon_counter: 0
		frame_pool:   &FramePool{} // fresh per-worker frame pool (#36); thread-local, no sharing
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
