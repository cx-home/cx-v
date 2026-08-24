@[has_globals]
module code

import cx

// ── The demand-driven pull core — rule EV-PULL (code.md §6.7/§14.4;
// stream 17 W1, #710 item 6) ─────────────────────────────────────────
//
// A combinator pulls from its source exactly what it yields. The
// machinery: every combinator IteratorNode is constructed LAZY (empty
// memo) with its source normalized to an IteratorNode (materialized
// sources wrap in an exhausted iterator, so "read item i" is uniform:
// source.memo[i] when available, else pull the source). Transform
// closures are resolved at CONSTRUCTION and parked in the per-program
// ProgramState.iter_closures registry (an IteratorNode is Ring-0 and
// cannot hold a code-layer Closure; frame-local anons may be gone
// from env.closures by pull time) — iter_pull invokes them through
// the state every env shares. `consumed`/`consumed_inner` are the
// source cursors; memo stays the yielded prefix and sources memoize,
// so nothing re-executes (ev-pull-002: once per item, ever).
//
// DOCUMENTED full-force kinds (§6.7's "except where a combinator
// documents it"): partition and group-by must see the whole source
// to produce their outputs; cycle materializes its base once, then
// yields modularly without re-pulling. Everything else is
// item-incremental. The EV-BUDGET floor guards total pulls.

// iter_wrap_source normalizes any source value to an IteratorNode so
// pull-time reads are uniform. An IteratorNode passes through (chain
// laziness); anything else materializes ONCE into an exhausted
// wrapper (its iteration was already eager by shape).
fn iter_wrap_source(n cx.Node, mut env MatchEnv) cx.Node {
	if n is cx.IteratorNode {
		return n
	}
	return cx.Node(cx.IteratorNode{
		source_kind: .iter_range // opaque; exhausted wrappers never re-pull
		source_args: []
		memo:        iterate_env(n, mut env)
		exhausted:   true
	})
}

// IterClosureEntry parks one transform closure + the scope needed to
// rebuild a pull-time env (the closure's own captured bindings and
// defining scope carry its lexical world; the entry scope covers
// nested sibling resolution).
pub struct IterClosureEntry {
pub:
	cl    Closure
	scope &Scope = unsafe { nil }
	// The construction frame's closure table (aliased — the COW
	// discipline keeps aliases read-only): a parked closure's BODY may
	// reference sibling fn values by synthetic id (partials do), which
	// resolve only against this table.
	closures map[string]Closure
}

// iter_park_closure resolves a transform argument (a closure sentinel
// or fn value) to its Closure and parks it in the state registry,
// returning the registry id carried in source_args.
fn iter_park_closure(fnv cx.Node, mut env MatchEnv) !string {
	cl := resolve_closure(fnv, env) or {
		return error('cx-err:CXER0100: combinator transform is not callable')
	}
	id := 'itcl-${env.state.next_iter_closure_id}'
	env.state.next_iter_closure_id++
	env.state.iter_closures[id] = IterClosureEntry{
		cl:       cl
		scope:    env.scope
		closures: env.closures
	}
	return id
}

// iter_invoke_parked invokes a parked transform against its OWN
// construction-frame world (closures table + scope — EV-CLOSURE-CAP-
// faithful lexical capture), sharing the caller's state/frame pool.
fn iter_invoke_parked(id_node cx.Node, args []cx.Node, mut env MatchEnv) !cx.Node {
	id := scalar_text_of(id_node)
	entry := env.state.iter_closures[id] or {
		return error('cx-err:CXER0001: iterator closure registry miss (${id})')
	}
	mut penv := MatchEnv{
		state:           env.state
		scope:           entry.scope
		closures:        entry.closures
		closures_shared: true
		frame_pool:      env.frame_pool
	}
	return invoke_closure(entry.cl, args, mut penv)!
}

// iter_force_via_state is the env-free consumer's forcing hook
// (iterate() calls it for an unexhausted combinator node): it builds
// a minimal pull env over the shared ProgramState — the transform
// closures carry their own captured bindings and defining scopes, so
// the pull env supplies only state + a scope + a frame pool.
fn iter_force_via_state(mut it cx.IteratorNode, state &ProgramState) ?[]cx.Node {
	mut scope := &Scope(unsafe { nil })
	for _, entry in state.iter_closures {
		if entry.scope != unsafe { nil } {
			scope = entry.scope
			break
		}
	}
	mut penv := MatchEnv{
		state:      unsafe { state }
		scope:      scope
		frame_pool: &FramePool{}
	}
	iter_pull(mut it, -1, mut penv) or {
		// A pull failure is NEVER silent: the iterator collapses to an
		// err-terminal carrying the failure (§9.2 at the force point).
		ecode := err_code_of_msg(err.msg())
		mut emsg := err.msg()
		if emsg.starts_with(ecode + ': ') {
			emsg = emsg[ecode.len + 2..]
		}
		iter_mark_err(mut it, mk_err(ecode, emsg))
		return it.memo.clone()
	}
	return it.memo.clone()
}

// iter_mark_err collapses an iterator to its §9.2 err-terminal.
fn iter_mark_err(mut it cx.IteratorNode, e cx.Node) {
	it.memo = [e]
	it.exhausted = true
	it.err_terminal = true
}

fn err_code_of_msg(msg string) string {
	if i := msg.index('cx-err:CXER') {
		tail := msg[i..]
		ecode := tail.all_before(' ').trim_right('.,;')
		if ecode.len >= 15 {
			return ecode[..15]
		}
	}
	return 'cx-err:CXER0100'
}

fn scalar_text_of(n cx.Node) string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// mk_lazy_iterator constructs a demand-driven combinator node (the
// EV-PULL replacement for the retired mk_eager_iterator).
fn mk_lazy_iterator(source_kind cx.IteratorSourceKind, source_args []cx.Node) cx.Node {
	return cx.Node(cx.IteratorNode{
		source_kind: source_kind
		source_args: source_args
		memo:        []
		exhausted:   false
		single_use:  false
	})
}

// iter_source_read reads item `idx` of a (normalized) source,
// pulling it forward on demand. none = the source ended before idx.
fn iter_source_read(src_node cx.Node, idx i64, mut env MatchEnv) !cx.Node {
	if src_node is cx.IteratorNode {
		mut src := unsafe { &cx.IteratorNode(&src_node) }
		if i64(src.memo.len) <= idx && !src.exhausted {
			iter_pull(mut src, idx + 1, mut env)!
		}
		if i64(src.memo.len) > idx {
			return src.memo[int(idx)]
		}
		return error(iter_src_end)
	}
	// Non-normalized source (defensive): eager read.
	items := iterate_env(src_node, mut env)
	if i64(items.len) > idx {
		return items[int(idx)]
	}
	return error(iter_src_end)
}

// iter_src_end is the in-band source-exhausted sentinel for
// iter_source_read (a Result, not an Option — V callers then pattern
// on the message; never surfaces to programs).
const iter_src_end = '__iter_src_end__'

// iter_read_or_end wraps iter_source_read: (item, false) or
// (dummy, true) on source end; real errors propagate.
fn iter_read_or_end(src cx.Node, idx i64, mut env MatchEnv) !(cx.Node, bool) {
	item := iter_source_read(src, idx, mut env) or {
		if err.msg() == iter_src_end {
			return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type }), true
		}
		return err
	}
	return item, false
}

// iter_pull extends `it.memo` to `want` items (want < 0 = all),
// setting `exhausted` when the source ends. The one entry point for
// demand-driven consumption; generator and live-source kinds delegate
// to the pre-W1 full-force walker (they carry no closures) except
// the bounded generators, which respect `want`.
fn iter_pull(mut it cx.IteratorNode, want i64, mut env MatchEnv) ! {
	if it.exhausted {
		return
	}
	if want < 0 && iter_statically_infinite(cx.Node(it)) {
		return error('cx-err:CXER0100: infinite range cannot be fully materialised — use [take] / [take-while]')
	}
	// EV-BUDGET: implementations MUST accept ≥ the floor in pulls
	// BEFORE the guard may fire — exactly-at-the-floor succeeds.
	mut steps := i64(0)
	for !it.exhausted && (want < 0 || i64(it.memo.len) < want) {
		if steps > i64(generator_force_budget) {
			return error('cx-err:CXER0100: iterator force budget exceeded (EV-BUDGET floor ${generator_force_budget})')
		}
		steps++
		iter_pull_step(mut it, want, mut env)!
	}
}

// iter_pull_step advances the iterator by AT LEAST one yielded item
// or exhausts it. One match arm per incremental kind.
fn iter_pull_step(mut it cx.IteratorNode, want i64, mut env MatchEnv) ! {
	match it.source_kind {
		.iter_map {
			item, item_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
			if item_end {
				it.exhausted = true
				return
			}
			it.consumed++
			mapped := iter_invoke_parked(it.source_args[1], [item], mut env)!
			if is_err_value(mapped) {
				iter_mark_err(mut it, mapped)
				return
			}
			it.memo << mapped
		}
		.iter_filter {
			item, item_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
			if item_end {
				it.exhausted = true
				return
			}
			it.consumed++
			verdict := iter_invoke_parked(it.source_args[1], [item], mut env)!
			if is_err_value(verdict) {
				// §9.2 / #348(a): an err-valued predicate short-circuits
				// the whole filter — under EV-PULL it surfaces at the
				// force point (err-terminal).
				iter_mark_err(mut it, verdict)
				return
			}
			if node_ebv(verdict)! {
				it.memo << item
			}
		}
		.iter_take {
			n := iter_arg_int(it.source_args[1])
			if i64(it.memo.len) >= n {
				it.exhausted = true
				return
			}
			item, item_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
			if item_end {
				it.exhausted = true
				return
			}
			it.consumed++
			it.memo << item
			if i64(it.memo.len) >= n {
				it.exhausted = true
			}
		}
		.iter_drop {
			n := iter_arg_int(it.source_args[1])
			idx := n + it.consumed
			item, item_end := iter_read_or_end(it.source_args[0], idx, mut env)!
			if item_end {
				it.exhausted = true
				return
			}
			it.consumed++
			it.memo << item
		}
		.iter_enumerate {
			item, item_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
			if item_end {
				it.exhausted = true
				return
			}
			idx := it.consumed
			it.consumed++
			it.memo << cx.Node(cx.Element{
				name:  seq_marker_name
				items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(idx), data_type: .int_type }),
					item]
			})
		}
		.iter_zip {
			a, a_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
			if a_end {
				it.exhausted = true
				return
			}
			b, b_end := iter_read_or_end(it.source_args[1], it.consumed, mut env)!
			if b_end {
				it.exhausted = true
				return
			}
			it.consumed++
			it.memo << cx.Node(cx.Element{ name: seq_marker_name, items: [a, b] })
		}
		.iter_chunks {
			size := iter_arg_int(it.source_args[1])
			mut chunk := []cx.Node{}
			for i64(chunk.len) < size {
				item, ended := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
				if ended {
					break
				}
				it.consumed++
				chunk << item
			}
			if chunk.len == 0 {
				it.exhausted = true
				return
			}
			it.memo << cx.Node(cx.Element{ name: seq_marker_name, items: chunk })
			if i64(chunk.len) < size {
				it.exhausted = true
			}
		}
		.iter_concat, .iter_chain {
			// consumed_inner = which source; consumed = index within it.
			for int(it.consumed_inner) < it.source_args.len {
				item, ended := iter_read_or_end(it.source_args[int(it.consumed_inner)], it.consumed, mut env)!
				if ended {
					it.consumed_inner++
					it.consumed = 0
					continue
				}
				it.consumed++
				it.memo << item
				return
			}
			it.exhausted = true
		}
		.iter_cycle {
			// The base materializes ONCE (documented — a cycle must know
			// its period); yields are modular reads of the base memo.
			base := it.source_args[0]
			if base is cx.IteratorNode {
				mut b := unsafe { &cx.IteratorNode(&base) }
				if !b.exhausted {
					iter_pull(mut b, -1, mut env)!
				}
				if b.memo.len == 0 {
					it.exhausted = true
					return
				}
				it.memo << b.memo[int(it.consumed % i64(b.memo.len))]
				it.consumed++
				return
			}
			it.exhausted = true
		}
		.iter_scan {
			item, item_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
			if item_end {
				it.exhausted = true
				return
			}
			it.consumed++
			acc := if it.memo.len > 0 {
				it.memo.last()
			} else {
				it.source_args[2] // seed
			}
			it.memo << iter_invoke_parked(it.source_args[1], [acc, item], mut env)!
		}
		.iter_flatten {
			for {
				inner, inner_end := iter_read_or_end(it.source_args[0], it.consumed, mut env)!
				if inner_end {
					it.exhausted = true
					return
				}
				inner_items := iterate_env(inner, mut env)
				if it.consumed_inner < i64(inner_items.len) {
					it.memo << inner_items[int(it.consumed_inner)]
					it.consumed_inner++
					if it.consumed_inner >= i64(inner_items.len) {
						it.consumed++
						it.consumed_inner = 0
					}
					return
				}
				it.consumed++
				it.consumed_inner = 0
			}
		}
		.iter_range_open {
			// The open range yields bounded under EV-PULL: value =
			// start + step * yielded-count; never self-exhausts (the
			// bounded consumer or the budget is the stop).
			start := iter_arg_int(it.source_args[0])
			step := if it.source_args.len > 1 { iter_arg_int(it.source_args[1]) } else { i64(1) }
			it.memo << cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(start + step * i64(it.memo.len))
				data_type: .int_type
			})
		}
		else {
			// Generator / live / full-force kinds: the pre-W1 walker
			// (range/open-range/iterate/unfold respect no `want` — the
			// bounded consumers above are the demand seam; partition /
			// group-by are DOCUMENTED full-force).
			pull_iterator_to_end(mut it) or {
				it.exhausted = true
				return err
			}
		}
	}
}

fn iter_arg_int(n cx.Node) i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
	}
	return 0
}

// iterate_env is the env-bearing forcing consumer: combinator
// iterators pull to exhaustion THROUGH their closures; every other
// shape takes the classic iterate() path.
pub fn iterate_env(n cx.Node, mut env MatchEnv) []cx.Node {
	if n is cx.IteratorNode {
		if !n.exhausted {
			mut it := unsafe { &cx.IteratorNode(&n) }
			iter_pull(mut it, -1, mut env) or { return it.memo.clone() }
			return it.memo.clone()
		}
	}
	return iterate(n)
}

// force_lazy_result forces any unexhausted iterators reachable in a
// program RESULT while the env is still alive — the one boundary
// where laziness must end (render/EBV are env-free by design and
// never force). Containers recurse shallowly (sequence/array/element
// items); everything else passes through.
pub fn force_lazy_result(n cx.Node, mut env MatchEnv) cx.Node {
	if n is cx.IteratorNode {
		items := iterate_env(n, mut env)
		if n.err_terminal && items.len == 1 {
			// §9.2 short-circuit: the err IS the result, bare.
			return items[0]
		}
		return cx.Node(cx.Element{ name: seq_marker_name, items: items })
	}
	if n is cx.Element {
		mut changed := false
		mut new_items := []cx.Node{cap: n.items.len}
		for it in n.items {
			f := force_lazy_result(it, mut env)
			if !changed && f !is cx.IteratorNode {
				// cheap identity check is not possible on sum values;
				// track change by kind transition only.
				if it is cx.IteratorNode {
					changed = true
				}
			}
			new_items << f
		}
		if changed {
			mut e2 := n
			e2.items = new_items
			return cx.Node(e2)
		}
		return n
	}
	return n
}

// g_iter_pull_state carries the current program's state pointer so the
// env-free iterate() can force combinator chains (set by new_env; one
// program per process at a time — the established process-global
// posture of caps/prof/sched).
__global (
	g_iter_pull_state voidptr
)

// iter_pull_state_set is called by new_env.
fn iter_pull_state_set(state &ProgramState) {
	g_iter_pull_state = voidptr(state)
}

// iter_is_pull_kind reports whether a source kind takes the W1
// demand-driven pull path (combinator kinds; generators and live
// sources keep the classic walker).
fn iter_is_pull_kind(k cx.IteratorSourceKind) bool {
	return k in [cx.IteratorSourceKind.iter_map, .iter_filter, .iter_take, .iter_drop,
		.iter_zip, .iter_enumerate, .iter_chunks, .iter_concat, .iter_chain, .iter_cycle,
		.iter_scan, .iter_flatten, .iter_range_open]
}

// iter_statically_infinite reports a chain that can NEVER exhaust —
// an open-range (or a map/filter/… whose source chain bottoms out in
// one) with no bounding take between. Unbounded forcing of such a
// chain keeps the classic STATIC refusal (never a 1M-pull crawl to
// the budget guard).
fn iter_statically_infinite(n cx.Node) bool {
	if n is cx.IteratorNode {
		match n.source_kind {
			.iter_range_open, .iter_iterate, .iter_unfold, .iter_cycle {
				return true
			}
			.iter_take {
				return false
			}
			.iter_map, .iter_filter, .iter_drop, .iter_scan, .iter_enumerate {
				if n.source_args.len > 0 {
					return iter_statically_infinite(n.source_args[0])
				}
			}
			else {}
		}
	}
	return false
}

fn mk_scalar_string(s string) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: .string_type
	})
}
