module main

import cx
import code
import os

// ── program evaluator tests (pure-functional core) ───────────────────────────────
//
// Each test parses CX source via the parser, evaluates it against a
// binding env, and asserts the resulting cx.Node shape.

fn run(src string) cx.Node {
	mut env := code.new_env()
	prog := cx.parse_program(src) or { panic('parse failed: ${err}') }
	return code.eval(prog.body, mut env) or { panic('eval failed: ${err}') }
}

fn run_with(src string, bindings map[string]cx.Node) cx.Node {
	mut env := code.new_env()
	for k, v in bindings {
		env.bindings[k] = v
	}
	prog := cx.parse_program(src) or { panic('parse failed: ${err}') }
	return code.eval(prog.body, mut env) or { panic('eval failed: ${err}') }
}

fn cx_root(source string) cx.Element {
	doc := cx.parse(source) or { panic(err) }
	for i in 0 .. doc.elements.len {
		n := doc.elements[i]
		if n is cx.Element {
			return n
		}
	}
	panic('no Element')
}

fn s_string(n cx.Node, expected string) bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is string { return v == expected }
	}
	return false
}

fn s_int(n cx.Node, expected i64) bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 { return v == expected }
	}
	return false
}

fn s_bool(n cx.Node, expected bool) bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool { return v == expected }
	}
	return false
}

// slot_string reads a scalar err/result field by name. Per,
// scalar fields are ATTRIBUTES (not `__cx_slot:` children), so this reads
// the attribute. (Name kept for call-site stability; reads an attribute.)
fn slot_string(el cx.Element, label string) string {
	return el.attr(label)
}

fn slot_int(el cx.Element, label string) i64 {
	s := el.attr(label)
	if s == '' {
		return 0
	}
	return s.i64()
}

// ── Literals ────────────────────────────────────────────────────────────────

fn test_eval_string_literal() {
	assert s_string(run("'hello'"), 'hello')
}

fn test_eval_int_literal() {
	assert s_int(run('42'), 42)
}

fn test_eval_bool_literal() {
	assert s_bool(run('true'), true)
}

fn test_eval_sequence_literal() {
	r := run('(1, 2, 3)')
	if r is cx.Element {
		assert r.items.len == 3
		assert s_int(r.items[0], 1)
		assert s_int(r.items[2], 3)
	} else { assert false }
}

fn test_eval_array_literal() {
	r := run('[1, 2, 3]')
	if r is cx.Element {
		assert r.items.len == 3
	} else { assert false }
}

fn test_eval_cx_element_literal() {
	r := run("[user 'alice' 'extra']")
	if r is cx.Element {
		assert r.name == 'user'
		assert r.items.len == 2
	} else { assert false }
}

fn test_eval_cx_element_with_attribute() {
	// v0.8.0 surface (D014): element construction uses attributes, NOT the
	// retired `:value 42` colon-slot. `[ok value=42]` builds `ok` with a
	// `value` attribute.
	r := run("[ok value=42]")
	if r is cx.Element {
		assert r.name == 'ok'
		assert r.attrs.len == 1
		assert r.attrs[0].name == 'value'
		v := r.attrs[0].value
		if v is i64 {
			assert v == 42
		} else {
			assert false, 'value attr should be int 42'
		}
	} else { assert false }
}

fn test_eval_cx_element_colon_atom_is_body_item() {
	// A `:NAME` token in element body is now an atom body item (the slot
	// reshape is retired). `[ok :value 42]` → element `ok` with body atom
	// `:value` + int 42.
	r := run("[ok :value 42]")
	if r is cx.Element {
		assert r.name == 'ok'
		assert r.attrs.len == 0
		assert r.items.len == 2
		first := r.items[0]
		if first is cx.ScalarNode {
			assert first.data_type == cx.ScalarType.atom_type
		} else {
			assert false, 'first body item should be the `:value` atom'
		}
	} else { assert false }
}

// ── Bindings + paths ────────────────────────────────────────────────────────

fn test_eval_bare_binding() {
	r := run_with('$x', { 'x': cx.Node(cx.ScalarNode{
		value: cx.ScalarValue('looked-up'), data_type: cx.ScalarType.string_type
	}) })
	assert s_string(r, 'looked-up')
}

fn test_eval_binding_with_child_path() {
	user := cx_root("[user [name 'alice']]")
	r := run_with('$u/name', { 'u': cx.Node(user) })
	// a simple terminal labeled-field accessor (pure child
	// chain, single focus, single-item child) auto-unwraps to the inner
	// value, so `$u/name` reads the body text 'alice' rather than the
	// `[name …]` element.
	if r is cx.TextNode {
		assert r.value == 'alice'
	} else { assert false }
}

fn test_eval_binding_with_attr_path() {
	user := cx_root("[user name=alice]")
	r := run_with('$u@name', { 'u': cx.Node(user) })
	assert s_string(r, 'alice')
}

fn test_unbound_variable_raises() {
	mut env := code.new_env()
	prog := cx.parse_program('$missing') or { panic(err) }
	code.eval(prog.body, mut env) or {
		assert err is code.EvalError
		return
	}
	assert false
}

// ── Calls ───────────────────────────────────────────────────────────────────

fn test_eval_count_builtin() {
	assert s_int(run('count((1, 2, 3))'), 3)
}

fn test_eval_empty_builtin_true() {
	assert s_bool(run('empty(())'), true)
}

fn test_eval_empty_builtin_false() {
	assert s_bool(run('empty((1, 2))'), false)
}

fn test_eval_upper_builtin() {
	assert s_string(run("upper('hi')"), 'HI')
}

fn test_eval_eq_builtin_true() {
	assert s_bool(run("eq('a', 'a')"), true)
}

fn test_eval_eq_builtin_false() {
	assert s_bool(run("eq('a', 'b')"), false)
}

// ── Pipe ────────────────────────────────────────────────────────────────────

fn test_pipe_threads_through_count() {
	// §8.9: bare transform stage; the threaded value is appended as the
	// final positional arg (`count` ≡ `[$count _]`). No infix `|`, no
	// `[through]` wrapper (both retired).
	r := run('[?pipe (1, 2, 3) count]')
	assert s_int(r, 3)
}

// ── If ──────────────────────────────────────────────────────────────────────

fn test_if_truthy_branch() {
	r := run("[?if true [then 'yes'] [else 'no']]")
	assert s_string(r, 'yes')
}

fn test_if_falsy_branch() {
	r := run("[?if false [then 'yes'] [else 'no']]")
	assert s_string(r, 'no')
}

// ── Let ─────────────────────────────────────────────────────────────────────

fn test_let_simple() {
	r := run('[?let [= $x 10] $x]')
	assert s_int(r, 10)
}

fn test_let_chained() {
	r := run('[?let [= $a 10] [?let [= $b 32] count(($a, $b))]]')
	assert s_int(r, 2)
}

// ── For-comprehension ───────────────────────────────────────────────────────

fn test_for_basic() {
	r := run('[?for [in $x (1, 2, 3)] [yield $x]]')
	if r is cx.Element {
		assert r.items.len == 3
		assert s_int(r.items[0], 1)
	} else { assert false }
}

fn test_for_with_where() {
	r := run("[?for [in \$x (1, 2, 3)] [where eq(\$x, 2)] [yield \$x]]")
	if r is cx.Element {
		assert r.items.len == 1
		assert s_int(r.items[0], 2)
	} else { assert false }
}

fn test_for_with_let() {
	r := run('[?for [in $x (1, 2)] [= $y $x] [yield $y]]')
	if r is cx.Element {
		assert r.items.len == 2
	} else { assert false }
}

// ── Find ────────────────────────────────────────────────────────────────────

fn test_find_yields_per_match() {
	doc := cx_root("[users [user [name 'alice']] [user [name 'bob']]]")
	r := run_with('[?for [user [name $n]] [yield $n]]', { 'doc': cx.Node(doc) })
	if r is cx.Element {
		assert r.items.len == 2
	} else { assert false }
}

fn test_find_with_attribute_predicate() {
	doc := cx_root("[users [user active=true [name 'alice']] [user active=false [name 'bob']]]")
	r := run_with('[?for [user @active=true [name $n]] [yield $n]]', { 'doc': cx.Node(doc) })
	if r is cx.Element {
		assert r.items.len == 1
	} else { assert false }
}

// ── Try (RETIRED, SAP C3c) ──────────────────────────────────────────────────
// `[?try]` is no longer in the §4.1 registry — handling unifies on
// [?match]/[?else]/[?fallback]/[?with-error-hook] + ?/!. The unknown-
// directive rejection is pinned here; the recovery semantics live in the
// [?match] tests + conformance sap-try-01/02 negatives.

fn test_try_is_retired_unknown_directive() {
	cx.parse_program("[?try 'x' [catch \$e \$e]]") or {
		assert err.msg().contains('unknown directive')
		return
	}
	assert false, '[?try] must no longer parse'
}

fn test_match_catches_err_value() {
	// The migrated surface: an err-value scrutinee reaches the arms.
	r := run('[?match notabuiltin() [case [err \$e] \$e] [else ok]]')
	if r is cx.Element {
		assert r.name == 'err' // result envelope
	} else { assert false }
}

// ── Closures ────────────────────────────────────────────────────────────────

fn test_fn_creates_callable() {
	// [?fn] returns a closure sentinel; binding it via [?let] and
	// invoking by binding-call should evaluate the body with the arg.
	r := run('[?let [= $double [?fn $x count(($x, $x))]] $double(42)]')
	assert s_int(r, 2)
}

fn test_fn_paren_param_list() {
	r := run('[?let [= $add [?fn ($a $b) count(($a, $b))]] $add(1, 2)]')
	assert s_int(r, 2)
}

fn test_def_named_function() {
	// 0060 unified [?def] form: `[?def NAME ($params) body]`.
	// (The retired `:name/:params/:body` slot form was removed.)
	// Multi-statement programs evaluate each top-level expression in
	// order, sharing the env (so [?def] registers `greeting` for
	// subsequent calls), and return the LAST expression's value.
	r := run("[?def greeting ($who) upper(\$who)] greeting('alice')")
	if !s_string(r, 'ALICE') {
		eprintln('def call result was: ${r}')
	}
	assert s_string(r, 'ALICE')
}

fn test_fn_closure_captures_lexical_env() {
	r := run("[?let [= \$base 10] [?let [= \$add-base [?fn \$x count((\$base, \$x))]] \$add-base(5)]]")
	assert s_int(r, 2)
}

// ── Error-postfix semantics (spec/code.md §9.2) ──────────────────────────────

fn test_bang_postfix_panics_on_err_result() {
	// no-such-builtin yields an [err] value; ! postfix should escalate
	// to a hard EvalError.
	mut env := code.new_env()
	prog := cx.parse_program('notabuiltin()!') or { panic(err) }
	code.eval(prog.body, mut env) or {
		assert err is code.EvalError
		return
	}
	assert false, 'expected EvalError from !-postfix on err result'
}

fn test_qmark_postfix_propagates_err() {
	// ? postfix is documentation-only — return value flows through.
	r := run("notabuiltin()?")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
	} else { assert false }
}

fn test_bang_postfix_passthrough_on_ok() {
	// ! on a successful call returns the value verbatim.
	r := run("upper('hi')!")
	assert s_string(r, 'HI')
}

// ── Resilience: [?fallback] and [?retry] ────────────────────────────────────

fn test_fallback_primary_success() {
	r := run("[?fallback 'primary' [recover-with 'secondary']]")
	assert s_string(r, 'primary')
}

fn test_fallback_primary_err_secondary_value() {
	r := run("[?fallback notabuiltin() [recover-with 'recovered']]")
	assert s_string(r, 'recovered')
}

fn test_fallback_both_err_returns_secondary_err() {
	// Both bodies err → fallback does NOT wrap the secondary err per spec §10.2.4.
	r := run("[?fallback notabuiltin() [recover-with another-bad-name()]]")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
	} else { assert false }
}

fn test_retry_happy_path_first_attempt() {
	r := run("[?retry max=3 'success']")
	assert s_string(r, 'success')
}

fn test_retry_exhausts_to_cxer0140() {
	r := run("[?retry max=3 notabuiltin()]")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
		// :code / :attempts now stored as __cx_slot:* children
		// (see eval.v mk_err_with_slots) so render emits the slot form.
		err_code := slot_string(r, 'code')
		assert err_code == 'cx-err:CXER0140'
		attempts := slot_int(r, 'attempts')
		assert attempts == 3
	} else { assert false }
}

fn test_retry_max_zero_rejects() {
	mut env := code.new_env()
	prog := cx.parse_program('[?retry max=0 42]') or { panic(err) }
	code.eval(prog.body, mut env) or {
		assert err is code.EvalError
		return
	}
	assert false
}

// ── Stateful resilience: [?timeout] [?circuit-breaker] [?rate-limit] ────────

fn test_timeout_completes_within() {
	r := run("[?timeout 1s 'fast']")
	assert s_string(r, 'fast')
}

fn test_timeout_deadline_exceeded_to_cxer0141() {
	// Mock-clock sleep: bare [?sleep] is wall-clock; resilience-
	// directive unit tests stay deterministic by using :mock.
	r := run("[?timeout 100ms [?let [= \$_ [?sleep 500ms [mock]]] 'never']]")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
		assert slot_string(r, 'code') == 'cx-err:CXER0141'
	} else { assert false }
}

fn test_timeout_on_timeout_recovery() {
	r := run("[?timeout 100ms [?let [= \$_ [?sleep 500ms [mock]]] 'never'] [on-timeout 'recovered']]")
	assert s_string(r, 'recovered')
}

fn test_cb_closed_passthrough() {
	r := run("[?circuit-breaker threshold=0.5 window=60s reset=30s min-samples=10 'ok-val']")
	assert s_string(r, 'ok-val')
}

fn test_cb_trips_open_after_failures() {
	// Trigger trip with :min-samples=1, then second call returns CXER0150.
	r := run("[?let [= \$a [?circuit-breaker threshold=0.0 window=60s reset=30s min-samples=1 name='cb-test' [?test-always-err]]] [?let [= \$b [?circuit-breaker threshold=0.0 window=60s reset=30s min-samples=1 name='cb-test' [?test-always-err]]] count((\$a, \$b))]]")
	assert s_int(r, 2)
}

fn test_cb_threshold_bounds_rejected() {
	mut env := code.new_env()
	prog := cx.parse_program("[?circuit-breaker threshold=1.5 window=60s reset=30s min-samples=1 'x']") or { panic(err) }
	code.eval(prog.body, mut env) or {
		assert err is code.EvalError
		return
	}
	assert false
}

fn test_rate_limit_under() {
	r := run("[?rate-limit max=5 per=1s 'under']")
	assert s_string(r, 'under')
}

fn test_rate_limit_over_returns_cxer0151() {
	r := run("[?let [= \$a [?rate-limit max=1 per=1s name='rl-t' 'a']] [?let [= \$b [?rate-limit max=1 per=1s name='rl-t' 'b']] \$b]]")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
		assert slot_string(r, 'code') == 'cx-err:CXER0151'
	} else { assert false }
}

fn test_rate_limit_replenishes_after_window() {
	r := run("[?let [= \$a [?rate-limit max=1 per=1s name='rl-r' 'a']] [?let [= \$_ [?test-clock advance=1100ms]] [?let [= \$c [?rate-limit max=1 per=1s name='rl-r' 'c']] \$c]]]")
	assert s_string(r, 'c')
}

// ── Test helpers ────────────────────────────────────────────────────────────

fn test_helper_test_always_err() {
	r := run("[?test-always-err]")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
	} else { assert false }
}

fn test_helper_test_err_then_ok_first_call_errs() {
	r := run("[?test-err-then-ok err-count=2 ok-value='done']")
	if r is cx.Element {
		assert r.name == 'err' // result envelope
	} else { assert false }
}

fn test_sleep_advances_mock_clock() {
	// Mock-clock sleep: explicit :mock keeps the test
	// deterministic + sub-second wall-clock. The timeout fixture
	// (above) cross-validates that mock-clock ns drives deadlines.
	r := run("[?let [= \$_ [?sleep 5s [mock]]] 'after-sleep']")
	assert s_string(r, 'after-sleep')
}

// ── Concurrency: channels + workers + select (Phase 3.9) ────────────────────

fn test_channel_send_receive() {
	r := run("[?let [= \$ch [?channel name='c1' buffer=1]] [?let [= \$_ [?send 'hello' to=\$ch]] [?receive from=\$ch]]]")
	assert s_string(r, 'hello')
}

fn test_channel_send_to_closed() {
	r := run("[?let [= \$ch [?channel name='c2' buffer=1]] [?let [= \$_ [?close \$ch]] [?send 'x' to=\$ch]]]")
	if r is cx.Element {
		// result envelope: errors are [result status=err …].
		assert r.name == 'err'
		assert slot_string(r, 'code') == 'cx-err:CXER0200'
	} else { assert false }
}

fn test_channel_double_close() {
	r := run("[?let [= \$ch [?channel name='c3' buffer=1]] [?let [= \$_ [?close \$ch]] [?close \$ch]]]")
	if r is cx.Element {
		assert slot_string(r, 'code') == 'cx-err:CXER0203'
	} else { assert false }
}

fn test_try_receive_empty_timeout() {
	r := run("[?let [= \$ch [?channel name='c4' buffer=1]] [?try-receive from=\$ch timeout=50ms]]")
	if r is cx.Element {
		assert slot_string(r, 'code') == 'cx-err:CXER0202'
	} else { assert false }
}

fn test_try_send_buffer_full() {
	r := run("[?let [= \$ch [?channel name='c5' buffer=1]] [?let [= \$_ [?send 'first' to=\$ch]] [?try-send 'second' to=\$ch timeout=50ms]]]")
	if r is cx.Element {
		assert slot_string(r, 'code') == 'cx-err:CXER0201'
	} else { assert false }
}

fn test_worker_happy_path() {
	r := run("[?let [= \$w [?worker name='w1' [body 'worker-result']]] [?wait-for [worker \$w]]]")
	assert s_string(r, 'worker-result')
}

fn test_worker_handle_lookup_miss() {
	r := run("[?worker-handle name='does-not-exist']")
	if r is cx.Element {
		assert slot_string(r, 'code') == 'cx-err:CXER0222'
	} else { assert false }
}

fn test_worker_cancel() {
	r := run("[?let [= \$w [?worker name='w-cancel' [body 'done']]] [?let [= \$_ [?cancel [worker \$w]]] [?wait-for [worker \$w]]]]")
	if r is cx.Element {
		assert slot_string(r, 'code') == 'cx-err:CXER0221'
	} else { assert false }
}

// ── IteratorNode foundation (W3a + W3b) ────────────────────────────
//
// Iterator is the lazy + memoized value kind grafted onto Node in
// vcx/cx/ast.v. W3a wires the foundation: an IteratorNode wrapping a
// `range(start, end[, step])` source materializes its memo on first
// `iterate()` and renders to paren-comma `(a, b, c)` form at the host
// boundary. Identity equality (OQ4) means two freshly
// constructed iterators with identical sources compare unequal.

fn mk_int(i i64) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	})
}

fn test_adr0041_iterator_range_materializes_via_iterate() {
	// `range(1, 5)` iterator — first iterate() pulls items into memo
	// and returns the freshly-pulled list.
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(1), mk_int(5)])
	items := code.iterate_pub(iter)
	assert items.len == 5
	for i, item in items {
		if item is cx.ScalarNode {
			v := item.value
			if v is i64 {
				assert v == i64(i + 1)
				continue
			}
		}
		assert false
	}
}

fn test_adr0041_iterator_renders_paren_comma_form() {
	// Host-boundary render — `range(1, 5)` iterator renders as
	// `(1, 2, 3, 4, 5)` matching SequenceNode's paren-comma form.
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(1), mk_int(5)])
	// Force-materialize.
	_ := code.iterate_pub(iter)
	rendered := code.render_node_pub(iter)
	assert rendered == '(1, 2, 3, 4, 5)'
}

fn test_adr0041_iterator_identity_equality_oq4() {
	// Two freshly-constructed iterators with identical sources compare
	// UNEQUAL per OQ4 — identity is the backing heap allocation.
	a := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(1), mk_int(3)])
	b := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(1), mk_int(3)])
	assert !code.nodes_equal_pub(a, b)

	// The same iterator compares equal to itself.
	assert code.nodes_equal_pub(a, a)
}

fn test_adr0041_iterator_memoization_on_repull() {
	// Once exhausted, iterate() returns the memo as-is. The second
	// pull MUST produce the same items as the first (memoization).
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(2), mk_int(4)])
	first := code.iterate_pub(iter)
	second := code.iterate_pub(iter)
	assert first.len == second.len
	assert first.len == 3
	for i in 0 .. first.len {
		assert code.nodes_equal_pub(first[i], second[i])
	}
}

fn test_adr0041_iterator_empty_range() {
	// direction-step disagreement yields empty.
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(5), mk_int(1)])  // start > end, default step 1
	items := code.iterate_pub(iter)
	assert items.len == 0
}

fn test_adr0041_iterator_strided() {
	// `range(start, end, step)` ships items inclusively
	// of `end` when stride aligns.
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[mk_int(1), mk_int(9), mk_int(2)])
	items := code.iterate_pub(iter)
	assert items.len == 5
	expected := [i64(1), 3, 5, 7, 9]
	for i, item in items {
		if item is cx.ScalarNode {
			v := item.value
			if v is i64 {
				assert v == expected[i]
				continue
			}
		}
		assert false
	}
}

// ── Tail-call optimization (#60) ─────────────────────────────────────────────
// A tail-recursive loop must run in O(1) native C stack. Before TCO the tree-
// walker recursed ~42 KB/level and SIGSEGV'd at ~190 deep — a depth these tests
// blow past, so they would crash the test process rather than fail an assert if
// the trampoline regressed. 50k deep is well beyond the old limit yet fast.

fn test_tco_deep_tail_recursion_via_if() {
	src := '[?def loop (\$n) [?if [= \$n 0] [then "ok"] [else [loop [- \$n 1]]]]]
[loop 50000]'
	r := run(src)
	assert s_string(r, 'ok')
}

fn test_tco_deep_tail_recursion_through_let_body() {
	// Tail position must thread through a [?let] body (the streaming read-loop
	// shape), not just [?if] branches.
	src := '[?def loop (\$n)
  [?let [= \$m [- \$n 1]]
   [?if [= \$n 0] [then "done"] [else [loop \$m]]]]]
[loop 50000]'
	r := run(src)
	assert s_string(r, 'done')
}

fn test_tco_accumulator_loop_returns_correct_value() {
	// TCO must preserve semantics: a tail-recursive sum 0..n must compute the
	// right total, not merely avoid overflow.
	src := '[?def sum (\$n \$acc) [?if [= \$n 0] [then \$acc] [else [sum [- \$n 1] [+ \$acc \$n]]]]]
[sum 1000 0]'
	r := run(src)
	assert s_int(r, 500500)
}

// ── Concurrent [?worker] (#58, CX_WORKER_THREADS) ────────────────────────────
// With the flag on, a [?worker] body runs on its own spawned V thread (so it
// coexists with a blocking serve sibling) and [?wait-for] joins it via the
// done spin-loop. A finite body must still return the correct terminal value.
fn test_concurrent_worker_returns_result() {
	os.setenv('CX_WORKER_THREADS', '1', true)
	r := run('[?let [= \$wh [?worker name=w [+ 1 2]]] [?wait-for worker=\$wh]]')
	os.setenv('CX_WORKER_THREADS', '', true) // reset before asserting
	assert s_int(r, 3)
}

// Default (flag off): worker runs synchronously to completion; same result.
fn test_synchronous_worker_returns_result() {
	os.setenv('CX_WORKER_THREADS', '', true)
	r := run('[?let [= \$wh [?worker name=w2 [+ 10 5]]] [?wait-for worker=\$wh]]')
	assert s_int(r, 15)
}
