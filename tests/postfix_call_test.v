module main

import cx

// A2/A3/B8 — postfix call `$x(arg)` over map / array / function values.
// A4/A5/B12 — lookup operator `?key` (postfix + unary + on path).

// ── A2 — Maps as functions (XPath 4.0 §4.14.1.2) ────────────────────────

fn test_a2_map_as_fn_returns_value() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {name: alice, age: 30} :return [?=m('name')]]", '') or {
		panic('${err}')
	}
	assert out == 'alice', 'expected alice, got: "${out}"'
}

fn test_a2_map_as_fn_int_value() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {name: alice, age: 30} :return [?=m('age')]]", '') or {
		panic('${err}')
	}
	assert out == '30', 'expected 30, got: "${out}"'
}

fn test_a2_map_as_fn_missing_key_empty() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {a: 1} :return [?=m('missing')]]", '') or { panic('${err}') }
	assert out == '', 'expected empty, got: "${out}"'
}

// ── A3 — Arrays as functions (XPath 4.0 §4.14.2.2) ──────────────────────

fn test_a3_array_as_fn_one_based_index() {
	out := cx.eval_cxl('[p]',
		'[?let a :be [10, 20, 30] :return [?=a(2)]]', '') or { panic('${err}') }
	assert out == '20', 'expected 20 (1-based idx 2), got: "${out}"'
}

fn test_a3_array_as_fn_first_index() {
	out := cx.eval_cxl('[p]',
		'[?let a :be [10, 20, 30] :return [?=a(1)]]', '') or { panic('${err}') }
	assert out == '10', 'expected 10, got: "${out}"'
}

fn test_a3_array_as_fn_out_of_range_empty() {
	out := cx.eval_cxl('[p]',
		'[?let a :be [10, 20] :return [?=a(99)]]', '') or { panic('${err}') }
	assert out == '', 'expected empty for out-of-range, got: "${out}"'
}

fn test_a3_array_as_fn_zero_index_empty() {
	out := cx.eval_cxl('[p]',
		'[?let a :be [10, 20] :return [?=a(0)]]', '') or { panic('${err}') }
	assert out == '', 'expected empty for 0 (1-based), got: "${out}"'
}

// ── A4 — Lookup operator postfix `$map?key` (XPath 4.0 §4.14.3.1) ───────

fn test_a4_postfix_lookup_map() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {name: alice} :return [?=m?name]]", '') or { panic('${err}') }
	assert out == 'alice', 'expected alice via ?key, got: "${out}"'
}

fn test_a4_postfix_lookup_missing_empty() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {a: 1} :return [?=m?missing]]", '') or { panic('${err}') }
	assert out == '', 'expected empty for missing key, got: "${out}"'
}

// ── A5 — Lookup operator unary `?key` (XPath 4.0 §4.14.3.2) ─────────────

fn test_a5_unary_lookup_against_context() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {name: alice} :return [?with m :return [?=?name]]]", '') or {
		panic('${err}')
	}
	assert out == 'alice', 'expected alice via unary ?key, got: "${out}"'
}

// ── B8 — Function-call postfix `$f(args)` (CXPath 3.0) ───────────────────

fn test_b8_fn_postfix_single_arg() {
	out := cx.eval_cxl('[p]',
		'[?let f :be [?fn :params [x] :body [?=x]] :return [?=f(42)]]', '') or {
		panic('${err}')
	}
	assert out == '42', 'expected 42, got: "${out}"'
}

fn test_b8_fn_postfix_returns_input_arg() {
	out := cx.eval_cxl('[p]',
		'[?let id :be [?fn :params [x] :body [?=x]] :return [?=id(7)]]', '') or {
		panic('${err}')
	}
	assert out == '7', 'expected 7, got: "${out}"'
}

// ── A6 — Map/array methods 4.0 surface (regression for existing
// map:/array: filter set; ensures the v0.7.0 postfix forms compose
// with the existing function library)

fn test_a6_map_size_via_filter() {
	out := cx.eval_cxl('[p]',
		"[?let m :be {a: 1, b: 2, c: 3} :return [?=[?map:size [m]]]]", '') or {
		panic('${err}')
	}
	assert out == '3', 'expected 3, got: "${out}"'
}

fn test_a6_array_size_via_filter() {
	out := cx.eval_cxl('[p]',
		'[?let a :be [10, 20, 30] :return [?=[?array:size [a]]]]', '') or {
		panic('${err}')
	}
	assert out == '3', 'expected 3, got: "${out}"'
}

// ── B9 — Inline fn expression `fn (x) { body }` (XPath 3.0) ─────────────
//
// B9 / B10 expression forms work via `?let :be EXPR` when EXPR is a
// single text expression. CX's `{ ... }` body delimiter conflicts
// with the CX map literal `{...}` at slot-body parsing time, so
// `fn (x) { x }` works (lone `{` non-trivial body — see below) while
// `fn () { 42 }` (with `{NUM}` body) trips the map-literal recognizer.
// The integration tests below cover the working slot-body shapes;
// the bare-expression parsing is independently verified via the
// smoke-test corpus.

fn test_b9_inline_fn_identity() {
	out := cx.eval_cxl('[p]',
		"[?let f :be fn (x) { x } :return [?=f(42)]]", '') or { panic('${err}') }
	assert out == '42', 'expected 42, got: "${out}"'
}

fn test_b9_inline_fn_dollar_prefix_accepted() {
	// Param spelled `$x` (XPath convention) — the `$` is stripped.
	out := cx.eval_cxl('[p]',
		"[?let f :be fn ($x) { x } :return [?=f(7)]]", '') or { panic('${err}') }
	assert out == '7', 'expected 7, got: "${out}"'
}

// ── B10 — Arrow lambda `-> (x) { body }` (XPath 4.0) ────────────────────

fn test_b10_arrow_lambda_with_param() {
	out := cx.eval_cxl('[p]',
		"[?let g :be -> (y) { y } :return [?=g(99)]]", '') or { panic('${err}') }
	assert out == '99', 'expected 99, got: "${out}"'
}

// ── B12 — Path postfix lookup `$path?key` (composes with A4) ────────────

fn test_b12_path_postfix_lookup_after_array_index() {
	// `$xs(1)?name` — array-as-fn followed by ?key on the resulting map.
	out := cx.eval_cxl('[p]',
		"[?let xs :be [{name: alice}, {name: bob}] :return [?=xs(1)?name]]", '') or {
		panic('${err}')
	}
	assert out == 'alice', 'expected alice, got: "${out}"'
}
