@[has_globals]
module code

import cx
import os
import math
import strconv

// stdlib_test.v — native primitives backing the `cx-stdlib/test` module
// (spec/std-lib/test.md): assertion / fixture / lifecycle helpers used by
// CX-authored unit-test programs. Distinct from the conformance harness
// (spec/core/code.md §11).
//
// ── failure model ─────────────────────────────────────────────────────
// Every assertion is `[returns null]` (§3.1). On the happy path it returns
// the null scalar; on failure it returns the spec FAILURE VALUE — an
// `[err code=cx-err:CXER2200 …]` node via mk_err (E_TEST_ASSERTION_FAILED,
// §5). These are VALUES, not V panics, mirroring stdlib_validate.v: the
// conformance runner renders the result and matches the bare CXER code in
// `out-err`. `skip` raises CXER2202; `assert-snapshot` divergence raises
// CXER2203; `fixture-load` is capability-gated (read, §8) and raises
// CXER0271 under deny-by-default.
//
// ── env-aware seam ────────────────────────────────────────────────────
// `assert-throws` / lifecycle hooks take a `$thunk::any` — the spec form is
// a nullary `[?fn () body]` (§2 doc-header of test.cxd). Applying a thunk
// and inspecting its outcome needs the evaluator env, which the env-free
// `test_stdlib_builtin` layer lacks. Those surfaces live in
// `test_stdlib_builtin_env`, invoked from eval.v::dispatch_call_l next to
// ft's hook (mirrors the ft_stdlib_builtin_env precedent).

// test error codes (§5).
const test_err_assert = 'cx-err:CXER2200'
const test_err_skipped = 'cx-err:CXER2202'
const test_err_snapshot = 'cx-err:CXER2203'

// ── value builders / helpers ──────────────────────────────────────────

fn test_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// test_assert_fail builds the standard E_TEST_ASSERTION_FAILED value.
fn test_assert_fail(message string) cx.Node {
	return mk_err(test_err_assert, 'E_TEST_ASSERTION_FAILED: ${message}')
}

// test_arg_str extracts a string from a scalar / text node.
fn test_arg_str(n cx.Node) ?string {
	match n {
		cx.ScalarNode {
			v := n.value
			if v is string {
				return v
			}
		}
		cx.TextNode {
			return n.value
		}
		else {}
	}
	return none
}

// test_truthy reports whether a node is the boolean `true` (the
// `$predicate::bool` happy value). A non-bool / false scalar is falsey.
fn test_truthy(n cx.Node) bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return false
}

fn test_node_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return f64(v) }
			f64 { return v }
			string {
				// I1 stream 11 (2b): the test harness accepts the exact
				// family — assert-near is a TOLERANCE check, not an
				// exactness surface, so a decimal/bigint image reads
				// through f64.
				if n.data_type == cx.ScalarType.decimal_type
					|| n.data_type == cx.ScalarType.bigint_type {
					if fv := test_atof(v) {
						return fv
					}
				}
			}
			else {}
		}
	}
	return none
}

fn test_atof(s string) ?f64 {
	return strconv.atof64(s) or { return none }
}

// test_seq_items returns the member nodes of a sequence / array value, or
// none for a non-collection.
fn test_seq_items(n cx.Node) ?[]cx.Node {
	match n {
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == 'sequence'
				|| n.name == 'array' {
				return n.items
			}
		}
		cx.SequenceNode {
			return n.items
		}
		cx.ArrayNode {
			return n.items
		}
		else {}
	}
	return none
}

// test_map_keys returns the keys of a map value and ok=true, or ok=false
// for a non-map.
fn test_map_keys(n cx.Node) ([]string, bool) {
	mut keys := []string{}
	if n is cx.Element {
		if n.name == '__cx_map__' || n.name == 'map' {
			for it in n.items {
				if it is cx.Element {
					keys << it.name
				}
			}
			for a in n.attrs {
				keys << a.name
			}
			return keys, true
		}
	}
	if n is cx.MapNode {
		for e in n.entries {
			keys << cx.scalar_value_str_public(e.key_value)
		}
		return keys, true
	}
	return keys, false
}

// test_element_matches implements the §3.1 assert-match structural test:
// the pattern element matches the value when names agree and every plain
// (non-@) pattern attribute equals the value's same-named attribute
// (structural-equality per code.md §5.2 rule 9). Extra value attributes
// are allowed (subset match).
fn test_element_matches(pattern cx.Node, value cx.Node) bool {
	if pattern is cx.Element && value is cx.Element {
		if pattern.name != value.name {
			return false
		}
		for pa in pattern.attrs {
			mut found := false
			for va in value.attrs {
				if va.name == pa.name {
					found = true
					if cx.scalar_value_str_public(pa.value) != cx.scalar_value_str_public(va.value) {
						return false
					}
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	// scalar / text patterns fall back to structural equality.
	return nodes_equal_pub(pattern, value)
}

// test_render renders a value to canonical CX text (snapshot / message
// form). Wraps the node in a single-element Document and runs the shipped
// compact emitter.
fn test_render(n cx.Node) string {
	doc := cx.Document{
		elements: [n]
	}
	return cx.emit_cx_compact(doc).trim_space()
}

// ── snapshot store (§3.1) ─────────────────────────────────────────────
//
// In-memory snapshot map: first sight of a key RECORDS and passes;
// re-sight COMPARES and raises CXER2203 on divergence. The on-disk
// __snapshots__/ store + CX_TEST_UPDATE_SNAPSHOTS mode are the deferred
// FS-dependent suite (test-020 carries gate=pending) — see SPEC-FINDINGS.
__global (
	test_snapshot_store = voidptr(0)
)

fn test_snapshot_lookup(key string) ?string {
	if test_snapshot_store == voidptr(0) {
		return none
	}
	m := unsafe { &map[string]string(test_snapshot_store) }
	if key in m {
		return (*m)[key]
	}
	return none
}

fn test_snapshot_record(key string, rendered string) {
	if test_snapshot_store == voidptr(0) {
		heap := &map[string]string{}
		unsafe {
			heap[key] = rendered
		}
		test_snapshot_store = voidptr(heap)
		return
	}
	mut m := unsafe { &map[string]string(test_snapshot_store) }
	unsafe {
		m[key] = rendered
	}
}

// ── env-free dispatch ─────────────────────────────────────────────────

fn test_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// ── §3.1 assertions ──────────────────────────────────────────
		'test-assert' {
			if args.len < 1 {
				return none
			}
			if test_truthy(args[0]) {
				return test_null()
			}
			label := if args.len > 1 {
				test_arg_str(args[1]) or { '' }
			} else {
				''
			}
			msg := if label != '' {
				'assertion failed: ${label}'
			} else {
				'assertion failed: predicate is false'
			}
			return test_assert_fail(msg)
		}
		'test-assert-equal' {
			if args.len < 2 {
				return none
			}
			if nodes_equal_pub(args[0], args[1]) {
				return test_null()
			}
			return test_assert_fail('expected ${test_render(args[1])}, got ${test_render(args[0])}')
		}
		'test-assert-not-equal' {
			if args.len < 2 {
				return none
			}
			if !nodes_equal_pub(args[0], args[1]) {
				return test_null()
			}
			return test_assert_fail('expected value to differ from ${test_render(args[1])}')
		}
		'test-assert-near' {
			if args.len < 3 {
				return none
			}
			a := test_node_f64(args[0]) or {
				return test_assert_fail('assert-near: actual is not numeric')
			}
			e := test_node_f64(args[1]) or {
				return test_assert_fail('assert-near: expected is not numeric')
			}
			eps := test_node_f64(args[2]) or {
				return test_assert_fail('assert-near: epsilon is not numeric')
			}
			if math.abs(a - e) <= eps {
				return test_null()
			}
			return test_assert_fail('|${a} - ${e}| > ${eps}')
		}
		'test-assert-contains' {
			if args.len < 2 {
				return none
			}
			haystack := args[0]
			needle := args[1]
			// string substring membership.
			if hs := test_arg_str(haystack) {
				if ns := test_arg_str(needle) {
					if hs.contains(ns) {
						return test_null()
					}
					return test_assert_fail('"${hs}" does not contain "${ns}"')
				}
			}
			// sequence / array element membership.
			if items := test_seq_items(haystack) {
				for it in items {
					if nodes_equal_pub(it, needle) {
						return test_null()
					}
				}
				return test_assert_fail('sequence does not contain ${test_render(needle)}')
			}
			// map key presence.
			keys, is_map := test_map_keys(haystack)
			if is_map {
				if ns := test_arg_str(needle) {
					if ns in keys {
						return test_null()
					}
				}
				return test_assert_fail('map has no key ${test_render(needle)}')
			}
			return test_assert_fail('assert-contains: unsupported haystack kind')
		}
		'test-assert-match' {
			if args.len < 2 {
				return none
			}
			// signature ($value $pattern); the structural match is symmetric
			// over the two element forms the fixtures supply.
			if test_element_matches(args[1], args[0]) {
				return test_null()
			}
			return test_assert_fail('value ${test_render(args[0])} does not match pattern ${test_render(args[1])}')
		}
		'test-assert-shape' {
			if args.len < 2 {
				return none
			}
			// Reuse the cx-stdlib/validate schema engine (§3.1: fail unless
			// validate-shape returns [ok …]; failure is [invalid …]).
			// validate_stdlib_builtin owns the record-field walk; map its
			// result to the test value.
			res := validate_stdlib_builtin('validate-shape', [args[0], args[1]]) or {
				return test_assert_fail('assert-shape: schema validation unavailable')
			}
			if res is cx.Element {
				if res.name == 'ok' {
					return test_null()
				}
				if res.name == 'invalid' {
					return test_assert_fail('value does not satisfy schema')
				}
			}
			// any other (malformed-schema CXER16xx) value: surface as failure.
			return test_assert_fail('assert-shape: ${test_render(res)}')
		}
		'test-fail' {
			msg := if args.len > 0 {
				test_arg_str(args[0]) or { '' }
			} else {
				''
			}
			return test_assert_fail(if msg != '' { msg } else { 'fail' })
		}
		'test-skip' {
			reason := if args.len > 0 {
				test_arg_str(args[0]) or { '' }
			} else {
				''
			}
			return mk_err(test_err_skipped, 'E_TEST_SKIPPED: ${reason}')
		}
		'test-assert-snapshot' {
			if args.len < 1 {
				return none
			}
			value := args[0]
			key := if args.len > 1 {
				test_arg_str(args[1]) or { '' }
			} else {
				''
			}
			rendered := test_render(value)
			if prev := test_snapshot_lookup(key) {
				if prev == rendered {
					return test_null()
				}
				return mk_err(test_err_snapshot,
					'E_TEST_SNAPSHOT_MISMATCH: recorded ${prev}, got ${rendered}')
			}
			// first run: record and pass.
			test_snapshot_record(key, rendered)
			return test_null()
		}
		// ── §3.2 fixtures ────────────────────────────────────────────
		'test-fixture' {
			if args.len < 1 {
				return none
			}
			// `fixture` collects trailing body items as a sequence value
			// tagged with $name (§3.2). args[0] is the name; args[1..] are
			// the collected body elements, so [$count …] is their number.
			mut items := []cx.Node{}
			for i in 1 .. args.len {
				items << args[i]
			}
			return cx.Element{
				name:  '__cx_seq__'
				attrs: [cx.Attribute{
					name:  'fixture'
					value: cx.ScalarValue(test_arg_str(args[0]) or { '' })
				}]
				items: items
			}
		}
		'test-fixture-load' {
			if args.len < 1 {
				return none
			}
			path := test_arg_str(args[0]) or { return none }
			// §8: filesystem read is capability-gated; deny-by-default raises
			// CXER0271 at the effect point before any read.
			if d := cap_guard('read', path) {
				return d
			}
			// granted path: load + parse the sibling fixture file.
			return test_fixture_load(path)
		}
		// ── §3.3 lifecycle hooks ─────────────────────────────────────
		// Env-free fallback: registration returns null without running the
		// thunk (§3.3). The env-aware variant owns the closure-arg form.
		'test-before-each', 'test-after-each', 'test-before-all', 'test-after-all' {
			return test_null()
		}
		// ── §3.4 configuration ───────────────────────────────────────
		'test-configure' {
			// configure mutates runner state and returns null (§3.4). A
			// single isolated eval has no runner loop, so this validates the
			// config-map shape and returns null.
			if args.len < 1 {
				return none
			}
			_, is_map := test_map_keys(args[0])
			if !is_map {
				return test_assert_fail('configure: argument is not a map')
			}
			return test_null()
		}
		else {
			return none
		}
	}
}

// test_fixture_load loads + parses a fixture file from `path` (called only
// after the read capability is granted). A missing / unparseable file
// raises CXER2201 E_TEST_FIXTURE_LOAD (§5).
fn test_fixture_load(path string) cx.Node {
	src := os.read_file(path) or {
		return mk_err('cx-err:CXER2201', 'E_TEST_FIXTURE_LOAD: cannot read ${path}')
	}
	doc := cx.parse(src) or {
		return mk_err('cx-err:CXER2201', 'E_TEST_FIXTURE_LOAD: cannot parse ${path}')
	}
	if doc.elements.len == 1 {
		return doc.elements[0]
	}
	return cx.Element{
		name:  '__cx_seq__'
		items: doc.elements
	}
}

// ── env-aware dispatch (thunks / lifecycle closures) ──────────────────
//
// Handles the test surfaces whose `$thunk::any` argument is a `[?fn]`
// closure that must be APPLIED with the evaluator env in scope. Invoked
// from eval.v::dispatch_call_l next to ft_stdlib_builtin_env. Returns none
// for any name it does not own so the env-free chain handles it.
fn test_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'test-assert-throws' {
			if args.len < 1 {
				return none
			}
			thunk := args[0]
			want := if args.len > 1 {
				test_arg_str(args[1]) or { '' }
			} else {
				''
			}
			// Apply the nullary thunk and capture its outcome. A raised
			// EvalError (V-error channel) or a returned [err …] VALUE both
			// count as "threw"; extract the error code from either.
			mut got_code := ''
			if is_fn_value(thunk) {
				res := apply_fn_value(thunk, []cx.Node{}, mut env) or {
					// raised: err.msg() is "<code>: <message>".
					got_code = err.msg().all_before(': ')
					return test_throws_check(got_code, want)
				}
				// returned a value: an [err …] value is also a throw.
				if is_err_value(res) {
					got_code = err_code_of(res)
				} else {
					// no raise → assert-throws itself fails (§3.1).
					return test_assert_fail('expected thunk to raise ${want}, but it returned ${test_render(res)}')
				}
			} else {
				// non-closure thunk: an already-evaluated value, so it did
				// not raise — unless it is itself an [err …] value.
				if is_err_value(thunk) {
					got_code = err_code_of(thunk)
				} else {
					return test_assert_fail('expected thunk to raise ${want}, but it produced ${test_render(thunk)}')
				}
			}
			return test_throws_check(got_code, want)
		}
		// Lifecycle hooks: register the thunk (no run at registration) and
		// return null. The env hook owns these so a `[?fn]` closure value is
		// accepted rather than mis-dispatched.
		'test-before-each', 'test-after-each', 'test-before-all', 'test-after-all' {
			return test_null()
		}
		else {
			return none
		}
	}
}

// test_throws_check compares the captured error code against the expected
// `$err-code` (substring match — the fixture passes a bare `CXER2200`,
// the captured code is the full `cx-err:CXER2200`). Pass → null;
// mismatch → CXER2200 failure (§3.1).
fn test_throws_check(got_code string, want string) cx.Node {
	if want == '' || got_code.contains(want) {
		return test_null()
	}
	return test_assert_fail('expected error ${want}, got ${got_code}')
}
