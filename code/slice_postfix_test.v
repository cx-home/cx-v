module code
import cx

// slice_postfix_test.v — parser tests for 
//
// Covers the BindingPostfix → SliceAxes grammar
// "Surface-syntax summary") and the positional disambiguation table.
// These tests confirm the AST shape only; evaluation is deferred to
// W5c (the evaluator stub returns CXER0100 "slice eval: deferred to
// W5c", which has its own coverage at the conformance layer in
// conformance/code.txt under `program-slice-w*`).
//
// Surface forms covered:
//   1. $xs[2:5]           — closed range with explicit start/stop
//   2. $xs[:5]            — open start
//   3. $xs[-3:]           — open stop with negative start
//   4. $xs[::2]           — strided (start/stop open, step=2)
//   5. $xs[::-1]          — reversed walk (step=-1)
//   6. $xs[*]             — full axis
//   7. $xs[2]             — single-Expr postfix; per the brief, the
//                          axis is recorded as kind=.single (the
//                          parser-level decision: a single integer
//                          without `:` / `*` / `,` still routes
//                          through the BindingPostfix path)
//   8. $xs[2:$_last]      — range with $_last on the RHS
//   9. $xs[2:5, 3:8]      — multi-axis (two range axes)
//
// regression: a bare `[1, 2, 3]` at expression head is
// still an array literal — the slice surface is gated by a preceding
// `$binding`, not the bracket shape alone.

// extract_slice unwraps a `cx.Program{body}` and asserts the body is a
// cx.ProgramSliceAccess. Used by every test below.
fn extract_slice(src string) ?cx.ProgramSliceAccess {
	prog := cx.parse_program(src) or {
		eprintln('parse failed for ${src}: ${err.msg()}')
		return none
	}
	body := prog.body
	if body is cx.ProgramSliceAccess {
		return body
	}
	eprintln('expected cx.ProgramSliceAccess, got ${body.type_name()} for ${src}')
	return none
}

// expect_int extracts an int literal from a cx.ProgramNode payload.
fn expect_int(n cx.ProgramNode, want i64) bool {
	if n is cx.ProgramLiteral && n.kind == .int_lit {
		return n.int_val == want
	}
	return false
}

// expect_binding_name extracts a bare-binding name from a cx.ProgramNode.
fn expect_binding_name(n cx.ProgramNode, want string) bool {
	if n is cx.ProgramBinding {
		return n.name == want && n.path.len == 0
	}
	return false
}

// ── 1. $xs[2:5] — closed range with explicit start/stop ──────────────────────

fn test_slice_closed_range() {
	s := extract_slice('\$xs[2:5]') or { assert false, 'extract failed' return }
	assert s.binding.name == 'xs'
	assert s.binding.path.len == 0
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .range
	start := ax.start or { assert false, 'expected start expression' return }
	stop  := ax.stop  or { assert false, 'expected stop expression'  return }
	assert ax.step == none
	assert expect_int(start, 2), 'start should be 2'
	assert expect_int(stop,  5), 'stop should be 5'
}

// ── 2. $xs[:5] — open start ──────────────────────────────────────────────────

fn test_slice_open_start() {
	s := extract_slice('\$xs[:5]') or { assert false, 'extract failed' return }
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .range
	assert ax.start == none, 'start should be absent'
	stop := ax.stop or { assert false, 'expected stop expression' return }
	assert ax.step == none
	assert expect_int(stop, 5)
}

// ── 3. $xs[-3:] — open stop with negative start ──────────────────────────────

fn test_slice_negative_start_open_stop() {
	s := extract_slice('\$xs[-3:]') or { assert false, 'extract failed' return }
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .range
	start := ax.start or { assert false, 'expected start expression' return }
	assert ax.stop == none, 'stop should be absent'
	assert ax.step == none
	assert expect_int(start, -3), 'start should be -3'
}

// ── 4. $xs[::2] — strided, both bounds open ──────────────────────────────────

fn test_slice_strided() {
	s := extract_slice('\$xs[::2]') or { assert false, 'extract failed' return }
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .range
	assert ax.start == none
	assert ax.stop  == none
	step := ax.step or { assert false, 'expected step expression' return }
	assert expect_int(step, 2)
}

// ── 5. $xs[::-1] — reversed walk ─────────────────────────────────────────────

fn test_slice_reversed() {
	s := extract_slice('\$xs[::-1]') or { assert false, 'extract failed' return }
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .range
	assert ax.start == none
	assert ax.stop  == none
	step := ax.step or { assert false, 'expected step expression' return }
	assert expect_int(step, -1)
}

// ── 6. $xs[*] — full axis ────────────────────────────────────────────────────

fn test_slice_full_axis() {
	s := extract_slice('\$xs[*]') or { assert false, 'extract failed' return }
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .full
	assert ax.start == none
	assert ax.stop  == none
	assert ax.step  == none
}

// ── 7. $xs[2] — single-index axis (W5c tightening) ───────────────────────────
//
// W5b parsed `$xs[2]` as the predicate-fallback case (two adjacent
// expressions: a `$xs` binding and a `[2]` array literal). W5c promotes
// the form to a structured `cx.ProgramSliceAccess` with a single `.single`
// axis carrying the integer expression — closing the disambiguation
// gap noted in the W5b brief and unblocking conformance fixture
// `program-slice-007-single-index` (`$xs[3]` → c).

fn test_slice_single_index_axis() {
	s := extract_slice('\$xs[3]') or { assert false, 'extract failed' return }
	assert s.binding.name == 'xs'
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .single
	start := ax.start or { assert false, 'expected start expression' return }
	assert ax.stop == none
	assert ax.step == none
	assert expect_int(start, 3), 'single-index axis should carry 3'
}

// ── 8. $xs[2:$_last] — range with $_last on RHS ──────────────────────────────

fn test_slice_with_last_binding() {
	s := extract_slice('\$xs[2:\$_last]') or { assert false, 'extract failed' return }
	assert s.axes.len == 1
	ax := s.axes[0]
	assert ax.kind == .range
	start := ax.start or { assert false, 'expected start' return }
	stop  := ax.stop  or { assert false, 'expected stop'  return }
	assert ax.step == none
	assert expect_int(start, 2)
	assert expect_binding_name(stop, '_last')
}

// ── 9. $xs[2:5, 3:8] — multi-axis (parsed, not evaluated) ────────────────────

fn test_slice_multi_axis_two_ranges() {
	s := extract_slice('\$xs[2:5, 3:8]') or { assert false, 'extract failed' return }
	assert s.axes.len == 2

	ax0 := s.axes[0]
	assert ax0.kind == .range
	assert expect_int(ax0.start or { assert false return }, 2)
	assert expect_int(ax0.stop  or { assert false return }, 5)

	ax1 := s.axes[1]
	assert ax1.kind == .range
	assert expect_int(ax1.start or { assert false return }, 3)
	assert expect_int(ax1.stop  or { assert false return }, 8)
}

// ── regression: bare [1, 2, 3] is an array literal ───────────────
//
// The slice surface is GATED by a preceding `$binding`. A bracket
// expression at expression head (no leading binding) remains an array
// literal — this test pins that the W5b parser change
// doesn't accidentally re-route bracket-head expressions.

fn test_array_literal_unchanged_at_expression_head() {
	prog := cx.parse_program('[1, 2, 3]') or {
		assert false, 'parse [1, 2, 3] failed: $err'
		return
	}
	body := prog.body
	if body is cx.ProgramLiteral {
		assert body.kind == .array_lit, 'expected array_lit, got ${body.kind}'
		assert body.items.len == 3
	} else {
		assert false, 'expected cx.ProgramLiteral for [1, 2, 3], got ${body.type_name()}'
	}
}

// ── disambiguation: $xs[2] differs from /step[2] ────────────────────
//
// `$xs[2]` parses as a slice-single axis (this milestone).
// `[?for $x :in //user[2] :yield $x]` — the `//user[2]` is a CXPath
// step with a positional predicate (predicate kind=.position).
// We confirm the existing predicate parsing path is untouched.

fn test_cxpath_predicate_still_position() {
	// Parse a CXPath head; the predicate on a NodeTest must remain
	// a positional predicate, NOT a slice.
	prog := cx.parse_program('//user[2]') or {
		assert false, 'parse //user[2] failed: $err'
		return
	}
	body := prog.body
	if body is cx.ProgramPathExpr {
		assert body.steps.len == 1
		assert body.steps[0].predicates.len == 1
		pred := body.steps[0].predicates[0]
		assert pred.kind == .position, 'expected .position, got ${pred.kind}'
		assert pred.int_index == 2
	} else {
		assert false, 'expected cx.ProgramPathExpr for //user[2], got ${body.type_name()}'
	}
}
