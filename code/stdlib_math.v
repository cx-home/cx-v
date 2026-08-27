module code

import cx
import math

// stdlib_math.v — native primitives backing the `cx-stdlib/math` module
// (spec/std-lib/math.md). Most of the surface (trig, hyperbolic, exact
// banker's rounding, the statistical estimators, deterministic
// Miller-Rabin, two's-complement wrapping arithmetic, IEEE-754 predicates
// and constants) is not expressible as a pure CX `[?def]` body, so the
// bundle bodies (stdlib_src_math) forward to the `math-*` primitives
// dispatched here. A handful of bodies reuse the language-core builtins
// (sqrt / cbrt / exp / log / log2 / log10 / pow / abs / min / max /
// floor / ceiling) directly. See stdlib_dispatch.v for the chain line.
//
// All math functions are PURE — no capability gating.
//
// Errors are VALUE nodes (mk_err, eval.v): the spec §5 codes
// CXER3000..CXER3003. The conformance runner matches the bare code in
// `out-err`. Domain errors on real-valued functions return NaN per
// IEEE-754 (never raise) where the spec says so.

// ── error codes (spec §5) ────────────────────────────────────────────
const math_err_overflow = 'cx-err:CXER3000' // E_MATH_OVERFLOW
const math_err_empty     = 'cx-err:CXER3001' // E_MATH_EMPTY_SEQUENCE
const math_err_domain    = 'cx-err:CXER3003' // E_MATH_DOMAIN_ERROR

const math_i64_max = i64(9223372036854775807)
const math_i64_min = i64(-9223372036854775807 - 1)

// ── scalar builders ──────────────────────────────────────────────────

fn math_float(f f64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(f)
		data_type: cx.ScalarType.float_type
	}
}

fn math_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn math_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

// ── argument readers ─────────────────────────────────────────────────

fn math_arg_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			else {}
		}
	}
	note_operand_fault('math', 'math-', 'number', n)
	return none
}

fn math_arg_i64(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	note_operand_fault('math', 'math-', 'int', n)
	return none
}

// math_arg_is_int reports whether the node is an int-typed scalar (used
// for kind-preserving ops like abs / min / max / clamp).
fn math_arg_is_int(n cx.Node) bool {
	if n is cx.ScalarNode {
		return n.value is i64
	}
	return false
}

// math_items extracts the materialized item list of any sequence-shaped
// node: a __cx_seq__ / __cx_arr__ element, a bare anonymous element, or
// an eager IteratorNode whose memo carries the items.
fn math_items(n cx.Node) []cx.Node {
	match n {
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
				return n.items
			}
		}
		cx.SequenceNode {
			return n.items
		}
		cx.ArrayNode {
			return n.items
		}
		cx.IteratorNode {
			return n.memo
		}
		else {}
	}
	return []cx.Node{}
}

// math_seq_floats reads a sequence arg into an []f64 (ints promote).
fn math_seq_floats(n cx.Node) []f64 {
	mut out := []f64{}
	for it in math_items(n) {
		if f := math_arg_f64(it) {
			out << f
		}
	}
	return out
}

// math_has_exact_kind reports whether a $math: argument carries an
// exact-family scalar (decimal / bigint) — either as the argument itself or
// as an item of a sequence-shaped one (CO-14). One level of items is the
// whole story: `math_items` is exactly the view the statistical verbs fold
// over, so anything it can reach is an operand and anything it cannot is
// not.
fn math_has_exact_kind(n cx.Node) bool {
	if n is cx.ScalarNode {
		return n.data_type == cx.ScalarType.decimal_type
			|| n.data_type == cx.ScalarType.bigint_type
	}
	for it in math_items(n) {
		if it is cx.ScalarNode {
			if it.data_type == cx.ScalarType.decimal_type
				|| it.data_type == cx.ScalarType.bigint_type {
				return true
			}
		}
	}
	return false
}

// math_seq_all_int reports whether every item of the sequence is an
// int-typed scalar (sum / product preserve int when closed over ints).
fn math_seq_all_int(n cx.Node) bool {
	items := math_items(n)
	if items.len == 0 {
		return false
	}
	for it in items {
		if !math_arg_is_int(it) {
			return false
		}
	}
	return true
}

// ── rounding helpers ─────────────────────────────────────────────────

// math_round_half_even — banker's rounding (IEEE-754 round-half-to-even).
fn math_round_half_even(x f64) i64 {
	f := math.floor(x)
	diff := x - f
	if diff < 0.5 {
		return i64(f)
	}
	if diff > 0.5 {
		return i64(f) + 1
	}
	// exactly halfway → round to even
	lo := i64(f)
	if lo % 2 == 0 {
		return lo
	}
	return lo + 1
}

// math_round_half_up — commercial rounding (half-away-from-zero).
fn math_round_half_up(x f64) i64 {
	if x >= 0 {
		return i64(math.floor(x + 0.5))
	}
	return -i64(math.floor(-x + 0.5))
}

// ── statistics helpers ───────────────────────────────────────────────

fn math_sum_f(xs []f64) f64 {
	mut s := 0.0
	for x in xs {
		s += x
	}
	return s
}

fn math_mean_f(xs []f64) f64 {
	return math_sum_f(xs) / f64(xs.len)
}

// math_variance returns the variance; sample (N-1) when `sample`, else
// population (N).
fn math_variance(xs []f64, sample bool) f64 {
	n := xs.len
	m := math_mean_f(xs)
	mut acc := 0.0
	for x in xs {
		d := x - m
		acc += d * d
	}
	denom := if sample { f64(n - 1) } else { f64(n) }
	return acc / denom
}

// math_percentile — linear interpolation between closest ranks (the
// canonical "type 7" / NIST method), p in [0,100].
fn math_percentile(xs []f64, p f64) f64 {
	mut s := xs.clone()
	s.sort()
	n := s.len
	if n == 1 {
		return s[0]
	}
	rank := (p / 100.0) * f64(n - 1)
	lo := int(math.floor(rank))
	hi := int(math.ceil(rank))
	if lo == hi {
		return s[lo]
	}
	frac := rank - f64(lo)
	return s[lo] + frac * (s[hi] - s[lo])
}

// ── number theory ────────────────────────────────────────────────────

fn math_gcd(a i64, b i64) i64 {
	mut x := if a < 0 { -a } else { a }
	mut y := if b < 0 { -b } else { b }
	for y != 0 {
		x, y = y, x % y
	}
	return x
}

// math_mulmod computes (a*b) mod m without 128-bit overflow (binary mul).
fn math_mulmod(a u64, b u64, m u64) u64 {
	mut result := u64(0)
	mut x := a % m
	mut y := b
	for y > 0 {
		if y & 1 == 1 {
			result = (result + x) % m
		}
		x = (x * 2) % m
		y >>= 1
	}
	return result
}

fn math_powmod(base u64, exp u64, m u64) u64 {
	mut result := u64(1)
	mut b := base % m
	mut e := exp
	for e > 0 {
		if e & 1 == 1 {
			result = math_mulmod(result, b, m)
		}
		b = math_mulmod(b, b, m)
		e >>= 1
	}
	return result
}

// math_is_prime — deterministic Miller-Rabin over the fixed witness set
// {2,3,5,7,11,13,17,19,23,29,31,37}, exact across the int64 range
// (spec §3.7).
fn math_is_prime(n i64) bool {
	if n < 2 {
		return false
	}
	small := [i64(2), 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
	for p in small {
		if n == p {
			return true
		}
		if n % p == 0 {
			return false
		}
	}
	// write n-1 = d * 2^r
	un := u64(n)
	mut d := un - 1
	mut r := 0
	for d & 1 == 0 {
		d >>= 1
		r++
	}
	for a in small {
		mut x := math_powmod(u64(a), d, un)
		if x == 1 || x == un - 1 {
			continue
		}
		mut composite := true
		for _ in 0 .. r - 1 {
			x = math_mulmod(x, x, un)
			if x == un - 1 {
				composite = false
				break
			}
		}
		if composite {
			return false
		}
	}
	return true
}

// math_factorial — exact for 0..20; n>20 overflows int64 (spec §3.7).
fn math_factorial(n i64) ?i64 {
	if n < 0 {
		return none
	}
	if n > 20 {
		return none // overflow sentinel
	}
	mut acc := i64(1)
	mut i := i64(2)
	for i <= n {
		acc *= i
		i++
	}
	return acc
}

// ── dispatch ─────────────────────────────────────────────────────────


// math_div_decimal — the rounding-context division (stream 11 §5 / L44;
// #683): `[$math:div-decimal $a $b {precision: N mode: :half-up}]` — the
// exact quotient rounded to `precision` fractional digits per `mode`
// (:half-up | :half-even | :down | :up). This is the ONLY way to divide
// a non-terminating decimal quotient; the bare `[/ …]` operator stays
// exact-or-CXER3002.
fn math_div_decimal(args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err('cx-err:CXER0108', 'E_ARG: div-decimal expects (a, b, {precision: N mode: :half-up|:half-even|:down|:up})')
	}
	a := atomize_exact_num(args[0]) or {
		return mk_err('cx-err:CXER3002', 'div-decimal: operands must be exact-family (decimal/bigint/int) — [cast] is the only decimal-float bridge (L44)')
	}
	b := atomize_exact_num(args[1]) or {
		return mk_err('cx-err:CXER3002', 'div-decimal: operands must be exact-family (decimal/bigint/int) — [cast] is the only decimal-float bridge (L44)')
	}
	ai := cx.cx_exact_num_image(a) or { '0' }
	bi := cx.cx_exact_num_image(b) or { '0' }
	mut precision := -1
	if pn := math_ctx_get(args[2], 'precision') {
		if v := scalar_int(pn) {
			precision = int(v)
		}
	}
	mut mode := ''
	if mn := math_ctx_get(args[2], 'mode') {
		if mn is cx.ScalarNode {
			mode = cx.scalar_value_str_public(mn.value)
		}
	}
	if precision < 0 || mode == '' {
		return mk_err('cx-err:CXER0108', 'E_ARG: div-decimal — the rounding context needs precision= (>= 0) and mode= (:half-up | :half-even | :down | :up)')
	}
	q := cx.cx_exact_div_ctx(ai, bi, precision, mode) or {
		if err.msg().contains('zero') {
			return mk_err('cx-err:CXER0101', 'division by zero')
		}
		return mk_err('cx-err:CXER3002', 'div-decimal: ${err.msg()}')
	}
	return cx.ScalarNode{
		value:     cx.ScalarValue(q)
		data_type: cx.ScalarType.decimal_type
	}
}

// math_ctx_get reads one `{…}` rounding-context entry.
fn math_ctx_get(m cx.Node, key string) ?cx.Node {
	if m is cx.Element {
		if m.name == map_marker_name {
			for it in m.items {
				if it is cx.Element {
					if it.name == key && it.items.len > 0 {
						return it.items[0]
					}
				}
			}
		}
	}
	return none
}

fn math_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// the rounding-context division (stream 11 §5, L44 — #683): the ONE
	// exact-kind math verb, carved out BEFORE the exact-family refusal
	// below (it exists precisely to take decimals).
	if name == 'math-div-decimal' {
		return math_div_decimal(args)
	}
	// I1 (math.md §4.4 + the 2b flip): an exact-family argument
	// (decimal/bigint) NEVER falls through to "no callable" — every
	// $math: fn REFUSES it with CXER3002 + the cast hint. The
	// decimal↔float bridge is [cast], nothing implicit; exact
	// floor/ceiling/round live on the EVALUATOR builtins (entry 15);
	// the exact module-lane rounding context is `div-decimal` above.
	//
	// CO-14: the refusal reaches INSIDE a sequence argument too. It used to
	// inspect only top-level scalars, so the statistical aggregates — whose
	// argument IS a sequence — never saw an exact operand: `math_arg_f64`
	// matches on the V payload (i64 / f64), a decimal's payload is a
	// `string`, so the item just failed to read and was SKIPPED. The money
	// value did not bridge, it VANISHED — `[$math:sum (19.99, 19.99)]` was
	// `0.0e0`, and `[$math:stddev (19.99, 2.0e0)]` reached `nan`, which
	// code.md's finite-only rule says no CX float may ever be. One
	// discipline over the whole family means the refusal is the same
	// whether the operand arrives as an argument or as an item.
	if name.starts_with('math-') {
		for a in args {
			if math_has_exact_kind(a) {
				return mk_err('cx-err:CXER3002',
					'${name}: not defined over the exact kinds (decimal/bigint) — [cast … :float] first (math.md §4.4)')
			}
		}
	}
	match name {
		// ── §3.1 basic ───────────────────────────────────────────────
		'math-sign' {
			if math_arg_is_int(args[0]) {
				v := math_arg_i64(args[0]) or { return none }
				return math_int(if v > 0 { i64(1) } else if v < 0 { i64(-1) } else { i64(0) })
			}
			v := math_arg_f64(args[0]) or { return none }
			return math_int(if v > 0 { i64(1) } else if v < 0 { i64(-1) } else { i64(0) })
		}
		'math-round' {
			// banker's rounding (half-to-even) — the spec default.
			x := math_arg_f64(args[0]) or { return none }
			return math_int(math_round_half_even(x))
		}
		'math-round-half-up' {
			x := math_arg_f64(args[0]) or { return none }
			return math_int(math_round_half_up(x))
		}
		'math-round-to' {
			x := math_arg_f64(args[0]) or { return none }
			places := math_arg_i64(args[1]) or { return none }
			factor := math.pow(10.0, f64(places))
			scaled := x * factor
			// half-away-from-zero at the chosen precision (commercial)
			rounded := if scaled >= 0 {
				math.floor(scaled + 0.5)
			} else {
				-math.floor(-scaled + 0.5)
			}
			mut out := rounded / factor
			// normalize signed negative zero to positive zero so a value
			// rounded down to nought renders `0.0`, not `-0.0` (a tiny
			// negative result of e.g. tan(pi) rounds to -0.0 otherwise).
			// `-0.0 + 0.0` is positive zero per IEEE-754.
			if out == 0.0 {
				out = out + 0.0
			}
			return math_float(out)
		}
		'math-truncate' {
			x := math_arg_f64(args[0]) or { return none }
			return math_int(i64(x)) // V i64() truncates toward zero
		}
		'math-clamp' {
			lo_is_int := math_arg_is_int(args[1])
			hi_is_int := math_arg_is_int(args[2])
			x_is_int := math_arg_is_int(args[0])
			x := math_arg_f64(args[0]) or { return none }
			lo := math_arg_f64(args[1]) or { return none }
			hi := math_arg_f64(args[2]) or { return none }
			mut r := x
			if r < lo {
				r = lo
			}
			if r > hi {
				r = hi
			}
			// kind-preserving: int out when all operands are int
			if x_is_int && lo_is_int && hi_is_int {
				return math_int(i64(r))
			}
			return math_float(r)
		}

		// ── §3.2 powers, logs ────────────────────────────────────────
		'math-log-base' {
			x := math_arg_f64(args[0]) or { return none }
			base := math_arg_f64(args[1]) or { return none }
			return math_float(math.log(x) / math.log(base))
		}

		// ── §3.3 trigonometry ────────────────────────────────────────
		'math-sin' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.sin(x))
		}
		'math-cos' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.cos(x))
		}
		'math-tan' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.tan(x))
		}
		'math-asin' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.asin(x))
		}
		'math-acos' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.acos(x))
		}
		'math-atan' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.atan(x))
		}
		'math-atan2' {
			y := math_arg_f64(args[0]) or { return none }
			x := math_arg_f64(args[1]) or { return none }
			return math_float(math.atan2(y, x))
		}
		'math-sinh' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.sinh(x))
		}
		'math-cosh' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.cosh(x))
		}
		'math-tanh' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.tanh(x))
		}
		'math-asinh' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.asinh(x))
		}
		'math-acosh' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.acosh(x))
		}
		'math-atanh' {
			x := math_arg_f64(args[0]) or { return none }
			return math_float(math.atanh(x))
		}
		'math-deg-to-rad' {
			deg := math_arg_f64(args[0]) or { return none }
			return math_float(deg * math.pi / 180.0)
		}
		'math-rad-to-deg' {
			rad := math_arg_f64(args[0]) or { return none }
			return math_float(rad * 180.0 / math.pi)
		}

		// ── §3.4 statistical ─────────────────────────────────────────
		'math-sum' {
			items := math_items(args[0])
			if math_seq_all_int(args[0]) {
				mut s := i64(0)
				for it in items {
					v := math_arg_i64(it) or { return none }
					s += v
				}
				return math_int(s)
			}
			return math_float(math_sum_f(math_seq_floats(args[0])))
		}
		'math-product' {
			items := math_items(args[0])
			if math_seq_all_int(args[0]) {
				mut p := i64(1)
				for it in items {
					v := math_arg_i64(it) or { return none }
					p *= v
				}
				return math_int(p)
			}
			mut p := 1.0
			for f in math_seq_floats(args[0]) {
				p *= f
			}
			return math_float(p)
		}
		'math-mean' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: mean of empty sequence')
			}
			return math_float(math_mean_f(xs))
		}
		'math-median' {
			mut xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: median of empty sequence')
			}
			xs.sort()
			n := xs.len
			if n % 2 == 1 {
				return math_float(xs[n / 2])
			}
			return math_float((xs[n / 2 - 1] + xs[n / 2]) / 2.0)
		}
		'math-mode' {
			items := math_items(args[0])
			if items.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: mode of empty sequence')
			}
			modes := math_modes(args[0]) or { return none }
			// smallest tied value (modes already sorted ascending)
			all_int := math_seq_all_int(args[0])
			if all_int {
				return math_int(i64(modes[0]))
			}
			return math_float(modes[0])
		}
		'math-multimode' {
			items := math_items(args[0])
			if items.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: multimode of empty sequence')
			}
			modes := math_modes(args[0]) or { return none }
			all_int := math_seq_all_int(args[0])
			mut out := []cx.Node{}
			for m in modes {
				if all_int {
					out << math_int(i64(m))
				} else {
					out << math_float(m)
				}
			}
			return cx.Element{
				name:  '__cx_seq__'
				items: out
			}
		}
		'math-stddev' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: stddev of empty sequence')
			}
			return math_float(math.sqrt(math_variance(xs, true)))
		}
		'math-variance' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: variance of empty sequence')
			}
			return math_float(math_variance(xs, true))
		}
		'math-stddev-pop' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: stddev-pop of empty sequence')
			}
			return math_float(math.sqrt(math_variance(xs, false)))
		}
		'math-variance-pop' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: variance-pop of empty sequence')
			}
			return math_float(math_variance(xs, false))
		}
		'math-percentile' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: percentile of empty sequence')
			}
			p := math_arg_f64(args[1]) or { return none }
			// Domain guard (§3.4: p in [0,100]). Without this an out-of-range
			// p drives the interpolation rank past the array bounds and the
			// native indexer PANICS the whole interpreter — a pure function
			// must never crash the host. NaN fails every comparison → rejected.
			if !(p >= 0.0 && p <= 100.0) {
				return mk_err(math_err_domain, 'E_MATH_DOMAIN_ERROR: percentile p=${p} outside [0,100]')
			}
			return math_float(math_percentile(xs, p))
		}
		'math-quantile' {
			xs := math_seq_floats(args[0])
			if xs.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: quantile of empty sequence')
			}
			q := math_arg_f64(args[1]) or { return none }
			if !(q >= 0.0 && q <= 1.0) {
				return mk_err(math_err_domain, 'E_MATH_DOMAIN_ERROR: quantile q=${q} outside [0,1]')
			}
			return math_float(math_percentile(xs, q * 100.0))
		}
		'math-correlation' {
			xs := math_seq_floats(args[0])
			ys := math_seq_floats(args[1])
			if xs.len == 0 || ys.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: correlation of empty sequence')
			}
			n := if xs.len < ys.len { xs.len } else { ys.len }
			mx := math_mean_f(xs)
			my := math_mean_f(ys)
			mut cov := 0.0
			mut vx := 0.0
			mut vy := 0.0
			for i in 0 .. n {
				dx := xs[i] - mx
				dy := ys[i] - my
				cov += dx * dy
				vx += dx * dx
				vy += dy * dy
			}
			return math_float(cov / math.sqrt(vx * vy))
		}
		'math-covariance' {
			xs := math_seq_floats(args[0])
			ys := math_seq_floats(args[1])
			if xs.len == 0 || ys.len == 0 {
				return mk_err(math_err_empty, 'E_MATH_EMPTY_SEQUENCE: covariance of empty sequence')
			}
			n := if xs.len < ys.len { xs.len } else { ys.len }
			mx := math_mean_f(xs)
			my := math_mean_f(ys)
			mut cov := 0.0
			for i in 0 .. n {
				cov += (xs[i] - mx) * (ys[i] - my)
			}
			return math_float(cov / f64(n - 1)) // sample (N-1) per §3.4
		}

		// ── §3.5 bit operations ──────────────────────────────────────
		'math-bit-and' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			return math_int(a & b)
		}
		'math-bit-or' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			return math_int(a | b)
		}
		'math-bit-xor' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			return math_int(a ^ b)
		}
		'math-bit-not' {
			x := math_arg_i64(args[0]) or { return none }
			return math_int(~x)
		}
		'math-bit-shift-left' {
			x := math_arg_i64(args[0]) or { return none }
			n := math_arg_i64(args[1]) or { return none }
			if n < 0 {
				return mk_err(math_err_domain, 'E_MATH_DOMAIN_ERROR: negative shift count ${n}')
			}
			if n >= 64 {
				return math_int(0) // saturate (§3.5)
			}
			return math_int(x << u64(n))
		}
		'math-bit-shift-right' {
			x := math_arg_i64(args[0]) or { return none }
			n := math_arg_i64(args[1]) or { return none }
			if n < 0 {
				return mk_err(math_err_domain, 'E_MATH_DOMAIN_ERROR: negative shift count ${n}')
			}
			if n >= 64 {
				// arithmetic (sign-extending) saturation (§3.5)
				return math_int(if x < 0 { i64(-1) } else { i64(0) })
			}
			return math_int(x >> u64(n)) // V `>>` on i64 is arithmetic
		}
		'math-popcount' {
			x := math_arg_i64(args[0]) or { return none }
			mut u := u64(x)
			mut c := 0
			for u != 0 {
				c += int(u & 1)
				u >>= 1
			}
			return math_int(i64(c))
		}
		'math-leading-zeros' {
			x := math_arg_i64(args[0]) or { return none }
			u := u64(x)
			if u == 0 {
				return math_int(64)
			}
			mut c := 0
			mut mask := u64(1) << 63
			for mask != 0 && (u & mask) == 0 {
				c++
				mask >>= 1
			}
			return math_int(i64(c))
		}
		'math-trailing-zeros' {
			x := math_arg_i64(args[0]) or { return none }
			u := u64(x)
			if u == 0 {
				return math_int(64)
			}
			mut c := 0
			mut v := u
			for v & 1 == 0 {
				c++
				v >>= 1
			}
			return math_int(i64(c))
		}

		// ── §3.6 predicates ──────────────────────────────────────────
		'math-is-nan' {
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			return math_bool(math.is_nan(f))
		}
		'math-is-infinite' {
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			return math_bool(math.is_inf(f, 0))
		}
		'math-is-finite' {
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			return math_bool(!math.is_nan(f) && !math.is_inf(f, 0))
		}
		'math-is-integer' {
			// true for int scalars; for float, true when integral & finite
			if math_arg_is_int(args[0]) {
				return math_bool(true)
			}
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			if math.is_nan(f) || math.is_inf(f, 0) {
				return math_bool(false)
			}
			return math_bool(f == math.floor(f))
		}
		'math-is-positive' {
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			return math_bool(f > 0)
		}
		'math-is-negative' {
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			return math_bool(f < 0)
		}
		'math-is-zero' {
			f := math_arg_f64(args[0]) or { return math_bool(false) }
			return math_bool(f == 0)
		}

		// ── §3.7 number theory ───────────────────────────────────────
		'math-gcd' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			// |i64_min| = 2^63 is unrepresentable in i64, so the abs-value
			// normalization in math_gcd would overflow back to a NEGATIVE
			// gcd. Reject as overflow rather than return a wrong sign.
			if a == math_i64_min || b == math_i64_min {
				return mk_err(math_err_overflow, 'E_MATH_OVERFLOW: gcd operand i64 minimum has no representable absolute value')
			}
			return math_int(math_gcd(a, b))
		}
		'math-lcm' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			if a == 0 || b == 0 {
				return math_int(0)
			}
			if a == math_i64_min || b == math_i64_min {
				return mk_err(math_err_overflow, 'E_MATH_OVERFLOW: lcm operand i64 minimum has no representable absolute value')
			}
			g := math_gcd(a, b)
			// lcm = (a/g) * b. Detect i64 overflow of the product (the true
			// lcm can exceed int64) and surface it rather than wrap silently.
			aq := a / g
			prod := aq * b
			if aq != 0 && prod / aq != b {
				return mk_err(math_err_overflow, 'E_MATH_OVERFLOW: lcm(${a}, ${b}) exceeds int64')
			}
			r := if prod < 0 { -prod } else { prod }
			if r < 0 {
				return mk_err(math_err_overflow, 'E_MATH_OVERFLOW: lcm(${a}, ${b}) exceeds int64')
			}
			return math_int(r)
		}
		'math-is-prime' {
			n := math_arg_i64(args[0]) or { return none }
			return math_bool(math_is_prime(n))
		}
		'math-factorial' {
			n := math_arg_i64(args[0]) or { return none }
			// Negative n is a DOMAIN error, not overflow (math_factorial
			// returns the same none sentinel for both, so disambiguate here).
			if n < 0 {
				return mk_err(math_err_domain, 'E_MATH_DOMAIN_ERROR: factorial of negative ${n}')
			}
			r := math_factorial(n) or {
				return mk_err(math_err_overflow, 'E_MATH_OVERFLOW: factorial(${n}) exceeds int64')
			}
			return math_int(r)
		}

		// ── §3.8 constants ───────────────────────────────────────────
		'math-pi' {
			return math_float(math.pi)
		}
		'math-e' {
			return math_float(math.e)
		}
		'math-tau' {
			return math_float(2.0 * math.pi)
		}
		'math-golden' {
			return math_float((1.0 + math.sqrt(5.0)) / 2.0)
		}
		'math-infinity' {
			return math_float(math.inf(1))
		}
		'math-nan' {
			return math_float(math.nan())
		}
		'math-epsilon' {
			// IEEE-754 double machine epsilon (2^-52)
			return math_float(2.220446049250313e-16)
		}

		// ── §3.9 explicit modular arithmetic ─────────────────────────
		'math-wrapping-add' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			return math_int(i64(u64(a) + u64(b)))
		}
		'math-wrapping-sub' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			return math_int(i64(u64(a) - u64(b)))
		}
		'math-wrapping-mul' {
			a := math_arg_i64(args[0]) or { return none }
			b := math_arg_i64(args[1]) or { return none }
			return math_int(i64(u64(a) * u64(b)))
		}
		'math-wrapping-pow' {
			base := math_arg_i64(args[0]) or { return none }
			exp := math_arg_i64(args[1]) or { return none }
			mut result := u64(1)
			mut b := u64(base)
			mut e := exp
			for e > 0 {
				if e & 1 == 1 {
					result *= b
				}
				b *= b
				e >>= 1
			}
			return math_int(i64(result))
		}

		else {
			return none
		}
	}
}

// math_modes returns the values tied at maximum frequency, sorted
// ascending. Float-valued (int items promote); callers re-narrow to int
// when the input is closed over ints.
fn math_modes(n cx.Node) ?[]f64 {
	xs := math_seq_floats(n)
	if xs.len == 0 {
		return none
	}
	// O(n) frequency tally keyed by the f64 bit pattern (the prior code did
	// an O(n) linear scan of the keys list per element → O(n²) on
	// all-distinct input). Signed zeros are merged (−0.0 == 0.0). Map
	// iteration order is unstable, but the final `modes.sort()` makes the
	// result deterministic.
	mut counts := map[u64]int{}
	for x in xs {
		bits := if x == 0.0 { u64(0) } else { math.f64_bits(x) }
		counts[bits]++
	}
	mut max_c := 0
	for _, c in counts {
		if c > max_c {
			max_c = c
		}
	}
	mut modes := []f64{}
	for bits, c in counts {
		if c == max_c {
			modes << math.f64_from_bits(bits)
		}
	}
	modes.sort()
	return modes
}
