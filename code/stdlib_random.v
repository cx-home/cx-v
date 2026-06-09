@[has_globals]
module code

import cx
import math
import rand.seed as vseed
import crypto.rand as crand
import encoding.hex
import encoding.base64

// stdlib_random.v — native primitives backing the `cx-stdlib/random`
// module (spec/stdlib_random.md). PRNG (xoshiro256++, §4.1) + crypto-
// random (system CSPRNG, §4.2) generation is not expressible in pure CX
// `[?def]` bodies, so the bundle bodies bottom out in the primitives
// dispatched here. See stdlib_dispatch.v for the registration line.
//
// ── CX value model ──────────────────────────────────────────────────
//   int      → ScalarType.int_type, i64.
//   float    → ScalarType.float_type, f64.
//   bool     → ScalarType.bool_type.
//   bytes    → ScalarType.bytes_type (raw octets carried as a string).
//   string   → ScalarType.string_type.
//   sequence → Element{ name: '__cx_seq__', items: [...] }.
//   generator→ Element{ name: 'generator' } carrying the 256-bit
//              xoshiro256++ state as four int children s0..s3 (the i64
//              bit-patterns of the u64 state words).
//   result   → Element{ name: 'result' } with labeled-slot children
//              :value and :next-generator (the §3.2 threaded pair). The
//              slot form auto-unwraps so `$r/value` / `$r/next-generator`
//              return the inner value / generator per walk_path_step.
//
// Errors are returned as `[err :code cx-err:CXERxxxx :message …]` element
// nodes (mk_err, eval.v) — the renderer surfaces the code string, which
// the conformance harness matches against `--- out_err`.

// ── bundled module source (spec/stdlib_random.md §3) ────────────────
//
// Each [?def] body forwards to a native primitive dispatched in
// random_stdlib_builtin below. This const is $embed_file-d from
// stdlib/random.cx — edit that file.

const stdlib_src_random = $embed_file('../../stdlib/random.cx').to_string()

// ── xoshiro256++ core (Vigna 2019) ──────────────────────────────────
//
// The PRNG algorithm is pinned as a stability guarantee (§4.1): the seed
// → sequence mapping is byte-for-byte identical across CX versions and
// Tier-1 bindings. from-seed mixes the seed via SplitMix64; next() is the
// canonical xoshiro256++ ++ output transform.

struct Xoshiro {
mut:
	s [4]u64
}

fn rotl(x u64, k int) u64 {
	return (x << u64(k)) | (x >> u64(64 - k))
}

// splitmix64_next mixes the seed-expansion state (canonical xoshiro256++
// initialization). Returns (output, advanced-state).
fn splitmix64_next(z_in u64) (u64, u64) {
	z := z_in + u64(0x9e3779b97f4a7c15)
	mut r := z
	r = (r ^ (r >> 30)) * u64(0xbf58476d1ce4e5b9)
	r = (r ^ (r >> 27)) * u64(0x94d049bb133111eb)
	return r ^ (r >> 31), z
}

fn xoshiro_from_seed(seed i64) Xoshiro {
	mut z := u64(seed)
	mut x := Xoshiro{}
	x.s[0], z = splitmix64_next(z)
	x.s[1], z = splitmix64_next(z)
	x.s[2], z = splitmix64_next(z)
	x.s[3], z = splitmix64_next(z)
	return x
}

// next produces the next 64-bit output and advances state (xoshiro256++).
fn (mut x Xoshiro) next() u64 {
	result := rotl(x.s[0] + x.s[3], 23) + x.s[0]
	t := x.s[1] << 17
	x.s[2] ^= x.s[0]
	x.s[3] ^= x.s[1]
	x.s[1] ^= x.s[2]
	x.s[0] ^= x.s[3]
	x.s[2] ^= t
	x.s[3] = rotl(x.s[3], 45)
	return result
}

// next_u63 returns a non-negative 63-bit integer (clears the sign bit so
// the i64 cast stays non-negative — `next-int` contract, §3.1).
fn (mut x Xoshiro) next_u63() i64 {
	return i64(x.next() >> 1)
}

// next_f64 returns a uniform float in [0.0, 1.0) using the top 53 bits.
fn (mut x Xoshiro) next_f64() f64 {
	return f64(x.next() >> 11) * (1.0 / f64(u64(1) << 53))
}

// range_u64 draws a uniform u64 in [0, n) with no modulo bias via
// classic rejection sampling: reject draws in the biased high tail, then
// reduce modulo n. n MUST be > 0.
fn (mut x Xoshiro) range_u64(n u64) u64 {
	if n == 0 {
		return 0
	}
	// rem = 2^64 mod n; threshold = last acceptable value (inclusive).
	rem := (-n) % n
	threshold := u64(0xffffffffffffffff) - rem
	for {
		r := x.next()
		if r <= threshold {
			return r % n
		}
	}
	return 0
}

// int_range draws a uniform i64 in [lo, hi] inclusive (rejection-sampled).
fn (mut x Xoshiro) int_range(lo i64, hi i64) i64 {
	width := u64(hi) - u64(lo) + 1 // width in u64 space; 0 means full 2^64 span
	if width == 0 {
		return i64(x.next())
	}
	return i64(u64(lo) + x.range_u64(width))
}

// ── distribution draws (shared between global + -with paths) ─────────

// gaussian_draw returns one normal(mean, stddev) sample via the polar
// (Marsaglia) Box-Muller form, consuming uniform [0,1) draws from x.
fn (mut x Xoshiro) gaussian_draw(mean f64, stddev f64) f64 {
	if stddev == 0.0 {
		return mean
	}
	for {
		u := 2.0 * x.next_f64() - 1.0
		v := 2.0 * x.next_f64() - 1.0
		s := u * u + v * v
		if s >= 1.0 || s == 0.0 {
			continue
		}
		mul := math.sqrt(-2.0 * math.log(s) / s)
		return mean + stddev * (u * mul)
	}
	return mean
}

// exponential_draw — inverse-CDF exponential with rate lambda (> 0).
fn (mut x Xoshiro) exponential_draw(lambda f64) f64 {
	u := x.next_f64()
	// 1-u maps [0,1) -> (0,1], avoiding log(0).
	return -math.log(1.0 - u) / lambda
}

// poisson_draw — Knuth's multiplication method (mean lambda > 0).
fn (mut x Xoshiro) poisson_draw(lambda f64) i64 {
	limit := math.exp(-lambda)
	mut k := i64(0)
	mut p := 1.0
	for {
		k++
		p *= x.next_f64()
		if p <= limit {
			break
		}
	}
	return k - 1
}

// fisher_yates returns a shuffled copy of items, consuming index draws
// from x (same unbiased range reduction as int-range).
fn (mut x Xoshiro) fisher_yates(items []cx.Node) []cx.Node {
	mut out := items.clone()
	mut i := out.len - 1
	for i > 0 {
		j := int(x.range_u64(u64(i + 1)))
		out[i], out[j] = out[j], out[i]
		i--
	}
	return out
}

// weighted_index selects one index proportional to weight, drawing a
// single uniform from x. Caller validates weights non-negative, total > 0.
fn (mut x Xoshiro) weighted_index(weights []f64, total f64) int {
	target := x.next_f64() * total
	mut acc := 0.0
	for i, w in weights {
		acc += w
		if target < acc && w > 0.0 {
			return i
		}
	}
	mut last := 0
	for i, w in weights {
		if w > 0.0 {
			last = i
		}
	}
	return last
}

// random_weighted_sample draws n elements without replacement, each step
// proportional to the remaining weights. Caller validates inputs.
fn random_weighted_sample(mut x Xoshiro, items []cx.Node, weights []f64, n int) []cx.Node {
	mut remaining_items := items.clone()
	mut remaining_w := weights.clone()
	mut out := []cx.Node{cap: n}
	for _ in 0 .. n {
		mut total := 0.0
		for w in remaining_w {
			total += w
		}
		idx := x.weighted_index(remaining_w, total)
		out << remaining_items[idx]
		remaining_items.delete(idx)
		remaining_w.delete(idx)
	}
	return out
}

// ── generator element <-> Xoshiro ───────────────────────────────────

fn random_int_child(name string, v i64) cx.Node {
	return cx.Element{
		name:  name
		items: [cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(v)
			data_type: cx.ScalarType.int_type
		})]
	}
}

fn gen_to_node(x Xoshiro) cx.Node {
	return cx.Element{
		name:  'generator'
		items: [
			random_int_child('s0', i64(x.s[0])),
			random_int_child('s1', i64(x.s[1])),
			random_int_child('s2', i64(x.s[2])),
			random_int_child('s3', i64(x.s[3])),
		]
	}
}

fn node_to_gen(n cx.Node) ?Xoshiro {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	if el.name != 'generator' {
		return none
	}
	mut x := Xoshiro{}
	mut found := 0
	for c in el.items {
		if c is cx.Element && c.items.len == 1 {
			inner := c.items[0]
			if inner is cx.ScalarNode {
				v := inner.value
				if v is i64 {
					match c.name {
						's0' { x.s[0] = u64(v) found++ }
						's1' { x.s[1] = u64(v) found++ }
						's2' { x.s[2] = u64(v) found++ }
						's3' { x.s[3] = u64(v) found++ }
						else {}
					}
				}
			}
		}
	}
	if found != 4 {
		return none
	}
	return x
}

// ── result-pair element ([result [value …] [next-generator …]]) ───────

fn result_pair(value cx.Node, x Xoshiro) cx.Node {
	// value / next-generator are labeled fields → plain child
	// elements (value is polymorphic — scalar or sequence — so it can't be
	// a scalar attribute). Read via $r/value / $r/next-generator; the
	// terminal labeled-field unwrap (#19) exposes the inner value.
	return cx.Element{
		name:  'result'
		items: [
			cx.Node(cx.Element{ name: 'value', items: [value] }),
			cx.Node(cx.Element{ name: 'next-generator', items: [gen_to_node(x)] }),
		]
	}
}

// ── scalar / sequence builders ──────────────────────────────────────

fn random_int(v i64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.int_type }
}

fn random_float(v f64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.float_type }
}

fn random_bool(v bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.bool_type }
}

fn random_string(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.string_type }
}

fn random_bytes_node(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.bytes_type }
}

fn random_null() cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type }
}

fn random_seq(items []cx.Node) cx.Node {
	return cx.Element{ name: '__cx_seq__', items: items }
}

// ── argument readers ────────────────────────────────────────────────

fn random_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	return none
}

fn random_arg_float(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			else {}
		}
	}
	return none
}

// random_seq_items extracts the item list of a sequence/array element.
fn random_seq_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
			return n.items
		}
	}
	return none
}

// random_weights extracts a []f64 from a sequence of float/int scalars.
fn random_weights(n cx.Node) ?[]f64 {
	items := random_seq_items(n)?
	mut out := []f64{cap: items.len}
	for it in items {
		out << random_arg_float(it)?
	}
	return out
}

// random_validate_weighted enforces the §3.5 error contract. Returns the
// positive-weight total on success, or an err-value node on failure.
fn random_validate_weighted(items []cx.Node, weights []f64, n int) (f64, ?cx.Node) {
	if weights.len != items.len {
		return 0.0, mk_err('cx-err:CXER1904', 'E_RANDOM_WEIGHTS_MISMATCH: weights ${weights.len} != xs ${items.len}')
	}
	if items.len == 0 {
		return 0.0, mk_err('cx-err:CXER1902', 'E_RANDOM_EMPTY_SEQUENCE: weighted on empty sequence')
	}
	mut total := 0.0
	mut positive := 0
	for w in weights {
		if w < 0.0 {
			return 0.0, mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative weight')
		}
		if w > 0.0 {
			positive++
		}
		total += w
	}
	if total <= 0.0 {
		return 0.0, mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: all weights zero')
	}
	if n < 0 {
		return 0.0, mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
	}
	if n > positive {
		return 0.0, mk_err('cx-err:CXER1903', 'E_RANDOM_SAMPLE_TOO_LARGE: n ${n} > positive-weight count ${positive}')
	}
	return total, none
}

// ── process-global generator state ──────────────────────────────────
//
// Seeded from system entropy at module load; re-seedable via `seed`.
// Impure — shared across all callers in the process.

__global g_random_state = Xoshiro{}

fn random_global_seeded() bool {
	return g_random_state.s[0] != 0 || g_random_state.s[1] != 0
		|| g_random_state.s[2] != 0 || g_random_state.s[3] != 0
}

fn random_ensure_seeded() {
	if !random_global_seeded() {
		s := vseed.time_seed_array(2)
		g_random_state = xoshiro_from_seed(i64(u64(s[0]) | (u64(s[1]) << 32)))
		if !random_global_seeded() {
			g_random_state = xoshiro_from_seed(i64(0x2545f4914f6cdd1d))
		}
	}
}

// ── crypto-random source (§4.2) ─────────────────────────────────────

fn random_crypto_bytes(n int) ?string {
	if n < 0 {
		return none
	}
	if n == 0 {
		return ''
	}
	buf := crand.bytes(n) or { return none }
	return buf.bytestr()
}

// random_crypto_u64 reads 8 crypto bytes as a big-endian u64.
fn random_crypto_u64() ?u64 {
	b := random_crypto_bytes(8)?
	mut r := u64(0)
	for i in 0 .. 8 {
		r = (r << 8) | u64(b[i])
	}
	return r
}

const entropy_err = 'cx-err:CXER1900'

// ── dispatch ─────────────────────────────────────────────────────────

// random_entropy_prims are the crypto-random surfaces drawing OS/CSPRNG
// entropy — gated under the `random` capability (security.md §2). The
// seeded PRNG (xoshiro) is deterministic and needs no capability.
const random_entropy_prims = ['random-crypto-bytes', 'random-crypto-int',
	'random-crypto-hex', 'random-crypto-base64-url', 'random-crypto-token-urlsafe']

fn random_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if name in random_entropy_prims {
		if d := cap_guard('random', name) {
			return d
		}
	}
	match name {
		// ── §3.1 PRNG process-global (impure) ───────────────────────
		'random-seed' {
			s := random_arg_int(args[0]) or { return none }
			g_random_state = xoshiro_from_seed(s)
			if !random_global_seeded() {
				g_random_state = xoshiro_from_seed(i64(0x2545f4914f6cdd1d))
			}
			return random_null()
		}
		'random-next-int' {
			random_ensure_seeded()
			return random_int(g_random_state.next_u63())
		}
		'random-next-float' {
			random_ensure_seeded()
			return random_float(g_random_state.next_f64())
		}
		'random-next-bool' {
			random_ensure_seeded()
			return random_bool(g_random_state.next() & 1 == 1)
		}
		'random-int-range' {
			lo := random_arg_int(args[0]) or { return none }
			hi := random_arg_int(args[1]) or { return none }
			if lo > hi {
				return mk_err('cx-err:CXER1901', 'E_RANDOM_RANGE_INVALID: lo ${lo} > hi ${hi}')
			}
			random_ensure_seeded()
			return random_int(g_random_state.int_range(lo, hi))
		}
		'random-float-range' {
			lo := random_arg_float(args[0]) or { return none }
			hi := random_arg_float(args[1]) or { return none }
			random_ensure_seeded()
			u := g_random_state.next_f64()
			return random_float(lo + u * (hi - lo))
		}
		'random-shuffle' {
			items := random_seq_items(args[0]) or { return none }
			random_ensure_seeded()
			return random_seq(g_random_state.fisher_yates(items))
		}
		'random-choose' {
			items := random_seq_items(args[0]) or { return none }
			if items.len == 0 {
				return mk_err('cx-err:CXER1902', 'E_RANDOM_EMPTY_SEQUENCE: choose on empty sequence')
			}
			random_ensure_seeded()
			idx := int(g_random_state.range_u64(u64(items.len)))
			return items[idx]
		}
		'random-sample' {
			items := random_seq_items(args[0]) or { return none }
			n := random_arg_int(args[1]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			if int(n) > items.len {
				return mk_err('cx-err:CXER1903', 'E_RANDOM_SAMPLE_TOO_LARGE: n ${n} > length ${items.len}')
			}
			random_ensure_seeded()
			shuffled := g_random_state.fisher_yates(items)
			return random_seq(shuffled[..int(n)].clone())
		}

		// ── §3.2 PRNG explicit-state (pure given generator) ─────────
		'random-from-seed' {
			s := random_arg_int(args[0]) or { return none }
			return gen_to_node(xoshiro_from_seed(s))
		}
		'random-next-int-with' {
			mut x := node_to_gen(args[0]) or { return none }
			v := x.next_u63()
			return result_pair(random_int(v), x)
		}
		'random-next-float-with' {
			mut x := node_to_gen(args[0]) or { return none }
			v := x.next_f64()
			return result_pair(random_float(v), x)
		}
		'random-next-bool-with' {
			mut x := node_to_gen(args[0]) or { return none }
			v := x.next() & 1 == 1
			return result_pair(random_bool(v), x)
		}
		'random-int-range-with' {
			mut x := node_to_gen(args[0]) or { return none }
			lo := random_arg_int(args[1]) or { return none }
			hi := random_arg_int(args[2]) or { return none }
			if lo > hi {
				return mk_err('cx-err:CXER1901', 'E_RANDOM_RANGE_INVALID: lo ${lo} > hi ${hi}')
			}
			v := x.int_range(lo, hi)
			return result_pair(random_int(v), x)
		}
		'random-float-range-with' {
			mut x := node_to_gen(args[0]) or { return none }
			lo := random_arg_float(args[1]) or { return none }
			hi := random_arg_float(args[2]) or { return none }
			if lo > hi {
				return mk_err('cx-err:CXER1901', 'E_RANDOM_RANGE_INVALID: lo ${lo} > hi ${hi}')
			}
			u := x.next_f64()
			return result_pair(random_float(lo + u * (hi - lo)), x)
		}
		'random-shuffle-with' {
			mut x := node_to_gen(args[0]) or { return none }
			items := random_seq_items(args[1]) or { return none }
			out := x.fisher_yates(items)
			return result_pair(random_seq(out), x)
		}
		'random-choose-with' {
			mut x := node_to_gen(args[0]) or { return none }
			items := random_seq_items(args[1]) or { return none }
			if items.len == 0 {
				return mk_err('cx-err:CXER1902', 'E_RANDOM_EMPTY_SEQUENCE: choose on empty sequence')
			}
			idx := int(x.range_u64(u64(items.len)))
			return result_pair(items[idx], x)
		}
		'random-sample-with' {
			mut x := node_to_gen(args[0]) or { return none }
			items := random_seq_items(args[1]) or { return none }
			n := random_arg_int(args[2]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			if int(n) > items.len {
				return mk_err('cx-err:CXER1903', 'E_RANDOM_SAMPLE_TOO_LARGE: n ${n} > length ${items.len}')
			}
			shuffled := x.fisher_yates(items)
			return result_pair(random_seq(shuffled[..int(n)].clone()), x)
		}

		// ── §3.3 crypto-random (impure, kernel-backed) ──────────────
		'random-crypto-bytes' {
			n := random_arg_int(args[0]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			b := random_crypto_bytes(int(n)) or {
				return mk_err(entropy_err, 'E_RANDOM_ENTROPY_UNAVAILABLE: system source error')
			}
			return random_bytes_node(b)
		}
		'random-crypto-int' {
			lo := random_arg_int(args[0]) or { return none }
			hi := random_arg_int(args[1]) or { return none }
			if lo > hi {
				return mk_err('cx-err:CXER1901', 'E_RANDOM_RANGE_INVALID: lo ${lo} > hi ${hi}')
			}
			width := u64(hi) - u64(lo) + 1
			if width == 0 {
				r := random_crypto_u64() or {
					return mk_err(entropy_err, 'E_RANDOM_ENTROPY_UNAVAILABLE: system source error')
				}
				return random_int(i64(r))
			}
			// Rejection sampling on crypto bytes (no modulo bias, §3.3).
			rem := (-width) % width
			threshold := u64(0xffffffffffffffff) - rem
			for {
				r := random_crypto_u64() or {
					return mk_err(entropy_err, 'E_RANDOM_ENTROPY_UNAVAILABLE: system source error')
				}
				if r <= threshold {
					return random_int(i64(u64(lo) + (r % width)))
				}
			}
			return random_int(lo)
		}
		'random-crypto-hex' {
			n := random_arg_int(args[0]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			b := random_crypto_bytes(int(n)) or {
				return mk_err(entropy_err, 'E_RANDOM_ENTROPY_UNAVAILABLE: system source error')
			}
			return random_string(hex.encode(b.bytes()))
		}
		'random-crypto-base64-url' {
			n := random_arg_int(args[0]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			b := random_crypto_bytes(int(n)) or {
				return mk_err(entropy_err, 'E_RANDOM_ENTROPY_UNAVAILABLE: system source error')
			}
			return random_string(base64.url_encode(b.bytes()).trim_right('='))
		}
		'random-crypto-token-urlsafe' {
			mut n := i64(32)
			if args.len >= 1 {
				n = random_arg_int(args[0]) or { return none }
			}
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			b := random_crypto_bytes(int(n)) or {
				return mk_err(entropy_err, 'E_RANDOM_ENTROPY_UNAVAILABLE: system source error')
			}
			return random_string(base64.url_encode(b.bytes()).trim_right('='))
		}

		// ── §3.4 distribution helpers ───────────────────────────────
		'random-gaussian' {
			mean := random_arg_float(args[0]) or { return none }
			stddev := random_arg_float(args[1]) or { return none }
			if stddev < 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative stddev')
			}
			random_ensure_seeded()
			return random_float(g_random_state.gaussian_draw(mean, stddev))
		}
		'random-exponential' {
			lambda := random_arg_float(args[0]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			random_ensure_seeded()
			return random_float(g_random_state.exponential_draw(lambda))
		}
		'random-poisson' {
			lambda := random_arg_float(args[0]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			random_ensure_seeded()
			return random_int(g_random_state.poisson_draw(lambda))
		}
		'random-gaussian-with' {
			mut x := node_to_gen(args[0]) or { return none }
			mean := random_arg_float(args[1]) or { return none }
			stddev := random_arg_float(args[2]) or { return none }
			if stddev < 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative stddev')
			}
			v := x.gaussian_draw(mean, stddev)
			return result_pair(random_float(v), x)
		}
		'random-exponential-with' {
			mut x := node_to_gen(args[0]) or { return none }
			lambda := random_arg_float(args[1]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			v := x.exponential_draw(lambda)
			return result_pair(random_float(v), x)
		}
		'random-poisson-with' {
			mut x := node_to_gen(args[0]) or { return none }
			lambda := random_arg_float(args[1]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			v := x.poisson_draw(lambda)
			return result_pair(random_int(v), x)
		}

		// ── §3.5 weighted sampling ──────────────────────────────────
		'random-choose-weighted' {
			items := random_seq_items(args[0]) or { return none }
			weights := random_weights(args[1]) or { return none }
			total, errv := random_validate_weighted(items, weights, 1)
			if e := errv {
				return e
			}
			random_ensure_seeded()
			idx := g_random_state.weighted_index(weights, total)
			return items[idx]
		}
		'random-sample-weighted' {
			items := random_seq_items(args[0]) or { return none }
			weights := random_weights(args[1]) or { return none }
			n := random_arg_int(args[2]) or { return none }
			_, errv := random_validate_weighted(items, weights, int(n))
			if e := errv {
				return e
			}
			random_ensure_seeded()
			out := random_weighted_sample(mut g_random_state, items, weights, int(n))
			return random_seq(out)
		}
		'random-choose-weighted-with' {
			mut x := node_to_gen(args[0]) or { return none }
			items := random_seq_items(args[1]) or { return none }
			weights := random_weights(args[2]) or { return none }
			total, errv := random_validate_weighted(items, weights, 1)
			if e := errv {
				return e
			}
			idx := x.weighted_index(weights, total)
			return result_pair(items[idx], x)
		}
		'random-sample-weighted-with' {
			mut x := node_to_gen(args[0]) or { return none }
			items := random_seq_items(args[1]) or { return none }
			weights := random_weights(args[2]) or { return none }
			n := random_arg_int(args[3]) or { return none }
			_, errv := random_validate_weighted(items, weights, int(n))
			if e := errv {
				return e
			}
			out := random_weighted_sample(mut x, items, weights, int(n))
			return result_pair(random_seq(out), x)
		}

		// ── §3.6 vectorized generation ──────────────────────────────
		'random-next-floats' {
			n := random_arg_int(args[0]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			random_ensure_seeded()
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_float(g_random_state.next_f64())
			}
			return random_seq(out)
		}
		'random-next-ints' {
			n := random_arg_int(args[0]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			random_ensure_seeded()
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_int(g_random_state.next_u63())
			}
			return random_seq(out)
		}
		'random-next-floats-with' {
			mut x := node_to_gen(args[0]) or { return none }
			n := random_arg_int(args[1]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_float(x.next_f64())
			}
			return result_pair(random_seq(out), x)
		}
		'random-next-ints-with' {
			mut x := node_to_gen(args[0]) or { return none }
			n := random_arg_int(args[1]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_int(x.next_u63())
			}
			return result_pair(random_seq(out), x)
		}
		else {
			return none
		}
	}
}
