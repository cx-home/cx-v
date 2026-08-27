@[has_globals]
module code

import cx
import math
import sync
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

// stdlib_src_random lives in stdlib_bundle.v (I4: source embeds are data,
// profile-invariant; see stdlib_src_env's note).

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
	note_operand_fault('random', 'random-', 'int', n)
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
	note_operand_fault('random', 'random-', 'float', n)
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

// ── implicit generator state — PER-THREAD streams (#625) ─────────────
//
// One process-wide Xoshiro raced under [?worker] threads: interleaved
// draws made a "deterministic" seed+draw sequence differ run to run, and
// the unsynchronized state mutation was itself a data race. Each OS
// thread now owns its own stream: entropy-seeded (tid-mixed, so two
// threads first-drawing in the same tick still diverge) at that thread's
// first draw, re-seedable via `[$random:seed]` — which seeds the CALLING
// thread's stream, making seed+draw deterministic WITHIN a thread.
// Cross-thread reproducible pipelines use the §3.2 explicit-state
// mirrors or the §3.7 generator handles. Registry lock held only for the
// tid lookup/insert; the returned per-thread state is mutated lock-free
// (only its owner thread ever touches it).

const g_random_streams_lock = &sync.Mutex(sync.new_mutex())

__global (
	g_random_streams map[u64]&Xoshiro
)

// random_tls returns the calling thread's stream, entropy-seeding it on
// first use.
fn random_tls() &Xoshiro {
	tid := cap_thread_id()
	mut l := unsafe { g_random_streams_lock }
	l.lock()
	if st := g_random_streams[tid] {
		l.unlock()
		return st
	}
	mut st := &Xoshiro{}
	s := vseed.time_seed_array(2)
	unsafe {
		*st = xoshiro_from_seed(i64((u64(s[0]) | (u64(s[1]) << 32)) ^ (tid * u64(0x9e3779b97f4a7c15))))
	}
	if st.s[0] == 0 && st.s[1] == 0 && st.s[2] == 0 && st.s[3] == 0 {
		unsafe {
			*st = xoshiro_from_seed(i64(0x2545f4914f6cdd1d))
		}
	}
	g_random_streams[tid] = st
	l.unlock()
	return st
}

// random_tls_seed re-seeds the calling thread's stream (the `seed` verb).
fn random_tls_seed(s i64) {
	mut st := random_tls()
	unsafe {
		*st = xoshiro_from_seed(s)
	}
	if st.s[0] == 0 && st.s[1] == 0 && st.s[2] == 0 && st.s[3] == 0 {
		unsafe {
			*st = xoshiro_from_seed(i64(0x2545f4914f6cdd1d))
		}
	}
}

// ── §3.7 stateful generator handles (#625) ───────────────────────────
//
// [$random:new $seed] returns an [rng handle=N] whose draws ($random:gen-*)
// mutate registry-held state under a per-handle lock — the imperative twin
// of the §3.2 pure -with mirrors, for worker code that wants a private
// deterministic stream without threading [result …] pairs. Concurrent draws
// on ONE handle are safe but serialize in arrival order (determinism under
// concurrency = one consumer per handle, or the pure mirrors).

@[heap]
struct RandomGen {
mut:
	lock &sync.Mutex = sync.new_mutex()
	st   Xoshiro
}

const g_random_gens_lock = &sync.Mutex(sync.new_mutex())

__global (
	g_random_gens    map[i64]&RandomGen
	g_random_gen_seq i64
)

fn random_gen_new(seed i64) i64 {
	mut l := unsafe { g_random_gens_lock }
	l.lock()
	g_random_gen_seq++
	id := g_random_gen_seq
	mut g := &RandomGen{
		st: xoshiro_from_seed(seed)
	}
	if g.st.s[0] == 0 && g.st.s[1] == 0 && g.st.s[2] == 0 && g.st.s[3] == 0 {
		g.st = xoshiro_from_seed(i64(0x2545f4914f6cdd1d))
	}
	g_random_gens[id] = g
	l.unlock()
	return id
}

fn random_gen_handle(id i64) cx.Node {
	return cx.Element{
		name:  'rng'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(id)
			},
		]
	}
}

// random_gen_of resolves a draw's handle argument, or an arg-invalid err.
fn random_gen_of(arg cx.Node) ?&RandomGen {
	if arg is cx.Element && arg.name == 'rng' {
		id := arg.attr('handle').i64()
		mut l := unsafe { g_random_gens_lock }
		l.lock()
		g := g_random_gens[id] or {
			l.unlock()
			return none
		}
		l.unlock()
		return g
	}
	return none
}

// ── crypto-random source (§4.2) ─────────────────────────────────────
// random_crypto_bytes (the OS/CSPRNG entropy primitive) lives in
// stdlib_crypto.v — I4: crypto's entropy-drawing surfaces (keypair/AEAD
// nonces, cap-guarded `random`) survive in artifacts built without this
// pack; ONE definition serves both files.

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

// random_entropy_prims lives in effect_alignment.v — I4: profile-invariant
// purity data, outside this `-d cx_no_pack_random`-gated file.

fn random_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// I1 (the 2b flip): an exact-family argument (decimal/bigint) never
	// falls through to "no callable" — refuse with CXER3002 + the cast
	// hint (random parameters are float-semantic; [cast] is the bridge).
	if name.starts_with('random-') {
		for a in args {
			if a is cx.ScalarNode {
				if a.data_type == cx.ScalarType.decimal_type
					|| a.data_type == cx.ScalarType.bigint_type {
					return mk_err('cx-err:CXER3002',
						'${name}: not defined over the exact kinds (decimal/bigint) — [cast … :float] first (math.md §4.4)')
				}
			}
		}
	}
	if name in random_entropy_prims {
		if d := cap_guard('random', name) {
			return d
		}
	}
	match name {
		// ── §3.1 PRNG process-global (impure) ───────────────────────
		'random-seed' {
			s := random_arg_int(args[0]) or { return none }
			random_tls_seed(s)
			return random_null()
		}
		'random-next-int' {
			mut rst := random_tls()
			return random_int(rst.next_u63())
		}
		'random-next-float' {
			mut rst := random_tls()
			return random_float(rst.next_f64())
		}
		'random-next-bool' {
			mut rst := random_tls()
			return random_bool(rst.next() & 1 == 1)
		}
		'random-int-range' {
			lo := random_arg_int(args[0]) or { return none }
			hi := random_arg_int(args[1]) or { return none }
			if lo > hi {
				return mk_err('cx-err:CXER1901', 'E_RANDOM_RANGE_INVALID: lo ${lo} > hi ${hi}')
			}
			mut rst := random_tls()
			return random_int(rst.int_range(lo, hi))
		}
		'random-float-range' {
			lo := random_arg_float(args[0]) or { return none }
			hi := random_arg_float(args[1]) or { return none }
			mut rst := random_tls()
			u := rst.next_f64()
			return random_float(lo + u * (hi - lo))
		}
		'random-shuffle' {
			items := random_seq_items(args[0]) or { return none }
			mut rst := random_tls()
			return random_seq(rst.fisher_yates(items))
		}
		'random-choose' {
			items := random_seq_items(args[0]) or { return none }
			if items.len == 0 {
				return mk_err('cx-err:CXER1902', 'E_RANDOM_EMPTY_SEQUENCE: choose on empty sequence')
			}
			mut rst := random_tls()
			idx := int(rst.range_u64(u64(items.len)))
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
			mut rst := random_tls()
			shuffled := rst.fisher_yates(items)
			return random_seq(shuffled[..int(n)].clone())
		}

		// ── §3.7 stateful generator handles (#625) ──────────────────
		'random-new' {
			s := random_arg_int(args[0]) or { return none }
			return random_gen_handle(random_gen_new(s))
		}
		'random-free' {
			if args[0] is cx.Element && (args[0] as cx.Element).name == 'rng' {
				id := (args[0] as cx.Element).attr('handle').i64()
				mut l := unsafe { g_random_gens_lock }
				l.lock()
				g_random_gens.delete(id)
				l.unlock()
				return random_null()
			}
			return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: free expects an [rng] handle')
		}
		'random-gen-int' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			g.lock.lock()
			v := g.st.next_u63()
			g.lock.unlock()
			return random_int(v)
		}
		'random-gen-float' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			g.lock.lock()
			v := g.st.next_f64()
			g.lock.unlock()
			return random_float(v)
		}
		'random-gen-bool' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			g.lock.lock()
			v := g.st.next() & 1 == 1
			g.lock.unlock()
			return random_bool(v)
		}
		'random-gen-int-range' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			lo := random_arg_int(args[1]) or { return none }
			hi := random_arg_int(args[2]) or { return none }
			if lo > hi {
				return mk_err('cx-err:CXER1901', 'E_RANDOM_RANGE_INVALID: lo ${lo} > hi ${hi}')
			}
			g.lock.lock()
			v := g.st.int_range(lo, hi)
			g.lock.unlock()
			return random_int(v)
		}
		'random-gen-float-range' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			lo := random_arg_float(args[1]) or { return none }
			hi := random_arg_float(args[2]) or { return none }
			g.lock.lock()
			u := g.st.next_f64()
			g.lock.unlock()
			return random_float(lo + u * (hi - lo))
		}
		'random-gen-shuffle' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			items := random_seq_items(args[1]) or { return none }
			g.lock.lock()
			out := g.st.fisher_yates(items)
			g.lock.unlock()
			return random_seq(out)
		}
		'random-gen-choose' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			items := random_seq_items(args[1]) or { return none }
			if items.len == 0 {
				return mk_err('cx-err:CXER1902', 'E_RANDOM_EMPTY_SEQUENCE: choose on empty sequence')
			}
			g.lock.lock()
			idx := int(g.st.range_u64(u64(items.len)))
			g.lock.unlock()
			return items[idx]
		}
		'random-gen-sample' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			items := random_seq_items(args[1]) or { return none }
			n := random_arg_int(args[2]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			if int(n) > items.len {
				return mk_err('cx-err:CXER1903', 'E_RANDOM_SAMPLE_TOO_LARGE: n ${n} > length ${items.len}')
			}
			g.lock.lock()
			shuffled := g.st.fisher_yates(items)
			g.lock.unlock()
			return random_seq(shuffled[..int(n)].clone())
		}
		'random-gen-gaussian' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			mean := random_arg_float(args[1]) or { return none }
			stddev := random_arg_float(args[2]) or { return none }
			if stddev < 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative stddev')
			}
			g.lock.lock()
			v := g.st.gaussian_draw(mean, stddev)
			g.lock.unlock()
			return random_float(v)
		}
		'random-gen-exponential' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			lambda := random_arg_float(args[1]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			g.lock.lock()
			v := g.st.exponential_draw(lambda)
			g.lock.unlock()
			return random_float(v)
		}
		'random-gen-poisson' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			lambda := random_arg_float(args[1]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			g.lock.lock()
			v := g.st.poisson_draw(lambda)
			g.lock.unlock()
			return random_int(v)
		}
		'random-gen-choose-weighted' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			items := random_seq_items(args[1]) or { return none }
			weights := random_weights(args[2]) or { return none }
			total, errv := random_validate_weighted(items, weights, 1)
			if e := errv {
				return e
			}
			g.lock.lock()
			idx := g.st.weighted_index(weights, total)
			g.lock.unlock()
			return items[idx]
		}
		'random-gen-sample-weighted' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			items := random_seq_items(args[1]) or { return none }
			weights := random_weights(args[2]) or { return none }
			n := random_arg_int(args[3]) or { return none }
			_, errv := random_validate_weighted(items, weights, int(n))
			if e := errv {
				return e
			}
			g.lock.lock()
			out := random_weighted_sample(mut g.st, items, weights, int(n))
			g.lock.unlock()
			return random_seq(out)
		}
		'random-gen-floats' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			n := random_arg_int(args[1]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			g.lock.lock()
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_float(g.st.next_f64())
			}
			g.lock.unlock()
			return random_seq(out)
		}
		'random-gen-ints' {
			mut g := random_gen_of(args[0]) or {
				return mk_err('cx-err:CXER1906', 'E_RANDOM_HANDLE_INVALID: unknown [rng] handle')
			}
			n := random_arg_int(args[1]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			g.lock.lock()
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_int(g.st.next_u63())
			}
			g.lock.unlock()
			return random_seq(out)
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
			mut rst := random_tls()
			return random_float(rst.gaussian_draw(mean, stddev))
		}
		'random-exponential' {
			lambda := random_arg_float(args[0]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			mut rst := random_tls()
			return random_float(rst.exponential_draw(lambda))
		}
		'random-poisson' {
			lambda := random_arg_float(args[0]) or { return none }
			if lambda <= 0.0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: non-positive lambda')
			}
			mut rst := random_tls()
			return random_int(rst.poisson_draw(lambda))
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
			mut rst := random_tls()
			idx := rst.weighted_index(weights, total)
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
			mut rst := random_tls()
			out := random_weighted_sample(mut rst, items, weights, int(n))
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
			mut rst := random_tls()
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_float(rst.next_f64())
			}
			return random_seq(out)
		}
		'random-next-ints' {
			n := random_arg_int(args[0]) or { return none }
			if n < 0 {
				return mk_err('cx-err:CXER1905', 'E_RANDOM_DISTRIBUTION_PARAM: negative n')
			}
			mut rst := random_tls()
			mut out := []cx.Node{cap: int(n)}
			for _ in 0 .. int(n) {
				out << random_int(rst.next_u63())
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
