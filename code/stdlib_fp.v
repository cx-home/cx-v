module code

import cx

// stdlib_fp.v — native primitives backing the `cx-stdlib/fp` module
// (spec/std-lib/fp.md). fp is composition over the four outcome channels
// (code.md §9.1.2): the six combinators map / flat-map / pure / traverse
// / sequence / fold dispatch on the HEAD TAG of the container value.
//
// Unlike most stdlib primitives, the fp combinators must APPLY a CX
// callable to interior values, so they need the live `MatchEnv` (closure
// table). They therefore cannot route through the env-less
// `stdlib_builtin(name, args)` chain in stdlib_dispatch.v; instead they
// are reached via `eval_fp_builtin(name, args, mut env)` from the
// higher-order built-in dispatch path in eval.v (alongside map/reduce),
// keyed off the `fp-` primitive name prefix. The bundle bodies
// (stdlib_src_fp) forward `[$fp:map F fn]` → `[$fp-map F $fn]` etc.
//
// ── dispatch precedence (spec §1.2, NORMATIVE) ───────────────────────
//   Given a value x, an fp combinator selects its instance in this fixed
//   order:
//     1. a registered head-tag instance for x's head — the built-in
//        `result` instance over `[ok]` / `[err]`;
//     2. else x is a sequence (`__cx_seq__` / bare envelope) → the
//        `sequence` instance (Maybe + List: None=(), Some(x)=(x));
//     3. else x is a bare scalar → the singleton Some(x) under the
//        sequence instance (a scalar is a singleton sequence, V3);
//     4. else (x is a tagged element with NO registered instance, e.g.
//        `[user …]`) → cx-err:CXER4400 (E_NO_INSTANCE).
//
//   A tagged element is NOT implicitly a container — only scalars and
//   sequences are auto-Maybe.
//
// ── error code (spec §5; MIGRATION_DECISIONS D001) ───────────────────
//   E_NO_INSTANCE = cx-err:CXER4400 (stdlib band 4400-4409). The SAP
//   draft's CXER0244 was inside the core Futures-reserved range and is
//   superseded by the stdlib allocation.

const fp_err_no_instance = 'cx-err:CXER4400' // E_NO_INSTANCE

// FpKind classifies a value for §1.2 dispatch.
enum FpKind {
	result_ok   // [ok …]      → result instance
	result_err  // [err …]     → result instance (railway short-circuit)
	sequence    // ()/(x)/(…)  → sequence instance (Maybe + List)
	scalar      // bare scalar → singleton Some(x) under sequence
	no_instance // tagged element with no registered instance → CXER4400
}

// fp_classify implements the §1.2 dispatch precedence over a value node.
fn fp_classify(n cx.Node) FpKind {
	if n is cx.Element {
		// Sequence / bare envelopes are the sequence instance regardless
		// of cardinality (empty = None, singleton = Some, ≥2 = List).
		if n.name == '' || n.name == seq_marker_name || n.name == arr_marker_name {
			return .sequence
		}
		if n.name == 'ok' {
			return .result_ok
		}
		if n.name == 'err' {
			return .result_err
		}
		// Any other tagged element (e.g. [user …]) has no registered
		// instance — opaque value, raises E_NO_INSTANCE under a combinator.
		return .no_instance
	}
	// SequenceNode / ArrayNode envelopes are the sequence instance.
	if n is cx.SequenceNode {
		return .sequence
	}
	if n is cx.ArrayNode {
		return .sequence
	}
	// IteratorNode is the sequence instance too (#529): $filter/$map and
	// the finite generators return eager iterators, and a combinator over
	// one must map its ITEMS. Unclassified it fell to .scalar — the whole
	// iterator became a singleton Some, so [$fp:map [$filter …] f] wrapped
	// the collection instead of mapping over it (the kind taint).
	if n is cx.IteratorNode {
		return .sequence
	}
	// Everything else (scalar, text) is a bare scalar → singleton.
	return .scalar
}

// fp_ok_body returns the interior value of an [ok …] element. An [ok]
// with a single body item yields that item; an [ok] with multiple items
// yields a sequence envelope of them; an empty [ok] yields the empty
// sequence.
fn fp_ok_body(n cx.Node) cx.Node {
	if n is cx.Element {
		if n.items.len == 1 {
			return n.items[0]
		}
		return cx.Element{
			name:  seq_marker_name
			items: n.items.clone()
		}
	}
	return n
}

// fp_mk_ok wraps a value into an [ok …] element. A sequence-envelope
// value is spread into the [ok] body so `[ok (1,2,3)]` round-trips.
fn fp_mk_ok(v cx.Node) cx.Node {
	return cx.Element{
		name:  'ok'
		items: [v]
	}
}

// fp_mk_seq wraps items into a sequence envelope (the canonical
// `__cx_seq__` shape the renderer prints as `(…)`).
fn fp_mk_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  seq_marker_name
		items: items
	}
}

// eval_fp_builtin dispatches the fp native primitives. Reached from the
// higher-order built-in path in eval.v (it needs `mut env` to apply the
// supplied callable). Returns `none` for a non-fp name so the caller
// falls through to ordinary dispatch.
fn eval_fp_builtin(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'fp-map' {
			return fp_map(args, mut env) or { err_to_node(err) }
		}
		'fp-flat-map' {
			return fp_flat_map(args, mut env) or { err_to_node(err) }
		}
		'fp-pure' {
			return fp_pure(args) or { err_to_node(err) }
		}
		'fp-fold' {
			return fp_fold(args, mut env) or { err_to_node(err) }
		}
		'fp-sequence' {
			return fp_sequence(args) or { err_to_node(err) }
		}
		'fp-traverse' {
			return fp_traverse(args, mut env) or { err_to_node(err) }
		}
		else {
			return none
		}
	}
}

// err_to_node coerces an EvalError raised inside an fp primitive into a
// renderable [err …] VALUE node (errors-are-values; §4 / code.md §9.1.2).
pub fn err_to_node(e IError) cx.Node {
	if e is EvalError {
		return mk_err(e.code, e.message)
	}
	return mk_err('cx-err:CXER0001', e.msg())
}

// fp_no_instance builds the E_NO_INSTANCE error VALUE node for a value
// whose head tag has no registered instance (§1.2 step 4). Errors are
// values (code.md §9.1.2): the combinator returns this [err …] node so a
// conformance `out-err` assertion sees the bare CXER4400 code.
fn fp_no_instance(n cx.Node) cx.Node {
	mut tag := 'value'
	if n is cx.Element {
		tag = n.name
	}
	return mk_err(fp_err_no_instance, 'fp: no registered instance for head tag "${tag}"')
}

// ── map (functor map) ─────────────────────────────────────────────────
// result:   [ok v] → [ok fn(v)]; [err …] → unchanged (propagation).
// sequence: map fn over items, re-wrap as a sequence envelope.
// scalar:   Some(x) → Some(fn(x)) = (fn(x)).
// element:  no instance → CXER4400.
fn fp_map(args []cx.Node, mut env MatchEnv) !cx.Node {
	if args.len != 2 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[$fp:map] expects (F, fn); got ${args.len} arg(s)'
		}
	}
	x := args[0]
	fn_val := args[1]
	match fp_classify(x) {
		.result_err {
			return x // railway: propagate the err unchanged
		}
		.result_ok {
			inner := fp_ok_body(x)
			return fp_mk_ok(apply_fn_value(fn_val, [inner], mut env)!)
		}
		.sequence {
			items := iterate(x)
			mut out := []cx.Node{cap: items.len}
			for it in items {
				out << apply_fn_value(fn_val, [it], mut env)!
			}
			return fp_mk_seq(out)
		}
		.scalar {
			// singleton Some(x) → Some(fn(x)) = (fn(x))
			return fp_mk_seq([apply_fn_value(fn_val, [x], mut env)!])
		}
		.no_instance {
			return fp_no_instance(x)
		}
	}
}

// ── flat-map (monad bind) ─────────────────────────────────────────────
// result:   [ok v] → fn(v) (which must itself be [ok]/[err]); [err …] →
//           unchanged (the railway short-circuit IS the propagation).
// sequence: map fn (each yields a sequence), concat one level.
// scalar:   Some(x) → fn(x).
// element:  no instance → CXER4400.
fn fp_flat_map(args []cx.Node, mut env MatchEnv) !cx.Node {
	if args.len != 2 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[$fp:flat-map] expects (F, fn); got ${args.len} arg(s)'
		}
	}
	x := args[0]
	fn_val := args[1]
	match fp_classify(x) {
		.result_err {
			return x // railway short-circuit
		}
		.result_ok {
			inner := fp_ok_body(x)
			return apply_fn_value(fn_val, [inner], mut env)!
		}
		.sequence {
			items := iterate(x)
			mut out := []cx.Node{}
			for it in items {
				produced := apply_fn_value(fn_val, [it], mut env)!
				// remove one level of nesting: each fn result is a
				// container; splice its items into the flat result.
				out << iterate(produced)
			}
			return fp_mk_seq(out)
		}
		.scalar {
			return apply_fn_value(fn_val, [x], mut env)!
		}
		.no_instance {
			return fp_no_instance(x)
		}
	}
}

// ── pure (lift) ───────────────────────────────────────────────────────
// Default instance is `sequence`: pure x = (x). A `tag=result` selects
// the result instance: pure x = [ok x]. The tag arrives as the second
// positional (the bundle body forwards `$tag`, defaulting to :sequence).
fn fp_pure(args []cx.Node) !cx.Node {
	if args.len < 1 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[$fp:pure] expects (x [tag]); got ${args.len} arg(s)'
		}
	}
	x := args[0]
	tag := if args.len >= 2 { fp_atom_or_string(args[1]) } else { 'sequence' }
	match tag {
		'result' {
			return fp_mk_ok(x)
		}
		'sequence', '' {
			return fp_mk_seq([x])
		}
		else {
			return EvalError{
				code:    fp_err_no_instance
				message: 'fp: pure has no registered instance "${tag}"'
			}
		}
	}
}

// fp_atom_or_string extracts the lexical form of an atom or string scalar
// (the `tag=` selector). Other node kinds yield the empty string.
fn fp_atom_or_string(n cx.Node) string {
	if n is cx.ScalarNode {
		if n.value is string {
			return n.value as string
		}
	}
	return ''
}

// ── fold (err-boundary reduce) ────────────────────────────────────────
// fold(F, init, fn) reduces the items of F with fn(acc, item). It is an
// err-boundary combinator (§4): an [err]-holding item reaches fn as an
// inspectable value (no auto-propagation across the boundary).
fn fp_fold(args []cx.Node, mut env MatchEnv) !cx.Node {
	if args.len != 3 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[$fp:fold] expects (F, init, fn); got ${args.len} arg(s)'
		}
	}
	x := args[0]
	mut acc := args[1]
	fn_val := args[2]
	if fp_classify(x) == .no_instance {
		return fp_no_instance(x)
	}
	items := iterate(x)
	for it in items {
		acc = apply_fn_value(fn_val, [acc, it], mut env)!
	}
	return acc
}

// ── sequence (err-boundary: turn a structure of containers inside-out) ─
// Over a sequence of `result` containers: if every element is [ok vi]
// the result is [ok (v1, …, vn)]; the FIRST [err] short-circuits and is
// returned unchanged (the deliberate collapse, §4). An empty sequence
// yields [ok ()].
fn fp_sequence(args []cx.Node) !cx.Node {
	if args.len != 1 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[$fp:sequence] expects (F); got ${args.len} arg(s)'
		}
	}
	return fp_sequence_node(args[0])
}

// fp_sequence_node is the inner sequence-swap: it turns the outer structure
// `F (G a)` inside-out to `G (F a)`, where the inner applicative `G` is
// DISPATCHED from the elements (§1.2), not assumed. The two built-in inner
// applicatives are `result` ([ok]/[err]) and `sequence` (Maybe + List). An
// element whose head tag has no registered instance (e.g. [just …], which
// is NOT a built-in — Maybe is the ≤1 sequence, spec §1.1) raises
// E_NO_INSTANCE.
fn fp_sequence_node(x cx.Node) !cx.Node {
	if fp_classify(x) == .no_instance {
		return fp_no_instance(x)
	}
	items := iterate(x)
	// Empty structure: no element to dispatch the inner applicative on.
	// Yield [ok ()] — the documented empty-sequence result (§4).
	if items.len == 0 {
		return fp_mk_ok(fp_mk_seq([]))
	}
	// Dispatch the inner applicative G from the elements. Any [ok]/[err]
	// element selects `result`; a no-instance element errs; otherwise the
	// elements are sequences/scalars → the `sequence` (Maybe + List) instance.
	mut has_result := false
	for it in items {
		match fp_classify(it) {
			.no_instance {
				return fp_no_instance(it)
			}
			.result_ok, .result_err {
				has_result = true
			}
			else {}
		}
	}
	if has_result {
		return fp_sequence_result(items)
	}
	return fp_sequence_list(items)
}

// fp_sequence_result swaps a sequence of `result` containers inside-out:
// every [ok vi] body is collected into [ok (v1, …, vn)]; the FIRST [err]
// short-circuits and is returned unchanged (the deliberate collapse, §4).
fn fp_sequence_result(items []cx.Node) !cx.Node {
	mut collected := []cx.Node{cap: items.len}
	for it in items {
		match fp_classify(it) {
			.result_err {
				return it // first err short-circuits
			}
			.result_ok {
				collected << fp_ok_body(it)
			}
			else {
				// a non-result element mixed under a result sequence: treat a
				// bare value as already-extracted (identity over the inner
				// applicative), preserving the value.
				collected << it
			}
		}
	}
	return fp_mk_ok(fp_mk_seq(collected))
}

// fp_sequence_list swaps a sequence of `sequence` containers inside-out via
// the LIST applicative (the cartesian product). This single instance also
// subsumes Maybe (spec §1.1: Maybe is the ≤1 sequence): an empty element ()
// = None makes the product empty → () (the Maybe short-circuit), and all
// Some(x)=(x) singletons collapse to the single combination ((x1, …, xn)).
fn fp_sequence_list(items []cx.Node) cx.Node {
	// Start with a single empty combination; extend it by each element's
	// options (its iterated items). A scalar element iterates to a singleton
	// (Some(x)); an empty () element zeroes the product (None).
	mut combos := [][]cx.Node{len: 1, init: []cx.Node{}}
	for it in items {
		opts := iterate(it)
		mut next := [][]cx.Node{cap: combos.len * opts.len}
		for combo in combos {
			for opt in opts {
				mut extended := combo.clone()
				extended << opt
				next << extended
			}
		}
		combos = next.clone()
	}
	mut out := []cx.Node{cap: combos.len}
	for combo in combos {
		out << fp_mk_seq(combo)
	}
	return fp_mk_seq(out)
}

// ── traverse (err-boundary: map an effectful fn, swapping layers) ──────
// traverse(F, fn) = sequence(map(F, fn)): apply the container-returning
// fn across the structure, then turn the layers inside-out.
fn fp_traverse(args []cx.Node, mut env MatchEnv) !cx.Node {
	if args.len != 2 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: '[$fp:traverse] expects (F, fn); got ${args.len} arg(s)'
		}
	}
	x := args[0]
	fn_val := args[1]
	if fp_classify(x) == .no_instance {
		return fp_no_instance(x)
	}
	items := iterate(x)
	mut mapped := []cx.Node{cap: items.len}
	for it in items {
		mapped << apply_fn_value(fn_val, [it], mut env)!
	}
	return fp_sequence_node(fp_mk_seq(mapped))
}
