module code

import cx

// predicate_eval.v — standalone PredicateExpr evaluator.
//
// Phase 2.21 (partial). This file ships the eager-iteration
// evaluator described by in a STANDALONE form. The wider
// CXPath axis-walker (which produces the candidate sequence that feeds
// the predicate) is Phase 2.6 and not yet started; until that lands the
// evaluator is exercised via a thin `Item` placeholder type that lets us
// validate the per-candidate binding + EBV-coercion behaviour in
// isolation. The signature and observable behaviour will not change
// when the axis-walker integration arrives — `Item` will be replaced by
// the full Document-AST item kind and the candidate sequence will be
// supplied by the path step rather than by the test caller.
//
// decisions implemented here:
//   - D2 ($_ as reserved context binding, innermost-shadows-outer)
//   - D3 ($_position / $_last 1-based / cardinality bindings)
//   - D4 (eager materialisation; per-candidate body evaluation with EBV)
//   - D5 (:bind NAME visible in every enclosed predicate — supplied via
//         the PredicateEvalContext.bindings map; how the path evaluator populates
//         that map is Phase 2.6 / Phase 2.20's responsibility)
//   - D7 (EBV coercion table, per cxdm §4.6)
//   - D8 (purity — enforced statically at Phase 2.22; evaluator assumes
//         pure bodies and does not branch on side-effects)
//
// Out of scope at Phase 2.21-standalone (deferred):
//   - Phase 2.6 — CXPath axis walker (will supply `candidates` for real)
//   - Phase 2.22 — static purity checker (CXER0230 family)
//   - Generic / non-atomic-template PredicateExpr bodies — returns a
//     well-shaped MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED error so the
//     caller can fall back to source-only evaluation.
//
// Cross-references:
//   - spec/cxdm.md §4.6 (EBV rule)
//   - vcx/cx/predicate_expr.v (the AST datum + atomic-template kinds)

// ── Item placeholder ─────────────────────────────────────────────────────────
//
// `Item` is the Phase 2.21-standalone stand-in for a CXDM
// item. It carries just enough shape for the evaluator to honour the
// atomic-template predicates (attribute existence/compare,
// positional, count, $_-family). Once the CXPath axis walker lands at
// Phase 2.6, this struct is superseded by the full Document-AST item.
//
// `@[heap]` is required because BindingScope holds an `&Item` reference
// to the candidate item, and V's escape analysis flags assignment of a
// stack-allocated `&Item` outside an `unsafe` block otherwise.
@[heap]
pub struct Item {
pub mut:
	kind           string                  // "element", "atom", "scalar", … (informational)
	name           ?string                 // element/atom local name
	value          ?string                 // scalar payload for scalar/string/bool/int items
	attrs          map[string]string       // attribute map for element-kind items
	children_count int                     // arity (used by count(*) style predicates later)
}

// ── Value (internal, evaluator-side) ─────────────────────────────────────────
//
// `Value` is the evaluator's internal result kind. It deliberately
// stays small and string-typed — the standalone Phase 2.21 evaluator
// only ever produces values from atomic-template predicate bodies,
// which means it sees `bool`, `int`, `string`, `null`, an `Item`
// (when `$_` or a `:bind`-captured name is referenced as a whole),
// or a sequence of those. Full Value parity with cxdm §4 lives on the
// CXPath evaluator (Phase 2.6) and code/eval.v.
pub enum ValueKind {
	bool_v
	int_v
	string_v
	null_v
	item_v
	sequence_v
}

pub struct Value {
pub mut:
	kind    ValueKind
	bool_   bool
	int_    int
	string_ string
	item_   ?&Item
	seq_    []Value
}

pub fn value_bool(b bool) Value {
	return Value{ kind: .bool_v, bool_: b }
}

pub fn value_int(n int) Value {
	return Value{ kind: .int_v, int_: n }
}

pub fn value_string(s string) Value {
	return Value{ kind: .string_v, string_: s }
}

pub fn value_null() Value {
	return Value{ kind: .null_v }
}

pub fn value_item(it &Item) Value {
	return Value{ kind: .item_v, item_: it }
}

pub fn value_seq(vs []Value) Value {
	return Value{ kind: .sequence_v, seq_: vs }
}

// ── BindingScope ─────────────────────────────────────────────────────────────
//
// BindingScope carries the names visible inside a PredicateExpr body
// during evaluation. Three population paths:
//
//   - `$_`         — set by `eval_predicate_filter` to the current candidate.
//   - `$_position` — set by `eval_predicate_filter` to the 1-based index.
//   - `$_last`     — set by `eval_predicate_filter` to the candidate count.
//   - user `:bind` — sourced from the caller-supplied `PredicateEvalContext.bindings`
//                    (Phase 2.6 / Phase 2.20 wire this up; Phase 2.21
//                    accepts it pre-populated).
//
// Innermost-shadows-outer (D2): when nested predicate evaluation lands
// (post-Phase 2.21), each nested predicate gets a fresh BindingScope
// derived by copying the outer map and overwriting `$_` / `$_position`
// / `$_last`. At Phase 2.21 only the outermost frame is built.
pub struct BindingScope {
pub:
	context_item ?&Item // value of `$_` at this scope level (set once at construction,
	// read-only after — immutable so it can hold an immutable `&Item` borrow; the
	// newer V checker rejects storing an immutable ref into a `mut` ref field)
pub mut:
	position int                       // value of `$_position` (1-based)
	last     int                       // value of `$_last` (sequence length)
	bindings map[string]Value          // every named binding visible in the body
}

// ── PredicateEvalContext ──────────────────────────────────────────────────────────────
//
// PredicateEvalContext is the standalone-evaluator caller's surface for handing
// in `:bind NAME` captures collected at path-walker time (Phase 2.6 /
// Phase 2.20). At Phase 2.21-standalone, tests populate this directly.
//
// Keys MUST NOT begin with `$_` — the `$_` family is reserved
// D2/D3) and is set by `eval_predicate_filter`. Supplying a `$_*` key
// here is a programmer error and is rejected at scope-build time.
pub struct PredicateEvalContext {
pub mut:
	bindings map[string]Value
}

// ── EBV ──────────────────────────────────────────────────────────────────────
//
// ebv coerces a Value to bool per cxdm §4.6. The
// table covered at Phase 2.21-standalone:
//
//   | kind            | EBV |
//   |-----------------|-----|
//   | bool            | the value itself |
//   | int             | non-zero |
//   | string          | non-empty |
//   | null            | false |
//   | item (element)  | true (present node) |
//   | empty sequence  | false |
//   | sequence len=1  | EBV applied recursively to the wrapped value |
//   | sequence len>1  | true |
//
// Deferred to later phases (no simple V representation yet on the
// standalone Item type): float (NaN), date, datetime, bytes, atom,
// array, map, path. When the CXPath evaluator lands at Phase 2.6
// these rows are filled in against the real Value sum.
pub fn ebv(v Value) !bool {
	return match v.kind {
		.bool_v {
			v.bool_
		}
		.int_v {
			v.int_ != 0
		}
		.string_v {
			v.string_.len > 0
		}
		.null_v {
			false
		}
		.item_v {
			// A present node is truthy (cxdm §4.6 rule 3).
			v.item_ != none
		}
		.sequence_v {
			if v.seq_.len == 0 {
				false
			} else if v.seq_.len == 1 {
				ebv(v.seq_[0])!
			} else {
				true
			}
		}
	}
}

// ── Scope construction ───────────────────────────────────────────────────────

// build_scope assembles a BindingScope for the i-th candidate (0-based
// `index`, `len` candidates total). User `:bind` captures from
// `context.bindings` are copied in; the reserved `$_` / `$_position`
// `$_last` slots are set from the iteration state. Per 
// the `_` identifier is reserved — any user binding whose name begins
// with `$_` is rejected here as a programmer error.
fn build_scope(item &Item, index int, len int, context PredicateEvalContext) !BindingScope {
	mut scope := BindingScope{
		context_item: item
		position:     index + 1 // 1-based
		last:         len
		bindings:     map[string]Value{}
	}
	for name, value in context.bindings {
		// Per gate 36.7 + D2: the bare identifier `_` is
		// reserved for the implicit `$_` context-item binding; user
		// `:bind` captures MUST use any other NCName. Names that
		// literally begin with `$` are also rejected — the caller
		// supplies the NCName, not the `$NAME` sigil-prefixed surface.
		if name == '_' || name.starts_with('\$') {
			return error('PREDICATE_EVAL: binding name `${name}` collides with reserved `\$_` family')
		}
		scope.bindings[name] = value
	}
	return scope
}

// ── Public entry point ───────────────────────────────────────────────────────

// eval_predicate_filter applies `predicate` to `candidates` with
// eager-iteration semantics. The candidate sequence is
// already materialised on entry (V slices are values); we walk it
// linearly, bind `$_` / `$_position` / `$_last` on every step, evaluate
// the predicate body, coerce the result via EBV, and keep the
// candidate iff EBV(result) = true.
//
// Returns the filtered candidate slice — never larger than the input,
// element order preserved. On a predicate body that exceeds the
// Phase 2.21-standalone atomic-template coverage the function returns
// a `MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED` error so the caller can
// either fall back to source-only evaluation or surface the gap.
//
// Purity is the caller's invariant — the static checker
// at Phase 2.22 catches impure bodies before they reach this function.
pub fn eval_predicate_filter(candidates []Item, predicate &cx.PredicateExpr, context PredicateEvalContext) ![]Item {
	// Static purity (§6.5.x): a path predicate that calls a known-impure
	// builtin / stdlib primitive (e.g. `now()`, `uuid()`) is rejected with
	// CXER0230 — a predicate body MUST be pure. Unclassified callees default
	// to pure. The error is message-prefixed with the wire code.
	empty_defs := []&cx.DefNode{}
	chk := new_purity_checker(empty_defs)
	chk.check_predicate(predicate) or {
		return error(err.msg())
	}
	// Eager materialisation — `candidates` is already
	// a V slice (which is by-value). We re-allocate the filtered
	// result rather than mutating in place to keep the function
	// pure-functional.
	mut out := []Item{cap: candidates.len}
	for i, cand in candidates {
		scope := build_scope(&cand, i, candidates.len, context)!
		result := eval_predicate_body(predicate, scope)!
		if ebv(result)! {
			out << cand
		}
	}
	return out
}

// ── Body interpreter ─────────────────────────────────────────────────────────

// eval_predicate_body interprets a PredicateExpr against a fully-built
// scope. Phase 2.21-standalone handles the atomic templates
// (attr_test, attr_compare, int_position, function_call, reserved_binding);
// anything else (bool_expr / instance_of / cast_as / sequence_op /
// generic) returns a MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED error.
pub fn eval_predicate_body(predicate &cx.PredicateExpr, scope BindingScope) !Value {
	return match predicate.kind {
		.attr_test, .atom_test {
			eval_attr_test(predicate, scope)!
		}
		.attr_compare {
			eval_attr_compare(predicate, scope)!
		}
		.int_position {
			eval_int_position(predicate, scope)!
		}
		.reserved_binding {
			eval_reserved_binding(predicate, scope)!
		}
		.function_call {
			eval_function_call(predicate, scope)!
		}
		.bool_expr, .instance_of, .cast_as, .sequence_op, .generic {
			error('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED: kind=${cx.predicate_expr_kind_name(predicate.kind)} (Phase 2.21 covers atomic templates only)')
		}
	}
}

// eval_attr_test handles `[@name]` — desugars to `[exists($_@name)]`.
// Returns a bool: true iff the context item exposes an attribute by
// that name (present-by-key, regardless of value).
fn eval_attr_test(p &cx.PredicateExpr, scope BindingScope) !Value {
	name := p.name or {
		return error('PREDICATE_EVAL: attr_test missing name field')
	}
	item := scope.context_item or {
		return error('PREDICATE_EVAL: attr_test has no `\$_` in scope')
	}
	return value_bool(name in item.attrs)
}

// eval_attr_compare handles `[@name OP value]` for OP ∈ { =, !=, <, <=, >, >= }.
// Comparison semantics:
//   - If the attribute is absent → result is false (per attr-test convention).
//   - If both sides parse as ints → integer comparison.
//   - Otherwise → string comparison.
//
// The RHS is captured verbatim by the parser including any surrounding
// quotes; we strip a single matching pair of "'" or '"' before
// comparing as a string.
fn eval_attr_compare(p &cx.PredicateExpr, scope BindingScope) !Value {
	name := p.name or {
		return error('PREDICATE_EVAL: attr_compare missing name field')
	}
	op := p.op or {
		return error('PREDICATE_EVAL: attr_compare missing op field')
	}
	rhs_raw := p.value or {
		return error('PREDICATE_EVAL: attr_compare missing value field')
	}
	item := scope.context_item or {
		return error('PREDICATE_EVAL: attr_compare has no `\$_` in scope')
	}
	if name !in item.attrs {
		return value_bool(false)
	}
	lhs := item.attrs[name]
	rhs := strip_quotes(rhs_raw)
	return value_bool(compare_strings(lhs, rhs, op)!)
}

// strip_quotes removes a single matching pair of leading+trailing `"`
// or `'` quotes from a verbatim RHS slice; otherwise returns the input.
fn strip_quotes(s string) string {
	if s.len >= 2 {
		first := s[0]
		last := s[s.len - 1]
		if (first == `"` && last == `"`) || (first == `\'` && last == `\'`) {
			return s[1..s.len - 1]
		}
	}
	return s
}

// compare_strings performs the comparison for attr_compare and the
// $_-binding compare cases. If both sides look like ints, the
// comparison is integer; otherwise string-lexicographic. This matches
// what the cxdm value-comparison surface does for the limited type set
// the standalone evaluator sees.
fn compare_strings(lhs string, rhs string, op string) !bool {
	if is_int_literal(lhs) && is_int_literal(rhs) {
		li := lhs.int()
		ri := rhs.int()
		return match op {
			'='  { li == ri }
			'!=' { li != ri }
			'<'  { li <  ri }
			'<=' { li <= ri }
			'>'  { li >  ri }
			'>=' { li >= ri }
			else { error('PREDICATE_EVAL: unknown op `${op}`') }
		}
	}
	return match op {
		'='  { lhs == rhs }
		'!=' { lhs != rhs }
		'<'  { lhs <  rhs }
		'<=' { lhs <= rhs }
		'>'  { lhs >  rhs }
		'>=' { lhs >= rhs }
		else { error('PREDICATE_EVAL: unknown op `${op}`') }
	}
}

fn is_int_literal(s string) bool {
	if s.len == 0 {
		return false
	}
	mut start := 0
	if s[0] == `-` || s[0] == `+` {
		if s.len == 1 {
			return false
		}
		start = 1
	}
	for i in start .. s.len {
		c := s[i]
		if c < `0` || c > `9` {
			return false
		}
	}
	return true
}

// eval_int_position handles `[N]` → `$_position = N`.
// The parser guarantees `position` is some(int) for this kind.
fn eval_int_position(p &cx.PredicateExpr, scope BindingScope) !Value {
	n := p.position or {
		return error('PREDICATE_EVAL: int_position missing position field')
	}
	return value_bool(scope.position == n)
}

// eval_reserved_binding handles a bare `$NAME` body. The three
// reserved cases (`$_`, `$_position`, `$_last`) are looked
// up from the scope's special slots; any other `$NAME` is resolved
// against `scope.bindings` (populated from the caller-supplied
// PredicateEvalContext at `eval_predicate_filter` entry — Phase 2.6 / Phase 2.20
// will wire this up against `:bind NAME` captures from prior path
// steps). Returning the bound Value lets the EBV
// coercion in `eval_predicate_filter` decide truthiness.
fn eval_reserved_binding(p &cx.PredicateExpr, scope BindingScope) !Value {
	name := p.name or {
		return error('PREDICATE_EVAL: reserved_binding missing name field')
	}
	match name {
		'\$_position' {
			return value_int(scope.position)
		}
		'\$_last' {
			return value_int(scope.last)
		}
		'\$_' {
			item := scope.context_item or {
				return error('PREDICATE_EVAL: `\$_` referenced with no context item in scope')
			}
			return value_item(item)
		}
		else {
			// User-named binding — strip the `$` sigil and look up in
			// the scope's bindings map (which carries the PredicateEvalContext
			// captures). An unbound name is a runtime error rather than
			// a silent false because scope rule treats
			// bind references as static (the parser / static checker
			// at Phase 2.22 will catch out-of-scope references; the
			// evaluator only sees well-formed bodies).
			if !name.starts_with('\$') {
				return error('PREDICATE_EVAL: reserved_binding name `${name}` is not a `\$`-sigil identifier')
			}
			bare := name[1..]
			if bare in scope.bindings {
				return scope.bindings[bare] or {
					return error('PREDICATE_EVAL: binding `${name}` lookup failed unexpectedly')
				}
			}
			return error('PREDICATE_EVAL: binding `${name}` not in scope')
		}
	}
}

// eval_function_call handles `[count(*)]` and `[count(*) OP N]` —
// the only function-call form recognised by the Phase 2.19 parser.
// `count(*)` resolves to the context item's children_count. The
// comparison shape mirrors attr_compare's integer fast-path.
fn eval_function_call(p &cx.PredicateExpr, scope BindingScope) !Value {
	fn_name := p.name or {
		return error('PREDICATE_EVAL: function_call missing name field')
	}
	if fn_name != 'count' {
		return error('MATCH_PREDICATE_EVAL_NOT_YET_IMPLEMENTED: function `${fn_name}` (Phase 2.21 supports only `count`)')
	}
	item := scope.context_item or {
		return error('PREDICATE_EVAL: function_call has no `\$_` in scope')
	}
	cnt := item.children_count
	op := p.op or {
		// Bare `count(*)` body — the int return value will EBV-coerce
		// to true iff non-zero, matching cxdm §4.6 rule 2.
		return value_int(cnt)
	}
	rhs := p.position or {
		return error('PREDICATE_EVAL: function_call ${fn_name}(*) ${op} expected an int RHS')
	}
	return value_bool(match op {
		'='  { cnt == rhs }
		'!=' { cnt != rhs }
		'<'  { cnt <  rhs }
		'<=' { cnt <= rhs }
		'>'  { cnt >  rhs }
		'>=' { cnt >= rhs }
		else { return error('PREDICATE_EVAL: unknown op `${op}` on function_call') }
	})
}
