module cx

import strconv

// ── CXPath AST ────────────────────────────────────────────────────────────────

struct CXPathExpr {
mut:
	steps []CXStep
	// ns_map: prefix → URI bindings used to resolve prefixed name tests
	// and prefixed attribute predicates. Populated at evaluation entry
	// from the document's xmlns declarations (first occurrence wins) +
	// reserved `xml:` / `cx:`. Empty when the query runs over a
	// namespace-free document — name tests then fall back to verbatim
	// source-name match. See spec/cxpath.md §Namespace-aware queries.
	ns_map map[string]string
	// ADR 0017 §D13 — union operator `path1 | path2` and sequence
	// literal `(p1, p2, ...)` (sugar for union). The first alternative's
	// steps populate `steps`; additional alternatives' step lists live
	// here. Empty `alt_steps` means a non-union expression. Evaluation
	// concatenates results from each alternative, preserving document
	// order and de-duplicating by structural Element equality.
	alt_steps [][]CXStep
	// ADR 0017 §D13 — tail map-key access: `.key` and `['key']` postfix
	// after the last step. Chains apply left-to-right (`m.a.b` ⇒
	// ['a', 'b']). v0.6.0 semantics: for each matched Element, scan
	// its body for a MapNode whose entry with this key has an Element
	// value; that becomes the new result. Non-Element map values yield
	// the empty Sequence in element-returning APIs (full value
	// semantics land with the CXL evaluator, §F).
	tail_map_keys []string
}

struct CXStep {
	axis  CXAxis
	name  string
	preds []CXPred
}

enum CXAxis {
	child
	descendant
}

type CXPred = CXPredAttrExists
	| CXPredAttrCmp
	| CXPredChildExists
	| CXPredNot
	| CXPredBoolAnd
	| CXPredBoolOr
	| CXPredPosition
	| CXPredFuncContains
	| CXPredFuncStartsWith
	| CXPredLocalNameCmp
	| CXPredNamespaceURICmp
	| CXPredIdMatch

struct CXPredAttrExists {
	attr string
}

struct CXPredAttrCmp {
	attr string
	op   string
	val  ScalarValue
}

struct CXPredChildExists {
	name string
}

struct CXPredNot {
	inner CXPred
}

struct CXPredBoolAnd {
	left  CXPred
	right CXPred
}

struct CXPredBoolOr {
	left  CXPred
	right CXPred
}

struct CXPredPosition {
	pos     int
	is_last bool
}

struct CXPredFuncContains {
	attr string
	val  string
}

struct CXPredFuncStartsWith {
	attr string
	val  string
}

// CXPredLocalNameCmp compares the element's local-name (post-colon
// part of the source name, or the whole name if no colon) against a
// string literal. Supports `=` and `!=` only — local names are always
// strings. Spelled `local-name()=...` in the source CXPath.
struct CXPredLocalNameCmp {
	op  string
	val string
}

// CXPredNamespaceURICmp compares the element's ns_uri against a string
// literal. The empty string matches an element whose `ns_uri` is none
// (i.e., no namespace). Supports `=` and `!=`. Spelled
// `namespace-uri()=...` in the source CXPath.
struct CXPredNamespaceURICmp {
	op  string
	val string
}

// CXPredIdMatch matches an element whose syntactic ID (Element.id,
// declared as `#name` per ADR 0003) equals the given string. Spelled
// `[#id-name]` in the source CXPath. The bare `#name` form (no `=`,
// no quotes) distinguishes ID matching from attribute-equality and
// from child-existence tests.
struct CXPredIdMatch {
	id string
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

struct CXPathLexer {
	src string
mut:
	pos int
}

fn (mut l CXPathLexer) skip_ws() {
	for l.pos < l.src.len && l.src[l.pos] == ` ` {
		l.pos++
	}
}

fn (mut l CXPathLexer) peek_str(s string) bool {
	return l.src[l.pos..].starts_with(s)
}

fn (mut l CXPathLexer) eat_str(s string) bool {
	if l.peek_str(s) {
		l.pos += s.len
		return true
	}
	return false
}

fn (mut l CXPathLexer) eat_char(c u8) bool {
	if l.pos < l.src.len && l.src[l.pos] == c {
		l.pos++
		return true
	}
	return false
}

fn (mut l CXPathLexer) read_ident() string {
	start := l.pos
	for l.pos < l.src.len {
		b := l.src[l.pos]
		if (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || (b >= `0` && b <= `9`) || b == `_` || b == `-` || b == `.` || b == `:` {
			l.pos++
		} else {
			break
		}
	}
	return l.src[start..l.pos]
}

// read_step_name reads a CXPath element-name token. Identical to
// read_ident except that `.` is NOT included — at the step-name
// position, `.` is reserved for ADR 0017 §D13 map-key access
// (`step.key`). Namespace separator `:` is still consumed so prefixed
// names like `cx:lang` parse correctly. Attribute and function names
// continue to use read_ident, which preserves dotted spellings where
// they make sense (`@version.major`).
fn (mut l CXPathLexer) read_step_name() string {
	start := l.pos
	for l.pos < l.src.len {
		b := l.src[l.pos]
		if (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || (b >= `0` && b <= `9`) || b == `_` || b == `-` || b == `:` {
			l.pos++
		} else {
			break
		}
	}
	return l.src[start..l.pos]
}

fn (mut l CXPathLexer) read_quoted() !string {
	if !l.eat_char(`'`) {
		return error("CXPath parse error: expected ' at pos ${l.pos}  expr: ${l.src}")
	}
	start := l.pos
	for l.pos < l.src.len && l.src[l.pos] != `'` {
		l.pos++
	}
	s := l.src[start..l.pos]
	if !l.eat_char(`'`) {
		return error("CXPath parse error: unterminated string at pos ${l.pos}  expr: ${l.src}")
	}
	return s
}

// ── Parser ────────────────────────────────────────────────────────────────────

fn cxpath_parse(expr string) !CXPathExpr {
	mut l := CXPathLexer{ src: expr }
	l.skip_ws()
	// ADR 0017 §D13 — sequence-literal `(p1, p2, ...)` at the
	// top level is sugar for `p1 | p2 | ...`. Only recognised at
	// expression start; parens at step-positions are reserved
	// (e.g., inside predicate boolean grouping) and never appear
	// where this branch fires.
	mut alt_step_lists := [][]CXStep{}
	mut tail_keys := []string{}
	if l.peek_str('(') {
		l.eat_char(`(`)
		l.skip_ws()
		first := cxpath_parse_steps(mut l)!
		alt_step_lists << first
		for {
			l.skip_ws()
			if !l.eat_char(`,`) {
				break
			}
			l.skip_ws()
			more := cxpath_parse_steps(mut l)!
			alt_step_lists << more
		}
		l.skip_ws()
		if !l.eat_char(`)`) {
			return error('CXPath parse error: expected ) at pos ${l.pos}  expr: ${expr}')
		}
	} else {
		first := cxpath_parse_steps(mut l)!
		alt_step_lists << first
		for {
			l.skip_ws()
			if !l.eat_char(`|`) {
				break
			}
			l.skip_ws()
			more := cxpath_parse_steps(mut l)!
			alt_step_lists << more
		}
	}
	// Tail postfix: `.key` / `['key']` chained per ADR §D13.
	for {
		l.skip_ws()
		if l.eat_char(`.`) {
			// Use read_step_name so chained `.a.b.c` splits at each
			// dot (read_ident would consume the entire dotted run as
			// one identifier).
			key := l.read_step_name()
			if key.len == 0 {
				return error('CXPath parse error: expected map key after . at pos ${l.pos}  expr: ${expr}')
			}
			tail_keys << key
			continue
		}
		// `['key']` form: bracket followed immediately by single-quote.
		if l.pos + 1 < l.src.len && l.src[l.pos] == `[` && l.src[l.pos + 1] == `'` {
			l.eat_char(`[`)
			key := l.read_quoted()!
			l.skip_ws()
			if !l.eat_char(`]`) {
				return error("CXPath parse error: expected ] after map key at pos ${l.pos}  expr: ${expr}")
			}
			tail_keys << key
			continue
		}
		break
	}
	if l.pos != l.src.len {
		return error('CXPath parse error: unexpected characters at pos ${l.pos}  expr: ${expr}')
	}
	if alt_step_lists.len == 0 || alt_step_lists[0].len == 0 {
		return error('CXPath parse error: empty expression  expr: ${expr}')
	}
	mut alts := [][]CXStep{}
	if alt_step_lists.len > 1 {
		alts = alt_step_lists[1..].clone()
	}
	return CXPathExpr{
		steps:         alt_step_lists[0]
		alt_steps:     alts
		tail_map_keys: tail_keys
	}
}

fn cxpath_parse_steps(mut l CXPathLexer) ![]CXStep {
	mut steps := []CXStep{}
	mut axis := CXAxis.child
	if l.peek_str('//') {
		l.pos += 2
		axis = .descendant
	} else if l.peek_str('/') {
		l.pos++
		axis = .child
	}
	step := cxpath_parse_one_step(mut l, axis)!
	steps << step
	for {
		l.skip_ws()
		if l.peek_str('//') {
			l.pos += 2
			steps << cxpath_parse_one_step(mut l, .descendant)!
		} else if l.peek_str('/') {
			l.pos++
			steps << cxpath_parse_one_step(mut l, .child)!
		} else {
			break
		}
	}
	return steps
}

fn cxpath_parse_one_step(mut l CXPathLexer, axis CXAxis) !CXStep {
	l.skip_ws()
	mut name := ''
	if l.eat_char(`*`) {
		name = ''
	} else {
		name = l.read_step_name()
		if name.len == 0 {
			return error('CXPath parse error: expected element name at pos ${l.pos}  expr: ${l.src}')
		}
	}
	mut preds := []CXPred{}
	for {
		l.skip_ws()
		if l.peek_str('[') {
			// ADR 0017 §D13 — `['key']` (bracket immediately followed
			// by single-quote) is map-key access at the path tail, not
			// a predicate. Bail out so the top-level parser can pick it
			// up. Today's predicate forms never lead with a quote, so
			// this lookahead is conflict-free.
			if l.pos + 1 < l.src.len && l.src[l.pos + 1] == `'` {
				break
			}
			preds << cxpath_parse_pred_bracket(mut l)!
		} else {
			break
		}
	}
	return CXStep{ axis: axis, name: name, preds: preds }
}

fn cxpath_parse_pred_bracket(mut l CXPathLexer) !CXPred {
	if !l.eat_char(`[`) {
		return error('CXPath parse error: expected [ at pos ${l.pos}  expr: ${l.src}')
	}
	l.skip_ws()
	pred := cxpath_parse_pred_expr(mut l)!
	l.skip_ws()
	if !l.eat_char(`]`) {
		return error('CXPath parse error: expected ] at pos ${l.pos}  expr: ${l.src}')
	}
	return pred
}

fn cxpath_parse_pred_expr(mut l CXPathLexer) !CXPred {
	left := cxpath_parse_pred_term(mut l)!
	l.skip_ws()
	if l.peek_str('or ') || l.peek_str('or]') || l.peek_str('or)') {
		saved := l.pos
		word := l.read_ident()
		if word == 'or' {
			l.skip_ws()
			right := cxpath_parse_pred_term(mut l)!
			return CXPred(CXPredBoolOr{ left: left, right: right })
		}
		l.pos = saved
	}
	return left
}

fn cxpath_parse_pred_term(mut l CXPathLexer) !CXPred {
	left := cxpath_parse_pred_factor(mut l)!
	l.skip_ws()
	if l.peek_str('and ') || l.peek_str('and]') || l.peek_str('and)') {
		saved := l.pos
		word := l.read_ident()
		if word == 'and' {
			l.skip_ws()
			right := cxpath_parse_pred_factor(mut l)!
			return CXPred(CXPredBoolAnd{ left: left, right: right })
		}
		l.pos = saved
	}
	return left
}

fn cxpath_parse_pred_factor(mut l CXPathLexer) !CXPred {
	l.skip_ws()
	if l.peek_str('not(') || l.peek_str('not (') {
		l.read_ident()
		l.skip_ws()
		if !l.eat_char(`(`) {
			return error('CXPath parse error: expected ( after not  expr: ${l.src}')
		}
		l.skip_ws()
		inner := cxpath_parse_pred_expr(mut l)!
		l.skip_ws()
		if !l.eat_char(`)`) {
			return error('CXPath parse error: expected ) after not(...)  expr: ${l.src}')
		}
		return CXPred(CXPredNot{ inner: inner })
	}
	if l.peek_str('contains(') {
		l.read_ident()
		l.skip_ws()
		if !l.eat_char(`(`) {
			return error('CXPath parse error: expected ( after contains  expr: ${l.src}')
		}
		l.skip_ws()
		if !l.eat_char(`@`) {
			return error('CXPath parse error: expected @attr in contains()  expr: ${l.src}')
		}
		attr := l.read_ident()
		l.skip_ws()
		if !l.eat_char(`,`) {
			return error('CXPath parse error: expected , in contains()  expr: ${l.src}')
		}
		l.skip_ws()
		val := cxpath_parse_scalar_str(mut l)!
		l.skip_ws()
		if !l.eat_char(`)`) {
			return error('CXPath parse error: expected ) after contains(...)  expr: ${l.src}')
		}
		return CXPred(CXPredFuncContains{ attr: attr, val: val })
	}
	if l.peek_str('starts-with(') {
		for l.pos < l.src.len && l.src[l.pos] != `(` {
			l.pos++
		}
		l.skip_ws()
		if !l.eat_char(`(`) {
			return error('CXPath parse error: expected ( after starts-with  expr: ${l.src}')
		}
		l.skip_ws()
		if !l.eat_char(`@`) {
			return error('CXPath parse error: expected @attr in starts-with()  expr: ${l.src}')
		}
		attr := l.read_ident()
		l.skip_ws()
		if !l.eat_char(`,`) {
			return error('CXPath parse error: expected , in starts-with()  expr: ${l.src}')
		}
		l.skip_ws()
		val := cxpath_parse_scalar_str(mut l)!
		l.skip_ws()
		if !l.eat_char(`)`) {
			return error('CXPath parse error: expected ) after starts-with(...)  expr: ${l.src}')
		}
		return CXPred(CXPredFuncStartsWith{ attr: attr, val: val })
	}
	if l.peek_str('last()') {
		l.pos += 6
		return CXPred(CXPredPosition{ is_last: true })
	}
	if l.peek_str('local-name()') || l.peek_str('namespace-uri()') {
		fn_name := l.read_ident()
		if !l.eat_char(`(`) {
			return error('CXPath parse error: expected ( after ${fn_name}  expr: ${l.src}')
		}
		l.skip_ws()
		if !l.eat_char(`)`) {
			return error('CXPath parse error: expected ) after ${fn_name}(  expr: ${l.src}')
		}
		l.skip_ws()
		op := cxpath_parse_op(mut l)
		if op != '=' && op != '!=' {
			return error('CXPath parse error: ${fn_name}() supports only = and != at pos ${l.pos}  expr: ${l.src}')
		}
		l.skip_ws()
		val := cxpath_parse_scalar_str(mut l)!
		if fn_name == 'local-name' {
			return CXPred(CXPredLocalNameCmp{ op: op, val: val })
		}
		return CXPred(CXPredNamespaceURICmp{ op: op, val: val })
	}
	if l.peek_str('(') {
		l.eat_char(`(`)
		l.skip_ws()
		inner := cxpath_parse_pred_expr(mut l)!
		l.skip_ws()
		if !l.eat_char(`)`) {
			return error('CXPath parse error: expected ) at pos ${l.pos}  expr: ${l.src}')
		}
		return inner
	}
	if l.peek_str('@') {
		l.eat_char(`@`)
		attr := l.read_ident()
		l.skip_ws()
		op := cxpath_parse_op(mut l)
		if op.len == 0 {
			return CXPred(CXPredAttrExists{ attr: attr })
		}
		l.skip_ws()
		val := cxpath_parse_scalar_val(mut l)!
		return CXPred(CXPredAttrCmp{ attr: attr, op: op, val: val })
	}
	// ADR 0003 D8: `[#id-name]` matches an element whose syntactic
	// ID equals 'id-name'. Distinct from `[name]` child-existence
	// (no leading `#`) and from `[@id=...]` attribute-equality.
	if l.peek_str('#') {
		l.eat_char(`#`)
		id := l.read_ident()
		if id.len == 0 {
			return error('CXPath parse error: expected ID name after # at pos ${l.pos}  expr: ${l.src}')
		}
		return CXPred(CXPredIdMatch{ id: id })
	}
	if l.pos < l.src.len && l.src[l.pos] >= `0` && l.src[l.pos] <= `9` {
		start := l.pos
		for l.pos < l.src.len && l.src[l.pos] >= `0` && l.src[l.pos] <= `9` {
			l.pos++
		}
		n := l.src[start..l.pos].int()
		return CXPred(CXPredPosition{ pos: n })
	}
	name := l.read_ident()
	if name.len > 0 {
		return CXPred(CXPredChildExists{ name: name })
	}
	return error('CXPath parse error: unexpected character at pos ${l.pos}  expr: ${l.src}')
}

fn cxpath_parse_op(mut l CXPathLexer) string {
	if l.eat_str('!=') { return '!=' }
	if l.eat_str('>=') { return '>=' }
	if l.eat_str('<=') { return '<=' }
	if l.eat_char(`=`) { return '=' }
	if l.eat_char(`>`) { return '>' }
	if l.eat_char(`<`) { return '<' }
	return ''
}

fn cxpath_parse_scalar_val(mut l CXPathLexer) !ScalarValue {
	if l.peek_str("'") {
		return ScalarValue(l.read_quoted()!)
	}
	s := l.read_ident()
	if s.len == 0 {
		return error('CXPath parse error: expected value at pos ${l.pos}  expr: ${l.src}')
	}
	return cxpath_autotype(s)
}

fn cxpath_parse_scalar_str(mut l CXPathLexer) !string {
	if l.peek_str("'") {
		return l.read_quoted()!
	}
	return l.read_ident()
}

fn cxpath_autotype(s string) ScalarValue {
	if s == 'true'  { return ScalarValue(true) }
	if s == 'false' { return ScalarValue(false) }
	if s == 'null'  { return ScalarValue(NullValue{}) }
	if !s.contains('.') && !s.contains('e') && !s.contains('E') {
		if n := s.parse_int(10, 64) {
			return ScalarValue(i64(n))
		}
	}
	if s.contains('.') || s.contains('e') || s.contains('E') {
		if f := strconv.atof64(s) {
			return ScalarValue(f)
		}
	}
	return ScalarValue(s)
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

pub fn (d Document) select_all(expr string) []Element {
	mut cx_expr := cxpath_parse(expr) or { panic(err.msg()) }
	cx_expr.ns_map = collect_doc_ns_map(d)
	virtual_root := Element{ name: '#document', items: d.elements }
	return cxpath_evaluate_expr(virtual_root, cx_expr)
}

pub fn (d Document) select(expr string) ?Element {
	results := d.select_all(expr)
	return if results.len > 0 { results[0] } else { none }
}

pub fn (e Element) select_all(expr string) []Element {
	mut cx_expr := cxpath_parse(expr) or { panic(err.msg()) }
	cx_expr.ns_map = collect_elem_ns_map(e)
	return cxpath_evaluate_expr(e, cx_expr)
}

// cxpath_evaluate_expr drives the v1.1 evaluation: each union
// alternative's step list is walked from `ctx`, results are
// concatenated in source order (left alt first), structurally
// de-duplicated per ADR 0017 §D13 + CXDM §4 Element-equality, then
// the tail `.key` / `['key']` postfix chain (if any) projects each
// match through MapNode entries with matching keys whose values are
// themselves Elements.
fn cxpath_evaluate_expr(ctx Element, expr CXPathExpr) []Element {
	mut combined := []Element{}
	cxpath_collect_for_path(ctx, expr.steps, expr.ns_map, mut combined)
	for alt in expr.alt_steps {
		cxpath_collect_for_path(ctx, alt, expr.ns_map, mut combined)
	}
	mut deduped := if expr.alt_steps.len > 0 {
		cxpath_dedup_elements(combined)
	} else {
		combined
	}
	for key in expr.tail_map_keys {
		mut next := []Element{}
		for el in deduped {
			cxpath_project_map_key(el, key, mut next)
		}
		deduped = next.clone()
	}
	return deduped
}

// cxpath_collect_for_path runs a single union alternative's step list
// against `ctx`, accumulating matching Elements into `out`. Bridges
// to the existing `cxpath_collect_step` walker by constructing a
// transient CXPathExpr whose `steps` is the alternative.
fn cxpath_collect_for_path(ctx Element, steps []CXStep, ns_map map[string]string,
		mut out []Element) {
	if steps.len == 0 {
		return
	}
	transient := CXPathExpr{ steps: steps, ns_map: ns_map }
	cxpath_collect_step(ctx, transient, 0, mut out)
}

// cxpath_dedup_elements removes structurally-equal duplicates while
// preserving first-occurrence order — the semantics required by
// ADR 0017 §D13 union and CXDM §4 Element equality. The current
// equality test is the lossless emit form (a stand-in for strict-
// canonical equality), which suffices for the common-case union of
// element queries; the §I work strengthens canonical / strict-equal
// machinery uniformly across the codebase.
fn cxpath_dedup_elements(elems []Element) []Element {
	if elems.len < 2 {
		return elems
	}
	mut out := []Element{cap: elems.len}
	mut seen := map[string]bool{}
	for el in elems {
		key := cxpath_element_identity_key(el)
		if key in seen {
			continue
		}
		seen[key] = true
		out << el
	}
	return out
}

// cxpath_element_identity_key returns a string identity for `el` used
// only for in-evaluator de-duplication of union results. Built from
// the lossless CX emit of a singleton document containing this
// element — emit is fully deterministic for a given AST, so equal
// ASTs produce equal keys.
fn cxpath_element_identity_key(el Element) string {
	tmp := Document{ elements: [Node(el)] }
	return emit_cx(tmp)
}

// cxpath_project_map_key implements one step of the tail `.key` /
// `['key']` postfix chain. The host Element's body is scanned for
// MapNode entries whose key (as canonicalised string) matches `key`;
// when a matching entry's value is itself an Element, that Element
// is appended to `out`. Non-Element values are silently skipped at
// v0.6.0 (the full value-returning surface lands with §F — the CXL
// evaluator).
fn cxpath_project_map_key(el Element, key string, mut out []Element) {
	for item in el.items {
		if item is MapNode {
			mn := item as MapNode
			for entry in mn.entries {
				if cxpath_map_key_matches(entry.key_type, entry.key_value, key) {
					if entry.value is Element {
						v := entry.value as Element
						out << v
					}
				}
			}
		}
	}
}

// cxpath_map_key_matches compares a MapEntry's key to the query key.
// Bare-name and quoted-string queries both compare against the
// canonical-string form of the MapEntry key (per ADR 0017 §D4: keys
// at v0.6.0 are strings/unquoted-names; non-string keys are reserved
// for CXL 3.1).
fn cxpath_map_key_matches(_kt ScalarType, kv ScalarValue, query string) bool {
	return scalar_value_str(kv) == query
}

pub fn (e Element) select(expr string) ?Element {
	results := e.select_all(expr)
	return if results.len > 0 { results[0] } else { none }
}

// collect_doc_ns_map walks the document and builds a flat
// prefix → URI map from every xmlns / xmlns:prefix declaration
// encountered (first occurrence wins). Reserved prefixes `xml:` and
// `cx:` are seeded unconditionally. Returned map is consumed by the
// CXPath name-test and attribute-predicate logic to resolve query
// prefixes; unbound query prefixes fall back to source-name match.
fn collect_doc_ns_map(d Document) map[string]string {
	mut m := seed_reserved_ns_map()
	for n in d.elements {
		if n is Element {
			collect_elem_ns_into(n, mut m)
		}
	}
	return m
}

fn collect_elem_ns_map(e Element) map[string]string {
	mut m := seed_reserved_ns_map()
	collect_elem_ns_into(e, mut m)
	return m
}

fn seed_reserved_ns_map() map[string]string {
	return {
		'xml': xml_namespace_uri
		'cx':  cx_namespace_uri
	}
}

fn collect_elem_ns_into(e Element, mut m map[string]string) {
	for a in e.attrs {
		if a.name == 'xmlns' {
			if '' !in m {
				m[''] = scalar_value_str(a.value)
			}
		} else if a.name.starts_with('xmlns:') && a.name.len > 6 {
			pfx := a.name[6..]
			if pfx !in m && pfx != 'xml' && pfx != 'cx' {
				m[pfx] = scalar_value_str(a.value)
			}
		}
	}
	for it in e.items {
		if it is Element {
			collect_elem_ns_into(it, mut m)
		}
	}
}

// cxpath_elem_name_matches returns true when the element matches the
// CXPath name test. Query prefixes resolve via ns_map; when bound,
// match is by expanded name (ns_uri + local). When the query prefix
// is unbound (and not reserved), match falls back to verbatim source
// `name`. An unprefixed query matches `el.name` directly — it does
// NOT pick up a default namespace, since the query author controls
// whether namespacing applies.
fn cxpath_elem_name_matches(el Element, query string, ns_map map[string]string) bool {
	if query == '' {
		return true
	}
	q_pfx, q_local := split_ns_prefix(query)
	if q_pfx == '' {
		return el.name == query
	}
	if uri := ns_map[q_pfx] {
		if el_uri := el.ns_uri {
			return el_uri == uri && el.local == q_local
		}
		return false
	}
	return el.name == query
}

// cxpath_attr_lookup returns the attribute value when an attribute
// matching `query` exists on `el`. Resolution mirrors element name
// matching: a query prefix bound in ns_map matches by expanded name
// (ns_uri + local), unbound prefixes fall back to source-name match.
// Per XML Namespaces 1.0 §6.2 (and namespaces.md §2.3), unprefixed
// attributes are never in any namespace, so an unprefixed query
// matches by source-name only — the document's default namespace
// does not apply.
fn cxpath_attr_lookup(el Element, query string, ns_map map[string]string) ?ScalarValue {
	q_pfx, q_local := split_ns_prefix(query)
	for a in el.attrs {
		if q_pfx == '' {
			if a.name == query {
				return a.value
			}
			continue
		}
		if uri := ns_map[q_pfx] {
			if a_uri := a.ns_uri {
				if a_uri == uri && a.local == q_local {
					return a.value
				}
			}
			continue
		}
		if a.name == query {
			return a.value
		}
	}
	return none
}

fn cxpath_attr_exists(el Element, query string, ns_map map[string]string) bool {
	cxpath_attr_lookup(el, query, ns_map) or { return false }
	return true
}

// ── Path-tracking variant (CB-5 thunk for transform_all) ─────────────────────
//
// `select_all_paths` returns a list of structural paths to every match,
// in the same preorder as `select_all`. Each path is a list of 0-based
// indices into Document.elements (root) then Element.items
// (descendants). Bindings can navigate to and replace elements at these
// paths, enabling transform_all without an in-binding CXPath
// implementation. See spec/abi.md §2.7.

pub fn (d Document) select_all_paths(expr string) [][]int {
	cx_expr := cxpath_parse(expr) or { panic(err.msg()) }
	mut result := [][]int{}
	virtual_root := Element{ name: '#document', items: d.elements }
	cxpath_collect_step_paths(virtual_root, cx_expr, 0, []int{}, mut result)
	return result
}

pub fn (e Element) select_all_paths(expr string) [][]int {
	cx_expr := cxpath_parse(expr) or { panic(err.msg()) }
	mut result := [][]int{}
	cxpath_collect_step_paths(e, cx_expr, 0, []int{}, mut result)
	return result
}

fn cxpath_collect_step_paths(ctx Element, expr CXPathExpr, step_idx int,
		current_path []int, mut result [][]int) {
	if step_idx >= expr.steps.len {
		return
	}
	step := expr.steps[step_idx]
	match step.axis {
		.child {
			// Build candidates with original-item indices preserved so
			// the path entries reference unfiltered Element.items
			// positions (what bindings need for substitution).
			mut candidates := []Element{}
			mut orig_indices := []int{}
			for orig_idx, item in ctx.items {
				if item is Element {
					el := item as Element
					if cxpath_elem_name_matches(el, step.name, expr.ns_map) {
						candidates << el
						orig_indices << orig_idx
					}
				}
			}
			for i, child in candidates {
				if cxpath_preds_match(child, step.preds, candidates, i, expr.ns_map) {
					mut new_path := current_path.clone()
					new_path << orig_indices[i]
					if step_idx == expr.steps.len - 1 {
						result << new_path
					} else {
						cxpath_collect_step_paths(child, expr, step_idx + 1,
							new_path, mut result)
					}
				}
			}
		}
		.descendant {
			cxpath_collect_descendants_paths(ctx, expr, step_idx, current_path,
				mut result)
		}
	}
}

fn cxpath_collect_descendants_paths(ctx Element, expr CXPathExpr, step_idx int,
		current_path []int, mut result [][]int) {
	step := expr.steps[step_idx]
	is_last := step_idx == expr.steps.len - 1
	mut candidates := []Element{}
	mut orig_indices := []int{}
	for orig_idx, item in ctx.items {
		if item is Element {
			el := item as Element
			if cxpath_elem_name_matches(el, step.name, expr.ns_map) {
				candidates << el
				orig_indices << orig_idx
			}
		}
	}
	for i, child in candidates {
		mut child_path := current_path.clone()
		child_path << orig_indices[i]
		if cxpath_preds_match(child, step.preds, candidates, i, expr.ns_map) {
			if is_last {
				result << child_path.clone()
			} else {
				cxpath_collect_step_paths(child, expr, step_idx + 1,
					child_path, mut result)
			}
		}
		cxpath_collect_descendants_paths(child, expr, step_idx, child_path,
			mut result)
	}
	if step.name != '' {
		// Recurse into non-matching elements too — descendant axis must
		// keep searching their subtrees.
		for orig_idx, item in ctx.items {
			if item is Element {
				el := item as Element
				if !cxpath_elem_name_matches(el, step.name, expr.ns_map) {
					mut sub_path := current_path.clone()
					sub_path << orig_idx
					cxpath_collect_descendants_paths(el, expr, step_idx,
						sub_path, mut result)
				}
			}
		}
	}
}

fn cxpath_collect_step(ctx Element, expr CXPathExpr, step_idx int, mut result []Element) {
	if step_idx >= expr.steps.len {
		return
	}
	step := expr.steps[step_idx]
	match step.axis {
		.child {
			ns_map := expr.ns_map.clone()
			step_name := step.name
			candidates := ctx.items.filter(it is Element
				&& cxpath_elem_name_matches(it as Element, step_name, ns_map)).map(it as Element)
			for i, child in candidates {
				if cxpath_preds_match(child, step.preds, candidates, i, expr.ns_map) {
					if step_idx == expr.steps.len - 1 {
						result << child
					} else {
						cxpath_collect_step(child, expr, step_idx + 1, mut result)
					}
				}
			}
		}
		.descendant {
			cxpath_collect_descendants(ctx, expr, step_idx, mut result)
		}
	}
}

fn cxpath_collect_descendants(ctx Element, expr CXPathExpr, step_idx int, mut result []Element) {
	step := expr.steps[step_idx]
	is_last := step_idx == expr.steps.len - 1
	ns_map := expr.ns_map.clone()
	step_name := step.name
	candidates := ctx.items.filter(it is Element
		&& cxpath_elem_name_matches(it as Element, step_name, ns_map)).map(it as Element)
	for i, child in candidates {
		if cxpath_preds_match(child, step.preds, candidates, i, expr.ns_map) {
			if is_last {
				result << child
			} else {
				cxpath_collect_step(child, expr, step_idx + 1, mut result)
			}
		}
		cxpath_collect_descendants(child, expr, step_idx, mut result)
	}
	if step.name != '' {
		non_candidates := ctx.items.filter(it is Element
			&& !cxpath_elem_name_matches(it as Element, step_name, ns_map)).map(it as Element)
		for child in non_candidates {
			cxpath_collect_descendants(child, expr, step_idx, mut result)
		}
	}
}

// ── Predicate evaluators ──────────────────────────────────────────────────────

fn cxpath_preds_match(el Element, preds []CXPred, siblings []Element, idx int, ns_map map[string]string) bool {
	for pred in preds {
		if !cxpath_pred_eval(el, pred, siblings, idx, ns_map) {
			return false
		}
	}
	return true
}

fn cxpath_pred_eval(el Element, pred CXPred, siblings []Element, idx int, ns_map map[string]string) bool {
	match pred {
		CXPredAttrExists {
			return cxpath_attr_exists(el, pred.attr, ns_map)
		}
		CXPredAttrCmp {
			attr_val := cxpath_attr_lookup(el, pred.attr, ns_map) or { return false }
			return cxpath_compare(attr_val, pred.op, pred.val)
		}
		CXPredChildExists {
			// Child-existence test mirrors element name matching:
			// resolves a query prefix via ns_map when bound, falls
			// back to source-name match otherwise.
			for it in el.items {
				if it is Element {
					if cxpath_elem_name_matches(it as Element, pred.name, ns_map) {
						return true
					}
				}
			}
			return false
		}
		CXPredNot {
			return !cxpath_pred_eval(el, pred.inner, siblings, idx, ns_map)
		}
		CXPredBoolAnd {
			return cxpath_pred_eval(el, pred.left, siblings, idx, ns_map)
				&& cxpath_pred_eval(el, pred.right, siblings, idx, ns_map)
		}
		CXPredBoolOr {
			return cxpath_pred_eval(el, pred.left, siblings, idx, ns_map)
				|| cxpath_pred_eval(el, pred.right, siblings, idx, ns_map)
		}
		CXPredPosition {
			if pred.is_last {
				return idx == siblings.len - 1
			}
			return idx == pred.pos - 1
		}
		CXPredFuncContains {
			attr_val := cxpath_attr_lookup(el, pred.attr, ns_map) or { return false }
			return scalar_value_str(attr_val).contains(pred.val)
		}
		CXPredFuncStartsWith {
			attr_val := cxpath_attr_lookup(el, pred.attr, ns_map) or { return false }
			return scalar_value_str(attr_val).starts_with(pred.val)
		}
		CXPredLocalNameCmp {
			// el.local is populated by resolve_namespaces post-parse.
			// For elements parsed before that pass (or constructed
			// programmatically without it), fall back to splitting
			// el.name on the first colon.
			actual := if el.local.len > 0 {
				el.local
			} else {
				_, l := split_ns_prefix(el.name)
				l
			}
			return if pred.op == '!=' { actual != pred.val } else { actual == pred.val }
		}
		CXPredNamespaceURICmp {
			actual := el.ns_uri or { '' }
			return if pred.op == '!=' { actual != pred.val } else { actual == pred.val }
		}
		CXPredIdMatch {
			el_id := el.id or { return false }
			return el_id == pred.id
		}
	}
}

fn cxpath_compare(actual ScalarValue, op string, expected ScalarValue) bool {
	match op {
		'='  { return cxpath_scalar_eq(actual, expected) }
		'!=' { return !cxpath_scalar_eq(actual, expected) }
		else {
			a := cxpath_scalar_to_f64(actual)
			b := cxpath_scalar_to_f64(expected)
			return match op {
				'>'  { a > b }
				'<'  { a < b }
				'>=' { a >= b }
				'<=' { a <= b }
				else { false }
			}
		}
	}
}

fn cxpath_scalar_eq(a ScalarValue, b ScalarValue) bool {
	return match a {
		bool {
			match b {
				bool { a == b }
				else { false }
			}
		}
		i64 {
			match b {
				i64    { a == b }
				f64    { f64(a) == b }
				string { a.str() == b }
				else   { false }
			}
		}
		f64 {
			match b {
				f64    { a == b }
				i64    { a == f64(b) }
				string { format_float(a) == b }
				else   { false }
			}
		}
		NullValue {
			b is NullValue
		}
		string {
			a == b.str()
		}
	}
}

fn cxpath_scalar_to_f64(v ScalarValue) f64 {
	return match v {
		i64 { f64(v) }
		f64 { v }
		else { panic('CXPath: numeric comparison requires numeric attribute, got: ${scalar_value_str(v)}') }
	}
}

// cxpath_elem_matches is used by transform_all to check if an element matches.
fn cxpath_elem_matches(el Element, expr CXPathExpr) bool {
	if expr.steps.len == 0 {
		return false
	}
	last := expr.steps[expr.steps.len - 1]
	if last.name != '' && !cxpath_elem_name_matches(el, last.name, expr.ns_map) {
		return false
	}
	non_pos := last.preds.filter(!(it is CXPredPosition))
	return cxpath_preds_match(el, non_pos, [], 0, expr.ns_map)
}
