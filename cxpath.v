module cx

import strconv

// ── CXPath AST ────────────────────────────────────────────────────────────────

struct CXPathExpr {
	steps []CXStep
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

fn (mut l CXPathLexer) read_quoted() string {
	if !l.eat_char(`'`) {
		panic("CXPath parse error: expected ' at pos ${l.pos}  expr: ${l.src}")
	}
	start := l.pos
	for l.pos < l.src.len && l.src[l.pos] != `'` {
		l.pos++
	}
	s := l.src[start..l.pos]
	if !l.eat_char(`'`) {
		panic("CXPath parse error: unterminated string at pos ${l.pos}  expr: ${l.src}")
	}
	return s
}

// ── Parser ────────────────────────────────────────────────────────────────────

fn cxpath_parse(expr string) CXPathExpr {
	mut l := CXPathLexer{ src: expr }
	steps := cxpath_parse_steps(mut l)
	if l.pos != l.src.len {
		panic('CXPath parse error: unexpected characters at pos ${l.pos}  expr: ${expr}')
	}
	if steps.len == 0 {
		panic('CXPath parse error: empty expression  expr: ${expr}')
	}
	return CXPathExpr{ steps: steps }
}

fn cxpath_parse_steps(mut l CXPathLexer) []CXStep {
	mut steps := []CXStep{}
	mut axis := CXAxis.child
	if l.peek_str('//') {
		l.pos += 2
		axis = .descendant
	} else if l.peek_str('/') {
		l.pos++
		axis = .child
	}
	step := cxpath_parse_one_step(mut l, axis)
	steps << step
	for {
		l.skip_ws()
		if l.peek_str('//') {
			l.pos += 2
			steps << cxpath_parse_one_step(mut l, .descendant)
		} else if l.peek_str('/') {
			l.pos++
			steps << cxpath_parse_one_step(mut l, .child)
		} else {
			break
		}
	}
	return steps
}

fn cxpath_parse_one_step(mut l CXPathLexer, axis CXAxis) CXStep {
	l.skip_ws()
	mut name := ''
	if l.eat_char(`*`) {
		name = ''
	} else {
		name = l.read_ident()
		if name.len == 0 {
			panic('CXPath parse error: expected element name at pos ${l.pos}  expr: ${l.src}')
		}
	}
	mut preds := []CXPred{}
	for {
		l.skip_ws()
		if l.peek_str('[') {
			preds << cxpath_parse_pred_bracket(mut l)
		} else {
			break
		}
	}
	return CXStep{ axis: axis, name: name, preds: preds }
}

fn cxpath_parse_pred_bracket(mut l CXPathLexer) CXPred {
	if !l.eat_char(`[`) {
		panic('CXPath parse error: expected [ at pos ${l.pos}  expr: ${l.src}')
	}
	l.skip_ws()
	pred := cxpath_parse_pred_expr(mut l)
	l.skip_ws()
	if !l.eat_char(`]`) {
		panic('CXPath parse error: expected ] at pos ${l.pos}  expr: ${l.src}')
	}
	return pred
}

fn cxpath_parse_pred_expr(mut l CXPathLexer) CXPred {
	left := cxpath_parse_pred_term(mut l)
	l.skip_ws()
	if l.peek_str('or ') || l.peek_str('or]') || l.peek_str('or)') {
		saved := l.pos
		word := l.read_ident()
		if word == 'or' {
			l.skip_ws()
			right := cxpath_parse_pred_term(mut l)
			return CXPred(CXPredBoolOr{ left: left, right: right })
		}
		l.pos = saved
	}
	return left
}

fn cxpath_parse_pred_term(mut l CXPathLexer) CXPred {
	left := cxpath_parse_pred_factor(mut l)
	l.skip_ws()
	if l.peek_str('and ') || l.peek_str('and]') || l.peek_str('and)') {
		saved := l.pos
		word := l.read_ident()
		if word == 'and' {
			l.skip_ws()
			right := cxpath_parse_pred_factor(mut l)
			return CXPred(CXPredBoolAnd{ left: left, right: right })
		}
		l.pos = saved
	}
	return left
}

fn cxpath_parse_pred_factor(mut l CXPathLexer) CXPred {
	l.skip_ws()
	if l.peek_str('not(') || l.peek_str('not (') {
		l.read_ident()
		l.skip_ws()
		if !l.eat_char(`(`) {
			panic('CXPath parse error: expected ( after not  expr: ${l.src}')
		}
		l.skip_ws()
		inner := cxpath_parse_pred_expr(mut l)
		l.skip_ws()
		if !l.eat_char(`)`) {
			panic('CXPath parse error: expected ) after not(...)  expr: ${l.src}')
		}
		return CXPred(CXPredNot{ inner: inner })
	}
	if l.peek_str('contains(') {
		l.read_ident()
		l.skip_ws()
		if !l.eat_char(`(`) {
			panic('CXPath parse error: expected ( after contains  expr: ${l.src}')
		}
		l.skip_ws()
		if !l.eat_char(`@`) {
			panic('CXPath parse error: expected @attr in contains()  expr: ${l.src}')
		}
		attr := l.read_ident()
		l.skip_ws()
		if !l.eat_char(`,`) {
			panic('CXPath parse error: expected , in contains()  expr: ${l.src}')
		}
		l.skip_ws()
		val := cxpath_parse_scalar_str(mut l)
		l.skip_ws()
		if !l.eat_char(`)`) {
			panic('CXPath parse error: expected ) after contains(...)  expr: ${l.src}')
		}
		return CXPred(CXPredFuncContains{ attr: attr, val: val })
	}
	if l.peek_str('starts-with(') {
		for l.pos < l.src.len && l.src[l.pos] != `(` {
			l.pos++
		}
		l.skip_ws()
		if !l.eat_char(`(`) {
			panic('CXPath parse error: expected ( after starts-with  expr: ${l.src}')
		}
		l.skip_ws()
		if !l.eat_char(`@`) {
			panic('CXPath parse error: expected @attr in starts-with()  expr: ${l.src}')
		}
		attr := l.read_ident()
		l.skip_ws()
		if !l.eat_char(`,`) {
			panic('CXPath parse error: expected , in starts-with()  expr: ${l.src}')
		}
		l.skip_ws()
		val := cxpath_parse_scalar_str(mut l)
		l.skip_ws()
		if !l.eat_char(`)`) {
			panic('CXPath parse error: expected ) after starts-with(...)  expr: ${l.src}')
		}
		return CXPred(CXPredFuncStartsWith{ attr: attr, val: val })
	}
	if l.peek_str('last()') {
		l.pos += 6
		return CXPred(CXPredPosition{ is_last: true })
	}
	if l.peek_str('(') {
		l.eat_char(`(`)
		l.skip_ws()
		inner := cxpath_parse_pred_expr(mut l)
		l.skip_ws()
		if !l.eat_char(`)`) {
			panic('CXPath parse error: expected ) at pos ${l.pos}  expr: ${l.src}')
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
		val := cxpath_parse_scalar_val(mut l)
		return CXPred(CXPredAttrCmp{ attr: attr, op: op, val: val })
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
	panic('CXPath parse error: unexpected character at pos ${l.pos}  expr: ${l.src}')
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

fn cxpath_parse_scalar_val(mut l CXPathLexer) ScalarValue {
	if l.peek_str("'") {
		return ScalarValue(l.read_quoted())
	}
	s := l.read_ident()
	if s.len == 0 {
		panic('CXPath parse error: expected value at pos ${l.pos}  expr: ${l.src}')
	}
	return cxpath_autotype(s)
}

fn cxpath_parse_scalar_str(mut l CXPathLexer) string {
	if l.peek_str("'") {
		return l.read_quoted()
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
	cx_expr := cxpath_parse(expr)
	mut result := []Element{}
	virtual_root := Element{ name: '#document', items: d.elements }
	cxpath_collect_step(virtual_root, cx_expr, 0, mut result)
	return result
}

pub fn (d Document) select(expr string) ?Element {
	results := d.select_all(expr)
	return if results.len > 0 { results[0] } else { none }
}

pub fn (e Element) select_all(expr string) []Element {
	cx_expr := cxpath_parse(expr)
	mut result := []Element{}
	cxpath_collect_step(e, cx_expr, 0, mut result)
	return result
}

pub fn (e Element) select(expr string) ?Element {
	results := e.select_all(expr)
	return if results.len > 0 { results[0] } else { none }
}

fn cxpath_collect_step(ctx Element, expr CXPathExpr, step_idx int, mut result []Element) {
	if step_idx >= expr.steps.len {
		return
	}
	step := expr.steps[step_idx]
	match step.axis {
		.child {
			candidates := ctx.items.filter(it is Element
				&& (step.name == '' || (it as Element).name == step.name)).map(it as Element)
			for i, child in candidates {
				if cxpath_preds_match(child, step.preds, candidates, i) {
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
	candidates := ctx.items.filter(it is Element
		&& (step.name == '' || (it as Element).name == step.name)).map(it as Element)
	for i, child in candidates {
		if cxpath_preds_match(child, step.preds, candidates, i) {
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
			&& (it as Element).name != step.name).map(it as Element)
		for child in non_candidates {
			cxpath_collect_descendants(child, expr, step_idx, mut result)
		}
	}
}

// ── Predicate evaluators ──────────────────────────────────────────────────────

fn cxpath_preds_match(el Element, preds []CXPred, siblings []Element, idx int) bool {
	for pred in preds {
		if !cxpath_pred_eval(el, pred, siblings, idx) {
			return false
		}
	}
	return true
}

fn cxpath_pred_eval(el Element, pred CXPred, siblings []Element, idx int) bool {
	match pred {
		CXPredAttrExists {
			return el.has_attr(pred.attr)
		}
		CXPredAttrCmp {
			attr_val := el.attr_val(pred.attr) or { return false }
			return cxpath_compare(attr_val, pred.op, pred.val)
		}
		CXPredChildExists {
			return el.get(pred.name) != none
		}
		CXPredNot {
			return !cxpath_pred_eval(el, pred.inner, siblings, idx)
		}
		CXPredBoolAnd {
			return cxpath_pred_eval(el, pred.left, siblings, idx)
				&& cxpath_pred_eval(el, pred.right, siblings, idx)
		}
		CXPredBoolOr {
			return cxpath_pred_eval(el, pred.left, siblings, idx)
				|| cxpath_pred_eval(el, pred.right, siblings, idx)
		}
		CXPredPosition {
			if pred.is_last {
				return idx == siblings.len - 1
			}
			return idx == pred.pos - 1
		}
		CXPredFuncContains {
			attr_val := el.attr_val(pred.attr) or { return false }
			return scalar_value_str(attr_val).contains(pred.val)
		}
		CXPredFuncStartsWith {
			attr_val := el.attr_val(pred.attr) or { return false }
			return scalar_value_str(attr_val).starts_with(pred.val)
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
	if last.name != '' && last.name != el.name {
		return false
	}
	non_pos := last.preds.filter(!(it is CXPredPosition))
	return cxpath_preds_match(el, non_pos, [], 0)
}
