module cx

import strings
import strconv

// ── CXL (CX Language) reference evaluator ────────────────────────────────────
//
// Per ADR 0016 / ADR 0017 §D7 and spec/cxl.md (CXL 1.0). This is the V
// reference implementation; every per-binding native evaluator MUST
// produce byte-identical output (ADR 0016 R8, conformance/cxl.txt).
//
// CXL 1.0 v0.6.0 directive set under the ADR 0017 uniform shape
// `[?Name [arg1, arg2, …]]` (§D6 / §D7):
//   Interpolation `[?=EXPR]`                — value emission (sugar)
//   `[?if [cond, then-body, else-body?]]`   — conditional (§3.2)
//   `[?if [[c1, b1], [c2, b2], [*, def]]]`  — multi-branch (§3.3)
//   `[?for [var, iterable, body]]`          — iteration (§3.4)
//   `[?with [context, body]]`               — context shift (§3.5)
//   `[?def [name, body]]`                   — define block (§3.7)
//   `[?use [name, context?]]`               — invoke block (§3.8)
//   `[?include [path]]`                     — partial (§3.6, deferred)
//   String filters (§4.1):
//     upper/lower/trim/length/concat/join/replace
//   Type / encoding filters (§4.5/§4.6):
//     default/escape-html/escape-url/raw
//   Sequence filters (§4.3, partial):
//     first/rest/empty/reverse/length
//   Output targets: text (default), cx, html (auto-escape)
//
// Deferred to follow-up: `[?include]` resolution (ADR 0014),
// numeric/temporal/full sequence filter set, markdown/json/yaml/
// xml/csv/tsv emission targets, streaming evaluation, whitespace-
// trim markers `[?-= … -]`, block-form newline consumption per
// spec/cxl.md §2.4.
//
// Sequence-flat data model per spec/cxdm.md: every evaluator value
// is `[]CXLItem`. An empty sequence is `[]`; a single-item value is
// `[item]`; concatenation flattens.
//
// Pre-ADR-0017 syntax forms (attribute-slot `:then=…/:else=…`,
// `?cond` directive, bare positional `?for v in expr body`) are NOT
// accepted by this evaluator. The parser (vcx/cx/parser.v) rejects
// them at parse time — this file only handles the new shape.

// ── CXDM value model (runtime) ───────────────────────────────────────────────

// CXLScalar is a bare typed scalar — an Item that is not a Node.
// Produced by attribute access (`@name` returns the attribute's typed
// ScalarValue), filter results, and literal expressions.
pub struct CXLScalar {
pub:
	data_type ScalarType
	value     ScalarValue
}

// CXLItem is the CXDM Item kind. Either a Node (Element / Text /
// ScalarNode / …) or a bare Scalar.
pub type CXLItem = Element
	| TextNode
	| ScalarNode
	| CommentNode
	| PINode
	| CXDirectiveNode
	| CXLScalar

// CXLValue is a CXDM Sequence — `[]CXLItem`. Empty sequence is the
// "missing"/"absent" value (EBV false per cxdm.md §4.5).
pub type CXLValue = []CXLItem

// ── Evaluator environment ────────────────────────────────────────────────────

struct CXLEnv {
mut:
	input    Document
	target   string                  // output-target: 'text', 'cx', 'html', …
	strict   bool                    // [?cx output-strict]
	context  CXLValue                // current evaluation context
	bindings map[string]CXLValue     // [?for] / [?with] / template parameter scope
	defs     map[string]TemplateDef  // [?def] named templates (ADR 0020)
	out      strings.Builder
}

// TemplateDef carries a `?def` block's parameter list and body. Zero-
// parameter templates have an empty `params` array; their semantics
// match the pre-ADR-0020 named-block model. Non-empty `params` is
// the ADR 0020 parameterized form — capability bit 30. Lexical-scope
// binding of params into env.bindings happens at template-invocation
// sites via dispatch_template_call; closure capture is not modeled
// (bodies do not escape their invocation frame).
struct TemplateDef {
mut:
	params []string
	body   []Node
}

fn new_cxl_env(input Document, target string) CXLEnv {
	mut env := CXLEnv{
		input:    input
		target:   if target == '' { 'text' } else { target }
		strict:   false
		context:  cxl_seq_from_doc(input)
		bindings: map[string]CXLValue{}
		defs:     map[string]TemplateDef{}
		out:      strings.new_builder(256)
	}
	return env
}

// cxl_seq_from_doc establishes the evaluator's implicit top-level
// context. When the document has exactly one Element root (the
// overwhelmingly common case for template inputs — `[product …]`,
// `[catalog …]`, etc.), the context is that root Element so `@attr`
// and bare child names resolve naturally per spec/cxl.md §1 examples.
// For documents with multiple top-level elements (multi-document
// streams, etc.), the context is a synthetic `#document` wrapper.
fn cxl_seq_from_doc(d Document) CXLValue {
	if d.elements.len == 1 && d.elements[0] is Element {
		return [CXLItem(d.elements[0] as Element)]
	}
	root := Element{ name: '#document', items: d.elements }
	return [CXLItem(root)]
}

// ── Public entry point ───────────────────────────────────────────────────────

// eval_cxl parses an input CX document and a CXL program, evaluates
// the program against the input, and returns the rendered output as a
// string. Errors propagate as V errors with a position-bearing message.
pub fn eval_cxl(input_cx string, program_cx string, output_target string) !string {
	input_doc  := parse(input_cx) or { return error('cxl: input parse failed: ${err.msg()}') }
	prog_doc   := parse(program_cx) or { return error('cxl: program parse failed: ${err.msg()}') }
	target     := pick_output_target(prog_doc, output_target)
	mut env    := new_cxl_env(input_doc, target)
	apply_program_config(prog_doc, mut env)
	for n in prog_doc.prolog { eval_node(n, mut env)! }
	for n in prog_doc.elements { eval_node(n, mut env)! }
	return env.out.str()
}

// pick_output_target prefers the caller-supplied target, then any
// `[?cx output-target=…]` directive in the program prolog / first
// elements, defaulting to 'text'.
fn pick_output_target(prog Document, caller string) string {
	if caller != '' { return caller }
	for n in prog.prolog {
		if t := target_from_cx_directive(n) { return t }
	}
	for n in prog.elements {
		if t := target_from_cx_directive(n) { return t }
		break // only scan the leading directive(s)
	}
	return 'text'
}

fn target_from_cx_directive(n Node) ?string {
	if n is CXDirectiveNode {
		for a in n.attrs {
			if a.name == 'output-target' {
				return scalar_value_str(a.value)
			}
		}
	}
	return none
}

fn apply_program_config(prog Document, mut env CXLEnv) {
	for n in prog.prolog { absorb_config_node(n, mut env) }
}

fn absorb_config_node(n Node, mut env CXLEnv) {
	if n is CXDirectiveNode {
		for a in n.attrs {
			match a.name {
				'output-target' { env.target = scalar_value_str(a.value) }
				'output-strict' { env.strict = true }
				else {}
			}
		}
	}
}

// ── Tree walk ────────────────────────────────────────────────────────────────

fn eval_node(n Node, mut env CXLEnv) ! {
	match n {
		InterpolationNode { eval_interpolation(n, mut env)! }
		EvalDirectiveNode { dispatch_eval_directive(n, mut env)! }
		TextNode          { env.out.write_string(n.value) }
		ScalarNode        { env.out.write_string(scalar_value_str(n.value)) }
		Element           { emit_element(n, mut env)! }
		CommentNode       {} // §2.1: program comments are dropped
		CXDirectiveNode   { cxl_emit_cx_directive(n, mut env) }
		SequenceNode      { for it in n.items { eval_node(it, mut env)! } }
		ArrayNode         { for it in n.items { eval_node(it, mut env)! } }
		else              {} // PIs, RawText, MapNode, etc. preserved-but-inert
	}
}

// emit_element handles a data CX element appearing in a CXL program.
// For target=cx, the element round-trips through cx text emission with
// its children's CXL forms evaluated. For other targets the element is
// emitted as CX text (the spec's "authoring warning" case at v0.6.0;
// see cxl.md §2.2 — emit, don't block).
fn emit_element(el Element, mut env CXLEnv) ! {
	emit_element_cx(el, mut env)!
}

fn emit_element_cx(el Element, mut env CXLEnv) ! {
	env.out.write_string('[')
	env.out.write_string(el.name)
	for a in el.attrs {
		env.out.write_string(' ')
		env.out.write_string(a.name)
		if body := a.body {
			env.out.write_string('=[')
			mut sub := strings.new_builder(64)
			saved := env.out
			env.out = sub
			for n in body { eval_node(n, mut env)! }
			env.out = saved
			env.out.write_string(sub.str())
			env.out.write_string(']')
		} else {
			env.out.write_string('=')
			env.out.write_string(scalar_value_str(a.value))
		}
	}
	if el.items.len > 0 {
		env.out.write_string(' ')
		for n in el.items { eval_node(n, mut env)! }
	}
	env.out.write_string(']')
}

// emit_cx_directive: top-of-file [?cx …] directives (output-target,
// output-strict, cxl-version) configure the evaluator and are stripped
// from output (§2.3). All other CXDirectives are passed through.
fn cxl_emit_cx_directive(n CXDirectiveNode, mut env CXLEnv) {
	for a in n.attrs {
		if a.name in ['output-target', 'output-strict', 'cxl-version'] {
			return
		}
	}
	env.out.write_string('[?cx')
	for a in n.attrs {
		env.out.write_string(' ')
		env.out.write_string(a.name)
		env.out.write_string('=')
		env.out.write_string(scalar_value_str(a.value))
	}
	env.out.write_string(']')
}

// ── Interpolation `[?=EXPR]` ─────────────────────────────────────────────────

fn eval_interpolation(n InterpolationNode, mut env CXLEnv) ! {
	val := eval_expr(n.expr, env)!
	emit_value_as_text(val, mut env)
}

fn emit_value_as_text(val CXLValue, mut env CXLEnv) {
	for it in val {
		s := item_to_text(it)
		if env.target == 'html' {
			env.out.write_string(escape_html_str(s))
		} else {
			env.out.write_string(s)
		}
	}
}

fn item_to_text(it CXLItem) string {
	return match it {
		CXLScalar  { scalar_value_str(it.value) }
		ScalarNode { scalar_value_str(it.value) }
		TextNode   { it.value }
		Element    { element_text_content(it) }
		else       { '' }
	}
}

// element_text_content extracts the concatenated text content of an
// Element — text nodes and scalar bodies emit their lexical form, child
// elements recurse. Equivalent to XPath string(.) on Elements.
fn element_text_content(el Element) string {
	mut b := strings.new_builder(32)
	for n in el.items {
		match n {
			TextNode   { b.write_string(n.value) }
			ScalarNode { b.write_string(scalar_value_str(n.value)) }
			Element    { b.write_string(element_text_content(n)) }
			else       {}
		}
	}
	return b.str()
}

// ── EvalDirective dispatch ───────────────────────────────────────────────────

fn dispatch_eval_directive(n EvalDirectiveNode, mut env CXLEnv) ! {
	// Reserved control-flow directives — cannot be shadowed by user
	// `?def` templates (the grammar's EvalName production [59a]
	// reserves these names; ?def parses 'if' / 'for' / etc. as
	// control-flow, never as a definable identifier).
	match n.name {
		'if'      { eval_if(n, mut env)!  return }
		'for'     { eval_for(n, mut env)! return }
		'with'    { eval_with(n, mut env)! return }
		'def'     { eval_def(n, mut env)! return }
		'use'     { eval_use(n, mut env)! return }
		'include' { return error('cxl: [?include] not yet implemented (v0.6.0 follow-up; depends on ADR 0014 include resolution)') }
		// `cond` dropped per ADR 0017 §D7 (folded into multi-branch `?if`).
		'cond'    { return error('cxl: [?cond] is dropped at CXL 1.0 — use [?if [[c1, b1], …, [*, default]]] (ADR 0017 §D7)') }
		// CXL 3.1+ — parsed but evaluator errors per ADR 0016 R4.
		'let', 'fn', 'match', 'try' {
			return error('cxl: [?${n.name}] is CXL 3.1; not available at CXL 1.0')
		}
		else {}
	}
	// User-defined templates win over builtin filter names per
	// ADR 0020 §D6 — `[?def upper :body …]` followed by `[?upper x]`
	// invokes the user template, not the builtin. Templates are
	// resolved before filters at every call site.
	if n.name in env.defs {
		dispatch_template_call(n, mut env)!
		return
	}
	// CXL 1.0 frozen filter set — invoked as directives at use-site.
	match n.name {
		'upper', 'lower', 'trim', 'length', 'concat', 'join', 'replace',
		'default', 'escape-html', 'escape-url', 'raw',
		'first', 'rest', 'empty', 'reverse' {
			val := eval_filter_directive(n, env)!
			emit_value_as_text(val, mut env)
		}
		else {
			return error('cxl: unknown evaluation directive [?${n.name}]')
		}
	}
}

// ── ArgArray helpers (ADR 0017 §D6) ──────────────────────────────────────────

// arg_array_slots returns the slot list of an EvalDirective's single
// ArgArray. Empty directives (`[?if]`) return an empty list. Returns
// an error if items[0] is not an ArrayNode (parser invariant violation;
// should never happen given the §F-parser dispatch).
fn arg_array_slots(n EvalDirectiveNode) ![]Node {
	if n.items.len == 0 { return []Node{} }
	if n.items.len != 1 {
		return error('cxl: [?${n.name}] expected one ArgArray body item, got ${n.items.len}')
	}
	arg := n.items[0]
	if arg !is ArrayNode {
		return error('cxl: [?${n.name}] expected ArgArray (ArrayNode), got ${typeof(arg).name}')
	}
	return (arg as ArrayNode).items
}

// slot_to_expr extracts an expression-text representation of a slot.
// Used for slots that carry a CXPath expression (cond, iterable,
// context) or a bare-name token (var, def-name, use-name). Single
// TextNode/ScalarNode slots return their text form; SequenceNode-
// wrapped multi-item slots concatenate text content (rare in
// expression positions but supported for completeness). Other node
// kinds error — a structural slot can't be coerced to expression
// text without ambiguity.
fn slot_to_expr(n Node) !string {
	return match n {
		TextNode   { n.value.trim_space() }
		ScalarNode { scalar_value_str(n.value).trim_space() }
		SequenceNode {
			mut b := strings.new_builder(16)
			for it in n.items {
				match it {
					TextNode   { b.write_string(it.value) }
					ScalarNode { b.write_string(scalar_value_str(it.value)) }
					else       { return error('cxl: slot expression contains non-text item ${typeof(it).name}') }
				}
			}
			b.str().trim_space()
		}
		else { error('cxl: slot expression cannot be ${typeof(n).name}') }
	}
}

// eval_slot_body evaluates a slot as a body — emits each body item to
// env.out in order. Single-Node slots are wrapped trivially; multi-
// item SequenceNode slots iterate. Used by then/else/body/with-body/
// def-body/for-body slots where the slot value renders as output
// rather than being consumed as an expression.
fn eval_slot_body(slot Node, mut env CXLEnv) ! {
	if slot is SequenceNode {
		for it in (slot as SequenceNode).items { eval_node(it, mut env)! }
		return
	}
	eval_node(slot, mut env)!
}

// is_pair_array reports whether a slot is itself a 2-element ArrayNode
// — used by ?if to detect multi-branch shape `[[c1,b1], [c2,b2], …]`.
fn is_pair_array(n Node) bool {
	if n is ArrayNode {
		arr := n as ArrayNode
		return arr.items.len == 2
	}
	return false
}

// ── `[?if]` — conditional / multi-branch (spec/cxl.md §3.2, §3.3) ───────────

fn eval_if(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len == 0 {
		return error('cxl: [?if] requires `[cond, then-body, else-body?]` or `[[c1,b1], …, [*, default]]`')
	}

	// Multi-branch detection per spec/cxl.md §3.3: every slot is a
	// 2-element array.
	mut is_multi := slots.len >= 1
	for s in slots {
		if !is_pair_array(s) { is_multi = false; break }
	}
	if is_multi {
		for s in slots {
			pair := s as ArrayNode
			cond_expr := slot_to_expr(pair.items[0])!
			if eval_branch_condition(cond_expr, env)! {
				eval_slot_body(pair.items[1], mut env)!
				return
			}
		}
		return // no branch matched, no default fired
	}

	// Two- or three-slot form: cond / then / else?
	if slots.len < 2 || slots.len > 3 {
		return error('cxl: [?if] expected 2 or 3 positional slots (cond, then, else?), got ${slots.len}')
	}
	cond_expr := slot_to_expr(slots[0])!
	cond_val  := eval_expr(cond_expr, env)!
	if value_ebv(cond_val) {
		eval_slot_body(slots[1], mut env)!
	} else if slots.len == 3 {
		eval_slot_body(slots[2], mut env)!
	}
}

// eval_branch_condition handles the §D8 wildcard sentinel `*` (always
// truthy) and otherwise evaluates the condition as CXPath / comparison.
fn eval_branch_condition(expr string, env CXLEnv) !bool {
	if expr == '*' { return true }
	val := eval_expr(expr, env)!
	return value_ebv(val)
}

// ── `[?for [var, iterable, body]]` (spec/cxl.md §3.4) ────────────────────────

fn eval_for(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 3 {
		return error('cxl: [?for] expected 3 slots [var, iterable, body], got ${slots.len}')
	}
	var_name := slot_to_expr(slots[0])!
	if var_name == '' {
		return error('cxl: [?for] var slot is empty')
	}
	iter_expr := slot_to_expr(slots[1])!
	seq       := eval_expr(iter_expr, env)!

	saved_binding := env.bindings[var_name] or { CXLValue([]CXLItem{}) }
	had_binding   := var_name in env.bindings
	body          := slots[2]
	for it in seq {
		env.bindings[var_name] = [it]
		eval_slot_body(body, mut env)!
	}
	if had_binding {
		env.bindings[var_name] = saved_binding
	} else {
		env.bindings.delete(var_name)
	}
}

// ── `[?with [context, body]]` (spec/cxl.md §3.5) ─────────────────────────────

fn eval_with(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len != 2 {
		return error('cxl: [?with] expected 2 slots [context, body], got ${slots.len}')
	}
	ctx_expr := slot_to_expr(slots[0])!
	new_ctx  := eval_expr(ctx_expr, env)!
	saved    := env.context
	env.context = new_ctx
	eval_slot_body(slots[1], mut env)!
	env.context = saved
}

// ── `[?def [name, body]]` / `[?use [name, ctx?]]` (spec/cxl.md §3.7/§3.8) ────

fn eval_def(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	// ADR 0017 §D7 amendment (2026-05-12) + ADR 0020 §D4: ?def is
	// canonically 3-slot [name, params, body]. The parser auto-
	// expands legacy 2-slot [name, body] to 3-slot with params=[].
	// We accept both here defensively in case AST is constructed
	// programmatically (e.g., via ast_bin decode from older writers).
	mut name_node := Node(SequenceNode{ items: []Node{} })
	mut params_items := []Node{}
	mut body_node := Node(SequenceNode{ items: []Node{} })
	match slots.len {
		2 {
			// Legacy 2-slot — params is implicitly empty
			name_node = slots[0]
			body_node = slots[1]
		}
		3 {
			name_node = slots[0]
			params_node := slots[1]
			if params_node !is ArrayNode {
				return error('cxl: [?def] params slot must be an Array of identifiers, got ${typeof(params_node).name}')
			}
			params_items = (params_node as ArrayNode).items.clone()
			body_node = slots[2]
		}
		else {
			return error('cxl: [?def] expected 2 or 3 slots [name, (params,) body], got ${slots.len}')
		}
	}
	name := slot_to_expr(name_node)!
	if name == '' {
		return error('cxl: [?def] name slot is empty')
	}
	// Extract param names from the params Array. Each item must be a
	// bare identifier (TextNode/ScalarNode/Element-with-empty-body
	// covered by the parser's normalize_params_slot — at this point
	// AST items are guaranteed identifier-shaped).
	mut params := []string{}
	for p_item in params_items {
		p_name := slot_to_expr(p_item)!
		if p_name == '' {
			return error('cxl: [?def] params Array contains empty/non-identifier item')
		}
		params << p_name
	}
	// Body items as a flat list for substitution at invocation.
	body_items := if body_node is SequenceNode {
		(body_node as SequenceNode).items.clone()
	} else {
		[body_node]
	}
	env.defs[name] = TemplateDef{
		params: params
		body:   body_items
	}
}

fn eval_use(n EvalDirectiveNode, mut env CXLEnv) ! {
	slots := arg_array_slots(n)!
	if slots.len < 1 || slots.len > 2 {
		return error('cxl: [?use] expected 1 or 2 slots [name, ctx?], got ${slots.len}')
	}
	name := slot_to_expr(slots[0])!
	tmpl := env.defs[name] or {
		return error('cxl: [?use] unknown block "${name}"')
	}
	// ADR 0020 §R4: [?use] is for zero-parameter templates only;
	// parameterized templates must be invoked via the directive-call
	// form `[?template-name arg1 arg2]` (positional args matching
	// the :params slot). ?use cannot supply N parameter values via
	// its one optional :ctx slot.
	if tmpl.params.len > 0 {
		return error('cxl: [?use ${name}] — template `${name}` has ${tmpl.params.len} parameter(s); invoke via [?${name} arg1 …] not [?use ${name}] (ADR 0020 §R4)')
	}
	if slots.len == 2 {
		ctx_expr := slot_to_expr(slots[1])!
		new_ctx  := eval_expr(ctx_expr, env)!
		saved    := env.context
		env.context = new_ctx
		for bn in tmpl.body { eval_node(bn, mut env)! }
		env.context = saved
	} else {
		for bn in tmpl.body { eval_node(bn, mut env)! }
	}
}

// dispatch_template_call invokes a user-defined `?def` template at a
// call site `[?template-name arg1 arg2 …]`. Args are evaluated to
// CXLValue in the call-site context, bound to the template's
// parameter names via env.bindings (save/restore pattern matching
// eval_for / eval_with), and the template body is evaluated under
// the resulting lexical frame. Per ADR 0020 §D2 closures are not
// modeled — parameter bindings unbind on body exit.
fn dispatch_template_call(n EvalDirectiveNode, mut env CXLEnv) ! {
	tmpl := env.defs[n.name] or {
		// dispatch_eval_directive only routes here after confirming
		// the name is in env.defs; this branch is unreachable in
		// normal evaluation but defended for safety.
		return error('cxl: dispatch_template_call: template "${n.name}" not in env.defs (parser invariant violation)')
	}
	// Collect positional args from the EvalDirective's ArgArray.
	mut arg_nodes := []Node{}
	if n.items.len == 1 {
		arg_arr := n.items[0]
		if arg_arr !is ArrayNode {
			return error('cxl: [?${n.name} …] expected positional ArgArray, got ${typeof(arg_arr).name}')
		}
		arg_nodes = (arg_arr as ArrayNode).items.clone()
	} else if n.items.len > 1 {
		return error('cxl: [?${n.name} …] expected single ArgArray body, got ${n.items.len} items')
	}
	// W018: arg count must match param count.
	if arg_nodes.len != tmpl.params.len {
		return error('cxl: W018: [?${n.name}] expects ${tmpl.params.len} arg(s), got ${arg_nodes.len}')
	}
	// Evaluate each arg in the *caller's* context (lexical scope of
	// the call site, not the template body).
	mut arg_values := []CXLValue{cap: arg_nodes.len}
	for arg in arg_nodes {
		arg_values << eval_slot_to_value(arg, env)!
	}
	// Save existing bindings for the parameter names so we can
	// restore on exit (mirrors eval_for's save/restore pattern).
	// Important: save BEFORE any binding update so we capture
	// pre-call state for every name, even if multiple params share
	// the same name (which would be a W018-adjacent error caught
	// at parse time, but defended).
	mut saved   := map[string]CXLValue{}
	mut had     := map[string]bool{}
	for p_name in tmpl.params {
		had[p_name] = p_name in env.bindings
		if had[p_name] {
			saved[p_name] = env.bindings[p_name]
		}
	}
	// Bind parameters into the lexical scope.
	for i, p_name in tmpl.params {
		env.bindings[p_name] = arg_values[i]
	}
	// Evaluate body in the parameter-bound frame.
	for body_item in tmpl.body {
		eval_node(body_item, mut env)!
	}
	// Restore prior bindings (lexical-scope unbind on body exit
	// per ADR 0020 §D2).
	for p_name in tmpl.params {
		if had[p_name] {
			env.bindings[p_name] = saved[p_name]
		} else {
			env.bindings.delete(p_name)
		}
	}
}

// ── Filter set (spec/cxl.md §4) ──────────────────────────────────────────────

// eval_filter_directive evaluates a filter directive (e.g. `[?upper
// [@name]]`) and returns its value. Each positional slot in the arg
// array is evaluated to a CXLValue; the filter function then receives
// the slot-value list and returns its result. Nested filter calls
// (`[?upper [[?trim [@name]]]]`) evaluate naturally because slot 0 of
// `?upper`'s arg array is the inner `?trim` EvalDirective, which
// recurses through eval_slot_to_value.
fn eval_filter_directive(n EvalDirectiveNode, env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	mut args := []CXLValue{cap: slots.len}
	for s in slots {
		args << eval_slot_to_value(s, env)!
	}
	return match n.name {
		'upper'       { filter_upper(args)! }
		'lower'       { filter_lower(args)! }
		'trim'        { filter_trim(args)! }
		'length'      { filter_length(args)! }
		'concat'      { filter_concat(args)! }
		'join'        { filter_join(args)! }
		'replace'     { filter_replace(args)! }
		'default'     { filter_default(args)! }
		'escape-html' { filter_escape_html(args)! }
		'escape-url'  { filter_escape_url(args)! }
		'raw'         { filter_raw(args)! }
		'first'       { filter_first(args)! }
		'rest'        { filter_rest(args)! }
		'empty'       { filter_empty(args)! }
		'reverse'     { filter_reverse(args)! }
		else          { error('cxl: filter [?${n.name}] not in CXL 1.0 set') }
	}
}

// eval_slot_to_value evaluates one filter-argument slot to a CXLValue.
// Slots may be:
//   - Bare-text expression token (CXPath / comparison) → eval_expr
//   - Quoted-string TextNode (e.g. `'/'`)              → scalar value
//   - ScalarNode atomic literal (`42`, `true`)         → scalar value
//   - Nested EvalDirective (filter composition)        → recursive eval
//   - InterpolationNode                                → its expr eval
//   - SequenceNode (mixed content)                     → joined text
fn eval_slot_to_value(n Node, env CXLEnv) !CXLValue {
	return match n {
		TextNode {
			t := n.value.trim_space()
			// Empty TextNode → empty sequence
			if t == '' { CXLValue([]CXLItem{}) }
			// Quoted strings are stripped by the parser, so a bare
			// TextNode either holds an expression (`@name`, `//path`,
			// `@stock > 0`), a bound variable reference (`x` /
			// `x/@sku` where x is a `?for` loop var or template
			// parameter), or a literal token. Treat names / paths /
			// expressions as expression text; treat anything else as
			// literal string.
			else if t[0] == `@` || t[0] == `/` || cxl_expr_has_operator(t) {
				eval_expr(t, env)!
			} else if bare_ident_is_bound(t, env) {
				// Bare identifier that resolves to a bound variable
				// (loop var, ?with binding, or template parameter)
				// — evaluate as a path expression so `x` or `x/@sku`
				// works in filter args and template-call args. Falls
				// back to literal-string handling below when the
				// identifier is not bound.
				eval_expr(t, env)!
			} else {
				[CXLItem(CXLScalar{
					data_type: .string_type
					value:     ScalarValue(n.value)
				})]
			}
		}
		ScalarNode {
			[CXLItem(CXLScalar{
				data_type: n.data_type
				value:     n.value
			})]
		}
		InterpolationNode {
			eval_expr(n.expr, env)!
		}
		EvalDirectiveNode {
			eval_filter_directive(n, env)!
		}
		SequenceNode {
			// Concatenate child text representations for filter
			// arguments. Rare; spec/cxl.md §4 filter args are
			// usually single-item.
			mut b := strings.new_builder(16)
			for it in n.items {
				match it {
					TextNode   { b.write_string(it.value) }
					ScalarNode { b.write_string(scalar_value_str(it.value)) }
					InterpolationNode {
						val := eval_expr(it.expr, env)!
						b.write_string(value_to_string(val))
					}
					else {}
				}
			}
			[CXLItem(CXLScalar{
				data_type: .string_type
				value:     ScalarValue(b.str())
			})]
		}
		else { error('cxl: filter arg slot cannot be ${typeof(n).name}') }
	}
}

// cxl_expr_has_operator reports whether a TextNode token contains a
// CXPath comparison / arithmetic operator — used to distinguish
// expression slots (`@stock > 0`) from bare literal-text slots
// (`hello world`). Heuristic; a more rigorous parser-level marker
// is deferred to CXL 3.1.
fn cxl_expr_has_operator(s string) bool {
	if s.contains(' > ') || s.contains(' < ') || s.contains(' = ')
		|| s.contains(' >= ') || s.contains(' <= ') || s.contains(' != ')
		|| s.contains(' == ') {
		return true
	}
	return false
}

fn filter_upper(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s.to_upper()) })]
}

fn filter_lower(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s.to_lower()) })]
}

fn filter_trim(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s.trim_space()) })]
}

fn filter_length(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len != 1 {
		return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(v.len)) })]
	}
	s := value_to_string(v)
	return [CXLItem(CXLScalar{ data_type: .int_type, value: ScalarValue(i64(s.runes().len)) })]
}

fn filter_concat(args []CXLValue) !CXLValue {
	mut b := strings.new_builder(32)
	for a in args { b.write_string(value_to_string(a)) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(b.str()) })]
}

fn filter_join(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cxl: [?join [SEP, XS]] needs 2 args')
	}
	sep := value_to_string(args[0])
	xs  := args[1]
	mut parts := []string{}
	for it in xs { parts << item_to_text(it) }
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(parts.join(sep)) })]
}

fn filter_replace(args []CXLValue) !CXLValue {
	if args.len < 3 {
		return error('cxl: [?replace [OLD, NEW, X]] needs 3 args')
	}
	old_s := value_to_string(args[0])
	new_s := value_to_string(args[1])
	x     := value_to_string(args[2])
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(x.replace(old_s, new_s)) })]
}

fn filter_default(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cxl: [?default [X, D]] needs 2 args')
	}
	if value_is_empty_or_null(args[0]) { return args[1] }
	return args[0]
}

fn filter_escape_html(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(escape_html_str(s)) })]
}

fn filter_escape_url(args []CXLValue) !CXLValue {
	s := value_to_string(args_first(args)!)
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(escape_url_component(s)) })]
}

fn filter_raw(args []CXLValue) !CXLValue {
	return args_first(args)!
}

fn filter_first(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len == 0 { return CXLValue([]CXLItem{}) }
	return [v[0]]
}

fn filter_rest(args []CXLValue) !CXLValue {
	v := args_first(args)!
	if v.len <= 1 { return CXLValue([]CXLItem{}) }
	return v[1..]
}

fn filter_empty(args []CXLValue) !CXLValue {
	v := args_first(args)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(v.len == 0) })]
}

fn filter_reverse(args []CXLValue) !CXLValue {
	v := args_first(args)!.clone()
	mut out := []CXLItem{cap: v.len}
	for i := v.len - 1; i >= 0; i-- { out << v[i] }
	return out
}

fn args_first(args []CXLValue) !CXLValue {
	if args.len == 0 {
		return error('cxl: filter expected at least one argument')
	}
	return args[0]
}

// ── Helpers — EBV, scalar emission, escape ───────────────────────────────────

fn value_ebv(v CXLValue) bool {
	if v.len == 0 { return false }
	if v.len > 1 { return true }
	it := v[0]
	return match it {
		CXLScalar {
			match it.data_type {
				.bool_type     { (it.value as bool) }
				.string_type   { (it.value as string).len > 0 }
				.int_type      { (it.value as i64) != 0 }
				.float_type    { f := (it.value as f64); f != 0.0 }
				.null_type     { false }
				.date_type, .datetime_type, .bytes_type, .decimal_type, .bigint_type { true }
			}
		}
		ScalarNode {
			match it.data_type {
				.bool_type     { (it.value as bool) }
				.string_type   { (it.value as string).len > 0 }
				.int_type      { (it.value as i64) != 0 }
				.null_type     { false }
				else           { true }
			}
		}
		else { true } // Node existence is truthy per cxdm.md §4.5
	}
}

fn value_to_string(v CXLValue) string {
	if v.len == 0 { return '' }
	mut b := strings.new_builder(16)
	for it in v { b.write_string(item_to_text(it)) }
	return b.str()
}

fn value_is_empty_or_null(v CXLValue) bool {
	if v.len == 0 { return true }
	for it in v {
		match it {
			CXLScalar {
				if it.data_type == .null_type { continue }
				if it.data_type == .string_type && (it.value as string).len == 0 { continue }
				return false
			}
			else { return false }
		}
	}
	return true
}

fn escape_html_str(s string) string {
	mut b := strings.new_builder(s.len + 8)
	for c in s {
		match c {
			`&` { b.write_string('&amp;') }
			`<` { b.write_string('&lt;') }
			`>` { b.write_string('&gt;') }
			`"` { b.write_string('&quot;') }
			`'` { b.write_string('&#39;') }
			else { b.write_u8(c) }
		}
	}
	return b.str()
}

fn escape_url_component(s string) string {
	mut b := strings.new_builder(s.len)
	for c in s.bytes() {
		match true {
			(c >= `0` && c <= `9`),
			(c >= `A` && c <= `Z`),
			(c >= `a` && c <= `z`),
			c == `-`, c == `_`, c == `.`, c == `~` {
				b.write_u8(c)
			}
			else {
				b.write_string('%')
				b.write_string(c.hex().to_upper())
			}
		}
	}
	return b.str()
}

// ── CXL expression evaluator ─────────────────────────────────────────────────
//
// CXL 1.0 expressions are CXPath plus three extensions documented in
// spec/cxl.md §3.1 / §7 / §8 examples:
//   - bare `@name`                  → attribute on current context
//   - `path/@name`                  → CXPath select, then @name on each
//   - bare child name `description` → child element(s) of context
//   - top-level comparison `LHS OP RHS` → bool for [?if] tests
//   - bare variable reference `v`   → loop variable lookup
//   - `v/sub/path` and `v/@attr`    → variable as context root
//
// Numeric / string literals on the RHS of comparisons follow CX auto-
// typing (cxpath_autotype). String literals MAY be single-quoted.
//
// This is a pragmatic v0.6.0 implementation; the full XQuery-style
// expression grammar lands at CXL 3.1+.

fn eval_expr(expr_in string, env CXLEnv) !CXLValue {
	expr := expr_in.trim_space()
	if expr == '' { return CXLValue([]CXLItem{}) }
	// Nested directive call inside an Interpolation body, e.g.
	// `[?=[?upper [@name]]]` — the captured Interpolation body is
	// opaque text per parse_interpolation; to evaluate the nested
	// call we re-parse the fragment as a CX document and dispatch
	// the resulting EvalDirectiveNode.
	if expr.starts_with('[?') && expr.ends_with(']') {
		return eval_nested_directive_value(expr, env)!
	}
	// Top-level comparison operator outside brackets → boolean test.
	if op_pos := find_top_level_comparison(expr) {
		return eval_comparison(expr, op_pos, env)!
	}
	return eval_path_expr(expr, env)!
}

fn eval_nested_directive_value(expr string, env CXLEnv) !CXLValue {
	frag := parse(expr) or {
		return error('cxl: nested directive parse failed: ${err.msg()}')
	}
	for n in frag.elements {
		match n {
			EvalDirectiveNode { return eval_filter_directive(n, env)! }
			InterpolationNode { return eval_expr(n.expr, env)! }
			else {}
		}
	}
	for n in frag.prolog {
		match n {
			EvalDirectiveNode { return eval_filter_directive(n, env)! }
			InterpolationNode { return eval_expr(n.expr, env)! }
			else {}
		}
	}
	return error('cxl: nested directive expression empty: "${expr}"')
}

// find_top_level_comparison returns the byte index of the operator
// (first byte of `>`, `<`, `=`, `!`) when an unbracketed comparison
// operator appears at top level.
fn find_top_level_comparison(s string) ?int {
	mut depth := 0
	mut i := 0
	for i < s.len {
		c := s[i]
		if c == `[` || c == `(` { depth++ }
		else if c == `]` || c == `)` { depth-- }
		else if depth == 0 {
			if c == `>` || c == `<` { return i }
			if c == `=` { return i }
			if c == `!` && i + 1 < s.len && s[i+1] == `=` { return i }
		}
		i++
	}
	return none
}

fn eval_comparison(expr string, op_pos int, env CXLEnv) !CXLValue {
	mut op_len := 1
	mut op := expr[op_pos..op_pos + 1]
	if op_pos + 1 < expr.len {
		next := expr[op_pos + 1]
		if (op == '>' || op == '<' || op == '!' || op == '=') && next == `=` {
			op = expr[op_pos..op_pos + 2]
			op_len = 2
		}
	}
	lhs := expr[..op_pos].trim_space()
	rhs := expr[op_pos + op_len..].trim_space()
	left  := eval_path_expr(lhs, env)!
	right := parse_rhs_literal(rhs, env)!
	b := compare_values(left, op, right)!
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(b) })]
}

fn parse_rhs_literal(rhs string, env CXLEnv) !CXLValue {
	if rhs.len > 0 && (rhs[0] == `@` || rhs[0] == `/` || rhs[0] == `'`) {
		if rhs[0] == `'` {
			s := rhs.trim('\'')
			return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(s) })]
		}
		return eval_path_expr(rhs, env)!
	}
	sv := cxpath_autotype(rhs)
	ty := scalar_type_of(sv)
	return [CXLItem(CXLScalar{ data_type: ty, value: sv })]
}

fn scalar_type_of(v ScalarValue) ScalarType {
	return match v {
		bool      { ScalarType.bool_type }
		i64       { ScalarType.int_type }
		f64       { ScalarType.float_type }
		string    { ScalarType.string_type }
		NullValue { ScalarType.null_type }
	}
}

fn compare_values(left CXLValue, op string, right CXLValue) !bool {
	if left.len == 0 || right.len == 0 {
		return op == '!=' && (left.len != right.len)
	}
	lv := item_to_scalar(left[0]) or { return error('cxl: lhs is not a scalar') }
	rv := item_to_scalar(right[0]) or { return error('cxl: rhs is not a scalar') }
	return scalar_compare(lv, op, rv)
}

fn item_to_scalar(it CXLItem) ?ScalarValue {
	return match it {
		CXLScalar  { it.value }
		ScalarNode { it.value }
		TextNode   { ScalarValue(it.value) }
		Element    { ScalarValue(element_text_content(it)) }
		else       { none }
	}
}

fn scalar_compare(l ScalarValue, op string, r ScalarValue) !bool {
	if l is i64 && r is i64 {
		li := l as i64
		ri := r as i64
		return match op {
			'=', '==' { li == ri }
			'!='      { li != ri }
			'<'       { li < ri }
			'<='      { li <= ri }
			'>'       { li > ri }
			'>='      { li >= ri }
			else      { error('cxl: unknown comparison op ${op}') }
		}
	}
	if (l is i64 || l is f64) && (r is i64 || r is f64) {
		lf := as_f64(l)
		rf := as_f64(r)
		return match op {
			'=', '==' { lf == rf }
			'!='      { lf != rf }
			'<'       { lf < rf }
			'<='      { lf <= rf }
			'>'       { lf > rf }
			'>='      { lf >= rf }
			else      { error('cxl: unknown comparison op ${op}') }
		}
	}
	if l is string && r is string {
		ls := l as string
		rs := r as string
		return match op {
			'=', '==' { ls == rs }
			'!='      { ls != rs }
			else      { error('cxl: string comparison only supports = and != (got ${op})') }
		}
	}
	if l is bool && r is bool {
		lb := l as bool
		rb := r as bool
		return match op {
			'=', '==' { lb == rb }
			'!='      { lb != rb }
			else      { error('cxl: bool comparison only supports = and != (got ${op})') }
		}
	}
	if op == '=' || op == '==' { return false }
	if op == '!=' { return true }
	return error('cxl: cannot order-compare values of incompatible types')
}

fn as_f64(v ScalarValue) f64 {
	return match v {
		i64       { f64(v) }
		f64       { v }
		string    { strconv.atof64(v) or { 0.0 } }
		bool      { if v { 1.0 } else { 0.0 } }
		NullValue { 0.0 }
	}
}

// ── Path expression evaluation ───────────────────────────────────────────────

fn eval_path_expr(expr string, env CXLEnv) !CXLValue {
	// 1. variable reference: leading word + optional '/'
	if expr.len > 0 && is_ident_start(expr[0]) {
		mut end := 0
		for end < expr.len && is_ident_cont(expr[end]) { end++ }
		head := expr[..end]
		if head in env.bindings {
			rest := expr[end..]
			return eval_path_from_value(env.bindings[head], rest, env)!
		}
	}
	// 2. attribute access on context
	if expr.starts_with('@') {
		return eval_attr_access(env.context, expr[1..])!
	}
	// 3. trailing /@attr → CXPath select + attribute access
	if at := expr.last_index('/@') {
		path_part := expr[..at]
		attr_part := expr[at + 2..]
		base := eval_cxpath_against(env.context, path_part)!
		return eval_attr_access(base, attr_part)!
	}
	// 4. plain CXPath path
	return eval_cxpath_against(env.context, expr)!
}

fn eval_path_from_value(base CXLValue, rest string, env CXLEnv) !CXLValue {
	_ = env
	if rest == '' { return base }
	if rest.starts_with('/@') { return eval_attr_access(base, rest[2..])! }
	if rest.starts_with('/')  { return eval_cxpath_against(base, rest[1..])! }
	if rest.starts_with('@')  { return eval_attr_access(base, rest[1..])! }
	return error('cxl: malformed variable continuation "${rest}"')
}

fn eval_attr_access(ctx CXLValue, attr_query string) !CXLValue {
	mut out := []CXLItem{}
	for it in ctx {
		if it is Element {
			if v := cxpath_attr_lookup(it, attr_query, map[string]string{}) {
				out << CXLItem(CXLScalar{
					data_type: cxl_attr_type(it, attr_query)
					value:     v
				})
			}
		}
	}
	return out
}

fn cxl_attr_type(el Element, attr_query string) ScalarType {
	for a in el.attrs {
		if a.name == attr_query {
			if dt := a.data_type { return dt }
			return .string_type
		}
	}
	return .string_type
}

// eval_cxpath_against runs a CXPath-style path against the items in
// ctx. For each Element item we invoke `el.select_all(path)`. The path
// may be a CXPath expression (e.g. `//variant[@stock > 0]`) or a bare
// child-name (`description`).
fn eval_cxpath_against(ctx CXLValue, path string) !CXLValue {
	mut out := []CXLItem{}
	p := path.trim_space()
	if p == '' { return ctx }
	for it in ctx {
		if it is Element {
			els := it.select_all(p)
			for el in els { out << CXLItem(el) }
		}
	}
	return out
}

fn is_ident_start(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || c == `_`
}

fn is_ident_cont(c u8) bool {
	return is_ident_start(c) || (c >= `0` && c <= `9`) || c == `-`
}

// bare_ident_is_bound reports whether `t` is a CXPath-shaped identifier-
// or-path expression whose leading identifier is currently bound in
// env.bindings (a `?for` loop var, `?with` context binding, or `?def`
// template parameter). Used by eval_slot_to_value to distinguish
// variable references (resolve via eval_expr) from literal strings
// in filter/template-call arguments.
fn bare_ident_is_bound(t string, env CXLEnv) bool {
	if t.len == 0 { return false }
	if !is_ident_start(t[0]) { return false }
	mut end := 0
	for end < t.len && is_ident_cont(t[end]) { end++ }
	head := t[..end]
	if head == '' { return false }
	return head in env.bindings
}
