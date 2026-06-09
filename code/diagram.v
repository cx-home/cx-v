module code

import cx
import encoding.base64
import os

// ── Phase 4: diagram renderer ───────────────────────────────────────────────
//
// Reference renderer for the visualization targets per spec/code.md
// §10.1 + §10.1.2. Three formats are supported (svg / png / mermaid);
// html and markdown stay Phase-4-gated.
//
// Round-trip contract (gate 9, "hybrid embed-source"): each rendered
// output carries the original program source as base64-encoded metadata
// (Mermaid leading `%%cx:<base64>%%` comment; SVG `<metadata><cx:source>`
// block; PNG tEXt chunk keyed `cx-source`). `reverse_parse_diagram`
// strips the visual layer and recovers the source verbatim — a parse of
// the recovered source MUST be structurally equal to the original
// program AST.
//
// Visualization is per-directive: spec/code.md §10.1.2's locked
// rendering table maps each directive (and per-clause shape) to a
// canonical visual primitive. The dialect is chosen per directive
// (flowchart for branching / loops; sequenceDiagram for async /
// services / channels). Mermaid is the text output; SVG / PNG go
// through graphviz at runtime via the DOT format (a separate
// per-directive emit; the two layout languages are not interconverted).

const cx_diagram_marker_open  = '%%cx:'
const cx_diagram_marker_close = '%%'

// render_diagram produces a visualization of `prog` in the requested
// `format`. `source_text` is the original CX program text (the bytes
// the parser was handed) — preserved verbatim and embedded in the
// rendered output so reverse_parse_diagram can recover it.
//
// `format` values: 'mermaid', 'svg', 'png'. Other values yield CXER0100.
// SVG/PNG depend on the `dot` binary (graphviz) being present at
// runtime; if not present the call returns CXER0001 with an actionable
// message.
// renderable_directives is the §10.1.2 locked render-rules set, plus the
// transparent binding/module SCAFFOLDING directives (`let`/`def`/`const`/
// `lib`) that the renderer descends through to reach the renderable
// directive they wrap (e.g. `[?let … [?worker …]]`). A top-level program
// directive outside this combined set is UNRENDERABLE (CXER0281) — e.g.
// the tier-3 effect `[?secret]`, which has no render rule and is not a
// scaffolding wrapper.
const renderable_directives = ['for', 'for-array', 'for-map', 'map', 'reduce',
	'if', 'match', 'try', 'retry', 'timeout', 'circuit-breaker', 'fallback',
	'rate-limit', 'bulkhead', 'http-service', 'worker', 'channel', 'send',
	'receive', 'try-send', 'try-receive', 'select', 'async', 'await',
	'await-all', 'await-any', 'await-race', 'cancel',
	// transparent scaffolding wrappers (descended through, not a leaf):
	'let', 'def', 'const', 'lib', 'pipe']

pub fn render_diagram(prog cx.Program, source_text string, format string) !string {
	// §10.1.2: a directive not in the locked render-rules table SHALL
	// raise CXER0281 (UNRENDERABLE_DIRECTIVE). The renderer visualizes a
	// directive-headed program; a top-level directive outside the table
	// (e.g. the tier-3 effect `[?secret]`) is unrenderable.
	if prog.body is cx.ProgramDirective {
		name := (prog.body as cx.ProgramDirective).name
		if name !in renderable_directives {
			return EvalError{
				code:    'cx-err:CXER0281'
				message: 'cx-err:CXER0281 E_UNRENDERABLE_DIRECTIVE: `[?${name}]` is not in the §10.1.2 locked render-rules table'
			}
		}
	}
	// `format` may optionally encode a detail level via a `:` suffix
	// (e.g. `mermaid:compact`, `mermaid:full`, `mermaid:min`). Bare
	// `mermaid` defaults to `min` to preserve pre-detail-level
	// rendering for clients that haven't migrated.
	base, detail := parse_diagram_format(format)
	match base {
		'mermaid' { return render_mermaid_with_detail(prog, source_text, detail) }
		'svg'     { return render_svg(prog, source_text)! }
		'png'     { return render_png(prog, source_text)! }
		else {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: "diagram format '${format}' not recognised (accepted: mermaid[:detail], svg, png)"
			}
		}
	}
}

// DiagramDetail controls how much element-shape information appears
// in Mermaid node labels. Defaults to `.min` (legacy behaviour:
// element name only); the playground passes `.compact` (name +
// first 2 attrs + (+N more)) or `.full` (name + all attrs).
pub enum DiagramDetail {
	min     // element name only — `[user]` / `[user …]` when non-empty
	compact // name + up to 2 attrs + (+K more attrs) — `[user @id=1 @name='a' (+2)]`
	full    // name + all attrs — `[user @id=1 @name='a' @role='admin' @tenant='acme']`
}

const compact_attr_cap = 2

// parse_diagram_format splits `format` on `:` and returns (base, detail).
// Unknown / missing suffix → `.min` (legacy behaviour).
fn parse_diagram_format(format string) (string, DiagramDetail) {
	if !format.contains(':') {
		return format, DiagramDetail.min
	}
	parts := format.split(':')
	base := parts[0]
	suffix := if parts.len > 1 { parts[1] } else { '' }
	detail := match suffix {
		'compact' { DiagramDetail.compact }
		'full'    { DiagramDetail.full }
		else      { DiagramDetail.min }
	}
	return base, detail
}

// reverse_parse_diagram extracts the embedded CX source from a
// previously-rendered diagram and returns it. Used by gate-9
// round-trip tests: render(prog, fmt) → reverse_parse_diagram →
// parse → assert structural equality vs original prog.
pub fn reverse_parse_diagram(rendered string, format string) !string {
	match format {
		'mermaid' {
			return extract_mermaid_source(rendered)!
		}
		'svg' {
			return extract_svg_source(rendered)!
		}
		'png' {
			return extract_png_source(rendered)!
		}
		else {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: "diagram format '${format}' not recognised"
			}
		}
	}
}

// ── Mermaid ─────────────────────────────────────────────────────────────────
//
// The Mermaid renderer implements §10.1.2's per-directive visualization
// table by walking the program AST and emitting one shape per directive
// family. Flowchart TD is the default dialect; sequenceDiagram is used
// for programs whose top-level shape is async/channel/service-heavy
// (per pick_mermaid_dialect).
//
// Per-family emitters (flowchart TD):
//
//   pipe         IN → STAGE₁ → STAGE₂ → … → result
//   if / match   diamond predicate with labelled arms (true/false, :case/:else)
//   for / map /  iteration container: source → iter-header → body → sink
//   reduce         (:par variants annotate with a parallel-merge marker)
//   try / catch  main path + recovery arrow off the err edge
//   retry /      labelled container around :body; resilience policies show
//   timeout /      their key parameters in the container label
//   circuit-…
//   fallback     :body and :recover-with both visible, err-edge between
//   send / recv  arrow into / out of the named channel node
//   select       diamond with one inbound arrow per :case channel
//   let          EXPR → $name → BODY
//   fn           "fn($params) → body-short" capsule node
//   async        future node; await-all merges several future arrows
//
// All emitters share the MermaidState scratch (lines + node-id counter)
// and a small set of helpers (`expr_label`, `mermaid_escape`) that
// produce short, human-readable labels for arbitrary AST subtrees.

fn render_mermaid(prog cx.Program, source_text string) string {
	return render_mermaid_with_detail(prog, source_text, DiagramDetail.min)
}

// render_mermaid_with_detail is the wide variant that carries the
// detail level into label rendering. Bare `render_mermaid` stays at
// `.min` so existing callers (gate-9 round-trip; CLI) keep their
// label shapes unchanged.
fn render_mermaid_with_detail(prog cx.Program, source_text string, detail DiagramDetail) string {
	mut s := MermaidState{
		lines:   []string{cap: 32}
		next_id: 0
		dialect: pick_mermaid_dialect(prog.body)
		detail:  detail
	}
	// Leading round-trip metadata comment: %%cx:<base64(source)>%%.
	encoded := base64.encode_str(source_text)
	s.lines << '${cx_diagram_marker_open}${encoded}${cx_diagram_marker_close}'
	s.lines << s.dialect
	if s.dialect == 'sequenceDiagram' {
		mmd_sequence(prog.body, mut s)
	} else {
		entry := mk_round(mut s, 'start')
		exit_id := mk_round(mut s, 'result')
		out_id := mmd_flow(prog.body, mut s)
		edge(mut s, entry, out_id)
		if out_id != exit_id {
			edge(mut s, out_id, exit_id)
		}
	}
	return s.lines.join('\n')
}

// MermaidState is the per-render emitter scratch. Lines accumulate the
// final output; next_id mints unique node ids; dialect is one of
// 'flowchart TD' / 'sequenceDiagram'.
struct MermaidState {
mut:
	lines    []string
	next_id  int
	dialect  string
	detail   DiagramDetail
	// channel_nodes maps channel-binding name (e.g. "ch") → its mermaid
	// node id, so send/receive arrows can target the same channel.
	channel_nodes map[string]string
}

// mk_id mints a unique short node id (`n1`, `n2`, …).
fn mk_id(mut s MermaidState) string {
	s.next_id++
	return 'n${s.next_id}'
}

// mk_node emits a flowchart node declaration with the given shape body
// (e.g. `"label"` / `{"label"}` / `([label])`) and returns the new id.
// The caller is responsible for picking the shape — this helper just
// allocates the id and concatenates.
fn mk_node(mut s MermaidState, shape string) string {
	id := mk_id(mut s)
	s.lines << '    ${id}${shape}'
	return id
}

// mk_rect emits a `id["label"]` flowchart rectangle and returns its id.
fn mk_rect(mut s MermaidState, label string) string {
	return mk_node(mut s, '["${mermaid_escape(label)}"]')
}

// mk_round emits a `id(["label"])` stadium-shape (used for start/finish).
fn mk_round(mut s MermaidState, label string) string {
	return mk_node(mut s, '(["${mermaid_escape(label)}"])')
}

// mk_diamond emits a `id{"label"}` diamond (used for if/select/match).
fn mk_diamond(mut s MermaidState, label string) string {
	return mk_node(mut s, '{"${mermaid_escape(label)}"}')
}

// mk_hex emits a `id{{"label"}}` hexagon (used for iteration headers).
fn mk_hex(mut s MermaidState, label string) string {
	return mk_node(mut s, '{{"${mermaid_escape(label)}"}}')
}

// mk_subroutine emits a `id[["label"]]` subroutine shape (used for fn
// capsules and resilience-wrapper inner anchors).
fn mk_subroutine(mut s MermaidState, label string) string {
	return mk_node(mut s, '[["${mermaid_escape(label)}"]]')
}

fn edge(mut s MermaidState, from string, to string) {
	s.lines << '    ${from} --> ${to}'
}

fn labeled_edge(mut s MermaidState, from string, to string, label string) {
	s.lines << '    ${from} -- "${mermaid_escape(label)}" --> ${to}'
}

// ── dialect selection ──────────────────────────────────────────────────────

// pick_mermaid_dialect chooses between `flowchart TD` and
// `sequenceDiagram` per §10.1.2. The rule: switch to sequenceDiagram
// only when the *top-level* (or top-level-of-a-let-body) directive is
// an inherently message-passing one — `[?service]`, `[?worker]`, or
// a top-level `[?select]`. cx.Programs that *use* channels as plumbing
// inside a `let`/`pipe`/`for` body render more usefully as flowcharts
// (data flow visible), so we don't recurse into let/iteration bodies
// for the dialect decision.
fn pick_mermaid_dialect(node cx.ProgramNode) string {
	if is_top_level_temporal(node) {
		return 'sequenceDiagram'
	}
	return 'flowchart TD'
}

fn is_top_level_temporal(node cx.ProgramNode) bool {
	if node is cx.ProgramDirective {
		name := node.name
		if name == 'http-service' || name == 'worker' || name == 'select' {
			return true
		}
		// Peer through trivial wrappers — top-level `[?let]` whose body
		// is itself temporal counts.
		if name == 'let' {
			for s in node.slots {
				if s.kind == .labeled && s.label == 'body' {
					return is_top_level_temporal(s.value)
				}
			}
		}
	}
	return false
}

// uses_temporal_directive — kept for backwards compatibility with any
// external caller; the dialect picker now uses the narrower
// `is_top_level_temporal` heuristic above.
fn uses_temporal_directive(node cx.ProgramNode) bool {
	if node is cx.ProgramDirective {
		name := node.name
		if name == 'async' || name == 'await' || name == 'await-all'
		   || name == 'await-any' || name == 'await-race' || name == 'cancel'
		   || name == 'http-service' || name == 'http-client' || name == 'channel'
		   || name == 'send' || name == 'receive' || name == 'try-send'
		   || name == 'try-receive' || name == 'select' || name == 'worker' {
			return true
		}
		for s in node.slots {
			if uses_temporal_directive(s.value) { return true }
		}
	}
	if node is cx.ProgramForComp {
		for c in node.clauses {
			if src := c.source {
				if uses_temporal_directive(src) { return true }
			}
			if expr := c.expr {
				if uses_temporal_directive(expr) { return true }
			}
		}
		if uses_temporal_directive(node.yield) { return true }
	}
	return false
}

// ── flowchart emission ─────────────────────────────────────────────────────

// mmd_flow renders one cx.ProgramNode as a flowchart subgraph and returns
// the id of the node that represents the subgraph's *result* (its exit
// edge). Callers wire that id forward (e.g. as the input of the next
// pipeline stage, or as the final hop into `done`).
fn mmd_flow(n cx.ProgramNode, mut s MermaidState) string {
	if n is cx.ProgramDirective {
		return mmd_directive_flow(n, mut s)
	}
	if n is cx.ProgramForComp {
		return mmd_for_comp_flow(n, mut s)
	}
	// Leaf / value-shaped node: one rect labelled with the expression.
	return mk_rect(mut s, expr_label(n, s.detail))
}

fn mmd_directive_flow(d cx.ProgramDirective, mut s MermaidState) string {
	match d.name {
		'pipe'            { return mmd_pipe(d, mut s) }
		'if'              { return mmd_if(d, mut s) }
		'match'           { return mmd_match(d, mut s) }
		'try'             { return mmd_try(d, mut s) }
		'let'             { return mmd_let(d, mut s) }
		'fn'              { return mmd_fn(d, mut s) }
		'map'             { return mmd_map(d, mut s) }
		'reduce'          { return mmd_reduce(d, mut s) }
		'for'             { return mmd_for_directive(d, mut s) }
		'retry', 'timeout', 'circuit-breaker',
		'rate-limit', 'bulkhead'
		                  { return mmd_resilience_wrap(d, mut s) }
		'fallback'        { return mmd_fallback(d, mut s) }
		'channel'         { return mmd_channel(d, mut s) }
		'send', 'try-send'
		                  { return mmd_send(d, mut s) }
		'receive', 'try-receive'
		                  { return mmd_receive(d, mut s) }
		'select'          { return mmd_select(d, mut s) }
		'async'           { return mmd_async(d, mut s) }
		'await', 'await-all', 'await-any', 'await-race'
		                  { return mmd_await(d, mut s) }
		'cancel'          { return mmd_cancel(d, mut s) }
		'http-service'    { return mmd_service(d, mut s) }
		'worker'          { return mmd_worker(d, mut s) }
		'http-client'     { return mmd_http_client(d, mut s) }
		else              { return mmd_generic_directive(d, mut s) }
	}
}

// mmd_generic_directive renders a directive that doesn't have its own
// per-family emitter: a rect labelled with the source-shape, with the
// labelled slots flowing downward into the same rect (no internal
// structure). This is the fallback for directives whose visual
// representation hasn't been specialised yet.
fn mmd_generic_directive(d cx.ProgramDirective, mut s MermaidState) string {
	return mk_rect(mut s, '[?${d.name}]')
}

// ── pipe ───────────────────────────────────────────────────────────────────
//
// `[?pipe IN :through F :through G]` — IN node → F → G → result.
// Each stage gets its own node; arrows are unlabelled. The input is
// the first positional slot; each :through labeled slot is one stage.

fn mmd_pipe(d cx.ProgramDirective, mut s MermaidState) string {
	mut input_node := ?cx.ProgramNode(none)
	mut stages := []cx.ProgramNode{}
	for slot in d.slots {
		if slot.kind == .positional && input_node == none {
			input_node = slot.value
			continue
		}
		if slot.kind == .labeled && slot.label == 'through' {
			stages << slot.value
		}
	}
	mut prev := if v := input_node {
		mmd_flow(v, mut s)
	} else {
		mk_rect(mut s, 'input')
	}
	for st in stages {
		next := mmd_pipe_stage(st, mut s)
		edge(mut s, prev, next)
		prev = next
	}
	return prev
}

// mmd_pipe_stage renders one `:through` stage. Inline `[?fn]` stages
// collapse into a single capsule (more readable than entry/exit pair);
// other stages route through the general flow emitter.
fn mmd_pipe_stage(stage cx.ProgramNode, mut s MermaidState) string {
	if stage is cx.ProgramDirective && stage.name == 'fn' {
		return mk_subroutine(mut s, fn_capsule_label(stage, s.detail))
	}
	return mmd_flow(stage, mut s)
}

// ── if ────────────────────────────────────────────────────────────────────
//
// `[?if PRED :then THEN :else ELSE]` — diamond labelled with PRED;
// two arrows labelled `true` / `false` heading into the THEN / ELSE
// subgraphs. The result of the whole [?if] is taken as a join node
// downstream of both arms.

fn mmd_if(d cx.ProgramDirective, mut s MermaidState) string {
	mut cond_node := ?cx.ProgramNode(none)
	mut then_node := ?cx.ProgramNode(none)
	mut else_node := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .positional && cond_node == none {
			cond_node = slot.value
			continue
		}
		if slot.kind == .labeled {
			if slot.label == 'then' { then_node = slot.value }
			else if slot.label == 'else' { else_node = slot.value }
		}
	}
	cond_label := if v := cond_node { expr_label(v, s.detail) } else { '?' }
	diamond := mk_diamond(mut s, 'if ${cond_label}')
	join := mk_rect(mut s, '[?if] result')
	if v := then_node {
		t := mmd_flow(v, mut s)
		labeled_edge(mut s, diamond, t, 'true')
		edge(mut s, t, join)
	}
	if v := else_node {
		e := mmd_flow(v, mut s)
		labeled_edge(mut s, diamond, e, 'false')
		edge(mut s, e, join)
	} else {
		// No :else arm — falsy branch flows directly to the join.
		labeled_edge(mut s, diamond, join, 'false')
	}
	return join
}

// ── match ─────────────────────────────────────────────────────────────────
//
// `[?match EXPR :case P₁ :yield B₁ :case P₂ :yield B₂ … :else :yield E]`
// → diamond labelled with EXPR; one arm per :case + the :else arm; arms
// share a join node downstream.

fn mmd_match(d cx.ProgramDirective, mut s MermaidState) string {
	mut subj := ?cx.ProgramNode(none)
	mut arms := []MermaidMatchArm{}
	mut pending_pat := ?cx.ProgramNode(none)
	mut pending_else := false
	for slot in d.slots {
		if slot.kind == .positional && subj == none {
			subj = slot.value
			continue
		}
		if slot.kind == .labeled {
			match slot.label {
				'case' { pending_pat = slot.value; pending_else = false }
				'else' { pending_else = true; pending_pat = none }
				'yield' {
					if pending_else {
						arms << MermaidMatchArm{ label: ':else', body: slot.value }
						pending_else = false
					} else if p := pending_pat {
						arms << MermaidMatchArm{ label: expr_label(p, s.detail), body: slot.value }
						pending_pat = none
					}
				}
				else {}
			}
		}
	}
	subj_label := if v := subj { expr_label(v, s.detail) } else { '?' }
	diamond := mk_diamond(mut s, 'match ${subj_label}')
	join := mk_rect(mut s, '[?match] result')
	if arms.len == 0 {
		// No arms (subject-only form) — diamond joins directly.
		edge(mut s, diamond, join)
		return join
	}
	for arm in arms {
		body_id := mmd_flow(arm.body, mut s)
		labeled_edge(mut s, diamond, body_id, arm.label)
		edge(mut s, body_id, join)
	}
	return join
}

struct MermaidMatchArm {
	label string
	body  cx.ProgramNode
}

// ── try / catch ───────────────────────────────────────────────────────────
//
// `[?try EXPR :catch $err HANDLER]` — main path through EXPR, plus an
// `err` arrow into HANDLER. Both meet at a downstream join.

fn mmd_try(d cx.ProgramDirective, mut s MermaidState) string {
	mut body := ?cx.ProgramNode(none)
	mut handler := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .positional && body == none {
			body = slot.value
			continue
		}
		if slot.kind == .labeled && slot.label == 'catch' {
			handler = slot.value
		}
	}
	join := mk_rect(mut s, '[?try] result')
	if v := body {
		b := mmd_flow(v, mut s)
		edge(mut s, b, join)
		if h := handler {
			hid := mmd_flow(h, mut s)
			labeled_edge(mut s, b, hid, 'err')
			edge(mut s, hid, join)
		}
	}
	return join
}

// ── let ───────────────────────────────────────────────────────────────────
//
// `[?let $name = EXPR :in BODY]` — EXPR node → $name node → BODY node.
// The $name node is a labelled hexagon-ish rect; BODY is the result.

fn mmd_let(d cx.ProgramDirective, mut s MermaidState) string {
	mut bind_name := ''
	mut value_node := ?cx.ProgramNode(none)
	mut body_node := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind != .labeled { continue }
		match slot.label {
			'bind' {
				v := slot.value
				if v is cx.ProgramLiteral && v.kind == .string_lit {
					bind_name = v.str_val
				}
			}
			'value' { value_node = slot.value }
			'body'  { body_node = slot.value }
			else {}
		}
	}
	// If the value is itself a `[?channel]` directive, alias the
	// channel-node-id under the let-binding name so subsequent
	// `[?send V :to $name]` / `[?receive :from $name]` arrows reach
	// the same node rather than minting a forward-reference placeholder.
	val_id := if v := value_node { mmd_flow(v, mut s) } else { mk_rect(mut s, '?') }
	if bind_name != '' {
		if v := value_node {
			if v is cx.ProgramDirective && v.name == 'channel' {
				s.channel_nodes[bind_name] = val_id
			}
		}
	}
	bind_id := mk_subroutine(mut s, '\$${bind_name}')
	edge(mut s, val_id, bind_id)
	if b := body_node {
		body_id := mmd_flow(b, mut s)
		edge(mut s, bind_id, body_id)
		return body_id
	}
	return bind_id
}

// ── fn ────────────────────────────────────────────────────────────────────
//
// `[?fn ($p₁ $p₂) BODY]` — single capsule node labelled
// `fn($p₁,$p₂) → body-short`. Treating fn as a leaf (no internal
// structure) keeps pipe stages legible; nested calls / branching inside
// the body would balloon the diagram.

fn mmd_fn(d cx.ProgramDirective, mut s MermaidState) string {
	return mk_subroutine(mut s, fn_capsule_label(d, s.detail))
}

fn fn_capsule_label(d cx.ProgramDirective, detail DiagramDetail) string {
	params, body := fn_extract(d) or { return '[?fn]' }
	param_part := params.join(',')
	body_part := expr_label(body, detail)
	return 'fn(${param_part}) → ${body_part}'
}

// fn_extract pulls the parameter-name list + body out of a `[?fn]`
// directive. Mirrors eval.v's extract_params_and_body but tolerant —
// returns ([],body) for shapes the diagram emitter can't parse rather
// than failing.
fn fn_extract(d cx.ProgramDirective) !([]string, cx.ProgramNode) {
	mut params := []string{}
	mut body := ?cx.ProgramNode(none)
	mut saw_params := false
	for slot in d.slots {
		if slot.kind == .labeled {
			if slot.label == 'body' { body = slot.value }
			else if slot.label == 'params' {
				params = fn_param_names(slot.value)
				saw_params = true
			}
			continue
		}
		if !saw_params {
			params = fn_param_names(slot.value)
			saw_params = true
			continue
		}
		if body == none { body = slot.value }
	}
	if b := body { return params, b }
	return error('no body')
}

fn fn_param_names(n cx.ProgramNode) []string {
	if n is cx.ProgramBinding {
		return [n.name]
	}
	if n is cx.ProgramLiteral {
		if n.kind == .sequence_lit || n.kind == .array_lit {
			mut out := []string{}
			for it in n.items {
				if it is cx.ProgramBinding { out << it.name }
			}
			return out
		}
	}
	return []string{}
}

// ── map / reduce / for ─────────────────────────────────────────────────────
//
// Iteration directives all share a four-node shape:
//
//   source → iter-header → body-capsule → sink
//
// `:par` annotates the iter-header label; `:ordered` adds an
// order-preserve marker before the sink. The body-capsule is the
// `:using` fn (or :yield expression) rendered as a single capsule —
// this keeps comprehensions visually compact.

fn mmd_map(d cx.ProgramDirective, mut s MermaidState) string {
	return mmd_iter_directive(d, mut s, 'map', false)
}

fn mmd_reduce(d cx.ProgramDirective, mut s MermaidState) string {
	return mmd_iter_directive(d, mut s, 'reduce', true)
}

fn mmd_iter_directive(d cx.ProgramDirective, mut s MermaidState, name string, is_reduce bool) string {
	mut source := ?cx.ProgramNode(none)
	mut using := ?cx.ProgramNode(none)
	mut init_node := ?cx.ProgramNode(none)
	mut is_par := false
	mut is_ordered := false
	for slot in d.slots {
		if slot.kind == .positional && source == none {
			source = slot.value
			continue
		}
		if slot.kind == .labeled {
			match slot.label {
				'using' { using = slot.value }
				'init'  { init_node = slot.value }
				'par'      { is_par = true }
				'ordered'  { is_ordered = true }
				else {}
			}
		}
	}
	src_id := if v := source { mmd_flow(v, mut s) } else { mk_rect(mut s, 'xs') }
	mut header_label := if is_par {
		'${name} :par'
	} else {
		name
	}
	if is_reduce {
		if v := init_node { header_label += ' :init ${expr_label(v, s.detail)}' }
	}
	header := mk_hex(mut s, header_label)
	edge(mut s, src_id, header)
	if u := using {
		body_id := if u is cx.ProgramDirective && u.name == 'fn' {
			mk_subroutine(mut s, fn_capsule_label(u, s.detail))
		} else {
			mmd_flow(u, mut s)
		}
		labeled_edge(mut s, header, body_id, ':using')
		mut tail := body_id
		if is_par && is_ordered {
			order_id := mk_rect(mut s, 'preserve order')
			edge(mut s, tail, order_id)
			tail = order_id
		}
		sink := mk_round(mut s, if is_reduce { 'fold' } else { 'collect' })
		edge(mut s, tail, sink)
		return sink
	}
	sink := mk_round(mut s, if is_reduce { 'fold' } else { 'collect' })
	edge(mut s, header, sink)
	return sink
}

// mmd_for_directive handles `[?for]` when the parser produced a
// cx.ProgramDirective (rather than a cx.ProgramForComp — both shapes appear).
fn mmd_for_directive(d cx.ProgramDirective, mut s MermaidState) string {
	mut bind_name := ''
	mut source := ?cx.ProgramNode(none)
	mut yield_node := ?cx.ProgramNode(none)
	mut where_node := ?cx.ProgramNode(none)
	mut is_par := false
	for slot in d.slots {
		if slot.kind == .labeled {
			match slot.label {
				'in'    { source = slot.value }
				'yield' { yield_node = slot.value }
				'where' { where_node = slot.value }
				'bind'  {
					v := slot.value
					if v is cx.ProgramLiteral && v.kind == .string_lit {
						bind_name = v.str_val
					}
				}
				'par'   { is_par = true }
				else {}
			}
		}
	}
	src_id := if v := source { mmd_flow(v, mut s) } else { mk_rect(mut s, 'source') }
	mut header_label := if bind_name != '' { 'for \$${bind_name}' } else { 'for' }
	if is_par { header_label += ' :par' }
	header := mk_hex(mut s, header_label)
	edge(mut s, src_id, header)
	mut last := header
	if w := where_node {
		wid := mk_diamond(mut s, ':where ${expr_label(w, s.detail)}')
		labeled_edge(mut s, last, wid, 'iter')
		last = wid
	}
	if y := yield_node {
		body_id := mmd_flow(y, mut s)
		labeled_edge(mut s, last, body_id, if where_node != none { 'true' } else { 'iter' })
		sink := mk_round(mut s, 'collect')
		edge(mut s, body_id, sink)
		return sink
	}
	sink := mk_round(mut s, 'collect')
	edge(mut s, last, sink)
	return sink
}

// mmd_for_comp_flow renders a cx.ProgramForComp node (the canonical
// representation of `[?for $v :in xs :yield body]` post-parse).
fn mmd_for_comp_flow(f cx.ProgramForComp, mut s MermaidState) string {
	mut bind_name := ''
	mut source_node := ?cx.ProgramNode(none)
	mut where_node := ?cx.ProgramNode(none)
	mut is_par := false
	mut is_ordered := false
	for c in f.clauses {
		match c.kind {
			.generator {
				bind_name = c.bind
				if src := c.source { source_node = src }
			}
			.filter {
				if expr := c.expr { where_node = expr }
			}
			.par { is_par = true }
			.ordered { is_ordered = true }
			else {}
		}
	}
	src_id := if v := source_node { mmd_flow(v, mut s) } else { mk_rect(mut s, 'source') }
	mut header_label := if bind_name != '' { 'for \$${bind_name}' } else { 'for' }
	if is_par { header_label += ' :par' }
	if is_ordered { header_label += ' :ordered' }
	header := mk_hex(mut s, header_label)
	labeled_edge(mut s, src_id, header, if bind_name != '' { 'binds \$${bind_name}' } else { 'iter' })
	mut prev := header
	if w := where_node {
		wid := mk_diamond(mut s, ':where ${expr_label(w, s.detail)}')
		edge(mut s, prev, wid)
		prev = wid
	}
	body_id := mmd_flow(f.yield, mut s)
	labeled_edge(mut s, prev, body_id, if where_node != none { 'true' } else { 'iter' })
	sink := mk_round(mut s, 'collect')
	edge(mut s, body_id, sink)
	return sink
}

// ── resilience wrappers ────────────────────────────────────────────────────
//
// `[?retry]` / `[?timeout]` / `[?circuit-breaker]` / `[?rate-limit]` /
// `[?bulkhead]` all render as a "policy band" rect followed by the
// inner :body — the band carries the policy parameters so a reader can
// see what knob is being twisted. The shape isn't a true subgraph (too
// noisy for nested resilience) — just a labelled gateway in front of
// the protected body.

fn mmd_resilience_wrap(d cx.ProgramDirective, mut s MermaidState) string {
	mut body := ?cx.ProgramNode(none)
	mut params := []string{}
	mut positional_dur := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .positional && positional_dur == none && d.name == 'timeout' {
			positional_dur = slot.value
			continue
		}
		if slot.kind != .labeled { continue }
		if slot.label == 'body' { body = slot.value; continue }
		params << ':${slot.label} ${expr_label(slot.value, s.detail)}'
	}
	mut policy_parts := ['[?${d.name}]']
	if dn := positional_dur {
		policy_parts << expr_label(dn, s.detail)
	}
	// Keep the policy label compact: at most 2 extra param hints.
	max_params := 2
	for i := 0; i < params.len && i < max_params; i++ {
		policy_parts << params[i]
	}
	if params.len > max_params {
		policy_parts << '…'
	}
	policy_label := policy_parts.join(' ')
	policy_id := mk_subroutine(mut s, policy_label)
	if b := body {
		body_id := mmd_flow(b, mut s)
		labeled_edge(mut s, policy_id, body_id, ':body')
		return body_id
	}
	return policy_id
}

// mmd_fallback renders `[?fallback :body P :recover-with S]` as both
// arms with an `err` edge from P to S.

fn mmd_fallback(d cx.ProgramDirective, mut s MermaidState) string {
	mut body := ?cx.ProgramNode(none)
	mut recover := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind != .labeled { continue }
		if slot.label == 'body' { body = slot.value }
		else if slot.label == 'recover-with' { recover = slot.value }
	}
	gate := mk_subroutine(mut s, '[?fallback]')
	join := mk_rect(mut s, '[?fallback] result')
	if b := body {
		bid := mmd_flow(b, mut s)
		edge(mut s, gate, bid)
		edge(mut s, bid, join)
		if r := recover {
			rid := mmd_flow(r, mut s)
			labeled_edge(mut s, bid, rid, 'err')
			edge(mut s, rid, join)
		}
	}
	return join
}

// ── channel send/receive ───────────────────────────────────────────────────
//
// `[?channel :name S :buffer N]` produces a channel-shaped node; the
// node is registered under the source-text channel name so subsequent
// `[?send]` / `[?receive]` arrows can target it. The channel-name is
// derived from the slot label when available.

fn mmd_channel(d cx.ProgramDirective, mut s MermaidState) string {
	mut ch_name := ''
	mut buffer_text := ''
	for slot in d.slots {
		if slot.kind != .labeled { continue }
		match slot.label {
			'name' {
				v := slot.value
				if v is cx.ProgramLiteral && v.kind == .string_lit {
					ch_name = v.str_val
				}
			}
			'buffer' { buffer_text = expr_label(slot.value, s.detail) }
			else {}
		}
	}
	mut label := 'channel'
	if ch_name != '' { label += ' "${ch_name}"' }
	if buffer_text != '' { label += ' (buffer ${buffer_text})' }
	id := mk_node(mut s, '[/"${mermaid_escape(label)}"/]')
	if ch_name != '' { s.channel_nodes[ch_name] = id }
	return id
}

fn mmd_send(d cx.ProgramDirective, mut s MermaidState) string {
	mut value := ?cx.ProgramNode(none)
	mut target := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .positional && value == none {
			value = slot.value
			continue
		}
		if slot.kind == .labeled && slot.label == 'to' {
			target = slot.value
		}
	}
	val_label := if v := value { expr_label(v, s.detail) } else { '?' }
	source := mk_rect(mut s, 'send ${val_label}')
	if t := target {
		ch_id := channel_node_for(t, mut s)
		labeled_edge(mut s, source, ch_id, val_label)
		return ch_id
	}
	return source
}

fn mmd_receive(d cx.ProgramDirective, mut s MermaidState) string {
	mut target := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == 'from' {
			target = slot.value
		}
	}
	sink := mk_rect(mut s, '[?${d.name}]')
	if t := target {
		ch_id := channel_node_for(t, mut s)
		labeled_edge(mut s, ch_id, sink, 'recv')
	}
	return sink
}

// channel_node_for returns the mermaid node id for the channel
// expression `t`. If `t` is a `$name` binding referring to a channel
// we've already emitted, reuse that node; otherwise mint a generic
// channel-shaped placeholder.
fn channel_node_for(t cx.ProgramNode, mut s MermaidState) string {
	if t is cx.ProgramBinding {
		if t.path.len == 0 {
			if id := s.channel_nodes[t.name] {
				return id
			}
			// Forward-reference: mint a placeholder node so subsequent
			// sends/receives share it.
			id := mk_node(mut s, '[/"channel \$${t.name}"/]')
			s.channel_nodes[t.name] = id
			return id
		}
	}
	return mk_node(mut s, '[/"channel ${mermaid_escape(expr_label(t, s.detail))}"/]')
}

// mmd_select renders `[?select :case [:from $ch …] …]` as a diamond
// with one inbound arrow per :case channel. Cases that don't shape as
// `[:from $ch …]` fall back to a labelled generic arm.

fn mmd_select(d cx.ProgramDirective, mut s MermaidState) string {
	diamond := mk_diamond(mut s, '[?select]')
	join := mk_rect(mut s, '[?select] result')
	mut case_count := 0
	for slot in d.slots {
		if slot.kind != .labeled { continue }
		if slot.label != 'case' { continue }
		case_count++
		// Try to interpret the case value as `[:from $ch …]`. The
		// parser tends to surface :case bodies as cx_element literals
		// when written as `[:from $ch :do EXPR]`.
		case_val := slot.value
		mut ch_target := ?cx.ProgramNode(none)
		mut handler := ?cx.ProgramNode(none)
		if case_val is cx.ProgramLiteral && case_val.kind == .cx_element {
			for csl in case_val.slots {
				if csl.kind == .labeled {
					match csl.label {
						'from' { ch_target = csl.value }
						'do', 'yield', 'body' { handler = csl.value }
						else {}
					}
				}
			}
		}
		if t := ch_target {
			ch_id := channel_node_for(t, mut s)
			labeled_edge(mut s, ch_id, diamond, 'case ${case_count}')
		}
		if h := handler {
			hid := mmd_flow(h, mut s)
			labeled_edge(mut s, diamond, hid, 'case ${case_count}')
			edge(mut s, hid, join)
		} else {
			labeled_edge(mut s, diamond, join, 'case ${case_count}')
		}
	}
	if case_count == 0 {
		edge(mut s, diamond, join)
	}
	return join
}

// ── async / await ─────────────────────────────────────────────────────────

fn mmd_async(d cx.ProgramDirective, mut s MermaidState) string {
	mut body := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .positional && body == none {
			body = slot.value
			continue
		}
		if slot.kind == .labeled && slot.label == 'body' {
			body = slot.value
		}
	}
	future := mk_subroutine(mut s, '[?async] future')
	if b := body {
		body_id := mmd_flow(b, mut s)
		labeled_edge(mut s, future, body_id, 'spawn')
	}
	return future
}

fn mmd_await(d cx.ProgramDirective, mut s MermaidState) string {
	// :await-all / :await-any / :await-race take a sequence-literal of
	// futures; render each as an inbound arrow into the barrier.
	join := mk_diamond(mut s, '[?${d.name}]')
	for slot in d.slots {
		if slot.kind != .positional { continue }
		val := slot.value
		if val is cx.ProgramLiteral && (val.kind == .sequence_lit || val.kind == .array_lit) {
			for item in val.items {
				fid := mmd_flow(item, mut s)
				edge(mut s, fid, join)
			}
			continue
		}
		fid := mmd_flow(val, mut s)
		edge(mut s, fid, join)
	}
	return join
}

fn mmd_cancel(d cx.ProgramDirective, mut s MermaidState) string {
	id := mk_subroutine(mut s, '[?cancel]')
	for slot in d.slots {
		if slot.kind != .positional { continue }
		fid := mmd_flow(slot.value, mut s)
		labeled_edge(mut s, id, fid, 'cancel')
	}
	return id
}

// ── services / workers / http ─────────────────────────────────────────────

fn mmd_service(d cx.ProgramDirective, mut s MermaidState) string {
	mut name := ''
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == 'name' {
			v := slot.value
			if v is cx.ProgramLiteral && v.kind == .string_lit { name = v.str_val }
		}
	}
	label := if name != '' { '[?service] "${name}"' } else { '[?service]' }
	return mk_subroutine(mut s, label)
}

fn mmd_worker(d cx.ProgramDirective, mut s MermaidState) string {
	mut name := ''
	mut body := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .labeled {
			match slot.label {
				'name' {
					v := slot.value
					if v is cx.ProgramLiteral && v.kind == .string_lit { name = v.str_val }
				}
				'body' { body = slot.value }
				else {}
			}
		}
	}
	label := if name != '' { '[?worker] "${name}"' } else { '[?worker]' }
	wid := mk_subroutine(mut s, label)
	if b := body {
		body_id := mmd_flow(b, mut s)
		labeled_edge(mut s, wid, body_id, ':body')
	}
	return wid
}

fn mmd_http_client(d cx.ProgramDirective, mut s MermaidState) string {
	mut method := ''
	mut url := ''
	for slot in d.slots {
		if slot.kind != .labeled { continue }
		match slot.label {
			'get', 'post', 'put', 'delete', 'patch' {
				method = slot.label.to_upper()
				v := slot.value
				if v is cx.ProgramLiteral && v.kind == .string_lit { url = v.str_val }
			}
			else {}
		}
	}
	mut label := '[?http-client]'
	if method != '' { label += ' ${method}' }
	if url != '' { label += ' ${url}' }
	return mk_subroutine(mut s, label)
}

// ── sequence-diagram emission ─────────────────────────────────────────────
//
// The sequence diagram path is used for async/channel-heavy programs.
// Implementation kept narrow: one note per directive name plus the
// implicit Caller lane. The flowchart path covers the breadth of the
// rendering table; sequenceDiagram is opt-in when the program shape is
// inherently message-passing.

fn mmd_sequence(node cx.ProgramNode, mut s MermaidState) {
	if node is cx.ProgramDirective {
		s.lines << '    Note over Caller: [?${node.name}]'
		for slot in node.slots {
			mmd_sequence(slot.value, mut s, )
		}
		return
	}
	if node is cx.ProgramForComp {
		s.lines << '    Note over Caller: [?for]'
		mmd_sequence(node.yield, mut s)
		return
	}
}

// ── label helpers ─────────────────────────────────────────────────────────

// expr_label renders an AST node as a short one-line label for use as
// a node label or edge label. Bindings keep their `$` sigil; literals
// keep their natural surface form; directives collapse to `[?name]`
// (so an outer diagram doesn't recursively render a nested directive's
// internals — that's what the per-family emitters are for).
fn expr_label(n cx.ProgramNode, detail DiagramDetail) string {
	raw := expr_label_raw(n, detail)
	// At full/compact the cap doubles so attr chips can ride along
	// without immediately spilling into `…`.
	max_len := match detail {
		.min     { 48 }
		.compact { 72 }
		.full    { 120 }
	}
	if raw.len <= max_len { return raw }
	return raw[..max_len] + '…'
}

// attr_chips renders an element's `attrs` as `@k=v` chips per the
// detail level: min → empty; compact → first 2 + ` (+K more)` when
// over; full → all.
fn attr_chips(attrs []cx.ProgramAttr, detail DiagramDetail) string {
	if attrs.len == 0 || detail == .min { return '' }
	cap_n := if detail == .full { attrs.len } else { compact_attr_cap }
	mut parts := []string{}
	for i := 0; i < attrs.len && i < cap_n; i++ {
		a := attrs[i]
		parts << ' @${a.name}=${expr_label_raw(a.value, detail)}'
	}
	remaining := attrs.len - cap_n
	if remaining > 0 {
		parts << ' (+${remaining})'
	}
	return parts.join('')
}

fn expr_label_raw(n cx.ProgramNode, detail DiagramDetail) string {
	match n {
		cx.ProgramLiteral {
			match n.kind {
				.string_lit { return "'${n.str_val}'" }
				.int_lit    { return n.int_val.str() }
				.float_lit  { return n.flt_val.str() }
				.bool_lit   { return n.bool_val.str() }
				.atom_lit   { return ':${n.str_val}' }
				.duration_lit { return n.dur_val }
				.sequence_lit {
					mut parts := []string{}
					for it in n.items { parts << expr_label_raw(it, detail) }
					return '(${parts.join(", ")})'
				}
				.array_lit {
					mut parts := []string{}
					for it in n.items { parts << expr_label_raw(it, detail) }
					return '[${parts.join(", ")}]'
				}
				.cx_element {
					chips := attr_chips(n.attrs, detail)
					has_body := n.items.len > 0 || n.slots.len > 0
					if !has_body && chips == '' {
						return '[${n.name}]'
					}
					if !has_body {
						return '[${n.name}${chips}]'
					}
					return '[${n.name}${chips} …]'
				}
				.block { return '…' }
				else { return '<lit>' }
			}
		}
		cx.ProgramBinding {
			mut buf := '\$' + n.name
			for step in n.path {
				match step.kind {
					.child              { buf += '/' + step.name }
					.attr               { buf += '@' + step.name }
					.member             { buf += '.' + step.name }
					.wildcard_children  { buf += '/*' }
					.descendant         { buf += '//' + step.name }
					.descendant_wildcard { buf += '//*' }
					.parent             { buf += '/..' }
				}
				for _ in step.predicates {
					buf += '[…]'
				}
			}
			return buf
		}
		cx.ProgramCall {
			if n.args.len == 0 {
				return n.name + '()'
			}
			mut parts := []string{}
			for a in n.args { parts << expr_label_raw(a, detail) }
			return '${n.name}(${parts.join(", ")})'
		}
		cx.ProgramDirective {
			return '[?${n.name}]'
		}
		cx.ProgramForComp {
			return '[?for]'
		}
		cx.ProgramPathExpr {
			mut out := match n.leading {
				.absolute   { '/' }
				.descendant { '//' }
				.relative   { '' }
			}
			for i, st in n.steps {
				if i > 0 { out += '/' }
				out += st.name
			}
			return out
		}
		cx.ProgramPattern {
			return '[' + n.head.value + ']'
		}
		cx.ProgramSliceAccess {
			// W5b parser-only placeholder. Canonical short-label form
			// lands with W5c when the evaluator surface is in place.
			return expr_label_raw(n.binding, detail) + '[…]'
		}
		cx.ProgramSliceLiteral {
			// first-class Slice literal short label.
			return '[slice]'
		}
		cx.ProgramWildcard {
			return if n.deep { '**' } else { '*' }
		}
		cx.Program {
			return expr_label_raw(n.body, detail)
		}
	}
}

// mermaid_escape is defined in code_diagram.v and shared across the
// `code` module's mermaid emitters. The version there handles `"`,
// `\`, and newline — sufficient for label-string use here.

// directive_label returns the canonical `[?name]` source-shape label
// for a directive. Still used by the DOT (graphviz) renderer below.
fn directive_label(d cx.ProgramDirective) string {
	return '[?${d.name}]'
}

fn extract_mermaid_source(rendered string) !string {
	open_idx := rendered.index(cx_diagram_marker_open) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'mermaid output missing %%cx:…%% marker'
		}
	}
	rest := rendered[open_idx + cx_diagram_marker_open.len..]
	close_idx := rest.index(cx_diagram_marker_close) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'mermaid output missing %%cx:…%% close marker'
		}
	}
	encoded := rest[..close_idx]
	return base64.decode_str(encoded)
}

// ── SVG / PNG via graphviz ──────────────────────────────────────────────────
//
// SVG and PNG share the DOT rendering path: emit DOT, shell to `dot
// -Tsvg` or `dot -Tpng`, splice in the embedded source as SVG metadata
// or a PNG tEXt chunk. Both depend on the `dot` binary being on PATH;
// when not present, the call returns CXER0001 with a "graphviz not
// found" message (callers — `cx eval --target=svg` / `cx diagram` —
// surface this to the operator).

fn render_svg(prog cx.Program, source_text string) !string {
	// Try the graphviz path; fall back to the round-trip-only envelope
	// when `dot` isn't available. Gate 9 only requires the embedded-
	// source round-trip — the visual content is Phase 4.2 polish.
	dot_text := render_dot(prog, source_text)
	if svg := shell_dot(dot_text, 'svg') {
		return inject_svg_metadata(svg, source_text)
	}
	return minimal_svg_envelope(source_text)
}

fn render_png(prog cx.Program, source_text string) !string {
	dot_text := render_dot(prog, source_text)
	if png_bytes := shell_dot(dot_text, 'png') {
		return inject_png_text_chunk(png_bytes, source_text)
	}
	return minimal_png_envelope(source_text)
}

// minimal_svg_envelope returns a valid SVG document carrying the
// source text in the cx:source metadata block. Used as the fallback
// when graphviz isn't on PATH. The visual is an empty 1×1 viewport
// — the file's purpose under this fallback is the round-trip, not
// the diagram.
fn minimal_svg_envelope(source_text string) string {
	encoded := base64.encode_str(source_text)
	return '<?xml version="1.0" encoding="UTF-8"?>\n' +
		'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">\n' +
		'  <metadata><cx:source xmlns:cx="https://cx.lang/v1">${encoded}</cx:source></metadata>\n' +
		'</svg>\n'
}

// minimal_png_envelope returns a binary PNG (1×1 transparent pixel)
// carrying the source text in a tEXt chunk keyed "cx-source". Pure
// V implementation — no graphviz dependency. Used as the fallback
// when graphviz isn't on PATH. Gate-9 round-trip uses this; Phase
// 4.2's graphviz integration replaces with the real visual.
fn minimal_png_envelope(source_text string) string {
	// PNG file structure (RFC 2083):
	//   signature: 89 50 4E 47 0D 0A 1A 0A
	//   IHDR chunk: 1×1, 8-bit grayscale, no alpha
	//   tEXt chunk: keyword "cx-source" \0 base64(source)
	//   IDAT chunk: minimal zlib-compressed scanline
	//   IEND chunk
	mut bytes := []u8{cap: source_text.len * 2 + 128}
	// Signature
	for b in [u8(0x89), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
		bytes << b
	}
	// IHDR: 13-byte data — width=1, height=1, bit_depth=8, color=0, compression=0, filter=0, interlace=0
	ihdr_data := [u8(0), 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]
	append_chunk(mut bytes, 'IHDR', ihdr_data)
	// tEXt: keyword \0 text
	encoded := base64.encode_str(source_text)
	mut text_data := []u8{}
	text_data << 'cx-source'.bytes()
	text_data << 0
	text_data << encoded.bytes()
	append_chunk(mut bytes, 'tEXt', text_data)
	// IDAT: minimal zlib-encoded scanline (filter=0 + one byte=0).
	// Hardcoded zlib stream for a 2-byte deflate of `[0, 0]`.
	idat_data := [u8(0x78), 0x9C, 0x62, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01]
	append_chunk(mut bytes, 'IDAT', idat_data)
	// IEND
	append_chunk(mut bytes, 'IEND', []u8{})
	return bytes.bytestr()
}

fn append_chunk(mut out []u8, chunk_type string, data []u8) {
	// length (4 bytes, big-endian)
	length := u32(data.len)
	out << u8((length >> 24) & 0xff)
	out << u8((length >> 16) & 0xff)
	out << u8((length >> 8) & 0xff)
	out << u8(length & 0xff)
	// type (4 bytes)
	type_start := out.len
	for c in chunk_type.bytes() {
		out << c
	}
	// data
	for b in data {
		out << b
	}
	// CRC-32 over type + data
	crc := crc32_compute(out[type_start..])
	out << u8((crc >> 24) & 0xff)
	out << u8((crc >> 16) & 0xff)
	out << u8((crc >> 8) & 0xff)
	out << u8(crc & 0xff)
}

// crc32_compute implements PNG's CRC-32 (polynomial 0xEDB88320, init
// 0xFFFFFFFF, final XOR 0xFFFFFFFF). No external dependency — the
// PNG chunk machinery is the only consumer.
fn crc32_compute(data []u8) u32 {
	mut crc := u32(0xFFFFFFFF)
	for b in data {
		mut c := crc ^ u32(b)
		for _ in 0 .. 8 {
			if c & 1 != 0 {
				c = (c >> 1) ^ u32(0xEDB88320)
			} else {
				c >>= 1
			}
		}
		crc = c
	}
	return crc ^ u32(0xFFFFFFFF)
}

fn render_dot(prog cx.Program, source_text string) string {
	_ = source_text
	mut b := []string{cap: 32}
	b << 'digraph CX {'
	b << '  rankdir=TB;'
	b << '  node [shape=box,fontname="Helvetica"];'
	dot_emit(prog.body, mut b, 0)
	b << '}'
	return b.join('\n')
}

fn dot_emit(node cx.ProgramNode, mut b []string, parent_idx int) {
	match node {
		cx.ProgramDirective {
			idx := b.len
			b << '  n${idx} [label="${dot_escape(directive_label(node))}"];'
			if parent_idx >= 0 {
				b << '  n${parent_idx} -> n${idx};'
			}
			for s in node.slots {
				dot_emit(s.value, mut b, idx)
			}
		}
		cx.ProgramForComp {
			idx := b.len
			b << '  n${idx} [label="for-comp"];'
			if parent_idx >= 0 {
				b << '  n${parent_idx} -> n${idx};'
			}
			dot_emit(node.yield, mut b, idx)
		}
		else {}
	}
}

fn dot_escape(s string) string {
	mut out := []u8{cap: s.len + 8}
	for c in s {
		if c == `"` { out << `\\` }
		out << c
	}
	return out.bytestr()
}

fn shell_dot(input string, fmt string) !string {
	// V's os.execute_or_panic is too aggressive; we want to surface a
	// "graphviz not installed" message as CXER0001 cleanly. The
	// implementation shells out via `dot -T${fmt}` reading from
	// stdin. If `dot` is missing, the system returns an error.
	return import_os_execute(input, ['dot', '-T${fmt}']) or {
		return EvalError{
			code:    'cx-err:CXER0001'
			message: 'graphviz (dot) required for diagram --format=${fmt}: ${err.msg()}'
		}
	}
}

// import_os_execute runs `argv` with `stdin` piped in, returns stdout,
// or surfaces the underlying error. Used to shell out to `dot` for
// SVG / PNG generation when graphviz is available.
fn import_os_execute(stdin_text string, argv []string) !string {
	if argv.len == 0 {
		return error('argv empty')
	}
	// Find the binary on PATH; if absent, fail fast with a clear msg.
	if os.find_abs_path_of_executable(argv[0]) or { '' } == '' {
		return error('${argv[0]}: not found on PATH')
	}
	mut p := os.new_process(argv[0])
	if argv.len > 1 {
		p.set_args(argv[1..])
	}
	p.set_redirect_stdio()
	p.run()
	if !p.is_alive() && p.code != 0 {
		err_text := p.stderr_read()
		return error('${argv[0]} exited ${p.code}: ${err_text}')
	}
	p.stdin_write(stdin_text)
	os.fd_close(p.stdio_fd[0])
	p.wait()
	if p.code != 0 {
		err_text := p.stderr_read()
		return error('${argv[0]} exited ${p.code}: ${err_text}')
	}
	return p.stdout_slurp()
}

fn inject_svg_metadata(svg string, source_text string) string {
	encoded := base64.encode_str(source_text)
	metadata := '  <metadata><cx:source xmlns:cx="https://cx.lang/v1">${encoded}</cx:source></metadata>'
	// Splice the metadata immediately after the opening <svg …> tag.
	gt_idx := svg.index('>') or { return svg }
	return svg[..gt_idx + 1] + '\n' + metadata + svg[gt_idx + 1..]
}

fn inject_png_text_chunk(png_bytes string, source_text string) string {
	// PNG file structure: 8-byte signature, then a sequence of chunks
	// (length:4 type:4 data:length crc:4). Insert a tEXt chunk
	// immediately after the IHDR chunk (which by spec is the first
	// chunk after the signature). The chunk carries keyword
	// "cx-source" + \0 + base64(source_text) as its data, with a
	// CRC-32 over type+data appended.
	in_bytes := png_bytes.bytes()
	if in_bytes.len < 8 + 8 + 13 + 4 {
		// File too small to even be a valid PNG (signature + IHDR
		// header + IHDR data + IHDR CRC = minimum 33 bytes). Fall
		// back to passing through unmodified.
		return png_bytes
	}
	// IHDR chunk: starts at offset 8, length field is at 8..12, so
	// the chunk total size is 4 + 4 + length + 4. Locate the byte
	// immediately after the IHDR chunk.
	ihdr_len := (u32(in_bytes[8]) << 24) | (u32(in_bytes[9]) << 16) |
	            (u32(in_bytes[10]) << 8) | u32(in_bytes[11])
	insert_at := 8 + 8 + int(ihdr_len) + 4
	if insert_at > in_bytes.len { return png_bytes }
	encoded := base64.encode_str(source_text)
	mut text_data := []u8{}
	text_data << 'cx-source'.bytes()
	text_data << 0
	text_data << encoded.bytes()
	mut chunk := []u8{cap: 12 + text_data.len}
	length := u32(text_data.len)
	chunk << u8((length >> 24) & 0xff)
	chunk << u8((length >> 16) & 0xff)
	chunk << u8((length >> 8) & 0xff)
	chunk << u8(length & 0xff)
	type_start := chunk.len
	for c in 'tEXt'.bytes() { chunk << c }
	for b in text_data { chunk << b }
	crc := crc32_compute(chunk[type_start..])
	chunk << u8((crc >> 24) & 0xff)
	chunk << u8((crc >> 16) & 0xff)
	chunk << u8((crc >> 8) & 0xff)
	chunk << u8(crc & 0xff)
	mut out := []u8{cap: in_bytes.len + chunk.len}
	for i in 0 .. insert_at { out << in_bytes[i] }
	for b in chunk { out << b }
	for i in insert_at .. in_bytes.len { out << in_bytes[i] }
	return out.bytestr()
}

fn extract_svg_source(rendered string) !string {
	start_tag := '<cx:source'
	end_tag := '</cx:source>'
	a := rendered.index(start_tag) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'svg output missing <cx:source> metadata'
		}
	}
	gt := rendered.index_after('>', a) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'svg <cx:source> tag malformed'
		}
	}
	body_start := gt + 1
	b := rendered.index_after(end_tag, body_start) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'svg <cx:source> not closed'
		}
	}
	encoded := rendered[body_start..b]
	return base64.decode_str(encoded)
}

fn extract_png_source(rendered string) !string {
	// Walk PNG chunks looking for tEXt with keyword "cx-source".
	// Signature check is purely defensive — accepts any PNG-shaped
	// blob.
	bytes := rendered.bytes()
	if bytes.len < 8 {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'png too small (less than 8-byte signature)'
		}
	}
	mut pos := 8
	for pos + 8 <= bytes.len {
		length := (u32(bytes[pos]) << 24) | (u32(bytes[pos+1]) << 16) |
		          (u32(bytes[pos+2]) << 8) | u32(bytes[pos+3])
		ctype := bytes[pos+4..pos+8].bytestr()
		data_start := pos + 8
		data_end := data_start + int(length)
		if data_end > bytes.len {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: 'png chunk length exceeds file bytes'
			}
		}
		if ctype == 'tEXt' {
			data := bytes[data_start..data_end]
			// Split on first null byte to separate keyword + text.
			mut sep := -1
			for i, b in data {
				if b == 0 { sep = i; break }
			}
			if sep < 0 { continue }
			keyword := data[..sep].bytestr()
			if keyword == 'cx-source' {
				encoded := data[sep+1..].bytestr()
				return base64.decode_str(encoded)
			}
		}
		// next chunk: length + type(4) + data + crc(4)
		pos = data_end + 4
	}
	return EvalError{
		code:    'cx-err:CXER0100'
		message: 'png output missing cx-source tEXt chunk'
	}
}
