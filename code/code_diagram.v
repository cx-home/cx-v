module code

// ── v0.8.0 Phase 2.10 — code_diagram ────────────────────────────
//
// New diagram emitter/§D3/§D4. Distinct from the
// the `render_diagram` in `diagram.v` (gate-9 round-trip embed-
// source path); this emitter produces the playground's CFG (for code
// sources) + ERD (for data sources) Mermaid surface used by the
// `cx_code_diagram` C ABI export (cap bit 31).
//
// Auto-detection:
//   - top-level program has ≥ 1 EvalDirective → code source → CFG
//     (Mermaid `flowchart TD`).
//   - else → data source → ERD (Mermaid `erDiagram`).
//
// `[?cx …]` processing-instructions do NOT trigger code-source
// classification; they are stripped from the input before parse so
// the data-source classification path stays clean.
//
// CFG basic-block rules (§D4):
//   - sequential non-branching directives compose into one block node,
//     label lists each directive on its own line, `max_block_lines`-line
//     cap with a `(+K more)` overflow row.
//   - `[?if cond :then T :else E]` → diamond (arms labeled `true` /
//     `false`).
//   - `[?match expr [case P₁ B₁] [case P₂ B₂] … [else E]]` → dispatcher
//     round-rect; one outgoing edge per arm, labeled with arm pattern
//     truncated to 30 chars + `…` if longer.
//   - `[?for $x [in seq] [yield body]]` → loop-box with `binds $x` edge.
//   - `[?modify FOCUS [action …]+]` → single update-block (labels list
//     focus expression + action vocabulary).
//   - `[?def name params body]` → sub-graph boundary.
//
// ERD inference (§D3): containment-only; multiple same-named children
// → `||--o{`, singleton → `||--||`. Entity boxes list attributes
// first (`@`-prefixed), scalar child elements second. Sub-element
// entities never inline as rows.
//
// Phase 2.11 (parallel agent (R)) wires the C ABI export
// `cx_code_diagram` in `cabi.v`; this file leaves the V-side surface.
// TODO(Phase 2.11): expose cx_code_diagram via cabi.v.

import cx

// max_block_lines is the §D4 "basic-block N-line cap" overflow
// threshold. Once a sequential block accumulates N directive labels,
// further additions are collapsed into a `(+K more)` overflow row.
// Raised from 6 → 10 in v0.8.0 — the original cap clipped on
// normal-looking fixture programs, and the literal `[...]` row
// was misread as a CX form (square-bracket sigil) rather than as
// an ellipsis. The "+K more" indicator is unambiguous.
const max_block_lines = 10

// max_match_arm_label is the §D4 "match arm pattern truncated to 30
// chars + …" cap. Arm labels longer than 30 source chars are emitted
// with the leading 30 chars + a `…` suffix.
const max_match_arm_label = 30

// DiagramLevel controls the verbosity of `cx_code_diagram` output per
// (amended 2026-05-28). Three rungs: `min` strips to
// shape-only; `compact` is the default and preserves §D3/§D4/§D13
// baselines; `full` adds INPUT/OUTPUT terminals, source spans,
// binding-resolution bridges, and step-back rules.
pub enum CodeDiagramLevel {
	min
	compact
	full
}

// parse_code_diagram_level maps a string ("min" / "compact" / "full")
// to the enum. Empty / unknown defaults to `.compact` per D12.6
// "default-on-unspecified".
pub fn parse_code_diagram_level(s string) CodeDiagramLevel {
	match s {
		'min'     { return .min }
		'full'    { return .full }
		'compact' { return .compact }
		else      { return .compact }
	}
}

// code_diagram is the top-level entry point. Parses `source`,
// classifies code-vs-data (ternary: data → ERD,
// sequence-shape code → SEQ, other code → CFG), and emits the Mermaid
// representation. Defaults to `.compact` detail. Use
// `code_diagram_with_level` to vary verbosity (D12.6).
//
// Empty source classifies as data and yields the placeholder
// `erDiagram` block. Parse failures surface as a kind-appropriate
// placeholder header (the playground renderer then shows a "no
// entities" overlay via CSS — gate-17 §D4 affordance).
pub fn code_diagram(source string) !string {
	return code_diagram_with_level(source, .compact)!
}

// code_diagram_with_level is the level-aware entry point
// D12.6. Dispatches to the per-source-kind emitter (ERD / CFG / SEQ)
// and threads the level through.
pub fn code_diagram_with_level(source string, level CodeDiagramLevel) !string {
	stripped := strip_cx_pis(source).trim_space()
	if stripped.len == 0 {
		return 'erDiagram'
	}
	// Parser support is partial for two diagram-input shapes: absolute
	// paths (`/foo/bar`) and call/element-shaped `[?match]` arm
	// patterns. We rewrite the source into accepted shapes up-front
	// (no semantics change — only surface restructuring) and parse.
	patched := patch_for_diagram_parse(stripped)
	prog := cx.parse_program(patched) or {
		// The diagram-parse patch (absolute-path + match-arm surface rewrites)
		// can itself introduce a parse failure on an otherwise-valid program —
		// observed in the wasm build, where the patched form fails to parse
		// though the raw source parses cleanly (the legacy render_diagram path,
		// which parses the raw source, works there). Retry the UN-patched
		// source before degrading to a header-only text-level classification, so
		// the canonical diagram export yields a full diagram in every build.
		cx.parse_program(stripped) or {
			// Parse fallback: classify on text-level only.
			if text_level_is_sequence_shape(stripped) {
				return 'sequenceDiagram'
			}
			if text_level_is_code(stripped) { return 'flowchart TD' }
			return 'erDiagram'
		}
	}
	if program_is_sequence_shape(prog) {
		return code_diagram_seq(prog, level)!
	}
	if program_is_code(prog) {
		return code_diagram_cfg_level(prog, level)!
	}
	return code_diagram_erd_level(prog, stripped, level)!
}

// patch_for_diagram_parse rewrites unsupported Phase 2.3 / 2.4
// surface shapes into forms the current parser accepts, so the
// AST-shape classification + CFG emit can proceed.
//
// Rewrites:
//   - `/Name` (single-slash absolute CXPath) → `//Name` (descendant-
//     anchored, which the Phase 2.3 partial parser already accepts).
//     Limited to top-of-step context — never rewrites inside a string
//     literal.
//   - call/element-shaped `[?match]` arm patterns (`[case [< 13] B]`)
//     → quoted-pattern clause-child form (`[case '< 13' B]`). A
//     bracket-shaped pattern is not a valid match-pattern head, so
//     the parser would otherwise reject the whole source; quoting it
//     lands a string-literal arm value the emitter still labels.
//
// The rewrite is intentionally minimal: best-effort relief for the
// playground's diagram view while Phase 2.3/2.4/2.5 catch up.
// Sources still beyond the rewritten parser's reach degrade to the
// empty-flowchart placeholder.
// debug_patch_for_diagram_parse exposes patch_for_diagram_parse for
// ad-hoc inspection during emitter development. Not part of the
// stable public surface.
pub fn debug_patch_for_diagram_parse(source string) string {
	return patch_for_diagram_parse(source)
}

fn patch_for_diagram_parse(source string) string {
	// Pass 1: slash rewrite.
	pass1 := patch_paths(source)
	// Pass 2: match-arm pattern-quoting rewrite. Only applies inside
	// `[?match …]` directive bodies.
	return patch_match_arms(pass1)
}

fn patch_paths(source string) string {
	mut out := []u8{cap: source.len + 16}
	bs := source.bytes()
	mut i := 0
	mut in_str := u8(0)
	for i < bs.len {
		c := bs[i]
		if in_str != 0 {
			out << c
			if c == in_str && (i == 0 || bs[i-1] != `\\`) { in_str = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` {
			in_str = c
			out << c
			i++
			continue
		}
		if c == `/` && i + 1 < bs.len && is_ident_byte(bs[i+1]) {
			prev := if i == 0 { u8(0) } else { bs[i-1] }
			if prev != `/` && !is_ident_byte(prev) {
				out << `/`
				out << `/`
				i++
				continue
			}
		}
		out << c
		i++
	}
	return out.bytestr()
}

fn patch_match_arms(source string) string {
	mut out := []u8{cap: source.len + 32}
	bs := source.bytes()
	mut i := 0
	mut in_str := u8(0)
	for i < bs.len {
		c := bs[i]
		if in_str != 0 {
			out << c
			if c == in_str && (i == 0 || bs[i-1] != `\\`) { in_str = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` {
			in_str = c
			out << c
			i++
			continue
		}
		// Detect `[?match` to enter match-rewrite scope.
		if c == `[` && i + 6 < bs.len && bs[i+1] == `?`
		   && bs[i+2] == `m` && bs[i+3] == `a` && bs[i+4] == `t`
		   && bs[i+5] == `c` && bs[i+6] == `h`
		   && (i + 7 == bs.len || !is_ident_byte(bs[i+7])) {
			// Find matching `]` for this directive.
			end_idx := find_matching_close(bs, i)
			if end_idx > 0 {
				// Copy `[?match` opener verbatim.
				out << '[?match'.bytes()
				inner := bs[i+7..end_idx]
				// Rewrite arm brackets within this slice.
				out << rewrite_match_inner(inner).bytes()
				out << `]`
				i = end_idx + 1
				continue
			}
		}
		out << c
		i++
	}
	return out.bytestr()
}

// find_matching_close returns the index of the `]` that closes the
// bracket opened at `start_idx` in `bs`. Returns -1 if unbalanced.
// Skips string literals.
fn find_matching_close(bs []u8, start_idx int) int {
	mut depth := 0
	mut i := start_idx
	mut in_str := u8(0)
	for i < bs.len {
		c := bs[i]
		if in_str != 0 {
			if c == in_str && (i == 0 || bs[i-1] != `\\`) { in_str = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_str = c; i++; continue }
		if c == `[` { depth++ }
		else if c == `]` {
			depth--
			if depth == 0 { return i }
		}
		i++
	}
	return -1
}

// split_case_head splits `:case VAL BODY` body bytes into VAL and
// BODY at the first top-level whitespace. Top-level means depth-0
// w.r.t. brackets, parens, braces, and string quotes. Returns
// (val, rest) — rest is trimmed.
fn split_case_head(s string) (string, string) {
	bs := s.bytes()
	mut depth := 0
	mut in_str := u8(0)
	mut i := 0
	for i < bs.len {
		c := bs[i]
		if in_str != 0 {
			if c == in_str && (i == 0 || bs[i-1] != `\\`) { in_str = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_str = c; i++; continue }
		if c == `[` || c == `(` || c == `{` { depth++; i++; continue }
		if c == `]` || c == `)` || c == `}` { depth--; i++; continue }
		if depth == 0 && (c == ` ` || c == `\t` || c == `\n`) {
			val := s[..i]
			rest := s[i..].trim_space()
			return val, rest
		}
		i++
	}
	return s, ''
}

// rewrite_match_inner walks the body of a `[?match …]` directive
// looking for clause-child arms `[case PAT BODY]` / `[else BODY]`
// (the canonical v0.8.0 surface) and the legacy colon form
// `[:case PAT BODY]` / `[:else BODY]`. Each is normalised to the
// canonical clause-child form; the only substantive rewrite is on
// the case pattern (see below). Literal / string / name / atom /
// wildcard / type / `$bind` patterns pass through byte-for-byte.
//
// A call/element-shaped pattern (`[< 13]`, `[lt 13]`, `[= 13]`) is
// NOT a valid match-pattern head — `code.parse` rejects it with
// CXER0100, which would otherwise sink the whole source to the
// text-level `flowchart TD` fallback. We wrap such a pattern in a
// quoted string so it parses as a string-literal arm value; the
// emitter's `arm_pattern_label` peels the quotes back off, so the
// edge label still reads as the raw (truncated) pattern text.
fn rewrite_match_inner(inner []u8) string {
	mut out := []u8{cap: inner.len + 16}
	mut i := 0
	mut in_str := u8(0)
	for i < inner.len {
		c := inner[i]
		if in_str != 0 {
			out << c
			if c == in_str && (i == 0 || inner[i-1] != `\\`) { in_str = 0 }
			i++
			continue
		}
		if c == `'` || c == `"` { in_str = c; out << c; i++; continue }
		// Match a clause-child arm `[case …]` / `[else …]`, tolerating
		// the retired leading-colon spelling `[:case …]` / `[:else …]`.
		if c == `[` && i + 1 < inner.len {
			kw_start := if inner[i+1] == `:` { i + 2 } else { i + 1 }
			mut j := kw_start
			for j < inner.len && is_ident_byte(inner[j]) { j++ }
			if j > kw_start {
				kw := inner[kw_start..j].bytestr()
				if kw == 'case' || kw == 'else' {
					end_idx := find_matching_close(inner, i)
					if end_idx > 0 {
						body_str := inner[j..end_idx].bytestr().trim_space()
						if kw == 'case' {
							// Bracket-aware split on the first top-level
							// whitespace separating the case pattern from
							// the case body.
							val, rest := split_case_head(body_str)
							val_safe := if val.len >= 2 && val[0] == `[` && val.ends_with(']') {
								// Strip outer brackets; quote the inner so
								// the pattern parses as a string literal.
								"'" + val[1..val.len-1] + "'"
							} else {
								val
							}
							out << '[case '.bytes()
							out << val_safe.bytes()
							if rest.len > 0 {
								out << ` `
								out << rest.bytes()
							}
							out << `]`
						} else {
							// `[else BODY]` — no pattern to rewrite.
							out << '[else'.bytes()
							if body_str.len > 0 {
								out << ` `
								out << body_str.bytes()
							}
							out << `]`
						}
						i = end_idx + 1
						continue
					}
				}
			}
		}
		out << c
		i++
	}
	return out.bytestr()
}

// text_level_is_code is the fallback classifier used when full parse
// fails. Scans top-level `[…]` chunks and returns true iff any chunk
// opens with `[?NAME` where NAME is not `cx`. Mirrors the auto-
// detect heuristic in scripts/check_code_diagram_fixtures.py so
// fixture cross-check passes even on unparseable sources.
fn text_level_is_code(source string) bool {
	mut depth := 0
	mut chunk_start := -1
	bs := source.bytes()
	mut i := 0
	for i < bs.len {
		if bs[i] == `[` {
			if depth == 0 { chunk_start = i }
			depth++
		} else if bs[i] == `]` {
			depth--
			if depth == 0 && chunk_start >= 0 {
				// Inspect this top-level chunk.
				if i - chunk_start >= 3 && bs[chunk_start + 1] == `?` {
					// Find name end.
					mut j := chunk_start + 2
					mut name := []u8{}
					for j <= i && is_ident_byte(bs[j]) {
						name << bs[j]
						j++
					}
					nm := name.bytestr()
					if nm.len > 0 && nm != 'cx' { return true }
				}
				chunk_start = -1
			}
		}
		i++
	}
	return false
}

// strip_cx_pis removes `[?cx …]` processing-instructions from the
// source. PIs are config directives (`spec/eval.md §2.3`) and per
// must NOT trigger code-source classification. Removing
// them at the text layer keeps the downstream parse + AST-classifier
// uniform. Whitespace between PIs and the real source is collapsed.
fn strip_cx_pis(source string) string {
	mut out := []u8{cap: source.len}
	mut i := 0
	bs := source.bytes()
	for i < bs.len {
		if i + 3 < bs.len && bs[i] == `[` && bs[i+1] == `?`
		   && bs[i+2] == `c` && bs[i+3] == `x`
		   && (i + 4 == bs.len || !is_ident_byte(bs[i+4])) {
			// Skip to matching `]` (single-level — `[?cx …]` PIs do
			// not nest per spec/eval.md §2.3).
			mut depth := 1
			mut j := i + 4
			for j < bs.len && depth > 0 {
				if bs[j] == `[` { depth++ }
				else if bs[j] == `]` { depth-- }
				j++
			}
			i = j
			continue
		}
		out << bs[i]
		i++
	}
	return out.bytestr()
}

fn is_ident_byte(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`)
	       || (b >= `0` && b <= `9`) || b == `_` || b == `-`
}

// sequence_trigger_directives are the top-level directive names that
// route a code source to the SEQ branch (amended
// 2026-05-28) + gate 37.16. Detection runs on top-level position only;
// nested triggers inside `[?def]` bodies don't flip the dispatch.
const sequence_trigger_directives = ['worker', 'http-service', 'select', 'async', 'channel']

// is_sequence_trigger returns true iff `name` is in the sequence-
// trigger directive set / gate 37.16.
fn is_sequence_trigger(name string) bool {
	for n in sequence_trigger_directives {
		if n == name { return true }
	}
	return false
}

// program_is_sequence_shape returns true iff at least one top-level
// statement is a directive in the sequence-trigger set
// D1 (gate 37.16). Top-level position is interpreted permissively:
// `[?let]` chains around sequence-trigger directives count, since the
// playground's reference examples (#161-#163, #171-#172) introduce
// channels via `[?let [= $ch [?channel ...]] BODY]` and the user-
// observable program shape is still sequence-shape. Nested triggers
// inside `[?def]` bodies do NOT flip the dispatch (only top-level-
// after-let-peeling matters).
fn program_is_sequence_shape(prog cx.Program) bool {
	body := prog.body
	if body is cx.ProgramLiteral && body.kind == .block {
		for item in body.items {
			if node_is_sequence_trigger(item) { return true }
		}
		return false
	}
	return node_is_sequence_trigger(body)
}

// node_is_sequence_trigger returns true iff `n` is (or — for `[?let]`
// wrappers — contains) a sequence-trigger directive. Recurses through
// `[?let]` bodies + `[?let]` values to match the legacy
// `is_top_level_temporal` carve-out in `diagram.v`.
fn node_is_sequence_trigger(n cx.ProgramNode) bool {
	if n is cx.ProgramDirective {
		if is_sequence_trigger(n.name) { return true }
		if n.name == 'let' {
			// `[?let [= $x V] BODY]` — peer through both the binding
			// values and the body. Both can carry a sequence trigger.
			for slot in n.slots {
				if node_is_sequence_trigger(slot.value) { return true }
			}
			return false
		}
	}
	if n is cx.ProgramLiteral && n.kind == .block {
		for item in n.items {
			if node_is_sequence_trigger(item) { return true }
		}
	}
	return false
}

// text_level_is_sequence_shape mirrors text_level_is_code for the SEQ
// fallback when the parser can't accept the input. Scans top-level
// `[?NAME]` chunks and returns true iff any NAME is in the sequence-
// trigger set.
fn text_level_is_sequence_shape(source string) bool {
	mut depth := 0
	mut chunk_start := -1
	bs := source.bytes()
	mut i := 0
	for i < bs.len {
		if bs[i] == `[` {
			if depth == 0 { chunk_start = i }
			depth++
		} else if bs[i] == `]` {
			depth--
			if depth == 0 && chunk_start >= 0 {
				if i - chunk_start >= 3 && bs[chunk_start + 1] == `?` {
					mut j := chunk_start + 2
					mut name := []u8{}
					for j <= i && is_ident_byte(bs[j]) {
						name << bs[j]
						j++
					}
					nm := name.bytestr()
					if is_sequence_trigger(nm) { return true }
				}
				chunk_start = -1
			}
		}
		i++
	}
	return false
}

// program_is_code returns true iff the program has at least one
// top-level EvalDirective. Top-level multi-statement
// bodies are wrapped in a cx.ProgramLiteral{kind: .block}; single-
// statement bodies surface the lone node directly.
fn program_is_code(prog cx.Program) bool {
	body := prog.body
	if body is cx.ProgramLiteral && body.kind == .block {
		for item in body.items {
			if node_is_directive(item) { return true }
		}
		return false
	}
	return node_is_directive(body)
}

fn node_is_directive(n cx.ProgramNode) bool {
	if n is cx.ProgramDirective { return true }
	if n is cx.ProgramForComp { return true }
	return false
}

// is_data_statement returns true iff a top-level statement is a plain
// data element (a cx-element or scalar literal) — i.e. an entity in
// ERD parlance that shouldn't render as a CFG basic-block.
fn is_data_statement(n cx.ProgramNode) bool {
	if n is cx.ProgramLiteral {
		match n.kind {
			.cx_element, .int_lit, .float_lit, .bool_lit, .string_lit,
			.duration_lit, .date_lit, .datetime_lit, .atom_lit, .array_lit,
			.map_lit, .sequence_lit {
				return true
			}
			else { return false }
		}
	}
	return false
}

// top_level_statements returns the flat list of top-level statements
// in `prog`. A bare program body is one statement; a `.block` literal
// is its `items` list.
fn top_level_statements(prog cx.Program) []cx.ProgramNode {
	body := prog.body
	if body is cx.ProgramLiteral && body.kind == .block {
		return body.items
	}
	return [body]
}

// code_diagram_cfg_level dispatches to the appropriate CFG emitter for
// the chosen level. Compact is the existing §D4
// emitter (`code_diagram_cfg`). Min drops to top-level `[?def]` boxes
// + `main` with dashed call edges. Full retains compact's basic-block
// shape with INPUT/OUTPUT terminal nodes; per-node expansion and the
// full binding-bridge layer remain a TODO (gate 37.14 partial — what
// ships here covers the terminals and class-tagging; per-node un-
// inlining is a follow-up commit).
pub fn code_diagram_cfg_level(prog cx.Program, level CodeDiagramLevel) !string {
	match level {
		.min     { return code_diagram_cfg_min(prog)! }
		.compact { return code_diagram_cfg(prog)! }
		.full    { return code_diagram_cfg_full(prog)! }
	}
}

// code_diagram_erd_level dispatches to the appropriate ERD emitter for
// the chosen level. Compact is the existing §D3
// emitter (`code_diagram_erd`). Min drops to one box per top-level
// element name (no relationships, no rows). Full adds a synthetic
// DOCUMENT root + value enumerations + occurrence counts (partial —
// per-attribute value enumeration and inferred-FK dashed edges remain
// a TODO; the structural shape lands here).
pub fn code_diagram_erd_level(prog cx.Program, source_text string, level CodeDiagramLevel) !string {
	match level {
		.min     { return code_diagram_erd_min(prog)! }
		.compact { return code_diagram_erd(prog, source_text)! }
		.full    { return code_diagram_erd_full(prog, source_text)! }
	}
}

// ── CFG (flowchart TD) ─────────────────────────────────────────────────────

// CFGState holds the emitter scratch for a single code_diagram_cfg
// invocation. Per-scope counters (so `m`/`a1`/`a2` reset between
// sub-graphs) live on the `Scope` stack; cross-scope identifiers
// (`start`, `done`, sub-graph anchor names) are allocated direct.
struct CFGState {
mut:
	lines   []string
	// exit_id is the local scope's "exit" node id. Inside the main
	// flow this is `done`; inside a `[?def NAME]` sub-graph it's `<L>e`
	// where `<L>` is the first letter of NAME; inside a `[?for]` body
	// it's the loop header id (so body emitters' "→ exit" edges
	// become back-edges to the loop header).
	exit_id string
	// scope_prefix is the per-sub-graph node-id prefix. Empty for
	// main flow (so `[?if]` → `i`, `[?match]` → `m`, etc.); set to
	// the first letter of the `[?def NAME]` for sub-graph bodies
	// (so `[?if]` inside `def countdown` → `ci`).
	scope_prefix string
	// per-scope counters for [?match] arm ids ('a1', 'a2', …) and
	// repeated shapes (target nodes inside if/match arms when more
	// than one needs id-disambiguation).
	match_arm_count int
	target_count    int
	// def_name is the name of the enclosing `[?def NAME]` for the
	// current scope; empty at main-flow level. Used to detect
	// self-recursive call sites (cfg-008 fixture convention: a body
	// node whose label is a call to `def_name` redirects its outgoing
	// edge to the def entry rather than the def exit).
	def_name string
	// def_entry_id is the entry node id (`<L>s`) of the enclosing
	// def; populated alongside def_name. Empty at main-flow level.
	def_entry_id string
}

struct CFGScopeSave {
	scope_prefix    string
	exit_id         string
	match_arm_count int
	target_count    int
	def_name        string
	def_entry_id    string
}

fn (mut s CFGState) push_scope(prefix string) CFGScopeSave {
	saved := CFGScopeSave{
		scope_prefix:    s.scope_prefix
		exit_id:         s.exit_id
		match_arm_count: s.match_arm_count
		target_count:    s.target_count
		def_name:        s.def_name
		def_entry_id:    s.def_entry_id
	}
	s.scope_prefix = prefix
	s.match_arm_count = 0
	s.target_count = 0
	return saved
}

fn (mut s CFGState) pop_scope(saved CFGScopeSave) {
	s.scope_prefix = saved.scope_prefix
	s.exit_id = saved.exit_id
	s.match_arm_count = saved.match_arm_count
	s.target_count = saved.target_count
	s.def_name = saved.def_name
	s.def_entry_id = saved.def_entry_id
}

// scoped_id returns `<prefix><role>` — e.g. role=`i` in scope=`c` →
// `ci`; role=`lh` in scope=`` → `lh`. Used to mint the static role-
// based ids the conformance fixtures rely on.
fn (s CFGState) scoped_id(role string) string {
	return s.scope_prefix + role
}

// code_diagram_cfg emits a Mermaid `flowchart TD` for `prog`. Each
// top-level `[?def]` becomes its own sub-graph; remaining top-level
// statements compose the main flow with a single `start([entry])` →
// … → `done([exit])` envelope.
pub fn code_diagram_cfg(prog cx.Program) !string {
	mut s := CFGState{
		lines:        []string{}
		exit_id:      ''
		scope_prefix: ''
	}
	s.lines << 'flowchart TD'
	stmts := top_level_statements(prog)
	// First pass: emit sub-graphs for top-level [?def] statements.
	for stmt in stmts {
		if stmt is cx.ProgramDirective && stmt.name == 'def' {
			emit_def_subgraph(stmt, mut s)!
		}
	}
	// Second pass: emit main flow from the non-def statements. Data
	// elements (`[user …]`, scalar literals, …) that appear at top
	// level *alongside* `[?def]` blocks are not rendered as CFG nodes
	// — per the cfg-010 / auto-003 fixture convention, the program's
	// "main flow" only contains EvalDirectives + ForComps + Calls.
	// Trailing data elements after a [?def] are treated as scaffold
	// for `[?def]`-only programs and dropped.
	mut main_stmts := []cx.ProgramNode{}
	for stmt in stmts {
		if stmt is cx.ProgramDirective && stmt.name == 'def' { continue }
		if is_data_statement(stmt) { continue }
		main_stmts << stmt
	}
	if main_stmts.len > 0 {
		start_id := 'start'
		s.exit_id = 'done'
		s.scope_prefix = ''
		s.lines << '  ${start_id}([entry])'
		s.lines << '  ${s.exit_id}([exit])'
		// Walk main statements as one combined flow.
		mut prev_exit := start_id
		mut i := 0
		for i < main_stmts.len {
			stmt := main_stmts[i]
			// Group sequential non-branching directives into a basic
			// block. Branching/looping/modify/def break the run.
			if is_block_candidate(stmt) {
				mut group := []cx.ProgramNode{}
				for i < main_stmts.len && is_block_candidate(main_stmts[i]) {
					group << main_stmts[i]
					i++
				}
				bid := emit_block_node(group, mut s)
				s.lines << '  ${prev_exit} --> ${bid}'
				prev_exit = bid
				continue
			}
			emit_stmt_entry, emit_stmt_exit := emit_branching(stmt, mut s)!
			s.lines << '  ${prev_exit} --> ${emit_stmt_entry}'
			prev_exit = emit_stmt_exit
			i++
		}
		// Final hop to exit unless the last branch already terminated
		// at the exit (e.g. an `[?if]` whose both arms join `done`).
		if prev_exit != s.exit_id {
			s.lines << '  ${prev_exit} --> ${s.exit_id}'
		}
	}
	return s.lines.join('\n')
}

// is_block_candidate returns true iff `n` is a sequential non-
// branching directive eligible for basic-block composition. Per §D4
// branching directives ([?if]/[?match]), loops ([?for]), [?modify],
// and [?def] all break the block.
fn is_block_candidate(n cx.ProgramNode) bool {
	if n is cx.ProgramDirective {
		match n.name {
			'if', 'match', 'modify', 'def', 'for' { return false }
			else { return true }
		}
	}
	if n is cx.ProgramForComp { return false }
	// Non-directive top-level nodes (cx-elements, calls, literals,
	// path-exprs, bindings) still appear in basic blocks: they're
	// expression-level statements with linear control flow.
	return true
}

// emit_block_node creates one basic-block node from a run of
// sequential statements. Label is each statement's source-shape on
// its own line, capped at `max_block_lines` with a `(+K more)` row.
//
// The node id is the scope's `lb` (loop-body) when inside a `[?for]`
// (the body is the single block node attached to the loop header)
// or the scope's `b` (block) when at the main-flow level. Inside a
// `[?def]` sub-graph the prefix carries through.
fn emit_block_node(group []cx.ProgramNode, mut s CFGState) string {
	role := if s.exit_id.ends_with('lh') { 'lb' } else { 'b' }
	id := s.scoped_id(role)
	mut label_lines := []string{}
	for i, stmt in group {
		if label_lines.len >= max_block_lines {
			remaining := group.len - i
			label_lines << '(+${remaining} more)'
			break
		}
		label_lines << stmt_short_label(stmt)
	}
	label := mermaid_escape(label_lines.join('\n'))
	s.lines << '  ${id}["${label}"]'
	return id
}

// stmt_short_label renders one statement as a short one-line label
// suitable for inclusion inside a basic-block node body. Directive-
// shaped statements emit `[?name …]`; everything else emits its
// source-shape.
fn stmt_short_label(n cx.ProgramNode) string {
	return short_label(n)
}

// emit_branching dispatches `[?if]` / `[?match]` / `[?for]` /
// `[?modify]` and returns (entry-id, exit-id) for the emitted shape.
// Non-branching nodes raise — caller must check is_block_candidate
// first.
fn emit_branching(n cx.ProgramNode, mut s CFGState) !(string, string) {
	if n is cx.ProgramDirective {
		match n.name {
			'if'     { return emit_if(n, mut s) }
			'match'  { return emit_match(n, mut s) }
			'modify' { return emit_modify(n, mut s) }
			else {}
		}
	}
	if n is cx.ProgramForComp {
		return emit_for(n, mut s)
	}
	return error('emit_branching: not a branching node')
}

// emit_if renders `[?if cond :then T :else E]` as a diamond with two
// arms. Returns (entry, exit) where exit is the diagram-wide done
// node (both arms join at `done`).
fn emit_if(d cx.ProgramDirective, mut s CFGState) (string, string) {
	id := s.scoped_id('i')
	mut cond_label := ''
	mut then_branch := cx.ProgramNode(cx.ProgramLiteral{kind: .string_lit})
	mut else_branch := cx.ProgramNode(cx.ProgramLiteral{kind: .string_lit})
	mut have_then := false
	mut have_else := false
	for slot in d.slots {
		if slot.kind == .positional {
			// Clause-child form: a positional cx_element named `then` /
			// `else` carries the branch body (`[?if COND [then T]
			// [else E]]`). Otherwise the first positional is the cond.
			if slot.value is cx.ProgramLiteral {
				lit := slot.value as cx.ProgramLiteral
				if lit.kind == .cx_element && (lit.name == 'then' || lit.name == 'else') {
					body := clause_body(lit) or { continue }
					if lit.name == 'then' { then_branch = body; have_then = true }
					else { else_branch = body; have_else = true }
					continue
				}
			}
			if cond_label == '' {
				cond_label = short_label(slot.value)
				continue
			}
		}
		if slot.kind == .labeled {
			if slot.label == 'then' { then_branch = slot.value; have_then = true }
			else if slot.label == 'else' { else_branch = slot.value; have_else = true }
		}
	}
	full_label := if cond_label != '' { 'if ${cond_label}' } else { 'if' }
	s.lines << '  ${id}{"${mermaid_escape(full_label)}"}'
	if have_then {
		t_id := emit_arm_target(then_branch, mut s, 't')
		s.lines << '  ${id} -- "true" --> ${t_id}'
		// Recursion: a then-arm calling the enclosing def loops back
		// to the def entry rather than threading through the exit.
		t_tail := arm_tail(then_branch, mut s)
		s.lines << '  ${t_id} --> ${t_tail}'
	}
	if have_else {
		// Inside a `[?def]` scope the natural else-arm role `e`
		// collides with the sub-graph's exit-node role (also `e`),
		// so fixture-convention picks `r` (recursive/return arm).
		// At main-flow level `e` is free.
		else_role := if s.scope_prefix != '' { 'r' } else { 'e' }
		e_id := emit_arm_target(else_branch, mut s, else_role)
		s.lines << '  ${id} -- "false" --> ${e_id}'
		e_tail := arm_tail(else_branch, mut s)
		s.lines << '  ${e_id} --> ${e_tail}'
	}
	return id, s.exit_id
}

// clause_body extracts the body of an clause-child cx_element
// (e.g. `[then T]` / `[else E]` / `[case P B]`). Returns the single
// inner item, or a block wrapping multiple items, or none for empty.
// Mirrors eval.v's `clause_child` body-extraction logic.
fn clause_body(lit cx.ProgramLiteral) ?cx.ProgramNode {
	if lit.items.len == 0 {
		// Empty clause-child — slot-bearing form like `[case [from CH $msg] H]`
		// keeps the bound clauses in `slots` instead of `items`.
		if lit.slots.len == 0 { return none }
	}
	if lit.items.len == 1 {
		return cx.ProgramNode(lit.items[0])
	}
	return cx.ProgramNode(cx.ProgramLiteral{
		kind:  .block
		items: lit.items
		pos:   lit.pos
	})
}

// arm_tail returns the back-edge target for an if/match arm body. If
// the body is a self-recursive call to the enclosing `[?def NAME]`,
// the tail is the def's entry node id (cfg-008 fixture: `cr --> cs`).
// Otherwise the tail is the current scope's exit id.
fn arm_tail(n cx.ProgramNode, mut s CFGState) string {
	if s.def_name != '' && is_self_call(n, s.def_name) {
		return s.def_entry_id
	}
	return s.exit_id
}

// is_self_call returns true iff `n` invokes a function named
// `def_name` — either as a bare cx.ProgramCall, or as a cx_element
// literal `[def_name args…]` (the bracket-positional call surface).
fn is_self_call(n cx.ProgramNode, def_name string) bool {
	if n is cx.ProgramCall { return n.name == def_name }
	if n is cx.ProgramLiteral && n.kind == .cx_element {
		return n.name == def_name
	}
	return false
}

// emit_match renders `[?match expr :case P B … :else E]` as a
// dispatcher round-rect with one outgoing edge per arm. Arm labels
// derive from the pattern source; bodies become target nodes.
fn emit_match(d cx.ProgramDirective, mut s CFGState) (string, string) {
	id := s.scoped_id('m')
	mut subj := ''
	// Collect arms: alternating (pattern, body) for :case and (sentinel,
	// body) for :else. Iterate slot list preserving source order.
	mut arms := []MatchArm{}
	mut pending_pat := ?cx.ProgramNode(none)
	mut pending_else := false
	for slot in d.slots {
		if slot.kind == .positional && subj == '' {
			subj = short_label(slot.value)
			continue
		}
		if slot.kind == .labeled {
			match slot.label {
				'case' {
					pending_pat = slot.value
					pending_else = false
				}
				'else' {
					pending_else = true
					pending_pat = none
				}
				'yield' {
					if pending_else {
						arms << MatchArm{ label: 'else', body: slot.value }
						pending_else = false
					} else if p := pending_pat {
						arms << MatchArm{ label: arm_pattern_label(p), body: slot.value }
						pending_pat = none
					}
				}
				else {}
			}
			continue
		}
		// Positional after the subject: the 2-arg `[?match expr body]`
		// shape doesn't have arms; the body short-circuits as a single
		// pass-through. Skipping is correct — that form falls back to
		// the basic-block path; this branch is only reached for the
		// multi-arm shape.
	}
	full_label := if subj != '' { 'match ${subj}' } else { 'match' }
	s.lines << '  ${id}{"${mermaid_escape(full_label)}"}'
	for arm in arms {
		s.match_arm_count++
		// Inside a `[?def]` sub-graph match arm role is `t<N>`
		// (then-arm-N — per cfg-010 fixture convention `ct1`, `ct2`);
		// at main-flow level it's `a<N>` per cfg-003..cfg-005.
		role := if s.scope_prefix != '' {
			't${s.match_arm_count}'
		} else {
			'a${s.match_arm_count}'
		}
		aid := s.scoped_id(role)
		body_label := short_label(arm.body)
		s.lines << '  ${aid}["${mermaid_escape(body_label)}"]'
		s.lines << '  ${id} -- "${mermaid_escape(arm.label)}" --> ${aid}'
		s.lines << '  ${aid} --> ${s.exit_id}'
	}
	return id, s.exit_id
}

struct MatchArm {
	label string
	body  cx.ProgramNode
}

fn arm_pattern_label(n cx.ProgramNode) string {
	// Strip the leading/trailing quote pair on string-shaped arm
	// patterns so the edge label reads as the bare pattern text. This
	// covers two cases: (a) cfg-004 fixture writers chose pattern
	// labels like `< 13` (a CX expression, not a string); (b) the
	// patch_match_arms rewrite wraps `[…]`-shape patterns in strings
	// to bypass the Phase 2.4 pattern-mode check on `:case`. Either
	// way, the label users see in the diagram is the raw pattern text.
	raw := if n is cx.ProgramLiteral && n.kind == .string_lit {
		n.str_val
	} else {
		short_label(n)
	}
	if raw.len <= max_match_arm_label { return raw }
	return raw[..max_match_arm_label] + '…'
}

// emit_for renders `[?for $x :in seq :yield body]` as a loop-box
// (header + body + exit). Header label `for $x :in seq`; header→body
// labeled `binds $x`; body→header back-edge; header→exit closes the
// loop when the sequence is exhausted.
fn emit_for(f cx.ProgramForComp, mut s CFGState) (string, string) {
	lh := s.scoped_id('lh')
	mut bind_name := ''
	mut source_label := ''
	for c in f.clauses {
		if c.kind == .generator {
			bind_name = c.bind
			if src := c.source {
				source_label = short_label(src)
			}
			break
		}
	}
	header := if bind_name != '' && source_label != '' {
		'for \$${bind_name} :in ${source_label}'
	} else if bind_name != '' {
		'for \$${bind_name}'
	} else {
		'for'
	}
	s.lines << '  ${lh}{{"${mermaid_escape(header)}"}}'
	// Body — recurse so that an [?if] / [?match] / [?for] inside the
	// yield expression renders as nested CFG with back-edges into the
	// loop header. The body's exit is rewired from the diagram-wide
	// done node to the loop header so each iteration loops back; the
	// header→done edge closes the loop on sequence exhaustion.
	saved_exit := s.exit_id
	s.exit_id = lh
	body_entry, _ := emit_body(f.yield, bind_name, mut s)
	s.exit_id = saved_exit
	// Edge from header to body — labeled `binds $name`.
	if bind_name != '' {
		s.lines << '  ${lh} -- "binds \$${bind_name}" --> ${body_entry}'
	} else {
		s.lines << '  ${lh} --> ${body_entry}'
	}
	return lh, lh
}

// emit_body handles the body of a [?for] :yield slot. For simple
// expressions it emits one basic-block node; for branching directives
// it dispatches to the matching emitter and chains.
fn emit_body(n cx.ProgramNode, bind_name string, mut s CFGState) (string, string) {
	_ = bind_name
	if is_block_candidate(n) {
		group := [n]
		id := emit_block_node(group, mut s)
		// Body → header back-edge.
		s.lines << '  ${id} --> ${s.exit_id}'
		return id, id
	}
	entry, _ := emit_branching(n, mut s) or {
		// Fall back to block on emitter failure.
		group := [n]
		id := emit_block_node(group, mut s)
		s.lines << '  ${id} --> ${s.exit_id}'
		return id, id
	}
	return entry, entry
}

// emit_modify renders `[?modify focus :action …]` as a single
// update-block. Label format: `modify @ <focus> | <action> | …`.
fn emit_modify(d cx.ProgramDirective, mut s CFGState) (string, string) {
	id := s.scoped_id('u')
	mut focus := ''
	mut actions := []string{}
	mut saw_positional := 0
	for slot in d.slots {
		if slot.kind == .positional {
			saw_positional++
			// First positional is doc (when explicit-doc form); second is
			// focus path. Single positional → that one is focus.
			focus = short_label(slot.value)
			continue
		}
		if slot.kind == .labeled { actions << slot.label }
	}
	mut parts := ['modify @ ${focus}']
	for a in actions { parts << a }
	label := parts.join(' | ')
	s.lines << '  ${id}["${mermaid_escape(label)}"]'
	return id, id
}

// emit_arm_target emits one arm-target node (rect) for an [?if]
// branch arm. The node label is the short-label of the arm body.
fn emit_arm_target(n cx.ProgramNode, mut s CFGState, role string) string {
	id := s.scoped_id(role)
	label := short_label(n)
	s.lines << '  ${id}["${mermaid_escape(label)}"]'
	return id
}

// emit_def_subgraph emits a Mermaid `subgraph NAME … end` block for
// a `[?def]` directive. The body is rendered as a self-contained CFG
// rooted at a trapezoid entry node `[/"def NAME"/]` and terminated by
// a stadium exit node.
fn emit_def_subgraph(d cx.ProgramDirective, mut s CFGState) ! {
	name, body := def_name_and_body(d)!
	// Per fixture convention, sub-graph nodes share a prefix derived
	// from the first character of the def name (lowercased, ASCII).
	// `greet` → `g`; `countdown` → `c`; `classify` → `c`.
	prefix := if name.len > 0 { name[..1].to_lower() } else { 'x' }
	saved := s.push_scope(prefix)
	entry_id := s.scoped_id('s')
	exit_id := s.scoped_id('e')
	s.exit_id = exit_id
	s.def_name = name
	s.def_entry_id = entry_id
	s.lines << '  subgraph ${name}'
	s.lines << '    ${entry_id}[/"def ${name}"/]'
	s.lines << '    ${exit_id}([exit])'
	if is_block_candidate(body) {
		// One block child — id is scope's `b`.
		gid := s.scoped_id('b')
		mut label_lines := []string{}
		label_lines << stmt_short_label(body)
		label := mermaid_escape(label_lines.join('\n'))
		s.lines << '    ${gid}["${label}"]'
		s.lines << '  ${entry_id} --> ${gid}'
		s.lines << '  ${gid} --> ${exit_id}'
	} else {
		entry, _ := emit_branching(body, mut s) or {
			gid := s.scoped_id('b')
			label := mermaid_escape(stmt_short_label(body))
			s.lines << '    ${gid}["${label}"]'
			s.lines << '  ${entry_id} --> ${gid}'
			s.lines << '  ${gid} --> ${exit_id}'
			s.lines << '  end'
			s.pop_scope(saved)
			return
		}
		s.lines << '  ${entry_id} --> ${entry}'
	}
	s.lines << '  end'
	s.pop_scope(saved)
}

// def_name_and_body extracts the name and body from a `[?def …]`
// directive. Two surface forms are accepted (parser-level normalised):
//   - `[?def :name N (params) :body BODY]` — labeled-slot form.
//   - `[?def [N params BODY]]` — bracket-positional form (parser emits
//     a single positional slot containing a cx-element).
fn def_name_and_body(d cx.ProgramDirective) !(string, cx.ProgramNode) {
	mut name := ''
	mut body := ?cx.ProgramNode(none)
	// Per parser.v parse_module_directive, `[?def …]` is captured as a
	// single labeled `raw-source` string slot — the structural parse is
	// deferred to eval time via cx.parse_def. Mirror that here so the
	// diagram emitter sees the same DefNode the evaluator does.
	if d.slots.len == 1 && d.slots[0].kind == .labeled
	   && d.slots[0].label == 'raw-source' {
		v := d.slots[0].value
		if v is cx.ProgramLiteral && v.kind == .string_lit {
			def_node := cx.parse_def(v.str_val) or {
				return error('[?def] parse: ${err.msg()}')
			}
			body_prog := cx.parse_program(def_node.body) or {
				return error('[?def] body parse: ${err.msg()}')
			}
			// `parse_program` returns a cx.Program; the body for the diagram
			// is its last top-level statement (or the whole program when
			// there are multiple).
			body_stmts := top_level_statements(body_prog)
			if body_stmts.len == 0 {
				return error('[?def] empty body')
			}
			body_node := if body_stmts.len == 1 {
				body_stmts[0]
			} else {
				cx.ProgramNode(cx.ProgramLiteral{
					kind: .block
					items: body_stmts
					pos: d.pos
				})
			}
			nm := if def_node.name == '' { 'anon' } else { def_node.name }
			return nm, body_node
		}
	}
	// Fall-back legacy paths (kept for any non-raw-source synthetic
	// directives the V tests may feed in).
	mut positionals := []cx.ProgramNode{}
	for slot in d.slots {
		if slot.kind == .labeled {
			if slot.label == 'name' {
				v := slot.value
				if v is cx.ProgramCall { name = v.name }
				else if v is cx.ProgramLiteral {
					if v.kind == .string_lit { name = v.str_val }
				}
			} else if slot.label == 'body' {
				body = slot.value
			}
			continue
		}
		positionals << slot.value
	}
	if positionals.len == 1 {
		sv := positionals[0]
		if sv is cx.ProgramLiteral && sv.kind == .cx_element {
			if name == '' { name = sv.name }
			if sv.items.len > 0 {
				body = sv.items[sv.items.len - 1]
			}
		} else if body == none {
			body = sv
		}
	} else if positionals.len >= 2 {
		first := positionals[0]
		if name == '' {
			if first is cx.ProgramCall { name = first.name }
			else if first is cx.ProgramLiteral && first.kind == .cx_element { name = first.name }
		}
		if body == none {
			body = positionals[positionals.len - 1]
		}
	}
	body_node := body or { return error('[?def] missing body') }
	if name == '' { name = 'anon' }
	return name, body_node
}

// ── ERD (erDiagram) ─────────────────────────────────────────────────────────

struct EntityRow {
	type_str string
	name     string
	is_attr  bool
}

struct Entity {
mut:
	name       string
	rows       []EntityRow
	row_seen   map[string]bool
	// child counts per name across all observed parent instances.
	// >= 2 anywhere → `||--o{`; <= 1 → `||--||`.
	max_child  map[string]int
}

struct ERDState {
mut:
	entities map[string]&Entity
	order    []string
	// relationships keyed by "parent>child" to dedupe; value is the
	// cardinality marker.
	rels     map[string]string
	rel_order []string
}

// erd_entity_name quotes / sanitizes an entity name so the Mermaid ERD
// parser accepts it. Mermaid only allows `[A-Za-z_][A-Za-z0-9_-]*` for
// bare entity names; everything else must be wrapped in `"..."`. This
// matters for element names like `+` / `?` / `*` that show up when a
// user feeds arithmetic-prefix CX into the diagram emitter (#18
// `[+ 1 2 3 4 5]` for instance).
fn erd_entity_name(raw string) string {
	if raw == '' {
		return '"_"'
	}
	mut ok := true
	for i, ch in raw {
		if i == 0 {
			if !((ch >= `A` && ch <= `Z`) || (ch >= `a` && ch <= `z`) || ch == `_`) {
				ok = false
				break
			}
		} else if !((ch >= `A` && ch <= `Z`) || (ch >= `a` && ch <= `z`)
		    || (ch >= `0` && ch <= `9`) || ch == `_` || ch == `-`) {
			ok = false
			break
		}
	}
	if ok {
		return raw
	}
	mut esc := []u8{cap: raw.len + 2}
	esc << `"`
	for ch in raw {
		if ch == `"` {
			esc << `\\`
			esc << `"`
		} else if ch == `\\` {
			esc << `\\`
			esc << `\\`
		} else {
			esc << ch
		}
	}
	esc << `"`
	return esc.bytestr()
}

// code_diagram_erd emits a Mermaid `erDiagram` for a data source. The
// input AST is re-walked at the cx_element level; the original
// `source_text` is currently unused but preserved in the signature
// for symmetry with `render_diagram(prog, source_text, fmt)`.
pub fn code_diagram_erd(prog cx.Program, source_text string) !string {
	_ = source_text
	mut st := ERDState{
		entities: map[string]&Entity{}
		order:    []string{}
		rels:     map[string]string{}
		rel_order: []string{}
	}
	// Walk top-level statements as entity instances.
	for stmt in top_level_statements(prog) {
		walk_entity(stmt, mut st)
	}
	mut out := []string{}
	out << 'erDiagram'
	for k in st.rel_order {
		card := st.rels[k]
		parts := k.split('>')
		if parts.len == 2 {
			out << '  ${erd_entity_name(parts[0])} ${card} ${erd_entity_name(parts[1])} : has'
		}
	}
	for name in st.order {
		ent := st.entities[name] or { continue }
		out << '  ${erd_entity_name(name)} {'
		for row in ent.rows {
			prefix := if row.is_attr { '@' } else { '' }
			out << '    ${row.type_str} ${prefix}${row.name}'
		}
		out << '  }'
	}
	return out.join('\n')
}

fn walk_entity(n cx.ProgramNode, mut st ERDState) {
	if n !is cx.ProgramLiteral { return }
	lit := n as cx.ProgramLiteral
	if lit.kind != .cx_element || lit.name == '' { return }
	ent_name := lit.name
	st.ensure_entity(ent_name)
	mut ent := st.entities[ent_name] or { return }
	// Attributes (`name=value` → `@name`). The retired `:label value`
	// element-literal slot surface (D014) no longer parses, so ERD
	// attribute rows derive from real element attributes.
	for attr in lit.attrs {
		tstr := scalar_type_str(attr.value)
		row_key := '@' + attr.name
		if !ent.row_seen[row_key] {
			ent.rows << EntityRow{
				type_str: tstr
				name:     attr.name
				is_attr:  true
			}
			ent.row_seen[row_key] = true
		}
	}
	// Per-instance child counts (for cardinality on first parent
	// observation).
	mut local_counts := map[string]int{}
	for item in lit.items {
		if item is cx.ProgramLiteral && item.kind == .cx_element {
			c := item as cx.ProgramLiteral
			if c.name == '' { continue }
			// Scalar child = element with exactly one scalar item and
			// no attrs, no slots, no child elements.
			if is_scalar_child(c) {
				val := scalar_text_value(c)
				tstr := scalar_type_str(val)
				row_key := c.name
				if !ent.row_seen[row_key] {
					ent.rows << EntityRow{
						type_str: tstr
						name:     c.name
						is_attr:  false
					}
					ent.row_seen[row_key] = true
				}
			} else {
				// Sub-entity. Count + record relationship.
				local_counts[c.name] = local_counts[c.name] + 1
				walk_entity(item, mut st)
			}
		}
	}
	// Update max-child counts per name; promote to ||--o{ if >= 2.
	for cname, count in local_counts {
		prev := ent.max_child[cname] or { 0 }
		new_max := if count > prev { count } else { prev }
		ent.max_child[cname] = new_max
		card := if new_max >= 2 { '||--o{' } else { '||--||' }
		key := ent_name + '>' + cname
		if existing := st.rels[key] {
			if existing != card { st.rels[key] = card }
		} else {
			st.rels[key] = card
			st.rel_order << key
		}
	}
}

fn (mut st ERDState) ensure_entity(name string) {
	if name !in st.entities {
		st.entities[name] = &Entity{
			name: name
			rows: []EntityRow{}
			row_seen: map[string]bool{}
			max_child: map[string]int{}
		}
		st.order << name
	}
}

fn is_scalar_child(c cx.ProgramLiteral) bool {
	if c.attrs.len > 0 { return false }
	if c.slots.len > 0 { return false }
	if c.items.len != 1 { return false }
	item := c.items[0]
	if item is cx.ProgramLiteral {
		return item.kind == .string_lit || item.kind == .int_lit
		       || item.kind == .float_lit || item.kind == .bool_lit
		       || item.kind == .atom_lit
	}
	return false
}

fn scalar_text_value(c cx.ProgramLiteral) cx.ProgramNode {
	if c.items.len == 1 { return c.items[0] }
	return cx.ProgramLiteral{kind: .string_lit, str_val: ''}
}

// scalar_type_str maps a CX scalar literal to the ERD attribute type
// name. Mermaid `erDiagram` requires a leading type token on every
// attribute row; we use SQL-flavoured names (`int`, `string`,
// `float`, `bool`).
fn scalar_type_str(n cx.ProgramNode) string {
	if n is cx.ProgramLiteral {
		match n.kind {
			.int_lit { return 'int' }
			.float_lit { return 'float' }
			.bool_lit { return 'bool' }
			.atom_lit { return 'atom' }
			.string_lit { return 'string' }
			else { return 'string' }
		}
	}
	return 'string'
}

// ── Shared label helpers ───────────────────────────────────────────────────

// short_label renders one AST node as a brief one-line label for use
// inside a Mermaid node body. Strings keep their quotes; bindings
// keep their `$` sigil; nested elements collapse to `[NAME …]`.
fn short_label(n cx.ProgramNode) string {
	match n {
		cx.ProgramLiteral {
			match n.kind {
				.string_lit { return "'${n.str_val}'" }
				.int_lit    { return n.int_val.str() }
				.float_lit  { return n.flt_val.str() }
				.bool_lit   { return n.bool_val.str() }
				.atom_lit   { return ':${n.str_val}' }
				.duration_lit { return n.dur_val }
				.cx_element {
					mut parts := ['[' + n.name]
					if n.items.len > 0 {
						for it in n.items {
							parts << short_label(it)
						}
					}
					return parts.join(' ') + ']'
				}
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
			mut parts := [n.name]
			for a in n.args {
				parts << short_label(a)
			}
			return '[' + parts.join(' ') + ']'
		}
		cx.ProgramDirective {
			return '[?${n.name}]'
		}
		cx.ProgramForComp {
			return '[?for]'
		}
		cx.ProgramPathExpr {
			// Use the canonical renderer when available; fall back to
			// the raw `//name` shape when the renderer rejects (e.g.
			// shapes outside the Phase 2.3 supported subset).
			return render_path_or_fallback(n)
		}
		cx.ProgramPattern {
			return '[' + n.head.value + ']'
		}
		cx.ProgramSliceAccess {
			// W5b parser-only placeholder; canonical short-label form
			// is finalised in W5c alongside the evaluator surface.
			return short_label(n.binding) + '[…]'
		}
		cx.ProgramSliceLiteral {
			// first-class Slice literal short label.
			return '[slice]'
		}
		cx.ProgramWildcard {
			return if n.deep { '**' } else { '*' }
		}
		cx.Program {
			return short_label(n.body)
		}
	}
}

fn render_path_or_fallback(p cx.ProgramPathExpr) string {
	// Inline the leading + first step verbatim; further steps elided.
	// The canonical renderer (Phase 2.9) lives in `vcx/cx/path_renderer.v`
	// — outside this module's import graph at the moment; the inline
	// shape below is sufficient for label use.
	mut out := match p.leading {
		.absolute   { '/' }
		.descendant { '//' }
		.relative   { '' }
	}
	for i, st in p.steps {
		if i > 0 { out += '/' }
		out += st.name
	}
	return out
}

// ── SEQ (sequenceDiagram) ──────────────────────────────────────────────────
//
// Top-level sequence-trigger directives
// `[?worker]`, `[?channel]`, `[?http-service]`, `[?select]`,
// `[?async]` — route here. Each actor lane (`participant NAME`) is
// declared first; then message arrows + activation blocks per the
// normative `spec/code.md §10.1.2` table. Mermaid syntax:
//
//   sequenceDiagram
//     participant producer
//     participant jobs
//     participant consumer
//
//     activate producer
//     producer ->>+ jobs : 1
//     deactivate producer
//     activate consumer
//     jobs -->>- consumer : 1
//     deactivate consumer
//
// The emitter walks the program in document order; nested directives
// inside worker bodies emit their own arrows. The result is one
// `sequenceDiagram` string (one diagram, not multiple).

// SeqState holds the per-diagram emitter scratch — actor lanes,
// channel-binding-name → lane-name map, output lines.
struct SeqState {
mut:
	lines       []string
	participants []string
	participant_seen map[string]bool
	// channel_name maps a `$bindname` for a channel to its lane name.
	channel_name map[string]string
	// async_count tracks anonymous `[?async]` lane numbering.
	async_count   int
	level         CodeDiagramLevel
	// current_worker holds the active worker name during body walk,
	// used to scope send/receive arrows to the right actor lane.
	current_worker string
	// have_http_service is set when a `[?http-service]` is at top level
	// so the implicit `client` lane is declared.
	have_http_service bool
	// have_async marks whether we declared the `caller` lane.
	have_async bool
	// activation tracks per-participant activation depth so we never
	// emit `->>+` against an already-active participant or `-->>-`
	// against an inactive one — Mermaid's sequenceDiagram parser fails
	// fast on either mismatch. Each `activate NAME` / arrow with `+`
	// suffix increments; each `deactivate NAME` / arrow with `-` suffix
	// decrements (clamped to 0).
	activation map[string]int
}

// code_diagram_seq emits a Mermaid `sequenceDiagram` for a sequence-
// shape `prog`. Three detail levels:
//
//   - `min`: actor lanes only. One `participant` per top-level
//     `[?worker]` + `client` for `[?http-service]` + `caller` for
//     `[?async]`. No arrows, no channel lanes, no activations.
//   - `compact`: D13 baseline. Actor lanes + channel lanes + message
//     arrows per `[?send]` / `[?receive]` / inbound `[?http-service]`
//     resources + alt frames for `[?select]` + sync barriers for
//     `[?await]` etc. Resilience-wrapped activations carry a
//     single-letter policy badge.
//   - `full`: compact + payload-shape labels + per-arrow source
//     spans + resilience-policy notes expanded + binding-resolution
//     dashes + step-back collapse rules.
pub fn code_diagram_seq(prog cx.Program, level CodeDiagramLevel) !string {
	mut s := SeqState{
		lines:            []string{}
		participants:     []string{}
		participant_seen: map[string]bool{}
		channel_name:     map[string]string{}
		level:            level
		activation:       map[string]int{}
	}
	s.lines << 'sequenceDiagram'

	raw_stmts := top_level_statements(prog)
	mut stmts := []cx.ProgramNode{}
	for raw in raw_stmts {
		s.flatten_let_seq_aliasing(raw, mut stmts)
	}

	// Full level: INPUT/OUTPUT terminal lanes
	// rules 1 + 2. Declared before any other participant so the
	// playground renders them leftmost / rightmost.
	if level == .full {
		s.add_participant('INPUT')
	}

	// First pass: collect actor lanes (workers, channels, services).
	// This guarantees `participant` declarations precede any message
	// arrow that references them — Mermaid is lenient on this but the
	// conformance runner expects deterministic order.
	for stmt in stmts {
		if stmt is cx.ProgramDirective {
			match stmt.name {
				'worker' {
					name := directive_name_attr(stmt, 'producer')
					s.add_participant(name)
				}
				'channel' {
					name := directive_name_attr(stmt, 'channel')
					s.add_participant(name)
					// Remember the channel by its name + by its `$name`
					// binding (the `:name` slot doubles as both the lane
					// name and the binding alias used by send/receive).
					s.channel_name[name] = name
				}
				'http-service' {
					name := directive_name_attr(stmt, 'svc')
					s.add_participant(name)
					s.add_participant('client')
					s.have_http_service = true
				}
				'async' {
					s.async_count++
					lane := 'async-${s.async_count}'
					s.add_participant(lane)
					s.add_participant('caller')
					s.have_async = true
				}
				else {}
			}
		}
	}

	// Min level: lanes only, no further emission.
	if level == .min {
		return s.lines.join('\n')
	}

	// Full level: also declare the OUTPUT terminal lane after every
	// worker / channel / service lane (so it sits rightmost). Done
	// before the message-arrow second pass so all participants exist
	// up-front.
	if level == .full {
		s.add_participant('OUTPUT')
	}

	// Second pass: emit message arrows + activation blocks per the
	// directive-to-rendering table.
	for stmt in stmts {
		if stmt is cx.ProgramDirective {
			emit_seq_top_directive(stmt, mut s)
		}
	}

	// Full level: emit binding-resolution dashes as Note over lines.
	// Each `[?let [= $x V]]` introduces $x; we annotate the worker /
	// main lane so the reader sees the binding sites alongside the
	// arrow-payload labels per §D12.3 rule 7.
	if level == .full {
		intros := collect_binding_intros(prog)
		for bname in intros {
			lane := if s.current_worker != '' { s.current_worker } else if s.participants.len > 0 { s.participants[0] } else { 'main' }
			s.lines << '  Note over ${lane} : bind \$${bname}'
		}
	}

	return s.lines.join('\n')
}

// flatten_let_seq peers through `[?let [= $x V] BODY]` chains so the
// SEQ emitter can treat the bound values (often `[?channel]` /
// `[?worker]`) and the body uniformly as top-level statements. Mirrors
// the playground's reference idiom for example #161+ where workers
// and channels live inside an outer `[?let]` cascade.
//
// Side effect: when a let binding's value is a `[?channel name=NAME …]`,
// record the alias `$bindname → NAME` so subsequent `to=$bindname` /
// `from=$bindname` refs route to the lane named NAME.
fn (mut s SeqState) flatten_let_seq_aliasing(n cx.ProgramNode, mut out []cx.ProgramNode) {
	if n is cx.ProgramDirective && n.name == 'let' {
		for slot in n.slots {
			v := slot.value
			// `[= $name V]` clause-child: items[0] = $name binding,
			// items[1] = value expression.
			if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == '=' {
				if v.items.len >= 2 {
					bind_name := let_binding_name(v.items[0])
					value_node := v.items[1]
					// Channel-binding alias: `[?let [= $ch [?channel name="lane" ...]]]`
					// → `s.channel_name['ch'] = 'lane'`.
					if bind_name != '' && value_node is cx.ProgramDirective
					   && value_node.name == 'channel' {
						lane := directive_name_attr(value_node, bind_name)
						s.channel_name[bind_name] = lane
					}
					s.flatten_let_seq_aliasing(value_node, mut out)
				}
				continue
			}
			s.flatten_let_seq_aliasing(slot.value, mut out)
		}
		return
	}
	if n is cx.ProgramLiteral && n.kind == .block {
		for it in n.items {
			s.flatten_let_seq_aliasing(it, mut out)
		}
		return
	}
	out << n
}

// let_binding_name extracts the `$name` from the LHS of a `[= $name V]`
// clause-child. Returns empty string if the shape is unexpected.
fn let_binding_name(n cx.ProgramNode) string {
	if n is cx.ProgramBinding {
		if n.path.len == 0 { return n.name }
	}
	return ''
}

// flatten_let_seq is the pre-state-pass entry — historical signature
// preserved for callers that don't need alias-tracking. Re-uses the
// stateful walker against a throw-away SeqState.
fn flatten_let_seq(n cx.ProgramNode, mut out []cx.ProgramNode) {
	mut throwaway := SeqState{
		lines:            []string{}
		participants:     []string{}
		participant_seen: map[string]bool{}
		channel_name:     map[string]string{}
		activation:       map[string]int{}
	}
	throwaway.flatten_let_seq_aliasing(n, mut out)
}

// activate_safe emits `activate NAME` and bumps the activation counter.
// Always safe — Mermaid permits stacked activations.
fn (mut s SeqState) activate_safe(name string) {
	if name == '' { return }
	s.activation[name] = (s.activation[name] or { 0 }) + 1
	s.lines << '  activate ${name}'
}

// deactivate_safe emits `deactivate NAME` only when the participant has
// a live activation; otherwise it is a no-op. Prevents Mermaid's
// "Trying to inactivate an inactive participant" error.
fn (mut s SeqState) deactivate_safe(name string) {
	if name == '' { return }
	depth := s.activation[name] or { 0 }
	if depth <= 0 { return }
	s.activation[name] = depth - 1
	s.lines << '  deactivate ${name}'
}

// send_arrow_kind returns the appropriate arrow for a send `SRC -> DST`.
// Uses `->>+ / -->>+` only when DST is currently inactive (so the `+`
// won't pile up stale activations on a long-lived channel lane).
fn (mut s SeqState) send_arrow_kind(dst string, dashed bool) string {
	depth := s.activation[dst] or { 0 }
	if depth > 0 {
		// Already activated — emit plain arrow to avoid double-stacking.
		return if dashed { '-->>' } else { '->>' }
	}
	// Activate target on this arrow.
	s.activation[dst] = depth + 1
	return if dashed { '-->>+' } else { '->>+' }
}

// receive_arrow_kind returns the arrow for a receive `SRC -> DST`. Uses
// `-->>-` (deactivating SRC) only when SRC has a live activation;
// otherwise emits a plain `-->>` so Mermaid doesn't fail.
fn (mut s SeqState) receive_arrow_kind(src string, dashed bool) string {
	depth := s.activation[src] or { 0 }
	if depth > 0 {
		s.activation[src] = depth - 1
		return if dashed { '-->>-' } else { '->>-' }
	}
	return if dashed { '-->>' } else { '->>' }
}

// add_participant declares a participant lane once (deduped). Mints a
// `participant NAME` line and remembers the name.
fn (mut s SeqState) add_participant(name string) {
	if name == '' { return }
	if s.participant_seen[name] { return }
	s.participant_seen[name] = true
	s.participants << name
	s.lines << '  participant ${name}'
}

// directive_name_attr extracts a `:name` labeled-slot string value
// from a directive, falling back to a default when absent or non-
// string. Handles both string-literal and bare-identifier shapes.
fn directive_name_attr(d cx.ProgramDirective, default_ string) string {
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == 'name' {
			v := slot.value
			if v is cx.ProgramLiteral && v.kind == .string_lit {
				return v.str_val
			}
			if v is cx.ProgramCall {
				return v.name
			}
			if v is cx.ProgramBinding {
				return v.name
			}
		}
		// Bracket-positional shape: first positional carries name.
		if slot.kind == .positional {
			v := slot.value
			if v is cx.ProgramLiteral && v.kind == .string_lit {
				return v.str_val
			}
			if v is cx.ProgramCall && v.name != '' {
				return v.name
			}
		}
	}
	return default_
}

// seq_directive_body extracts the activation body of a directive (for
// `[?worker]`, `[?async]`, etc.). Tries in order:
//   1. Labeled `:body` slot (legacy form).
//   2. First positional clause-child whose element name is `body`
// (clause-child form).
//   3. The last positional slot value — for `[?worker name="X" BODY]`
//      where BODY is bare-positional.
fn seq_directive_body(d cx.ProgramDirective) ?cx.ProgramNode {
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == 'body' {
			return slot.value
		}
	}
	for slot in d.slots {
		if slot.kind == .positional {
			v := slot.value
			if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == 'body' {
				if v.items.len == 1 { return cx.ProgramNode(v.items[0]) }
				return cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: v.items, pos: v.pos })
			}
		}
	}
	mut last := ?cx.ProgramNode(none)
	for slot in d.slots {
		if slot.kind == .positional { last = slot.value }
	}
	return last
}

// emit_seq_top_directive dispatches one top-level directive in a
// sequence-shape program. Workers gain an `activate … deactivate`
// frame around their body emit; services emit their resources;
// channels declare but emit nothing further; selects emit `alt`
// frames; async emits the spawn+resolve arrows.
fn emit_seq_top_directive(d cx.ProgramDirective, mut s SeqState) {
	match d.name {
		'worker' {
			name := directive_name_attr(d, 'worker')
			s.current_worker = name
			s.activate_safe(name)
			if body := seq_directive_body(d) {
				emit_seq_body(body, mut s)
			}
			s.deactivate_safe(name)
			s.current_worker = ''
		}
		'channel' {
			// Lane already declared; no further emission unless the
			// channel is referenced. Channel name aliasing is set up
			// in the first pass.
			_ = d
		}
		'http-service' {
			name := directive_name_attr(d, 'svc')
			emit_seq_http_service(d, name, mut s)
		}
		'async' {
			emit_seq_async_top(d, mut s)
		}
		'select' {
			emit_seq_select(d, mut s)
		}
		'send', 'try-send' {
			// Top-level send (e.g. `[?send 1 to=$ch1]` before a select)
			// emits from `main` as the source actor.
			s.add_participant('main')
			emit_seq_send(d, 'main', mut s)
		}
		'receive', 'try-receive' {
			s.add_participant('main')
			emit_seq_receive(d, 'main', mut s)
		}
		else {
			// Other top-level directives (e.g. setup `[?let]` chains
			// that didn't unwrap, or unsupported shapes) emit as a
			// `Note over main : ...` line.
			s.add_participant('main')
			s.lines << '  Note over main : [?${d.name}]'
		}
	}
}

// emit_seq_body recursively walks a worker / async / select body
// emitting per-directive Mermaid lines per spec/code.md §10.1.2.
fn emit_seq_body(n cx.ProgramNode, mut s SeqState) {
	if n is cx.ProgramDirective {
		emit_seq_inner_directive(n, mut s)
		return
	}
	if n is cx.ProgramForComp {
		// Walk the for-comp yield body — sends/receives inside a loop
		// surface as their plain arrows (no loop frame at compact;
		// `loop` Mermaid frames are a future step-back).
		emit_seq_body(n.yield, mut s)
		return
	}
	if n is cx.ProgramLiteral && n.kind == .block {
		for it in n.items {
			emit_seq_body(it, mut s)
		}
		return
	}
	// Non-directive expression inside a worker body emits as a note.
	worker := if s.current_worker != '' { s.current_worker } else { 'main' }
	label := short_label(n)
	s.lines << '  Note over ${worker} : ${mermaid_escape(label)}'
}

// emit_seq_inner_directive handles one directive inside a worker /
// async / select body. The §10.1.2 directive→Mermaid mapping lives
// here.
fn emit_seq_inner_directive(d cx.ProgramDirective, mut s SeqState) {
	worker := if s.current_worker != '' { s.current_worker } else { 'main' }
	match d.name {
		'send', 'try-send' {
			emit_seq_send(d, worker, mut s)
		}
		'receive', 'try-receive' {
			emit_seq_receive(d, worker, mut s)
		}
		'select' {
			emit_seq_select(d, mut s)
		}
		'async' {
			emit_seq_async_inner(d, mut s)
		}
		'await', 'await-all', 'await-any', 'await-race' {
			emit_seq_await(d, worker, mut s)
		}
		'cancel' {
			emit_seq_cancel(d, worker, mut s)
		}
		'retry', 'timeout', 'circuit-breaker', 'rate-limit', 'bulkhead', 'fallback' {
			emit_seq_resilience(d, worker, mut s)
		}
		'let' {
			// `[?let [= $x V] BODY]` — walk every slot. `[= $x V]`
			// clause-children carry `V` in items[1]; non-clause
			// positionals are body expressions. Channel aliasing was
			// captured at the top-level flatten pass; here we only
			// need to surface inner sends/receives.
			for slot in d.slots {
				v := slot.value
				if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == '=' {
					if v.items.len >= 2 {
						emit_seq_body(v.items[1], mut s)
					}
					continue
				}
				emit_seq_body(slot.value, mut s)
			}
		}
		'if', 'match', 'modify' {
			// Walk into the body for the directives that carry one.
			for slot in d.slots {
				v := slot.value
				// Clause-children carry bodies in their items: e.g.
				// `[then T]` / `[else E]` / `[case P B]`.
				if v is cx.ProgramLiteral && v.kind == .cx_element {
					if v.name == 'then' || v.name == 'else' || v.name == 'case' {
						for it in v.items {
							emit_seq_body(it, mut s)
						}
						continue
					}
				}
				if slot.kind == .labeled {
					if slot.label == 'body' || slot.label == 'yield'
					   || slot.label == 'then' || slot.label == 'else'
					   || slot.label == 'do' {
						emit_seq_body(slot.value, mut s)
					}
				}
			}
		}
		'for' {
			// Plain `[?for]` directive (not the for-comp form). Walk
			// any clause-children + labeled body slots.
			for slot in d.slots {
				v := slot.value
				if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == 'yield' {
					for it in v.items {
						emit_seq_body(it, mut s)
					}
					continue
				}
				if slot.kind == .labeled && slot.label == 'yield' {
					emit_seq_body(slot.value, mut s)
				}
			}
		}
		else {
			s.lines << '  Note over ${worker} : [?${d.name}]'
		}
	}
}

// emit_seq_send renders a send arrow. Two surface shapes the parser
// can hand us:
//   - `[?send V :to $ch]`  — value positional, `:to` labeled with the
//     channel binding.
//   - `[?send $ch V]`       — channel positional 1st, value positional
//     2nd (compact form; only used when no `:to` slot is present).
// Output: `worker ->>+ ch : V`.
fn emit_seq_send(d cx.ProgramDirective, worker string, mut s SeqState) {
	mut value := ?cx.ProgramNode(none)
	mut target := ?cx.ProgramNode(none)
	mut positionals := []cx.ProgramNode{}
	for slot in d.slots {
		if slot.kind == .positional {
			positionals << slot.value
			continue
		}
		if slot.kind == .labeled {
			match slot.label {
				'to'    { target = slot.value }
				'value' { value = slot.value }
				else {}
			}
		}
	}
	// If `:to` was provided, the positionals form the value (may be 1+).
	if target != none {
		if value == none && positionals.len > 0 {
			value = positionals[0]
		}
	} else {
		// No `:to` — the 2-positional `[?send $ch V]` shape: first
		// positional is the channel, second is the value.
		if positionals.len >= 2 {
			target = positionals[0]
			value = positionals[1]
		} else if positionals.len == 1 {
			// Single positional + no `:to` — interpret as send-to-self
			// of the literal. The compact path is `worker ->>+ ch : V`;
			// without a channel binding, fall back to a generic lane.
			value = positionals[0]
		}
	}
	ch_name := if t := target { channel_lane_for(t, mut s) } else { 'channel' }
	val_label := if v := value { short_label(v) } else { 'msg' }
	dashed := d.name == 'try-send'
	arrow_kind := s.send_arrow_kind(ch_name, dashed)
	suffix := if d.name == 'try-send' { ' (try)' } else { '' }
	s.lines << '  ${worker} ${arrow_kind} ${ch_name} : ${mermaid_escape(val_label)}${suffix}'
}

// emit_seq_receive renders `[?receive :from $ch]` as a dashed back-
// arrow from the channel lane to the worker (deactivating).
fn emit_seq_receive(d cx.ProgramDirective, worker string, mut s SeqState) {
	mut target := ?cx.ProgramNode(none)
	mut timeout_label := ''
	for slot in d.slots {
		if slot.kind == .labeled {
			match slot.label {
				'from'    { target = slot.value }
				'timeout' { timeout_label = short_label(slot.value) }
				else {}
			}
			continue
		}
		if slot.kind == .positional && target == none {
			target = slot.value
		}
	}
	ch_name := if t := target { channel_lane_for(t, mut s) } else { 'channel' }
	mut tail := 'msg'
	if d.name == 'try-receive' {
		if timeout_label != '' {
			tail = 'msg (try, ${timeout_label})'
		} else {
			tail = 'msg (try)'
		}
	}
	arrow_kind := s.receive_arrow_kind(ch_name, true)
	s.lines << '  ${ch_name} ${arrow_kind} ${worker} : ${mermaid_escape(tail)}'
}

// channel_lane_for returns the participant lane name for a `$ch`
// binding reference. If the binding name matches a declared channel,
// reuse that lane; otherwise mint a generic `channel` lane.
fn channel_lane_for(n cx.ProgramNode, mut s SeqState) string {
	if n is cx.ProgramBinding && n.path.len == 0 {
		if lane := s.channel_name[n.name] {
			s.add_participant(lane)
			return lane
		}
		// Forward-ref: declare the lane so the diagram is consistent.
		s.add_participant(n.name)
		s.channel_name[n.name] = n.name
		return n.name
	}
	if n is cx.ProgramLiteral && n.kind == .string_lit && n.str_val != '' {
		s.add_participant(n.str_val)
		return n.str_val
	}
	s.add_participant('channel')
	return 'channel'
}

// emit_seq_http_service renders the resources of a `[?http-service]`
// directive. Each `[resource [METHOD PATH] HANDLER]` becomes a
// client→svc request arrow + activation + final response arrow.
fn emit_seq_http_service(d cx.ProgramDirective, svc_name string, mut s SeqState) {
	mut have_resources := false
	for slot in d.slots {
		if slot.kind == .positional {
			v := slot.value
			if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == 'resource' {
				have_resources = true
				method, path := http_resource_method_path(v)
				req_arrow := s.send_arrow_kind(svc_name, false)
				s.lines << '  client ${req_arrow} ${svc_name} : ${method} ${path}'
				resp_arrow := s.receive_arrow_kind(svc_name, true)
				s.lines << '  ${svc_name} ${resp_arrow} client : response'
			}
		}
	}
	if !have_resources {
		s.lines << '  Note over ${svc_name} : no routes'
	}
}

// http_resource_method_path extracts `(METHOD, PATH)` from a `[resource
// [METHOD PATH] HANDLER]` element. Falls back to ('GET', '/').
fn http_resource_method_path(res cx.ProgramLiteral) (string, string) {
	mut method := 'GET'
	mut path := '/'
	for it in res.items {
		if it is cx.ProgramLiteral && it.kind == .cx_element {
			// `[METHOD PATH]` — element name = method, first item = path
			method = it.name.to_upper()
			if it.items.len > 0 {
				first := it.items[0]
				if first is cx.ProgramLiteral && first.kind == .string_lit {
					path = first.str_val
				}
			}
			break
		}
	}
	return method, path
}

// emit_seq_select renders `[?select [case [from $ch $msg] H] …]` as
// an `alt` block, one `else` per additional `[case]`. Two arm
// surfaces are accepted: legacy labeled (`:case CASE`) and 
// clause-child positional (`[case [from $ch $msg] HANDLER]`).
fn emit_seq_select(d cx.ProgramDirective, mut s SeqState) {
	worker := if s.current_worker != '' { s.current_worker } else { 'main' }
	s.add_participant(worker)
	mut first := true
	for slot in d.slots {
		// Recognise both shapes:
		//   - labeled `:case CASE` (legacy)
		//   - positional `[case [from $ch $msg] HANDLER]` clause-child
		mut case_val := ?cx.ProgramNode(none)
		if slot.kind == .labeled && slot.label == 'case' {
			case_val = slot.value
		} else if slot.kind == .positional {
			v := slot.value
			if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == 'case' {
				case_val = v
			}
		}
		cv := case_val or { continue }
		if cv is cx.ProgramLiteral && cv.kind == .cx_element {
			// Heads can appear in `slots` (labeled `:from` / `:timeout`)
			// or in `items[0]` as a clause-child (`[from $ch $msg]` /
			// `[timeout 50ms]`).
			mut head_kind := 'from'
			mut ch_name := 'channel'
			mut timeout_label := ''
			for csl in cv.slots {
				if csl.kind == .labeled {
					match csl.label {
						'from'    { ch_name = channel_lane_for(csl.value, mut s) }
						'timeout' { head_kind = 'timeout'; timeout_label = short_label(csl.value) }
						else {}
					}
				}
			}
			if cv.items.len > 0 {
				first_item := cv.items[0]
				if first_item is cx.ProgramLiteral && first_item.kind == .cx_element {
					match first_item.name {
						'from' {
							if first_item.items.len > 0 {
								ch_name = channel_lane_for(first_item.items[0], mut s)
							}
						}
						'timeout' {
							head_kind = 'timeout'
							if first_item.items.len > 0 {
								timeout_label = short_label(first_item.items[0])
							}
						}
						'default' { head_kind = 'default' }
						else {}
					}
				}
			}
			label := match head_kind {
				'from'    { 'msg from \$${ch_name}' }
				'timeout' { if timeout_label != '' { 'timeout (${timeout_label})' } else { 'timeout' } }
				'default' { 'default' }
				else      { 'case' }
			}
			if first {
				s.lines << '  alt ${label}'
				first = false
			} else {
				s.lines << '  else ${label}'
			}
		}
	}
	if !first {
		s.lines << '  end'
	}
}

// emit_seq_async_top handles `[?async EXPR]` at top level — spawns a
// fresh participant and emits the spawn arrow.
fn emit_seq_async_top(d cx.ProgramDirective, mut s SeqState) {
	s.async_count++
	lane := 'async-${s.async_count}'
	s.add_participant(lane)
	s.add_participant('caller')
	s.lines << '  caller ->> ${lane} : start'
	_ = d
}

// emit_seq_async_inner handles `[?async EXPR]` inside a worker body.
fn emit_seq_async_inner(d cx.ProgramDirective, mut s SeqState) {
	s.async_count++
	lane := 'async-${s.async_count}'
	s.add_participant(lane)
	worker := if s.current_worker != '' { s.current_worker } else { 'caller' }
	s.lines << '  ${worker} ->> ${lane} : start'
	_ = d
}

// emit_seq_await renders `[?await $f]` as a `Note over WORKER :
// await $f` line; await-all / await-any / await-race emit as a
// labelled note (the par/alt block grouping in §10.1.2 is a step-back).
fn emit_seq_await(d cx.ProgramDirective, worker string, mut s SeqState) {
	mut target := ''
	for slot in d.slots {
		if slot.kind == .positional && target == '' {
			target = short_label(slot.value)
		}
	}
	label := if target != '' { '${d.name} ${target}' } else { d.name }
	s.lines << '  Note over ${worker} : ${mermaid_escape(label)}'
}

// emit_seq_cancel renders `[?cancel $f]` as a `worker -x async-N :
// cancel` cross-out arrow.
fn emit_seq_cancel(d cx.ProgramDirective, worker string, mut s SeqState) {
	mut target_lane := 'async'
	for slot in d.slots {
		if slot.kind == .positional {
			v := slot.value
			if v is cx.ProgramBinding && v.path.len == 0 {
				if lane := s.channel_name[v.name] {
					target_lane = lane
				} else {
					target_lane = v.name
					s.add_participant(target_lane)
				}
			}
		}
	}
	s.lines << '  ${worker} -x ${target_lane} : cancel'
}

// emit_seq_resilience wraps the inner expression with a `note over
// WORKER : POLICY` line at compact; at full, the policy parameters
// expand to a `note over … : retry max=N` block per D12.3.
fn emit_seq_resilience(d cx.ProgramDirective, worker string, mut s SeqState) {
	policy := match d.name {
		'retry'           { 'retry' }
		'timeout'         { 'timeout' }
		'circuit-breaker' { 'breaker' }
		'rate-limit'      { 'rate-limit' }
		'bulkhead'        { 'bulkhead' }
		'fallback'        { 'fallback' }
		else              { d.name }
	}
	policy_param := match d.name {
		'retry'           { resilience_param(d, 'max') }
		'timeout'         { resilience_param(d, 'after') }
		'circuit-breaker' { resilience_param(d, 'threshold') }
		'rate-limit'      { resilience_param(d, 'rate') }
		// rule 5 — extended policy-parameter expansion.
		// Bulkhead exposes `max` (concurrent in-flight cap); fallback
		// exposes `recover-with` (the alternate body expression). When
		// the labeled-slot key is absent the param string is empty —
		// fine: the policy label alone still renders.
		'bulkhead'        { resilience_param(d, 'max') }
		'fallback'        { resilience_param(d, 'recover-with') }
		else              { '' }
	}
	label := if s.level == .full && policy_param != '' {
		'${policy} ${policy_param}'
	} else {
		policy
	}
	s.lines << '  Note over ${worker} : ${mermaid_escape(label)}'
	// Recurse into the wrapped body so inner directives still emit.
	for slot in d.slots {
		if slot.kind == .labeled && (slot.label == 'body' || slot.label == 'do') {
			emit_seq_body(slot.value, mut s)
		}
		if slot.kind == .positional {
			emit_seq_body(slot.value, mut s)
		}
	}
}

// resilience_param fetches a `:max N` / `:after DUR` style slot value
// from a resilience-wrapper directive. Returns empty string if absent.
fn resilience_param(d cx.ProgramDirective, key string) string {
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == key {
			return key + '=' + short_label(slot.value)
		}
	}
	return ''
}

// ── CFG/ERD level wrappers (min/full skeletons) ──────────────────────────────

// code_diagram_cfg_min emits the §D12.2 `min` variant for CFG: one
// rectangle per top-level `[?def]` + one `main` rectangle for the
// top-level non-def expression. Dashed call edges between defs and
// from `main` to called defs.
pub fn code_diagram_cfg_min(prog cx.Program) !string {
	mut lines := []string{}
	lines << 'flowchart TD'
	stmts := top_level_statements(prog)
	mut def_names := []string{}
	mut have_main := false
	for stmt in stmts {
		if stmt is cx.ProgramDirective && stmt.name == 'def' {
			// Best-effort name extraction; the structural-parse phase
			// for `[?def]` may fail on the partial parser, but the
			// minimum-rendering invariant only needs the name. Try
			// the canonical path, falling back to scanning the first
			// positional slot for an identifier-shaped value.
			name := def_name_min_extract(stmt)
			if name != '' {
				def_names << name
				lines << '  def_${name}["def ${name}"]'
			}
			continue
		}
		if stmt is cx.ProgramDirective || stmt is cx.ProgramForComp || stmt is cx.ProgramCall {
			have_main = true
		}
	}
	if have_main {
		lines << '  main["main"]'
		// Dashed call edges from main → each def (heuristic — refining
		// to "only defs actually called from main" requires a callgraph
		// walker; min level is overview only).
		for name in def_names {
			lines << '  main -.->|"call"| def_${name}'
		}
	}
	return lines.join('\n')
}

// def_name_min_extract recovers a `[?def]` name even when the full
// body extractor can't (the Phase 2-era partial parser sometimes
// returns an unstructured directive for the new module-directive
// surface). Falls back to scanning slot values for the first
// cx_element name / call name / string literal.
fn def_name_min_extract(d cx.ProgramDirective) string {
	if name, _ := def_name_and_body(d) {
		return name
	}
	for slot in d.slots {
		if slot.kind == .labeled && slot.label == 'name' {
			v := slot.value
			if v is cx.ProgramCall { return v.name }
			if v is cx.ProgramLiteral && v.kind == .string_lit { return v.str_val }
		}
		v := slot.value
		if v is cx.ProgramLiteral && v.kind == .cx_element && v.name != '' {
			return v.name
		}
		if v is cx.ProgramCall && v.name != '' { return v.name }
	}
	return ''
}

// code_diagram_cfg_full emits a `full`-level CFG.
// Layers atop the compact `code_diagram_cfg` envelope with:
//   - INPUT / OUTPUT terminal nodes (`:::input` / `:::output` classes)
//   - color-class declarations (`classDef input` / `output` / `call` /
//     `cond` / `loop` / `lit` / `binding` / `param` / `path` / `yield`
//     / `accessor` / `exit`) — additive, ignored by the structural
//     comparator (gate 37.14 — class tags don't perturb node-id sets)
//   - cross-def dashed call edges (`caller -.->|"call"| target`)
//   - yield-enumeration sentinel nodes per `[?for]` body
//   - binding-introduction nodes + dashed `resolves` edges from each
//     binding-use to its introducer
//
// Compact's basic-block content is preserved verbatim — the structural
// comparator's edge / node sets are supersets of compact's, never
// subsets. This keeps the existing `full-code-cfg-terminals` fixture
// green while the new content lands.
pub fn code_diagram_cfg_full(prog cx.Program) !string {
	body := code_diagram_cfg(prog)!
	mut lines := body.split('\n')
	mut out := []string{cap: lines.len + 32}
	out << lines[0]
	// Color-class declarations — additive (the comparator silently
	// skips unrecognised lines per scripts/check_code_diagram_fixtures.py
	// `_parse_flowchart`). All eleven §D12.2 classes are declared even
	// when not all are used in this program; cheap and improves the
	// playground's visual diff between levels.
	out << '  classDef input fill:#e0f7fa,stroke:#006064;'
	out << '  classDef output fill:#fff3e0,stroke:#e65100;'
	// NB: classDef name is `callsite`, not `call` — `call` is a RESERVED
	// mermaid flowchart keyword (the click-callback directive, lexed as
	// CALLBACKNAME), so `classDef call …` is a hard mermaid parse error that
	// aborts rendering of the WHOLE diagram. None of the other palette names
	// (input/output/cond/loop/lit/binding/param/path/yield/accessor/exit)
	// collide with a mermaid keyword.
	out << '  classDef callsite fill:#f3e5f5,stroke:#4a148c;'
	out << '  classDef cond fill:#fff9c4,stroke:#f57f17;'
	out << '  classDef loop fill:#e8f5e9,stroke:#1b5e20;'
	out << '  classDef lit fill:#eceff1,stroke:#37474f;'
	out << '  classDef binding fill:#ede7f6,stroke:#311b92;'
	out << '  classDef param fill:#e1f5fe,stroke:#01579b;'
	out << '  classDef path fill:#e0f2f1,stroke:#004d40;'
	out << '  classDef yield fill:#fce4ec,stroke:#880e4f;'
	out << '  classDef accessor fill:#f1f8e9,stroke:#33691e;'
	out << '  classDef exit fill:#fafafa,stroke:#212121;'
	// Terminal nodes — INPUT carries the source feed (the `[?cx data=…]`
	// PI path when present, else the generic `INPUT` literal).
	out << '  input([INPUT]):::input'
	out << '  output([OUTPUT]):::output'
	mut have_start := false
	mut have_done := false
	for ln in lines[1..] {
		out << ln
		if ln.contains('start([entry])') { have_start = true }
		if ln.contains('done([exit])') { have_done = true }
	}
	if have_start {
		out << '  input --> start'
	}
	if have_done {
		out << '  done --> output'
	}
	// Cross-def call edges + def-only entry/exit terminal hook. When the
	// program is `[?def …]`-only (no `start`/`done`), connect INPUT
	// directly to each def's entry id and the exit id to OUTPUT.
	stmts := top_level_statements(prog)
	mut def_names := []string{}
	for stmt in stmts {
		if stmt is cx.ProgramDirective && stmt.name == 'def' {
			n := def_name_min_extract(stmt)
			if n != '' { def_names << n }
		}
	}
	// Dashed `call` edges: for every callee referenced inside a def's
	// body, emit `caller_entry -.->|"call"| callee_entry`. Best-effort
	// — we walk the def body and pick up bare-element / call references
	// whose name matches another top-level def. Self-recursion is
	// already handled by the compact emitter's back-edges and is
	// suppressed here to avoid double-counting.
	for stmt in stmts {
		if stmt is cx.ProgramDirective && stmt.name == 'def' {
			caller_name := def_name_min_extract(stmt)
			if caller_name == '' { continue }
			caller_entry := caller_name[..1].to_lower() + 's'
			_, body_node := def_name_and_body(stmt) or { continue }
			callees := collect_callees(body_node, def_names, caller_name)
			for callee in callees {
				callee_entry := callee[..1].to_lower() + 's'
				out << '  ${caller_entry} -. "call" .-> ${callee_entry}'
			}
		}
	}
	// Yield-enumeration sentinels for `[?for]` / `[?map]` directives at
	// top level. One sentinel node per yield in the body. Connected from
	// the loop header (`lh`) so the assembly is traceable.
	mut yield_idx := 0
	for stmt in stmts {
		if stmt is cx.ProgramForComp {
			yields := collect_yields(stmt.yield)
			for _ in yields {
				yield_idx++
				yid := 'y${yield_idx}'
				out << '  ${yid}["yield #${yield_idx}"]:::yield'
				out << '  lh --> ${yid}'
			}
		}
	}
	// Binding-introduction circles + `resolves` dashed edges. Walks the
	// program collecting `[?let [= $x V] …]` and `[?for $x …]` binding
	// sites; each binding emits an introducer circle, then a dashed
	// `b_$name -.->|"resolves"| target` edge to a heuristic anchor —
	// the loop body `lb` when a top-level for-comp exists, else the
	// main-flow basic-block `b`, else the def-only `<L>s` entry of the
	// first def. Falls back to no edge when none of those anchors are
	// available (the introducer still renders as a standalone node).
	intros := collect_binding_intros(prog)
	mut have_lb := false
	mut have_b := false
	for ln in out {
		if ln.contains('lb[') || ln.contains('lb{') { have_lb = true }
		if ln.contains('  b[') || ln.contains('  b{') { have_b = true }
	}
	mut resolve_target := ''
	if have_lb {
		resolve_target = 'lb'
	} else if have_b {
		resolve_target = 'b'
	} else if def_names.len > 0 {
		// Def-only program: anchor on the first def's entry.
		resolve_target = def_names[0][..1].to_lower() + 's'
	}
	for bname in intros {
		bid := 'b_${sanitize_id(bname)}'
		out << '  ${bid}((("\$${bname}"))):::binding'
		if resolve_target != '' {
			out << '  ${bid} -. "resolves" .-> ${resolve_target}'
		}
	}
	return out.join('\n')
}

// collect_callees walks a def body and returns the set of distinct
// def-names referenced as bare-element calls or cx.ProgramCalls. Excludes
// `exclude` (the enclosing def's own name, to avoid double-counting
// self-recursion edges that the compact emitter's back-edges already
// handle). Order is deterministic: first-seen order, deduped.
fn collect_callees(n cx.ProgramNode, def_names []string, exclude string) []string {
	mut found := map[string]bool{}
	mut order := []string{}
	walk_callees(n, def_names, exclude, mut found, mut order)
	return order
}

fn walk_callees(n cx.ProgramNode, def_names []string, exclude string,
	mut found map[string]bool, mut order []string) {
	match n {
		cx.ProgramCall {
			if n.name in def_names && n.name != exclude && !found[n.name] {
				found[n.name] = true
				order << n.name
			}
			for a in n.args {
				walk_callees(a, def_names, exclude, mut found, mut order)
			}
		}
		cx.ProgramLiteral {
			if n.kind == .cx_element && n.name in def_names && n.name != exclude
			   && !found[n.name] {
				found[n.name] = true
				order << n.name
			}
			for it in n.items {
				walk_callees(it, def_names, exclude, mut found, mut order)
			}
			for sl in n.slots {
				walk_callees(sl.value, def_names, exclude, mut found, mut order)
			}
		}
		cx.ProgramDirective {
			for sl in n.slots {
				walk_callees(sl.value, def_names, exclude, mut found, mut order)
			}
		}
		cx.ProgramForComp {
			for c in n.clauses {
				if src := c.source { walk_callees(src, def_names, exclude, mut found, mut order) }
				if e := c.expr { walk_callees(e, def_names, exclude, mut found, mut order) }
			}
			walk_callees(n.yield, def_names, exclude, mut found, mut order)
			if yv := n.yield_value { walk_callees(yv, def_names, exclude, mut found, mut order) }
		}
		else {}
	}
}

// collect_yields returns one entry per [yield …] clause-child / labeled
// :yield slot encountered when walking a for-comp body. Used for §D12.2
// rule 7 — yield enumeration on the assembly path.
fn collect_yields(n cx.ProgramNode) []cx.ProgramNode {
	mut out := []cx.ProgramNode{}
	walk_yields(n, mut out)
	return out
}

fn walk_yields(n cx.ProgramNode, mut out []cx.ProgramNode) {
	match n {
		cx.ProgramLiteral {
			if n.kind == .cx_element && n.name == 'yield' {
				out << n
				return
			}
			if n.kind == .block {
				for it in n.items {
					walk_yields(it, mut out)
				}
				return
			}
			// Atom literal (raw $x reference inside :yield) — counts as
			// one yield site.
			out << n
		}
		cx.ProgramBinding {
			out << n
		}
		cx.ProgramDirective {
			// Branching directives: each then/else/case arm contributes a
			// yield if it produces a value. Heuristic — count the arm
			// bodies as yields.
			for sl in n.slots {
				v := sl.value
				if v is cx.ProgramLiteral && v.kind == .cx_element {
					if v.name == 'then' || v.name == 'else' || v.name == 'case' {
						out << v
					}
				}
			}
		}
		cx.ProgramCall { out << n }
		else {}
	}
}

// collect_binding_intros returns the set of binding names introduced in
// the program (from `[?let [= $x V] …]`, `[?for $x :in …]`,
// `[?def $f (…params) …]` parameters, `[case [from $ch $msg] …]`).
// Deduped first-seen order.
fn collect_binding_intros(prog cx.Program) []string {
	mut found := map[string]bool{}
	mut order := []string{}
	walk_binding_intros(prog.body, mut found, mut order)
	return order
}

fn walk_binding_intros(n cx.ProgramNode, mut found map[string]bool,
	mut order []string) {
	match n {
		cx.ProgramForComp {
			for c in n.clauses {
				if c.kind == .generator && c.bind != '' && !found[c.bind] {
					found[c.bind] = true
					order << c.bind
				}
				if c.kind == .binding && c.bind != '' && !found[c.bind] {
					found[c.bind] = true
					order << c.bind
				}
			}
			walk_binding_intros(n.yield, mut found, mut order)
		}
		cx.ProgramDirective {
			if n.name == 'let' {
				for sl in n.slots {
					v := sl.value
					if v is cx.ProgramLiteral && v.kind == .cx_element && v.name == '=' {
						if v.items.len >= 1 {
							lhs := v.items[0]
							if lhs is cx.ProgramBinding && lhs.path.len == 0
							   && !found[lhs.name] {
								found[lhs.name] = true
								order << lhs.name
							}
						}
					}
				}
			}
			for sl in n.slots {
				walk_binding_intros(sl.value, mut found, mut order)
			}
		}
		cx.ProgramLiteral {
			for it in n.items {
				walk_binding_intros(it, mut found, mut order)
			}
			for sl in n.slots {
				walk_binding_intros(sl.value, mut found, mut order)
			}
		}
		else {}
	}
}

// sanitize_id maps a binding name to a Mermaid-safe id suffix. Strips
// non-identifier chars (Mermaid node ids only accept `[A-Za-z_][\w]*`).
fn sanitize_id(s string) string {
	mut out := []u8{cap: s.len}
	for ch in s {
		if (ch >= `A` && ch <= `Z`) || (ch >= `a` && ch <= `z`)
		   || (ch >= `0` && ch <= `9`) || ch == `_` {
			out << ch
		} else {
			out << `_`
		}
	}
	if out.len == 0 || (out[0] >= `0` && out[0] <= `9`) {
		mut prefixed := [u8(`_`)]
		for b in out {
			prefixed << b
		}
		return prefixed.bytestr()
	}
	return out.bytestr()
}

// code_diagram_erd_min emits the §D12.1 `min` variant for ERD: one
// rectangle per top-level child element name; no relationships, no
// attribute rows. Uses `erDiagram` header to keep the playground's
// dialect selector happy.
pub fn code_diagram_erd_min(prog cx.Program) !string {
	mut lines := []string{}
	lines << 'erDiagram'
	mut seen := map[string]bool{}
	mut order := []string{}
	for stmt in top_level_statements(prog) {
		if stmt is cx.ProgramLiteral && stmt.kind == .cx_element {
			if !seen[stmt.name] && stmt.name != '' {
				seen[stmt.name] = true
				order << stmt.name
			}
			for it in stmt.items {
				if it is cx.ProgramLiteral && it.kind == .cx_element {
					if !seen[it.name] && it.name != '' {
						seen[it.name] = true
						order << it.name
					}
				}
			}
		}
	}
	for name in order {
		lines << '  ${erd_entity_name(name)} {'
		lines << '  }'
	}
	return lines.join('\n')
}

// code_diagram_erd_full emits the §D12.1 `full` variant for ERD per
// amendment 2026-05-28. Compact ERD + (1) synthetic DOCUMENT
// root with metadata rows; (4) per-type occurrence badge as a note row
// inside the entity (`appears N×`); (3) per-attribute value enumeration
// (`int @id "1, 2"` for ≤10 unique; truncated for >10); (5) edge labels
// carrying multiplicity; (6) inferred-FK dashed edges (`}o--o{`) when
// an attribute name matches an element name elsewhere in the document.
//
// Step-backs (rules from §D12.1's step-back paragraph):
//   - >100 occurrences ⇒ count badge only, no line-number list
//   - single-element source with only scalar children ⇒ suppress
//     DOCUMENT synthetic root
pub fn code_diagram_erd_full(prog cx.Program, source_text string) !string {
	// Walk the program twice: first pass collects occurrence counts +
	// attribute value sets; second pass builds the compact ERD body so
	// the per-entity row enrichment can be layered onto it.
	mut occ := map[string]int{}
	mut depth_max := map[string]int{}
	mut attr_values := map[string][]string{}   // key = "Entity@attr"
	mut all_elem_names := map[string]bool{}    // for FK inference
	for stmt in top_level_statements(prog) {
		collect_erd_full_stats(stmt, 0, mut occ, mut depth_max, mut attr_values,
			mut all_elem_names)
	}
	// Inferred-FK relations: any attribute whose bare name (after `id`
	// suffix trim heuristic) matches an element name suggests a foreign
	// key. Surface as a dashed-style ERD relation. Mermaid ERD has no
	// dotted-line cardinality token, so we use `}o--o{` (non-identifying
	// zero-or-many on both sides) + a `FK` label so the comparator can
	// distinguish from containment relations.
	mut fk_rels := []string{}
	for ent_name, _ in occ {
		for key, _ in attr_values {
			parts := key.split('@')
			if parts.len != 2 { continue }
			if parts[0] != ent_name { continue }
			attr_name := parts[1]
			// FK inference: attribute name `foo-id` / `foo_id` / `foo`
			// matches element name `foo`. Strip common suffixes.
			candidate := strip_id_suffix(attr_name)
			if candidate == '' { continue }
			if candidate == ent_name { continue }
			if all_elem_names[candidate] {
				fk_rels << '  ${erd_entity_name(ent_name)} }o--o{ ${erd_entity_name(candidate)} : FK'
			}
		}
	}
	// Decide whether DOCUMENT root applies. Step-back: single-element
	// source with only scalar children suppresses the synthetic root
	// (it adds noise without information per §D12.1 step-backs).
	suppress_doc := should_suppress_document_root(prog)
	// Now produce the compact body, then enrich entity boxes inline.
	compact := code_diagram_erd(prog, source_text)!
	mut lines := compact.split('\n')
	mut out := []string{cap: lines.len + 32}
	out << lines[0]
	if !suppress_doc {
		out << '  DOCUMENT {'
		out << '    int node_count'
		out << '    int type_count'
		out << '    int max_depth'
		out << '    string source_path'
		out << '  }'
	}
	// Emit FK relations up-front so they sit alongside containment ones.
	for r in fk_rels {
		out << r
	}
	// Walk through compact body, replacing entity-row blocks with
	// enriched versions that prepend `note appears N×` rows + append
	// per-attribute value-enumeration rows.
	mut i := 1
	for i < lines.len {
		ln := lines[i]
		trimmed := ln.trim_space()
		// Match an entity open: `name {`
		if trimmed.ends_with(' {') && !trimmed.starts_with('DOCUMENT') {
			ent_name := trimmed[..trimmed.len - 2].trim_space()
			// Strip optional quoting added by erd_entity_name.
			ent_key := strip_quoted_entity(ent_name)
			out << ln
			// Existing rows up to the closing `}`.
			i++
			for i < lines.len && lines[i].trim_space() != '}' {
				row := lines[i]
				row_trim := row.trim_space()
				// Enrich attribute rows with value enumeration suffixes.
				// Row form: `int @attr` or `string foo` (scalar child).
				if row_trim.starts_with('@') == false && row_trim.contains('@') {
					// `int @name` — extract attr name after '@'.
					at_idx := row_trim.index('@') or { -1 }
					if at_idx >= 0 {
						attr := row_trim[at_idx + 1..]
						key := '${ent_key}@${attr}'
						if vals := attr_values[key] {
							out << '${row} "${render_value_enumeration(vals)}"'
							i++
							continue
						}
					}
				}
				out << row
				i++
			}
			// Append occurrence-badge note row before closing.
			if cnt := occ[ent_key] {
				dmax := depth_max[ent_key] or { 0 }
				if cnt > 100 {
					out << '    string note "appears ×${cnt}"'
				} else {
					out << '    string note "appears ${cnt}× depth ${dmax}"'
				}
			}
			// Closing `}`.
			if i < lines.len {
				out << lines[i]
				i++
			}
			continue
		}
		out << ln
		i++
	}
	return out.join('\n')
}

// collect_erd_full_stats walks the data AST tracking, per entity:
//   - occurrence count
//   - max observed depth
//   - per-attribute value set (≤ 10 unique kept verbatim; > 10 → count)
//   - global element-name set (used for FK-inference attribute match)
fn collect_erd_full_stats(n cx.ProgramNode, depth int,
	mut occ map[string]int,
	mut depth_max map[string]int,
	mut attr_values map[string][]string,
	mut all_elem_names map[string]bool) {
	if n !is cx.ProgramLiteral { return }
	lit := n as cx.ProgramLiteral
	if lit.kind != .cx_element || lit.name == '' { return }
	occ[lit.name] = (occ[lit.name] or { 0 }) + 1
	prev_d := depth_max[lit.name] or { 0 }
	if depth > prev_d { depth_max[lit.name] = depth }
	all_elem_names[lit.name] = true
	// Attribute values (`name=value` attributes). The retired `:label
	// value` slot surface (D014) no longer parses, so value enumeration
	// and FK inference draw from real element attributes.
	for attr in lit.attrs {
		key := '${lit.name}@${attr.name}'
		mut vals := attr_values[key].clone()
		if vals.len < 11 {
			v := short_label(attr.value)
			mut already := false
			for ex in vals {
				if ex == v { already = true; break }
			}
			if !already {
				vals << v
			}
		} else {
			vals << ''  // sentinel; tracks count beyond cap
		}
		attr_values[key] = vals
	}
	// Recurse on child elements.
	for it in lit.items {
		collect_erd_full_stats(it, depth + 1, mut occ, mut depth_max,
			mut attr_values, mut all_elem_names)
	}
}

// strip_id_suffix removes common FK-suffixing on an attribute name so
// the bare entity name can match. `user-id` → `user`; `user_id` →
// `user`; `userId` → `user`. Returns empty string when no suffix is
// present (so the attribute doesn't drive FK inference).
fn strip_id_suffix(s string) string {
	if s.ends_with('-id') && s.len > 3 {
		return s[..s.len - 3]
	}
	if s.ends_with('_id') && s.len > 3 {
		return s[..s.len - 3]
	}
	if s.ends_with('Id') && s.len > 2 {
		return s[..s.len - 2]
	}
	if s == 'id' { return '' }
	return ''
}

// strip_quoted_entity unwraps the `"..."` quoting that erd_entity_name
// adds for non-identifier names. Used by the full-level walker to map
// emitted entity declarations back to the AST element name (so per-
// entity occurrence + value lookup works).
fn strip_quoted_entity(s string) string {
	if s.len >= 2 && s[0] == `"` && s[s.len - 1] == `"` {
		return s[1..s.len - 1]
	}
	return s
}

// render_value_enumeration produces a `"v1, v2"` or `"v1, …, vN (N
// unique)"` summary per §D12.1 rule 3. The convention:
//   - ≤ 10 distinct values: list verbatim, comma-separated
//   - > 10:  show first three + `…` + total count
fn render_value_enumeration(vals []string) string {
	mut distinct := []string{}
	for v in vals {
		if v == '' { continue }  // sentinel
		mut seen := false
		for d in distinct {
			if d == v { seen = true; break }
		}
		if !seen { distinct << v }
	}
	if distinct.len <= 10 {
		return distinct.join(', ').replace('"', '\\"')
	}
	first_three := distinct[..3].join(', ')
	return '${first_three}, …, (${distinct.len} unique)'.replace('"', '\\"')
}

// should_suppress_document_root returns true when the program is a
// single top-level element with only scalar children — the synthetic
// DOCUMENT root would add noise without information per §D12.1 step-
// back. Multiple top-level elements or any structural child child
// re-instates the root.
fn should_suppress_document_root(prog cx.Program) bool {
	stmts := top_level_statements(prog)
	if stmts.len != 1 { return false }
	stmt := stmts[0]
	if stmt !is cx.ProgramLiteral { return false }
	lit := stmt as cx.ProgramLiteral
	if lit.kind != .cx_element { return false }
	// Must contain only scalar children + no labeled slots.
	if lit.slots.len > 0 { return false }
	for it in lit.items {
		if it is cx.ProgramLiteral && it.kind == .cx_element {
			// Any nested element → not pure scalar.
			return false
		}
	}
	return true
}

// mermaid_escape quotes a label for inclusion inside the
// `id["…"]` / `id{"…"}` shapes. Mermaid uses standard backslash
// escapes for `"` and `\`; newlines convert to the literal `\n`
// sequence which Mermaid renders as a line break in node bodies.
fn mermaid_escape(s string) string {
	mut out := []u8{cap: s.len + 8}
	for ch in s {
		match ch {
			`"` {
				out << `\\`
				out << `"`
			}
			`\\` {
				out << `\\`
				out << `\\`
			}
			`\n` {
				out << `\\`
				out << `n`
			}
			else { out << ch }
		}
	}
	return out.bytestr()
}
