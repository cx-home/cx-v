module code

import cx

// lower_to_cx_node — AST→AST lowering from the program parser's
// `cx.ProgramDirective` to the cx-data parser's `ModifyNode` / `MatchNode`,
// REPLACING the dispatcher bridge's source round-trip
// (`program_node_to_source` → `cx.parse_modify` / `cx.parse_match`).
//
// WHY (parser-consolidation step 2, see
// _gate_evidence/PARSER_ARCHITECTURE_ASSESSMENT.md): the bridge re-parsed
// the program AST's own emitted source through a SECOND parser. That
// double-parse is the drift class SAP D014 exposed (emitter moved to
// clause form; the cx-data parsers stayed colon-only → round-trip broke →
// silent legacy fallback). Lowering directly from the already-parsed
// cx.ProgramDirective removes the text round-trip and the second-parser
// dependency entirely — the surface the emitter speaks no longer matters
// to the bridge.
//
// CORRECTNESS CONTRACT: for every directive, the lowering MUST produce a
// node whose canonical hash equals `cx.parse_*(program_node_to_source(d))`
// today. The parser-parity gate (vcx/tests/parser_parity_test.v) asserts
// exactly this differential over the corpus. The verbatim string fields
// (doc/focus/action value, scrutinee/pattern/guard/body) are the
// identity-participating data; we reproduce them by emitting each
// COMPONENT via `program_node_to_source` — the same substrings the
// cx-data parser extracts from the whole emit.

// lower_program_directive_to_modify_node builds a `cx.ModifyNode` directly
// from a `[?modify]` cx.ProgramDirective. Returns none when the directive
// shape is not the two-positional `[?modify DOC FOCUS Action+]` form the
// bridge handles (caller falls back to legacy), mirroring the previous
// `cx.parse_modify` decline.
fn lower_program_directive_to_modify_node(d cx.ProgramDirective) ?cx.ModifyNode {
	// Collect the (at most two) positional head slots: DOC then FOCUS.
	mut positionals := []cx.ProgramSlot{}
	mut action_slots := []cx.ProgramSlot{}
	for s in d.slots {
		if s.kind == .positional {
			positionals << s
		} else if s.kind == .labeled && cx.is_modify_action_name(s.label) {
			action_slots << s
		}
	}
	if positionals.len < 2 {
		return none
	}
	doc_src := program_node_to_source(positionals[0].value).trim_space()
	focus_src := program_node_to_source(positionals[1].value).trim_space()
	if action_slots.len == 0 {
		return none
	}

	mut actions := []cx.ModifyAction{cap: action_slots.len}
	for s in action_slots {
		kind := cx.modify_action_kind_from_name(s.label) or { return none }
		mut name := ''
		mut value := ''
		match s.label {
			'delete' {
				// No operand (parser stores a placeholder bool).
			}
			'rename', 'delete-attr' {
				// value is a string_lit holding the Name token.
				if s.value is cx.ProgramLiteral {
					name = (s.value as cx.ProgramLiteral).str_val
				} else {
					return none
				}
			}
			'set-attr' {
				// value is a sequence_lit [string_lit NAME, EXPR].
				if s.value is cx.ProgramLiteral {
					lit := s.value as cx.ProgramLiteral
					if lit.kind != .sequence_lit || lit.items.len != 2 {
						return none
					}
					if lit.items[0] is cx.ProgramLiteral {
						name = (lit.items[0] as cx.ProgramLiteral).str_val
					} else {
						return none
					}
					value = program_node_to_source(lit.items[1]).trim_space()
				} else {
					return none
				}
			}
			else {
				// set / using / append / prepend / insert-before /
				// insert-after / replace — single cx.ProgramExpr value.
				value = program_node_to_source(s.value).trim_space()
			}
		}
		mut action := cx.ModifyAction{
			kind:  kind
			name:  name
			value: value
		}
		// Best-effort structural graft (advisory; not hash-participating),
		// matching parse_modify's try_parse_snippet_to_node population.
		if value.len > 0 {
			if vn := cx.try_parse_snippet_to_node(value) {
				action.value_node = vn
			}
		}
		actions << action
	}

	return cx.ModifyNode{
		doc:     doc_src
		focus:   focus_src
		actions: actions
	}
}

// lower_program_directive_to_match_node builds a `cx.MatchNode` directly
// from a multi-arm `[?match]` cx.ProgramDirective. Arms reach this as a flat
// labeled-slot sequence (per parse_match_clause): `case`(+optional
// `where`)+`yield`, `when`+`yield`, `else`+`yield`. Returns none when no
// case/when/else arm is present (single-arm / non-multi form — caller
// falls back to legacy, mirroring the previous bridge decline).
//
// Only the verbatim string fields are populated here (they are the
// hash-/identity-participating data). The typed pattern_node/body_node
// slots are filled afterwards by retype_match_pattern_nodes — exactly as
// the previous cx.parse_match → retype path did.
fn lower_program_directive_to_match_node(d cx.ProgramDirective) ?cx.MatchNode {
	// Scrutinee: first positional slot (absent → predicate-only mode).
	mut scrutinee := ?string(none)
	for s in d.slots {
		if s.kind == .positional {
			scrutinee = program_node_to_source(s.value).trim_space()
			break
		}
	}

	mut arms := []cx.MatchArm{}
	mut have_arm := false
	mut cur := cx.MatchArm{}
	for s in d.slots {
		if s.kind != .labeled {
			continue
		}
		match s.label {
			'case' {
				cur = cx.MatchArm{
					kind:    cx.ArmKind.case_arm
					pattern: program_node_to_source(s.value).trim_space()
				}
				have_arm = true
			}
			'when' {
				// Predicate stored in `guard` per MatchArm contract.
				cur = cx.MatchArm{
					kind:  cx.ArmKind.when_arm
					guard: program_node_to_source(s.value).trim_space()
				}
				have_arm = true
			}
			'else' {
				cur = cx.MatchArm{
					kind: cx.ArmKind.else_arm
				}
				have_arm = true
			}
			'where' {
				// :where guard on the current :case arm.
				if !have_arm {
					return none
				}
				cur.guard = program_node_to_source(s.value).trim_space()
			}
			'yield' {
				// Finalizes the current arm.
				if !have_arm {
					return none
				}
				cur.body = program_node_to_source(s.value).trim_space()
				arms << cur
				cur = cx.MatchArm{}
				have_arm = false
			}
			else {
				return none
			}
		}
	}
	if arms.len == 0 {
		return none
	}
	return cx.MatchNode{
		scrutinee: scrutinee
		arms:      arms
	}
}

// lower_match_source_to_node is the public entry used by the dispatcher
// bridge (replacing cx.parse_match) and the parity gate. Parses `src` via
// the program parser and lowers a multi-arm `[?match]` directive to a
// cx.MatchNode. The caller applies retype_match_pattern_nodes.
pub fn lower_match_source_to_node(src string) ?cx.MatchNode {
	prog := cx.parse_program(src) or { return none }
	if prog.body is cx.ProgramDirective {
		d := prog.body as cx.ProgramDirective
		if d.name == 'match' {
			return lower_program_directive_to_match_node(d)
		}
	}
	return none
}

// lower_modify_source_to_node is the public entry used by the dispatcher
// bridge (replacing `cx.parse_modify(program_node_to_source(d))`) and by
// the parser-parity gate. Parses `src` via the program parser and lowers
// the resulting `[?modify]` directive directly to a `cx.ModifyNode`.
// Returns none for non-`[?modify]` input or shapes the bridge declines.
pub fn lower_modify_source_to_node(src string) ?cx.ModifyNode {
	prog := cx.parse_program(src) or { return none }
	if prog.body is cx.ProgramDirective {
		d := prog.body as cx.ProgramDirective
		if d.name == 'modify' {
			return lower_program_directive_to_modify_node(d)
		}
	}
	return none
}
