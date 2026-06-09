module main

import cx

// Tests for the Phase 2.4 multi-arm `[?match]` parser.
//
// Covers grammar productions [136]–[140]:
//   - 2+ `:case` arm forms (element pattern, scalar literal, wildcard)
//   - `:case … :where GUARD :yield BODY` guarded arms
//   - `:when PREDICATE :yield BODY` predicate arms
//   - `:else :yield BODY` fallback arm
//   - predicate-only (no scrutinee) Searched-CASE mode
// validation: `:else` MUST be last; predicate-only forbids `:case`
//
// Fixture-aligned coverage targets the `program-match-multi-*` IDs in
// `conformance/code.txt` (the parser must accept the surface forms used
// there; evaluator semantics are Phase 2.7).
//
// Out of scope (no evaluator here):
//   - First-match-wins runtime semantics — Phase 2.7.
//   - Structural ProgramExpr subtree parsing of arm bodies — Phase 2.x.
//   - 2-arg `[?match value pattern :yield expr]` legacy form — separate path.

// ── Basic two-arm parse ───────────────────────────────────────────────────────

fn test_parse_match_two_case_arms_basic() {
	src := '[?match \$s :case 200 :yield :ok :case 404 :yield :not-found]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if s := n.scrutinee {
		assert s == '\$s'
	} else {
		assert false, 'scrutinee should be \$s'
	}
	assert n.arms.len == 2
	assert n.arms[0].kind == cx.ArmKind.case_arm
	assert n.arms[0].pattern == '200'
	assert n.arms[0].body == ':ok'
	assert n.arms[1].kind == cx.ArmKind.case_arm
	assert n.arms[1].pattern == '404'
	assert n.arms[1].body == ':not-found'
}

fn test_parse_match_three_arms_with_else() {
	src := '[?match \$s :case 200 :yield :ok :case 404 :yield :not-found :else :yield :err]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 3
	assert n.arms[2].kind == cx.ArmKind.else_arm
	assert n.arms[2].body == ':err'
	assert n.arms[2].pattern == ''
	assert n.arms[2].guard == none
}

fn test_parse_match_with_where_guard() {
	src := '[?match \$u :case [user \$u] :where (\$u@age >= 18) :yield :adult :case [user \$u] :yield :minor]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[0].kind == cx.ArmKind.case_arm
	assert n.arms[0].pattern == '[user \$u]'
	if g := n.arms[0].guard {
		assert g == '(\$u@age >= 18)'
	} else {
		assert false, 'where guard should be set on first arm'
	}
	assert n.arms[0].body == ':adult'
	// Second arm has no guard.
	assert n.arms[1].guard == none
	assert n.arms[1].body == ':minor'
}

fn test_parse_match_single_arm_plus_else() {
	src := '[?match \$v :case 200 :yield :http-ok :else :yield :other]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[0].kind == cx.ArmKind.case_arm
	assert n.arms[1].kind == cx.ArmKind.else_arm
}

// ── Predicate-only (SQL Searched-CASE) ────────────────────────────────────────

fn test_parse_match_predicate_only_when_arms() {
	src := '[?match :when (\$score >= 90) :yield :A :when (\$score >= 80) :yield :B :else :yield :F]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.scrutinee == none, 'predicate-only mode should have no scrutinee'
	assert n.arms.len == 3
	assert n.arms[0].kind == cx.ArmKind.when_arm
	if g := n.arms[0].guard {
		assert g == '(\$score >= 90)'
	} else {
		assert false, 'when arm guard should be the predicate'
	}
	assert n.arms[0].body == ':A'
}

fn test_parse_match_mixed_case_and_when_arms() {
	// Scrutinee bound; both :case:when arms can interleave.
	src := '[?match \$req :case [http-get \$u] :yield [route \$u] :when (\$req@deadline < now()) :yield :expired :else :yield :unsupported]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 3
	assert n.arms[0].kind == cx.ArmKind.case_arm
	assert n.arms[0].pattern == '[http-get \$u]'
	assert n.arms[0].body == '[route \$u]'
	assert n.arms[1].kind == cx.ArmKind.when_arm
	if g := n.arms[1].guard {
		assert g == '(\$req@deadline < now())'
	} else {
		assert false, 'when arm guard should be set'
	}
	assert n.arms[2].kind == cx.ArmKind.else_arm
}

// ── Wildcard + CXPath patterns ────────────────────────────────────────────────

fn test_parse_match_wildcard_pattern() {
	src := '[?match \$v :case 200 :yield :http-ok :case _ :yield :other]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[1].pattern == '_'
}

fn test_parse_match_cxpath_pattern() {
	// CXPath:case
	src := '[?match \$n :case //prose :yield [p \$n] :else :yield ()]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[0].pattern == '//prose'
	assert n.arms[0].body == '[p \$n]'
	assert n.arms[1].body == '()'
}

// ── Source + loc tracking ─────────────────────────────────────────────────────

fn test_parse_match_sets_source_and_loc() {
	src := '[?match \$s :case 200 :yield :ok :else :yield :err]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	if s := n.source {
		assert s == src
	} else {
		assert false, 'source should be set'
	}
	if l := n.loc {
		assert l.start == 0
		assert l.end == src.len
	} else {
		assert false, 'loc should be set'
	}
}

// ── Round-trip equality (eq excludes source/loc) ──────────────────────────────

fn test_parse_match_round_trip_eq_hand_constructed() {
	parsed := cx.parse_match('[?match \$s :case 200 :yield :ok :case 404 :yield :not-found :else :yield :err]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	hand := cx.MatchNode{
		scrutinee: ?string('\$s')
		arms: [
			cx.new_case_arm('200', ':ok'),
			cx.new_case_arm('404', ':not-found'),
			cx.new_else_arm(':err'),
		]
	}
	assert parsed.eq(hand)
	assert hand.eq(parsed)
}

fn test_parse_match_round_trip_predicate_only() {
	parsed := cx.parse_match('[?match :when (\$x > 100) :yield :big :else :yield :small]') or {
		assert false, 'parse failed: ${err}'
		return
	}
	hand := cx.MatchNode{
		scrutinee: ?string(none)
		arms:      [cx.new_when_arm('(\$x > 100)', ':big'), cx.new_else_arm(':small')]
	}
	assert parsed.eq(hand)
}

// ── Fixture-aligned shapes (conformance/code.txt program-match-multi-*) ──────

// Fixture: program-match-multi-001-element-dispatch
fn test_parse_match_fixture_001_element_dispatch() {
	src := '[?match \$n :case [prose \$p] :yield [p \$p] :case [code \$c] :yield [pre \$c] :else :yield ()]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-001 parse failed: ${err}'
		return
	}
	if s := n.scrutinee {
		assert s == '\$n'
	} else {
		assert false, 'scrutinee should be \$n'
	}
	assert n.arms.len == 3
	assert n.arms[0].pattern == '[prose \$p]'
	assert n.arms[0].body == '[p \$p]'
	assert n.arms[1].pattern == '[code \$c]'
	assert n.arms[1].body == '[pre \$c]'
	assert n.arms[2].kind == cx.ArmKind.else_arm
	assert n.arms[2].body == '()'
}

// Fixture: program-match-multi-002-scalar-literal
fn test_parse_match_fixture_002_scalar_literal() {
	src := '[?match \$s :case 200 :yield :ok :case 404 :yield :not-found :else :yield :err]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-002 parse failed: ${err}'
		return
	}
	assert n.arms.len == 3
	assert n.arms[0].pattern == '200'
	assert n.arms[1].pattern == '404'
	assert n.arms[2].kind == cx.ArmKind.else_arm
}

// Fixture: program-match-multi-004-no-else-returns-empty
fn test_parse_match_fixture_004_no_else() {
	src := '[?match \$s :case 200 :yield :ok :case 404 :yield :not-found]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-004 parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	// No :else arm allowed (yields empty sequence at eval).
	for arm in n.arms {
		assert arm.kind == cx.ArmKind.case_arm
	}
}

// Fixture: program-match-multi-005-when-arm-predicate
fn test_parse_match_fixture_005_when_predicate() {
	src := '[?match \$x :when (\$x > 100) :yield :big :when (\$x > 50) :yield :medium :else :yield :small]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-005 parse failed: ${err}'
		return
	}
	assert n.arms.len == 3
	assert n.arms[0].kind == cx.ArmKind.when_arm
	assert n.arms[1].kind == cx.ArmKind.when_arm
	assert n.arms[2].kind == cx.ArmKind.else_arm
}

// Fixture: program-match-multi-006-where-guard
fn test_parse_match_fixture_006_where_guard() {
	src := '[?match \$u :case [user \$u] :where (\$u@age >= 18) :yield :adult :case [user \$u] :yield :minor]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-006 parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[0].pattern == '[user \$u]'
	if g := n.arms[0].guard {
		assert g == '(\$u@age >= 18)'
	} else {
		assert false, 'where guard missing'
	}
	assert n.arms[0].body == ':adult'
	assert n.arms[1].guard == none
}

// Fixture: program-match-multi-007-wildcard
fn test_parse_match_fixture_007_wildcard() {
	src := '[?match \$v :case 200 :yield :http-ok :case _ :yield :other]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-007 parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[1].pattern == '_'
	assert n.arms[1].body == ':other'
}

// Fixture: program-match-multi-010-predicate-only-searched-case
fn test_parse_match_fixture_010_searched_case() {
	src := '[?match :when (\$score >= 90) :yield :A :when (\$score >= 80) :yield :B :when (\$score >= 70) :yield :C :else :yield :F]'
	n := cx.parse_match(src) or {
		assert false, 'fixture-010 parse failed: ${err}'
		return
	}
	assert n.scrutinee == none, 'predicate-only mode'
	assert n.arms.len == 4
	for i in 0 .. 3 {
		assert n.arms[i].kind == cx.ArmKind.when_arm
	}
	assert n.arms[3].kind == cx.ArmKind.else_arm
}

// ── Error cases (validation + malformed input) ───────────────────

fn test_parse_match_else_not_last_errors() {
	src := '[?match \$s :case 200 :yield :ok :else :yield :err :case 404 :yield :not-found]'
	_ := cx.parse_match(src) or {
		assert err.msg().contains(':else not last'),
			'expected else-not-last error, got: ${err}'
		return
	}
	assert false, ':else followed by :case should error'
}

fn test_parse_match_multiple_else_errors() {
	src := '[?match \$s :case 200 :yield :ok :else :yield :err :else :yield :other]'
	_ := cx.parse_match(src) or {
		assert err.msg().contains('multiple :else'),
			'expected multiple-else error, got: ${err}'
		return
	}
	assert false, 'multiple :else arms should error'
}

fn test_parse_match_empty_arms_errors() {
	src := '[?match \$s]'
	_ := cx.parse_match(src) or {
		// Any error is acceptable.
		return
	}
	assert false, 'empty match with no arms should error'
}

fn test_parse_match_predicate_only_with_case_errors() {
	// predicate-only mode (no scrutinee) forbids :case arms.
	src := '[?match :case 200 :yield :ok :else :yield :err]'
	_ := cx.parse_match(src) or {
		assert err.msg().contains(':case forbidden in predicate-only mode'),
			'expected predicate-only-forbids-case error, got: ${err}'
		return
	}
	assert false, ':case in predicate-only mode should error'
}

fn test_parse_match_missing_yield_errors() {
	src := '[?match \$s :case 200 :ok]'
	_ := cx.parse_match(src) or {
		// Any error is acceptable — likely "missing :yield" or "missing pattern".
		return
	}
	assert false, 'arm without :yield should error'
}

fn test_parse_match_missing_match_prefix_errors() {
	src := '[match \$s :case 200 :yield :ok]'
	_ := cx.parse_match(src) or {
		assert err.msg().contains('missing [?match prefix'),
			'expected missing-prefix error, got: ${err}'
		return
	}
	assert false, 'missing [?match prefix should error'
}

fn test_parse_match_unknown_arm_keyword_errors() {
	// `:foo` is not in {case, when, else}, so the scrutinee reader
	// gobbles it as part of the (unparsed) scrutinee expression — and
	// then the arm loop finds no arms and errors. Any error is fine;
	// we just confirm the input does NOT parse to a valid MatchNode.
	src := '[?match \$s :foo 200 :yield :ok]'
	_ := cx.parse_match(src) or { return }
	assert false, 'unknown arm keyword should error (input has no valid arms)'
}

fn test_parse_match_empty_input_errors() {
	_ := cx.parse_match('') or { return }
	assert false, 'empty input should error'
}

fn test_parse_match_missing_closing_bracket_errors() {
	src := '[?match \$s :case 200 :yield :ok'
	_ := cx.parse_match(src) or { return }
	assert false, 'missing closing ] should error'
}

// ── String-literal shielding in expression slots ─────────────────────────────

fn test_parse_match_string_literal_with_colons_does_not_split() {
	// A `:` inside a quoted string MUST NOT be treated as an arm keyword.
	src := '[?match \$s :case "a :case b :yield c" :yield :ok :else :yield :err]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[0].pattern == '"a :case b :yield c"'
	assert n.arms[0].body == ':ok'
}

fn test_parse_match_nested_brackets_in_body() {
	// Nested `[ ]` in the body must be tracked by depth; the `:yield`
	// terminator must look only at top-level keywords.
	src := '[?match \$s :case [a [b :case c] d] :yield [out :yield x] :else :yield ()]'
	n := cx.parse_match(src) or {
		assert false, 'parse failed: ${err}'
		return
	}
	assert n.arms.len == 2
	assert n.arms[0].pattern == '[a [b :case c] d]'
	assert n.arms[0].body == '[out :yield x]'
	assert n.arms[1].body == '()'
}
