module main

import code

// #79 — Tier-2 code identity (pre-Phase-1 floor): alpha-equivalence,
// name-independence, comment/format insensitivity, and semantic distinctness
// at the hash level. Dependency-by-hash + mutual-recursion SCC are subsequent
// increments; these cases use leaf defs whose only free refs are builtins.

fn h(def_source string) string {
	return code.cx_code_tier2_hash(def_source) or {
		panic('tier2 hash failed for `${def_source}`: ${err}')
	}
}

// ── alpha-equivalence: bound-variable renaming must collide ──────────────────

fn test_tier2_alpha_equivalent_param() {
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def f (\$y) [+ \$y 1]]'
	assert h(a) == h(b), 'alpha-equivalent param rename must collide'
}

fn test_tier2_name_independence() {
	// The def NAME is an alias, excluded from identity.
	a := '[?def foo (\$x) [+ \$x 1]]'
	b := '[?def bar (\$x) [+ \$x 1]]'
	assert h(a) == h(b), 'def name must not affect Tier-2 identity'
}

fn test_tier2_alpha_and_name_together() {
	a := '[?def foo (\$x) [+ \$x 1]]'
	b := '[?def bar (\$z) [+ \$z 1]]'
	assert h(a) == h(b), 'name + alpha rename must collide'
}

fn test_tier2_nested_fn_alpha() {
	a := '[?def f (\$x) [?fn (\$g) [+ \$g \$x]]]'
	b := '[?def f (\$a) [?fn (\$b) [+ \$b \$a]]]'
	assert h(a) == h(b), 'nested fn + param alpha rename must collide'
}

fn test_tier2_nested_let_alpha() {
	a := '[?def f (\$x) [?let [= \$y 5] [+ \$y \$x]]]'
	b := '[?def f (\$p) [?let [= \$q 5] [+ \$q \$p]]]'
	assert h(a) == h(b), 'nested let + param alpha rename must collide'
}

// ── comment / formatting insensitivity ──────────────────────────────────────

fn test_tier2_comment_insensitive() {
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def f (\$x) [; this comment is identity-irrelevant ;] [+ \$x 1]]'
	assert h(a) == h(b), 'comments must not affect Tier-2 identity'
}

fn test_tier2_whitespace_insensitive() {
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def f   (\$x)\n  [+   \$x   1]]'
	assert h(a) == h(b), 'whitespace/formatting must not affect Tier-2 identity'
}

// ── semantic difference must NOT collide ─────────────────────────────────────

fn test_tier2_semantic_difference_distinct() {
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def f (\$x) [+ \$x 2]]'
	assert h(a) != h(b), 'different literal → different Tier-2 identity'
}

fn test_tier2_param_use_difference_distinct() {
	// Same arity, but one ignores the param — different computation.
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def f (\$x) [+ 9 1]]'
	assert h(a) != h(b), 'different body structure → different Tier-2 identity'
}

fn test_tier2_operator_difference_distinct() {
	a := '[?def f (\$x) [+ \$x 1]]'
	b := '[?def f (\$x) [* \$x 1]]'
	assert h(a) != h(b), 'different operator → different Tier-2 identity'
}

// ── well-formedness: every hash is a 64-hex sha256 ───────────────────────────

fn test_tier2_hash_shape() {
	assert h('[?def f (\$x) [+ \$x 1]]').len == 64
}
