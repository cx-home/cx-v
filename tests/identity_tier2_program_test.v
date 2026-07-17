module main

import code

// #79 increment 2 — dependency-by-hash (Merkle-DAG) + mutual-recursion SCC.
// cx_program_tier2_hashes resolves sibling references to their Tier-2 hashes,
// so a caller's identity depends transitively on its callees' bodies (not
// their names), and mutual-recursion cycles hash as one component.

fn prog(src string) map[string]string {
	return code.cx_program_tier2_hashes(src) or {
		panic('program tier2 hashes failed: ${err}')
	}
}

// ── dependency sensitivity ───────────────────────────────────────────────────

fn test_tier2_caller_depends_on_callee_body() {
	// Same caller, callee bodies differ → caller hashes must differ.
	a := '[?def helper (\$x) [+ \$x 1]]
[?def main (\$y) [helper \$y]]'
	b := '[?def helper (\$x) [+ \$x 2]]
[?def main (\$y) [helper \$y]]'
	ha := prog(a)
	hb := prog(b)
	assert ha['main'] != hb['main'], 'caller hash must change when callee body changes'
}

fn test_tier2_caller_stable_when_callee_unchanged() {
	// Renaming the callee (alias) but keeping its body must NOT change the
	// caller's identity — names are aliases, dependency is by hash.
	a := '[?def helper (\$x) [+ \$x 1]]
[?def main (\$y) [helper \$y]]'
	b := '[?def aux (\$x) [+ \$x 1]]
[?def main (\$y) [aux \$y]]'
	ha := prog(a)
	hb := prog(b)
	assert ha['main'] == hb['main'], 'caller identity must be independent of callee NAME (hash-keyed dep)'
}

fn test_tier2_builtin_not_a_dependency() {
	// `+` is a builtin, not a sibling def — calling it is not a dep edge, and a
	// leaf def's program hash equals its standalone hash.
	src := '[?def f (\$x) [+ \$x 1]]'
	ph := prog(src)
	standalone := code.cx_code_tier2_hash('[?def f (\$x) [+ \$x 1]]') or { panic(err) }
	assert ph['f'] == standalone, 'leaf def program hash == standalone hash'
}

// ── mutual recursion: hashed as one component ────────────────────────────────

fn test_tier2_mutual_recursion_name_independent() {
	// even-p/odd-p mutually recurse; renaming the pair (and their bound vars)
	// must collide — the SCC is hashed positionally, name-free.
	a := '[?def even-p (\$n) [?match \$n [zero] true \$_ [odd-p [dec \$n]]]]
[?def odd-p (\$n) [?match \$n [zero] false \$_ [even-p [dec \$n]]]]'
	b := '[?def ev (\$m) [?match \$m [zero] true \$_ [od [dec \$m]]]]
[?def od (\$m) [?match \$m [zero] false \$_ [ev [dec \$m]]]]'
	ha := prog(a)
	hb := prog(b)
	assert ha['even-p'] == hb['ev'], 'mutual-recursion member must be name-independent'
	assert ha['odd-p'] == hb['od'], 'mutual-recursion member must be name-independent'
}

fn test_tier2_mutual_recursion_behavior_sensitive() {
	// Changing the cycle's behavior (swap true/false) must change the hashes.
	a := '[?def even-p (\$n) [?match \$n [zero] true \$_ [odd-p [dec \$n]]]]
[?def odd-p (\$n) [?match \$n [zero] false \$_ [even-p [dec \$n]]]]'
	b := '[?def even-p (\$n) [?match \$n [zero] false \$_ [odd-p [dec \$n]]]]
[?def odd-p (\$n) [?match \$n [zero] true \$_ [even-p [dec \$n]]]]'
	ha := prog(a)
	hb := prog(b)
	assert ha['even-p'] != hb['even-p'], 'changing cycle behavior must change the component hash'
}

fn test_tier2_mutual_recursion_members_distinct() {
	// The two members of the cycle are different computations → distinct hashes.
	src := '[?def even-p (\$n) [?match \$n [zero] true \$_ [odd-p [dec \$n]]]]
[?def odd-p (\$n) [?match \$n [zero] false \$_ [even-p [dec \$n]]]]'
	h := prog(src)
	assert h['even-p'] != h['odd-p'], 'distinct cycle members must hash distinctly'
}

fn test_tier2_self_recursion_is_cyclic() {
	// A directly self-recursive def is a singleton cycle; it still produces a
	// well-formed hash (its self-reference becomes positional, not its name).
	a := '[?def fact (\$n) [?match \$n [zero] 1 \$_ [* \$n [fact [dec \$n]]]]]'
	b := '[?def f2 (\$m) [?match \$m [zero] 1 \$_ [* \$m [f2 [dec \$m]]]]]'
	ha := prog(a)
	hb := prog(b)
	assert ha['fact'].len == 64
	assert ha['fact'] == hb['f2'], 'self-recursive def must be name-independent'
}

// ── well-formedness ──────────────────────────────────────────────────────────

fn test_tier2_program_all_hashes_well_formed() {
	src := '[?def helper (\$x) [+ \$x 1]]
[?def main (\$y) [helper \$y]]'
	h := prog(src)
	assert h.len == 2
	assert h['helper'].len == 64
	assert h['main'].len == 64
}
