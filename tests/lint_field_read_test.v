module main

import os
import testenv

// lint_field_read_test.v — #610: CX-L007 flags $count/$empty/$exists over a
// SIMPLE FIELD ACCESSOR (a pure /name child chain — the code.md §6.2
// field-read shape, whose aggregation reports the field's CONTENT arity,
// ruled by-design in #584) and teaches the sanctioned match-counting idioms.
// Warning severity, detect-only. Node-set forms (//, /*, predicates),
// bare bindings, dot-chains, and non-aggregation reads never fire.

fn l7_bin() string {
	return testenv.cx_bin()
}

fn l7_out(src string) string {
	f := os.join_path(os.temp_dir(), 'cx_l007_${os.getpid()}_${src.len}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	r := os.execute('${l7_bin()} lint ${f}')
	return r.output
}

fn l7_count(out string) int {
	mut n := 0
	for line in out.split('\n') {
		if line.contains('CX-L007') {
			n++
		}
	}
	return n
}

fn test_l007_fires_on_field_read_aggregation() {
	// the #584 shape verbatim: count over a pure child chain.
	out := l7_out('[?let [= \$b [box [life [evidence [id "e1"]]]]] [\$count \$b/life]]')
	assert l7_count(out) == 1, 'count over a field read must warn: ${out}'
	assert out.contains('§6.2') || out.contains('content'), 'finding must teach the composition: ${out}'
	assert out.contains('//life') || out.contains('predicate'), 'finding must name the sanctioned idioms: ${out}'

	// $empty and $exists share the trap; deeper chains fire too.
	out2 := l7_out('[?let [= \$x [a [b [c 1]]]] [\$empty \$x/a/b]]')
	assert l7_count(out2) == 1, 'empty over a deep field chain must warn: ${out2}'
	out3 := l7_out('[?let [= \$r [res [v [thing]]]] [\$exists \$r/v]]')
	assert l7_count(out3) == 1, 'exists over a field read must warn: ${out3}'

	// nested positions (inside a view literal / for-comp) still fire.
	out4 := l7_out('[?let [= \$b [w [k 1]]] [?for [in \$i (1,2)] [yield [item [\$count \$b/k]]]]]')
	assert l7_count(out4) == 1, 'nested aggregation must warn: ${out4}'
}

fn test_l007_silent_on_sanctioned_forms() {
	// the sanctioned match-counting idioms never fire.
	out := l7_out('[?let [= \$b [box [life [e 1]]]] [\$count \$b//life]]')
	assert l7_count(out) == 0, 'descendant counting must not warn: ${out}'
	out2 := l7_out('[?let [= \$b [box [life [e 1]]]] [\$count \$b/*]]')
	assert l7_count(out2) == 0, 'wildcard counting must not warn: ${out2}'
	out3 := l7_out('[?let [= \$b [box [life [e 1]]]] [\$count \$b/life[= \$_@x 1]]]')
	assert l7_count(out3) == 0, 'predicate step must not warn: ${out3}'

	// bare bindings, dot-chains, and non-aggregation reads are fine.
	out4 := l7_out('[?let [= \$s (1, 2, 3)] [\$count \$s]]')
	assert l7_count(out4) == 0, 'bare-binding count must not warn: ${out4}'
	out5 := l7_out('[?let [= \$m {a: {b: 7}}] [\$count \$m.a]]')
	assert l7_count(out5) == 0, 'map dot-chain must not warn: ${out5}'
	out6 := l7_out('[?let [= \$b [box [life 1]]] \$b/life]')
	assert l7_count(out6) == 0, 'a plain field read must not warn: ${out6}'
}

fn test_l007_suppressable() {
	src := '[?let [= \$b [box [life [e 1]]]] [\$count \$b/life]]'
	out := l7_out(src)
	assert l7_count(out) == 1
	f := os.join_path(os.temp_dir(), 'cx_l007_off_${os.getpid()}.cx')
	os.write_file(f, src) or { panic('write: ${err}') }
	defer { os.rm(f) or {} }
	r := os.execute('${l7_bin()} lint --disable CX-L007 ${f}')
	assert l7_count(r.output) == 0, 'disable flag must suppress: ${r.output}'
}
