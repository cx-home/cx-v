module main
import cx

import code

// v08_meta_test — D5 (code.md §4.2): `[?meta {…} FORM]` inert value
// annotations + the `[meta-of EXPR]` reflection builtin (Clojure-metadata
// model). The annotation is an inert side-band on the value: rendering is
// transparent, structural equality / EBV / arithmetic read through it, and
// only `meta-of` observes the map. Stacked wraps merge last(outer)-wins.

fn ev(src string) string {
	code.caps_set_all()
	prog := cx.parse_program(src) or { return 'PARSE-ERR: ${err}' }
	mut env := code.new_env()
	res := code.eval(prog.body, mut env) or { return 'EVAL-ERR: ${err}' }
	return code.render_canonical(res).trim_space()
}

// ── inert: [?meta {…} V] returns V unchanged ───────────────────────────────

fn test_meta_is_inert() {
	assert ev('[?meta {author: "ep"} 42]') == '42'
	assert ev('[?meta {pii: true} [user name=ann]]') == '[user name=ann]'
}

// ── meta-of reflects the map; empty map when absent ────────────────────────

fn test_meta_of_reads_map() {
	got := ev('[?let [= $x [?meta {author: "ep", status: :draft} 42]] [meta-of $x]]')
	assert got == "{author: 'ep', status: :draft}", got
}

fn test_meta_of_absent_is_empty_map() {
	assert ev('[meta-of 7]') == '{}'
	assert ev('[meta-of [user name=ann]]') == '{}'
}

// ── ignored by evaluation: arithmetic / comparison read through ────────────

fn test_meta_transparent_to_arithmetic() {
	assert ev('[+ [?meta {a: 1} 5] 1]') == '6'
}

fn test_meta_ignored_by_equality() {
	// Two values differing ONLY in metadata are `=`.
	assert ev('[= [?meta {a: 1} 5] 5]') == 'true'
	assert ev('[= [?meta {a: 1} 5] [?meta {b: 2} 5]]') == 'true'
}

// ── stacked wraps merge into one flat map, last(outer)-wins ────────────────

fn test_meta_merge_last_wins() {
	got := ev('[?let [= $x [?meta {a: 1} [?meta {a: 2, b: 3} 9]]] [meta-of $x]]')
	assert got == '{a: 1, b: 3}', got
}

// ── annotation must be a map ───────────────────────────────────────────────

fn test_meta_requires_map() {
	r := ev('[?meta 5 9]')
	assert r.contains('CXER0100'), r
}

// ── meta rides through a binding (the value is reflectable later) ──────────

fn test_meta_rides_through_binding() {
	got := ev('[?let [= $p [?meta {unit: :years} 30]] [meta-of $p]]')
	assert got == '{unit: :years}', got
}

// ── D5: `<cx:meta>` XML serialization (emit) ───────────────────────────────

fn xml(src string) string {
	code.caps_set_all()
	return (code.eval_code('', src, 'xml') or { 'ERR: ${err}' }).trim_space()
}

fn test_meta_xml_emit_element_inner() {
	got := xml('[?meta {pii: true} [user name=ann]]')
	assert got.contains('<cx:meta>'), got
	assert got.contains('<cx:map>'), got
	assert got.contains('<cx:entry cx:key="pii">true</cx:entry>'), got
	assert got.contains('<user name="ann"/>'), got
}

fn test_meta_xml_emit_scalar_inner() {
	got := xml('[?meta {unit: :years} 331]')
	// `<cx:meta>` wraps the map + the scalar. Per @CHOICE-1 (slice A) a discrete
	// typed (non-string) scalar in a multi-item body serializes to its `<cx:TYPE>`
	// carrier — `<cx:int>331</cx:int>` — so the int type round-trips losslessly
	// (the old bare `331` re-parsed as text).
	assert got == '<cx:meta><cx:map><cx:entry cx:key="unit">years</cx:entry></cx:map><cx:int>331</cx:int></cx:meta>', got
}

fn test_no_meta_no_wrapper() {
	got := xml('[user name=ann]')
	assert got == '<user name="ann"/>', got
}
