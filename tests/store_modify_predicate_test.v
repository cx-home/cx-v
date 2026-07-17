module main

import os
import testenv

// store_modify_predicate_test.v — #141. `$store:modify-doc` `select` must honor
// CXPath step predicates (canonical prefix form `[= $_@attr 'v']`, #110), not
// just bare element-name steps, so a keyed collection element can be targeted
// for update or eviction. Before the fix, every predicate form was a silent
// no-op (the whole predicate string was used as the element name and never
// matched). These tests spawn the real cx binary and pin the green behavior;
// they were RED prior to the store_elem_matches_predicates fix in
// stdlib_store.v.

fn mp_cx() string {
	return testenv.cx_bin()
}

fn mp_run(prog string) os.Result {
	p := os.join_path(os.temp_dir(), 'cx_mp_${os.getpid()}_${prog.len}.cx')
	os.write_file(p, prog) or { panic('write ${p}: ${err}') }
	defer {
		os.rm(p) or {}
	}
	return os.execute('"${mp_cx()}" --allow-all "${p}"')
}

const seed_two = "[?lib 'cx-stdlib/store' :as store] [?let [= \$s [\$store:open \"mem://\"]] " +
	"[?let [= \$h [\$store:put-doc \$s [targets [t mmsi=\"1\" sog=\"0\"] [t mmsi=\"2\" sog=\"0\"]]]] "

// remove by key: only the matched element is deleted.
fn test_remove_by_predicate_key() {
	prog := seed_two +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [remove select=\"//t[= \$_@mmsi '1']\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.exit_code == 0, 'remove-by-key failed: ${r.output}'
	assert !r.output.contains("mmsi='1'"), 'keyed target NOT removed: ${r.output}'
	assert r.output.contains("mmsi='2'"), 'non-matching sibling wrongly removed: ${r.output}'
}

// set-attr by key: only the matched element's attribute changes.
fn test_set_attr_by_predicate_key() {
	prog := seed_two +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [set-attr select=\"//t[= \$_@mmsi '1']\" name=sog value=\"9\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.exit_code == 0, 'set-attr-by-key failed: ${r.output}'
	assert r.output.contains("mmsi='1' sog='9'"), 'keyed target NOT updated: ${r.output}'
	assert r.output.contains("mmsi='2' sog='0'"), 'non-matching sibling wrongly updated: ${r.output}'
}

// attribute-existence predicate matches every element carrying the attr.
fn test_remove_by_attr_existence() {
	prog := seed_two +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [remove select=\"//t[@mmsi]\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.exit_code == 0, 'remove-by-existence failed: ${r.output}'
	assert !r.output.contains('[t '), 'all keyed targets should be removed: ${r.output}'
}

// a predicate that matches NOTHING leaves the document unchanged (fail-closed,
// NOT a silent match-all that would wipe the collection).
fn test_predicate_no_match_is_identity() {
	prog := seed_two +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [remove select=\"//t[= \$_@mmsi '999']\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.exit_code == 0, 'no-match modify failed: ${r.output}'
	assert r.output.contains("mmsi='1'") && r.output.contains("mmsi='2'"), 'no-match must leave doc intact: ${r.output}'
}

// #134 Gap-1 regression: a nested select targets the matched CHILD, never the
// document root. (Before #134, set-attr ignored select and edited the root.)
fn test_nested_select_targets_child_not_root() {
	prog := "[?lib 'cx-stdlib/store' :as store] [?let [= \$s [\$store:open \"mem://\"]] " +
		"[?let [= \$h [\$store:put-doc \$s [targets [t mmsi=\"111\" sog=\"0\"]]]] " +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [set-attr select=\"//t\" name=sog value=\"9\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.exit_code == 0, 'nested set-attr failed: ${r.output}'
	assert r.output.contains("[t mmsi='111' sog='9']"), 'child target not updated: ${r.output}'
	assert !r.output.contains("[targets sog="), 'root wrongly edited (select ignored): ${r.output}'
}

// the RETIRED infix select spelling (#110) is rejected fail-closed — a hard
// CXER0100 error, never a silent no-op or a match-all wipe.
fn test_retired_infix_select_is_rejected() {
	prog := seed_two +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [remove select=\"//t[@mmsi='1']\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.output.contains('CXER0100'), 'retired infix select must hard-error: ${r.output}'
	assert r.output.contains('unsupported select predicate'), 'expected fail-closed predicate rejection: ${r.output}'
}

// bare-name select (no predicate) still applies to every match — no regression
// from the #134 landing.
fn test_bare_select_unchanged() {
	prog := seed_two +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [remove select=\"//t\"]]] " +
		"[\$cx:emit [\$store:get-doc \$s \$h2]]]]]"
	r := mp_run(prog)
	assert r.exit_code == 0, 'bare-select remove failed: ${r.output}'
	assert !r.output.contains('[t '), 'bare //t should remove all: ${r.output}'
}
