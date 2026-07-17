module main

import os
import testenv

// store_modify_using_test.v — #134-3 + #141 (remaining scope).
//
// Two surfaces, both spec-sanctioned, both pinned here:
//
//   1. COMPOSITION (#134-3): [?modify [get-doc] … [using [?fn]]] + put-doc —
//      the canonical §8.10 engine over a fetched doc.
//   2. THE `[using FN]` ACTION ON `modify-doc` ITSELF (#141): store.md says
//      modify-doc "applies a Layer-1 action", and bindings.md's Layer-1 action
//      table includes `[using FN]` — one of the eleven §8.10 actions. FN
//      receives each selected node; its return value replaces the node — ANY
//      kind (kind-shift allowed per code.md §8.10). CXER0104 when the using
//      value is not callable or FN fails to produce a value. A lambda is never
//      server-pushed: on a remote store the verb degrades to get -> transform
//      -> put client-side (same new content-addressed hash either way).
//
// The mu_* tests were RED before store_stdlib_builtin_env landed (the env-free
// action dispatch rejected `using` as an unsupported action). All tests spawn
// the real cx binary.

fn muse_cx() string {
	return testenv.cx_bin()
}

fn muse_run(prog string) os.Result {
	p := os.join_path(os.temp_dir(), 'cx_muse_${os.getpid()}_${prog.len}.cx')
	os.write_file(p, prog) or { panic('write ${p}: ${err}') }
	defer {
		os.rm(p) or {}
	}
	return os.execute('"${muse_cx()}" --allow-all "${p}"')
}

// per-node lambda transform on a stored doc, via composition: the [?modify]
// engine applies the [?fn] to each //t match, then put-doc stores the result.
fn test_store_lambda_transform_via_compose() {
	prog := "[?lib 'cx-stdlib/store' :as store] [?let [= \$s [\$store:open \"mem://\"]] " +
		"[?let [= \$h [\$store:put-doc \$s [targets [t mmsi=\"111\" sog=\"0\"] [t mmsi=\"222\" sog=\"0\"]]]] " +
		"[?let [= \$h2 [\$store:put-doc \$s [?modify [\$store:get-doc \$s \$h] //t [using [?fn (\$n) [t kept=\"1\"]]]]]] " +
		"[\$store:get-doc \$s \$h2]]]]"
	r := muse_run(prog)
	assert r.exit_code == 0, 'compose transform failed: ${r.output}'
	assert r.output.contains("[t kept='1']"), 'lambda transform not applied per node: ${r.output}'
	assert !r.output.contains("mmsi='111'"), 'original child survived the transform: ${r.output}'
}

// ── #141: the `[using FN]` action on `modify-doc` itself ────────────────────

const mu_seed = "[?lib 'cx-stdlib/store' :as store] [?let [= \$s [\$store:open \"mem://\"]] " +
	"[?let [= \$h [\$store:put-doc \$s [targets [t mmsi=\"1\" sog=\"3\"] [t mmsi=\"2\" sog=\"7\"]]]] "

// keyed computed replace: FN receives the MATCHED NODE; only the keyed element
// is replaced, and the replacement embeds the received node (proves the node
// actually reaches the lambda).
fn test_using_by_predicate_key_receives_node() {
	prog := mu_seed +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [wrapped \$n]] select=\"//t[= \$_@mmsi '1']\"]]] " +
		'[\$cx:emit [\$store:get-doc \$s \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'using-by-key failed: ${r.output}'
	assert r.output.contains('wrapped'), 'replacement missing: ${r.output}'
	assert r.output.contains("mmsi='1'"), 'matched node not passed to FN: ${r.output}'
	assert r.output.contains("mmsi='2'"), 'non-matching sibling lost: ${r.output}'
	assert !r.output.contains("[wrapped [t mmsi='2'"), 'FN applied to non-matching sibling: ${r.output}'
}

// kind-shift (code.md §8.10): FN may return a string; it replaces the element
// verbatim. CXER0104 is NOT raised on legitimate kind-shift.
fn test_using_kind_shift_string_return() {
	prog := mu_seed +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) \"gone\"] select=\"//t[= \$_@mmsi '1']\"]]] " +
		'[\$cx:emit [\$store:get-doc \$s \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'kind-shift failed: ${r.output}'
	assert r.output.contains('gone'), 'string replacement missing: ${r.output}'
	assert !r.output.contains("mmsi='1'"), 'matched element not replaced: ${r.output}'
	assert r.output.contains("mmsi='2'"), 'non-matching sibling lost: ${r.output}'
}

// bare descendant select: FN applies to EVERY matched node.
fn test_using_all_matches() {
	prog := mu_seed +
		'[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [x]] select="//t"]]] ' +
		'[\$cx:emit [\$store:get-doc \$s \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'all-matches failed: ${r.output}'
	assert r.output.count('[x]') == 2, 'expected both t elements replaced: ${r.output}'
	assert !r.output.contains('mmsi'), 'a t element survived: ${r.output}'
}

// direct-child axis (/t[@k='v']) works the same as it does for the other actions.
fn test_using_direct_child_axis() {
	prog := mu_seed +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [x]] select=\"/t[= \$_@mmsi '2']\"]]] " +
		'[\$cx:emit [\$store:get-doc \$s \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'direct-child failed: ${r.output}'
	assert r.output.contains('[x]'), 'keyed child not replaced: ${r.output}'
	assert r.output.contains("mmsi='1'"), 'non-matching sibling lost: ${r.output}'
	assert !r.output.contains("mmsi='2'"), 'matched child not replaced: ${r.output}'
}

// zero-match focus → document unchanged (not an error): content-addressing
// returns the SAME hash.
fn test_using_no_match_is_identity() {
	prog := mu_seed +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [x]] select=\"//t[= \$_@mmsi '9']\"]]] " +
		'[\$cx:emit [= \$h \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'no-match failed: ${r.output}'
	assert r.output.contains('true'), 'no-match must return the identical doc hash: ${r.output}'
}

// no select → the action applies to the document root; FN's return becomes the
// whole new doc.
fn test_using_root_replace() {
	prog := mu_seed +
		'[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [newroot ok="1"]]]]] ' +
		'[\$cx:emit [\$store:get-doc \$s \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'root-replace failed: ${r.output}'
	assert r.output.contains("[newroot ok='1']"), 'root not replaced: ${r.output}'
}

// nested same-name matches: the OUTERMOST match wins — FN's result is a new
// computed value, so the walker does not descend into it looking for further
// matches (unlike set-attr, whose result preserves the original structure).
fn test_using_nested_outermost_wins() {
	prog := "[?lib 'cx-stdlib/store' :as store] [?let [= \$s [\$store:open \"mem://\"]] " +
		'[?let [= \$h [\$store:put-doc \$s [targets [t k="1" [t k="1"]]]]] ' +
		"[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [x]] select=\"//t[= \$_@k '1']\"]]] " +
		'[\$cx:emit [\$store:get-doc \$s \$h2]]]]]'
	r := muse_run(prog)
	assert r.exit_code == 0, 'nested failed: ${r.output}'
	assert r.output.count('[x]') == 1, 'inner match must be consumed by the outer replacement: ${r.output}'
}

// a non-callable using value is CXER0104 (per code.md §8.10, same as the
// [?modify] legacy arm) — never a silent no-op.
fn test_using_non_lambda_is_cxer0104() {
	prog := mu_seed +
		'[?let [= \$h2 [\$store:modify-doc \$s \$h [using [notafn] select="//t"]]] ' +
		'[\$cx:emit \$h2]]]]'
	r := muse_run(prog)
	assert r.output.contains('CXER0104'), 'non-lambda using must raise CXER0104: ${r.output}'
}

// FN that fails to produce a value is CXER0104 E_USING_FAILED — the store is
// unchanged (no partial write).
fn test_using_failing_lambda_is_cxer0104() {
	prog := mu_seed +
		'[?let [= \$h2 [\$store:modify-doc \$s \$h [using [?fn (\$n) [\$no-such-callable-xyz \$n]] select="//t"]]] ' +
		'[\$cx:emit \$h2]]]]'
	r := muse_run(prog)
	assert r.output.contains('CXER0104'), 'failing FN must raise CXER0104: ${r.output}'
}
