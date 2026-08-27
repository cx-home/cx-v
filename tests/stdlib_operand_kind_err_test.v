module main

import os
import testenv

// stdlib_operand_kind_err_test.v — #955 / R-A8.
//
// MEASURED DEFECT: a kind-mismatched argument to a cx-stdlib module fn came
// back as
//     [err code=user-undefined message='no callable "str-split"']
// — an operand-kind fault wearing a name-resolution error, naming the
// INTERNAL primitive (`str-split`) the caller never wrote (they wrote
// `strings:split`).
//
// R-A8: operand-kind faults answer a uniform `cx-err:CXER0100` err naming
// (a) the argument position, (b) the expected kind, and (c) the function
// name AS WRITTEN; `none` out of a dispatcher means ONLY "this dispatcher
// does not own this name", so a GENUINE name miss keeps the pre-existing
// `user-undefined` / `no callable "…"` behavior untouched.

fn run_cx(label string, src string) os.Result {
	path := os.join_path(os.temp_dir(), 'cx_operand_kind_${label}_${os.getpid()}.cx')
	os.write_file(path, src) or { panic(err) }
	defer {
		os.rm(path) or {}
	}
	return os.execute('${testenv.cx_bin()} ${path}')
}

// ── 1. the defect: an operand-kind fault is CXER0100, named as written ──────

fn test_kind_mismatch_is_cxer0100_named_as_written() {
	r := run_cx('split_kinds', "[?lib 'cx-stdlib/strings']\n[\$strings:split 1 2]\n")
	assert r.output.contains('cx-err:CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('strings:split'), 'err must name the fn AS WRITTEN: ${r.output}'
	assert r.output.contains('argument 1'), 'err must name the argument position: ${r.output}'
	assert r.output.contains('string'), 'err must name the expected kind: ${r.output}'
	// The two halves of the defect, pinned as negatives.
	assert !r.output.contains('str-split'), 'internal primitive name leaked: ${r.output}'
	assert !r.output.contains('user-undefined'), 'kind fault still wearing a name-resolution err: ${r.output}'
}

// The position is the FAULTING slot, not merely the first slot — a later
// argument of a different kind is reported at its own index.
fn test_kind_mismatch_reports_the_faulting_position() {
	r := run_cx('split_limit', "[?lib 'cx-stdlib/strings']\n[\$strings:split-limit 'a,b,c' ',' 'x']\n")
	assert r.output.contains('cx-err:CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('strings:split-limit'), 'err must name the fn AS WRITTEN: ${r.output}'
	assert r.output.contains('argument 3'), 'err must name the FAULTING position: ${r.output}'
	assert r.output.contains('int'), 'err must name the expected kind: ${r.output}'
	assert !r.output.contains('str-split-limit'), 'internal primitive name leaked: ${r.output}'
}

fn test_kind_mismatch_sibling_arms() {
	r := run_cx('siblings', "[?lib 'cx-stdlib/strings']\n[\$strings:trim-end-chars 'abc' 9]\n")
	assert r.output.contains('cx-err:CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('strings:trim-end-chars'), 'err must name the fn AS WRITTEN: ${r.output}'
	assert r.output.contains('argument 2'), 'err must name the argument position: ${r.output}'
	assert !r.output.contains('str-trim-end-chars'), 'internal primitive name leaked: ${r.output}'
}

// ── 2. a GENUINE name miss is UNCHANGED ────────────────────────────────────

fn test_unknown_name_keeps_user_undefined() {
	r := run_cx('nosuchfn', "[?lib 'cx-stdlib/strings']\n[\$strings:nosuchfn 'a']\n")
	assert r.output.contains('user-undefined'), 'name miss must stay user-undefined: ${r.output}'
	assert r.output.contains('no callable "strings:nosuchfn"'), 'name miss message changed: ${r.output}'
	assert !r.output.contains('CXER0100'), 'name miss must NOT become an operand-kind fault: ${r.output}'
}

// ── 3. the working call is untouched ───────────────────────────────────────

fn test_well_typed_call_still_works() {
	r := run_cx('ok', "[?lib 'cx-stdlib/strings']\n[\$strings:split 'a,b' ',']\n")
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert r.output.contains('a'), 'split result missing: ${r.output}'
	assert r.output.contains('b'), 'split result missing: ${r.output}'
	assert !r.output.contains('CXER0100'), 'a well-typed call raised an operand-kind fault: ${r.output}'
}

// A recovered probe must NOT surface: `join` reads its separator after a
// lenient item read, and the call succeeds — no stale fault may leak into a
// LATER dispatch.
fn test_recovered_read_leaves_no_stale_fault() {
	src := "[?lib 'cx-stdlib/strings']\n[\$strings:join ('a', 'b') '-']\n[\$strings:upper 'ok']\n"
	r := run_cx('stale', src)
	assert r.exit_code == 0, 'expected exit 0, got ${r.exit_code}: ${r.output}'
	assert !r.output.contains('CXER0100'), 'stale operand fault leaked: ${r.output}'
	assert r.output.contains('OK'), 'follow-on call did not run: ${r.output}'
}

// ── 4. the class, not the site: a sibling MODULE answers the same way ──────

fn test_other_modules_share_the_lane() {
	r := run_cx('path_kind', "[?lib 'cx-stdlib/path']\n[\$path:basename 7]\n")
	assert r.output.contains('cx-err:CXER0100'), 'expected CXER0100, got: ${r.output}'
	assert r.output.contains('path:basename'), 'err must name the fn AS WRITTEN: ${r.output}'
	assert !r.output.contains('path-basename'), 'internal primitive name leaked: ${r.output}'
	assert !r.output.contains('user-undefined'), 'kind fault still wearing a name-resolution err: ${r.output}'
}
