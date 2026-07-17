module main

import os
import testenv

// #418 — `cx demo` demonstrates the CURRENT surface (double-colon types,
// [table[…]] block form), every section's output matches its narration,
// no internal step fails silently, and the retired `cx eval … --data=`
// advertisement is gone.

fn test_demo_exits_zero_with_no_errors() {
	r := os.execute('${testenv.cx_bin()} demo 2>&1')
	assert r.exit_code == 0, 'cx demo must exit 0, got ${r.exit_code}: ${r.output}'
	assert !r.output.to_lower().contains('error'), 'cx demo output contains an error: ${r.output}'
}

fn test_demo_shows_current_surface() {
	r := os.execute('${testenv.cx_bin()} demo 2>&1')
	out := r.output
	// Section 1: double-colon typed scalars, JSON round-trip with exact int64.
	assert out.contains('[port::u16 8080]'), 'typed-scalar section not on the :: surface'
	assert out.contains('"user_id": 9007199254740993'), 'int64 precision demo missing/wrong'
	// Section 2: the [table[…]] block form and a real CSV projection.
	assert out.contains('[table[name age::int city]]'), 'table section not on the [table[…]] surface'
	assert out.contains('name,age,city'), 'CSV header row missing — table conversion broke'
	assert out.contains('carol,40,lisbon'), 'CSV data rows missing — table conversion broke'
	// Section 3: the program actually EVALUATES (not just parses).
	assert out.contains("[greeting 'Hello, erik!']"), 'program section did not evaluate'
	// Retired single-colon annotations and the retired eval --data advert.
	assert !out.contains(' :u16 '), 'retired single-colon type annotation resurfaced'
	assert !out.contains('--data'), 'retired `cx eval … --data=` advertisement resurfaced (#415)'
}

// Determinism: the demo output is byte-for-byte the committed fixture
// (fixtures/expected_demo_output.txt — the smoke-eval gate diffs it too).
fn test_demo_matches_committed_fixture() {
	fixture := os.join_path(@VMODROOT, '..', 'fixtures', 'expected_demo_output.txt')
	want := os.read_file(fixture) or {
		assert false, 'cannot read ${fixture}: ${err}'
		return
	}
	r := os.execute('${testenv.cx_bin()} demo')
	assert r.exit_code == 0
	assert r.output == want, 'cx demo output drifted from fixtures/expected_demo_output.txt — regenerate it if the change is intentional'
}
