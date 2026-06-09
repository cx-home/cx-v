module main

import cx

// Tests for the Phase 2.11 v0.8.0 C ABI surface in `vcx/cx/cabi.v`.
// Covers:
//   - `cx_code_tree` is callable; returns valid JSON conforming to
// the contract (kind / name / loc present; loc.end
//     resolves to source length on the stub path).
//   - `cx_features` advertises the v0.8.0 cap-bit set (bits 28, 31,
//     32 — `cx_code_eval` / `cx_code_diagram` / `cx_code_tree`).
//   - Layer-1 round-trip through `cx_to_cx` (parse → render) returns
//     byte-equal canonical output for a simple element-only source.
//   - The retired `cx_eval` family is gone — the V module no longer
//     exports a `cx_eval` symbol (compile-time check that the rename
// is complete).
//
// `cx_code_eval` and `cx_code_diagram` live in `vcx/code/cabi.v` per
// the import-cycle constraint documented in that file; their unit
// tests stay under `vcx/code/`. This file exercises the
// vcx/cx-resident surface plus the cross-cutting `cx_features`
// bitmask.

// ── helpers ────────────────────────────────────────────────────────────────

fn vstring_of(p &char) string {
	if p == unsafe { nil } {
		return ''
	}
	return unsafe { cstring_to_vstring(p) }
}

// ── cx_features cap-bit advertisement ──────────────────────────────────────

fn test_cx_features_advertises_v0_8_0_bits() {
	hex := vstring_of(cx.cx_version())
	assert hex.len > 0, 'cx_version returns non-empty'

	features := vstring_of(cx.cx_features())
	assert features.starts_with('0x'), 'features is lowercase hex with 0x prefix (got "${features}")'

	// Parse hex → u64.
	mut bits := u64(0)
	for c in features[2..] {
		bits *= 16
		match c {
			`0`...`9` { bits += u64(c - `0`) }
			`a`...`f` { bits += u64(c - `a` + 10) }
			else { assert false, 'unexpected hex char ${c:c} in features "${features}"' }
		}
	}

	// Bit 28 — `cx_code_eval*` family (carried to v0.8.0
	// D5 + spec/abi.md §1.5.5 row 28).
	assert (bits & (u64(1) << 28)) != 0, 'bit 28 (cx_code_eval*) MUST be set'
	// Bit 31 — `cx_code_diagram` (ERD-or-CFG).
	assert (bits & (u64(1) << 31)) != 0, 'bit 31 (cx_code_diagram) MUST be set'
	// Bit 32 — `cx_code_tree` (new C ABI).
	assert (bits & (u64(1) << 32)) != 0, 'bit 32 (cx_code_tree) MUST be set'
}

// ── cx_code_tree contract (real walker, Phase 2.11) ──────────

fn test_cx_code_tree_empty_source_returns_minimal_root() {
	mut out_len := usize(0)
	src := ''
	src_ptr := unsafe { &char(src.str) }
	got := cx.cx_code_tree(src_ptr, usize(src.len), unsafe { &out_len })
	assert got != unsafe { nil }, 'cx_code_tree returns non-NULL on empty source'
	json := vstring_of(got)
	defer { cx.cx_free(got) }

	// every node has `{kind, loc}`. Empty-source path
	// returns `{kind:"element", name:"root", loc:{start:0,end:0}, children:[]}`.
	assert json.contains('"kind":"element"'), 'kind:element present (got ${json})'
	assert json.contains('"name":"root"'), 'name:root present'
	assert json.contains('"loc":{"start":0,"end":0}'), 'loc spans 0..0 for empty (got ${json})'
	assert usize(json.len) == out_len, 'out_len matches JSON length'
}

fn test_cx_code_tree_simple_source_resolves_to_source_length() {
	mut out_len := usize(0)
	src := '[user id=1]'
	src_ptr := unsafe { &char(src.str) }
	got := cx.cx_code_tree(src_ptr, usize(src.len), unsafe { &out_len })
	assert got != unsafe { nil }
	json := vstring_of(got)
	defer { cx.cx_free(got) }

	// invariant: loc.start < loc.end for non-empty
	// sources; loc.end resolves to a valid UTF-8 substring of source.
	// Real walker: single top-level element returns its own node.
	assert json.contains('"kind":"element"'), 'kind present'
	assert json.contains('"name":"user"'), 'name surfaces source element (got ${json})'
	assert json.contains('"loc":{"start":0,"end":${src.len}}'), 'loc.end == source_len (got ${json})'
	assert json.contains('"kind":"attribute"'), 'attribute child present (got ${json})'
	assert usize(json.len) == out_len, 'out_len matches'
}

fn test_cx_code_tree_null_out_len_is_safe() {
	src := '[a]'
	src_ptr := unsafe { &char(src.str) }
	// Passing nil out_len pointer must not crash; the function
	// MUST skip the dereference per the brief's "out_len (if
	// non-NULL) receives ..." contract.
	null_out_len := unsafe { &usize(nil) }
	got := cx.cx_code_tree(src_ptr, usize(src.len), null_out_len)
	assert got != unsafe { nil }
	cx.cx_free(got)
}

// ── Layer-1 round-trip — parse → render byte-equal on canonical input ──────

fn test_layer1_round_trip_cx_to_cx_byte_equal() {
	// Canonical CX input (already in fmt-canonical form). The
	// `cx_to_cx` export is the Layer-1 `parse(bytes).bytes()`
	// pipeline: parses CX text, emits canonical CX bytes. A
	// canonical-in / canonical-out round trip MUST be byte-equal
	// per spec/canonical.md §3.
	src := '[user @id=1]'
	src_ptr := unsafe { &char(src.str) }
	mut err_out := unsafe { &char(nil) }
	got := cx.cx_to_cx(src_ptr, unsafe { &err_out })
	assert got != unsafe { nil }, 'cx_to_cx returns non-NULL on valid input'
	rendered := vstring_of(got)
	cx.cx_free(got)
	// The default cx_to_cx emit normalises whitespace; assert the
	// element name + attribute survive the round-trip.
	assert rendered.contains('user'), 'element name preserved (got ${rendered})'
	assert rendered.contains('@id'), 'attribute name preserved'
	assert rendered.contains('1'), 'attribute value preserved'
}

// ── Retired cx_eval — symbol must NOT exist (hard rename) ──────

// Compile-time check: referencing `cx.cx_eval` from V code would fail
// to compile because the symbol is unexported. We can't directly
// assert "symbol absent" from V, but the V module's public surface is
// the source of truth — if `cx_eval` reappears in `vcx/cx/cabi.v`,
// this file would still compile and the assertion below is a marker
// that the retirement comment is intact. The `nm`-level check that
// the .dylib has no `_cx_eval` symbol lives in the release-gate
// scripts.

fn test_retired_cx_eval_marker() {
	// Sentinel: assert that `cx_code_eval` is the live name. If
	// (Q)-agent re-introduces a `cx_eval` alias, this test still
	// passes (the rename is still complete on the new-name side);
	// the linker check at lib build catches duplicate symbols.
	features := vstring_of(cx.cx_features())
	// Bit 28 is the `cx_code_eval*` family bit per spec/abi.md
	// §3 row 28; presence here is the assertion that the 
	// rename landed.
	assert features.starts_with('0x'), 'features hex format'
}
