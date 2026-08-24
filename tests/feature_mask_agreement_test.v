// Feature-mask agreement gate (#802, the #805 gate-truth batch).
//
// `cx_features` is the C-ABI truth surface bindings parse on load
// (spec/abi.md §3). This gate pins mask/surface AGREEMENT in both
// directions for every bit the #802 audit touched (23, 29, 34-40)
// plus bit 41 and the evaluator sanity bit 28: a bit may be SET only
// while its probe is green, and a green surface must be ADVERTISED —
// so the mask can never silently rot again (the drift class #802
// filed: bits shipped for months while the mask read CLEAR).
//
// Probe style: in-process, against the same module surface the C ABI
// wraps. Each test asserts BOTH the bit and its witness; either
// rotting alone fails the gate. Bit 39 (debugging) is the honest
// NEGATIVE: the surface does not ship, so the gate pins the bit
// CLEAR — whoever ships misc/debug.md must flip that row with the
// implementation in the same landing.

import cx
import code
import strconv

fn features_mask() u64 {
	s := cx.cx_features_mask_pub()
	hex := if s.starts_with('0x') { s[2..] } else { s }
	return strconv.parse_uint(hex, 16, 64) or {
		panic('cx_features mask is not parseable hex: ${s} (${err})')
	}
}

fn bit_set(b int) bool {
	return (features_mask() >> u64(b)) & 1 == 1
}

fn fm_int_node(v i64) cx.Node {
	return cx.Node(cx.ScalarNode{ data_type: .int_type, value: cx.ScalarValue(v) })
}

// ── bit 23: Arrow C-Data — build-composed symmetry ────────────────────

fn test_mask_bit23_arrow_build_symmetry() {
	// The base library never claims Arrow (libcx_arrow carries its own
	// cx_arrow_features); a build with the arrow files lane compiled
	// in composes the bit. Symmetric by construction — this row pins
	// the symmetry against a future static-const regression.
	$if cx_arrow_files ? {
		assert bit_set(23), 'arrow files lane compiled in but bit 23 clear'
	} $else {
		assert !bit_set(23), 'bit 23 claimed without the arrow lane compiled in'
	}
}

// ── bit 28: CX code evaluator ─────────────────────────────────────────

fn test_mask_bit28_evaluator() {
	assert bit_set(28), 'bit 28 (code evaluator) must be advertised'
	out := code.eval_code('[empty]', '[* 6 7]', 'text') or {
		panic('bit 28 probe: eval failed: ${err}')
	}
	assert out.trim_space() == '42', 'bit 28 probe: got ${out}'
}

// ── bit 29: collection literals (ast_bin v6 round-trip) ───────────────

fn test_mask_bit29_collection_literals() {
	assert bit_set(29), 'bit 29 (collection literals) must be advertised'
	src := '[t [arr [1, 2]] [m {k: 1}] [s (7, 8)]]'
	doc := cx.parse(src) or { panic('bit 29 probe: parse: ${err}') }
	bin := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bin) or { panic('bit 29 probe: decode: ${err}') }
	assert cx.emit_cx(doc2) == cx.emit_cx(doc), 'bit 29 probe: v6 wire not identity'
}

// ── bit 33: atom scalar kind (ast_bin v7) ─────────────────────────────

fn test_mask_bit33_atom_kind() {
	assert bit_set(33), 'bit 33 (atom kind) must be advertised'
	doc := cx.parse('[a :ok]') or { panic('bit 33 probe: parse: ${err}') }
	bin := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bin) or { panic('bit 33 probe: decode: ${err}') }
	assert cx.emit_cx(doc2) == cx.emit_cx(doc), 'bit 33 probe: v7 wire not identity'
}

// ── bit 34: [?def] module-level functions ─────────────────────────────

fn test_mask_bit34_def() {
	assert bit_set(34), 'bit 34 ([?def]) must be advertised'
	out := code.eval_code('[empty]', '[?def dbl pure ($x) [* $x 2]]\n[dbl 21]', 'text') or {
		panic('bit 34 probe: eval failed: ${err}')
	}
	assert out.trim_space() == '42', 'bit 34 probe: got ${out}'
}

// ── bit 35: [?lib] module loading (cx-stdlib lane) ────────────────────

fn test_mask_bit35_lib() {
	assert bit_set(35), 'bit 35 ([?lib]) must be advertised'
	out := code.eval_code('[empty]', "[?lib 'cx-stdlib/cx']\n[\$cx:canonical \"[a 1]\"]", 'text') or {
		panic('bit 35 probe: eval failed: ${err}')
	}
	assert out.contains('[a 1]'), 'bit 35 probe: got ${out}'
}

// ── bit 36: ast_bin v8 — PathNode/MatchNode/ModifyNode jointly ────────

fn test_mask_bit36_v8_wire() {
	assert bit_set(36), 'bit 36 (ast_bin v8 three-kinds) must be advertised'
	// PathNode (0x13) exercises the v8 envelope + dispatch; the three
	// kinds are gated JOINTLY (the s17 W6 graft completed the promise).
	pn := cx.new_path_node(cx.PathForm.descendant, [
		cx.new_path_step(cx.PathAxis.child, 'user'),
	])
	doc := cx.Document{ elements: [cx.Node(pn)] }
	bin := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bin) or { panic('bit 36 probe: decode: ${err}') }
	assert doc2.elements.len == 1
	n := doc2.elements[0]
	if n is cx.PathNode {
		assert n.form == cx.PathForm.descendant
		assert n.steps.len == 1 && n.steps[0].node_test == 'user'
	} else {
		assert false, 'bit 36 probe: decoded kind is not PathNode'
	}
}

// ── bit 37: iterator wire (IteratorNode 0x16) ─────────────────────────

fn test_mask_bit37_iterator_wire() {
	assert bit_set(37), 'bit 37 (iterator wire) must be advertised'
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range, [
		fm_int_node(1),
		fm_int_node(5),
		fm_int_node(1),
	])
	doc := cx.Document{ elements: [iter] }
	bin := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bin) or { panic('bit 37 probe: decode: ${err}') }
	assert doc2.elements.len == 1
	n := doc2.elements[0]
	if n is cx.IteratorNode {
		assert n.source_kind == cx.IteratorSourceKind.iter_range
		assert n.source_args.len == 3
	} else {
		assert false, 'bit 37 probe: decoded kind is not IteratorNode'
	}
}

// ── bit 38: capability security ([?with-caps] + CXER0271) ────────────

fn test_mask_bit38_capability_security() {
	assert bit_set(38), 'bit 38 (capability security) must be advertised'
	// Deny-by-default: the direct eval API grants NOTHING, so the
	// entropy generator must refuse CXER0271 at its effect point
	// (E_CAP_DENIED rides the err-value channel; a thrown error with
	// the same code is equally a pass — both are the denial).
	prog := "[?lib 'cx-stdlib/random']\n[?with-caps [deny random] [\$random:crypto-hex 8]]"
	if out := code.eval_code('[empty]', prog, 'text') {
		assert out.contains('CXER0271'), 'bit 38 probe: denied effect evaluated WITHOUT the denial: ${out}'
	} else {
		assert err.msg().contains('CXER0271'), 'bit 38 probe: expected CXER0271, got ${err.msg()}'
	}
}

// ── bit 39: debugging — the honest NEGATIVE ───────────────────────────

fn test_mask_bit39_debug_stays_clear() {
	// misc/debug.md (breakpoints, stepping, DAP, record-replay) does
	// NOT ship. The mask must not claim it; whoever lands the surface
	// flips this row together with the implementation.
	assert !bit_set(39), 'bit 39 claimed but no debug surface ships'
}

// ── bit 40: ast_bin v9 table record (0x17) ────────────────────────────

fn test_mask_bit40_v9_table_record() {
	assert bit_set(40), 'bit 40 (ast_bin v9 table record) must be advertised'
	src := '[u [table[name age::int]]\n  alice 30\n  bob 25\n]'
	doc := cx.parse(src) or { panic('bit 40 probe: parse: ${err}') }
	bin := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bin) or { panic('bit 40 probe: decode: ${err}') }
	assert cx.emit_cx(doc2) == cx.emit_cx(doc), 'bit 40 probe: v9 wire not identity'
}

// ── bit 41: the I5 engine (EV-PULL + the §3.10.3 lattice) ─────────────

fn test_mask_bit41_i5_engine() {
	assert bit_set(41), 'bit 41 (I5 runtime-representation engine) must be advertised'
	// EV-PULL half: bounded take over an infinite range.
	out := code.eval_code('[empty]', '[$count [?take 3 [$range 1 *]]]', 'text') or {
		panic('bit 41 probe (EV-PULL): eval failed: ${err}')
	}
	assert out.trim_space() == '3', 'bit 41 probe (EV-PULL): got ${out}'
	// Lattice half: a u16 column keeps its width through the 0x60 wire.
	tdoc := cx.parse('[t [table[u::u16]]\n  7\n  65535\n]\n') or {
		panic('bit 41 probe (lattice): parse: ${err}')
	}
	bin := cx.emit_data_bin(tdoc) or { panic('bit 41 probe (lattice): emit: ${err}') }
	tdoc2 := cx.parse_data_bin(bin) or { panic('bit 41 probe (lattice): decode: ${err}') }
	assert cx.emit_cx(tdoc2).contains('u::u16'), 'bit 41 probe (lattice): width erased'
}
