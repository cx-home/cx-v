module main

import cx

// Tests for the Iterator wire format. Round-trips IteratorNode
// values through `emit_ast_bin` / `bin_to_doc` (which uses the new tag
// 0x16 opcode, cap-bit 37) and asserts the decoded iterator carries
// the same source_kind, single_use, and source_args shape — and that
// `memo` / `exhausted` are reset (decoders never see the runtime
// memoisation state,).

// Helper — wraps an iterator value as the single element of a
// Document so it round-trips through the public ast_bin entry points
// without us needing private encode_node/decode_node access.
fn ast_bin_iter_roundtrip(iter cx.Node) cx.Node {
	doc := cx.Document{ elements: [iter] }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('bin_to_doc: ${err}') }
	if doc2.elements.len != 1 {
		panic('expected 1 element, got ${doc2.elements.len}')
	}
	return doc2.elements[0]
}

// Helper — build a scalar int Node (avoid depending on whatever
// internal helper might exist).
fn int_node(v i64) cx.Node {
	return cx.Node(cx.ScalarNode{
		data_type: cx.ScalarType.int_type
		value:     cx.ScalarValue(v)
	})
}

fn test_iterator_wire_roundtrip_range() {
	// iter_range with [start=1, end=5, step=1].
	src := [int_node(1), int_node(5), int_node(1)]
	iter := cx.new_iterator(cx.IteratorSourceKind.iter_range, src)
	decoded := ast_bin_iter_roundtrip(iter)
	if decoded is cx.IteratorNode {
		assert decoded.source_kind == cx.IteratorSourceKind.iter_range
		assert decoded.source_args.len == 3
		assert decoded.memo.len == 0, 'memo must reset on decode'
		assert decoded.exhausted == false, 'exhausted must reset on decode'
		assert decoded.single_use == false
		// source_args walk: scalar ints should round-trip.
		first := decoded.source_args[0]
		if first is cx.ScalarNode {
			v := first.value
			if v is i64 {
				assert v == 1
			} else { assert false, 'expected i64 scalar' }
		} else { assert false, 'expected ScalarNode' }
	} else {
		assert false, 'expected IteratorNode, got different sum variant'
	}
}

fn test_iterator_wire_roundtrip_map_nested_iter() {
	// iter_map carries [src_iter, closure_sentinel]. We pass a nested
	// iter_range as the src plus a sentinel scalar standing in for the
	// closure (the wire codec is closure-agnostic; nested iterator
	// recursion is what we want to validate).
	inner_args := [int_node(0), int_node(10), int_node(2)]
	inner_iter := cx.new_iterator(cx.IteratorSourceKind.iter_range, inner_args)
	closure_sentinel := int_node(0)
	outer_args := [inner_iter, closure_sentinel]
	outer := cx.new_iterator(cx.IteratorSourceKind.iter_map, outer_args)
	decoded := ast_bin_iter_roundtrip(outer)
	if decoded is cx.IteratorNode {
		assert decoded.source_kind == cx.IteratorSourceKind.iter_map
		assert decoded.source_args.len == 2
		// Nested iterator recursion — slot 0 must round-trip as an
		// IteratorNode (not silently degrade to SequenceNode, which
		// was the W3a workaround this fixes).
		nested := decoded.source_args[0]
		if nested is cx.IteratorNode {
			assert nested.source_kind == cx.IteratorSourceKind.iter_range
			assert nested.source_args.len == 3
		} else {
			assert false, 'nested arg must round-trip as IteratorNode'
		}
	} else {
		assert false, 'expected IteratorNode'
	}
}

fn test_iterator_wire_roundtrip_take_preserves_args() {
	// iter_take carries [src_iter, count_scalar]. Verify the count
	// scalar walks through unchanged.
	inner := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[int_node(0), int_node(100), int_node(1)])
	outer := cx.new_iterator(cx.IteratorSourceKind.iter_take,
		[inner, int_node(7)])
	decoded := ast_bin_iter_roundtrip(outer)
	if decoded is cx.IteratorNode {
		assert decoded.source_kind == cx.IteratorSourceKind.iter_take
		assert decoded.source_args.len == 2
		count := decoded.source_args[1]
		if count is cx.ScalarNode {
			v := count.value
			if v is i64 {
				assert v == 7
			} else { assert false, 'expected i64 count' }
		} else { assert false, 'expected ScalarNode for count' }
	} else {
		assert false, 'expected IteratorNode'
	}
}

fn test_iterator_wire_roundtrip_filter_and_single_use_flag() {
	// iter_filter carries [src_iter, closure_sentinel]. Construct the
	// IteratorNode manually with single_use=true to exercise that
	// wire slot (reserves it for external
	// stream sources).
	inner := cx.new_iterator(cx.IteratorSourceKind.iter_range,
		[int_node(1), int_node(20), int_node(1)])
	iter := cx.Node(cx.IteratorNode{
		source_kind: cx.IteratorSourceKind.iter_filter
		source_args: [inner, int_node(0)] // sentinel
		single_use:  true
	})
	decoded := ast_bin_iter_roundtrip(iter)
	if decoded is cx.IteratorNode {
		assert decoded.source_kind == cx.IteratorSourceKind.iter_filter
		assert decoded.single_use == true, 'single_use flag must round-trip'
		assert decoded.source_args.len == 2
	} else {
		assert false, 'expected IteratorNode'
	}
}
