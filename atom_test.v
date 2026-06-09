module cx

// atom_test.v — unit tests for atom scalar kind.
//
// Covers gates 33.1 (auto-typing), 33.2 (equality), 33.3 (ast_bin
// round-trip), 33.4 (canonical render), 33.5 (reserved-name rejection),
// 33.6 (identity-hash disjoint domain). The fixture-driven coverage
// lives in conformance/atoms.txt (parse + emit + AST JSON).

fn test_atom_autotype_returns_atom_scalar() {
	s := try_autotype(':ok') or {
		assert false, 'try_autotype(":ok") returned none'
		return
	}
	assert s.data_type == .atom_type
	v := s.value as string
	assert v == 'ok'
}

fn test_atom_autotype_kebab_name() {
	s := try_autotype(':not-found') or {
		assert false, ':not-found returned none'
		return
	}
	assert s.data_type == .atom_type
	v := s.value as string
	assert v == 'not-found'
}

fn test_atom_autotype_underscore_digits() {
	s := try_autotype(':http_2') or {
		assert false, ':http_2 returned none'
		return
	}
	assert s.data_type == .atom_type
	v := s.value as string
	assert v == 'http_2'
}

fn test_atom_autotype_reserved_true_returns_none() {
	// `:true` is rejected as an atom. (It also matches
	// the bool branch earlier, but the autotyper there returns the
	// bare-`true` bool, not the atom — and the source-text `:true`
	// in atom position falls through to none here.)
	_ := try_autotype(':true') or {
		assert true, 'expected none'
		return
	}
	// If we got here, autotype returned something — verify it's NOT
	// an atom (bool branch earlier would not match :true; this is the
	// reserved-name guard.)
	assert false, ':true should return none as an atom literal'
}

fn test_atom_autotype_reserved_false_returns_none() {
	_ := try_autotype(':false') or {
		assert true
		return
	}
	assert false, ':false should return none as an atom literal'
}

fn test_atom_autotype_reserved_null_returns_none() {
	_ := try_autotype(':null') or {
		assert true
		return
	}
	assert false, ':null should return none as an atom literal'
}

fn test_atom_autotype_with_letter_e_in_name() {
	// Regression: names containing `e` must not fall into the float
	// branch (which would call strconv.atof64 → none → outer none).
	for name in ['debug', 'expert', 'event', 'pending', 'failed'] {
		tok := ':${name}'
		s := try_autotype(tok) or {
			assert false, '${tok} returned none'
			return
		}
		assert s.data_type == .atom_type, '${tok} got ${s.data_type}'
		v := s.value as string
		assert v == name
	}
}

fn test_atom_renders_with_colon_prefix() {
	s := ScalarNode{ data_type: .atom_type, value: ScalarValue('ok') }
	assert cx_scalar(s) == ':ok'
}

fn test_atom_render_kebab() {
	s := ScalarNode{ data_type: .atom_type, value: ScalarValue('not-found') }
	assert cx_scalar(s) == ':not-found'
}

fn test_atom_ast_bin_roundtrip() {
	// Gate 33.3 — atom encodes via 0x03 Scalar with data_type="atom"
	// and decodes back to the same scalar.
	src := '[event kind=:click]'
	parsed := parse(src) or {
		assert false, 'parse: $err'
		return
	}
	buf := emit_ast_bin(parsed)
	decoded := bin_to_doc(buf) or {
		assert false, 'bin_to_doc: $err'
		return
	}
	emitted := emit_cx(decoded).trim_space()
	assert emitted == '[event kind=:click]', 'roundtrip mismatch: ${emitted}'
}

fn test_atom_ast_bin_roundtrip_body_via_collection() {
	src := '[transitions [:idle, :running, :complete]]'
	parsed := parse(src) or {
		assert false, 'parse: $err'
		return
	}
	buf := emit_ast_bin(parsed)
	decoded := bin_to_doc(buf) or {
		assert false, 'bin_to_doc: $err'
		return
	}
	emitted := emit_cx(decoded).trim_space()
	assert emitted == '[transitions [:idle, :running, :complete]]', 'roundtrip mismatch: ${emitted}'
}

fn test_atom_hash_distinct_from_string_with_same_name() {
	// Gate 33.6 — hash domains for atom and string MUST differ. The
	// canonical render is `:ok` for the atom and `'ok'` (quoted) for
	// the string, so the canonical bytes already differ — the SHA-256
	// over the canonical form propagates the distinction naturally.
	atom_canon := cx_text_canonical('[v kind=:ok]') or {
		assert false, 'atom_canon: $err'
		return
	}
	string_canon := cx_text_canonical("[v kind='ok']") or {
		assert false, 'string_canon: $err'
		return
	}
	assert atom_canon != string_canon, 'canonical forms collided: atom=${atom_canon} string=${string_canon}'

	atom_hash := cx_text_hash('[v kind=:ok]') or {
		assert false, 'atom_hash: $err'
		return
	}
	string_hash := cx_text_hash("[v kind='ok']") or {
		assert false, 'string_hash: $err'
		return
	}
	assert atom_hash != string_hash, 'identity hashes collided'
}

fn test_atom_in_attribute_position_autotype_via_bytes() {
	// Gate 33.1 attribute hot path. The attribute parser uses
	// try_autotype_bytes; non-numeric tokens fall back to try_autotype
	// (string path), where my atom rule fires. End-to-end: an atom
	// attribute should parse to data_type=atom_type.
	parsed := parse('[event kind=:click]') or {
		assert false, 'parse: $err'
		return
	}
	e := parsed.elements[0] as Element
	assert e.attrs.len == 1
	attr := e.attrs[0]
	dt := attr.data_type() or {
		assert false, 'attribute has no data_type'
		return
	}
	assert dt == 'atom', 'expected atom, got ${dt}'
	v := attr.value as string
	assert v == 'click'
}
