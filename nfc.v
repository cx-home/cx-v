module cx

// nfc.v — Unicode NFC normalization for NAMES (I1 identity epoch, stream 12
// L22/L23, owner-ruled (a)): element and attribute names normalize to NFC at
// parse so two spellings of one name (é vs e+◌́) are ONE name and ONE
// address; values are NEVER normalized (data fidelity). The tables are
// CX-owned, generated from the pinned UCD (tools/gen_nfc_tables.v →
// nfc_tables.v); Hangul is algorithmic per UAX #15 §16 and needs none.

const hangul_s_base = u32(0xac00)
const hangul_l_base = u32(0x1100)
const hangul_v_base = u32(0x1161)
const hangul_t_base = u32(0x11a7)
const hangul_l_count = u32(19)
const hangul_v_count = u32(21)
const hangul_t_count = u32(28)
const hangul_n_count = hangul_v_count * hangul_t_count // 588
const hangul_s_count = hangul_l_count * hangul_n_count // 11172

fn nfc_ccc(cp u32) int {
	mut lo := 0
	mut hi := cx_nfc_ccc_flat.len / 2 - 1
	for lo <= hi {
		mid := (lo + hi) / 2
		k := cx_nfc_ccc_flat[mid * 2]
		if k == cp {
			return int(cx_nfc_ccc_flat[mid * 2 + 1])
		}
		if k < cp {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return 0
}

fn nfc_decomp(cp u32) ?[]u32 {
	mut lo := 0
	mut hi := cx_nfc_decomp_keys.len - 1
	for lo <= hi {
		mid := (lo + hi) / 2
		k := cx_nfc_decomp_keys[mid]
		if k == cp {
			span := cx_nfc_decomp_spans[mid]
			off := int(span / 256)
			n := int(span % 256)
			mut out := []u32{cap: n}
			for i in 0 .. n {
				out << cx_nfc_decomp_pool[off + i]
			}
			return out
		}
		if k < cp {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return none
}

fn nfc_compose_pair(a u32, b u32) ?u32 {
	// Hangul LV / LVT composition is algorithmic.
	if a >= hangul_l_base && a < hangul_l_base + hangul_l_count
		&& b >= hangul_v_base && b < hangul_v_base + hangul_v_count {
		l := a - hangul_l_base
		v := b - hangul_v_base
		return hangul_s_base + (l * hangul_n_count) + (v * hangul_t_count)
	}
	if a >= hangul_s_base && a < hangul_s_base + hangul_s_count
		&& (a - hangul_s_base) % hangul_t_count == 0
		&& b > hangul_t_base && b < hangul_t_base + hangul_t_count {
		return a + (b - hangul_t_base)
	}
	key := (u64(a) << 32) | u64(b)
	mut lo := 0
	mut hi := cx_nfc_comp_keys.len - 1
	for lo <= hi {
		mid := (lo + hi) / 2
		k := cx_nfc_comp_keys[mid]
		if k == key {
			return cx_nfc_comp_vals[mid]
		}
		if k < key {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return none
}

// cx_nfc_name normalizes a NAME to Unicode NFC. ASCII (and any input with
// no codepoint at or above U+00C0) returns unchanged on the fast path —
// the overwhelming majority of names never touch the tables.
pub fn cx_nfc_name(s string) string {
	mut needs := false
	for b in s.bytes() {
		if b >= 0x80 {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	// Decode UTF-8 → codepoints (input is pre-validated by the parse
	// entries; a malformed byte here passes through untouched).
	src := s.bytes()
	mut cps := []u32{cap: src.len}
	mut i := 0
	for i < src.len {
		cp, sz := utf8_cp_at(src, i)
		if sz == 0 {
			return s
		}
		cps << u32(cp)
		i += sz
	}

	// 1. Canonical decomposition (tables are fully expanded; Hangul
	//    algorithmic).
	mut d := []u32{cap: cps.len + 4}
	for cp in cps {
		if cp >= hangul_s_base && cp < hangul_s_base + hangul_s_count {
			sindex := cp - hangul_s_base
			d << hangul_l_base + sindex / hangul_n_count
			d << hangul_v_base + (sindex % hangul_n_count) / hangul_t_count
			t := sindex % hangul_t_count
			if t > 0 {
				d << hangul_t_base + t
			}
			continue
		}
		if ex := nfc_decomp(cp) {
			for c in ex {
				d << c
			}
		} else {
			d << cp
		}
	}

	// 2. Canonical ordering: stable exchange of adjacent combining marks
	//    with descending CCC.
	mut changed := true
	for changed {
		changed = false
		for j := 1; j < d.len; j++ {
			ca := nfc_ccc(d[j - 1])
			cb := nfc_ccc(d[j])
			if ca > cb && cb != 0 {
				tmp := d[j - 1]
				d[j - 1] = d[j]
				d[j] = tmp
				changed = true
			}
		}
	}

	// 3. Canonical composition (UAX #15 §8).
	mut out := []u32{cap: d.len}
	mut last_starter := -1
	mut last_ccc := -1
	for cp in d {
		c := nfc_ccc(cp)
		if last_starter >= 0 && (last_ccc < c || last_ccc == 0) {
			if comp := nfc_compose_pair(out[last_starter], cp) {
				out[last_starter] = comp
				continue
			}
		}
		if c == 0 {
			out << cp
			last_starter = out.len - 1
			last_ccc = 0
		} else {
			out << cp
			last_ccc = c
		}
	}

	// Encode back to UTF-8.
	mut buf := []u8{cap: s.len}
	for cp in out {
		encode_utf8_cp(cp, mut buf)
	}
	return buf.bytestr()
}

fn encode_utf8_cp(cp u32, mut buf []u8) {
	if cp < 0x80 {
		buf << u8(cp)
	} else if cp < 0x800 {
		buf << u8(0xc0 | (cp >> 6))
		buf << u8(0x80 | (cp & 0x3f))
	} else if cp < 0x10000 {
		buf << u8(0xe0 | (cp >> 12))
		buf << u8(0x80 | ((cp >> 6) & 0x3f))
		buf << u8(0x80 | (cp & 0x3f))
	} else {
		buf << u8(0xf0 | (cp >> 18))
		buf << u8(0x80 | ((cp >> 12) & 0x3f))
		buf << u8(0x80 | ((cp >> 6) & 0x3f))
		buf << u8(0x80 | (cp & 0x3f))
	}
}
