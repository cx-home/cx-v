module cx

// canonical_datetime.v — strict-canonical UTC-Z datetime normalization
// (I1 identity epoch; campaign stream 12, W-7/L20: "datetime strict → UTC Z").
//
// One instant, one address: a datetime carrying a UTC offset rewrites to the
// SAME INSTANT rendered Zulu (`2026-08-05T10:00:00+02:00` →
// `2026-08-05T08:00:00Z`), a bare `+00:00`/`-00:00` becomes `Z`, and
// trailing fractional zeros are stripped (`…T10:00:00.500Z` → `…T10:00:00.5Z`,
// `.000` drops entirely) — otherwise the same instant has unbounded distinct
// canonical spellings, hence unbounded Tier-1 addresses (W-7).
//
// Offset-LESS datetimes (`2026-08-05T10:00:00`) are local/floating times with
// no defined instant; they pass through untouched — normalizing them would
// invent an instant the author never stated.
//
// The arithmetic is pure Gregorian civil math (days-from-civil / civil-from-
// days, the standard proleptic algorithm) — Ring 0 stays free of V's time
// module and of any platform timezone database (only fixed offsets exist in
// the grammar, so none is needed).

// canonicalize_datetimes rewrites every datetime-typed scalar (element body
// scalars, attribute values, map keys/values, sequence/array items, table
// cells) to the strict-canonical UTC-Z form.
pub fn canonicalize_datetimes(mut doc Document) {
	canonical_dt_nodes(mut doc.prolog)
	canonical_dt_nodes(mut doc.elements)
}

fn canonical_dt_nodes(mut nodes []Node) {
	for i := 0; i < nodes.len; i++ {
		mut n := nodes[i]
		match mut n {
			Element {
				for j := 0; j < n.attrs.len; j++ {
					v := n.attrs[j].value
					if v is string {
						if is_datetime(v) {
							n.attrs[j].value = ScalarValue(canonical_dt_text(v))
						}
					}
				}
				canonical_dt_nodes(mut n.items)
				if td := n.table_opt() {
					mut t2 := TableData{
						cols:         td.cols.clone()
						rows:         td.rows.clone()
						from_chunked: td.from_chunked
					}
					mut changed := false
					for r := 0; r < t2.rows.len; r++ {
						mut row := t2.rows[r].clone()
						mut row_changed := false
						for c := 0; c < row.len; c++ {
							cv := row[c]
							if cv is string {
								if is_datetime(cv) {
									row[c] = TableCellValue(canonical_dt_text(cv))
									row_changed = true
								}
							}
						}
						if row_changed {
							t2.rows[r] = row
							changed = true
						}
					}
					if changed {
						n = n.with_table(t2)
					}
				}
				nodes[i] = n
			}
			ScalarNode {
				if n.data_type == .datetime_type {
					v := n.value
					if v is string {
						n.value = ScalarValue(canonical_dt_text(v))
						nodes[i] = n
					}
				}
			}
			SequenceNode {
				canonical_dt_nodes(mut n.items)
				nodes[i] = n
			}
			ArrayNode {
				canonical_dt_nodes(mut n.items)
				nodes[i] = n
			}
			MapNode {
				for j := 0; j < n.entries.len; j++ {
					kv := n.entries[j].key_value
					if kv is string {
						if n.entries[j].key_type == .datetime_type && is_datetime(kv) {
							n.entries[j].key_value = ScalarValue(canonical_dt_text(kv))
						}
					}
					canonical_dt_node(mut n.entries[j].value)
				}
				nodes[i] = n
			}
			else {}
		}
	}
}

fn canonical_dt_node(mut n Node) {
	mut arr := [n]
	canonical_dt_nodes(mut arr)
	n = arr[0]
}

// canonical_dt_text normalizes ONE datetime literal. Input is guaranteed
// `is_datetime` (YYYY-MM-DDTHH:MM:SS with optional .frac and optional
// Z | ±HH:MM). Unparseable input returns unchanged (fail-safe: never
// corrupt a value the guard admitted but this parser cannot read).
fn canonical_dt_text(s string) string {
	b := s.bytes()
	if b.len < 19 {
		return s
	}
	year := dt_int(b, 0, 4)
	mon := dt_int(b, 5, 2)
	day := dt_int(b, 8, 2)
	hh := dt_int(b, 11, 2)
	mm := dt_int(b, 14, 2)
	ss := dt_int(b, 17, 2)
	if year < 0 || mon < 0 || day < 0 || hh < 0 || mm < 0 || ss < 0 {
		return s
	}
	mut pos := 19
	mut frac := ''
	if pos < b.len && b[pos] == `.` {
		start := pos + 1
		mut end := start
		for end < b.len && b[end] >= `0` && b[end] <= `9` {
			end++
		}
		frac = s[start..end]
		pos = end
	}
	// Trailing fractional zeros strip; an all-zero fraction drops (W-7).
	frac = frac.trim_right('0')
	mut off_min := 0
	mut had_offset := false
	if pos < b.len {
		c := b[pos]
		if c == `Z` || c == `z` {
			had_offset = true
			pos++
		} else if c == `+` || c == `-` {
			oh := dt_int(b, pos + 1, 2)
			om := dt_int(b, pos + 4, 2)
			if oh < 0 || om < 0 || pos + 6 > b.len || b[pos + 3] != `:` {
				return s
			}
			off_min = oh * 60 + om
			if c == `-` {
				off_min = -off_min
			}
			had_offset = true
			pos += 6
		}
	}
	if pos != b.len {
		return s
	}
	if !had_offset {
		// Floating local time: no instant to normalize; only the fraction
		// canonicalizes.
		return dt_render(year, mon, day, hh, mm, ss, frac, false)
	}
	// Shift to UTC: total minutes since civil epoch, minus the offset.
	mut total_min := i64(days_from_civil(year, mon, day)) * 1440 + i64(hh) * 60 + i64(mm) - i64(off_min)
	mut days := total_min / 1440
	mut rem := total_min % 1440
	if rem < 0 {
		rem += 1440
		days--
	}
	y2, mo2, d2 := civil_from_days(days)
	return dt_render(y2, mo2, d2, int(rem / 60), int(rem % 60), ss, frac, true)
}

fn dt_int(b []u8, pos int, n int) int {
	if pos + n > b.len {
		return -1
	}
	mut v := 0
	for i in pos .. pos + n {
		if b[i] < `0` || b[i] > `9` {
			return -1
		}
		v = v * 10 + int(b[i] - `0`)
	}
	return v
}

fn dt_render(y int, mo int, d int, hh int, mm int, ss int, frac string, zulu bool) string {
	mut out := '${y:04}-${mo:02}-${d:02}T${hh:02}:${mm:02}:${ss:02}'
	if frac.len > 0 {
		out += '.' + frac
	}
	if zulu {
		out += 'Z'
	}
	return out
}

// days_from_civil / civil_from_days — the standard proleptic-Gregorian
// conversion (era-based; exact over the full year range the grammar admits).
fn days_from_civil(y int, m int, d int) i64 {
	yy := if m <= 2 { y - 1 } else { y }
	era := (if yy >= 0 { yy } else { yy - 399 }) / 400
	yoe := yy - era * 400
	mp := (m + 9) % 12
	doy := (153 * mp + 2) / 5 + d - 1
	doe := yoe * 365 + yoe / 4 - yoe / 100 + doy
	return i64(era) * 146097 + i64(doe) - 719468
}

fn civil_from_days(z0 i64) (int, int, int) {
	z := z0 + 719468
	era := (if z >= 0 { z } else { z - 146096 }) / 146097
	doe := z - era * 146097
	yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
	y := yoe + era * 400
	doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
	mp := (5 * doy + 2) / 153
	d := doy - (153 * mp + 2) / 5 + 1
	m := if mp < 10 { mp + 3 } else { mp - 9 }
	yy := if m <= 2 { y + 1 } else { y }
	return int(yy), int(m), int(d)
}
