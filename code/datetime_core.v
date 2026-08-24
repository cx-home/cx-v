module code

import cx

// datetime_core.v — the PURE proleptic-Gregorian datetime core (I4,
// #651/#516): calendar math, TDateTime, ISO-8601/duration parsing and
// canonical string forms, and the datetime scalar decode. Split out of
// the [$time:*] pack file so the EVALUATOR-core surfaces that consume
// it (eval_range_datetime — code.md §6.3 datetime ranges — and the
// crypto/similar pure call sites) survive in artifacts built without
// the local-effect time pack (-d cx_no_pack_time, spec §4 embed
// profile). Everything here is deterministic host-clock-free math;
// the clock-reading primitives stay in the pack file.

pub fn time_datetime_node(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.datetime_type }
}

fn time_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// ── Gregorian calendar core ──────────────────────────────────────────

const ns_per_us = i64(1_000)
const ns_per_ms = i64(1_000_000)
pub const ns_per_s = i64(1_000_000_000)
const ns_per_min = i64(60) * ns_per_s
const ns_per_hour = i64(3600) * ns_per_s
const ns_per_day = i64(86400) * ns_per_s

const month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

fn time_is_leap(year i64) bool {
	return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn time_days_in_month(year i64, month i64) int {
	if month < 1 || month > 12 {
		return 0
	}
	if month == 2 && time_is_leap(year) {
		return 29
	}
	return month_lengths[int(month) - 1]
}

fn days_from_civil(y i64, m i64, d i64) i64 {
	yy := if m <= 2 { y - 1 } else { y }
	era := (if yy >= 0 { yy } else { yy - 399 }) / 400
	yoe := yy - era * 400
	doy := (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1
	doe := yoe * 365 + yoe / 4 - yoe / 100 + doy
	return era * 146097 + doe - 719468
}

fn civil_from_days(z_in i64) (i64, i64, i64) {
	z := z_in + 719468
	era := (if z >= 0 { z } else { z - 146096 }) / 146097
	doe := z - era * 146097
	yoe := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
	y := yoe + era * 400
	doy := doe - (365 * yoe + yoe / 4 - yoe / 100)
	mp := (5 * doy + 2) / 153
	d := doy - (153 * mp + 2) / 5 + 1
	m := if mp < 10 { mp + 3 } else { mp - 9 }
	return (if m <= 2 { y + 1 } else { y }), m, d
}

pub struct TDateTime {
pub:
	year   i64
	month  i64
	day    i64
	hour   i64
	minute i64
	second i64
	nanos  i64
	offset i64 // seconds east of UTC
}

pub fn (dt TDateTime) instant_ns() i64 {
	day_count := days_from_civil(dt.year, dt.month, dt.day)
	local_ns := day_count * ns_per_day + dt.hour * ns_per_hour + dt.minute * ns_per_min +
		dt.second * ns_per_s + dt.nanos
	return local_ns - dt.offset * ns_per_s
}

pub fn dt_from_instant(instant_ns i64, offset i64) TDateTime {
	local_ns := instant_ns + offset * ns_per_s
	mut day_count := local_ns / ns_per_day
	mut rem := local_ns % ns_per_day
	if rem < 0 {
		rem += ns_per_day
		day_count -= 1
	}
	y, m, d := civil_from_days(day_count)
	hour := rem / ns_per_hour
	rem2 := rem % ns_per_hour
	minute := rem2 / ns_per_min
	rem3 := rem2 % ns_per_min
	second := rem3 / ns_per_s
	nanos := rem3 % ns_per_s
	return TDateTime{
		year: y, month: m, day: d, hour: hour, minute: minute,
		second: second, nanos: nanos, offset: offset
	}
}

// ── canonical string forms ───────────────────────────────────────────

fn pad2(v i64) string {
	s := v.str()
	return if s.len < 2 { '0'.repeat(2 - s.len) + s } else { s }
}

fn pad3(v i64) string {
	s := v.str()
	return if s.len < 3 { '0'.repeat(3 - s.len) + s } else { s }
}

fn pad4(v i64) string {
	neg := v < 0
	a := if neg { -v } else { v }
	mut s := a.str()
	if s.len < 4 {
		s = '0'.repeat(4 - s.len) + s
	}
	return if neg { '-' + s } else { s }
}

fn pad9(v i64) string {
	s := v.str()
	return if s.len < 9 { '0'.repeat(9 - s.len) + s } else { s }
}

fn fmt_offset(offset_secs i64) string {
	if offset_secs == 0 {
		return 'Z'
	}
	sign := if offset_secs < 0 { '-' } else { '+' }
	a := if offset_secs < 0 { -offset_secs } else { offset_secs }
	oh := a / 3600
	om := (a % 3600) / 60
	return '${sign}${pad2(oh)}:${pad2(om)}'
}

fn (dt TDateTime) date_string() string {
	return '${pad4(dt.year)}-${pad2(dt.month)}-${pad2(dt.day)}'
}

pub fn (dt TDateTime) datetime_string() string {
	mut base := '${pad4(dt.year)}-${pad2(dt.month)}-${pad2(dt.day)}T${pad2(dt.hour)}:${pad2(dt.minute)}:${pad2(dt.second)}'
	if dt.nanos != 0 {
		mut frac := pad9(dt.nanos)
		for frac.len > 3 && frac.ends_with('0') {
			frac = frac[..frac.len - 1]
		}
		base += '.' + frac
	}
	return base + fmt_offset(dt.offset)
}

// ── parsing ──────────────────────────────────────────────────────────

fn parse_uint_run(s string, start int) (i64, int) {
	mut i := start
	mut v := i64(0)
	for i < s.len && s[i] >= `0` && s[i] <= `9` {
		v = v * 10 + i64(s[i] - `0`)
		i++
	}
	return v, i
}

fn valid_date(y i64, m i64, d i64) bool {
	if y < -9999 || y > 9999 {
		return false
	}
	if m < 1 || m > 12 {
		return false
	}
	if d < 1 || d > time_days_in_month(y, m) {
		return false
	}
	return true
}

fn valid_time_of_day(h i64, mi i64, s i64) bool {
	return h >= 0 && h <= 23 && mi >= 0 && mi <= 59 && s >= 0 && s <= 60
}

fn parse_date_iso(s string) ?TDateTime {
	mut i := 0
	mut neg := false
	if i < s.len && (s[i] == `-` || s[i] == `+`) {
		neg = s[i] == `-`
		i++
	}
	year_raw, ni := parse_uint_run(s, i)
	if ni == i || ni >= s.len || s[ni] != `-` {
		return none
	}
	year := if neg { -year_raw } else { year_raw }
	month, mi := parse_uint_run(s, ni + 1)
	if mi == ni + 1 || mi >= s.len || s[mi] != `-` {
		return none
	}
	day, di := parse_uint_run(s, mi + 1)
	if di == mi + 1 || di != s.len {
		return none
	}
	if !valid_date(year, month, day) {
		return none
	}
	return TDateTime{ year: year, month: month, day: day, offset: 0 }
}

fn scale_fraction(frac_raw i64, digits int) i64 {
	mut v := frac_raw
	mut d := digits
	for d < 9 {
		v *= 10
		d++
	}
	for d > 9 {
		v /= 10
		d--
	}
	return v
}

fn parse_datetime_iso(s string) ?TDateTime {
	mut i := 0
	mut neg := false
	if i < s.len && (s[i] == `-` || s[i] == `+`) {
		neg = s[i] == `-`
		i++
	}
	year_raw, ni := parse_uint_run(s, i)
	if ni == i || ni >= s.len || s[ni] != `-` {
		return none
	}
	year := if neg { -year_raw } else { year_raw }
	month, mi := parse_uint_run(s, ni + 1)
	if mi == ni + 1 || mi >= s.len || s[mi] != `-` {
		return none
	}
	day, di := parse_uint_run(s, mi + 1)
	if di == mi + 1 {
		return none
	}
	if di >= s.len {
		return none
	}
	if s[di] != `T` && s[di] != ` ` && s[di] != `t` {
		return none
	}
	hour, hi := parse_uint_run(s, di + 1)
	if hi == di + 1 || hi >= s.len || s[hi] != `:` {
		return none
	}
	minute, mni := parse_uint_run(s, hi + 1)
	if mni == hi + 1 {
		return none
	}
	mut second := i64(0)
	mut nanos := i64(0)
	mut idx := mni
	if idx < s.len && s[idx] == `:` {
		sec, si := parse_uint_run(s, idx + 1)
		if si == idx + 1 {
			return none
		}
		second = sec
		idx = si
		if idx < s.len && s[idx] == `.` {
			fstart := idx + 1
			frac_raw, fi := parse_uint_run(s, fstart)
			if fi == fstart {
				return none
			}
			fdigits := fi - fstart
			nanos = scale_fraction(frac_raw, fdigits)
			idx = fi
		}
	}
	mut offset := i64(0)
	if idx < s.len {
		c := s[idx]
		if c == `Z` || c == `z` {
			offset = 0
			idx++
		} else if c == `+` || c == `-` {
			osign := if c == `-` { i64(-1) } else { i64(1) }
			oh, ohi := parse_uint_run(s, idx + 1)
			if ohi == idx + 1 {
				return none
			}
			mut om := i64(0)
			mut j := ohi
			if j < s.len && s[j] == `:` {
				m2, mj := parse_uint_run(s, j + 1)
				if mj == j + 1 {
					return none
				}
				om = m2
				j = mj
			} else if ohi - (idx + 1) == 4 {
				om = oh % 100
				offset = osign * ((oh / 100) * 3600 + om * 60)
				idx = ohi
				if idx != s.len {
					return none
				}
				if !valid_date(year, month, day) || !valid_time_of_day(hour, minute, second) {
					return none
				}
				return TDateTime{ year: year, month: month, day: day, hour: hour,
					minute: minute, second: second, nanos: nanos, offset: offset }
			}
			offset = osign * (oh * 3600 + om * 60)
			idx = j
		} else {
			return none
		}
	}
	if idx != s.len {
		return none
	}
	if !valid_date(year, month, day) || !valid_time_of_day(hour, minute, second) {
		return none
	}
	return TDateTime{ year: year, month: month, day: day, hour: hour, minute: minute,
		second: second, nanos: nanos, offset: offset }
}

fn parse_duration_str(s_in string) ?i64 {
	s := s_in.trim_space()
	if s.len == 0 {
		return none
	}
	mut neg := false
	mut body := s
	if body.starts_with('-') {
		neg = true
		body = body[1..]
	} else if body.starts_with('+') {
		body = body[1..]
	}
	mut total := i64(0)
	if body.len > 0 && (body[0] == `P` || body[0] == `p`) {
		total = parse_iso_duration(body) or { return none }
	} else {
		total = parse_shorthand_duration(body) or { return none }
	}
	return if neg { -total } else { total }
}

fn parse_iso_duration(body string) ?i64 {
	mut i := 1
	mut total := i64(0)
	mut in_time := false
	mut saw_any := false
	for i < body.len {
		c := body[i]
		if c == `T` || c == `t` {
			in_time = true
			i++
			continue
		}
		num, ni := parse_uint_run(body, i)
		if ni == i {
			return none
		}
		mut frac := i64(0)
		mut frac_digits := 0
		mut after := ni
		if after < body.len && (body[after] == `.` || body[after] == `,`) {
			f, fi := parse_uint_run(body, after + 1)
			if fi == after + 1 {
				return none
			}
			frac = f
			frac_digits = fi - (after + 1)
			after = fi
		}
		if after >= body.len {
			return none
		}
		unit := body[after]
		i = after + 1
		saw_any = true
		match unit {
			`D`, `d` { total += num * ns_per_day }
			`H`, `h` {
				if !in_time {
					return none
				}
				total += num * ns_per_hour
			}
			`M`, `m` {
				if !in_time {
					return none
				}
				total += num * ns_per_min
			}
			`S`, `s` {
				if !in_time {
					return none
				}
				total += num * ns_per_s
				if frac_digits > 0 {
					total += scale_fraction(frac, frac_digits)
				}
			}
			else { return none }
		}
	}
	if !saw_any {
		return none
	}
	return total
}

fn parse_shorthand_duration(body string) ?i64 {
	mut i := 0
	mut total := i64(0)
	mut saw_any := false
	for i < body.len {
		num, ni := parse_uint_run(body, i)
		if ni == i {
			return none
		}
		if ni >= body.len {
			return none
		}
		mut j := ni
		for j < body.len && ((body[j] >= `a` && body[j] <= `z`) || (body[j] >= `A` && body[j] <= `Z`)) {
			j++
		}
		unit := body[ni..j].to_lower()
		mult := match unit {
			'ns' { i64(1) }
			'us' { ns_per_us }
			'ms' { ns_per_ms }
			's' { ns_per_s }
			'm' { ns_per_min }
			'h' { ns_per_hour }
			'd' { ns_per_day }
			else { i64(0) }
		}
		if mult == 0 {
			return none
		}
		total += num * mult
		i = j
		saw_any = true
	}
	if !saw_any {
		return none
	}
	return total
}

pub fn decode_datetime(n cx.Node) ?TDateTime {
	s := time_arg_str(n) or { return none }
	if dt := parse_datetime_iso(s) {
		return dt
	}
	return parse_date_iso(s)
}
