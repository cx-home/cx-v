module code

import cx
import time as vtime

// stdlib_time.v — native primitives backing the `cx-stdlib/time` module
// (spec/stdlib_time.md). Date / datetime / duration / instant logic is
// not expressible in pure CX `[?def]` bodies (Gregorian calendar math,
// ISO/RFC parsing, LDML formatting, tz offsets), so the bundle bodies
// bottom out in the primitives dispatched here. See stdlib_dispatch.v
// for the registration line.
//
// ── CX value model (spec §2) ────────────────────────────────────────
//   instant  → i64 nanoseconds since the Unix epoch, ScalarType.int_type.
//   duration → i64 signed nanoseconds, ScalarType.int_type.
//   date     → ScalarType.date_type, ScalarValue string "YYYY-MM-DD".
//   datetime → ScalarType.datetime_type, canonical ISO-8601 string.
//   weekday  → ScalarType.atom_type ("monday".."sunday").
//
// All calendar math is computed internally on a proleptic Gregorian
// calendar (Western only, §7) so results are deterministic regardless
// of the host clock or zoneinfo. The host clock is touched only by the
// impure time-source primitives.
//
// Errors are returned as `[err :code cx-err:CXERxxxx :message …]`
// element nodes (the renderer surfaces the code string, which the
// conformance harness matches against `--- out_err`).

// ── scalar builders ─────────────────────────────────────────────────

fn time_int(v i64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.int_type }
}

fn time_float(v f64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.float_type }
}

fn time_bool(v bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.bool_type }
}

fn time_str(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.string_type }
}

fn time_atom(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.atom_type }
}

fn time_date_node(v string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(v), data_type: cx.ScalarType.date_type }
}


fn time_null() cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type }
}

fn time_seq(items []cx.Node) cx.Node {
	return cx.Element{ name: '__cx_seq__', items: items }
}

fn time_err(err_code string, msg string) cx.Node {
	// err scalar fields (code/message) are attributes; reuse the
	// shared err shape so all err values round-trip identically.
	return mk_err(err_code, msg)
}

// ── argument readers ────────────────────────────────────────────────


fn time_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			string {
				// A leading-zero numeric token (`01`, `00`) is NOT an Integer
				// per lexicon [L20c] — it is preserved as a string (ZIP/SKU
				// rule). When such a token lands in an integer-parameter
				// position (`[$time:datetime 2030 01 01 00 00 00]`) CX coerces
				// it leniently to the integer it denotes, rather than failing
				// the whole call to a misleading "no callable". Only a pure
				// optionally-signed decimal run coerces; anything else stays
				// rejected.
				return decimal_int_str(v)
			}
			else {}
		}
	} else if n is cx.TextNode {
		return decimal_int_str(n.value)
	}
	note_operand_fault('time', 'time-', 'int', n)
	return none
}

// decimal_int_str returns the i64 a pure optionally-signed decimal string
// denotes (`05` → 5, `-007` → -7), or none if `s` is not a bare decimal
// integer run. Used for lenient coercion of leading-zero numeric tokens
// ([L20c]) sitting in integer-parameter position.
fn decimal_int_str(s string) ?i64 {
	if s.len == 0 {
		return none
	}
	mut i := 0
	if s[0] == `-` || s[0] == `+` {
		i = 1
	}
	if i >= s.len {
		return none
	}
	for ; i < s.len; i++ {
		if s[i] < `0` || s[i] > `9` {
			return none
		}
	}
	return s.i64()
}

fn time_arg_type(n cx.Node) ?cx.ScalarType {
	if n is cx.ScalarNode {
		return n.data_type
	}
	note_operand_fault('time', 'time-', 'scalar', n)
	return none
}


// ── duration formatting ──────────────────────────────────────────────

fn format_duration_canonical(ns_in i64) string {
	if ns_in == 0 {
		return '0s'
	}
	mut ns := ns_in
	mut sign := ''
	if ns < 0 {
		sign = '-'
		ns = -ns
	}
	mut out := ''
	d := ns / ns_per_day
	if d > 0 {
		out += '${d}d'
		ns %= ns_per_day
	}
	h := ns / ns_per_hour
	if h > 0 {
		out += '${h}h'
		ns %= ns_per_hour
	}
	m := ns / ns_per_min
	if m > 0 {
		out += '${m}m'
		ns %= ns_per_min
	}
	s := ns / ns_per_s
	if s > 0 {
		out += '${s}s'
		ns %= ns_per_s
	}
	if ns > 0 {
		if ns % ns_per_ms == 0 {
			out += '${ns / ns_per_ms}ms'
		} else if ns % ns_per_us == 0 {
			out += '${ns / ns_per_us}us'
		} else {
			out += '${ns}ns'
		}
	}
	return sign + out
}

// ── timezone table (curated IANA subset + offset rules) ──────────────

struct TzRule {
	name       string
	std_offset i64
	dst_offset i64
	dst_kind   int // 0=none, 1=US, 2=EU, 3=AU(Sydney)
}

const tz_rules = [
	TzRule{ name: 'UTC', std_offset: 0, dst_offset: 0, dst_kind: 0 },
	TzRule{ name: 'Etc/UTC', std_offset: 0, dst_offset: 0, dst_kind: 0 },
	TzRule{ name: 'America/New_York', std_offset: -5 * 3600, dst_offset: -4 * 3600, dst_kind: 1 },
	TzRule{ name: 'America/Chicago', std_offset: -6 * 3600, dst_offset: -5 * 3600, dst_kind: 1 },
	TzRule{ name: 'America/Denver', std_offset: -7 * 3600, dst_offset: -6 * 3600, dst_kind: 1 },
	TzRule{ name: 'America/Los_Angeles', std_offset: -8 * 3600, dst_offset: -7 * 3600, dst_kind: 1 },
	TzRule{ name: 'Europe/London', std_offset: 0, dst_offset: 1 * 3600, dst_kind: 2 },
	TzRule{ name: 'Europe/Paris', std_offset: 1 * 3600, dst_offset: 2 * 3600, dst_kind: 2 },
	TzRule{ name: 'Europe/Berlin', std_offset: 1 * 3600, dst_offset: 2 * 3600, dst_kind: 2 },
	TzRule{ name: 'Asia/Tokyo', std_offset: 9 * 3600, dst_offset: 9 * 3600, dst_kind: 0 },
	TzRule{ name: 'Asia/Kolkata', std_offset: 5 * 3600 + 1800, dst_offset: 5 * 3600 + 1800, dst_kind: 0 },
	TzRule{ name: 'Australia/Sydney', std_offset: 10 * 3600, dst_offset: 11 * 3600, dst_kind: 3 },
]

fn lookup_tz(name string) ?TzRule {
	for r in tz_rules {
		if r.name == name {
			return r
		}
	}
	return none
}

fn nth_weekday_of_month(y i64, m i64, weekday i64, n int) i64 {
	if n > 0 {
		first_dow := weekday_of(y, m, 1)
		mut delta := weekday - first_dow
		if delta < 0 {
			delta += 7
		}
		return 1 + delta + i64(n - 1) * 7
	}
	last := time_days_in_month(y, m)
	last_dow := weekday_of(y, m, last)
	mut delta := last_dow - weekday
	if delta < 0 {
		delta += 7
	}
	return last - delta
}

fn weekday_of(y i64, m i64, d i64) i64 {
	dc := days_from_civil(y, m, d)
	mut w := (dc + 4) % 7
	if w < 0 {
		w += 7
	}
	return w
}

fn civil_local_to_utc(y i64, m i64, d i64, h i64, mi i64, s i64, offset i64) i64 {
	dc := days_from_civil(y, m, d)
	local_ns := dc * ns_per_day + h * ns_per_hour + mi * ns_per_min + s * ns_per_s
	return local_ns - offset * ns_per_s
}

// dt_instant_overflows reports whether a date falls outside the i64-nanosecond
// instant range (≈ 1677-09-21 .. 2262-04-11 from the 1970 epoch). Beyond it,
// civil_local_to_utc's `dc * ns_per_day` silently wraps to a bogus (often
// negative) instant, so a recurrence walked past it would compare/return
// garbage (an occurrence appearing BEFORE `after`). Callers raise CXER3304.
// The day bound is i64.max / ns_per_day ≈ 106751; ±106750 keeps headroom for
// the intra-day + offset terms.
const max_instant_days = i64(106750)

fn dt_instant_overflows(dt TDateTime) bool {
	dc := days_from_civil(dt.year, dt.month, dt.day)
	return dc > max_instant_days || dc < -max_instant_days
}

fn tz_offset_for(rule TzRule, instant_ns i64) i64 {
	if rule.dst_kind == 0 {
		return rule.std_offset
	}
	utc := dt_from_instant(instant_ns, 0)
	year := utc.year
	match rule.dst_kind {
		1 {
			start_day := nth_weekday_of_month(year, 3, 0, 2)
			end_day := nth_weekday_of_month(year, 11, 0, 1)
			start_instant := civil_local_to_utc(year, 3, start_day, 2, 0, 0, rule.std_offset)
			end_instant := civil_local_to_utc(year, 11, end_day, 2, 0, 0, rule.dst_offset)
			if instant_ns >= start_instant && instant_ns < end_instant {
				return rule.dst_offset
			}
			return rule.std_offset
		}
		2 {
			start_day := nth_weekday_of_month(year, 3, 0, -1)
			end_day := nth_weekday_of_month(year, 10, 0, -1)
			start_instant := civil_local_to_utc(year, 3, start_day, 1, 0, 0, 0)
			end_instant := civil_local_to_utc(year, 10, end_day, 1, 0, 0, 0)
			if instant_ns >= start_instant && instant_ns < end_instant {
				return rule.dst_offset
			}
			return rule.std_offset
		}
		3 {
			oct_day := nth_weekday_of_month(year, 10, 0, 1)
			apr_day := nth_weekday_of_month(year, 4, 0, 1)
			dst_start := civil_local_to_utc(year, 10, oct_day, 2, 0, 0, rule.std_offset)
			dst_end := civil_local_to_utc(year, 4, apr_day, 3, 0, 0, rule.dst_offset)
			if instant_ns >= dst_start || instant_ns < dst_end {
				return rule.dst_offset
			}
			return rule.std_offset
		}
		else {
			return rule.std_offset
		}
	}
}

// ── LDML pattern formatting (§3.7, root locale English) ───────────────

const month_names_full = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
	'August', 'September', 'October', 'November', 'December']
const month_names_short = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
	'Oct', 'Nov', 'Dec']
const weekday_names_full = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
	'Saturday']
const weekday_names_short = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const weekday_atoms = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
	'saturday']

fn hour_12(h i64) i64 {
	hh := h % 12
	return if hh == 0 { 12 } else { hh }
}

fn format_ldml(dt TDateTime, pattern string) ?string {
	mut out := ''
	mut i := 0
	wd := weekday_of(dt.year, dt.month, dt.day)
	for i < pattern.len {
		c := pattern[i]
		if c == `'` {
			if i + 1 < pattern.len && pattern[i + 1] == `'` {
				out += "'"
				i += 2
				continue
			}
			mut j := i + 1
			for j < pattern.len && pattern[j] != `'` {
				out += pattern[j].ascii_str()
				j++
			}
			i = j + 1
			continue
		}
		is_letter := (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		if !is_letter {
			out += c.ascii_str()
			i++
			continue
		}
		mut j := i
		for j < pattern.len && pattern[j] == c {
			j++
		}
		run := j - i
		tok := c.ascii_str().repeat(run)
		piece := ldml_token(dt, wd, tok) or { return none }
		out += piece
		i = j
	}
	return out
}

fn ldml_token(dt TDateTime, wd i64, tok string) ?string {
	match tok {
		'yyyy' { return pad4(dt.year) }
		'yy' { return pad2(dt.year % 100) }
		'y' { return dt.year.str() }
		'MMMM' { return month_names_full[int(dt.month) - 1] }
		'MMM' { return month_names_short[int(dt.month) - 1] }
		'MM' { return pad2(dt.month) }
		'M' { return dt.month.str() }
		'dd' { return pad2(dt.day) }
		'd' { return dt.day.str() }
		'HH' { return pad2(dt.hour) }
		'H' { return dt.hour.str() }
		'hh' { return pad2(hour_12(dt.hour)) }
		'h' { return hour_12(dt.hour).str() }
		'a' { return if dt.hour < 12 { 'AM' } else { 'PM' } }
		'mm' { return pad2(dt.minute) }
		'm' { return dt.minute.str() }
		'ss' { return pad2(dt.second) }
		's' { return dt.second.str() }
		'SSS' { return pad3(dt.nanos / ns_per_ms) }
		'EEEE' { return weekday_names_full[int(wd)] }
		'EEE' { return weekday_names_short[int(wd)] }
		'z' { return if dt.offset == 0 { 'UTC' } else { fmt_offset(dt.offset) } }
		'Z' { return fmt_offset(dt.offset) }
		else { return none }
	}
}

// ── strftime parsing (§3.6 legacy escape hatch) ──────────────────────

fn parse_strftime(s string, format string) !TDateTime {
	mut year := i64(1970)
	mut month := i64(1)
	mut day := i64(1)
	mut hour := i64(0)
	mut minute := i64(0)
	mut second := i64(0)
	mut si := 0
	mut fi := 0
	for fi < format.len {
		if format[fi] == `%` && fi + 1 < format.len {
			tok := format[fi + 1]
			fi += 2
			match tok {
				`Y` {
					v, ni := parse_uint_run(s, si)
					if ni == si { return error('malformed') }
					year = v
					si = ni
				}
				`m` {
					v, ni := parse_uint_run(s, si)
					if ni == si { return error('malformed') }
					month = v
					si = ni
				}
				`d` {
					v, ni := parse_uint_run(s, si)
					if ni == si { return error('malformed') }
					day = v
					si = ni
				}
				`H` {
					v, ni := parse_uint_run(s, si)
					if ni == si { return error('malformed') }
					hour = v
					si = ni
				}
				`M` {
					v, ni := parse_uint_run(s, si)
					if ni == si { return error('malformed') }
					minute = v
					si = ni
				}
				`S` {
					v, ni := parse_uint_run(s, si)
					if ni == si { return error('malformed') }
					second = v
					si = ni
				}
				`%` {
					if si >= s.len || s[si] != `%` { return error('malformed') }
					si++
				}
				else {
					return error('unknown-token')
				}
			}
		} else {
			if si >= s.len || s[si] != format[fi] {
				return error('malformed')
			}
			si++
			fi++
		}
	}
	if si != s.len {
		return error('malformed')
	}
	if !valid_date(year, month, day) || !valid_time_of_day(hour, minute, second) {
		return error('malformed')
	}
	return TDateTime{ year: year, month: month, day: day, hour: hour, minute: minute,
		second: second, offset: 0 }
}

// ── RFC 2822 parsing (§3.6) ──────────────────────────────────────────

const rfc2822_months = {
	'Jan': i64(1), 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
	'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

fn parse_rfc2822_str(s_in string) ?TDateTime {
	mut s := s_in.trim_space()
	if comma := s.index(',') {
		if comma <= 3 {
			s = s[comma + 1..].trim_space()
		}
	}
	parts := s.split(' ').filter(it != '')
	if parts.len < 5 {
		return none
	}
	day := parts[0].i64()
	month := rfc2822_months[parts[1]] or { return none }
	year_raw := parts[2].i64()
	year := if parts[2].len == 2 {
		if year_raw < 70 { 2000 + year_raw } else { 1900 + year_raw }
	} else {
		year_raw
	}
	tparts := parts[3].split(':')
	if tparts.len < 2 {
		return none
	}
	hour := tparts[0].i64()
	minute := tparts[1].i64()
	second := if tparts.len >= 3 { tparts[2].i64() } else { i64(0) }
	offset := parse_rfc2822_zone(parts[4]) or { return none }
	if !valid_date(year, month, day) || !valid_time_of_day(hour, minute, second) {
		return none
	}
	return TDateTime{ year: year, month: month, day: day, hour: hour, minute: minute,
		second: second, offset: offset }
}

fn parse_rfc2822_zone(z string) ?i64 {
	match z {
		'UT', 'GMT', 'Z' { return i64(0) }
		'EST' { return i64(-5 * 3600) }
		'EDT' { return i64(-4 * 3600) }
		'CST' { return i64(-6 * 3600) }
		'CDT' { return i64(-5 * 3600) }
		'MST' { return i64(-7 * 3600) }
		'MDT' { return i64(-6 * 3600) }
		'PST' { return i64(-8 * 3600) }
		'PDT' { return i64(-7 * 3600) }
		else {}
	}
	if z.len == 5 && (z[0] == `+` || z[0] == `-`) {
		sign := if z[0] == `-` { i64(-1) } else { i64(1) }
		oh := z[1..3].i64()
		om := z[3..5].i64()
		return sign * (oh * 3600 + om * 60)
	}
	return none
}

// ── LDML parsing ─────────────────────────────────────────────────────

fn parse_ldml(s string, pattern string) !TDateTime {
	mut year := i64(1970)
	mut month := i64(1)
	mut day := i64(1)
	mut hour := i64(0)
	mut minute := i64(0)
	mut second := i64(0)
	mut si := 0
	mut pi := 0
	for pi < pattern.len {
		c := pattern[pi]
		if c == `'` {
			if pi + 1 < pattern.len && pattern[pi + 1] == `'` {
				if si >= s.len || s[si] != `'` {
					return error('malformed')
				}
				si++
				pi += 2
				continue
			}
			mut j := pi + 1
			for j < pattern.len && pattern[j] != `'` {
				if si >= s.len || s[si] != pattern[j] {
					return error('malformed')
				}
				si++
				j++
			}
			pi = j + 1
			continue
		}
		is_letter := (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		if !is_letter {
			if si >= s.len || s[si] != c {
				return error('malformed')
			}
			si++
			pi++
			continue
		}
		mut j := pi
		for j < pattern.len && pattern[j] == c {
			j++
		}
		run := j - pi
		tok := c.ascii_str().repeat(run)
		match tok {
			'yyyy', 'yy', 'y' {
				v, ni := parse_uint_run(s, si)
				if ni == si { return error('malformed') }
				year = if tok == 'yy' && v < 100 {
					if v < 70 { 2000 + v } else { 1900 + v }
				} else { v }
				si = ni
			}
			'MM', 'M' {
				v, ni := parse_uint_run(s, si)
				if ni == si { return error('malformed') }
				month = v
				si = ni
			}
			'MMM' {
				if si + 3 > s.len { return error('malformed') }
				mname := s[si..si + 3]
				month = rfc2822_months[mname] or { return error('malformed') }
				si += 3
			}
			'MMMM' {
				mut matched := false
				for mi2, mn in month_names_full {
					if s[si..].starts_with(mn) {
						month = i64(mi2 + 1)
						si += mn.len
						matched = true
						break
					}
				}
				if !matched { return error('malformed') }
			}
			'dd', 'd' {
				v, ni := parse_uint_run(s, si)
				if ni == si { return error('malformed') }
				day = v
				si = ni
			}
			'HH', 'H', 'hh', 'h' {
				v, ni := parse_uint_run(s, si)
				if ni == si { return error('malformed') }
				hour = v
				si = ni
			}
			'mm', 'm' {
				v, ni := parse_uint_run(s, si)
				if ni == si { return error('malformed') }
				minute = v
				si = ni
			}
			'ss', 's' {
				v, ni := parse_uint_run(s, si)
				if ni == si { return error('malformed') }
				second = v
				si = ni
			}
			'a' {
				if s[si..].starts_with('PM') {
					if hour < 12 { hour += 12 }
					si += 2
				} else if s[si..].starts_with('AM') {
					if hour == 12 { hour = 0 }
					si += 2
				} else {
					return error('malformed')
				}
			}
			else {
				return error('unknown-token')
			}
		}
		pi = j
	}
	if si != s.len {
		return error('malformed')
	}
	if !valid_date(year, month, day) || !valid_time_of_day(hour, minute, second) {
		return error('malformed')
	}
	return TDateTime{ year: year, month: month, day: day, hour: hour, minute: minute,
		second: second, offset: 0 }
}

// ── element builders ─────────────────────────────────────────────────

// time_int_attr builds an int-typed attribute. duration-parts
// timezone scalar fields are attributes, not labeled slots.
fn time_int_attr(label string, v i64) cx.Attribute {
	return cx.new_attribute(label, cx.ScalarValue(v), cx.AttributeMeta{
		data_type: ?string('int')
	})
}

fn duration_parts_element(ns_in i64) cx.Node {
	mut ns := ns_in
	mut neg := false
	if ns < 0 {
		neg = true
		ns = -ns
	}
	days := ns / ns_per_day
	ns %= ns_per_day
	hours := ns / ns_per_hour
	ns %= ns_per_hour
	mins := ns / ns_per_min
	ns %= ns_per_min
	secs := ns / ns_per_s
	ns %= ns_per_s
	sign := if neg { i64(-1) } else { i64(1) }
	return cx.Element{
		name: 'duration-parts'
		attrs: [
			time_int_attr('days', sign * days),
			time_int_attr('hours', sign * hours),
			time_int_attr('minutes', sign * mins),
			time_int_attr('seconds', sign * secs),
			time_int_attr('nanoseconds', sign * ns),
		]
	}
}

fn iso_week_of_year(y i64, m i64, d i64) i64 {
	dc := days_from_civil(y, m, d)
	mut iso_dow := weekday_of(y, m, d)
	iso_dow = if iso_dow == 0 { 7 } else { iso_dow }
	thursday := dc + (4 - iso_dow)
	ty, _, _ := civil_from_days(thursday)
	jan1 := days_from_civil(ty, 1, 1)
	return (thursday - jan1) / 7 + 1
}

fn timezone_element(rule TzRule) cx.Node {
	has_dst := rule.dst_kind != 0
	// name/offset/dst are scalar fields → attributes.
	return cx.Element{
		name: 'timezone'
		attrs: [
			cx.new_attribute('name', cx.ScalarValue(rule.name), cx.AttributeMeta{
				data_type: ?string(none)
			}),
			time_int_attr('offset', rule.std_offset),
			cx.new_attribute('dst', cx.ScalarValue(has_dst), cx.AttributeMeta{
				data_type: ?string('bool')
			}),
		]
	}
}

fn format_rfc2822(dt TDateTime) string {
	wd := weekday_of(dt.year, dt.month, dt.day)
	zone := if dt.offset == 0 {
		'+0000'
	} else {
		sign := if dt.offset < 0 { '-' } else { '+' }
		a := if dt.offset < 0 { -dt.offset } else { dt.offset }
		'${sign}${pad2(a / 3600)}${pad2((a % 3600) / 60)}'
	}
	return '${weekday_names_short[int(wd)]}, ${pad2(dt.day)} ${month_names_short[int(dt.month) - 1]} ${pad4(dt.year)} ${pad2(dt.hour)}:${pad2(dt.minute)}:${pad2(dt.second)} ${zone}'
}

fn format_relative(target i64, now i64) string {
	diff := target - now
	a := if diff < 0 { -diff } else { diff }
	future := diff > 0
	mut amount := i64(0)
	mut unit := ''
	if a < ns_per_min {
		amount = a / ns_per_s
		unit = 'second'
	} else if a < ns_per_hour {
		amount = a / ns_per_min
		unit = 'minute'
	} else if a < ns_per_day {
		amount = a / ns_per_hour
		unit = 'hour'
	} else if a < 30 * ns_per_day {
		amount = a / ns_per_day
		unit = 'day'
	} else if a < 365 * ns_per_day {
		amount = a / (30 * ns_per_day)
		unit = 'month'
	} else {
		amount = a / (365 * ns_per_day)
		unit = 'year'
	}
	if amount == 0 {
		return 'just now'
	}
	plural := if amount == 1 { '' } else { 's' }
	if future {
		return 'in ${amount} ${unit}${plural}'
	}
	return '${amount} ${unit}${plural} ago'
}

// ── decode helpers ───────────────────────────────────────────────────

fn decode_date(n cx.Node) ?TDateTime {
	s := time_arg_str(n) or { return none }
	if dt := parse_date_iso(s) {
		return dt
	}
	return parse_datetime_iso(s)
}


fn decode_date_or_datetime(n cx.Node) ?TDateTime {
	s := time_arg_str(n) or { return none }
	if dt := parse_datetime_iso(s) {
		return dt
	}
	return parse_date_iso(s)
}

fn decode_any_instant(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		match n.value {
			i64 {
				return n.value as i64
			}
			string {
				dt := decode_date_or_datetime(n) or { return none }
				return dt.instant_ns()
			}
			else {}
		}
	}
	return none
}

fn time_add_duration(target cx.Node, dur cx.Node, sign i64) ?cx.Node {
	delta := time_arg_int(dur) or { return none }
	signed := sign * delta
	dtype := time_arg_type(target) or { return none }
	match dtype {
		.int_type {
			base := time_arg_int(target) or { return none }
			return time_int(base + signed)
		}
		.date_type {
			dt := decode_date(target) or { return none }
			ni := dt.instant_ns() + signed
			return time_date_node(dt_from_instant(ni, 0).date_string())
		}
		.datetime_type {
			dt := decode_datetime(target) or { return none }
			ni := dt.instant_ns() + signed
			return time_datetime_node(dt_from_instant(ni, dt.offset).datetime_string())
		}
		else {
			return none
		}
	}
}

fn add_months_clamp(dt TDateTime, n i64, strict bool) cx.Node {
	total := (dt.year * 12 + (dt.month - 1)) + n
	mut y := total / 12
	mut m := total % 12
	if m < 0 {
		m += 12
		y -= 1
	}
	m += 1
	max_day := time_days_in_month(y, m)
	if dt.day > max_day {
		if strict {
			return time_err('cx-err:CXER3300',
				'E_TIME_INVALID_COMPONENT: day ${dt.day} does not exist in ${y}-${m}')
		}
		return time_date_node(TDateTime{ year: y, month: m, day: max_day }.date_string())
	}
	return time_date_node(TDateTime{ year: y, month: m, day: dt.day }.date_string())
}

// ── recurrence (§3.10 — RFC 5545 RRULE + cron) ───────────────────────
//
// A `[recurrence …]` is a pure, homoiconic value. Internal model:
//
//   [recurrence freq=:weekly interval=2 anchor="…" tz="…" wkst=:monday
//     count=N | until="…"
//     [by-second 0 30] [by-minute …] [by-hour …]
//     [by-day :tuesday [nth -1 :friday]]
//     [by-month-day …] [by-year-day …] [by-week-no …] [by-month …]
//     [by-set-pos …]]
//
// freq / interval / anchor / tz / wkst / count / until are attributes;
// the BY* parts are child elements. `recurrence` builds + validates this
// shape; every other §3.10 function reads it back via `recur_rule_from`.
//
// Expansion semantics mirror RFC 5545 §3.3.10: starting from the anchor,
// each interval of `freq`×`interval` produces a candidate set; BY* parts
// coarser-than-or-equal-to freq FILTER, finer parts EXPAND, in the RFC's
// fixed order; BYSETPOS selects the i-th / i-th-from-last of the sorted
// candidate set of one interval. anchor / until are wall-clock LOCAL in
// `tz`, so BYHOUR/MINUTE/SECOND are evaluated in that zone and a rule
// round-trips through DST without drift (gap→forward / overlap→earlier).

const recur_max_occurrences = i64(100000)

// freq codes (coarse→fine order used for BY* filter/expand classification)
const freq_yearly = 0
const freq_monthly = 1
const freq_weekly = 2
const freq_daily = 3
const freq_hourly = 4
const freq_minutely = 5
const freq_secondly = 6

fn recur_freq_from_atom(a string) ?int {
	return match a {
		'yearly' { freq_yearly }
		'monthly' { freq_monthly }
		'weekly' { freq_weekly }
		'daily' { freq_daily }
		'hourly' { freq_hourly }
		'minutely' { freq_minutely }
		'secondly' { freq_secondly }
		else { none }
	}
}

fn recur_freq_to_atom(f int) string {
	return match f {
		freq_yearly { 'yearly' }
		freq_monthly { 'monthly' }
		freq_weekly { 'weekly' }
		freq_daily { 'daily' }
		freq_hourly { 'hourly' }
		freq_minutely { 'minutely' }
		freq_secondly { 'secondly' }
		else { 'daily' }
	}
}

fn recur_freq_to_rrule(f int) string {
	return match f {
		freq_yearly { 'YEARLY' }
		freq_monthly { 'MONTHLY' }
		freq_weekly { 'WEEKLY' }
		freq_daily { 'DAILY' }
		freq_hourly { 'HOURLY' }
		freq_minutely { 'MINUTELY' }
		freq_secondly { 'SECONDLY' }
		else { 'DAILY' }
	}
}

fn recur_freq_from_rrule(s string) ?int {
	return match s {
		'YEARLY' { freq_yearly }
		'MONTHLY' { freq_monthly }
		'WEEKLY' { freq_weekly }
		'DAILY' { freq_daily }
		'HOURLY' { freq_hourly }
		'MINUTELY' { freq_minutely }
		'SECONDLY' { freq_secondly }
		else { none }
	}
}

// weekday atom ↔ index. RFC 5545 numbers weekdays MO..SU; this engine
// uses the civil weekday_of convention (0=Sunday .. 6=Saturday).
const recur_weekday_atoms = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
	'saturday']
const recur_weekday_rrule = ['SU', 'MO', 'TU', 'WE', 'TH', 'FR', 'SA']

fn recur_weekday_from_atom(a string) ?i64 {
	for i, w in recur_weekday_atoms {
		if w == a {
			return i64(i)
		}
	}
	return none
}

fn recur_weekday_from_rrule(s string) ?i64 {
	for i, w in recur_weekday_rrule {
		if w == s {
			return i64(i)
		}
	}
	return none
}

// A BYDAY entry: weekday plus an optional ordinal (0 = no ordinal).
struct RecurByDay {
	weekday i64
	ord     int // 0 = plain; ±N = nth/from-last within month (MONTHLY/YEARLY)
}

// The parsed, validated recurrence rule.
struct RecurRule {
	freq        int
	interval    i64
	anchor      TDateTime // wall-clock local in tz
	tz          string
	wkst        i64 // civil index of week-start
	count       i64 // 0 = unbounded by count
	has_count   bool
	until       TDateTime // wall-clock local in tz
	has_until   bool
	by_second   []i64
	by_minute   []i64
	by_hour     []i64
	by_day      []RecurByDay
	by_monthday []i64
	by_yearday  []i64
	by_weekno   []i64
	by_month    []i64
	by_setpos   []i64
}

fn (r RecurRule) is_finite() bool {
	return r.has_count || r.has_until
}

// ── reading a [recurrence] element into a RecurRule ──────────────────

fn recur_attr_str(el cx.Element, name string) ?string {
	for a in el.attrs {
		if a.name == name {
			v := a.value
			if v is string {
				return v
			}
		}
	}
	return none
}

fn recur_attr_int(el cx.Element, name string) ?i64 {
	for a in el.attrs {
		if a.name == name {
			v := a.value
			match v {
				i64 { return v }
				f64 { return i64(v) }
				else {}
			}
		}
	}
	return none
}

fn recur_child(el cx.Element, name string) ?cx.Element {
	for it in el.items {
		if it is cx.Element && it.name == name {
			return it
		}
	}
	return none
}

// recur_int_list reads the bare int items of a `[by-* N N N]` child.
fn recur_int_list(el cx.Element, name string) []i64 {
	mut out := []i64{}
	if c := recur_child(el, name) {
		for it in c.items {
			if it is cx.ScalarNode {
				v := it.value
				match v {
					i64 { out << v }
					f64 { out << i64(v) }
					else {}
				}
			}
		}
	}
	return out
}

// recur_atom_of reads a scalar node as an atom string (no leading colon).
fn recur_atom_of(n cx.Node) ?string {
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.atom_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	return none
}

// recur_parse_byday reads `[by-day :tuesday [nth -1 :friday]]` into
// RecurByDay entries. Plain weekday atoms → ord 0; `[nth N :weekday]` →
// ordinal N. Returns an error string on malformed content.
fn recur_parse_byday(el cx.Element) !([]RecurByDay) {
	mut out := []RecurByDay{}
	c := recur_child(el, 'by-day') or { return out }
	for it in c.items {
		if a := recur_atom_of(it) {
			wd := recur_weekday_from_atom(a) or { return error('bad-weekday') }
			out << RecurByDay{ weekday: wd, ord: 0 }
			continue
		}
		if it is cx.Element && it.name == 'nth' {
			if it.items.len < 2 {
				return error('bad-nth')
			}
			ord := if it.items[0] is cx.ScalarNode {
				v := (it.items[0] as cx.ScalarNode).value
				match v {
					i64 { int(v) }
					f64 { int(v) }
					else { return error('bad-nth') }
				}
			} else {
				return error('bad-nth')
			}
			wda := recur_atom_of(it.items[1]) or { return error('bad-nth') }
			wd := recur_weekday_from_atom(wda) or { return error('bad-weekday') }
			if ord == 0 {
				return error('bad-nth')
			}
			out << RecurByDay{ weekday: wd, ord: ord }
			continue
		}
		return error('bad-byday')
	}
	return out
}

// recur_rule_from validates and lifts a `[recurrence]` element. Returns
// an err Node (CXER3322 / CXER3323) on fault, threaded through `!`-style
// by returning `?` none + a separate validated path. Here we return a
// Result whose error message is the CXER code+mnemonic for the caller.
fn recur_rule_from(n cx.Node) !RecurRule {
	if n !is cx.Element {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: not a [recurrence] element')
	}
	el := n as cx.Element
	if el.name != 'recurrence' {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: expected [recurrence], got [${el.name}]')
	}
	// freq (required atom)
	freq_atom := recur_attr_str(el, 'freq') or {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: missing freq')
	}
	freq := recur_freq_from_atom(freq_atom) or {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: unknown freq :${freq_atom}')
	}
	// interval (default 1, positive)
	mut interval := i64(1)
	if iv := recur_attr_int(el, 'interval') {
		interval = iv
	}
	if interval < 1 {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: interval must be positive')
	}
	// anchor (required datetime, wall-clock local)
	anchor_s := recur_attr_str(el, 'anchor') or {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: missing anchor')
	}
	anchor := parse_datetime_iso(anchor_s) or {
		dt := parse_date_iso(anchor_s) or {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: bad anchor ${anchor_s}')
		}
		dt
	}
	// tz (default UTC)
	tz := recur_attr_str(el, 'tz') or { 'UTC' }
	if _ := lookup_tz(tz) {} else {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: unknown tz ${tz}')
	}
	// wkst (default monday)
	mut wkst := i64(1)
	if w := recur_attr_str(el, 'wkst') {
		wkst = recur_weekday_from_atom(w) or {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: unknown wkst :${w}')
		}
	}
	// count / until (mutually exclusive)
	mut has_count := false
	mut count := i64(0)
	if c := recur_attr_int(el, 'count') {
		has_count = true
		count = c
		if count < 1 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: count must be positive')
		}
	}
	mut has_until := false
	mut until := TDateTime{}
	if u := recur_attr_str(el, 'until') {
		has_until = true
		until = parse_datetime_iso(u) or {
			parse_date_iso(u) or {
				return error('CXER3322|E_TIME_RULE_FIELD_INVALID: bad until ${u}')
			}
		}
	}
	if has_count && has_until {
		return error('CXER3323|E_TIME_RULE_CONTRADICTORY: count and until are mutually exclusive')
	}
	// BY* parts
	by_second := recur_int_list(el, 'by-second')
	by_minute := recur_int_list(el, 'by-minute')
	by_hour := recur_int_list(el, 'by-hour')
	by_day := recur_parse_byday(el) or {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: bad by-day')
	}
	by_monthday := recur_int_list(el, 'by-month-day')
	by_yearday := recur_int_list(el, 'by-year-day')
	by_weekno := recur_int_list(el, 'by-week-no')
	by_month := recur_int_list(el, 'by-month')
	by_setpos := recur_int_list(el, 'by-set-pos')
	// range validation
	for v in by_second {
		if v < 0 || v > 60 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-second ${v}')
		}
	}
	for v in by_minute {
		if v < 0 || v > 59 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-minute ${v}')
		}
	}
	for v in by_hour {
		if v < 0 || v > 23 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-hour ${v}')
		}
	}
	for v in by_monthday {
		if v == 0 || v < -31 || v > 31 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-month-day ${v}')
		}
	}
	for v in by_yearday {
		if v == 0 || v < -366 || v > 366 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-year-day ${v}')
		}
	}
	for v in by_weekno {
		if v == 0 || v < -53 || v > 53 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-week-no ${v}')
		}
	}
	for v in by_month {
		if v < 1 || v > 12 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-month ${v}')
		}
	}
	for v in by_setpos {
		if v == 0 || v < -366 || v > 366 {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-set-pos ${v}')
		}
	}
	// ordinal BYDAY only legal under MONTHLY/YEARLY (RFC 5545)
	for bd in by_day {
		if bd.ord != 0 && freq != freq_monthly && freq != freq_yearly {
			return error('CXER3322|E_TIME_RULE_FIELD_INVALID: ordinal by-day requires monthly/yearly freq')
		}
	}
	// BYWEEKNO only valid with YEARLY (RFC 5545)
	if by_weekno.len > 0 && freq != freq_yearly {
		return error('CXER3322|E_TIME_RULE_FIELD_INVALID: by-week-no requires yearly freq')
	}
	rule := RecurRule{
		freq: freq, interval: interval, anchor: anchor, tz: tz, wkst: wkst,
		count: count, has_count: has_count, until: until, has_until: has_until,
		by_second: by_second, by_minute: by_minute, by_hour: by_hour,
		by_day: by_day, by_monthday: by_monthday, by_yearday: by_yearday,
		by_weekno: by_weekno, by_month: by_month, by_setpos: by_setpos,
	}
	// contradiction check: a fixed BYMONTH+BYMONTHDAY combination that can
	// never occur (e.g. month 2 + day 30).
	recur_check_contradictory(rule)!
	return rule
}

// recur_check_contradictory rejects rules that can provably never fire.
fn recur_check_contradictory(r RecurRule) ! {
	// BYMONTH=M + BYMONTHDAY=D with D exceeding every chosen month's max
	// (using a leap year for February's upper bound).
	if r.by_month.len > 0 && r.by_monthday.len > 0 {
		mut any_ok := false
		for m in r.by_month {
			max_d := time_days_in_month(2000, m) // 2000 is leap → Feb=29
			for d in r.by_monthday {
				ad := if d < 0 { max_d + d + 1 } else { d }
				if ad >= 1 && ad <= max_d {
					any_ok = true
				}
			}
		}
		if !any_ok {
			return error('CXER3323|E_TIME_RULE_CONTRADICTORY: by-month + by-month-day can never coincide')
		}
	}
}

// recur_resolve_local resolves a wall-clock LOCAL datetime in `tz` to its UTC
// offset, handling the two DST edge cases verbatim per §4.2:
//   • OVERLAP (fall-back): the local time exists under BOTH offsets → adopt
//     the EARLIER instant (the pre-transition offset). The prior two-pass
//     SEEDED with std_offset and so resolved to the LATER (post-transition)
//     offset — wrong by one hour for every fall-back-overlap local time.
//   • GAP (spring-forward): the local time exists under NEITHER offset → roll
//     the wall clock FORWARD by the spring jump to the next valid local time,
//     rather than emitting a nonexistent local label.
// Returns the resolved offset AND the (possibly rolled-forward) wall clock.
fn recur_resolve_local(rule TzRule, dt TDateTime) (i64, TDateTime) {
	if rule.dst_kind == 0 {
		return rule.std_offset, dt
	}
	inst_dst := civil_local_to_utc(dt.year, dt.month, dt.day, dt.hour, dt.minute,
		dt.second, rule.dst_offset)
	inst_std := civil_local_to_utc(dt.year, dt.month, dt.day, dt.hour, dt.minute,
		dt.second, rule.std_offset)
	dst_valid := tz_offset_for(rule, inst_dst) == rule.dst_offset
	std_valid := tz_offset_for(rule, inst_std) == rule.std_offset
	if dst_valid && std_valid {
		// Overlap: both interpretations are self-consistent → the EARLIER
		// instant wins (smaller UTC ns).
		if inst_dst <= inst_std {
			return rule.dst_offset, dt
		}
		return rule.std_offset, dt
	}
	if dst_valid {
		return rule.dst_offset, dt
	}
	if std_valid {
		return rule.std_offset, dt
	}
	// Gap: neither interpretation is valid (the local time is skipped by the
	// spring-forward jump). Roll the wall clock forward by the jump size and
	// resolve at the post-gap offset.
	gap := rule.dst_offset - rule.std_offset
	wall_ns := civil_local_to_utc(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, 0)
	rolled := dt_from_instant(wall_ns + gap * ns_per_s, 0)
	inst := civil_local_to_utc(rolled.year, rolled.month, rolled.day, rolled.hour,
		rolled.minute, rolled.second, rule.dst_offset)
	return tz_offset_for(rule, inst), rolled
}

// recur_local_to_instant converts a wall-clock local datetime in `tz`
// to a UTC instant (ns).
fn recur_local_to_instant(tzname string, dt TDateTime) i64 {
	rule := lookup_tz(tzname) or {
		return dt.instant_ns()
	}
	off, rd := recur_resolve_local(rule, dt)
	return civil_local_to_utc(rd.year, rd.month, rd.day, rd.hour, rd.minute, rd.second, off)
}

// recur_render_local builds the canonical datetime string for a local
// wall-clock value in `tz`, carrying the resolved offset (and, for a gap
// time, the rolled-forward wall clock).
fn recur_render_local(tzname string, dt TDateTime) string {
	rule := lookup_tz(tzname) or {
		return TDateTime{ ...dt, offset: 0 }.datetime_string()
	}
	off, rd := recur_resolve_local(rule, dt)
	return TDateTime{ ...rd, offset: off }.datetime_string()
}

// ── expansion engine ─────────────────────────────────────────────────
//
// recur_expand walks intervals from the anchor, building candidate
// wall-clock-local datetimes per interval, applies BYSETPOS, filters to
// the [lo, hi) window (UTC instants), and yields ascending instants
// until `limit` results are gathered, the window upper bound is passed,
// or the rule is exhausted (count / until). `lo_inclusive` controls
// whether a candidate exactly at `lo` is admitted.
//
// Returns (results, hit_budget). hit_budget=true means the search budget
// was exhausted without naturally terminating → CXER3325 for unbounded
// queries.

struct RecurCandidate {
	dt      TDateTime // wall-clock local
	instant i64       // UTC ns
}

// recur_candidates_for_interval builds the sorted candidate set for the
// interval whose "current" reference date is (cy, cm, cd) — interpreted
// per freq. Produces wall-clock-local TDateTime values.
fn recur_candidates_for_interval(r RecurRule, base TDateTime) []TDateTime {
	mut days := [][]i64{} // list of (year, month, day) triples
	match r.freq {
		freq_yearly {
			days = recur_yearly_days(r, base.year)
		}
		freq_monthly {
			days = recur_monthly_days(r, base.year, base.month)
		}
		freq_weekly {
			days = recur_weekly_days(r, base)
		}
		freq_daily {
			days = recur_daily_days(r, base)
		}
		else {
			// HOURLY/MINUTELY/SECONDLY: the single base day/time. Date BY*
			// filter the base day; time BY* at-or-coarser than freq filter
			// base's components, finer parts expand (handled below).
			if recur_passes_filters(r, base.year, base.month, base.day) {
				// hour: filter for HOURLY+ (freq <= hourly grain), expand for
				// nothing coarser here. For HOURLY, by-hour filters base.hour.
				hour_ok := r.by_hour.len == 0 || base.hour in r.by_hour
				// minute: filters for HOURLY/MINUTELY; expands for HOURLY when
				// by-minute present.
				min_filter := r.freq == freq_minutely || r.freq == freq_secondly
				min_ok := !min_filter || r.by_minute.len == 0 || base.minute in r.by_minute
				sec_filter := r.freq == freq_secondly
				sec_ok := !sec_filter || r.by_second.len == 0 || base.second in r.by_second
				if hour_ok && min_ok && sec_ok {
					days = [[base.year, base.month, base.day]]
				}
			}
		}
	}
	mut out := []TDateTime{}
	// time-component expansion. For sub-daily freqs the coarser-or-equal
	// parts were already filtered against `base` above; here we expand the
	// finer parts (and default the rest to base's components).
	mut hours := [base.hour]
	mut mins := [base.minute]
	mut secs := [base.second]
	if r.freq <= freq_daily {
		// coarser than hourly: all time parts expand from their BY lists
		if r.by_hour.len > 0 {
			hours = r.by_hour.clone()
		}
		if r.by_minute.len > 0 {
			mins = r.by_minute.clone()
		}
		if r.by_second.len > 0 {
			secs = r.by_second.clone()
		}
	} else if r.freq == freq_hourly {
		// hour fixed by base; minute/second expand
		if r.by_minute.len > 0 {
			mins = r.by_minute.clone()
		}
		if r.by_second.len > 0 {
			secs = r.by_second.clone()
		}
	} else if r.freq == freq_minutely {
		// hour+minute fixed by base; second expands
		if r.by_second.len > 0 {
			secs = r.by_second.clone()
		}
	}
	for ymd in days {
		for h in hours {
			for mi in mins {
				for s in secs {
					out << TDateTime{
						year: ymd[0], month: ymd[1], day: ymd[2],
						hour: h, minute: mi, second: s, nanos: 0,
					}
				}
			}
		}
	}
	// sort ascending by wall-clock
	out.sort_with_compare(fn (a &TDateTime, b &TDateTime) int {
		ia := civil_local_to_utc(a.year, a.month, a.day, a.hour, a.minute, a.second, 0)
		ib := civil_local_to_utc(b.year, b.month, b.day, b.hour, b.minute, b.second, 0)
		if ia < ib { return -1 }
		if ia > ib { return 1 }
		return 0
	})
	return out
}

fn recur_passes_filters(r RecurRule, y i64, m i64, d i64) bool {
	if r.by_month.len > 0 && m !in r.by_month {
		return false
	}
	if r.by_monthday.len > 0 {
		max_d := time_days_in_month(y, m)
		mut ok := false
		for md in r.by_monthday {
			ad := if md < 0 { max_d + md + 1 } else { md }
			if ad == d {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if r.by_yearday.len > 0 {
		ydays := if time_is_leap(y) { i64(366) } else { i64(365) }
		doy := days_from_civil(y, m, d) - days_from_civil(y, 1, 1) + 1
		mut ok := false
		for yd in r.by_yearday {
			ad := if yd < 0 { ydays + yd + 1 } else { yd }
			if ad == doy {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if r.by_day.len > 0 {
		wd := weekday_of(y, m, d)
		mut ok := false
		for bd in r.by_day {
			if bd.weekday != wd {
				continue
			}
			if bd.ord == 0 {
				ok = true
				continue
			}
			// ordinal within month
			target := nth_weekday_of_month(y, m, bd.weekday, bd.ord)
			if target == d {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if r.by_weekno.len > 0 {
		wk := iso_week_of_year(y, m, d)
		// support negative week numbers relative to year's last ISO week
		last_wk := iso_week_of_year(y, 12, 28)
		mut ok := false
		for wn in r.by_weekno {
			aw := if wn < 0 { last_wk + wn + 1 } else { wn }
			if aw == wk {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// recur_yearly_days enumerates all (y,m,d) in `year` satisfying the date
// BY* filters; if none of the date-narrowing BY* parts are present, the
// anchor's month/day seeds the set.
fn recur_yearly_days(r RecurRule, year i64) [][]i64 {
	mut out := [][]i64{}
	has_date_by := r.by_month.len > 0 || r.by_monthday.len > 0 || r.by_yearday.len > 0
		|| r.by_day.len > 0 || r.by_weekno.len > 0
	if !has_date_by {
		// RFC 5545 §3.3.10: a recurrence computed to an invalid date (a YEARLY
		// rule anchored on Feb 29 evaluated in a non-leap year) is IGNORED, not
		// clamped to Feb 28. Skip the year rather than emit 2025-02-29.
		if !valid_date(year, r.anchor.month, r.anchor.day) {
			return out
		}
		out << [year, r.anchor.month, r.anchor.day]
		return out
	}
	for m in 1 .. 13 {
		dim := time_days_in_month(year, m)
		for d in 1 .. (dim + 1) {
			if recur_passes_filters(r, year, m, d) {
				out << [year, i64(m), i64(d)]
			}
		}
	}
	return out
}

fn recur_monthly_days(r RecurRule, year i64, month i64) [][]i64 {
	mut out := [][]i64{}
	if r.by_month.len > 0 && month !in r.by_month {
		return out
	}
	has_day_by := r.by_monthday.len > 0 || r.by_day.len > 0 || r.by_yearday.len > 0
	if !has_day_by {
		// RFC 5545 §3.3.10: a MONTHLY rule with no BYMONTHDAY recurs on the
		// anchor's day-of-month; a month that lacks that day (the 31st in Feb/
		// Apr/Jun/Sep/Nov) is SKIPPED, NOT clamped to the month's last day. The
		// §4.1 clamp applies to calendar add-months arithmetic, never to RRULE
		// expansion — clamping here would fabricate instances RFC says to omit.
		dim := time_days_in_month(year, month)
		if r.anchor.day > dim {
			return out
		}
		out << [year, month, r.anchor.day]
		return out
	}
	dim := time_days_in_month(year, month)
	for d in 1 .. (dim + 1) {
		if recur_passes_filters(r, year, month, d) {
			out << [year, month, i64(d)]
		}
	}
	return out
}

fn recur_weekly_days(r RecurRule, base TDateTime) [][]i64 {
	mut out := [][]i64{}
	// the 7 days of the week containing `base`, starting at wkst
	base_dc := days_from_civil(base.year, base.month, base.day)
	base_wd := weekday_of(base.year, base.month, base.day)
	mut delta := base_wd - r.wkst
	if delta < 0 {
		delta += 7
	}
	week_start := base_dc - delta
	for i in 0 .. 7 {
		dc := week_start + i
		y, m, d := civil_from_days(dc)
		if r.by_day.len > 0 {
			wd := weekday_of(y, m, d)
			mut matched := false
			for bd in r.by_day {
				if bd.weekday == wd {
					matched = true
				}
			}
			if !matched {
				continue
			}
		} else {
			// no BYDAY: only the anchor weekday fires
			if weekday_of(y, m, d) != weekday_of(r.anchor.year, r.anchor.month, r.anchor.day) {
				continue
			}
		}
		if r.by_month.len > 0 && m !in r.by_month {
			continue
		}
		out << [y, m, d]
	}
	return out
}

fn recur_daily_days(r RecurRule, base TDateTime) [][]i64 {
	mut out := [][]i64{}
	if recur_passes_filters(r, base.year, base.month, base.day) {
		out << [base.year, base.month, base.day]
	}
	return out
}

// recur_advance_base steps the interval reference forward by
// freq×interval from `base` (wall-clock local).
fn recur_advance_base(r RecurRule, base TDateTime) TDateTime {
	match r.freq {
		freq_yearly {
			return TDateTime{ ...base, year: base.year + r.interval }
		}
		freq_monthly {
			total := (base.year * 12 + (base.month - 1)) + r.interval
			mut y := total / 12
			mut m := total % 12
			if m < 0 {
				m += 12
				y -= 1
			}
			m += 1
			return TDateTime{ ...base, year: y, month: m }
		}
		freq_weekly {
			dc := days_from_civil(base.year, base.month, base.day) + r.interval * 7
			y, m, d := civil_from_days(dc)
			return TDateTime{ ...base, year: y, month: m, day: d }
		}
		freq_daily {
			dc := days_from_civil(base.year, base.month, base.day) + r.interval
			y, m, d := civil_from_days(dc)
			return TDateTime{ ...base, year: y, month: m, day: d }
		}
		freq_hourly {
			ni := civil_local_to_utc(base.year, base.month, base.day, base.hour, base.minute,
				base.second, 0) + r.interval * ns_per_hour
			return dt_from_instant(ni, 0)
		}
		freq_minutely {
			ni := civil_local_to_utc(base.year, base.month, base.day, base.hour, base.minute,
				base.second, 0) + r.interval * ns_per_min
			return dt_from_instant(ni, 0)
		}
		freq_secondly {
			ni := civil_local_to_utc(base.year, base.month, base.day, base.hour, base.minute,
				base.second, 0) + r.interval * ns_per_s
			return dt_from_instant(ni, 0)
		}
		else {
			return base
		}
	}
}

// recur_fast_forward advances `base` (the interval reference) in bulk so
// that the next interval's candidates land at or just before `lo_instant`,
// without overshooting. It steps in halving jumps so it cannot skip the
// first in-window occurrence. Safe only for non-count-bounded rules.
fn recur_fast_forward(r RecurRule, base0 TDateTime, anchor_instant i64, lo_instant i64) TDateTime {
	mut base := base0
	// approximate ns per interval to size the initial jump
	per := recur_interval_ns(r)
	if per <= 0 || lo_instant <= anchor_instant {
		return base
	}
	mut jump := (lo_instant - anchor_instant) / per - 2
	for jump > 0 {
		mut probe := base
		mut k := i64(0)
		for k < jump {
			probe = recur_advance_base(r, probe)
			k++
		}
		probe_inst := recur_local_to_instant(r.tz, probe)
		if probe_inst < lo_instant {
			base = probe
		} else {
			jump /= 2
		}
	}
	return base
}

// recur_interval_ns is the nominal length of one freq×interval step.
fn recur_interval_ns(r RecurRule) i64 {
	base := match r.freq {
		freq_yearly { i64(365) * ns_per_day }
		freq_monthly { i64(30) * ns_per_day }
		freq_weekly { i64(7) * ns_per_day }
		freq_daily { ns_per_day }
		freq_hourly { ns_per_hour }
		freq_minutely { ns_per_min }
		freq_secondly { ns_per_s }
		else { ns_per_day }
	}
	return base * r.interval
}

// recur_expand walks the rule from the anchor and returns occurrences in
// ascending order. Stops when:
//   - `hi_instant` > 0 and a candidate's instant ≥ hi_instant (window cap), or
//   - `max_results` > 0 and that many results gathered (then keeps the cap), or
//   - the rule's own count / until bound is reached, or
//   - the per-interval budget is exhausted (sets hit_budget=true).
// Returns (results, hit_budget). hit_budget=true only for non-naturally-
// terminating (infinite, uncapped) scans — the caller maps it to CXER3325.
fn recur_expand(r RecurRule, hi_instant i64, max_results int) ([]RecurCandidate, bool, bool) {
	return recur_expand_from(r, 0, hi_instant, max_results)
}

// recur_expand_from is recur_expand with an optional `lo_instant`
// fast-forward. When lo_instant > 0 and the rule is NOT count-bounded
// (count counts from the anchor, so it must walk from there), the base is
// advanced in bulk to within one interval of lo_instant before scanning.
// This keeps cron / unbounded rules anchored at a far-past seed (e.g.
// 1970) from exhausting the per-interval budget.
fn recur_expand_from(r RecurRule, lo_instant i64, hi_instant i64, max_results int) ([]RecurCandidate, bool, bool) {
	mut out := []RecurCandidate{}
	mut base := r.anchor
	mut produced := i64(0)
	mut budget := i64(0)
	anchor_instant := recur_local_to_instant(r.tz, r.anchor)
	until_instant := if r.has_until { recur_local_to_instant(r.tz, r.until) } else { i64(0) }
	if lo_instant > 0 && !r.has_count {
		base = recur_fast_forward(r, base, anchor_instant, lo_instant)
	}
	for {
		// Stop before walking into the unrepresentable instant range: past
		// ≈2262-04 the ns conversion wraps and every comparison below is
		// garbage. Signal overflow so the caller raises CXER3304 rather than
		// returning a bogus occurrence (or silently nothing).
		if dt_instant_overflows(base) {
			return out, false, true
		}
		budget++
		if budget > recur_max_occurrences {
			return out, true, false
		}
		cands := recur_candidates_for_interval(r, base)
		mut resolved := []RecurCandidate{}
		for c in cands {
			inst := recur_local_to_instant(r.tz, c)
			resolved << RecurCandidate{ dt: c, instant: inst }
		}
		// BYSETPOS selects from the sorted candidate set of this interval
		mut selected := resolved.clone()
		if r.by_setpos.len > 0 {
			selected = []RecurCandidate{}
			for sp in r.by_setpos {
				idx := if sp < 0 { resolved.len + int(sp) } else { int(sp) - 1 }
				if idx >= 0 && idx < resolved.len {
					selected << resolved[idx]
				}
			}
			selected.sort_with_compare(fn (a &RecurCandidate, b &RecurCandidate) int {
				if a.instant < b.instant { return -1 }
				if a.instant > b.instant { return 1 }
				return 0
			})
		}
		for c in selected {
			if c.instant < anchor_instant {
				continue
			}
			if r.has_until && c.instant > until_instant {
				return out, false, false
			}
			if hi_instant > 0 && c.instant >= hi_instant {
				return out, false, false
			}
			out << c
			produced++
			if r.has_count && produced >= r.count {
				return out, false, false
			}
			if max_results > 0 && out.len >= max_results {
				return out, false, false
			}
		}
		base = recur_advance_base(r, base)
	}
	return out, false, false
}

// ── RRULE string parse / format ──────────────────────────────────────

fn recur_parse_rrule_to_element(s string, anchor cx.Node, tz string, opts cx.Node) cx.Node {
	anchor_dt := decode_datetime(anchor) or {
		return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: bad anchor')
	}
	mut body := s.trim_space()
	if body.to_upper().starts_with('RRULE:') {
		body = body[6..]
	}
	mut freq_atom := ''
	mut interval := i64(1)
	mut count := i64(0)
	mut has_count := false
	mut until := ''
	mut by_second := []i64{}
	mut by_minute := []i64{}
	mut by_hour := []i64{}
	mut by_day_items := []cx.Node{}
	mut by_monthday := []i64{}
	mut by_yearday := []i64{}
	mut by_weekno := []i64{}
	mut by_month := []i64{}
	mut by_setpos := []i64{}
	mut wkst := ''
	for part in body.split(';') {
		if part.trim_space() == '' {
			continue
		}
		kv := part.split_nth('=', 2)
		if kv.len != 2 {
			return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: ${part}')
		}
		key := kv[0].trim_space().to_upper()
		val := kv[1].trim_space()
		match key {
			'FREQ' {
				f := recur_freq_from_rrule(val.to_upper()) or {
					return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: FREQ=${val}')
				}
				freq_atom = recur_freq_to_atom(f)
			}
			'INTERVAL' {
				interval = val.i64()
				if interval < 1 {
					return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: INTERVAL')
				}
			}
			'COUNT' {
				has_count = true
				count = val.i64()
			}
			'UNTIL' {
				until = recur_rrule_until_to_iso(val) or {
					return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: UNTIL=${val}')
				}
			}
			'WKST' {
				wd := recur_weekday_from_rrule(val.to_upper()) or {
					return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: WKST=${val}')
				}
				wkst = recur_weekday_atoms[wd]
			}
			'BYSECOND' { by_second = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYSECOND') } }
			'BYMINUTE' { by_minute = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYMINUTE') } }
			'BYHOUR' { by_hour = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYHOUR') } }
			'BYMONTHDAY' { by_monthday = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYMONTHDAY') } }
			'BYYEARDAY' { by_yearday = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYYEARDAY') } }
			'BYWEEKNO' { by_weekno = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYWEEKNO') } }
			'BYMONTH' { by_month = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYMONTH') } }
			'BYSETPOS' { by_setpos = recur_csv_ints(val) or {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYSETPOS') } }
			'BYDAY' {
				by_day_items = recur_parse_rrule_byday(val) or {
					return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: BYDAY=${val}')
				}
			}
			else {
				return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: unknown ${key}')
			}
		}
	}
	if freq_atom == '' {
		return time_err('cx-err:CXER3320', 'E_TIME_RRULE_MALFORMED: missing FREQ')
	}
	// build the [recurrence] element, then validate it (reuses CXER3322/3323)
	mut attrs := [
		recur_atom_attr('freq', freq_atom),
	]
	if interval != 1 {
		attrs << time_int_attr('interval', interval)
	}
	attrs << recur_str_attr('anchor', anchor_dt.datetime_string())
	attrs << recur_str_attr('tz', tz)
	if wkst != '' {
		attrs << recur_atom_attr('wkst', wkst)
	}
	if has_count {
		attrs << time_int_attr('count', count)
	}
	if until != '' {
		attrs << recur_str_attr('until', until)
	}
	mut items := []cx.Node{}
	recur_add_int_child(mut items, 'by-second', by_second)
	recur_add_int_child(mut items, 'by-minute', by_minute)
	recur_add_int_child(mut items, 'by-hour', by_hour)
	if by_day_items.len > 0 {
		items << cx.Element{ name: 'by-day', items: by_day_items }
	}
	recur_add_int_child(mut items, 'by-month-day', by_monthday)
	recur_add_int_child(mut items, 'by-year-day', by_yearday)
	recur_add_int_child(mut items, 'by-week-no', by_weekno)
	recur_add_int_child(mut items, 'by-month', by_month)
	recur_add_int_child(mut items, 'by-set-pos', by_setpos)
	el := cx.Element{ name: 'recurrence', attrs: attrs, items: items }
	// validate (maps malformed combos to CXER3322/3323)
	recur_rule_from(el) or {
		return recur_error_node(err.msg())
	}
	return el
}

fn recur_rrule_until_to_iso(v string) ?string {
	// RFC 5545 UNTIL is a DATE or DATE-TIME (often basic form YYYYMMDDTHHMMSSZ)
	if v.len == 8 {
		// YYYYMMDD
		y := v[0..4].i64()
		m := v[4..6].i64()
		d := v[6..8].i64()
		if !valid_date(y, m, d) {
			return none
		}
		return TDateTime{ year: y, month: m, day: d }.date_string()
	}
	if v.len >= 15 && (v[8] == `T` || v[8] == `t`) {
		y := v[0..4].i64()
		m := v[4..6].i64()
		d := v[6..8].i64()
		h := v[9..11].i64()
		mi := v[11..13].i64()
		s := v[13..15].i64()
		if !valid_date(y, m, d) || !valid_time_of_day(h, mi, s) {
			return none
		}
		// drop trailing Z; UNTIL is interpreted wall-clock-local per our model
		return TDateTime{ year: y, month: m, day: d, hour: h, minute: mi, second: s }.datetime_string()
	}
	// extended ISO form
	if dt := parse_datetime_iso(v) {
		return TDateTime{ ...dt, offset: 0 }.datetime_string()
	}
	if dt := parse_date_iso(v) {
		return dt.date_string()
	}
	return none
}

fn recur_csv_ints(v string) ?[]i64 {
	mut out := []i64{}
	for tok in v.split(',') {
		t := tok.trim_space()
		if t == '' {
			return none
		}
		mut i := 0
		if t[0] == `+` || t[0] == `-` {
			i = 1
		}
		if i >= t.len {
			return none
		}
		for j in i .. t.len {
			if t[j] < `0` || t[j] > `9` {
				return none
			}
		}
		out << t.i64()
	}
	return out
}

fn recur_parse_rrule_byday(v string) ?[]cx.Node {
	mut out := []cx.Node{}
	for tok in v.split(',') {
		t := tok.trim_space()
		if t.len < 2 {
			return none
		}
		// optional leading ordinal (±N) then 2-letter weekday
		mut i := 0
		mut sign := i64(1)
		if t[i] == `+` {
			i++
		} else if t[i] == `-` {
			sign = -1
			i++
		}
		mut ord := i64(0)
		mut has_ord := false
		for i < t.len && t[i] >= `0` && t[i] <= `9` {
			ord = ord * 10 + i64(t[i] - `0`)
			has_ord = true
			i++
		}
		wd_str := t[i..].to_upper()
		wd := recur_weekday_from_rrule(wd_str) or { return none }
		if has_ord {
			out << cx.Element{
				name: 'nth'
				items: [
					time_int(sign * ord),
					time_atom(recur_weekday_atoms[wd]),
				]
			}
		} else {
			out << time_atom(recur_weekday_atoms[wd])
		}
	}
	return out
}

fn recur_format_rrule(r RecurRule) string {
	mut parts := ['FREQ=${recur_freq_to_rrule(r.freq)}']
	if r.interval != 1 {
		parts << 'INTERVAL=${r.interval}'
	}
	if r.has_count {
		parts << 'COUNT=${r.count}'
	}
	if r.has_until {
		u := r.until
		parts << 'UNTIL=${pad4(u.year)}${pad2(u.month)}${pad2(u.day)}T${pad2(u.hour)}${pad2(u.minute)}${pad2(u.second)}Z'
	}
	// WKST only emitted when non-default (MO)
	if r.wkst != 1 {
		parts << 'WKST=${recur_weekday_rrule[r.wkst]}'
	}
	if r.by_month.len > 0 {
		parts << 'BYMONTH=' + recur_ints_csv(r.by_month)
	}
	if r.by_weekno.len > 0 {
		parts << 'BYWEEKNO=' + recur_ints_csv(r.by_weekno)
	}
	if r.by_yearday.len > 0 {
		parts << 'BYYEARDAY=' + recur_ints_csv(r.by_yearday)
	}
	if r.by_monthday.len > 0 {
		parts << 'BYMONTHDAY=' + recur_ints_csv(r.by_monthday)
	}
	if r.by_day.len > 0 {
		mut ds := []string{}
		for bd in r.by_day {
			if bd.ord == 0 {
				ds << recur_weekday_rrule[bd.weekday]
			} else {
				ds << '${bd.ord}${recur_weekday_rrule[bd.weekday]}'
			}
		}
		parts << 'BYDAY=' + ds.join(',')
	}
	if r.by_hour.len > 0 {
		parts << 'BYHOUR=' + recur_ints_csv(r.by_hour)
	}
	if r.by_minute.len > 0 {
		parts << 'BYMINUTE=' + recur_ints_csv(r.by_minute)
	}
	if r.by_second.len > 0 {
		parts << 'BYSECOND=' + recur_ints_csv(r.by_second)
	}
	if r.by_setpos.len > 0 {
		parts << 'BYSETPOS=' + recur_ints_csv(r.by_setpos)
	}
	return parts.join(';')
}

fn recur_ints_csv(xs []i64) string {
	mut out := []string{}
	for x in xs {
		out << x.str()
	}
	return out.join(',')
}

// ── cron parse / format ──────────────────────────────────────────────
//
// 5-field: minute hour day-of-month month day-of-week
// 6-field: second minute hour day-of-month month day-of-week
// @macros: @yearly/@annually @monthly @weekly @daily/@midnight @hourly

fn recur_parse_cron_to_element(s string, tz string, opts cx.Node) cx.Node {
	body := s.trim_space()
	if body == '' {
		return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: empty')
	}
	mut fields := []string{}
	if body.starts_with('@') {
		fields = recur_cron_macro(body) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: unknown macro ${body}')
		}
	} else {
		fields = body.split(' ').filter(it != '')
	}
	mut sec_f := ''
	mut has_sec := false
	mut min_f := ''
	mut hr_f := ''
	mut dom_f := ''
	mut mon_f := ''
	mut dow_f := ''
	if fields.len == 5 {
		min_f, hr_f, dom_f, mon_f, dow_f = fields[0], fields[1], fields[2], fields[3], fields[4]
	} else if fields.len == 6 {
		has_sec = true
		sec_f, min_f, hr_f, dom_f, mon_f, dow_f = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
	} else {
		return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: expected 5 or 6 fields, got ${fields.len}')
	}
	by_second := if has_sec {
		recur_cron_field(sec_f, 0, 59) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: second ${sec_f}')
		}
	} else {
		[]i64{}
	}
	min_star := min_f == '*'
	hour_star := hr_f == '*'
	by_minute := if min_star { []i64{} } else {
		recur_cron_field(min_f, 0, 59) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: minute ${min_f}')
		}
	}
	by_hour := if hour_star { []i64{} } else {
		recur_cron_field(hr_f, 0, 23) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: hour ${hr_f}')
		}
	}
	dom_star := dom_f == '*'
	mon_star := mon_f == '*'
	dow_star := dow_f == '*'
	by_monthday := if dom_star { []i64{} } else {
		recur_cron_field(dom_f, 1, 31) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: day-of-month ${dom_f}')
		}
	}
	by_month := if mon_star { []i64{} } else {
		recur_cron_field(mon_f, 1, 12) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: month ${mon_f}')
		}
	}
	dow_vals := if dow_star { []i64{} } else {
		recur_cron_field(dow_f, 0, 7) or {
			return time_err('cx-err:CXER3321', 'E_TIME_CRON_MALFORMED: day-of-week ${dow_f}')
		}
	}
	// cron freq: pick the finest unconstrained time grain so unconstrained
	// (`*`) minute/hour fields expand naturally; dom/mon/dow restrictions
	// ride along as BY* filters (valid under any sub-daily/daily freq). A
	// fully time-fixed cron (minute+hour given) is DAILY-grade.
	mut freq := freq_daily
	if min_star {
		freq = freq_minutely
	} else if hour_star {
		freq = freq_hourly
	}
	// build the element
	mut attrs := [recur_atom_attr('freq', recur_freq_to_atom(freq))]
	// anchor: cron has no anchor; seed at epoch midnight wall-clock so the
	// time-of-day comes entirely from BY* parts. Use a neutral 1970 anchor.
	attrs << recur_str_attr('anchor', '1970-01-01T00:00:00')
	attrs << recur_str_attr('tz', tz)
	mut items := []cx.Node{}
	recur_add_int_child(mut items, 'by-second', by_second)
	recur_add_int_child(mut items, 'by-minute', by_minute)
	recur_add_int_child(mut items, 'by-hour', by_hour)
	if dow_vals.len > 0 {
		mut day_items := []cx.Node{}
		for dv in dow_vals {
			// cron: 0 and 7 are both Sunday → civil 0
			civ := if dv == 7 { i64(0) } else { dv }
			day_items << time_atom(recur_weekday_atoms[civ])
		}
		items << cx.Element{ name: 'by-day', items: day_items }
	}
	recur_add_int_child(mut items, 'by-month-day', by_monthday)
	recur_add_int_child(mut items, 'by-month', by_month)
	el := cx.Element{ name: 'recurrence', attrs: attrs, items: items }
	recur_rule_from(el) or {
		return recur_error_node(err.msg())
	}
	return el
}

fn recur_cron_macro(m string) ?[]string {
	return match m {
		'@yearly', '@annually' { ['0', '0', '1', '1', '*'] }
		'@monthly' { ['0', '0', '1', '*', '*'] }
		'@weekly' { ['0', '0', '*', '*', '0'] }
		'@daily', '@midnight' { ['0', '0', '*', '*', '*'] }
		'@hourly' { ['0', '*', '*', '*', '*'] }
		else { none }
	}
}

// recur_cron_field parses a single cron field into a sorted, de-duplicated
// value list. Supports *, N, N-M ranges, */S steps, N-M/S, and comma lists.
fn recur_cron_field(f string, lo int, hi int) ?[]i64 {
	mut set := map[i64]bool{}
	for tok in f.split(',') {
		t := tok.trim_space()
		if t == '' {
			return none
		}
		mut range_part := t
		mut step := 1
		if t.contains('/') {
			sp := t.split('/')
			if sp.len != 2 {
				return none
			}
			range_part = sp[0]
			step = sp[1].int()
			if step < 1 {
				return none
			}
		}
		mut rlo := lo
		mut rhi := hi
		if range_part == '*' {
			// full range
		} else if range_part.contains('-') {
			rp := range_part.split('-')
			if rp.len != 2 {
				return none
			}
			rlo = rp[0].int()
			rhi = rp[1].int()
		} else {
			v := recur_cron_int(range_part) or { return none }
			rlo = v
			rhi = if t.contains('/') { hi } else { v }
		}
		if rlo < lo || rhi > hi || rlo > rhi {
			return none
		}
		mut v := rlo
		for v <= rhi {
			set[i64(v)] = true
			v += step
		}
	}
	mut out := set.keys()
	out.sort()
	return out
}

fn recur_cron_int(s string) ?int {
	if s == '' {
		return none
	}
	for c in s {
		if c < `0` || c > `9` {
			return none
		}
	}
	return s.int()
}

// recur_format_cron renders a cron-expressible rule. Raises CXER3324 for
// anything cron cannot express.
fn recur_format_cron(r RecurRule) cx.Node {
	if r.interval > 1 {
		return time_err('cx-err:CXER3324', 'E_TIME_CRON_INEXPRESSIBLE: interval>1')
	}
	if r.by_setpos.len > 0 {
		return time_err('cx-err:CXER3324', 'E_TIME_CRON_INEXPRESSIBLE: by-set-pos')
	}
	if r.has_count || r.has_until {
		return time_err('cx-err:CXER3324', 'E_TIME_CRON_INEXPRESSIBLE: count/until')
	}
	if r.by_yearday.len > 0 || r.by_weekno.len > 0 {
		return time_err('cx-err:CXER3324', 'E_TIME_CRON_INEXPRESSIBLE: by-year-day/by-week-no')
	}
	for bd in r.by_day {
		if bd.ord != 0 {
			return time_err('cx-err:CXER3324', 'E_TIME_CRON_INEXPRESSIBLE: ordinal by-day')
		}
	}
	// minute / hour fields. A sub-daily frequency wildcards the finer fields:
	// FREQ=HOURLY → hour `*` (fire every hour at the anchor minute); MINUTELY →
	// minute + hour `*`; SECONDLY → second + minute + hour `*`. The prior code
	// emitted the anchor's hour/minute unconditionally, silently collapsing
	// HOURLY/MINUTELY rules to a once-a-day cron (CXER §4.1 cron mapping).
	sub_minute := r.freq == freq_secondly
	sub_hour := r.freq == freq_minutely || sub_minute
	sub_day := r.freq == freq_hourly || sub_hour
	min_field := if r.by_minute.len > 0 {
		recur_ints_csv(sorted_i64(r.by_minute))
	} else if sub_hour {
		'*'
	} else {
		r.anchor.minute.str()
	}
	hr_field := if r.by_hour.len > 0 {
		recur_ints_csv(sorted_i64(r.by_hour))
	} else if sub_day {
		'*'
	} else {
		r.anchor.hour.str()
	}
	dom_field := if r.by_monthday.len > 0 { recur_ints_csv(sorted_i64(r.by_monthday)) } else { '*' }
	mon_field := if r.by_month.len > 0 { recur_ints_csv(sorted_i64(r.by_month)) } else { '*' }
	mut dow_field := '*'
	if r.by_day.len > 0 {
		mut ds := []i64{}
		for bd in r.by_day {
			ds << bd.weekday
		}
		dow_field = recur_ints_csv(sorted_i64(ds))
	}
	if r.by_second.len > 0 || sub_minute {
		sec_field := if r.by_second.len > 0 {
			recur_ints_csv(sorted_i64(r.by_second))
		} else {
			'*'
		}
		return time_str('${sec_field} ${min_field} ${hr_field} ${dom_field} ${mon_field} ${dow_field}')
	}
	return time_str('${min_field} ${hr_field} ${dom_field} ${mon_field} ${dow_field}')
}

fn sorted_i64(xs []i64) []i64 {
	mut out := xs.clone()
	out.sort()
	return out
}

// ── element-build helpers ────────────────────────────────────────────

fn recur_atom_attr(name string, v string) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(v), cx.AttributeMeta{ data_type: ?string('atom') })
}

fn recur_str_attr(name string, v string) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(v), cx.AttributeMeta{ data_type: ?string(none) })
}

fn recur_add_int_child(mut items []cx.Node, name string, vals []i64) {
	if vals.len == 0 {
		return
	}
	mut kids := []cx.Node{}
	for v in vals {
		kids << time_int(v)
	}
	items << cx.Element{ name: name, items: kids }
}

// recur_error_node maps a "CXERxxxx|message" error string into an err node.
fn recur_error_node(m string) cx.Node {
	if idx := m.index('|') {
		ecode := m[..idx]
		msg := m[idx + 1..]
		return time_err('cx-err:${ecode}', msg)
	}
	return time_err('cx-err:CXER3322', 'E_TIME_RULE_FIELD_INVALID: ${m}')
}

// recur_validate_to_node runs the validator over a rule node, returning
// the parsed err node on fault or none on success.
fn recur_validate_node(n cx.Node) ?cx.Node {
	recur_rule_from(n) or {
		return recur_error_node(err.msg())
	}
	return none
}

// ── dispatch table ───────────────────────────────────────────────────

// time_clock_prims lives in effect_alignment.v — I4: profile-invariant
// purity data, outside this `-d cx_no_pack_time`-gated file.

pub fn time_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if name in time_clock_prims {
		if d := cap_guard('clock', name) {
			return d
		}
	}
	match name {
		'time-now' {
			n := vtime.utc()
			return time_datetime_node(dt_from_instant(n.unix_nano(), 0).datetime_string())
		}
		'time-today' {
			n := vtime.utc()
			return time_date_node(dt_from_instant(n.unix_nano(), 0).date_string())
		}
		'time-instant-now' {
			n := vtime.utc()
			return time_int(n.unix_nano())
		}
		'time-monotonic-now' {
			return time_int(i64(vtime.sys_mono_now()))
		}
		'time-utc-now' {
			n := vtime.utc()
			return time_datetime_node(dt_from_instant(n.unix_nano(), 0).datetime_string())
		}
		'time-system-timezone' {
			return time_str('UTC')
		}
		'time-now-mock' {
			s := time_arg_str(args[0]) or { return none }
			return time_datetime_node(s)
		}
		'time-today-mock' {
			s := time_arg_str(args[0]) or { return none }
			return time_date_node(s)
		}
		'time-instant-now-mock' {
			i := time_arg_int(args[0]) or { return none }
			return time_int(i)
		}
		'time-mock-advance' {
			return time_null()
		}
		'time-mock-set' {
			return time_null()
		}
		'time-date' {
			y := time_arg_int(args[0]) or { return none }
			m := time_arg_int(args[1]) or { return none }
			d := time_arg_int(args[2]) or { return none }
			if !valid_date(y, m, d) {
				return time_err('cx-err:CXER3300', 'E_TIME_INVALID_COMPONENT: ${y}-${m}-${d}')
			}
			return time_date_node(TDateTime{ year: y, month: m, day: d }.date_string())
		}
		'time-datetime' {
			y := time_arg_int(args[0]) or { return none }
			m := time_arg_int(args[1]) or { return none }
			d := time_arg_int(args[2]) or { return none }
			h := time_arg_int(args[3]) or { return none }
			mi := time_arg_int(args[4]) or { return none }
			s := time_arg_int(args[5]) or { return none }
			if !valid_date(y, m, d) || !valid_time_of_day(h, mi, s) {
				return time_err('cx-err:CXER3300', 'E_TIME_INVALID_COMPONENT')
			}
			return time_datetime_node(TDateTime{ year: y, month: m, day: d, hour: h,
				minute: mi, second: s, offset: 0 }.datetime_string())
		}
		'time-datetime-with-tz' {
			y := time_arg_int(args[0]) or { return none }
			m := time_arg_int(args[1]) or { return none }
			d := time_arg_int(args[2]) or { return none }
			h := time_arg_int(args[3]) or { return none }
			mi := time_arg_int(args[4]) or { return none }
			s := time_arg_int(args[5]) or { return none }
			tz := time_arg_str(args[6]) or { return none }
			if !valid_date(y, m, d) || !valid_time_of_day(h, mi, s) {
				return time_err('cx-err:CXER3300', 'E_TIME_INVALID_COMPONENT')
			}
			rule := lookup_tz(tz) or {
				return time_err('cx-err:CXER3302', 'E_TIME_UNKNOWN_TIMEZONE: ${tz}')
			}
			mut guess := civil_local_to_utc(y, m, d, h, mi, s, rule.std_offset)
			off := tz_offset_for(rule, guess)
			guess = civil_local_to_utc(y, m, d, h, mi, s, off)
			off2 := tz_offset_for(rule, guess)
			return time_datetime_node(TDateTime{ year: y, month: m, day: d, hour: h,
				minute: mi, second: s, offset: off2 }.datetime_string())
		}
		'time-from-unix' {
			secs := time_arg_int(args[0]) or { return none }
			return time_int(secs * ns_per_s)
		}
		'time-from-unix-ms' {
			ms := time_arg_int(args[0]) or { return none }
			return time_int(ms * ns_per_ms)
		}
		'time-from-unix-ns' {
			ns := time_arg_int(args[0]) or { return none }
			return time_int(ns)
		}
		'time-epoch' {
			return time_int(0)
		}
		'time-year' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			return time_int(dt.year)
		}
		'time-month' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			return time_int(dt.month)
		}
		'time-day' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			return time_int(dt.day)
		}
		'time-hour' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.hour)
		}
		'time-minute' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.minute)
		}
		'time-second' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.second)
		}
		'time-nanosecond' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.nanos)
		}
		'time-weekday' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			wd := weekday_of(dt.year, dt.month, dt.day)
			return time_atom(weekday_atoms[int(wd)])
		}
		'time-day-of-year' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			doy := days_from_civil(dt.year, dt.month, dt.day) - days_from_civil(dt.year, 1, 1) + 1
			return time_int(doy)
		}
		'time-week-of-year' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			return time_int(iso_week_of_year(dt.year, dt.month, dt.day))
		}
		'time-timezone-offset' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.offset)
		}
		'time-to-unix' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.instant_ns() / ns_per_s)
		}
		'time-to-unix-ms' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.instant_ns() / ns_per_ms)
		}
		'time-to-unix-ns' {
			dt := decode_datetime(args[0]) or { return none }
			return time_int(dt.instant_ns())
		}
		'time-add' {
			return time_add_duration(args[0], args[1], 1)
		}
		'time-subtract' {
			return time_add_duration(args[0], args[1], -1)
		}
		'time-diff' {
			a := decode_any_instant(args[0]) or { return none }
			b := decode_any_instant(args[1]) or { return none }
			return time_int(a - b)
		}
		'time-add-days' {
			dt := decode_date(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			y, m, d := civil_from_days(days_from_civil(dt.year, dt.month, dt.day) + n)
			return time_date_node(TDateTime{ year: y, month: m, day: d }.date_string())
		}
		'time-add-months' {
			dt := decode_date(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			return add_months_clamp(dt, n, false)
		}
		'time-add-months-strict' {
			dt := decode_date(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			return add_months_clamp(dt, n, true)
		}
		'time-add-years' {
			dt := decode_date(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			return add_months_clamp(dt, n * 12, false)
		}
		'time-add-hours' {
			dt := decode_datetime(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			ni := dt.instant_ns() + n * ns_per_hour
			return time_datetime_node(dt_from_instant(ni, dt.offset).datetime_string())
		}
		'time-add-minutes' {
			dt := decode_datetime(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			ni := dt.instant_ns() + n * ns_per_min
			return time_datetime_node(dt_from_instant(ni, dt.offset).datetime_string())
		}
		'time-add-seconds' {
			dt := decode_datetime(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			ni := dt.instant_ns() + n * ns_per_s
			return time_datetime_node(dt_from_instant(ni, dt.offset).datetime_string())
		}
		'time-duration-ms' {
			v := time_arg_int(args[0]) or { return none }
			return time_int(v * ns_per_ms)
		}
		'time-duration-s' {
			v := time_arg_int(args[0]) or { return none }
			return time_int(v * ns_per_s)
		}
		'time-duration-m' {
			v := time_arg_int(args[0]) or { return none }
			return time_int(v * ns_per_min)
		}
		'time-duration-h' {
			v := time_arg_int(args[0]) or { return none }
			return time_int(v * ns_per_hour)
		}
		'time-duration-d' {
			v := time_arg_int(args[0]) or { return none }
			return time_int(v * ns_per_day)
		}
		'time-duration-parts' {
			ns := time_arg_int(args[0]) or { return none }
			return duration_parts_element(ns)
		}
		'time-duration-total-ms' {
			ns := time_arg_int(args[0]) or { return none }
			return time_int(ns / ns_per_ms)
		}
		'time-duration-total-s' {
			ns := time_arg_int(args[0]) or { return none }
			return time_int(ns / ns_per_s)
		}
		'time-duration-total-h' {
			ns := time_arg_int(args[0]) or { return none }
			return time_float(f64(ns) / f64(ns_per_hour))
		}
		'time-duration-add' {
			a := time_arg_int(args[0]) or { return none }
			b := time_arg_int(args[1]) or { return none }
			return time_int(a + b)
		}
		'time-duration-sub' {
			a := time_arg_int(args[0]) or { return none }
			b := time_arg_int(args[1]) or { return none }
			return time_int(a - b)
		}
		'time-duration-mul' {
			a := time_arg_int(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			return time_int(a * n)
		}
		'time-duration-div' {
			a := time_arg_int(args[0]) or { return none }
			n := time_arg_int(args[1]) or { return none }
			if n == 0 {
				return time_err('cx-err:CXER3304', 'E_TIME_DURATION_OVERFLOW: divide by zero')
			}
			return time_int(a / n)
		}
		'time-parse-date' {
			s := time_arg_str(args[0]) or { return none }
			dt := parse_date_iso(s) or {
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_date_node(dt.date_string())
		}
		'time-parse-datetime' {
			s := time_arg_str(args[0]) or { return none }
			dt := parse_datetime_iso(s) or {
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_datetime_node(dt.datetime_string())
		}
		'time-parse-instant' {
			s := time_arg_str(args[0]) or { return none }
			dt := parse_datetime_iso(s) or {
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_int(dt.instant_ns())
		}
		'time-parse-duration' {
			s := time_arg_str(args[0]) or { return none }
			ns := parse_duration_str(s) or {
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_int(ns)
		}
		'time-parse-rfc3339' {
			s := time_arg_str(args[0]) or { return none }
			dt := parse_datetime_iso(s) or {
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_datetime_node(dt.datetime_string())
		}
		'time-parse-rfc2822' {
			s := time_arg_str(args[0]) or { return none }
			dt := parse_rfc2822_str(s) or {
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_datetime_node(dt.datetime_string())
		}
		'time-parse-with-format' {
			s := time_arg_str(args[0]) or { return none }
			fmtp := time_arg_str(args[1]) or { return none }
			res := parse_ldml(s, fmtp) or {
				if err.msg() == 'unknown-token' {
					return time_err('cx-err:CXER3303', 'E_TIME_FORMAT_TOKEN_UNKNOWN: ${fmtp}')
				}
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_datetime_node(res.datetime_string())
		}
		'time-parse-strftime' {
			s := time_arg_str(args[0]) or { return none }
			fmtp := time_arg_str(args[1]) or { return none }
			res := parse_strftime(s, fmtp) or {
				if err.msg() == 'unknown-token' {
					return time_err('cx-err:CXER3303', 'E_TIME_FORMAT_TOKEN_UNKNOWN: ${fmtp}')
				}
				return time_err('cx-err:CXER3301', 'E_TIME_PARSE_MALFORMED: ${s}')
			}
			return time_datetime_node(res.datetime_string())
		}
		'time-format-iso8601' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			dtype := time_arg_type(args[0]) or { return none }
			if dtype == cx.ScalarType.date_type {
				return time_str(dt.date_string())
			}
			return time_str(dt.datetime_string())
		}
		'time-format-rfc3339' {
			dt := decode_datetime(args[0]) or { return none }
			return time_str(dt.datetime_string())
		}
		'time-format-rfc2822' {
			dt := decode_datetime(args[0]) or { return none }
			return time_str(format_rfc2822(dt))
		}
		'time-format-with-format' {
			dt := decode_date_or_datetime(args[0]) or { return none }
			fmtp := time_arg_str(args[1]) or { return none }
			out := format_ldml(dt, fmtp) or {
				return time_err('cx-err:CXER3303', 'E_TIME_FORMAT_TOKEN_UNKNOWN: ${fmtp}')
			}
			return time_str(out)
		}
		'time-format-duration' {
			ns := time_arg_int(args[0]) or { return none }
			return time_str(format_duration_canonical(ns))
		}
		'time-format-relative' {
			dt := decode_datetime(args[0]) or { return none }
			now_dt := decode_datetime(args[1]) or { return none }
			return time_str(format_relative(dt.instant_ns(), now_dt.instant_ns()))
		}
		'time-timezone' {
			nm := time_arg_str(args[0]) or { return none }
			rule := lookup_tz(nm) or {
				return time_err('cx-err:CXER3302', 'E_TIME_UNKNOWN_TIMEZONE: ${nm}')
			}
			return timezone_element(rule)
		}
		'time-to-timezone' {
			dt := decode_datetime(args[0]) or { return none }
			tz := time_arg_str(args[1]) or { return none }
			rule := lookup_tz(tz) or {
				return time_err('cx-err:CXER3302', 'E_TIME_UNKNOWN_TIMEZONE: ${tz}')
			}
			instant := dt.instant_ns()
			off := tz_offset_for(rule, instant)
			return time_datetime_node(dt_from_instant(instant, off).datetime_string())
		}
		'time-to-utc' {
			dt := decode_datetime(args[0]) or { return none }
			return time_datetime_node(dt_from_instant(dt.instant_ns(), 0).datetime_string())
		}
		'time-list-timezones' {
			mut items := []cx.Node{cap: tz_rules.len}
			for r in tz_rules {
				items << time_str(r.name)
			}
			return time_seq(items)
		}
		'time-is-leap-year' {
			y := time_arg_int(args[0]) or { return none }
			return time_bool(time_is_leap(y))
		}
		'time-is-before' {
			a := decode_any_instant(args[0]) or { return none }
			b := decode_any_instant(args[1]) or { return none }
			return time_bool(a < b)
		}
		'time-is-after' {
			a := decode_any_instant(args[0]) or { return none }
			b := decode_any_instant(args[1]) or { return none }
			return time_bool(a > b)
		}
		'time-is-same' {
			a := decode_any_instant(args[0]) or { return none }
			b := decode_any_instant(args[1]) or { return none }
			return time_bool(a == b)
		}
		'time-is-same-day' {
			a := decode_datetime(args[0]) or { return none }
			b := decode_datetime(args[1]) or { return none }
			return time_bool(a.year == b.year && a.month == b.month && a.day == b.day)
		}
		'time-days-in-month' {
			y := time_arg_int(args[0]) or { return none }
			m := time_arg_int(args[1]) or { return none }
			if m < 1 || m > 12 {
				return time_err('cx-err:CXER3300', 'E_TIME_INVALID_COMPONENT: month ${m}')
			}
			return time_int(time_days_in_month(y, m))
		}
		// ── §3.10 recurrence ──────────────────────────────────────────
		'time-recurrence' {
			return time_recurrence_build(args)
		}
		'time-validate-rule' {
			if e := recur_validate_node(args[0]) {
				return e
			}
			return args[0]
		}
		'time-is-valid-rule' {
			if _ := recur_validate_node(args[0]) {
				return time_bool(false)
			}
			return time_bool(true)
		}
		'time-parse-rrule' {
			s := time_arg_str(args[0]) or { return none }
			tz := time_arg_str(args[2]) or { return none }
			return recur_parse_rrule_to_element(s, args[1], tz, args[3])
		}
		'time-format-rrule' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			return time_str(recur_format_rrule(rule))
		}
		'time-parse-cron' {
			s := time_arg_str(args[0]) or { return none }
			tz := time_arg_str(args[1]) or { return none }
			return recur_parse_cron_to_element(s, tz, args[2])
		}
		'time-format-cron' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			return recur_format_cron(rule)
		}
		'time-next-occurrence' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			after := decode_datetime(args[1]) or { return none }
			after_instant := recur_local_to_instant(rule.tz, after)
			// fast-forward to just before `after`, then take the first
			// candidate strictly greater. The cap bounds the scan; the
			// fast-forward lands within ~2 intervals of `after`, so the
			// first `> after` is well inside it.
			results, hit_budget, overflowed := recur_expand_from(rule, after_instant, 0, 10000)
			for c in results {
				if c.instant > after_instant {
					return time_datetime_node(recur_render_local(rule.tz, c.dt))
				}
			}
			if overflowed {
				return time_err('cx-err:CXER3304', 'E_TIME_DURATION_OVERFLOW: next occurrence exceeds the representable instant range (~2262-04)')
			}
			if hit_budget && !rule.is_finite() {
				return time_err('cx-err:CXER3325', 'E_TIME_OCCURRENCE_LIMIT: search budget exceeded')
			}
			// past a bounded rule's last → absence
			return cx.Element{}
		}
		'time-occurrences-in' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			from_dt := decode_datetime(args[1]) or { return none }
			to_dt := decode_datetime(args[2]) or { return none }
			from_instant := recur_local_to_instant(rule.tz, from_dt)
			to_instant := recur_local_to_instant(rule.tz, to_dt)
			results, hit_budget, overflowed := recur_expand_from(rule, from_instant, to_instant, 0)
			if overflowed {
				return time_err('cx-err:CXER3304', 'E_TIME_DURATION_OVERFLOW: window exceeds the representable instant range (~2262-04)')
			}
			if hit_budget && !rule.is_finite() {
				return time_err('cx-err:CXER3325', 'E_TIME_OCCURRENCE_LIMIT: search budget exceeded')
			}
			mut items := []cx.Node{}
			for c in results {
				if c.instant >= from_instant {
					items << time_datetime_node(recur_render_local(rule.tz, c.dt))
				}
			}
			return time_seq(items)
		}
		'time-nth-occurrence' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			n := time_arg_int(args[1]) or { return none }
			if n < 1 {
				return time_err('cx-err:CXER3326', 'E_TIME_OCCURRENCE_INDEX: n must be >= 1')
			}
			results, hit_budget, overflowed := recur_expand(rule, 0, int(n))
			if i64(results.len) >= n {
				return time_datetime_node(recur_render_local(rule.tz, results[n - 1].dt))
			}
			if overflowed {
				return time_err('cx-err:CXER3304', 'E_TIME_DURATION_OVERFLOW: nth occurrence exceeds the representable instant range (~2262-04)')
			}
			if hit_budget && !rule.is_finite() {
				return time_err('cx-err:CXER3325', 'E_TIME_OCCURRENCE_LIMIT: search budget exceeded')
			}
			// beyond a bounded last → absence
			return cx.Element{}
		}
		'time-rule-freq' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			return time_atom(recur_freq_to_atom(rule.freq))
		}
		'time-rule-bound' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			if rule.has_count {
				return cx.Element{ name: 'count', items: [time_int(rule.count)] }
			}
			if rule.has_until {
				return cx.Element{
					name: 'until'
					items: [time_datetime_node(recur_render_local(rule.tz, rule.until))]
				}
			}
			return cx.Element{}
		}
		'time-rule-is-finite' {
			rule := recur_rule_from(args[0]) or { return recur_error_node(err.msg()) }
			return time_bool(rule.is_finite())
		}
		else {
			return none
		}
	}
}

// ── recurrence constructor ───────────────────────────────────────────

// time_opts lifts a `__cx_map__` node into a V map (mirrors crypto_opts).
fn time_opts(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

fn time_opt_int(m map[string]cx.Node, key string) ?i64 {
	n := m[key] or { return none }
	return time_arg_int(n)
}

fn time_opt_str(m map[string]cx.Node, key string) ?string {
	n := m[key] or { return none }
	return time_arg_str(n)
}

fn time_opt_atom(m map[string]cx.Node, key string) ?string {
	n := m[key] or { return none }
	return recur_atom_of(n)
}

// time_opt_int_list reads a list-valued option (sequence / array) into []i64.
fn time_opt_int_list(m map[string]cx.Node, key string) ?[]i64 {
	n := m[key] or { return none }
	mut out := []i64{}
	if n is cx.SequenceNode {
		for it in n.items {
			if v := time_arg_int(it) {
				out << v
			}
		}
		return out
	}
	if n is cx.Element {
		if n.name == '__cx_arr__' || n.name == '__cx_seq__' || n.name == '' {
			for it in n.items {
				if v := time_arg_int(it) {
					out << v
				}
			}
			return out
		}
	}
	if v := time_arg_int(n) {
		out << v
	}
	return out
}

// time_recurrence_build implements `[?def recurrence ($freq $anchor $tz $opts) …]`.
// The opts map carries interval/wkst/count/until and the BY* parts (as int
// lists; by-day accepts a sequence of weekday atoms / [nth …] elements).
fn time_recurrence_build(args []cx.Node) cx.Node {
	freq_atom := recur_atom_of(args[0]) or {
		return time_err('cx-err:CXER3322', 'E_TIME_RULE_FIELD_INVALID: freq must be an atom')
	}
	anchor := decode_datetime(args[1]) or {
		return time_err('cx-err:CXER3322', 'E_TIME_RULE_FIELD_INVALID: bad anchor')
	}
	tz := time_arg_str(args[2]) or { 'UTC' }
	opts := if args.len > 3 { time_opts(args[3]) } else { map[string]cx.Node{} }
	mut attrs := [recur_atom_attr('freq', freq_atom)]
	if iv := time_opt_int(opts, 'interval') {
		attrs << time_int_attr('interval', iv)
	}
	attrs << recur_str_attr('anchor', anchor.datetime_string())
	attrs << recur_str_attr('tz', tz)
	if w := time_opt_atom(opts, 'wkst') {
		attrs << recur_atom_attr('wkst', w)
	}
	if c := time_opt_int(opts, 'count') {
		attrs << time_int_attr('count', c)
	}
	if u := time_opt_str(opts, 'until') {
		attrs << recur_str_attr('until', u)
	}
	mut items := []cx.Node{}
	if v := time_opt_int_list(opts, 'by-second') {
		recur_add_int_child(mut items, 'by-second', v)
	}
	if v := time_opt_int_list(opts, 'by-minute') {
		recur_add_int_child(mut items, 'by-minute', v)
	}
	if v := time_opt_int_list(opts, 'by-hour') {
		recur_add_int_child(mut items, 'by-hour', v)
	}
	if bd := opts['by-day'] {
		day_items := recur_byday_from_opt(bd)
		if day_items.len > 0 {
			items << cx.Element{ name: 'by-day', items: day_items }
		}
	}
	if v := time_opt_int_list(opts, 'by-month-day') {
		recur_add_int_child(mut items, 'by-month-day', v)
	}
	if v := time_opt_int_list(opts, 'by-year-day') {
		recur_add_int_child(mut items, 'by-year-day', v)
	}
	if v := time_opt_int_list(opts, 'by-week-no') {
		recur_add_int_child(mut items, 'by-week-no', v)
	}
	if v := time_opt_int_list(opts, 'by-month') {
		recur_add_int_child(mut items, 'by-month', v)
	}
	if v := time_opt_int_list(opts, 'by-set-pos') {
		recur_add_int_child(mut items, 'by-set-pos', v)
	}
	el := cx.Element{ name: 'recurrence', attrs: attrs, items: items }
	// validate eagerly
	recur_rule_from(el) or {
		return recur_error_node(err.msg())
	}
	return el
}

fn recur_byday_from_opt(bd cx.Node) []cx.Node {
	mut out := []cx.Node{}
	mut src := []cx.Node{}
	if bd is cx.SequenceNode {
		src = bd.items.clone()
	} else if bd is cx.Element && (bd.name == '__cx_arr__' || bd.name == '__cx_seq__' || bd.name == '') {
		src = bd.items.clone()
	} else {
		src = [bd]
	}
	for it in src {
		if a := recur_atom_of(it) {
			out << time_atom(a)
		} else if it is cx.Element && it.name == 'nth' {
			out << it
		}
	}
	return out
}
