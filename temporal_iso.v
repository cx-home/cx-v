module cx

// Temporal-span ISO 8601 images (lexicon [L25]/[L26]).
//
// The CX SOURCE/canonical form of a duration/period is the [L25]/[L26] grammar
// (`90m`, `1h30m`, `1y6mo`); the XML body IMAGE is ISO 8601 (`PT1H30M`, `P1Y6M`,
// `P10D`, `P2W`). These helpers convert between the two for the CX⇄XML mapping.
// XML→CX yields the CANONICAL CX form (greedy largest-unit decomposition), so
// the round-trip is value-stable (e.g. `90m` → `PT1H30M` → `1h30m`).

const iso_ns_per_us = i64(1_000)
const iso_ns_per_ms = i64(1_000_000)
const iso_ns_per_s = i64(1_000_000_000)
const iso_ns_per_min = i64(60) * 1_000_000_000
const iso_ns_per_hour = i64(3600) * 1_000_000_000
const iso_ns_per_day = i64(86_400) * 1_000_000_000
const iso_ns_per_week = i64(604_800) * 1_000_000_000

// duration_cx_to_iso converts a CX duration literal (`1h30m`) to its ISO 8601
// image (`PT1H30M`). Returns none if the input is not a valid duration.
pub fn duration_cx_to_iso(cx_dur string) ?string {
	ns := duration_to_ns_pub(cx_dur) or { return none }
	return ns_to_iso_duration(ns)
}

// iso_to_duration_cx converts an ISO 8601 duration image back to the canonical
// CX duration form. Returns none if the input is not a valid ISO duration.
pub fn iso_to_duration_cx(iso string) ?string {
	ns := iso_duration_to_ns(iso) or { return none }
	return ns_to_cx_duration(ns)
}

// period_cx_to_iso converts a CX period literal (`1y6mo`) to ISO 8601 (`P1Y6M`).
pub fn period_cx_to_iso(cx_per string) ?string {
	months := period_to_months(cx_per) or { return none }
	return months_to_iso_period(months)
}

// iso_to_period_cx converts an ISO 8601 period image (`P1Y6M`) back to the
// canonical CX period form (`1y6mo`).
pub fn iso_to_period_cx(iso string) ?string {
	months := iso_period_to_months(iso) or { return none }
	return months_to_cx_period(months)
}

// duration_to_ns_pub exposes the duration→nanoseconds total for the ISO layer
// (the evaluator has its own private copy; this is the parse-layer one).
fn duration_to_ns_pub(s string) ?i64 {
	if s.len == 0 {
		return none
	}
	mut i := 0
	mut neg := false
	if s[0] == `+` {
		i = 1
	} else if s[0] == `-` {
		neg = true
		i = 1
	}
	if i >= s.len {
		return none
	}
	mut total := i64(0)
	for i < s.len {
		dstart := i
		for i < s.len && s[i] >= `0` && s[i] <= `9` {
			i++
		}
		if i == dstart {
			return none
		}
		n := s[dstart..i].i64()
		mut unit_ns := i64(0)
		mut ulen := 0
		if i + 2 <= s.len {
			match s[i..i + 2] {
				'ns' { unit_ns = 1; ulen = 2 }
				'us' { unit_ns = iso_ns_per_us; ulen = 2 }
				'ms' { unit_ns = iso_ns_per_ms; ulen = 2 }
				else {}
			}
		}
		if ulen == 0 {
			match s[i] {
				`s` { unit_ns = iso_ns_per_s; ulen = 1 }
				`m` { unit_ns = iso_ns_per_min; ulen = 1 }
				`h` { unit_ns = iso_ns_per_hour; ulen = 1 }
				`d` { unit_ns = iso_ns_per_day; ulen = 1 }
				`w` { unit_ns = iso_ns_per_week; ulen = 1 }
				else {}
			}
		}
		if ulen == 0 {
			return none
		}
		total += n * unit_ns
		i += ulen
	}
	return if neg { -total } else { total }
}

// ns_to_iso_duration formats a nanosecond span as ISO 8601. A whole number of
// weeks (and nothing else) → `P{n}W`; otherwise the date part carries days and
// the time part carries hours/minutes/(fractional) seconds.
fn ns_to_iso_duration(ns i64) string {
	if ns == 0 {
		return 'PT0S'
	}
	neg := ns < 0
	mut a := if neg { -ns } else { ns }
	sign := if neg { '-' } else { '' }
	if a % iso_ns_per_week == 0 {
		return '${sign}P${a / iso_ns_per_week}W'
	}
	days := a / iso_ns_per_day
	a = a % iso_ns_per_day
	hours := a / iso_ns_per_hour
	a = a % iso_ns_per_hour
	mins := a / iso_ns_per_min
	a = a % iso_ns_per_min
	secs := a / iso_ns_per_s
	subns := a % iso_ns_per_s
	mut date_part := ''
	if days > 0 {
		date_part += '${days}D'
	}
	mut time_part := ''
	if hours > 0 {
		time_part += '${hours}H'
	}
	if mins > 0 {
		time_part += '${mins}M'
	}
	if secs > 0 || subns > 0 {
		time_part += '${format_seconds(secs, subns)}S'
	}
	mut out := '${sign}P${date_part}'
	if time_part != '' {
		out += 'T${time_part}'
	}
	return out
}

// format_seconds renders whole + fractional seconds, trimming trailing zeros
// (e.g. 0 / 500_000_000 → "0.5"; 1 / 0 → "1"; 0 / 40 → "0.000000040").
fn format_seconds(secs i64, subns i64) string {
	if subns == 0 {
		return secs.str()
	}
	mut frac := '${subns:09}' // 9-digit zero-padded nanoseconds
	frac = frac.trim_right('0')
	return '${secs}.${frac}'
}

// iso_duration_to_ns parses an ISO 8601 duration (`P[..W][..D]T[..H][..M][..S]`,
// with optional fractional seconds) to nanoseconds. Period designators (Y / a
// date-part M) are NOT durations and yield none.
fn iso_duration_to_ns(iso string) ?i64 {
	if iso.len < 2 {
		return none
	}
	mut s := iso
	mut neg := false
	if s.starts_with('-') {
		neg = true
		s = s[1..]
	} else if s.starts_with('+') {
		s = s[1..]
	}
	if s.len == 0 || s[0] != `P` {
		return none
	}
	s = s[1..]
	mut total := i64(0)
	mut in_time := false
	mut i := 0
	mut saw_field := false
	for i < s.len {
		if s[i] == `T` {
			in_time = true
			i++
			continue
		}
		// number (allow a decimal point for seconds)
		nstart := i
		for i < s.len && ((s[i] >= `0` && s[i] <= `9`) || s[i] == `.`) {
			i++
		}
		if i == nstart || i >= s.len {
			return none
		}
		numtext := s[nstart..i]
		desig := s[i]
		i++
		match desig {
			`W` {
				if in_time {
					return none
				}
				total += i64(numtext.i64()) * iso_ns_per_week
			}
			`D` {
				if in_time {
					return none
				}
				total += i64(numtext.i64()) * iso_ns_per_day
			}
			`H` {
				if !in_time {
					return none
				}
				total += i64(numtext.i64()) * iso_ns_per_hour
			}
			`S` {
				if !in_time {
					return none
				}
				total += seconds_text_to_ns(numtext)
			}
			`M` {
				// Date-part M is months (a PERIOD designator) — not a duration.
				if !in_time {
					return none
				}
				total += i64(numtext.i64()) * iso_ns_per_min
			}
			`Y` {
				return none
			}
			else {
				return none
			}
		}
		saw_field = true
	}
	if !saw_field {
		return none
	}
	return if neg { -total } else { total }
}

// seconds_text_to_ns parses a (possibly fractional) seconds field to ns.
fn seconds_text_to_ns(t string) i64 {
	if !t.contains('.') {
		return t.i64() * iso_ns_per_s
	}
	parts := t.split('.')
	whole := parts[0].i64()
	mut frac := if parts.len > 1 { parts[1] } else { '' }
	if frac.len > 9 {
		frac = frac[..9]
	}
	for frac.len < 9 {
		frac += '0'
	}
	return whole * iso_ns_per_s + frac.i64()
}

// ns_to_cx_duration renders a nanosecond span as the canonical CX duration
// form — greedy largest-unit decomposition (`5400e9` → `1h30m`). The result
// re-lexes to the same span; this is the form XML→CX yields.
fn ns_to_cx_duration(ns i64) string {
	if ns == 0 {
		return '0s'
	}
	neg := ns < 0
	mut a := if neg { -ns } else { ns }
	sign := if neg { '-' } else { '' }
	mut out := ''
	weeks := a / iso_ns_per_week
	a = a % iso_ns_per_week
	if weeks > 0 {
		out += '${weeks}w'
	}
	days := a / iso_ns_per_day
	a = a % iso_ns_per_day
	if days > 0 {
		out += '${days}d'
	}
	hours := a / iso_ns_per_hour
	a = a % iso_ns_per_hour
	if hours > 0 {
		out += '${hours}h'
	}
	mins := a / iso_ns_per_min
	a = a % iso_ns_per_min
	if mins > 0 {
		out += '${mins}m'
	}
	secs := a / iso_ns_per_s
	a = a % iso_ns_per_s
	if secs > 0 {
		out += '${secs}s'
	}
	ms := a / iso_ns_per_ms
	a = a % iso_ns_per_ms
	if ms > 0 {
		out += '${ms}ms'
	}
	us := a / iso_ns_per_us
	a = a % iso_ns_per_us
	if us > 0 {
		out += '${us}us'
	}
	if a > 0 {
		out += '${a}ns'
	}
	return '${sign}${out}'
}

// period_to_months totals a CX period literal (`1y6mo`) to whole months.
fn period_to_months(s string) ?i64 {
	if s.len == 0 {
		return none
	}
	mut i := 0
	mut neg := false
	if s[0] == `+` {
		i = 1
	} else if s[0] == `-` {
		neg = true
		i = 1
	}
	if i >= s.len {
		return none
	}
	mut total := i64(0)
	for i < s.len {
		dstart := i
		for i < s.len && s[i] >= `0` && s[i] <= `9` {
			i++
		}
		if i == dstart {
			return none
		}
		n := s[dstart..i].i64()
		if i + 2 <= s.len && s[i..i + 2] == 'mo' {
			total += n
			i += 2
		} else if i < s.len && s[i] == `y` {
			total += n * 12
			i += 1
		} else {
			return none
		}
	}
	return if neg { -total } else { total }
}

// months_to_iso_period formats whole months as ISO 8601 (`18` → `P1Y6M`).
fn months_to_iso_period(months i64) string {
	if months == 0 {
		return 'P0M'
	}
	neg := months < 0
	a := if neg { -months } else { months }
	sign := if neg { '-' } else { '' }
	years := a / 12
	mos := a % 12
	mut out := '${sign}P'
	if years > 0 {
		out += '${years}Y'
	}
	if mos > 0 {
		out += '${mos}M'
	}
	return out
}

// iso_period_to_months parses an ISO 8601 period (`P1Y6M`) to whole months.
// Only the year/month designators are valid for a period.
fn iso_period_to_months(iso string) ?i64 {
	if iso.len < 2 {
		return none
	}
	mut s := iso
	mut neg := false
	if s.starts_with('-') {
		neg = true
		s = s[1..]
	} else if s.starts_with('+') {
		s = s[1..]
	}
	if s.len == 0 || s[0] != `P` {
		return none
	}
	s = s[1..]
	mut total := i64(0)
	mut i := 0
	mut saw := false
	for i < s.len {
		nstart := i
		for i < s.len && s[i] >= `0` && s[i] <= `9` {
			i++
		}
		if i == nstart || i >= s.len {
			return none
		}
		n := s[nstart..i].i64()
		match s[i] {
			`Y` { total += n * 12 }
			`M` { total += n }
			else { return none }
		}
		i++
		saw = true
	}
	if !saw {
		return none
	}
	return if neg { -total } else { total }
}

// months_to_cx_period renders whole months as the canonical CX period form
// (`18` → `1y6mo`).
fn months_to_cx_period(months i64) string {
	if months == 0 {
		return '0mo'
	}
	neg := months < 0
	a := if neg { -months } else { months }
	sign := if neg { '-' } else { '' }
	years := a / 12
	mos := a % 12
	mut out := '${sign}'
	if years > 0 {
		out += '${years}y'
	}
	if mos > 0 {
		out += '${mos}mo'
	}
	return out
}
