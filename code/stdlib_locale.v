module code

import cx
import os

// stdlib_locale.v — native primitives backing `cx-stdlib/locale`
// (spec/std-lib/locale.md). Locale-aware collation (UCA / CLDR tailorings),
// number / date / time / currency formatting, BCP-47 tag introspection,
// locale display names, text direction, and locale-aware case mapping. The
// module's `[?def]` bodies (stdlib_src_locale in stdlib_bundle.v) forward
// here via stdlib_dispatch.v::stdlib_builtin.
//
// ── CX value model ──────────────────────────────────────────────────
//   collate / collate-with-opts → int (-1/0/1) scalar.
//   collate-key                 → bytes scalar (opaque UCA sort key).
//   format-number / *-with-opts → string scalar (grouped per locale).
//   parse-number-locale         → float scalar.
//   format-date / -datetime     → string scalar (ICU/LDML pattern).
//   format-date-style           → string scalar (locale style atom).
//   parse-date-locale           → date scalar.
//   format-currency             → string scalar.
//   currency-symbol             → string scalar.
//   list-locales                → sequence(string).
//   is-supported                → bool.
//   default-locale              → string (impure: reads $LANG).
//   locale-name / language-of / country-of / script-of → string.
//   text-direction              → atom (:ltr / :rtl).
//   upper-locale / lower-locale / title-locale → string.
//
// Errors are VALUES (mk_err, eval.v): CXER3500 E_LOCALE_DATA_UNAVAILABLE,
// CXER3501 E_LOCALE_TAG_INVALID, CXER3502 E_LOCALE_PATTERN_INVALID,
// CXER3503 E_LOCALE_CURRENCY_INVALID, CXER3504 E_LOCALE_NUMBER_PARSE_FAILED
// (§5). The runner matches the bare code string against `out-err`.
//
// locale is PURE for all functions except default-locale; the CLDR-subset
// catalog is static const data, so no `@[has_globals]` is needed.

// ── value builders ───────────────────────────────────────────────────

fn loc_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn loc_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn loc_float(f f64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(f)
		data_type: cx.ScalarType.float_type
	}
}

fn loc_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn loc_atom(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.atom_type
	}
}

fn loc_bytes(b []u8) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b.bytestr())
		data_type: cx.ScalarType.bytes_type
	}
}

fn loc_date(v string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.date_type
	}
}

fn loc_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// ── argument readers ─────────────────────────────────────────────────

fn loc_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// loc_arg_num reads a numeric (int/float) or numeric-string argument as f64.
fn loc_arg_num(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return f64(v) }
			f64 { return v }
			string { return v.f64() }
			else { return none }
		}
	}
	return none
}

// loc_arg_atom reads an atom argument's bare name (no leading colon).
fn loc_arg_atom(n cx.Node) ?string {
	if n is cx.ScalarNode {
		if n.value is string {
			return n.value as string
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

fn loc_node_text(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// ── error helpers ────────────────────────────────────────────────────

fn loc_err_data_unavailable(msg string) cx.Node {
	return mk_err('cx-err:CXER3500', 'E_LOCALE_DATA_UNAVAILABLE: ${msg}')
}

fn loc_err_tag_invalid(msg string) cx.Node {
	return mk_err('cx-err:CXER3501', 'E_LOCALE_TAG_INVALID: ${msg}')
}

fn loc_err_pattern_invalid(msg string) cx.Node {
	return mk_err('cx-err:CXER3502', 'E_LOCALE_PATTERN_INVALID: ${msg}')
}

fn loc_err_currency_invalid(msg string) cx.Node {
	return mk_err('cx-err:CXER3503', 'E_LOCALE_CURRENCY_INVALID: ${msg}')
}

fn loc_err_number_parse(msg string) cx.Node {
	return mk_err('cx-err:CXER3504', 'E_LOCALE_NUMBER_PARSE_FAILED: ${msg}')
}

// ── BCP-47 tag parsing & validation (§2, §4.1) ───────────────────────

struct LocaleTag {
mut:
	language string // lowercase, 2-8 ALPHA
	script   string // Titlecase, 4 ALPHA
	region   string // upper, 2 ALPHA or 3 DIGIT
	variants []string
}

fn loc_is_alpha(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
}

fn loc_is_digit(c u8) bool {
	return c >= `0` && c <= `9`
}

fn loc_is_alnum(c u8) bool {
	return loc_is_alpha(c) || loc_is_digit(c)
}

fn loc_subtag_alpha(s string) bool {
	if s.len == 0 {
		return false
	}
	for c in s {
		if !loc_is_alpha(c) {
			return false
		}
	}
	return true
}

fn loc_subtag_alnum(s string) bool {
	if s.len == 0 {
		return false
	}
	for c in s {
		if !loc_is_alnum(c) {
			return false
		}
	}
	return true
}

fn loc_all_digit(s string) bool {
	if s.len == 0 {
		return false
	}
	for c in s {
		if !loc_is_digit(c) {
			return false
		}
	}
	return true
}

// loc_parse_tag validates a BCP-47 language tag structurally and returns the
// canonical-cased subtags. Returns none on a malformed tag. Accepts:
//   language (2-8 ALPHA) [ "-" script (4 ALPHA) ] [ "-" region (2 ALPHA|3 DIGIT) ]
//   *( "-" variant (5-8 alnum | DIGIT 3alnum) )
// Sufficient for the §3.5 introspection surface and §4.1 fallback.
fn loc_parse_tag(tag string) ?LocaleTag {
	if tag.len == 0 {
		return none
	}
	parts := tag.split('-')
	if parts.len == 0 {
		return none
	}
	mut t := LocaleTag{}
	lang := parts[0]
	if !(lang.len >= 2 && lang.len <= 8 && loc_subtag_alpha(lang)) {
		return none
	}
	t.language = lang.to_lower()
	mut i := 1
	// script (exactly 4 ALPHA)
	if i < parts.len && parts[i].len == 4 && loc_subtag_alpha(parts[i]) {
		s := parts[i]
		t.script = s[0..1].to_upper() + s[1..].to_lower()
		i++
	}
	// region (2 ALPHA or 3 DIGIT)
	if i < parts.len {
		p := parts[i]
		if (p.len == 2 && loc_subtag_alpha(p)) || (p.len == 3 && loc_all_digit(p)) {
			t.region = p.to_upper()
			i++
		}
	}
	// variants (5-8 alnum, or 4 chars starting with a DIGIT)
	for i < parts.len {
		p := parts[i]
		valid := (p.len >= 5 && p.len <= 8 && loc_subtag_alnum(p))
			|| (p.len == 4 && loc_is_digit(p[0]) && loc_subtag_alnum(p))
		if !valid {
			return none
		}
		t.variants << p.to_lower()
		i++
	}
	return t
}

// ── CLDR-subset catalog (§2) ─────────────────────────────────────────

const loc_catalog = [
	'en-US',
	'en-GB',
	'de-DE',
	'fr-FR',
	'es-ES',
	'it-IT',
	'pt-BR',
	'pt-PT',
	'nl-NL',
	'ja-JP',
	'zh-Hans-CN',
	'zh-Hant-TW',
	'ko-KR',
	'ru-RU',
	'ar-SA',
	'he-IL',
	'tr-TR',
	'pl-PL',
	'sv-SE',
	'da-DK',
	'fi-FI',
	'nb-NO',
	'cs-CZ',
	'el-GR',
	'th-TH',
	'vi-VN',
	'hi-IN',
	'id-ID',
	'uk-UA',
	'ro-RO',
]

// Number-format symbols per resolved language.
struct NumSymbols {
	group   string
	decimal string
}

fn loc_num_symbols(t LocaleTag) NumSymbols {
	match t.language {
		'de', 'es', 'it', 'pt', 'nl', 'da', 'tr', 'el', 'id', 'ro' {
			return NumSymbols{
				group:   '.'
				decimal: ','
			}
		}
		'fr', 'ru', 'pl', 'cs', 'sv', 'fi', 'nb', 'uk' {
			// §3.2 fr-FR example renders an ASCII space group separator.
			return NumSymbols{
				group:   ' '
				decimal: ','
			}
		}
		else {
			// en, ja, ko, zh, th, vi, hi, he, ar (latin-digit fallback): en-US.
			return NumSymbols{
				group:   ','
				decimal: '.'
			}
		}
	}
}

// Currency data: ISO 4217 minor-unit digit count + symbol (en display).
struct CurrencyData {
	digits int
	symbol string
}

const loc_currency_table = {
	'USD': CurrencyData{
		digits: 2
		symbol: '\$'
	}
	'EUR': CurrencyData{
		digits: 2
		symbol: '€'
	}
	'GBP': CurrencyData{
		digits: 2
		symbol: '£'
	}
	'JPY': CurrencyData{
		digits: 0
		symbol: '￥'
	}
	'CNY': CurrencyData{
		digits: 2
		symbol: '¥'
	}
	'KRW': CurrencyData{
		digits: 0
		symbol: '₩'
	}
	'CHF': CurrencyData{
		digits: 2
		symbol: 'CHF'
	}
	'CAD': CurrencyData{
		digits: 2
		symbol: '\$'
	}
	'AUD': CurrencyData{
		digits: 2
		symbol: '\$'
	}
	'INR': CurrencyData{
		digits: 2
		symbol: '₹'
	}
	'RUB': CurrencyData{
		digits: 2
		symbol: '₽'
	}
	'BRL': CurrencyData{
		digits: 2
		symbol: 'R\$'
	}
	'BHD': CurrencyData{
		digits: 3
		symbol: '.د.ب'
	}
	'IQD': CurrencyData{
		digits: 3
		symbol: 'ع.د'
	}
	'SEK': CurrencyData{
		digits: 2
		symbol: 'kr'
	}
	'NOK': CurrencyData{
		digits: 2
		symbol: 'kr'
	}
	'DKK': CurrencyData{
		digits: 2
		symbol: 'kr'
	}
	'PLN': CurrencyData{
		digits: 2
		symbol: 'zł'
	}
	'TRY': CurrencyData{
		digits: 2
		symbol: '₺'
	}
	'MXN': CurrencyData{
		digits: 2
		symbol: '\$'
	}
}

// RTL languages (§3.5).
fn loc_is_rtl_language(lang string) bool {
	return lang in ['ar', 'he', 'fa', 'ur', 'ps', 'syr', 'dv', 'yi']
}

// loc_has_collation_data: §5 CXER3500 — a tag whose language/script the bundle
// has no collation data for. Constructed scripts / languages are unavailable.
fn loc_has_collation_data(t LocaleTag) bool {
	if t.language in ['tlh', 'qya', 'sjn', 'tok', 'art', 'mis', 'zxx'] {
		return false
	}
	if t.script == 'Piqd' {
		return false
	}
	return true
}

// ── §3.1 Collation (UCA / TR10 subset) ───────────────────────────────

struct CollateOpts {
mut:
	locale             string
	strength           string
	case_first         string
	numeric            bool
	ignore_punctuation bool
}

fn loc_default_collate_opts() CollateOpts {
	return CollateOpts{
		locale:     'en-US'
		strength:   'tertiary'
		case_first: 'locale-default'
		numeric:    false
	}
}

fn loc_read_collate_opts(n cx.Node) CollateOpts {
	mut o := loc_default_collate_opts()
	if n is cx.Element && (n.name == '__cx_map__' || n.name == 'map') {
		for entry in n.items {
			if entry is cx.Element && entry.items.len > 0 {
				val := loc_node_text(entry.items[0])
				match entry.name {
					'locale' { o.locale = val }
					'strength' { o.strength = val }
					'case-first' { o.case_first = val }
					'numeric' { o.numeric = val == 'true' }
					'ignore-punctuation' { o.ignore_punctuation = val == 'true' }
					else {}
				}
			}
		}
	}
	return o
}

// loc_primary_weight maps a rune to its DUCET-ish primary weight: base
// letter, case- and diacritic-folded so "ä" and "a" share it (§6 German).
fn loc_primary_weight(r rune) u32 {
	return u32(loc_fold_base(r))
}

// loc_fold_base strips diacritics for the Latin-1 / Latin Extended-A accented
// forms used by the conformance suite, lowercasing as it goes.
fn loc_fold_base(r rune) rune {
	mut c := r
	if c >= `A` && c <= `Z` {
		c = c + 32
	}
	return match c {
		0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5 { rune(`a`) }
		0x00E7 { rune(`c`) }
		0x00E8, 0x00E9, 0x00EA, 0x00EB { rune(`e`) }
		0x00EC, 0x00ED, 0x00EE, 0x00EF { rune(`i`) }
		0x00F1 { rune(`n`) }
		0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6 { rune(`o`) }
		0x00F9, 0x00FA, 0x00FB, 0x00FC { rune(`u`) }
		0x00FD, 0x00FF { rune(`y`) }
		else { c }
	}
}

// loc_secondary_weight: an accented form sorts after its base at L2 (CLDR
// default: base < accented).
fn loc_secondary_weight(r rune) u32 {
	mut c := r
	if c >= `A` && c <= `Z` {
		c = c + 32
	}
	return match c {
		0x00E0 { u32(1) }
		0x00E1 { u32(2) }
		0x00E2 { u32(3) }
		0x00E3 { u32(4) }
		0x00E4 { u32(5) }
		0x00E5 { u32(6) }
		0x00E8, 0x00E9, 0x00EA, 0x00EB { u32(5) }
		0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6 { u32(5) }
		0x00F9, 0x00FA, 0x00FB, 0x00FC { u32(5) }
		else { u32(0) }
	}
}

// loc_tertiary_weight captures case: lowercase < uppercase (CLDR default).
fn loc_tertiary_weight(r rune) u32 {
	if r >= `A` && r <= `Z` {
		return u32(2)
	}
	if r >= 0x00C0 && r <= 0x00DE && r != 0x00D7 {
		return u32(2)
	}
	return u32(1)
}

fn loc_is_punct(r rune) bool {
	return (r >= 0x21 && r <= 0x2F) || (r >= 0x3A && r <= 0x40)
		|| (r >= 0x5B && r <= 0x60) || (r >= 0x7B && r <= 0x7E)
}

// loc_collate_compare returns -1/0/1 per the UCA-subset multi-level algorithm
// honoring strength, numeric, and ignore-punctuation.
fn loc_collate_compare(a string, b string, o CollateOpts) int {
	if o.numeric {
		nr := loc_numeric_compare(a, b)
		if nr != 0 {
			return nr
		}
	}
	ra := loc_runes_for_collation(a, o)
	rb := loc_runes_for_collation(b, o)

	r0 := loc_level_compare(ra, rb, 0)
	if r0 != 0 {
		return r0
	}
	if o.strength == 'primary' {
		return 0
	}
	r1 := loc_level_compare(ra, rb, 1)
	if r1 != 0 {
		return r1
	}
	if o.strength == 'secondary' {
		return 0
	}
	r2 := loc_level_compare(ra, rb, 2)
	if r2 != 0 {
		return r2
	}
	if o.strength == 'quaternary' {
		return loc_codepoint_compare(a, b)
	}
	return 0
}

fn loc_runes_for_collation(s string, o CollateOpts) []rune {
	mut out := []rune{}
	for r in s.runes() {
		if o.ignore_punctuation && loc_is_punct(r) {
			continue
		}
		out << r
	}
	return out
}

fn loc_level_compare(a []rune, b []rune, level int) int {
	mut i := 0
	for i < a.len && i < b.len {
		wa := loc_weight_at(a[i], level)
		wb := loc_weight_at(b[i], level)
		if wa < wb {
			return -1
		}
		if wa > wb {
			return 1
		}
		i++
	}
	if a.len < b.len {
		return -1
	}
	if a.len > b.len {
		return 1
	}
	return 0
}

fn loc_weight_at(r rune, level int) u32 {
	return match level {
		0 { loc_primary_weight(r) }
		1 { loc_secondary_weight(r) }
		else { loc_tertiary_weight(r) }
	}
}

fn loc_codepoint_compare(a string, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// loc_numeric_compare implements the §4.2 natural-sort gotcha: embedded digit
// runs compare as numbers. Returns 0 when equal under numeric comparison.
fn loc_numeric_compare(a string, b string) int {
	ar := a.runes()
	br := b.runes()
	mut i := 0
	mut j := 0
	for i < ar.len && j < br.len {
		ca := ar[i]
		cb := br[j]
		da := ca >= `0` && ca <= `9`
		db := cb >= `0` && cb <= `9`
		if da && db {
			sa := i
			for i < ar.len && ar[i] >= `0` && ar[i] <= `9` {
				i++
			}
			sb := j
			for j < br.len && br[j] >= `0` && br[j] <= `9` {
				j++
			}
			na := loc_runes_to_str(ar[sa..i]).trim_left('0')
			nb := loc_runes_to_str(br[sb..j]).trim_left('0')
			if na.len != nb.len {
				return if na.len < nb.len { -1 } else { 1 }
			}
			if na != nb {
				return if na < nb { -1 } else { 1 }
			}
		} else {
			fa := loc_fold_base(ca)
			fb := loc_fold_base(cb)
			if fa != fb {
				return if fa < fb { -1 } else { 1 }
			}
			i++
			j++
		}
	}
	if ar.len - i < br.len - j {
		return -1
	}
	if ar.len - i > br.len - j {
		return 1
	}
	return 0
}

fn loc_runes_to_str(rs []rune) string {
	mut s := ''
	for r in rs {
		s += r.str()
	}
	return s
}

// loc_collate_key builds an opaque UCA sort key whose byte order matches
// loc_collate_compare at tertiary strength. Big-endian per-level weights
// separated by 0x00 level markers.
fn loc_collate_key(s string, o CollateOpts) []u8 {
	rs := loc_runes_for_collation(s, o)
	mut out := []u8{}
	for level in 0 .. 3 {
		for r in rs {
			w := loc_weight_at(r, level)
			out << u8((w >> 24) & 0xFF)
			out << u8((w >> 16) & 0xFF)
			out << u8((w >> 8) & 0xFF)
			out << u8(w & 0xFF)
		}
		out << u8(0x00)
	}
	return out
}

// ── §3.2 Number formatting ───────────────────────────────────────────

struct NumberOpts {
mut:
	locale       string
	max_fraction int
	min_fraction int
	grouping     bool
	notation     string
}

fn loc_default_number_opts() NumberOpts {
	return NumberOpts{
		locale:       'en-US'
		max_fraction: 3
		min_fraction: 0
		grouping:     true
		notation:     'standard'
	}
}

fn loc_read_number_opts(n cx.Node) NumberOpts {
	mut o := loc_default_number_opts()
	if n is cx.Element && (n.name == '__cx_map__' || n.name == 'map') {
		for entry in n.items {
			if entry is cx.Element && entry.items.len > 0 {
				val := loc_node_text(entry.items[0])
				match entry.name {
					'locale' { o.locale = val }
					'max-fraction-digits' { o.max_fraction = val.int() }
					'min-fraction-digits' { o.min_fraction = val.int() }
					'grouping' { o.grouping = val != 'false' }
					'notation' { o.notation = val }
					else {}
				}
			}
		}
	}
	return o
}

fn loc_format_number(n f64, t LocaleTag, o NumberOpts) string {
	sym := loc_num_symbols(t)
	if o.notation == 'compact' {
		return loc_format_compact(n, sym)
	}
	if o.notation == 'scientific' || o.notation == 'engineering' {
		return loc_format_scientific(n, o.notation, sym)
	}
	return loc_format_decimal(n, sym, o.grouping, o.max_fraction, o.min_fraction)
}

fn loc_format_decimal(n f64, sym NumSymbols, grouping bool, max_frac int, min_frac int) string {
	neg := n < 0
	mut v := if neg { -n } else { n }
	scale := loc_pow10(max_frac)
	v = loc_round_half_up(v * scale) / scale
	int_part := i64(v)
	frac := v - f64(int_part)

	int_str := loc_group_int(int_part, sym.group, grouping)
	mut frac_digits := loc_frac_digits(frac, max_frac)
	for frac_digits.len > min_frac && frac_digits.ends_with('0') {
		frac_digits = frac_digits[..frac_digits.len - 1]
	}
	mut out := int_str
	if frac_digits.len > 0 {
		out += sym.decimal + frac_digits
	}
	if neg {
		out = '-' + out
	}
	return out
}

fn loc_pow10(n int) f64 {
	mut p := f64(1)
	for _ in 0 .. n {
		p *= 10
	}
	return p
}

fn loc_round_half_up(x f64) f64 {
	return if x < 0 { -loc_floor(-x + 0.5) } else { loc_floor(x + 0.5) }
}

fn loc_floor(x f64) f64 {
	return f64(i64(x))
}

fn loc_group_int(n i64, sep string, grouping bool) string {
	digits := n.str()
	if !grouping || digits.len <= 3 {
		return digits
	}
	mut out := ''
	mut count := 0
	for i := digits.len - 1; i >= 0; i-- {
		out = digits[i].ascii_str() + out
		count++
		if count % 3 == 0 && i != 0 {
			out = sep + out
		}
	}
	return out
}

fn loc_frac_digits(frac f64, places int) string {
	if places == 0 {
		return ''
	}
	scale := loc_pow10(places)
	scaled := i64(loc_round_half_up(frac * scale))
	mut s := scaled.str()
	for s.len < places {
		s = '0' + s
	}
	if s.len > places {
		s = s[s.len - places..]
	}
	return s
}

fn loc_format_compact(n f64, sym NumSymbols) string {
	neg := n < 0
	v := if neg { -n } else { n }
	thresholds := [f64(1_000_000_000_000.0), 1_000_000_000.0, 1_000_000.0, 1_000.0]
	suffixes := ['T', 'B', 'M', 'K']
	for idx, th in thresholds {
		if v >= th {
			scaled := v / th
			rounded := loc_round_half_up(scaled * 10) / 10
			intp := i64(rounded)
			fracp := loc_frac_digits(rounded - f64(intp), 1)
			mut out := intp.str()
			if fracp != '' && fracp != '0' {
				out += sym.decimal + fracp
			}
			out += suffixes[idx]
			return if neg { '-' + out } else { out }
		}
	}
	return loc_format_decimal(n, sym, false, 0, 0)
}

fn loc_format_scientific(n f64, notation string, sym NumSymbols) string {
	if n == 0 {
		return '0E0'
	}
	neg := n < 0
	mut v := if neg { -n } else { n }
	mut exp := 0
	for v >= 10 {
		v /= 10
		exp++
	}
	for v < 1 {
		v *= 10
		exp--
	}
	if notation == 'engineering' {
		for exp % 3 != 0 {
			v *= 10
			exp--
		}
	}
	mant := loc_format_decimal(v, sym, false, 3, 0)
	out := '${mant}E${exp}'
	return if neg { '-' + out } else { out }
}

fn loc_parse_number(s string, t LocaleTag) ?f64 {
	sym := loc_num_symbols(t)
	mut cleaned := s.trim_space()
	if cleaned == '' {
		return none
	}
	cleaned = cleaned.replace(sym.group, '')
	if sym.decimal != '.' {
		cleaned = cleaned.replace(sym.decimal, '.')
	}
	mut seen_dot := false
	mut seen_digit := false
	for idx, c in cleaned {
		if c == `-` || c == `+` {
			if idx != 0 {
				return none
			}
		} else if c == `.` {
			if seen_dot {
				return none
			}
			seen_dot = true
		} else if c >= `0` && c <= `9` {
			seen_digit = true
		} else {
			return none
		}
	}
	if !seen_digit {
		return none
	}
	return cleaned.f64()
}

// ── §3.3 / §3.4 Date / time formatting (ICU/LDML token table) ─────────

struct CalNames {
	months_full    []string
	months_short   []string
	weekdays_full  []string // index 0 = Sunday
	weekdays_short []string
	am             string
	pm             string
}

fn loc_cal_names(t LocaleTag) CalNames {
	match t.language {
		'fr' {
			return CalNames{
				months_full:    ['janvier', 'février', 'mars', 'avril', 'mai', 'juin',
					'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre']
				months_short:   ['janv.', 'févr.', 'mars', 'avr.', 'mai', 'juin', 'juil.',
					'août', 'sept.', 'oct.', 'nov.', 'déc.']
				weekdays_full:  ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi',
					'samedi']
				weekdays_short: ['dim.', 'lun.', 'mar.', 'mer.', 'jeu.', 'ven.', 'sam.']
				am:             'AM'
				pm:             'PM'
			}
		}
		'ja' {
			return CalNames{
				months_full:    ['1月', '2月', '3月', '4月', '5月', '6月', '7月', '8月', '9月',
					'10月', '11月', '12月']
				months_short:   ['1月', '2月', '3月', '4月', '5月', '6月', '7月', '8月', '9月',
					'10月', '11月', '12月']
				weekdays_full:  ['日曜日', '月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日']
				weekdays_short: ['日', '月', '火', '水', '木', '金', '土']
				am:             '午前'
				pm:             '午後'
			}
		}
		'de' {
			return CalNames{
				months_full:    ['Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli',
					'August', 'September', 'Oktober', 'November', 'Dezember']
				months_short:   ['Jan.', 'Feb.', 'März', 'Apr.', 'Mai', 'Juni', 'Juli', 'Aug.',
					'Sept.', 'Okt.', 'Nov.', 'Dez.']
				weekdays_full:  ['Sonntag', 'Montag', 'Dienstag', 'Mittwoch', 'Donnerstag',
					'Freitag', 'Samstag']
				weekdays_short: ['So.', 'Mo.', 'Di.', 'Mi.', 'Do.', 'Fr.', 'Sa.']
				am:             'AM'
				pm:             'PM'
			}
		}
		else {
			return CalNames{
				months_full:    ['January', 'February', 'March', 'April', 'May', 'June', 'July',
					'August', 'September', 'October', 'November', 'December']
				months_short:   ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
					'Oct', 'Nov', 'Dec']
				weekdays_full:  ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
					'Saturday']
				weekdays_short: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
				am:             'AM'
				pm:             'PM'
			}
		}
	}
}

struct DateTimeParts {
mut:
	year   int
	month  int
	day    int
	hour   int
	minute int
	second int
	millis int
	tzname string
	tzoff  string
}

fn loc_parse_iso(s string) ?DateTimeParts {
	if s.len < 10 {
		return none
	}
	if s[4] != `-` || s[7] != `-` {
		return none
	}
	mut p := DateTimeParts{}
	p.year = s[0..4].int()
	p.month = s[5..7].int()
	p.day = s[8..10].int()
	if p.month < 1 || p.month > 12 || p.day < 1 || p.day > 31 {
		return none
	}
	if s.len > 10 {
		if s[10] != `T` && s[10] != ` ` {
			return none
		}
		rest := s[11..]
		mut timestr := rest
		if rest.ends_with('Z') {
			p.tzname = 'UTC'
			p.tzoff = '+0000'
			timestr = rest[..rest.len - 1]
		} else {
			off := loc_find_offset(rest)
			if off >= 0 {
				timestr = rest[..off]
				p.tzoff = rest[off..]
			}
		}
		tparts := timestr.split(':')
		if tparts.len >= 2 {
			p.hour = tparts[0].int()
			p.minute = tparts[1].int()
			if tparts.len >= 3 {
				sec := tparts[2]
				if sec.contains('.') {
					dot := sec.index('.') or { sec.len }
					p.second = sec[..dot].int()
					ms := sec[dot + 1..]
					p.millis = (ms + '000')[..3].int()
				} else {
					p.second = sec.int()
				}
			}
		}
	}
	return p
}

fn loc_find_offset(s string) int {
	for i := 1; i < s.len; i++ {
		if s[i] == `+` || s[i] == `-` {
			return i
		}
	}
	return -1
}

// loc_day_of_week computes weekday (0=Sunday) via Zeller's congruence.
fn loc_day_of_week(year int, month int, day int) int {
	mut y := year
	mut m := month
	if m < 3 {
		m += 12
		y -= 1
	}
	k := y % 100
	j := y / 100
	h := (day + (13 * (m + 1)) / 5 + k + k / 4 + j / 4 + 5 * j) % 7
	return (h + 6) % 7
}

fn loc_pad2(n int) string {
	s := n.str()
	return if s.len < 2 { '0' + s } else { s }
}

fn loc_pad3(n int) string {
	mut s := n.str()
	for s.len < 3 {
		s = '0' + s
	}
	return s
}

// loc_valid_pattern: an ICU/LDML pattern may only carry known field letters
// (§3.3 token table). An unknown bare letter (e.g. "Q") is unparseable.
fn loc_valid_pattern(pattern string) bool {
	known := 'yMdHhmsSEazZ'.bytes()
	for r in pattern.runes() {
		if r < 128 {
			c := u8(r)
			if loc_is_alpha(c) && c !in known {
				return false
			}
		}
	}
	return true
}

fn loc_format_pattern(p DateTimeParts, t LocaleTag, pattern string) string {
	names := loc_cal_names(t)
	wd := loc_day_of_week(p.year, p.month, p.day)
	mut out := ''
	rs := pattern.runes()
	mut i := 0
	for i < rs.len {
		r := rs[i]
		if r == `'` {
			i++
			for i < rs.len && rs[i] != `'` {
				out += rs[i].str()
				i++
			}
			i++
			continue
		}
		if r < 128 && loc_is_alpha(u8(r)) {
			mut run := 1
			for i + run < rs.len && rs[i + run] == r {
				run++
			}
			out += loc_render_token(u8(r), run, p, wd, names)
			i += run
			continue
		}
		out += r.str()
		i++
	}
	return out
}

fn loc_render_token(c u8, run int, p DateTimeParts, wd int, names CalNames) string {
	match c {
		`y` {
			if run == 2 {
				return loc_pad2(p.year % 100)
			}
			mut s := p.year.str()
			for s.len < run {
				s = '0' + s
			}
			return s
		}
		`M` {
			if run >= 4 {
				return names.months_full[p.month - 1]
			}
			if run == 3 {
				return names.months_short[p.month - 1]
			}
			if run == 2 {
				return loc_pad2(p.month)
			}
			return p.month.str()
		}
		`d` {
			if run >= 2 {
				return loc_pad2(p.day)
			}
			return p.day.str()
		}
		`E` {
			if run >= 4 {
				return names.weekdays_full[wd]
			}
			return names.weekdays_short[wd]
		}
		`H` {
			if run >= 2 {
				return loc_pad2(p.hour)
			}
			return p.hour.str()
		}
		`h` {
			mut h12 := p.hour % 12
			if h12 == 0 {
				h12 = 12
			}
			if run >= 2 {
				return loc_pad2(h12)
			}
			return h12.str()
		}
		`m` {
			if run >= 2 {
				return loc_pad2(p.minute)
			}
			return p.minute.str()
		}
		`s` {
			if run >= 2 {
				return loc_pad2(p.second)
			}
			return p.second.str()
		}
		`S` {
			return loc_pad3(p.millis)
		}
		`a` {
			return if p.hour < 12 { names.am } else { names.pm }
		}
		`z` {
			return if p.tzname != '' { p.tzname } else { 'UTC' }
		}
		`Z` {
			return if p.tzoff != '' { p.tzoff } else { '+0000' }
		}
		else {
			return ''
		}
	}
}

// loc_style_pattern returns the locale's conventional date pattern for a style
// atom (:short / :medium / :long / :full).
fn loc_style_pattern(t LocaleTag, style string) ?string {
	match t.language {
		'ja' {
			return match style {
				'short' { 'yyyy/MM/dd' }
				'medium' { 'yyyy/MM/dd' }
				'long' { 'yyyy年M月d日' }
				'full' { 'yyyy年M月d日EEEE' }
				else { none }
			}
		}
		'fr' {
			return match style {
				'short' { 'dd/MM/yyyy' }
				'medium' { 'd MMM yyyy' }
				'long' { 'd MMMM yyyy' }
				'full' { 'EEEE d MMMM yyyy' }
				else { none }
			}
		}
		'de' {
			return match style {
				'short' { 'dd.MM.yy' }
				'medium' { 'dd.MM.yyyy' }
				'long' { 'd. MMMM yyyy' }
				'full' { 'EEEE, d. MMMM yyyy' }
				else { none }
			}
		}
		else {
			return match style {
				'short' { 'M/d/yy' }
				'medium' { 'MMM d, yyyy' }
				'long' { 'MMMM d, yyyy' }
				'full' { 'EEEE, MMMM d, yyyy' }
				else { none }
			}
		}
	}
}

// ── §3.4 Currency formatting ─────────────────────────────────────────

fn loc_format_currency(n f64, currency string, t LocaleTag) cx.Node {
	cd := loc_currency_table[currency.to_upper()] or {
		return loc_err_currency_invalid('unknown ISO 4217 code "${currency}"')
	}
	sym := loc_num_symbols(t)
	num := loc_format_decimal(n, sym, true, cd.digits, cd.digits)
	if loc_symbol_after(t) {
		return loc_str('${num} ${cd.symbol}')
	}
	return loc_str('${cd.symbol}${num}')
}

fn loc_symbol_after(t LocaleTag) bool {
	return t.language in ['de', 'fr', 'es', 'it', 'pt', 'nl', 'ru', 'pl', 'cs', 'sv', 'fi',
		'nb', 'da', 'el', 'tr', 'uk', 'ro']
}

// ── §3.5 Locale information ──────────────────────────────────────────

const loc_language_display = {
	'en': 'English'
	'de': 'German'
	'fr': 'French'
	'es': 'Spanish'
	'it': 'Italian'
	'pt': 'Portuguese'
	'nl': 'Dutch'
	'ja': 'Japanese'
	'zh': 'Chinese'
	'ko': 'Korean'
	'ru': 'Russian'
	'ar': 'Arabic'
	'he': 'Hebrew'
	'tr': 'Turkish'
	'pl': 'Polish'
	'sv': 'Swedish'
	'da': 'Danish'
	'fi': 'Finnish'
	'nb': 'Norwegian Bokmål'
	'cs': 'Czech'
	'el': 'Greek'
	'th': 'Thai'
	'vi': 'Vietnamese'
	'hi': 'Hindi'
	'id': 'Indonesian'
	'uk': 'Ukrainian'
	'ro': 'Romanian'
}

const loc_region_display = {
	'US': 'United States'
	'GB': 'United Kingdom'
	'DE': 'Germany'
	'FR': 'France'
	'ES': 'Spain'
	'IT': 'Italy'
	'BR': 'Brazil'
	'PT': 'Portugal'
	'NL': 'Netherlands'
	'JP': 'Japan'
	'CN': 'China'
	'TW': 'Taiwan'
	'KR': 'South Korea'
	'RU': 'Russia'
	'SA': 'Saudi Arabia'
	'IL': 'Israel'
	'TR': 'Turkey'
	'PL': 'Poland'
	'SE': 'Sweden'
	'DK': 'Denmark'
	'FI': 'Finland'
	'NO': 'Norway'
	'CZ': 'Czechia'
	'GR': 'Greece'
	'TH': 'Thailand'
	'VN': 'Vietnam'
	'IN': 'India'
	'ID': 'Indonesia'
	'UA': 'Ukraine'
	'RO': 'Romania'
}

fn loc_display_name(t LocaleTag) string {
	lang := loc_language_display[t.language] or { t.language }
	if t.region != '' {
		region := loc_region_display[t.region] or { t.region }
		return '${lang} (${region})'
	}
	return lang
}

// loc_is_supported: §4.1 — true at any fallback level. A structurally-valid
// tag always resolves to exact / language / synthetic-minimal data.
fn loc_is_supported(t LocaleTag) bool {
	_ := t
	return true
}

// ── §3.6 Locale-aware case mapping ───────────────────────────────────

fn loc_upper(s string, t LocaleTag) string {
	if t.language == 'tr' || t.language == 'az' {
		return loc_turkish_upper(s)
	}
	if t.language == 'lt' {
		return loc_lithuanian_upper(s)
	}
	return loc_default_upper(s)
}

fn loc_lower(s string, t LocaleTag) string {
	if t.language == 'tr' || t.language == 'az' {
		return loc_turkish_lower(s)
	}
	return loc_default_lower(s)
}

fn loc_title(s string, t LocaleTag) string {
	mut out := ''
	mut at_word_start := true
	for r in s.runes() {
		is_space := r == ` ` || r == `\t` || r == `\n`
		if is_space {
			out += r.str()
			at_word_start = true
			continue
		}
		if at_word_start {
			out += loc_upper(r.str(), t)
		} else {
			out += loc_lower(r.str(), t)
		}
		at_word_start = false
	}
	return out
}

fn loc_default_upper(s string) string {
	mut out := ''
	for r in s.runes() {
		if r == 0x00DF { // ß
			out += 'SS'
			continue
		}
		out += loc_upper_rune(r).str()
	}
	return out
}

fn loc_default_lower(s string) string {
	mut out := ''
	for r in s.runes() {
		out += loc_lower_rune(r).str()
	}
	return out
}

fn loc_upper_rune(r rune) rune {
	if r >= `a` && r <= `z` {
		return r - 32
	}
	if r >= 0x00E0 && r <= 0x00FE && r != 0x00F7 {
		return r - 32
	}
	return r
}

fn loc_lower_rune(r rune) rune {
	if r >= `A` && r <= `Z` {
		return r + 32
	}
	if r >= 0x00C0 && r <= 0x00DE && r != 0x00D7 {
		return r + 32
	}
	return r
}

// loc_turkish_upper: i → İ (U+0130), dotless ı (U+0131) → I.
fn loc_turkish_upper(s string) string {
	mut out := ''
	for r in s.runes() {
		match r {
			`i` { out += 'İ' }
			0x0131 { out += 'I' }
			0x00DF { out += 'SS' }
			else { out += loc_upper_rune(r).str() }
		}
	}
	return out
}

// loc_turkish_lower: I → ı (U+0131 dotless), İ (U+0130) → i.
fn loc_turkish_lower(s string) string {
	mut out := ''
	for r in s.runes() {
		match r {
			`I` { out += 'ı' }
			0x0130 { out += 'i' }
			else { out += loc_lower_rune(r).str() }
		}
	}
	return out
}

// loc_lithuanian_upper strips the explicit combining-dot-above on uppercase.
fn loc_lithuanian_upper(s string) string {
	mut out := ''
	for r in s.runes() {
		if r == 0x0307 {
			continue
		}
		out += loc_upper_rune(r).str()
	}
	return out
}

// ── §3.5 default-locale env read ─────────────────────────────────────

// loc_env_lang reads $LANG / $LC_ALL and extracts the BCP-47-ish tag,
// falling back to "en-US" (§3.5 / §4.1).
fn loc_env_lang() string {
	for key in ['LC_ALL', 'LC_MESSAGES', 'LANG'] {
		raw := os.getenv(key)
		if raw != '' {
			mut tag := raw
			if tag.contains('.') {
				dot := tag.index('.') or { tag.len }
				tag = tag[..dot]
			}
			if tag.contains('@') {
				at := tag.index('@') or { tag.len }
				tag = tag[..at]
			}
			tag = tag.replace('_', '-')
			if tag == 'C' || tag == 'POSIX' || tag == '' {
				continue
			}
			if _ := loc_parse_tag(tag) {
				return tag
			}
		}
	}
	return 'en-US'
}

// ── date-value reader ────────────────────────────────────────────────

fn loc_date_parts_of(n cx.Node) ?DateTimeParts {
	s := loc_arg_str(n) or { return none }
	return loc_parse_iso(s)
}

// loc_parse_date_with_pattern parses a formatted date given a pattern. The
// first-landing scope covers numeric ICU patterns (y/M/d/H/h/m/s tokens
// separated by literals), recovering the date components positionally.
fn loc_parse_date_with_pattern(s string, t LocaleTag, pattern string) ?DateTimeParts {
	_ := t
	rs := pattern.runes()
	sr := s.runes()
	mut pi := 0
	mut si := 0
	mut p := DateTimeParts{
		year:  1970
		month: 1
		day:   1
	}
	for pi < rs.len {
		r := rs[pi]
		if r < 128 && loc_is_alpha(u8(r)) {
			mut run := 1
			for pi + run < rs.len && rs[pi + run] == r {
				run++
			}
			pi += run
			start := si
			for si < sr.len && sr[si] >= `0` && sr[si] <= `9` {
				si++
			}
			if si == start {
				return none
			}
			val := loc_runes_to_str(sr[start..si]).int()
			match u8(r) {
				`y` { p.year = val }
				`M` { p.month = val }
				`d` { p.day = val }
				`H`, `h` { p.hour = val }
				`m` { p.minute = val }
				`s` { p.second = val }
				else {}
			}
		} else {
			if si >= sr.len || sr[si] != r {
				return none
			}
			pi++
			si++
		}
	}
	if p.month < 1 || p.month > 12 || p.day < 1 || p.day > 31 {
		return none
	}
	return p
}

// ── dispatch ─────────────────────────────────────────────────────────

fn locale_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'locale-collate' {
			a := loc_arg_str(args[0]) or { return none }
			b := loc_arg_str(args[1]) or { return none }
			loc := loc_arg_str(args[2]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			if !loc_has_collation_data(t) {
				return loc_err_data_unavailable('no collation data for "${loc}"')
			}
			mut o := loc_default_collate_opts()
			o.locale = loc
			return loc_int(i64(loc_collate_compare(a, b, o)))
		}
		'locale-collate-with-opts' {
			a := loc_arg_str(args[0]) or { return none }
			b := loc_arg_str(args[1]) or { return none }
			o := loc_read_collate_opts(args[2])
			t := loc_parse_tag(o.locale) or { return loc_err_tag_invalid('"${o.locale}"') }
			if !loc_has_collation_data(t) {
				return loc_err_data_unavailable('no collation data for "${o.locale}"')
			}
			return loc_int(i64(loc_collate_compare(a, b, o)))
		}
		'locale-collate-key' {
			s := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			if !loc_has_collation_data(t) {
				return loc_err_data_unavailable('no collation data for "${loc}"')
			}
			mut o := loc_default_collate_opts()
			o.locale = loc
			return loc_bytes(loc_collate_key(s, o))
		}
		'locale-format-number' {
			n := loc_arg_num(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			mut o := loc_default_number_opts()
			o.locale = loc
			return loc_str(loc_format_number(n, t, o))
		}
		'locale-format-number-with-opts' {
			n := loc_arg_num(args[0]) or { return none }
			o := loc_read_number_opts(args[1])
			t := loc_parse_tag(o.locale) or { return loc_err_tag_invalid('"${o.locale}"') }
			return loc_str(loc_format_number(n, t, o))
		}
		'locale-parse-number-locale' {
			s := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			v := loc_parse_number(s, t) or {
				return loc_err_number_parse('"${s}" not valid for "${loc}"')
			}
			return loc_float(v)
		}
		'locale-format-date' {
			p := loc_date_parts_of(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			pattern := loc_arg_str(args[2]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			if !loc_valid_pattern(pattern) {
				return loc_err_pattern_invalid('"${pattern}"')
			}
			return loc_str(loc_format_pattern(p, t, pattern))
		}
		'locale-format-datetime' {
			p := loc_date_parts_of(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			pattern := loc_arg_str(args[2]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			if !loc_valid_pattern(pattern) {
				return loc_err_pattern_invalid('"${pattern}"')
			}
			return loc_str(loc_format_pattern(p, t, pattern))
		}
		'locale-format-date-style' {
			p := loc_date_parts_of(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			style := loc_arg_atom(args[2]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			pattern := loc_style_pattern(t, style) or {
				return loc_err_pattern_invalid('unknown style ":${style}"')
			}
			return loc_str(loc_format_pattern(p, t, pattern))
		}
		'locale-parse-date-locale' {
			s := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			pattern := loc_arg_str(args[2]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			if !loc_valid_pattern(pattern) {
				return loc_err_pattern_invalid('"${pattern}"')
			}
			p := loc_parse_date_with_pattern(s, t, pattern) or {
				return loc_err_pattern_invalid('"${s}" does not match "${pattern}"')
			}
			mut ys := p.year.str()
			for ys.len < 4 {
				ys = '0' + ys
			}
			return loc_date('${ys}-${loc_pad2(p.month)}-${loc_pad2(p.day)}')
		}
		'locale-format-currency' {
			n := loc_arg_num(args[0]) or { return none }
			currency := loc_arg_str(args[1]) or { return none }
			loc := loc_arg_str(args[2]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_format_currency(n, currency, t)
		}
		'locale-currency-symbol' {
			currency := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			cd := loc_currency_table[currency.to_upper()] or {
				return loc_err_currency_invalid('unknown ISO 4217 code "${currency}"')
			}
			return loc_str(cd.symbol)
		}
		'locale-list-locales' {
			mut items := []cx.Node{}
			for l in loc_catalog {
				items << loc_str(l)
			}
			return loc_seq(items)
		}
		'locale-is-supported' {
			loc := loc_arg_str(args[0]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_bool(loc_is_supported(t))
		}
		'locale-default-locale' {
			return loc_str(loc_env_lang())
		}
		'locale-locale-name' {
			loc := loc_arg_str(args[0]) or { return none }
			loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(loc_display_name(t))
		}
		'locale-language-of' {
			loc := loc_arg_str(args[0]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(t.language)
		}
		'locale-country-of' {
			loc := loc_arg_str(args[0]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(t.region)
		}
		'locale-script-of' {
			loc := loc_arg_str(args[0]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(t.script)
		}
		'locale-text-direction' {
			loc := loc_arg_str(args[0]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_atom(if loc_is_rtl_language(t.language) { 'rtl' } else { 'ltr' })
		}
		'locale-upper-locale' {
			s := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(loc_upper(s, t))
		}
		'locale-lower-locale' {
			s := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(loc_lower(s, t))
		}
		'locale-title-locale' {
			s := loc_arg_str(args[0]) or { return none }
			loc := loc_arg_str(args[1]) or { return none }
			t := loc_parse_tag(loc) or { return loc_err_tag_invalid('"${loc}"') }
			return loc_str(loc_title(s, t))
		}
		else {
			return none
		}
	}
}

// ── bundled module source (stdlib/locale.cx is the same bytes) ───────
// The `[?def]` public surface (spec/std-lib/locale.md §3) forwarding to the
// `locale-`-prefixed native primitives above. Per-module ownership: this
// const lives here (mirrors stdlib_hash/env/validate). NOTE: this const is
// $embed_file-d from stdlib/locale.cx — edit that file.
const stdlib_src_locale = $embed_file('../stdlib/locale.cx').to_string()
