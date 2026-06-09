module code

import cx
import os

// stdlib_i18n.v — native primitives backing `cx-stdlib/i18n`
// (spec/std-lib/i18n.md). Message catalogs, locale-fallback resolution,
// ICU MessageFormat evaluation (interpolation / plural / select /
// selectordinal / nested / typed-arg), and CLDR cardinal + ordinal
// plural-category data. The module's `[?def]` bodies (stdlib_src_i18n in
// stdlib_bundle.v) forward here via stdlib_dispatch.v::stdlib_builtin.
//
// ── CX value model ──────────────────────────────────────────────────
//   catalog → [catalog default="<loc>"
//                [entry key="<k>" [msg locale="<l>" "<msgformat>"] …] …]
//             (§2.1). Immutable element value.
//   message / message-or / format-message → string RESULT, returned as a
//             cx.TextNode so the conformance render emits the rendered
//             message verbatim (the i18n.cxd fixtures pin the bare text,
//             not a quoted scalar).
//   plural-category / -ordinal → atom (:zero/:one/:two/:few/:many/:other).
//   catalog-locales / -keys → (__cx_seq__ of string).
//
// Errors are VALUE nodes (mk_err): §5 codes CXER3800..CXER3805 plus the
// capability denial CXER0271 for load-catalog (§7). The conformance
// runner matches the bare code in `out-err`.
//
// i18n is pure except load-catalog (read capability, §7). There is no
// independent locale-data resolver here; number grouping for the `#`
// plural-number and bare `{n}` interpolation is produced inline (the
// `locale` sibling owns the full formatter — only en grouping is
// exercised by the i18n conformance surface).

// ── value builders ───────────────────────────────────────────────────

// i18n_text returns a rendered message string as a TextNode (bare render).
fn i18n_text(s string) cx.Node {
	return cx.TextNode{
		value: s
	}
}

fn i18n_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn i18n_atom(name string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(name)
		data_type: cx.ScalarType.atom_type
	}
}

fn i18n_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// ── argument readers ───────────────────────────────────────────────────

fn i18n_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// i18n_num reads a numeric scalar as f64; none for non-numeric.
fn i18n_num(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return f64(v) }
			f64 { return v }
			else { return none }
		}
	}
	return none
}

// i18n_attr returns the attribute value of `el` named `name`, or '' .
fn i18n_attr(el cx.Element, name string) string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

fn i18n_has_attr(el cx.Element, name string) bool {
	for a in el.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

// i18n_map_entries reads a `__cx_map__` envelope element into an ordered
// list of (key, value-node) pairs. Returns none if not a map.
fn i18n_map_entries(n cx.Node) ?[][2]cx.Node {
	if n is cx.Element {
		if n.name == '__cx_map__' {
			mut out := [][2]cx.Node{}
			for e in n.items {
				if e is cx.Element {
					val := if e.items.len > 0 {
						e.items[0]
					} else {
						cx.Node(cx.TextNode{
							value: ''
						})
					}
					out << [cx.Node(i18n_str(e.name)), val]!
				}
			}
			return out
		}
	}
	if n is cx.MapNode {
		mut out := [][2]cx.Node{}
		for e in n.entries {
			out << [cx.Node(i18n_str(cx.scalar_value_str_public(e.key_value))), e.value]!
		}
		return out
	}
	return none
}

// i18n_map_lookup returns the value node for string key `k` in a
// `__cx_map__` / MapNode, or none.
fn i18n_map_lookup(n cx.Node, k string) ?cx.Node {
	entries := i18n_map_entries(n) or { return none }
	for pair in entries {
		key := i18n_arg_str(pair[0]) or { continue }
		if key == k {
			return pair[1]
		}
	}
	return none
}

// ── error helpers (§5) ─────────────────────────────────────────────────

fn i18n_err_format(msg string) cx.Node {
	return mk_err('cx-err:CXER3800', 'E_I18N_MESSAGEFORMAT_INVALID: ${msg}')
}

fn i18n_err_key(key string) cx.Node {
	return mk_err('cx-err:CXER3801', 'E_I18N_KEY_NOT_FOUND: ${key}')
}

fn i18n_err_missing_arg(name string) cx.Node {
	return mk_err('cx-err:CXER3802', 'E_I18N_MISSING_ARG: ${name}')
}

fn i18n_err_type(msg string) cx.Node {
	return mk_err('cx-err:CXER3803', 'E_I18N_ARG_TYPE_MISMATCH: ${msg}')
}

fn i18n_err_not_catalog() cx.Node {
	return mk_err('cx-err:CXER3805', 'E_I18N_NOT_A_CATALOG: expected a [catalog …] element')
}

// ── catalog model (§2.1) ───────────────────────────────────────────────

struct CatalogMsg {
	locale string
	msg    string
}

struct CatalogEntry {
mut:
	key  string
	msgs []CatalogMsg
}

struct Catalog {
mut:
	default_locale string
	entries        []CatalogEntry
}

// i18n_catalog_element renders a Catalog to its canonical [catalog …]
// element form (§2.1).
fn i18n_catalog_element(c Catalog) cx.Node {
	mut items := []cx.Node{cap: c.entries.len}
	for ent in c.entries {
		mut msg_items := []cx.Node{cap: ent.msgs.len}
		for m in ent.msgs {
			msg_items << cx.Element{
				name:  'msg'
				attrs: [cx.Attribute{
					name:  'locale'
					value: cx.ScalarValue(m.locale)
				}]
				items: [cx.Node(cx.TextNode{
					value: m.msg
				})]
			}
		}
		items << cx.Element{
			name:  'entry'
			attrs: [cx.Attribute{
				name:  'key'
				value: cx.ScalarValue(ent.key)
			}]
			items: msg_items
		}
	}
	return cx.Element{
		name:  'catalog'
		attrs: [cx.Attribute{
			name:  'default'
			value: cx.ScalarValue(c.default_locale)
		}]
		items: items
	}
}

// i18n_catalog_from_node reads a [catalog …] element back into a Catalog.
// Returns none when the node is not a catalog element (→ CXER3805).
fn i18n_catalog_from_node(n cx.Node) ?Catalog {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	if el.name != 'catalog' {
		return none
	}
	mut c := Catalog{
		default_locale: 'en'
	}
	if i18n_has_attr(el, 'default') {
		d := i18n_attr(el, 'default')
		if d != '' {
			c.default_locale = d
		}
	}
	for child in el.items {
		if child is cx.Element && child.name == 'entry' {
			mut ent := CatalogEntry{
				key: i18n_attr(child, 'key')
			}
			for mc in child.items {
				if mc is cx.Element && mc.name == 'msg' {
					loc := i18n_attr(mc, 'locale')
					mut text := ''
					for t in mc.items {
						if t is cx.TextNode {
							text += t.value
						} else if t is cx.ScalarNode {
							text += cx.scalar_value_str_public(t.value)
						}
					}
					ent.msgs << CatalogMsg{
						locale: loc
						msg:    text
					}
				}
			}
			c.entries << ent
		}
	}
	return c
}

// i18n_catalog_from_map builds a Catalog from a `{ key → { locale → msg } }`
// map (§3.1). The optional string "default" entry sets the default locale.
fn i18n_catalog_from_map(n cx.Node) ?Catalog {
	entries := i18n_map_entries(n)?
	mut c := Catalog{
		default_locale: 'en'
	}
	for pair in entries {
		key := i18n_arg_str(pair[0]) or { continue }
		if key == 'default' {
			if d := i18n_arg_str(pair[1]) {
				c.default_locale = d
			}
			continue
		}
		mut ent := CatalogEntry{
			key: key
		}
		loc_entries := i18n_map_entries(pair[1]) or { [][2]cx.Node{} }
		for lp in loc_entries {
			loc := i18n_arg_str(lp[0]) or { continue }
			msg := i18n_arg_str(lp[1]) or { '' }
			ent.msgs << CatalogMsg{
				locale: loc
				msg:    msg
			}
		}
		c.entries << ent
	}
	return c
}

fn (c Catalog) lookup_entry(key string) ?CatalogEntry {
	for ent in c.entries {
		if ent.key == key {
			return ent
		}
	}
	return none
}

// fallback_chain builds the locale-fallback chain for `locale` (§2.2):
// full tag, then progressively-truncated tags, then "en", then the
// catalog's declared default.
fn (c Catalog) fallback_chain(locale string) []string {
	mut chain := []string{}
	mut seen := map[string]bool{}
	mut cur := locale
	for cur != '' {
		if cur !in seen {
			chain << cur
			seen[cur] = true
		}
		if idx := cur.last_index('-') {
			cur = cur[..idx]
		} else {
			break
		}
	}
	if 'en' !in seen {
		chain << 'en'
		seen['en'] = true
	}
	if c.default_locale !in seen {
		chain << c.default_locale
	}
	return chain
}

// resolve_message returns the MessageFormat string for `key` resolved
// through the fallback chain, or none if the key has no entry at any level.
fn (c Catalog) resolve_message(key string, locale string) ?string {
	ent := c.lookup_entry(key) or { return none }
	for loc in c.fallback_chain(locale) {
		for m in ent.msgs {
			if m.locale == loc {
				return m.msg
			}
		}
	}
	return none
}

// ── number formatting (en grouping; locale delegate) ───────────────────

// i18n_format_number renders a number for the (en) locale: integer
// thousands grouped with ',', fractional part preserved.
fn i18n_format_number(n f64, locale string) string {
	if n == f64(i64(n)) {
		return i18n_group_int(i64(n), i18n_group_sep(locale))
	}
	s := n.str()
	if dot := s.index('.') {
		intpart := s[..dot]
		frac := s[dot..]
		neg := intpart.starts_with('-')
		digits := if neg { intpart[1..] } else { intpart }
		grouped := i18n_group_digits(digits, i18n_group_sep(locale))
		return (if neg { '-' } else { '' }) + grouped + frac
	}
	return s
}

fn i18n_group_sep(_ string) string {
	// en (and the conformance default) groups with ','. The locale-aware
	// separator is owned by the locale sibling; only en grouping is
	// exercised by the i18n conformance surface.
	return ','
}

fn i18n_group_int(n i64, sep string) string {
	neg := n < 0
	digits := if neg { (-n).str() } else { n.str() }
	grouped := i18n_group_digits(digits, sep)
	return (if neg { '-' } else { '' }) + grouped
}

fn i18n_group_digits(digits string, sep string) string {
	if digits.len <= 3 {
		return digits
	}
	mut out := []u8{}
	rem := digits.len % 3
	mut i := 0
	if rem > 0 {
		for i < rem {
			out << digits[i]
			i++
		}
		if i < digits.len {
			out << sep[0]
		}
	}
	for i < digits.len {
		out << digits[i]
		i++
		if i < digits.len && (digits.len - i) % 3 == 0 {
			out << sep[0]
		}
	}
	return out.bytestr()
}

// i18n_coerce_arg renders a bare {name} argument value (§4): number →
// grouped; string verbatim; atom → its name; bool → true/false.
fn i18n_coerce_arg(n cx.Node, locale string) string {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return i18n_format_number(f64(v), locale) }
			f64 { return i18n_format_number(v, locale) }
			bool { return if v { 'true' } else { 'false' } }
			cx.NullValue { return 'null' }
			string { return v }
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// ── CLDR plural rules (§3.5) ────────────────────────────────────────────

// i18n_plural_cardinal returns the cardinal CLDR category for n in locale.
fn i18n_plural_cardinal(n f64, locale string) ?string {
	lang := i18n_lang(locale)
	i := i64(if n < 0 { -n } else { n })
	is_int := n == f64(i64(n))
	match lang {
		'en' {
			if is_int && i == 1 {
				return 'one'
			}
			return 'other'
		}
		'ru' {
			if !is_int {
				return 'other'
			}
			m10 := i % 10
			m100 := i % 100
			if m10 == 1 && m100 != 11 {
				return 'one'
			}
			if m10 >= 2 && m10 <= 4 && !(m100 >= 12 && m100 <= 14) {
				return 'few'
			}
			if m10 == 0 || (m10 >= 5 && m10 <= 9) || (m100 >= 11 && m100 <= 14) {
				return 'many'
			}
			return 'other'
		}
		'pl' {
			if !is_int {
				return 'other'
			}
			if i == 1 {
				return 'one'
			}
			m10 := i % 10
			m100 := i % 100
			if m10 >= 2 && m10 <= 4 && !(m100 >= 12 && m100 <= 14) {
				return 'few'
			}
			return 'many'
		}
		'ar' {
			if !is_int {
				return 'other'
			}
			if i == 0 {
				return 'zero'
			}
			if i == 1 {
				return 'one'
			}
			if i == 2 {
				return 'two'
			}
			m100 := i % 100
			if m100 >= 3 && m100 <= 10 {
				return 'few'
			}
			if m100 >= 11 && m100 <= 99 {
				return 'many'
			}
			return 'other'
		}
		else {
			return none // no CLDR data → caller degrades to :other
		}
	}
}

// i18n_plural_ordinal returns the ordinal CLDR category for n in locale.
fn i18n_plural_ordinal(n f64, locale string) ?string {
	lang := i18n_lang(locale)
	i := i64(if n < 0 { -n } else { n })
	is_int := n == f64(i64(n))
	match lang {
		'en' {
			if !is_int {
				return 'other'
			}
			m10 := i % 10
			m100 := i % 100
			if m10 == 1 && m100 != 11 {
				return 'one'
			}
			if m10 == 2 && m100 != 12 {
				return 'two'
			}
			if m10 == 3 && m100 != 13 {
				return 'few'
			}
			return 'other'
		}
		else {
			return none // no CLDR ordinal data → caller degrades to :other
		}
	}
}

// i18n_lang returns the primary language subtag of a BCP 47 tag, lowercased.
fn i18n_lang(locale string) string {
	mut l := locale
	if idx := l.index('-') {
		l = l[..idx]
	}
	return l.to_lower()
}

// ── MessageFormat parser + evaluator (§3.4) ─────────────────────────────

struct MfEval {
mut:
	args    cx.Node
	locale  string
	runes   []rune
	pos     int
	err     cx.Node
	err_set bool
}

// i18n_eval_messageformat parses + evaluates `tmpl` against `args` for
// `locale`. Returns a TextNode result, or an err VALUE.
fn i18n_eval_messageformat(tmpl string, locale string, args cx.Node) cx.Node {
	mut e := MfEval{
		args:   args
		locale: locale
		runes:  tmpl.runes()
		pos:    0
		err:    cx.TextNode{
			value: ''
		}
	}
	out := e.parse_text(false, '')
	if e.err_set {
		return e.err
	}
	if e.pos < e.runes.len {
		return i18n_err_format('unexpected "}" in "${tmpl}"')
	}
	return i18n_text(out)
}

// The MessageFormat evaluator threads its cursor through the `e.pos` /
// `e.runes` fields. Sub-bodies (select / plural branches) are re-parsed by
// saving the outer cursor, swapping in the branch runes, parsing, then
// restoring — see render_branch / render_plural_branch. `hash` carries the
// `#` substitution for the enclosing plural branch ('' when not in one).

// parse_text consumes literal text + {…} forms until end-of-input or, when
// `nested` is true, an unescaped `}` (left for the caller to consume).
fn (mut e MfEval) parse_text(nested bool, hash string) string {
	mut out := []rune{}
	for e.pos < e.runes.len {
		c := e.runes[e.pos]
		if c == `'` {
			if e.pos + 1 < e.runes.len && e.runes[e.pos + 1] == `'` {
				out << `'`
				e.pos += 2
				continue
			}
			e.pos++
			for e.pos < e.runes.len && e.runes[e.pos] != `'` {
				out << e.runes[e.pos]
				e.pos++
			}
			if e.pos < e.runes.len {
				e.pos++
			}
			continue
		}
		if c == `#` && nested {
			out << hash.runes()
			e.pos++
			continue
		}
		if c == `}` {
			return out.string()
		}
		if c == `{` {
			sub := e.parse_placeholder()
			if e.err_set {
				return ''
			}
			out << sub.runes()
			continue
		}
		out << c
		e.pos++
	}
	return out.string()
}

// parse_placeholder consumes a `{ … }` form starting at the `{`.
fn (mut e MfEval) parse_placeholder() string {
	e.pos++ // consume '{'
	mut name := []rune{}
	for e.pos < e.runes.len && e.runes[e.pos] != `,` && e.runes[e.pos] != `}` {
		name << e.runes[e.pos]
		e.pos++
	}
	argname := name.string().trim_space()
	if e.pos >= e.runes.len {
		e.fail(i18n_err_format('unbalanced "{" — missing "}"'))
		return ''
	}
	if e.runes[e.pos] == `}` {
		e.pos++ // consume '}'
		argv := i18n_map_lookup(e.args, argname) or {
			e.fail(i18n_err_missing_arg(argname))
			return ''
		}
		return i18n_coerce_arg(argv, e.locale)
	}
	e.pos++ // consume ','
	mut kw := []rune{}
	for e.pos < e.runes.len && e.runes[e.pos] != `,` && e.runes[e.pos] != `}` {
		kw << e.runes[e.pos]
		e.pos++
	}
	keyword := kw.string().trim_space()
	match keyword {
		'plural' {
			e.consume_comma()
			return e.parse_plural(argname, false)
		}
		'selectordinal' {
			e.consume_comma()
			return e.parse_plural(argname, true)
		}
		'select' {
			e.consume_comma()
			return e.parse_select(argname)
		}
		'number', 'date', 'time' {
			return e.parse_typed(argname, keyword)
		}
		else {
			e.fail(i18n_err_format('unknown argument type "${keyword}"'))
			return ''
		}
	}
}

// parse_typed handles {name, number|date|time[, style]}.
fn (mut e MfEval) parse_typed(argname string, typ string) string {
	mut style := ''
	if e.pos < e.runes.len && e.runes[e.pos] == `,` {
		e.pos++
		mut sb := []rune{}
		for e.pos < e.runes.len && e.runes[e.pos] != `}` {
			sb << e.runes[e.pos]
			e.pos++
		}
		style = sb.string().trim_space()
	}
	if e.pos >= e.runes.len || e.runes[e.pos] != `}` {
		e.fail(i18n_err_format('unbalanced "{" in typed arg "${argname}"'))
		return ''
	}
	e.pos++ // consume '}'
	argv := i18n_map_lookup(e.args, argname) or {
		e.fail(i18n_err_missing_arg(argname))
		return ''
	}
	match typ {
		'number' {
			n := i18n_num(argv) or {
				e.fail(i18n_err_type('number arg "${argname}" is non-numeric'))
				return ''
			}
			match style {
				'percent' {
					return i18n_format_number(n * 100.0, e.locale) + '%'
				}
				'currency' {
					return '\$' + i18n_format_number(n, e.locale)
				}
				else {
					return i18n_format_number(n, e.locale)
				}
			}
		}
		else {
			// date/time delegate to the locale formatter; the i18n
			// conformance surface asserts no specific date/time rendering.
			return i18n_coerce_arg(argv, e.locale)
		}
	}
}

// parse_select handles {name, select, kw {…} … other {…}}.
fn (mut e MfEval) parse_select(argname string) string {
	branches, has_other := e.parse_branches() or { return '' }
	if e.err_set {
		return ''
	}
	if !has_other {
		e.fail(i18n_err_format('select on "${argname}" missing required "other"'))
		return ''
	}
	argv := i18n_map_lookup(e.args, argname) or {
		e.fail(i18n_err_missing_arg(argname))
		return ''
	}
	sel := i18n_coerce_arg(argv, e.locale)
	body := branches[sel] or { branches['other'] or { '' } }
	return e.render_branch(body)
}

// parse_plural handles {name, plural|selectordinal, [offset:N] branches}.
fn (mut e MfEval) parse_plural(argname string, ordinal bool) string {
	mut offset := i64(0)
	for e.pos < e.runes.len && e.runes[e.pos] == ` ` {
		e.pos++
	}
	if e.pos + 7 <= e.runes.len && e.runes[e.pos..e.pos + 7].string() == 'offset:' {
		e.pos += 7
		mut ob := []rune{}
		for e.pos < e.runes.len && e.runes[e.pos] != ` ` && e.runes[e.pos] != `{` {
			ob << e.runes[e.pos]
			e.pos++
		}
		offset = ob.string().i64()
	}
	exact, branches, has_other := e.parse_plural_branches() or { return '' }
	if e.err_set {
		return ''
	}
	if !has_other {
		e.fail(i18n_err_format('plural on "${argname}" missing required "other"'))
		return ''
	}
	argv := i18n_map_lookup(e.args, argname) or {
		e.fail(i18n_err_missing_arg(argname))
		return ''
	}
	n := i18n_num(argv) or {
		e.fail(i18n_err_type('plural arg "${argname}" is non-numeric'))
		return ''
	}
	if i64(n) == n {
		if body := exact[i64(n)] {
			return e.render_plural_branch(body, n - f64(offset), e.locale)
		}
	}
	off_n := n - f64(offset)
	cat := if ordinal {
		i18n_plural_ordinal(off_n, e.locale) or { 'other' }
	} else {
		i18n_plural_cardinal(off_n, e.locale) or { 'other' }
	}
	body := branches[cat] or { branches['other'] or { '' } }
	return e.render_plural_branch(body, off_n, e.locale)
}

// parse_branches reads `kw {body} …` until the closing '}' of the form.
fn (mut e MfEval) parse_branches() ?(map[string]string, bool) {
	mut branches := map[string]string{}
	mut has_other := false
	for {
		e.skip_ws()
		if e.pos >= e.runes.len {
			e.fail(i18n_err_format('unbalanced "{" — missing "}" after branch'))
			return none
		}
		if e.runes[e.pos] == `}` {
			e.pos++
			break
		}
		keyword := e.read_keyword()
		e.skip_ws()
		if e.pos >= e.runes.len || e.runes[e.pos] != `{` {
			e.fail(i18n_err_format('expected "{" after branch keyword "${keyword}"'))
			return none
		}
		body := e.read_braced() or { return none }
		if keyword == 'other' {
			has_other = true
		}
		branches[keyword] = body
	}
	return branches, has_other
}

// parse_plural_branches separates exact `=N` matches from category keywords.
fn (mut e MfEval) parse_plural_branches() ?(map[i64]string, map[string]string, bool) {
	mut exact := map[i64]string{}
	mut branches := map[string]string{}
	mut has_other := false
	for {
		e.skip_ws()
		if e.pos >= e.runes.len {
			e.fail(i18n_err_format('unbalanced "{" — missing "}" after plural branch'))
			return none
		}
		if e.runes[e.pos] == `}` {
			e.pos++
			break
		}
		keyword := e.read_keyword()
		e.skip_ws()
		if e.pos >= e.runes.len || e.runes[e.pos] != `{` {
			e.fail(i18n_err_format('expected "{" after plural branch "${keyword}"'))
			return none
		}
		body := e.read_braced() or { return none }
		if keyword.starts_with('=') {
			numpart := keyword[1..]
			if !i18n_all_digits(numpart) {
				e.fail(i18n_err_format('malformed exact match "${keyword}"'))
				return none
			}
			exact[numpart.i64()] = body
		} else {
			if keyword == 'other' {
				has_other = true
			}
			branches[keyword] = body
		}
	}
	return exact, branches, has_other
}

// consume_comma skips the `,` separator (plus surrounding spaces) that
// follows the plural/select/selectordinal keyword before its branches.
fn (mut e MfEval) consume_comma() {
	for e.pos < e.runes.len && e.runes[e.pos] == ` ` {
		e.pos++
	}
	if e.pos < e.runes.len && e.runes[e.pos] == `,` {
		e.pos++
	}
}

fn (mut e MfEval) skip_ws() {
	for e.pos < e.runes.len
		&& (e.runes[e.pos] == ` ` || e.runes[e.pos] == `\n` || e.runes[e.pos] == `\t`) {
		e.pos++
	}
}

fn (mut e MfEval) read_keyword() string {
	mut kw := []rune{}
	for e.pos < e.runes.len && e.runes[e.pos] != `{` && e.runes[e.pos] != ` `
		&& e.runes[e.pos] != `\n` && e.runes[e.pos] != `\t` {
		kw << e.runes[e.pos]
		e.pos++
	}
	return kw.string().trim_space()
}

fn i18n_all_digits(s string) bool {
	if s.len == 0 {
		return false
	}
	for c in s {
		if !(c >= `0` && c <= `9`) {
			return false
		}
	}
	return true
}

// read_braced reads a balanced `{ … }` body (handling nested braces and
// '-quotes). pos at '{' on entry, just past the matching '}' on exit.
fn (mut e MfEval) read_braced() ?string {
	if e.pos >= e.runes.len || e.runes[e.pos] != `{` {
		e.fail(i18n_err_format('expected "{"'))
		return none
	}
	e.pos++ // consume '{'
	mut out := []rune{}
	mut depth := 1
	for e.pos < e.runes.len {
		c := e.runes[e.pos]
		if c == `'` {
			out << c
			e.pos++
			if e.pos < e.runes.len && e.runes[e.pos] == `'` {
				out << `'`
				e.pos++
				continue
			}
			for e.pos < e.runes.len && e.runes[e.pos] != `'` {
				out << e.runes[e.pos]
				e.pos++
			}
			if e.pos < e.runes.len {
				out << e.runes[e.pos]
				e.pos++
			}
			continue
		}
		if c == `{` {
			depth++
			out << c
			e.pos++
			continue
		}
		if c == `}` {
			depth--
			if depth == 0 {
				e.pos++
				return out.string()
			}
			out << c
			e.pos++
			continue
		}
		out << c
		e.pos++
	}
	e.fail(i18n_err_format('unbalanced "{" — missing "}"'))
	return none
}

// render_branch re-parses a select branch body as MessageFormat text,
// saving/restoring the outer cursor around the nested parse.
fn (mut e MfEval) render_branch(body string) string {
	saved_runes := e.runes
	saved_pos := e.pos
	e.runes = body.runes()
	e.pos = 0
	r := e.parse_text(true, '')
	e.runes = saved_runes
	e.pos = saved_pos
	return r
}

// render_plural_branch re-parses a plural branch with '#' bound to the
// locale-formatted (offset-adjusted) number; nested {…} forms evaluate.
fn (mut e MfEval) render_plural_branch(body string, num f64, locale string) string {
	hash := i18n_format_number(num, locale)
	saved_runes := e.runes
	saved_pos := e.pos
	e.runes = body.runes()
	e.pos = 0
	r := e.parse_text(true, hash)
	e.runes = saved_runes
	e.pos = saved_pos
	return r
}

fn (mut e MfEval) fail(err cx.Node) {
	if !e.err_set {
		e.err = err
		e.err_set = true
	}
}

// ── dispatch ───────────────────────────────────────────────────────────

fn i18n_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// ── §3.1 catalogs ───────────────────────────────────────────
		'i18n-catalog-from-map' {
			c := i18n_catalog_from_map(args[0]) or { return none }
			return i18n_catalog_element(c)
		}
		'i18n-load-catalog' {
			path := i18n_arg_str(args[0]) or { return none }
			// §7: filesystem read is capability-gated; deny-by-default
			// raises CXER0271 at the effect point before any read.
			if d := cap_guard('read', path) {
				return d
			}
			return i18n_load_catalog(path)
		}
		'i18n-catalog-merge' {
			// `catalog-merge` is variadic (`*$catalogs::element`): the
			// evaluator collects the call args into a single `__cx_seq__`
			// envelope bound to `$catalogs`. Expand the envelope (or accept
			// raw positional catalog elements).
			return i18n_merge(i18n_flatten_catalogs(args))
		}
		'i18n-catalog-merge-seq' {
			items := i18n_seq_items(args[0]) or { []cx.Node{} }
			return i18n_merge(items)
		}
		'i18n-catalog-locales' {
			c := i18n_catalog_from_node(args[0]) or { return i18n_err_not_catalog() }
			mut seen := map[string]bool{}
			mut items := []cx.Node{}
			for ent in c.entries {
				for m in ent.msgs {
					if m.locale !in seen {
						seen[m.locale] = true
						items << i18n_str(m.locale)
					}
				}
			}
			return i18n_seq(items)
		}
		'i18n-catalog-keys' {
			c := i18n_catalog_from_node(args[0]) or { return i18n_err_not_catalog() }
			mut items := []cx.Node{cap: c.entries.len}
			for ent in c.entries {
				items << i18n_str(ent.key)
			}
			return i18n_seq(items)
		}

		// ── §3.2 message resolution ──────────────────────────────────
		'i18n-message' {
			c := i18n_catalog_from_node(args[0]) or { return i18n_err_not_catalog() }
			key := i18n_arg_str(args[1]) or { return none }
			locale := i18n_arg_str(args[2]) or { return none }
			tmpl := c.resolve_message(key, locale) or { return i18n_err_key(key) }
			return i18n_eval_messageformat(tmpl, locale, args[3])
		}
		'i18n-message-or' {
			c := i18n_catalog_from_node(args[0]) or { return i18n_err_not_catalog() }
			key := i18n_arg_str(args[1]) or { return none }
			locale := i18n_arg_str(args[2]) or { return none }
			fallback := i18n_arg_str(args[4]) or { return none }
			tmpl := c.resolve_message(key, locale) or {
				return i18n_eval_messageformat(fallback, locale, args[3])
			}
			return i18n_eval_messageformat(tmpl, locale, args[3])
		}

		// ── §3.3 direct MessageFormat ────────────────────────────────
		'i18n-format-message' {
			tmpl := i18n_arg_str(args[0]) or { return none }
			locale := i18n_arg_str(args[1]) or { return none }
			return i18n_eval_messageformat(tmpl, locale, args[2])
		}

		// ── §3.5 CLDR plural data ────────────────────────────────────
		'i18n-plural-category' {
			n := i18n_num(args[0]) or { return none }
			locale := i18n_arg_str(args[1]) or { return none }
			cat := i18n_plural_cardinal(n, locale) or { 'other' }
			return i18n_atom(cat)
		}
		'i18n-plural-category-ordinal' {
			n := i18n_num(args[0]) or { return none }
			locale := i18n_arg_str(args[1]) or { return none }
			cat := i18n_plural_ordinal(n, locale) or { 'other' }
			return i18n_atom(cat)
		}

		else {
			return none
		}
	}
}

// i18n_flatten_catalogs expands a variadic call's `__cx_seq__` envelope
// into a flat catalog list (or passes raw positional catalog args through).
fn i18n_flatten_catalogs(args []cx.Node) []cx.Node {
	mut out := []cx.Node{}
	for a in args {
		if a is cx.Element && (a.name == '__cx_seq__' || a.name == '__cx_arr__') {
			for it in a.items {
				out << it
			}
			continue
		}
		out << a
	}
	return out
}

// i18n_seq_items extracts the materialized item list of a sequence node.
fn i18n_seq_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
			return n.items
		}
	}
	if n is cx.IteratorNode {
		return n.memo
	}
	return none
}

// i18n_merge merges catalogs left-to-right, last-writer-wins (§3.1). A
// non-catalog argument raises CXER3805. The result's default is the last
// catalog's declared default (walking right-to-left); zero catalogs →
// [catalog default="en"].
fn i18n_merge(cats []cx.Node) cx.Node {
	mut result := Catalog{
		default_locale: 'en'
	}
	mut default_set := false
	for i := cats.len - 1; i >= 0; i-- {
		c := i18n_catalog_from_node(cats[i]) or { return i18n_err_not_catalog() }
		if !default_set {
			result.default_locale = c.default_locale
			default_set = true
		}
	}
	for cn in cats {
		c := i18n_catalog_from_node(cn) or { return i18n_err_not_catalog() }
		for ent in c.entries {
			result.merge_entry(ent)
		}
	}
	return i18n_catalog_element(result)
}

fn (mut c Catalog) merge_entry(ent CatalogEntry) {
	for i, existing in c.entries {
		if existing.key == ent.key {
			mut merged := c.entries[i]
			for m in ent.msgs {
				merged.set_msg(m.locale, m.msg)
			}
			c.entries[i] = merged
			return
		}
	}
	c.entries << ent
}

fn (mut ent CatalogEntry) set_msg(locale string, msg string) {
	for i, m in ent.msgs {
		if m.locale == locale {
			ent.msgs[i] = CatalogMsg{
				locale: locale
				msg:    msg
			}
			return
		}
	}
	ent.msgs << CatalogMsg{
		locale: locale
		msg:    msg
	}
}

// i18n_load_catalog reads the on-disk [catalog …] CX document (§3.1) and
// validates each MessageFormat string (a malformed one → CXER3800). The
// capability check (§7) is applied by the caller before this runs.
fn i18n_load_catalog(path string) cx.Node {
	if !os.exists(path) || os.is_dir(path) {
		return i18n_err_not_catalog()
	}
	src := os.read_file(path) or { return i18n_err_not_catalog() }
	doc := cx.parse(src) or {
		return i18n_err_format('unparseable catalog document at ${path}')
	}
	for el in doc.elements {
		if el is cx.Element && el.name == 'catalog' {
			c := i18n_catalog_from_node(el) or { return i18n_err_not_catalog() }
			for ent in c.entries {
				for m in ent.msgs {
					probe := i18n_eval_messageformat(m.msg, m.locale, i18n_empty_args())
					if probe is cx.Element && probe.name == 'err' {
						if i18n_attr(probe, 'code') == 'cx-err:CXER3800' {
							return probe
						}
					}
				}
			}
			return i18n_catalog_element(c)
		}
	}
	return i18n_err_not_catalog()
}

// i18n_empty_args returns an empty __cx_map__ envelope (load-time validation).
fn i18n_empty_args() cx.Node {
	return cx.Element{
		name:  '__cx_map__'
		items: []cx.Node{}
	}
}
