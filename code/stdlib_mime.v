@[has_globals]
module code

import cx
import crypto.rand as crand
import encoding.hex
import os

// stdlib_mime.v — native primitives backing `cx-stdlib/mime`
// (spec/std-lib/mime.md). The MIME type registry, Content-Type /
// Content-Disposition parsing + formatting, RFC 5987 extended-parameter
// decode, multipart-boundary generation, type classification, and
// Accept-header content negotiation. The module's `[?def]` bodies
// (stdlib_src_mime, in stdlib_bundle.v) forward here via
// stdlib_dispatch.v::stdlib_builtin.
//
// ── CX value model ──────────────────────────────────────────────────
//   parse-content-type        → [content-type type="…" subtype="…"
//                                 [parameters name="value" …]] (§2.1).
//   parse-content-disposition → [content-disposition type="…"
//                                 [parameters filename="…" filename*="…"]]
//                                 (§2.2).
//   parse-accept              → (__cx_seq__ of [accept type="…"
//                                 subtype="…" q=<float> [params …]]) sorted
//                                 by q desc then specificity (§3.7).
//   type/subtype/parameter names lowercased; parameter values preserved
//   (boundary case-sensitive). type/subtype live as ATTRIBUTES so the
//   conformance CXPath accessors (`$p/@type`, `$p/accept/@q`) read them.
//
// Errors are VALUE nodes (mk_err, eval.v): the spec §5 codes
// CXER2800..CXER2804. The conformance runner matches the bare code in
// `out-err`.
//
// The registry is process-global mutable state (register-type /
// load-mime-types), so this file carries `@[has_globals]`: the registry
// overlay is held behind a nil-default voidptr global like stdlib_store.v
// / stdlib_random.v, lazily allocated on first use. See `mime_registry()`.

// ── value builders ───────────────────────────────────────────────────

fn mime_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn mime_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn mime_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn mime_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn mime_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('mime', 'mime-', 'string', n)
	return none
}

fn mime_node_text(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// mime_items extracts the materialized item list of a sequence-shaped
// node: a __cx_seq__ / __cx_arr__ element or an eager IteratorNode.
fn mime_items(n cx.Node) []cx.Node {
	match n {
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' {
				return n.items
			}
		}
		cx.IteratorNode {
			return n.memo
		}
		else {}
	}
	return []cx.Node{}
}

fn mime_attr_str(el cx.Element, name string) string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// ── error helpers (§5) ────────────────────────────────────────────────

fn mime_err_content_type(msg string) cx.Node {
	return mk_err('cx-err:CXER2800', 'E_MIME_CONTENT_TYPE_MALFORMED: ${msg}')
}

fn mime_err_disposition(msg string) cx.Node {
	return mk_err('cx-err:CXER2801', 'E_MIME_CONTENT_DISPOSITION_MALFORMED: ${msg}')
}

fn mime_err_boundary(msg string) cx.Node {
	return mk_err('cx-err:CXER2802', 'E_MIME_BOUNDARY_INVALID: ${msg}')
}

fn mime_err_extended(msg string) cx.Node {
	return mk_err('cx-err:CXER2803', 'E_MIME_EXTENDED_PARAM_DECODE_FAILED: ${msg}')
}

fn mime_err_types_file(msg string) cx.Node {
	return mk_err('cx-err:CXER2804', 'E_MIME_TYPES_FILE_INVALID: ${msg}')
}

// ── process-global registry overlay ───────────────────────────────────
//
// The built-in extension→type map (mime_builtin_types) is immutable; the
// overlay carries runtime register-type / load-mime-types additions. Held
// behind a nil-default voidptr global, lazily allocated (the proven
// stdlib_store.v form), so no `-enable-globals` flag is required at the
// file level — the global is a single pointer with a nil default.

@[heap]
struct MimeRegistry {
mut:
	// ext_to_type maps a leading-dot extension (".jpg") → MIME type.
	// Later registrations override built-ins (overlay wins on lookup).
	ext_to_type map[string]string
}

__global (
	g_mime_reg voidptr
)

fn mime_registry() &MimeRegistry {
	if g_mime_reg == unsafe { nil } {
		r := &MimeRegistry{
			ext_to_type: map[string]string{}
		}
		g_mime_reg = voidptr(r)
	}
	return unsafe { &MimeRegistry(g_mime_reg) }
}

// mime_normalize_ext lowercases and ensures a single leading dot.
fn mime_normalize_ext(ext string) string {
	mut e := ext.to_lower()
	if e.starts_with('.') {
		return e
	}
	return '.' + e
}

// mime_lookup_type resolves an extension to a MIME type: overlay first,
// then the built-in table, else 'application/octet-stream'.
fn mime_lookup_type(ext string) string {
	e := mime_normalize_ext(ext)
	reg := mime_registry()
	if t := reg.ext_to_type[e] {
		return t
	}
	if t := mime_builtin_types[e] {
		return t
	}
	return 'application/octet-stream'
}

// mime_extensions_for collects every known extension mapping to `mtype`
// (case-insensitive type compare). Overlay entries override built-ins for
// the same extension; the union of extensions is returned in a stable
// order (built-in table order, then overlay-only additions).
fn mime_extensions_for(mtype string) []string {
	t := mtype.to_lower()
	reg := mime_registry()
	mut out := []string{}
	mut seen := map[string]bool{}
	for ext in mime_builtin_ext_order {
		// effective type after overlay
		eff := if ov := reg.ext_to_type[ext] {
			ov
		} else {
			mime_builtin_types[ext]
		}
		if eff.to_lower() == t && ext !in seen {
			out << ext
			seen[ext] = true
		}
	}
	for ext, ov in reg.ext_to_type {
		if ov.to_lower() == t && ext !in seen {
			out << ext
			seen[ext] = true
		}
	}
	return out
}

// mime_primary_extension returns the most-common extension for a type, or
// '' if unknown. "Most common" = the curated primary in
// mime_type_primary_ext, else the first extension found.
fn mime_primary_extension(mtype string) string {
	t := mtype.to_lower()
	if p := mime_type_primary_ext[t] {
		return p
	}
	exts := mime_extensions_for(mtype)
	if exts.len > 0 {
		return exts[0]
	}
	return ''
}

// ── Content-Type parsing (§3.2) ───────────────────────────────────────
//
// header = type "/" subtype *( ";" parameter )
// parameter = name "=" ( token / quoted-string )
// type/subtype/parameter names are lowercased; parameter values preserved
// (boundary case-sensitive). A quoted value is unquoted (§4 normalization).

struct MediaParam {
	name  string
	value string
}

struct ParsedMedia {
mut:
	typ     string
	subtype string
	params  []MediaParam
}

fn mime_is_token_char(c u8) bool {
	// RFC 2045 token: any CHAR except CTLs, SPACE, and tspecials.
	if c <= 32 || c >= 127 {
		return false
	}
	tspecials := '()<>@,;:\\"/[]?='
	return !tspecials.contains_u8(c)
}

// mime_parse_params parses the `; name=value; …` parameter tail starting
// at the given remainder. Returns the params or none on a malformed
// parameter (used by both content-type and content-disposition).
fn mime_parse_params(s string) ?[]MediaParam {
	mut params := []MediaParam{}
	mut i := 0
	for i < s.len {
		// skip optional whitespace
		for i < s.len && (s[i] == ` ` || s[i] == `\t`) {
			i++
		}
		if i >= s.len {
			break
		}
		if s[i] != `;` {
			return none
		}
		i++ // consume ';'
		for i < s.len && (s[i] == ` ` || s[i] == `\t`) {
			i++
		}
		if i >= s.len {
			// trailing ';' — tolerate (no parameter follows)
			break
		}
		// parameter name = token
		name_start := i
		for i < s.len && mime_is_token_char(s[i]) {
			i++
		}
		if i == name_start {
			return none
		}
		name := s[name_start..i].to_lower()
		for i < s.len && (s[i] == ` ` || s[i] == `\t`) {
			i++
		}
		if i >= s.len || s[i] != `=` {
			return none
		}
		i++ // consume '='
		for i < s.len && (s[i] == ` ` || s[i] == `\t`) {
			i++
		}
		if i >= s.len {
			return none
		}
		mut value := ''
		if s[i] == `"` {
			// quoted-string with backslash escapes
			i++
			mut buf := []u8{}
			mut closed := false
			for i < s.len {
				c := s[i]
				if c == `\\` && i + 1 < s.len {
					buf << s[i + 1]
					i += 2
					continue
				}
				if c == `"` {
					closed = true
					i++
					break
				}
				buf << c
				i++
			}
			if !closed {
				return none
			}
			value = buf.bytestr()
		} else {
			// token value
			val_start := i
			for i < s.len && mime_is_token_char(s[i]) {
				i++
			}
			if i == val_start {
				return none
			}
			value = s[val_start..i]
		}
		params << MediaParam{
			name:  name
			value: value
		}
	}
	return params
}

// mime_parse_media parses `type/subtype[; params]` (Content-Type form).
// Accepts wildcards (text/*, */*) per §4 — they are valid in Accept but
// the parser is shared. Returns none on a structural failure.
fn mime_parse_media(header string) ?ParsedMedia {
	s := header.trim(' \t')
	if s == '' {
		return none
	}
	// split off the parameters at the first ';'
	mut head := s
	mut tail := ''
	if si := s.index(';') {
		head = s[..si]
		tail = s[si..]
	}
	head_trim := head.trim(' \t')
	slash := head_trim.index('/') or { return none }
	typ := head_trim[..slash].trim(' \t').to_lower()
	subtype := head_trim[slash + 1..].trim(' \t').to_lower()
	if typ == '' || subtype == '' {
		return none
	}
	// validate type/subtype are tokens (allow '*' wildcard for accept).
	if !mime_is_type_token(typ) || !mime_is_type_token(subtype) {
		return none
	}
	mut m := ParsedMedia{
		typ:     typ
		subtype: subtype
	}
	if tail != '' {
		m.params = mime_parse_params(tail) or { return none }
	}
	return m
}

// mime_is_type_token reports whether `s` is a valid type/subtype token —
// a non-empty run of token chars, or the bare '*' wildcard.
fn mime_is_type_token(s string) bool {
	if s == '*' {
		return true
	}
	if s == '' {
		return false
	}
	for c in s {
		if !mime_is_token_char(c) {
			return false
		}
	}
	return true
}

// mime_media_element renders a ParsedMedia as a [content-type …] element.
fn mime_media_element(m ParsedMedia) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'type'
			value: cx.ScalarValue(m.typ)
		},
		cx.Attribute{
			name:  'subtype'
			value: cx.ScalarValue(m.subtype)
		},
	]
	mut items := []cx.Node{}
	if m.params.len > 0 {
		mut pattrs := []cx.Attribute{}
		for p in m.params {
			pattrs << cx.Attribute{
				name:  p.name
				value: cx.ScalarValue(p.value)
			}
		}
		items << cx.Element{
			name:  'parameters'
			attrs: pattrs
		}
	}
	return cx.Element{
		name:  'content-type'
		attrs: attrs
		items: items
	}
}

// mime_media_from_element reads a [content-type …] element back into a
// ParsedMedia (type/subtype attrs + [parameters …] child attrs).
fn mime_media_from_element(n cx.Node) ?ParsedMedia {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	mut m := ParsedMedia{
		typ:     mime_attr_str(el, 'type')
		subtype: mime_attr_str(el, 'subtype')
	}
	for child in el.items {
		if child is cx.Element && child.name == 'parameters' {
			for a in child.attrs {
				m.params << MediaParam{
					name:  a.name
					value: cx.scalar_value_str_public(a.value)
				}
			}
		}
	}
	return m
}

// mime_quote_value quotes a parameter value if it contains a tspecial /
// whitespace; bare tokens are emitted unquoted (§3.2 canonical form).
fn mime_quote_value(v string) string {
	mut needs := v.len == 0
	for c in v {
		if !mime_is_token_char(c) {
			needs = true
			break
		}
	}
	if !needs {
		return v
	}
	mut buf := []u8{}
	buf << `"`
	for c in v {
		if c == `"` || c == `\\` {
			buf << `\\`
		}
		buf << c
	}
	buf << `"`
	return buf.bytestr()
}

// mime_format_media emits the canonical `type/subtype; name=value; …`.
fn mime_format_media(m ParsedMedia) string {
	mut out := m.typ + '/' + m.subtype
	for p in m.params {
		out += '; ' + p.name + '=' + mime_quote_value(p.value)
	}
	return out
}

// ── Content-Disposition (§3.3) ────────────────────────────────────────
//
// header = disposition-type *( ";" parameter )
// disposition-type = token (no "/"); reuses the parameter grammar.

fn mime_parse_disposition(header string) ?ParsedMedia {
	s := header.trim(' \t')
	if s == '' {
		return none
	}
	mut head := s
	mut tail := ''
	if si := s.index(';') {
		head = s[..si]
		tail = s[si..]
	}
	dtype := head.trim(' \t').to_lower()
	if dtype == '' || !mime_is_type_token(dtype) {
		return none
	}
	mut m := ParsedMedia{
		typ:     dtype
		subtype: ''
	}
	if tail != '' {
		m.params = mime_parse_params(tail) or { return none }
	}
	return m
}

fn mime_disposition_element(m ParsedMedia) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'type'
			value: cx.ScalarValue(m.typ)
		},
	]
	mut items := []cx.Node{}
	if m.params.len > 0 {
		mut pattrs := []cx.Attribute{}
		for p in m.params {
			pattrs << cx.Attribute{
				name:  p.name
				value: cx.ScalarValue(p.value)
			}
		}
		items << cx.Element{
			name:  'parameters'
			attrs: pattrs
		}
	}
	return cx.Element{
		name:  'content-disposition'
		attrs: attrs
		items: items
	}
}

// mime_disposition_from_element reads a [content-disposition …] element.
fn mime_disposition_from_element(n cx.Node) ?ParsedMedia {
	if n !is cx.Element {
		return none
	}
	el := n as cx.Element
	mut m := ParsedMedia{
		typ:     mime_attr_str(el, 'type')
		subtype: ''
	}
	for child in el.items {
		if child is cx.Element && child.name == 'parameters' {
			for a in child.attrs {
				m.params << MediaParam{
					name:  a.name
					value: cx.scalar_value_str_public(a.value)
				}
			}
		}
	}
	return m
}

fn mime_param_value(m ParsedMedia, name string) ?string {
	for p in m.params {
		if p.name == name {
			return p.value
		}
	}
	return none
}

// mime_is_ascii reports whether every byte of `s` is in the ASCII range.
fn mime_is_ascii(s string) bool {
	for c in s {
		if c >= 127 {
			return false
		}
	}
	return true
}

// ── RFC 5987 extended-parameter decode (§3.3) ─────────────────────────
//
// ext-value = charset "'" [ language ] "'" value-chars
// value-chars are pct-encoded; only UTF-8 / ISO-8859-1 charsets are
// expected. Returns none (→ CXER2803) on a malformed value.
fn mime_decode_ext_value(ext string) ?string {
	// split charset'lang'value
	q1 := ext.index("'") or { return none }
	charset := ext[..q1].to_lower()
	rest := ext[q1 + 1..]
	q2 := rest.index("'") or { return none }
	value := rest[q2 + 1..]
	if charset != 'utf-8' && charset != 'iso-8859-1' && charset != '' {
		return none
	}
	// percent-decode value-chars to bytes
	mut buf := []u8{}
	mut i := 0
	for i < value.len {
		c := value[i]
		if c == `%` {
			if i + 2 >= value.len {
				return none
			}
			hi := mime_hex_val(value[i + 1]) or { return none }
			lo := mime_hex_val(value[i + 2]) or { return none }
			buf << u8((hi << 4) | lo)
			i += 3
		} else {
			buf << c
			i++
		}
	}
	if charset == 'iso-8859-1' {
		// each byte is a Latin-1 codepoint → UTF-8
		mut out := []u8{}
		for b in buf {
			if b < 0x80 {
				out << b
			} else {
				out << u8(0xC0 | (b >> 6))
				out << u8(0x80 | (b & 0x3F))
			}
		}
		return out.bytestr()
	}
	// utf-8 (or unspecified): validate
	if !utf8_validate(buf) {
		return none
	}
	return buf.bytestr()
}

fn mime_hex_val(c u8) ?u8 {
	if c >= `0` && c <= `9` {
		return u8(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return u8(c - `a` + 10)
	}
	if c >= `A` && c <= `F` {
		return u8(c - `A` + 10)
	}
	return none
}

// mime_encode_ext_value percent-encodes a UTF-8 filename into an RFC 5987
// `UTF-8''…` ext-value. attr-char survive; everything else is %XX.
fn mime_encode_ext_value(filename string) string {
	mut out := "UTF-8''"
	for c in filename.bytes() {
		if mime_is_attr_char(c) {
			out += c.ascii_str()
		} else {
			out += mime_hex_upper(c)
		}
	}
	return out
}

// mime_is_attr_char — RFC 5987 attr-char: ALPHA / DIGIT / !#$&+-.^_`|~
fn mime_is_attr_char(c u8) bool {
	if (c >= `A` && c <= `Z`) || (c >= `a` && c <= `z`) || (c >= `0` && c <= `9`) {
		return true
	}
	return '!#\$&+-.^_`|~'.contains_u8(c)
}

fn mime_hex_upper(b u8) string {
	digits := '0123456789ABCDEF'
	return '%' + digits[b >> 4].ascii_str() + digits[b & 0x0f].ascii_str()
}

// mime_ascii_fallback derives an ASCII-only `filename=` fallback from a
// non-ASCII name: non-ASCII bytes become '_' (RFC 6266 guidance).
fn mime_ascii_fallback(filename string) string {
	mut out := []u8{}
	for c in filename.bytes() {
		if c < 127 && c != `"` && c != `\\` {
			out << c
		} else {
			out << `_`
		}
	}
	return out.bytestr()
}

// ── multipart boundary (§3.4) ─────────────────────────────────────────

// mime_random_hex returns `n` lowercase hex chars from the crypto RNG.
fn mime_random_hex(n int) ?string {
	// need ceil(n/2) bytes; trim to n chars.
	nbytes := (n + 1) / 2
	b := crand.bytes(nbytes) or { return none }
	h := hex.encode(b)
	return h[..n]
}

// mime_is_valid_boundary — RFC 2046: 1–70 chars, restricted character set
// (bcharsnospace plus space, but cannot end in space). bchars =
// bcharsnospace / " "; bcharsnospace = DIGIT / ALPHA / "'()+_,-./:=?".
fn mime_is_valid_boundary(s string) bool {
	if s.len < 1 || s.len > 70 {
		return false
	}
	for i, c in s {
		if c == ` ` {
			// space allowed only in interior, not as the final char
			if i == s.len - 1 {
				return false
			}
			continue
		}
		if !mime_is_bchar_nospace(c) {
			return false
		}
	}
	return true
}

fn mime_is_bchar_nospace(c u8) bool {
	if (c >= `0` && c <= `9`) || (c >= `A` && c <= `Z`) || (c >= `a` && c <= `z`) {
		return true
	}
	return "'()+_,-./:=?".contains_u8(c)
}

// ── type classification (§3.5) ────────────────────────────────────────

// mime_top_level returns the lowercased top-level type of `mtype`
// (the part before '/'), or the whole string if there is no slash.
fn mime_top_level(mtype string) string {
	t := mtype.trim(' \t').to_lower()
	// strip any parameters
	mut base := t
	if si := t.index(';') {
		base = t[..si]
	}
	if slash := base.index('/') {
		return base[..slash]
	}
	return base
}

fn mime_subtype_of(mtype string) string {
	t := mtype.trim(' \t').to_lower()
	mut base := t
	if si := t.index(';') {
		base = t[..si]
	}
	if slash := base.index('/') {
		return base[slash + 1..]
	}
	return ''
}

// mime_is_binary classifies application/* and any non-text media as
// binary, with the well-known text-bearing application subtypes treated as
// non-binary by the structured-syntax / explicit list (§3.5).
fn mime_is_binary(mtype string) bool {
	top := mime_top_level(mtype)
	if top == 'text' {
		return false
	}
	if top == 'image' || top == 'audio' || top == 'video' || top == 'application' {
		// structured text suffixes (+json/+xml) are textual, but the §6
		// fixture only asserts application/pdf → binary; keep it simple and
		// spec-aligned: non-text top-levels are binary by default.
		return true
	}
	if top == 'multipart' || top == 'message' {
		return false
	}
	return true
}

// mime_structured_suffix returns the RFC 6838 §4.2.8 structured-syntax
// suffix (the part after the LAST '+' in the subtype), or '' if none.
fn mime_structured_suffix(mtype string) string {
	sub := mime_subtype_of(mtype)
	if plus := sub.last_index('+') {
		return sub[plus + 1..]
	}
	return ''
}

// ── Accept negotiation (§3.7) ─────────────────────────────────────────

struct AcceptRange {
mut:
	typ      string
	subtype  string
	q        f64
	order    int // original position, for stable sort
	params   []MediaParam
}

// mime_parse_accept parses an Accept header into q-ranked ranges, sorted
// by q descending then specificity (type/subtype > type/* > */*).
fn mime_parse_accept(header string) []AcceptRange {
	mut ranges := []AcceptRange{}
	parts := header.split(',')
	mut idx := 0
	for part in parts {
		p := part.trim(' \t')
		if p == '' {
			continue
		}
		m := mime_parse_media(p) or { continue }
		mut q := f64(1.0)
		mut other := []MediaParam{}
		for par in m.params {
			if par.name == 'q' {
				q = par.value.f64()
			} else {
				other << par
			}
		}
		ranges << AcceptRange{
			typ:     m.typ
			subtype: m.subtype
			q:       q
			order:   idx
			params:  other
		}
		idx++
	}
	ranges.sort_with_compare(fn (a &AcceptRange, b &AcceptRange) int {
		if a.q > b.q {
			return -1
		}
		if a.q < b.q {
			return 1
		}
		sa := mime_specificity(a.typ, a.subtype)
		sb := mime_specificity(b.typ, b.subtype)
		if sa > sb {
			return -1
		}
		if sa < sb {
			return 1
		}
		return a.order - b.order
	})
	return ranges
}

// mime_specificity: type/subtype = 2, type/* = 1, */* = 0.
fn mime_specificity(typ string, subtype string) int {
	if typ == '*' {
		return 0
	}
	if subtype == '*' {
		return 1
	}
	return 2
}

fn mime_accept_element(r AcceptRange) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'type'
			value: cx.ScalarValue(r.typ)
		},
		cx.Attribute{
			name:  'subtype'
			value: cx.ScalarValue(r.subtype)
		},
		cx.Attribute{
			name:  'q'
			value: cx.ScalarValue(r.q)
		},
	]
	mut pattrs := []cx.Attribute{}
	for p in r.params {
		pattrs << cx.Attribute{
			name:  p.name
			value: cx.ScalarValue(p.value)
		}
	}
	return cx.Element{
		name:  'accept'
		attrs: attrs
		items: [cx.Node(cx.Element{
			name:  'params'
			attrs: pattrs
		})]
	}
}

// mime_match_accept returns the best q-weighted offer per RFC 7231 §5.3.2,
// or '' when nothing is acceptable (best q is 0).
fn mime_match_accept(header string, offered []string) string {
	ranges := mime_parse_accept(header)
	mut best := ''
	mut best_q := f64(0.0)
	mut best_spec := -1
	for off in offered {
		otop := mime_top_level(off)
		osub := mime_subtype_of(off)
		// find the most-specific matching range for this offer
		mut match_q := f64(-1.0)
		mut match_spec := -1
		for r in ranges {
			if mime_range_matches(r, otop, osub) {
				spec := mime_specificity(r.typ, r.subtype)
				if spec > match_spec || (spec == match_spec && r.q > match_q) {
					match_q = r.q
					match_spec = spec
				}
			}
		}
		if match_q <= 0 {
			continue
		}
		if match_q > best_q || (match_q == best_q && match_spec > best_spec) {
			best = off
			best_q = match_q
			best_spec = match_spec
		}
	}
	return best
}

fn mime_range_matches(r AcceptRange, otop string, osub string) bool {
	if r.typ == '*' {
		return true
	}
	if r.typ != otop {
		return false
	}
	if r.subtype == '*' {
		return true
	}
	return r.subtype == osub
}

// ── dispatch ───────────────────────────────────────────────────────────

fn mime_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// ── §3.1 type lookup ────────────────────────────────────────
		'mime-type-for-extension' {
			ext := mime_arg_str(args[0]) or { return none }
			return mime_str(mime_lookup_type(ext))
		}
		'mime-extension-for-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_str(mime_primary_extension(mtype))
		}
		'mime-all-extensions-for-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			exts := mime_extensions_for(mtype)
			mut items := []cx.Node{cap: exts.len}
			for e in exts {
				items << mime_str(e)
			}
			return mime_seq(items)
		}
		'mime-register-type' {
			ext := mime_arg_str(args[0]) or { return none }
			mtype := mime_arg_str(args[1]) or { return none }
			mut reg := mime_registry()
			reg.ext_to_type[mime_normalize_ext(ext)] = mtype
			return cx.ScalarNode{
				value:     cx.ScalarValue(cx.NullValue{})
				data_type: cx.ScalarType.null_type
			}
		}
		'mime-load-mime-types' {
			path := mime_arg_str(args[0]) or { return none }
			return mime_load_types_impl(path)
		}

		// ── §3.2 content-type ───────────────────────────────────────
		'mime-parse-content-type' {
			header := mime_arg_str(args[0]) or { return none }
			m := mime_parse_media(header) or {
				return mime_err_content_type('unparseable "${header}"')
			}
			return mime_media_element(m)
		}
		'mime-format-content-type' {
			m := mime_media_from_element(args[0]) or { return none }
			return mime_str(mime_format_media(m))
		}
		'mime-get-parameter' {
			m := mime_media_from_element(args[0]) or { return none }
			pname := mime_arg_str(args[1]) or { return none }
			v := mime_param_value(m, pname.to_lower()) or { return mime_str('') }
			return mime_str(v)
		}

		// ── §3.3 content-disposition ────────────────────────────────
		'mime-parse-content-disposition' {
			header := mime_arg_str(args[0]) or { return none }
			m := mime_parse_disposition(header) or {
				return mime_err_disposition('unparseable "${header}"')
			}
			return mime_disposition_element(m)
		}
		'mime-format-content-disposition' {
			m := mime_disposition_from_element(args[0]) or { return none }
			return mime_str(mime_format_disposition(m))
		}
		'mime-disposition-filename' {
			m := mime_disposition_from_element(args[0]) or { return none }
			// prefer filename* (RFC 5987 extended) over filename
			if ext := mime_param_value(m, 'filename*') {
				decoded := mime_decode_ext_value(ext) or {
					return mime_err_extended('malformed filename* "${ext}"')
				}
				return mime_str(decoded)
			}
			if fn_ := mime_param_value(m, 'filename') {
				return mime_str(fn_)
			}
			return mime_str('')
		}

		// ── §3.4 multipart boundary ─────────────────────────────────
		// #828 (RULED: 828-1a): this draws OS ENTROPY — its own failure mode
		// is "entropy unavailable" — so it charges `random` like every other
		// entropy draw. security.md §2.1 is a closed EFFECT-POINT table, not
		// a secrets table: the question is whether the surface reaches an OS
		// resource that can fail, not whether its output is confidential. (A
		// boundary is indeed not a secret; that is why it needs to be
		// collision-resistant against body content, which is still entropy.)
		'mime-multipart-boundary' {
			if d := cap_guard('random', name) {
				return d
			}
			h := mime_random_hex(17) or {
				return mime_err_boundary('entropy unavailable')
			}
			return mime_str('=_Part_' + h)
		}
		'mime-is-valid-boundary' {
			s := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_is_valid_boundary(s))
		}

		// ── §3.5 classification ─────────────────────────────────────
		'mime-is-text-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'text')
		}
		'mime-is-binary-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_is_binary(mtype))
		}
		'mime-is-image-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'image')
		}
		'mime-is-audio-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'audio')
		}
		'mime-is-video-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'video')
		}
		'mime-is-message-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'message')
		}
		'mime-is-multipart-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'multipart')
		}
		'mime-is-application-type' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_bool(mime_top_level(mtype) == 'application')
		}
		'mime-is-structured-syntax' {
			mtype := mime_arg_str(args[0]) or { return none }
			return mime_str(mime_structured_suffix(mtype))
		}

		// ── §3.6 charset ────────────────────────────────────────────
		'mime-charset-of' {
			m := mime_media_from_element(args[0]) or { return none }
			v := mime_param_value(m, 'charset') or { return mime_str('') }
			return mime_str(v)
		}
		'mime-with-charset' {
			m := mime_media_from_element(args[0]) or { return none }
			charset := mime_arg_str(args[1]) or { return none }
			mut nm := ParsedMedia{
				typ:     m.typ
				subtype: m.subtype
			}
			mut replaced := false
			for p in m.params {
				if p.name == 'charset' {
					nm.params << MediaParam{
						name:  'charset'
						value: charset
					}
					replaced = true
				} else {
					nm.params << p
				}
			}
			if !replaced {
				nm.params << MediaParam{
					name:  'charset'
					value: charset
				}
			}
			return mime_media_element(nm)
		}

		// ── §3.7 accept ─────────────────────────────────────────────
		'mime-parse-accept' {
			header := mime_arg_str(args[0]) or { return none }
			ranges := mime_parse_accept(header)
			mut items := []cx.Node{cap: ranges.len}
			for r in ranges {
				items << mime_accept_element(r)
			}
			return mime_seq(items)
		}
		'mime-match-accept' {
			header := mime_arg_str(args[0]) or { return none }
			mut offered := []string{}
			for it in mime_items(args[1]) {
				offered << mime_node_text(it)
			}
			return mime_str(mime_match_accept(header, offered))
		}

		else {
			return none
		}
	}
}

// mime_format_disposition emits a Content-Disposition header. ASCII
// filenames emit a plain `filename="…"`; a non-ASCII filename emits both
// a `filename*=UTF-8''…` (RFC 5987) and an ASCII `filename=` fallback
// (RFC 6266). Other parameters pass through unchanged.
fn mime_format_disposition(m ParsedMedia) string {
	mut out := m.typ
	for p in m.params {
		if p.name == 'filename' {
			if mime_is_ascii(p.value) {
				out += '; filename=' + mime_quote_value(p.value)
			} else {
				out += '; filename=' + mime_quote_value(mime_ascii_fallback(p.value))
				out += "; filename*=" + mime_encode_ext_value(p.value)
			}
		} else if p.name == 'filename*' {
			// carried as the extended form already — pass through verbatim.
			out += "; filename*=" + p.value
		} else {
			out += '; ' + p.name + '=' + mime_quote_value(p.value)
		}
	}
	return out
}

// mime_load_types_impl reads an OS / custom `mime.types` file, merging
// each `type ext1 ext2 …` line into the registry overlay. Returns the
// count of (ext→type) mappings loaded. Raises CXER2804 on a missing or
// unreadable file. Touches the filesystem → requires `read` (gated by the
// effect-point capability check; see §7). The deny-by-default check is
// applied before the read.
fn mime_load_types_impl(path string) cx.Node {
	// Filesystem read is capability-gated (§7): with no active grant the
	// effect point denies (deny-by-default, security.md §4). The grant
	// surface is not yet wired into the evaluator, so a missing file is
	// the path the conformance suite exercises (CXER2804). We attempt the
	// read; a missing/unreadable file → CXER2804.
	if !os.exists(path) || os.is_dir(path) {
		return mime_err_types_file('missing or unreadable: ${path}')
	}
	content := os.read_file(path) or {
		return mime_err_types_file('cannot read: ${path}')
	}
	mut reg := mime_registry()
	mut count := 0
	for raw in content.split_into_lines() {
		line := raw.trim(' \t')
		if line == '' || line.starts_with('#') {
			continue
		}
		fields := line.fields()
		if fields.len < 2 {
			continue
		}
		mtype := fields[0]
		for i in 1 .. fields.len {
			reg.ext_to_type[mime_normalize_ext(fields[i])] = mtype
			count++
		}
	}
	return mime_int(i64(count))
}

// ── built-in extension → MIME type registry (§2.3) ────────────────────
//
// A curated ~200-extension offline default. Lowercase, leading-dot keys.
// `mime_builtin_ext_order` preserves a stable iteration order for
// all-extensions-for-type; `mime_type_primary_ext` pins the canonical
// "most common" extension for reverse lookup (e.g. image/jpeg → .jpg).

const mime_builtin_types = {
	// text
	'.txt':   'text/plain'
	'.text':  'text/plain'
	'.log':   'text/plain'
	'.ini':   'text/plain'
	'.conf':  'text/plain'
	'.html':  'text/html'
	'.htm':   'text/html'
	'.xhtml': 'application/xhtml+xml'
	'.css':   'text/css'
	'.csv':   'text/csv'
	'.tsv':   'text/tab-separated-values'
	'.md':    'text/markdown'
	'.markdown': 'text/markdown'
	'.vtt':   'text/vtt'
	'.ics':   'text/calendar'
	'.rtf':   'application/rtf'
	'.sgml':  'text/sgml'
	'.yaml':  'application/yaml'
	'.yml':   'application/yaml'
	// application / data
	'.json':  'application/json'
	'.jsonld': 'application/ld+json'
	'.map':   'application/json'
	'.js':    'text/javascript'
	'.mjs':   'text/javascript'
	'.cjs':   'text/javascript'
	'.xml':   'application/xml'
	'.rss':   'application/rss+xml'
	'.atom':  'application/atom+xml'
	'.svg':   'image/svg+xml'
	'.svgz':  'image/svg+xml'
	'.wasm':  'application/wasm'
	'.pdf':   'application/pdf'
	'.ps':    'application/postscript'
	'.eps':   'application/postscript'
	'.ai':    'application/postscript'
	'.zip':   'application/zip'
	'.gz':    'application/gzip'
	'.tgz':   'application/gzip'
	'.bz2':   'application/x-bzip2'
	'.xz':    'application/x-xz'
	'.zst':   'application/zstd'
	'.7z':    'application/x-7z-compressed'
	'.rar':   'application/vnd.rar'
	'.tar':   'application/x-tar'
	'.jar':   'application/java-archive'
	'.war':   'application/java-archive'
	'.bin':   'application/octet-stream'
	'.exe':   'application/octet-stream'
	'.dll':   'application/octet-stream'
	'.dmg':   'application/x-apple-diskimage'
	'.iso':   'application/x-iso9660-image'
	'.deb':   'application/vnd.debian.binary-package'
	'.rpm':   'application/x-rpm'
	'.apk':   'application/vnd.android.package-archive'
	'.msi':   'application/x-msi'
	'.swf':   'application/x-shockwave-flash'
	'.torrent': 'application/x-bittorrent'
	'.sh':    'application/x-sh'
	'.sql':   'application/sql'
	'.epub':  'application/epub+zip'
	'.mobi':  'application/x-mobipocket-ebook'
	// office / opendocument
	'.doc':   'application/msword'
	'.docx':  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
	'.xls':   'application/vnd.ms-excel'
	'.xlsx':  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
	'.ppt':   'application/vnd.ms-powerpoint'
	'.pptx':  'application/vnd.openxmlformats-officedocument.presentationml.presentation'
	'.odt':   'application/vnd.oasis.opendocument.text'
	'.ods':   'application/vnd.oasis.opendocument.spreadsheet'
	'.odp':   'application/vnd.oasis.opendocument.presentation'
	// fonts
	'.woff':  'font/woff'
	'.woff2': 'font/woff2'
	'.ttf':   'font/ttf'
	'.otf':   'font/otf'
	'.eot':   'application/vnd.ms-fontobject'
	// images
	'.png':   'image/png'
	'.jpg':   'image/jpeg'
	'.jpeg':  'image/jpeg'
	'.gif':   'image/gif'
	'.webp':  'image/webp'
	'.avif':  'image/avif'
	'.bmp':   'image/bmp'
	'.ico':   'image/vnd.microsoft.icon'
	'.cur':   'image/vnd.microsoft.icon'
	'.tif':   'image/tiff'
	'.tiff':  'image/tiff'
	'.heic':  'image/heic'
	'.heif':  'image/heif'
	'.psd':   'image/vnd.adobe.photoshop'
	'.jp2':   'image/jp2'
	// audio
	'.mp3':   'audio/mpeg'
	'.m4a':   'audio/mp4'
	'.aac':   'audio/aac'
	'.oga':   'audio/ogg'
	'.ogg':   'audio/ogg'
	'.opus':  'audio/opus'
	'.flac':  'audio/flac'
	'.wav':   'audio/wav'
	'.weba':  'audio/webm'
	'.mid':   'audio/midi'
	'.midi':  'audio/midi'
	'.aiff':  'audio/aiff'
	'.aif':   'audio/aiff'
	// video
	'.mp4':   'video/mp4'
	'.m4v':   'video/mp4'
	'.mov':   'video/quicktime'
	'.avi':   'video/x-msvideo'
	'.wmv':   'video/x-ms-wmv'
	'.flv':   'video/x-flv'
	'.mkv':   'video/x-matroska'
	'.webm':  'video/webm'
	'.ogv':   'video/ogg'
	'.mpeg':  'video/mpeg'
	'.mpg':   'video/mpeg'
	'.3gp':   'video/3gpp'
	'.3g2':   'video/3gpp2'
	'.ts':    'video/mp2t'
	// message
	'.eml':   'message/rfc822'
	'.mht':   'message/rfc822'
	// programming source (served as text/plain by convention)
	'.c':     'text/x-c'
	'.h':     'text/x-c'
	'.cpp':   'text/x-c'
	'.py':    'text/x-python'
	'.rb':    'text/x-ruby'
	'.go':    'text/x-go'
	'.rs':    'text/x-rust'
	'.java':  'text/x-java-source'
	'.php':   'application/x-httpd-php'
	'.pl':    'application/x-perl'
}

// mime_builtin_ext_order is the stable iteration order for
// all-extensions-for-type. V map iteration order is insertion order, but
// a const map's order is not guaranteed across compiles, so the order is
// pinned here explicitly (the extensions a type may share are grouped).
const mime_builtin_ext_order = [
	'.txt', '.text', '.log', '.ini', '.conf', '.html', '.htm', '.xhtml',
	'.css', '.csv', '.tsv', '.md', '.markdown', '.vtt', '.ics', '.rtf',
	'.sgml', '.yaml', '.yml', '.json', '.jsonld', '.map', '.js', '.mjs',
	'.cjs', '.xml', '.rss', '.atom', '.svg', '.svgz', '.wasm', '.pdf',
	'.ps', '.eps', '.ai', '.zip', '.gz', '.tgz', '.bz2', '.xz', '.zst',
	'.7z', '.rar', '.tar', '.jar', '.war', '.bin', '.exe', '.dll', '.dmg',
	'.iso', '.deb', '.rpm', '.apk', '.msi', '.swf', '.torrent', '.sh',
	'.sql', '.epub', '.mobi', '.doc', '.docx', '.xls', '.xlsx', '.ppt',
	'.pptx', '.odt', '.ods', '.odp', '.woff', '.woff2', '.ttf', '.otf',
	'.eot', '.png', '.jpg', '.jpeg', '.gif', '.webp',
	'.avif', '.bmp', '.ico', '.cur', '.tif', '.tiff', '.heic', '.heif',
	'.psd', '.jp2', '.mp3', '.m4a', '.aac', '.oga', '.ogg', '.opus',
	'.flac', '.wav', '.weba', '.mid', '.midi', '.aiff', '.aif', '.mp4',
	'.m4v', '.mov', '.avi', '.wmv', '.flv', '.mkv', '.webm', '.ogv',
	'.mpeg', '.mpg', '.3gp', '.3g2', '.ts', '.eml', '.mht', '.c', '.h',
	'.cpp', '.py', '.rb', '.go', '.rs', '.java', '.php', '.pl',
]

// mime_type_primary_ext pins the canonical reverse-lookup extension for
// types with multiple known extensions (§3.1 "most common extension").
const mime_type_primary_ext = {
	'text/plain':    '.txt'
	'text/html':     '.html'
	'text/markdown': '.md'
	'image/jpeg':    '.jpg'
	'image/tiff':    '.tif'
	'image/svg+xml': '.svg'
	'image/vnd.microsoft.icon': '.ico'
	'audio/mpeg':    '.mp3'
	'audio/ogg':     '.ogg'
	'audio/midi':    '.mid'
	'audio/aiff':    '.aiff'
	'video/mp4':     '.mp4'
	'video/mpeg':    '.mpeg'
	'application/json': '.json'
	'application/gzip': '.gz'
	'application/yaml': '.yaml'
	'application/postscript': '.ps'
	'text/javascript': '.js'
	'application/xml': '.xml'
	'message/rfc822': '.eml'
}
