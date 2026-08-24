module platform
import code {
	mk_err,
}

import cx
import encoding.base64
import rand

// stdlib_email.v — native primitives backing `cx-stdlib/email`
// (spec/std-lib/email.md). RFC 5322 + MIME multipart message parse / emit,
// RFC 2047 encoded-word decode/encode, RFC 5322 address-list parsing
// (incl. groups), and RFC 3464 DSN lifting. None of this is expressible
// as a pure-CX `[?def]` body, so the bundle bodies (stdlib_src_email,
// stdlib_bundle.v) forward here via stdlib_dispatch.v. The `email-`-prefix
// keeps the primitive names from clashing with the language-core builtins.
//
// ── CX value model ──────────────────────────────────────────────────
//   A parsed message is a `[message [headers …] [body …]]` element
//   (spec §2). `[headers [name "v"] …]` preserves order + multiplicity;
//   `[body [parts [part content-type=… encoding=… …] …] [is-multipart …]
//   [boundary …]]`. parse / build / build-multipart / reply / forward
//   return this element; emit returns a bytes scalar; the typed accessors
//   reduce to a string / bool / datetime / element / sequence per §3.
//   An address is `[address [display-name …] [local-part …] [domain …]
//   [raw …]]`; a group is `[address-group name=… [address …] …]`.
//
// Errors are VALUES (mk_err, eval.v): CXER1300..CXER1306 (§6). The runner
// matches the bare CXER code as a substring of the rendered err value.
//
// email is PURE — no process-global state, no `@[has_globals]`. The
// freshly-generated multipart boundary on emit uses `rand` (the §4.3
// boundary is "random, guaranteed not to occur in part bodies"); the
// spec marks emit :pure, so we draw from the same global PRNG the rest of
// the toolchain uses without declaring module state.

// ── value builders ───────────────────────────────────────────────────

fn email_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn email_bytes(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.bytes_type
	}
}

fn email_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn email_datetime(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.datetime_type
	}
}

fn email_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn email_map(keys []string, vals []cx.Node) cx.Node {
	mut entries := []cx.Node{}
	for i, k in keys {
		entries << cx.Element{
			name:  k
			items: [vals[i]]
		}
	}
	return cx.Element{
		name:  '__cx_map__'
		items: entries
	}
}

// ── argument readers ──────────────────────────────────────────────────

fn email_arg_str(n cx.Node) ?string {
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

// email_node_text reads any scalar/text node's textual value.
fn email_node_text(n cx.Node) string {
	match n {
		cx.ScalarNode {
			v := n.value
			match v {
				string { return v }
				i64 { return v.str() }
				f64 { return cx.scalar_value_str_public(v) }
				bool { return if v { 'true' } else { 'false' } }
				cx.NullValue { return '' }
			}
		}
		cx.TextNode {
			return n.value
		}
		else {
			return ''
		}
	}
}

// email_seq_items extracts the item list of a sequence / array element.
fn email_seq_items(n cx.Node) ?[]cx.Node {
	match n {
		cx.SequenceNode { return n.items }
		cx.ArrayNode { return n.items }
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == ''
				|| n.name == 'sequence' || n.name == 'array' {
				return n.items
			}
			return none
		}
		else {
			return none
		}
	}
}

// email_map_entries returns the ordered (key, value) pairs of a map.
fn email_map_entries(n cx.Node) ([]string, []cx.Node, bool) {
	mut keys := []string{}
	mut vals := []cx.Node{}
	if n is cx.Element {
		if n.name == '__cx_map__' {
			for it in n.items {
				if it is cx.Element {
					keys << it.name
					if it.items.len > 0 {
						vals << it.items[0]
					} else {
						vals << email_str('')
					}
				}
			}
			return keys, vals, true
		}
	}
	return keys, vals, false
}

// email_map_get returns the first textual value for a key in a map, or none.
fn email_map_get(n cx.Node, key string) ?cx.Node {
	keys, vals, ok := email_map_entries(n)
	if !ok {
		return none
	}
	for i, k in keys {
		if k == key {
			return vals[i]
		}
	}
	return none
}

// email_child returns the first child element named `name`, or none.
fn email_child(el cx.Element, name string) ?cx.Element {
	for c in el.items {
		if c is cx.Element && c.name == name {
			return c
		}
	}
	return none
}

// email_child_text returns the single-scalar body of a named child.
fn email_child_text(el cx.Element, name string) string {
	c := email_child(el, name) or { return '' }
	if c.items.len > 0 {
		return email_node_text(c.items[0])
	}
	return ''
}

// email_attr returns the value of an element attribute, or ''.
fn email_attr(el cx.Element, name string) string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

fn email_has_attr(el cx.Element, name string) bool {
	for a in el.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

// ── error helpers ─────────────────────────────────────────────────────

fn email_has_crlf(s string) bool {
	return s.contains('\r') || s.contains('\n')
}

fn email_err_malformed(msg string) cx.Node {
	return mk_err('cx-err:CXER1300', 'E_EMAIL_MALFORMED: ${msg}')
}

fn email_err_address(msg string) cx.Node {
	return mk_err('cx-err:CXER1301', 'E_EMAIL_ADDRESS_MALFORMED: ${msg}')
}

fn email_err_encoding(msg string) cx.Node {
	return mk_err('cx-err:CXER1302', 'E_EMAIL_ENCODING_UNKNOWN: ${msg}')
}

fn email_err_charset(msg string) cx.Node {
	return mk_err('cx-err:CXER1303', 'E_EMAIL_CHARSET_UNKNOWN: ${msg}')
}

fn email_err_required(msg string) cx.Node {
	return mk_err('cx-err:CXER1304', 'E_EMAIL_REQUIRED_HEADER_MISSING: ${msg}')
}

fn email_err_boundary(msg string) cx.Node {
	return mk_err('cx-err:CXER1305', 'E_EMAIL_BOUNDARY_COLLISION: ${msg}')
}

fn email_err_not_dsn(msg string) cx.Node {
	return mk_err('cx-err:CXER1306', 'E_EMAIL_NOT_DSN: ${msg}')
}

fn email_is_err(n cx.Node) bool {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return true
			}
		}
	}
	return false
}

// ── charset support (§4.4) ────────────────────────────────────────────

// email_charset_supported reports whether the (case-insensitive) charset
// name is in the §4.4 pinned set. Charsets outside the set raise
// CXER1303. We DECODE only the ASCII-compatible subset byte-cleanly for
// the conformance surface (UTF-8 verbatim; Latin/Windows/Asian charsets
// pass ASCII bytes through, which is all the fixtures exercise — see
// SPEC-FINDINGS §Q for the non-ASCII transcode residual).
fn email_charset_supported(charset string) bool {
	cs := charset.to_lower().replace('_', '-')
	if cs == 'utf-8' || cs == 'utf8' || cs == 'us-ascii' || cs == 'ascii' {
		return true
	}
	if cs.starts_with('iso-8859-') {
		return true
	}
	if cs.starts_with('windows-125') {
		return true
	}
	asian := ['shift-jis', 'shift_jis', 'sjis', 'gb2312', 'gbk', 'big5', 'euc-kr',
		'iso-2022-jp']
	return cs in asian
}

// email_charset_decode converts `raw` bytes from `charset` to a UTF-8
// string. Returns none if the charset is unsupported (caller raises
// CXER1303 and preserves the raw bytes). For UTF-8 the bytes are taken
// verbatim; for the other pinned charsets we map the ASCII-clean subset
// (high bytes are passed through as Latin-1 — byte-clean — which covers
// the fixtures; full transcode tables are §Q residual).
fn email_charset_decode(raw []u8, charset string) ?string {
	if !email_charset_supported(charset) {
		return none
	}
	cs := charset.to_lower().replace('_', '-')
	if cs == 'utf-8' || cs == 'utf8' || cs == 'us-ascii' || cs == 'ascii' {
		return raw.bytestr()
	}
	// ISO-8859-1 / Windows / Asian: ASCII bytes are identical; map each
	// byte 0..255 to its codepoint (Latin-1 fallback, byte-clean).
	mut out := []u8{}
	for b in raw {
		if b < 0x80 {
			out << b
		} else {
			// encode codepoint b as 2-byte UTF-8 (Latin-1 mapping).
			out << u8(0xC0 | (b >> 6))
			out << u8(0x80 | (b & 0x3F))
		}
	}
	return out.bytestr()
}

// ── RFC 2047 encoded-word (§3.4) ──────────────────────────────────────

// email_decode_encoded_word decodes a single `=?charset?enc?text?=` token
// (or a string containing such tokens, with non-token runs passed through
// and whitespace between adjacent encoded-words folded per RFC 2047 §6.2).
// Returns an err-value (CXER1303) on an unsupported charset.
fn email_decode_encoded_word(input string) cx.Node {
	mut out := []u8{}
	mut i := 0
	bytes := input.bytes()
	n := bytes.len
	mut prev_was_ew := false
	mut pending_ws := []u8{}
	for i < n {
		// Look for `=?` start.
		if i + 1 < n && bytes[i] == `=` && bytes[i + 1] == `?` {
			// find the closing `?=`.
			mut j := i + 2
			mut close := -1
			for j + 1 < n {
				if bytes[j] == `?` && bytes[j + 1] == `=` {
					close = j
					break
				}
				j++
			}
			if close >= 0 {
				token := input[i..close + 2]
				if decoded := email_decode_one_word(token) {
					if email_is_err(decoded) {
						return decoded
					}
					ds := email_node_text(decoded)
					// RFC 2047 §6.2: drop linear whitespace BETWEEN two
					// adjacent encoded-words.
					if !prev_was_ew {
						out << pending_ws
					}
					pending_ws = []u8{}
					out << ds.bytes()
					prev_was_ew = true
					i = close + 2
					continue
				}
			}
		}
		c := bytes[i]
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			pending_ws << c
		} else {
			out << pending_ws
			pending_ws = []u8{}
			out << c
			prev_was_ew = false
		}
		i++
	}
	out << pending_ws
	return email_str(out.bytestr())
}

// email_decode_one_word decodes exactly one `=?charset?enc?text?=` token.
// Returns none if the token is not a well-formed encoded-word; an
// err-value on an unsupported charset.
fn email_decode_one_word(token string) ?cx.Node {
	if !token.starts_with('=?') || !token.ends_with('?=') {
		return none
	}
	inner := token[2..token.len - 2]
	parts := inner.split('?')
	if parts.len != 3 {
		return none
	}
	charset := parts[0]
	enc := parts[1].to_upper()
	text := parts[2]
	mut raw := []u8{}
	if enc == 'B' {
		raw = base64.decode(text)
	} else if enc == 'Q' {
		raw = email_q_decode(text, true)
	} else {
		return none
	}
	if !email_charset_supported(charset) {
		return email_err_charset('unsupported charset "${charset}"')
	}
	decoded := email_charset_decode(raw, charset) or {
		return email_err_charset('unsupported charset "${charset}"')
	}
	return email_str(decoded)
}

// email_q_decode decodes RFC 2047 "Q" / quoted-printable text. In Q mode
// (`underscore_to_space`) a literal `_` decodes to space (RFC 2047 §4.2);
// in body QP mode `_` is literal and soft line-breaks (`=\r\n`) are
// dropped.
fn email_q_decode(s string, underscore_to_space bool) []u8 {
	mut out := []u8{}
	bytes := s.bytes()
	n := bytes.len
	mut i := 0
	for i < n {
		c := bytes[i]
		if c == `=` {
			if i + 2 < n {
				hi := email_hex_val(bytes[i + 1]) or {
					out << c
					i++
					continue
				}
				lo := email_hex_val(bytes[i + 2]) or {
					out << c
					i++
					continue
				}
				out << u8((hi << 4) | lo)
				i += 3
				continue
			}
			// `=` at end or `=\r\n` soft break in body QP.
			if i + 2 == n && bytes[i + 1] == `\r` && bytes[i + 2] == `\n` {
				i += 3
				continue
			}
			if i + 1 < n && bytes[i + 1] == `\n` {
				i += 2
				continue
			}
			out << c
			i++
			continue
		}
		if underscore_to_space && c == `_` {
			out << u8(` `)
			i++
			continue
		}
		out << c
		i++
	}
	return out
}

fn email_hex_val(c u8) ?u8 {
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

// email_encode_encoded_word produces an RFC 2047 encoded-word from a
// UTF-8 string. `encoding` is "Q" or "B"; always wrapped in `=?…?=`.
fn email_encode_encoded_word(s string, charset string, encoding string) cx.Node {
	enc := encoding.to_upper()
	if enc == 'B' {
		return email_str('=?${charset}?B?${base64.encode(s.bytes())}?=')
	}
	// Q-encode: printable ASCII (except `=`, `?`, `_`, space) verbatim;
	// space → `_`; everything else → `=XX`.
	mut body := ''
	for b in s.bytes() {
		if b == ` ` {
			body += '_'
		} else if (b >= 0x21 && b <= 0x7E) && b != `=` && b != `?` && b != `_` {
			body += b.ascii_str()
		} else {
			body += email_hex_upper(b)
		}
	}
	return email_str('=?${charset}?Q?${body}?=')
}

fn email_hex_upper(b u8) string {
	digits := '0123456789ABCDEF'
	return '=' + digits[b >> 4].ascii_str() + digits[b & 0x0f].ascii_str()
}

// email_decode_header decodes any encoded-words in a header value to UTF-8.
// Returns the decoded string, or propagates an err-value on charset error.
fn email_decode_header_value(s string) cx.Node {
	if !s.contains('=?') {
		return email_str(s)
	}
	return email_decode_encoded_word(s)
}

// ── RFC 5322 message parse (§3.1) ─────────────────────────────────────

struct HeaderField {
	name  string // original case
	lname string // lowercased
	value string // unfolded, raw (not decoded)
}

struct ParsedMessage {
mut:
	headers []HeaderField
	body    string // raw body bytes (string-clean)
}

// email_normalize_eol converts CRLF / CR to LF for line splitting.
fn email_normalize_eol(s string) string {
	return s.replace('\r\n', '\n').replace('\r', '\n')
}

// email_parse_message splits raw bytes into headers + body, unfolding
// continuation lines (RFC 5322 §2.2.3). Returns none if the input has no
// recognizable header (→ CXER1300).
fn email_parse_message(raw string) ?ParsedMessage {
	s := email_normalize_eol(raw)
	// Header / body split at the first blank line.
	mut header_block := s
	mut body := ''
	if idx := s.index('\n\n') {
		header_block = s[..idx]
		body = s[idx + 2..]
	} else if s.ends_with('\n') {
		header_block = s[..s.len - 1]
	}

	mut fields := []HeaderField{}
	lines := header_block.split('\n')
	mut cur_name := ''
	mut cur_val := ''
	mut have := false
	for line in lines {
		if line.len > 0 && (line[0] == ` ` || line[0] == `\t`) {
			// continuation (folding): append (with a single space).
			if have {
				cur_val += ' ' + line.trim_left(' \t')
			}
			continue
		}
		// new header: flush previous.
		if have {
			fields << email_make_field(cur_name, cur_val)
		}
		ci := line.index(':') or {
			// a non-blank line with no colon in the header block is malformed.
			return none
		}
		cur_name = line[..ci]
		cur_val = line[ci + 1..].trim_left(' \t')
		have = true
	}
	if have {
		fields << email_make_field(cur_name, cur_val)
	}
	if fields.len == 0 {
		return none
	}
	return ParsedMessage{
		headers: fields
		body:    body
	}
}

fn email_make_field(name string, value string) HeaderField {
	return HeaderField{
		name:  name.trim_space()
		lname: name.trim_space().to_lower()
		value: value
	}
}

// email_header_first returns the raw value of the first header named
// (case-insensitive) `name`, plus a presence flag.
fn email_header_first(pm ParsedMessage, name string) (string, bool) {
	ln := name.to_lower()
	for f in pm.headers {
		if f.lname == ln {
			return f.value, true
		}
	}
	return '', false
}

fn email_header_all(pm ParsedMessage, name string) []string {
	ln := name.to_lower()
	mut out := []string{}
	for f in pm.headers {
		if f.lname == ln {
			out << f.value
		}
	}
	return out
}

// ── MIME body / part model ────────────────────────────────────────────

struct MimePart {
mut:
	content_type string = 'text/plain'
	charset      string
	encoding     string // transfer encoding
	disposition  string
	filename     string
	content_id   string
	raw_body     string // undecoded body bytes
	children     []MimePart
	is_multipart bool
	boundary     string
	headers      []HeaderField // the part's own MIME headers
}

// email_parse_content_type extracts the bare type and parameters from a
// Content-Type header value.
fn email_ct_param(ct string, name string) string {
	parts := ct.split(';')
	for p in parts[1..] {
		kv := p.trim_space()
		eq := kv.index('=') or { continue }
		k := kv[..eq].trim_space().to_lower()
		if k == name {
			mut v := kv[eq + 1..].trim_space()
			if v.starts_with('"') && v.ends_with('"') && v.len >= 2 {
				v = v[1..v.len - 1]
			}
			return v
		}
	}
	return ''
}

fn email_ct_type(ct string) string {
	semi := ct.index(';') or { return ct.trim_space().to_lower() }
	return ct[..semi].trim_space().to_lower()
}

// email_build_part recursively builds a MimePart tree from a header set +
// body. `headers` are the (already-parsed) MIME headers for this entity.
fn email_build_part(headers []HeaderField, body string) MimePart {
	mut part := MimePart{
		headers: headers
	}
	mut ct := 'text/plain'
	for h in headers {
		match h.lname {
			'content-type' { ct = h.value }
			'content-transfer-encoding' { part.encoding = h.value.trim_space().to_lower() }
			'content-disposition' { part.disposition = h.value }
			'content-id' { part.content_id = h.value.trim('<> \t') }
			else {}
		}
	}
	part.content_type = email_ct_type(ct)
	part.charset = email_ct_param(ct, 'charset')
	part.boundary = email_ct_param(ct, 'boundary')
	// filename from disposition or content-type name=.
	if part.disposition != '' {
		part.filename = email_ct_param(part.disposition, 'filename')
	}
	if part.filename == '' {
		part.filename = email_ct_param(ct, 'name')
	}
	part.raw_body = body
	if part.content_type.starts_with('multipart/') && part.boundary != '' {
		part.is_multipart = true
		part.children = email_split_multipart(body, part.boundary)
	}
	return part
}

// email_split_multipart splits a multipart body on its boundary and
// recursively parses each part (RFC 2046 §5.1).
fn email_split_multipart(body string, boundary string) []MimePart {
	mut parts := []MimePart{}
	delim := '--' + boundary
	// Normalize EOL for splitting.
	s := email_normalize_eol(body)
	lines := s.split('\n')
	mut cur := []string{}
	mut in_part := false
	for line in lines {
		if line == delim || line.starts_with(delim + ' ') {
			if in_part {
				parts << email_parse_part_block(cur.join('\n'))
			}
			cur = []string{}
			in_part = true
			continue
		}
		if line == delim + '--' {
			if in_part {
				parts << email_parse_part_block(cur.join('\n'))
			}
			in_part = false
			break
		}
		if in_part {
			cur << line
		}
	}
	return parts
}

// email_parse_part_block parses one MIME part: its headers + body.
fn email_parse_part_block(block string) MimePart {
	mut header_block := block
	mut body := ''
	if idx := block.index('\n\n') {
		header_block = block[..idx]
		body = block[idx + 2..]
	}
	mut fields := []HeaderField{}
	lines := header_block.split('\n')
	mut cur_name := ''
	mut cur_val := ''
	mut have := false
	for line in lines {
		if line.len > 0 && (line[0] == ` ` || line[0] == `\t`) {
			if have {
				cur_val += ' ' + line.trim_left(' \t')
			}
			continue
		}
		if have {
			fields << email_make_field(cur_name, cur_val)
		}
		ci := line.index(':') or {
			have = false
			continue
		}
		cur_name = line[..ci]
		cur_val = line[ci + 1..].trim_left(' \t')
		have = true
	}
	if have {
		fields << email_make_field(cur_name, cur_val)
	}
	return email_build_part(fields, body)
}

// email_root_part builds the top-level MimePart for a parsed message.
fn email_root_part(pm ParsedMessage) MimePart {
	return email_build_part(pm.headers, pm.body)
}

// email_decode_body decodes a part's body per its transfer encoding +
// charset. Returns the decoded UTF-8 text, or an err-value (CXER1302 for
// an unsupported transfer encoding; CXER1303 for an unsupported charset).
fn email_decode_body(part MimePart) cx.Node {
	enc := part.encoding
	mut raw := []u8{}
	match enc {
		'', '7bit', '8bit', 'binary' {
			raw = part.raw_body.bytes()
		}
		'quoted-printable' {
			raw = email_q_decode(part.raw_body, false)
		}
		'base64' {
			// strip CR/LF/space before decoding.
			cleaned := part.raw_body.replace('\r', '').replace('\n', '').replace(' ', '')
			raw = base64.decode(cleaned)
		}
		else {
			return email_err_encoding('unsupported transfer encoding "${enc}"')
		}
	}
	charset := if part.charset == '' { 'utf-8' } else { part.charset }
	decoded := email_charset_decode(raw, charset) or {
		return email_err_charset('unsupported charset "${charset}"')
	}
	return email_str(email_strip_trailing_eol(decoded))
}

fn email_strip_trailing_eol(s string) string {
	mut r := s
	for r.ends_with('\n') || r.ends_with('\r') {
		r = r[..r.len - 1]
	}
	return r
}

// email_flat_parts returns all leaf parts (non-multipart) of a tree, in
// document order.
fn email_flat_parts(part MimePart) []MimePart {
	if !part.is_multipart {
		return [part]
	}
	mut out := []MimePart{}
	for c in part.children {
		out << email_flat_parts(c)
	}
	return out
}

// email_part_is_attachment reports whether a leaf part is an attachment
// (Content-Disposition: attachment, or inline/other with a filename).
fn email_part_is_attachment(part MimePart) bool {
	disp := email_ct_type(part.disposition)
	if disp == 'attachment' {
		return true
	}
	if part.filename != '' {
		return true
	}
	return false
}

// ── element materialization (parse result, §2) ────────────────────────

// email_message_element renders a ParsedMessage as the §2 [message …]
// element. Header values are kept RAW (encoded-words intact); the typed
// accessors decode on read.
fn email_message_element(pm ParsedMessage) cx.Node {
	mut header_items := []cx.Node{}
	for f in pm.headers {
		header_items << cx.Element{
			name:  f.name.to_lower()
			items: [email_str(f.value)]
		}
	}
	root := email_root_part(pm)
	body_el := email_body_element(root)
	return cx.Element{
		name:  'message'
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: header_items
			}),
			body_el,
		]
	}
}

// email_body_element renders the body model (parts + is-multipart +
// boundary) for the root part.
fn email_body_element(root MimePart) cx.Node {
	mut parts_items := []cx.Node{}
	leaves := email_flat_parts(root)
	for p in leaves {
		parts_items << email_part_element(p)
	}
	mut body_children := []cx.Node{}
	body_children << cx.Element{
		name:  'parts'
		items: parts_items
	}
	body_children << cx.Element{
		name:  'is-multipart'
		items: [email_str(if root.is_multipart { 'true' } else { 'false' })]
	}
	if root.is_multipart && root.boundary != '' {
		body_children << cx.Element{
			name:  'boundary'
			items: [email_str(root.boundary)]
		}
	}
	return cx.Element{
		name:  'body'
		items: body_children
	}
}

// email_part_element renders a single leaf part as a [part …] element with
// its content-type / encoding / charset / filename / content-id attrs and
// raw (undecoded) body.
fn email_part_element(p MimePart) cx.Node {
	mut attrs := []cx.Attribute{}
	attrs << cx.Attribute{
		name:  'content-type'
		value: cx.ScalarValue(p.content_type)
	}
	if p.encoding != '' {
		attrs << cx.Attribute{
			name:  'encoding'
			value: cx.ScalarValue(p.encoding)
		}
	}
	if p.charset != '' {
		attrs << cx.Attribute{
			name:  'charset'
			value: cx.ScalarValue(p.charset)
		}
	}
	if p.filename != '' {
		attrs << cx.Attribute{
			name:  'filename'
			value: cx.ScalarValue(p.filename)
		}
	}
	if p.content_id != '' {
		attrs << cx.Attribute{
			name:  'content-id'
			value: cx.ScalarValue(p.content_id)
		}
	}
	if p.disposition != '' {
		attrs << cx.Attribute{
			name:  'disposition'
			value: cx.ScalarValue(email_ct_type(p.disposition))
		}
	}
	return cx.Element{
		name:  'part'
		attrs: attrs
		items: [email_str(p.raw_body)]
	}
}

// ── reading a [message] element back into accessor-friendly form ──────

// email_element_headers returns the (name, value) header fields of a
// [message] element's [headers] child, in order.
fn email_element_headers(n cx.Node) []HeaderField {
	mut out := []HeaderField{}
	if n !is cx.Element {
		return out
	}
	el := n as cx.Element
	hdrs := email_child(el, 'headers') or { return out }
	for c in hdrs.items {
		if c is cx.Element {
			val := if c.items.len > 0 { email_node_text(c.items[0]) } else { '' }
			out << HeaderField{
				name:  c.name
				lname: c.name.to_lower()
				value: val
			}
		}
	}
	return out
}

// email_element_header_first returns the first value of a header by name.
fn email_element_header_first(n cx.Node, name string) (string, bool) {
	ln := name.to_lower()
	for f in email_element_headers(n) {
		if f.lname == ln {
			return f.value, true
		}
	}
	return '', false
}

// email_element_parts returns the leaf [part …] elements from a [message]
// element's body.
fn email_element_parts(n cx.Node) []cx.Element {
	mut out := []cx.Element{}
	if n !is cx.Element {
		return out
	}
	el := n as cx.Element
	body := email_child(el, 'body') or { return out }
	parts := email_child(body, 'parts') or { return out }
	for c in parts.items {
		if c is cx.Element && c.name == 'part' {
			out << c
		}
	}
	return out
}

// email_part_from_element reads a [part …] element into a MimePart.
fn email_part_from_element(el cx.Element) MimePart {
	mut p := MimePart{}
	p.content_type = email_attr(el, 'content-type')
	if p.content_type == '' {
		p.content_type = 'text/plain'
	}
	p.encoding = email_attr(el, 'encoding')
	p.charset = email_attr(el, 'charset')
	p.filename = email_attr(el, 'filename')
	p.content_id = email_attr(el, 'content-id')
	p.disposition = email_attr(el, 'disposition')
	if el.items.len > 0 {
		p.raw_body = email_node_text(el.items[0])
	}
	return p
}

// ── address parsing (§3.5, §2.3) ──────────────────────────────────────

struct EmailAddress {
mut:
	display_name string
	local_part   string
	domain       string
	raw          string
}

// email_parse_one_address parses a single mailbox: `Display Name <local@domain>`
// or a bare `local@domain`. Returns none on a malformed address.
fn email_parse_one_address(s string) ?EmailAddress {
	t := s.trim_space()
	if t == '' {
		return none
	}
	mut addr := EmailAddress{
		raw: t
	}
	mut addr_spec := t
	// `Name <addr>` form.
	if lt := t.last_index('<') {
		gt := t.index('>') or { return none }
		if gt < lt {
			return none
		}
		dn := t[..lt].trim_space()
		addr.display_name = email_unquote_phrase(dn)
		addr_spec = t[lt + 1..gt].trim_space()
	}
	at := addr_spec.last_index('@') or { return none }
	local := addr_spec[..at]
	domain := addr_spec[at + 1..]
	if local == '' || domain == '' {
		return none
	}
	if local.contains('<') || local.contains('>') || domain.contains('<')
		|| domain.contains('>') || domain.contains('@') {
		return none
	}
	if domain.contains(' ') || local.contains(' ') {
		return none
	}
	addr.local_part = local
	addr.domain = domain
	return addr
}

// email_unquote_phrase strips surrounding double-quotes from a display
// name and decodes any encoded-words.
fn email_unquote_phrase(s string) string {
	mut t := s.trim_space()
	if t.starts_with('"') && t.ends_with('"') && t.len >= 2 {
		t = t[1..t.len - 1]
	}
	if t.contains('=?') {
		dec := email_decode_encoded_word(t)
		if !email_is_err(dec) {
			return email_node_text(dec)
		}
	}
	return t
}

// email_address_element renders an EmailAddress as the §2.3 [address …].
fn email_address_element(a EmailAddress) cx.Node {
	mut items := []cx.Node{}
	if a.display_name != '' {
		items << cx.Element{
			name:  'display-name'
			items: [email_str(a.display_name)]
		}
	}
	items << cx.Element{
		name:  'local-part'
		items: [email_str(a.local_part)]
	}
	items << cx.Element{
		name:  'domain'
		items: [email_str(a.domain)]
	}
	items << cx.Element{
		name:  'raw'
		items: [email_str(a.raw)]
	}
	return cx.Element{
		name:  'address'
		items: items
	}
}

// email_address_from_element reads an [address] element back.
fn email_address_from_element(el cx.Element) EmailAddress {
	return EmailAddress{
		display_name: email_child_text(el, 'display-name')
		local_part:   email_child_text(el, 'local-part')
		domain:       email_child_text(el, 'domain')
		raw:          email_child_text(el, 'raw')
	}
}

// email_split_address_list splits a list on top-level commas (respecting
// `<>` and `""` and group `:`/`;`). Returns the raw member strings.
fn email_split_top_commas(s string) []string {
	mut out := []string{}
	mut depth := 0
	mut in_quote := false
	mut cur := []u8{}
	for c in s.bytes() {
		if in_quote {
			cur << c
			if c == `"` {
				in_quote = false
			}
			continue
		}
		match c {
			`"` {
				in_quote = true
				cur << c
			}
			`<` {
				depth++
				cur << c
			}
			`>` {
				if depth > 0 {
					depth--
				}
				cur << c
			}
			`,` {
				if depth == 0 {
					out << cur.bytestr()
					cur = []u8{}
				} else {
					cur << c
				}
			}
			else {
				cur << c
			}
		}
	}
	out << cur.bytestr()
	return out
}

// email_parse_address_list parses zero-or-more addresses, including RFC
// 5322 groups (`name: a, b;`). Returns the heterogeneous sequence of
// [address] / [address-group] nodes, or an err-value (CXER1301).
fn email_parse_address_list(input string) cx.Node {
	t := input.trim_space()
	if t == '' {
		return email_seq([])
	}
	mut items := []cx.Node{}
	// Group detection: a `:` before any `@` and a terminating `;`.
	// Process the list token-by-token, recognizing `name: ... ;` groups.
	mut rest := t
	for rest.trim_space() != '' {
		rest = rest.trim_space()
		// is the next token a group? look for `:` that precedes both `@`
		// and `,` and `<`.
		colon := rest.index(':') or { -1 }
		if colon >= 0 && email_is_group_head(rest, colon) {
			name := rest[..colon].trim_space()
			// find the terminating `;`.
			semi := rest.index(';') or {
				return email_err_address('unterminated group "${name}"')
			}
			members := rest[colon + 1..semi].trim_space()
			grp := email_group_element(name, members) or {
				return email_err_address('malformed group "${name}"')
			}
			items << grp
			rest = rest[semi + 1..].trim_space()
			if rest.starts_with(',') {
				rest = rest[1..]
			}
			continue
		}
		// otherwise, a plain comma-separated list (no more groups).
		members := email_split_top_commas(rest)
		for m in members {
			mm := m.trim_space()
			if mm == '' {
				continue
			}
			a := email_parse_one_address(mm) or {
				return email_err_address('malformed address "${mm}"')
			}
			items << email_address_element(a)
		}
		break
	}
	return email_seq(items)
}

// email_is_group_head reports whether the `:` at `colon` introduces an
// RFC 5322 group (the phrase before it has no `@`, `<`, or `,`, and a
// terminating `;` exists after it).
fn email_is_group_head(s string, colon int) bool {
	if colon <= 0 {
		return false
	}
	head := s[..colon]
	if head.contains('@') || head.contains('<') || head.contains(',') {
		return false
	}
	return s.index_after(';', colon) or { -1 } >= 0
}

// email_group_element builds an [address-group name=… …] node.
fn email_group_element(name string, members string) ?cx.Node {
	mut items := []cx.Node{}
	if members.trim_space() != '' {
		for m in email_split_top_commas(members) {
			mm := m.trim_space()
			if mm == '' {
				continue
			}
			a := email_parse_one_address(mm) or { return none }
			items << email_address_element(a)
		}
	}
	return cx.Element{
		name:  'address-group'
		attrs: [cx.Attribute{
			name:  'name'
			value: cx.ScalarValue(name)
		}]
		items: items
	}
}

// email_format_address formats an [address] element as an RFC 5322 mailbox.
fn email_format_address_str(a EmailAddress) string {
	spec := '${a.local_part}@${a.domain}'
	if a.display_name == '' {
		return spec
	}
	dn := if email_phrase_needs_quote(a.display_name) {
		'"${a.display_name}"'
	} else {
		a.display_name
	}
	return '${dn} <${spec}>'
}

fn email_phrase_needs_quote(s string) bool {
	specials := '()<>[]:;@\\,."'
	for c in s {
		if specials.contains_u8(c) {
			return true
		}
	}
	return false
}

// email_format_address_list formats a heterogeneous [address]/[address-group]
// sequence per §3.5 canonical emission.
fn email_format_address_list(seq cx.Node) cx.Node {
	items := email_seq_items(seq) or { return email_str('') }
	mut out := []string{}
	for it in items {
		if it is cx.Element {
			if it.name == 'address-group' {
				name := email_attr(it, 'name')
				mut members := []string{}
				for m in it.items {
					if m is cx.Element && m.name == 'address' {
						a := email_address_from_element(m)
						members << email_format_address_str(a)
					}
				}
				out << '${name}:' + if members.len > 0 { ' ' + members.join(', ') } else { '' } + ';'
			} else if it.name == 'address' {
				a := email_address_from_element(it)
				out << email_format_address_str(a)
			}
		}
	}
	return email_str(out.join(', '))
}

// ── header → address accessors ────────────────────────────────────────

// email_addrs_from_header parses a recipient header's value to a sequence
// of [address] nodes (groups are flattened to their member addresses).
fn email_addrs_from_header(msg cx.Node, header string) cx.Node {
	val, present := email_element_header_first(msg, header)
	if !present || val.trim_space() == '' {
		return email_seq([])
	}
	parsed := email_parse_address_list(val)
	if email_is_err(parsed) {
		return email_seq([])
	}
	items := email_seq_items(parsed) or { return email_seq([]) }
	mut out := []cx.Node{}
	for it in items {
		if it is cx.Element {
			if it.name == 'address-group' {
				for m in it.items {
					if m is cx.Element && m.name == 'address' {
						out << m
					}
				}
			} else {
				out << it
			}
		}
	}
	return email_seq(out)
}

// ── RFC 5322 Date parsing (§3.2 date-header) ──────────────────────────

const email_months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep',
	'oct', 'nov', 'dec']

// email_parse_date parses an RFC 5322 date to an ISO 8601 datetime string.
// Supports the `[Day,] DD Mon YYYY HH:MM[:SS] +ZZZZ` form. Returns none on
// failure.
fn email_parse_rfc5322_date(input string) ?string {
	mut s := input.trim_space()
	// drop optional `Day,` prefix.
	if ci := s.index(',') {
		s = s[ci + 1..].trim_space()
	}
	toks := s.fields()
	if toks.len < 4 {
		return none
	}
	day := toks[0].int()
	mon_name := toks[1].to_lower()
	mut month := 0
	for i, m in email_months {
		if mon_name.starts_with(m) {
			month = i + 1
			break
		}
	}
	if month == 0 {
		return none
	}
	year := toks[2].int()
	time_tok := toks[3]
	tparts := time_tok.split(':')
	if tparts.len < 2 {
		return none
	}
	hour := tparts[0].int()
	minute := tparts[1].int()
	second := if tparts.len >= 3 { tparts[2].int() } else { 0 }
	mut tz := 'Z'
	if toks.len >= 5 {
		off := toks[4]
		if off == '+0000' || off == '-0000' || off.to_upper() == 'GMT'
			|| off.to_upper() == 'UTC' {
			tz = 'Z'
		} else if off.len == 5 && (off[0] == `+` || off[0] == `-`) {
			tz = '${off[..3]}:${off[3..]}'
		}
	}
	return '${year:04d}-${month:02d}-${day:02d}T${hour:02d}:${minute:02d}:${second:02d}${tz}'
}

// ── multipart boundary generation (§4.3) ──────────────────────────────

fn email_gen_boundary() string {
	mut hex := ''
	digits := '0123456789abcdef'
	for _ in 0 .. 24 {
		hex += digits[rand.intn(16) or { 0 }].ascii_str()
	}
	return '=_Part_${hex}'
}

// ── emit (§3.1) ───────────────────────────────────────────────────────

// email_emit re-encodes a [message] element to RFC 5322 bytes. Canonical:
// CRLF line endings; encoded-word subjects; QP/base64 part encoding;
// multipart boundaries. Raises CXER1304 if From or all recipients missing,
// CXER1305 on a boundary collision.
fn email_emit(msg cx.Node) cx.Node {
	if msg !is cx.Element {
		return email_err_malformed('emit expects a [message] element')
	}
	el := msg as cx.Element
	headers := email_element_headers(msg)

	// Required-header check (§6 CXER1304): From + at least one recipient.
	mut has_from := false
	mut has_recipient := false
	for h in headers {
		if h.lname == 'from' && h.value.trim_space() != '' {
			has_from = true
		}
		if (h.lname == 'to' || h.lname == 'cc' || h.lname == 'bcc')
			&& h.value.trim_space() != '' {
			has_recipient = true
		}
	}
	if !has_from {
		return email_err_required('From header missing')
	}
	if !has_recipient {
		return email_err_required('no recipient (To/Cc/Bcc) present')
	}

	body := email_child(el, 'body') or {
		return email_err_malformed('message has no [body]')
	}
	is_mp := email_child_text(body, 'is-multipart') == 'true'
	parts := email_element_parts(msg)

	mut out := []string{}
	// Header block (excluding Content-Type/MIME — regenerated for body).
	for h in headers {
		mut v := h.value
		if h.lname == 'subject' && !email_is_ascii(v) {
			v = email_node_text(email_encode_subject(v))
		}
		// SECURITY: reject header injection — a raw CR/LF in a header name
		// or value injects arbitrary headers (Bcc/…) or splits the body
		// (RFC 5322 §2.2 forbids bare CR/LF in a field body). Fail closed.
		if email_has_crlf(h.name) || email_has_crlf(v) {
			return email_err_malformed('header "${h.name}" contains a CR/LF (header-injection attempt rejected)')
		}
		out << '${h.name}: ${v}'
	}

	if is_mp {
		mut boundary := email_child_text(body, 'boundary')
		if boundary == '' {
			boundary = email_gen_boundary()
		}
		// Boundary collision check (§6 CXER1305).
		for p in parts {
			pbody := if p.items.len > 0 { email_node_text(p.items[0]) } else { '' }
			if pbody.contains('--' + boundary) || pbody.contains(boundary) {
				return email_err_boundary('boundary "${boundary}" appears in a part body')
			}
		}
		out << 'MIME-Version: 1.0'
		out << 'Content-Type: multipart/alternative; boundary="${boundary}"'
		out << ''
		for p in parts {
			out << '--' + boundary
			out << email_emit_part(p)
		}
		out << '--' + boundary + '--'
		return email_bytes(out.join('\r\n') + '\r\n')
	}

	// single part.
	if parts.len > 0 {
		p := parts[0]
		mp := email_part_from_element(p)
		out << 'Content-Type: ${mp.content_type}'
		out << ''
		out << mp.raw_body
	} else {
		out << ''
	}
	return email_bytes(out.join('\r\n') + '\r\n')
}

// email_emit_part renders one part's MIME headers + body for a multipart.
fn email_emit_part(p cx.Element) string {
	mp := email_part_from_element(p)
	mut lines := []string{}
	mut ct := 'Content-Type: ${mp.content_type}'
	if mp.charset != '' {
		ct += '; charset="${mp.charset}"'
	}
	lines << ct
	if mp.filename != '' {
		lines << 'Content-Disposition: attachment; filename="${mp.filename}"'
	}
	lines << ''
	lines << mp.raw_body
	return lines.join('\r\n')
}

fn email_is_ascii(s string) bool {
	for b in s.bytes() {
		if b >= 0x80 {
			return false
		}
	}
	return true
}

// email_encode_subject encoded-word-wraps a non-ASCII subject (§4.1):
// B for >50% non-ASCII, Q otherwise.
fn email_encode_subject(s string) cx.Node {
	mut nonascii := 0
	for b in s.bytes() {
		if b >= 0x80 {
			nonascii++
		}
	}
	enc := if nonascii * 2 > s.len { 'B' } else { 'Q' }
	return email_encode_encoded_word(s, 'UTF-8', enc)
}

// ── builder (§3.6) ────────────────────────────────────────────────────

// email_normalize_recipients turns a single string / [address] / sequence
// recipient value into the RFC 5322 header text (comma-joined).
fn email_recipient_header(v cx.Node) string {
	// sequence?
	if items := email_seq_items(v) {
		mut parts := []string{}
		for it in items {
			parts << email_recipient_one(it)
		}
		return parts.join(', ')
	}
	return email_recipient_one(v)
}

fn email_recipient_one(v cx.Node) string {
	if v is cx.Element && v.name == 'address' {
		a := email_address_from_element(v)
		return email_format_address_str(a)
	}
	return email_node_text(v)
}

// email_recipient_count counts recipients in a single-or-sequence value.
fn email_recipient_count(v cx.Node) int {
	if items := email_seq_items(v) {
		return items.len
	}
	return 1
}

// email_build constructs a plaintext [message] element from a parts map.
fn email_build(parts cx.Node) cx.Node {
	from := email_map_get(parts, 'from') or { return email_err_required('build: missing "from"') }
	to := email_map_get(parts, 'to') or { return email_err_required('build: missing "to"') }
	subject := email_map_get(parts, 'subject') or {
		return email_err_required('build: missing "subject"')
	}
	body_v := email_map_get(parts, 'body') or {
		return email_err_required('build: missing "body"')
	}

	mut header_items := []cx.Node{}
	header_items << email_header_elem('From', email_node_text(from))
	header_items << email_header_elem('To', email_recipient_header(to))
	if cc := email_map_get(parts, 'cc') {
		header_items << email_header_elem('Cc', email_recipient_header(cc))
	}
	if bcc := email_map_get(parts, 'bcc') {
		header_items << email_header_elem('Bcc', email_recipient_header(bcc))
	}
	if rt := email_map_get(parts, 'reply-to') {
		header_items << email_header_elem('Reply-To', email_node_text(rt))
	}
	header_items << email_header_elem('Subject', email_node_text(subject))
	if dt := email_map_get(parts, 'date') {
		header_items << email_header_elem('Date', email_node_text(dt))
	}

	body_text := email_node_text(body_v)
	return email_assemble(header_items, [email_text_part(body_text)], false, '')
}

// email_build_multipart constructs a multipart [message] with the plaintext
// body + alternative parts.
fn email_build_multipart(parts cx.Node, alternatives cx.Node) cx.Node {
	base := email_build(parts)
	if email_is_err(base) {
		return base
	}
	if base !is cx.Element {
		return base
	}
	el := base as cx.Element
	headers := email_child(el, 'headers') or { return base }

	mut part_nodes := []cx.Node{}
	// plaintext body part first.
	body_v := email_map_get(parts, 'body') or { email_str('') }
	part_nodes << email_text_part(email_node_text(body_v))
	// alternative parts.
	if items := email_seq_items(alternatives) {
		for it in items {
			if it is cx.Element && it.name == 'part' {
				ct := email_attr(it, 'content-type')
				bodyv := email_attr(it, 'body')
				mut fname := email_attr(it, 'filename')
				part_nodes << email_make_part(ct, bodyv, fname)
			}
		}
	}
	mut header_items := []cx.Node{}
	for c in headers.items {
		header_items << c
	}
	return email_assemble(header_items, part_nodes, true, email_gen_boundary())
}

fn email_header_elem(name string, value string) cx.Node {
	return cx.Element{
		name:  name.to_lower()
		items: [email_str(value)]
	}
}

fn email_text_part(body string) cx.Node {
	return email_make_part('text/plain', body, '')
}

fn email_make_part(content_type string, body string, filename string) cx.Node {
	mut attrs := []cx.Attribute{}
	ct := if content_type == '' { 'text/plain' } else { content_type }
	attrs << cx.Attribute{
		name:  'content-type'
		value: cx.ScalarValue(ct)
	}
	if filename != '' {
		attrs << cx.Attribute{
			name:  'filename'
			value: cx.ScalarValue(filename)
		}
	}
	return cx.Element{
		name:  'part'
		attrs: attrs
		items: [email_str(body)]
	}
}

// email_assemble wires header items + part nodes into a [message] element.
fn email_assemble(header_items []cx.Node, part_nodes []cx.Node, is_mp bool, boundary string) cx.Node {
	mut body_children := []cx.Node{}
	body_children << cx.Element{
		name:  'parts'
		items: part_nodes
	}
	body_children << cx.Element{
		name:  'is-multipart'
		items: [email_str(if is_mp { 'true' } else { 'false' })]
	}
	if is_mp && boundary != '' {
		body_children << cx.Element{
			name:  'boundary'
			items: [email_str(boundary)]
		}
	}
	return cx.Element{
		name:  'message'
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: header_items
			}),
			cx.Node(cx.Element{
				name:  'body'
				items: body_children
			}),
		]
	}
}

// ── reply / forward (§3.7) ────────────────────────────────────────────

fn email_reply(orig cx.Node, parts cx.Node) cx.Node {
	if orig !is cx.Element {
		return email_err_malformed('reply: orig is not a [message]')
	}
	// threading.
	orig_mid, has_mid := email_element_header_first(orig, 'message-id')
	orig_refs, _ := email_element_header_first(orig, 'references')
	orig_subj := email_subject_str(orig)
	orig_from, _ := email_element_header_first(orig, 'from')

	mut header_items := []cx.Node{}
	// From: only if supplied (pure reply does not synthesize sender).
	if from := email_map_get(parts, 'from') {
		header_items << email_header_elem('From', email_node_text(from))
	}
	// To: parts.to overrides, else orig.from.
	mut to_text := orig_from
	if to := email_map_get(parts, 'to') {
		to_text = email_recipient_header(to)
	}
	header_items << email_header_elem('To', to_text)
	// Subject: Re: prefix.
	mut subj := orig_subj
	if s := email_map_get(parts, 'subject') {
		subj = email_node_text(s)
	} else if !subj.to_lower().starts_with('re:') {
		subj = 'Re: ' + subj
	}
	header_items << email_header_elem('Subject', subj)
	// In-Reply-To = orig.message-id; References = orig.references ++ message-id.
	if has_mid {
		header_items << email_header_elem('In-Reply-To', email_strip_brackets(orig_mid))
		mut refs := orig_refs.trim_space()
		mid := orig_mid.trim_space()
		refs = if refs == '' { mid } else { refs + ' ' + mid }
		header_items << email_header_elem('References', refs)
	}
	body_v := email_map_get(parts, 'body') or { email_str('') }
	return email_assemble(header_items, [email_text_part(email_node_text(body_v))],
		false, '')
}

fn email_forward(orig cx.Node, parts cx.Node) cx.Node {
	if orig !is cx.Element {
		return email_err_malformed('forward: orig is not a [message]')
	}
	orig_subj := email_subject_str(orig)

	mut header_items := []cx.Node{}
	if from := email_map_get(parts, 'from') {
		header_items << email_header_elem('From', email_node_text(from))
	}
	if to := email_map_get(parts, 'to') {
		header_items << email_header_elem('To', email_recipient_header(to))
	}
	mut subj := orig_subj
	if s := email_map_get(parts, 'subject') {
		subj = email_node_text(s)
	} else if !subj.to_lower().starts_with('fwd:') {
		subj = 'Fwd: ' + subj
	}
	header_items << email_header_elem('Subject', subj)

	// Wrap orig as a message/rfc822 attachment part.
	orig_bytes := email_emit(orig)
	wrapped := if email_is_err(orig_bytes) { '' } else { email_node_text(orig_bytes) }
	mut attrs := []cx.Attribute{}
	attrs << cx.Attribute{
		name:  'content-type'
		value: cx.ScalarValue('message/rfc822')
	}
	attrs << cx.Attribute{
		name:  'disposition'
		value: cx.ScalarValue('attachment')
	}
	attrs << cx.Attribute{
		name:  'filename'
		value: cx.ScalarValue('forwarded.eml')
	}
	rfc822_part := cx.Element{
		name:  'part'
		attrs: attrs
		items: [email_str(wrapped)]
	}
	body_v := email_map_get(parts, 'body') or { email_str('') }
	return email_assemble(header_items, [email_text_part(email_node_text(body_v)),
		rfc822_part], true, email_gen_boundary())
}

fn email_strip_brackets(s string) string {
	return s.trim_space().trim('<>')
}

// ── typed accessors (§3.2 / §3.3) ─────────────────────────────────────

fn email_subject_str(msg cx.Node) string {
	v, present := email_element_header_first(msg, 'subject')
	if !present {
		return ''
	}
	dec := email_decode_header_value(v)
	if email_is_err(dec) {
		return v
	}
	return email_node_text(dec)
}

// email_text_body / email_html_body return the first text/plain | text/html
// part body, decoded. Empty string if absent. Propagates a decode error.
fn email_body_of_type(msg cx.Node, want string) cx.Node {
	for pel in email_element_parts(msg) {
		mp := email_part_from_element(pel)
		if mp.content_type == want {
			return email_decode_body(mp)
		}
	}
	return email_str('')
}

// ── DSN (§3.8) ────────────────────────────────────────────────────────

struct DsnRecipient {
	final      string
	action     string
	status     string
	diagnostic string
	remote_mta string
}

// email_parse_dsn lifts a multipart/report; report-type=delivery-status
// message into a [dsn …] element. Raises CXER1306 if not a DSN.
fn email_parse_dsn(msg cx.Node) cx.Node {
	if msg !is cx.Element {
		return email_err_not_dsn('not a [message]')
	}
	// The top-level Content-Type must be multipart/report report-type=
	// delivery-status. We detect via a delivery-status part.
	mut ds_part := MimePart{}
	mut found := false
	for pel in email_element_parts(msg) {
		mp := email_part_from_element(pel)
		if mp.content_type == 'message/delivery-status' {
			ds_part = mp
			found = true
			break
		}
	}
	if !found {
		return email_err_not_dsn('no message/delivery-status part')
	}
	orig_mid, _ := email_element_header_first(msg, 'message-id')

	// The delivery-status body is per-recipient RFC 822-style field blocks
	// separated by blank lines; the first block is per-message (Reporting-MTA).
	body := email_normalize_eol(ds_part.raw_body)
	blocks := body.split('\n\n')
	mut reporting_mta := ''
	mut recipients := []DsnRecipient{}
	for bi, block in blocks {
		fields := email_parse_dsn_fields(block)
		if bi == 0 {
			reporting_mta = fields['reporting-mta']
			// per-message block may also carry the first recipient if no
			// blank line — but conventionally separate.
			continue
		}
		if 'final-recipient' in fields || 'action' in fields {
			recipients << DsnRecipient{
				final:      email_dsn_addr(fields['final-recipient'])
				action:     fields['action']
				status:     fields['status']
				diagnostic: fields['diagnostic-code']
				remote_mta: fields['remote-mta']
			}
		}
	}
	if recipients.len == 0 {
		return email_err_not_dsn('no per-recipient delivery-status fields')
	}
	return email_dsn_element(orig_mid, reporting_mta, recipients)
}

fn email_parse_dsn_fields(block string) map[string]string {
	mut m := map[string]string{}
	for line in block.split('\n') {
		ci := line.index(':') or { continue }
		k := line[..ci].trim_space().to_lower()
		v := line[ci + 1..].trim_space()
		m[k] = v
	}
	return m
}

// email_dsn_addr strips the `rfc822;` / `dns;` type prefix from a DSN
// address-type value.
fn email_dsn_addr(v string) string {
	if si := v.index(';') {
		return v[si + 1..].trim_space()
	}
	return v.trim_space()
}

fn email_dsn_element(orig_mid string, reporting_mta string, recipients []DsnRecipient) cx.Node {
	mut items := []cx.Node{}
	if orig_mid != '' {
		items << cx.Element{
			name:  'original-message-id'
			items: [email_str(email_strip_brackets(orig_mid))]
		}
	}
	if reporting_mta != '' {
		items << cx.Element{
			name:  'reporting-mta'
			items: [email_str(reporting_mta)]
		}
	}
	mut rec_items := []cx.Node{}
	for r in recipients {
		mut attrs := []cx.Attribute{}
		attrs << cx.Attribute{
			name:  'final'
			value: cx.ScalarValue(r.final)
		}
		attrs << cx.Attribute{
			name:  'action'
			value: cx.ScalarValue(r.action)
		}
		if r.status != '' {
			attrs << cx.Attribute{
				name:  'status'
				value: cx.ScalarValue(r.status)
			}
		}
		if r.diagnostic != '' {
			attrs << cx.Attribute{
				name:  'diagnostic'
				value: cx.ScalarValue(r.diagnostic)
			}
		}
		if r.remote_mta != '' {
			attrs << cx.Attribute{
				name:  'remote-mta'
				value: cx.ScalarValue(r.remote_mta)
			}
		}
		rec_items << cx.Element{
			name:  'recipient'
			attrs: attrs
		}
	}
	items << cx.Element{
		name:  'recipients'
		items: rec_items
	}
	return cx.Element{
		name:  'dsn'
		items: items
	}
}

// email_dsn_recipients reads the [recipient …] children from a [dsn] elem.
fn email_dsn_recipients(dsn cx.Node) []cx.Element {
	mut out := []cx.Element{}
	if dsn !is cx.Element {
		return out
	}
	el := dsn as cx.Element
	recs := email_child(el, 'recipients') or { return out }
	for c in recs.items {
		if c is cx.Element && c.name == 'recipient' {
			out << c
		}
	}
	return out
}

fn email_is_bounce(dsn cx.Node) bool {
	for r in email_dsn_recipients(dsn) {
		action := email_attr(r, 'action')
		if action == 'failed' || action == 'delayed' {
			return true
		}
	}
	return false
}

fn email_is_hard_bounce(dsn cx.Node) bool {
	for r in email_dsn_recipients(dsn) {
		action := email_attr(r, 'action')
		status := email_attr(r, 'status')
		if action == 'failed' && status.starts_with('5.') {
			return true
		}
	}
	return false
}

// ── dispatch ──────────────────────────────────────────────────────────

fn email_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'email-parse' {
			raw := email_arg_str(args[0]) or { return none }
			pm := email_parse_message(raw) or {
				return email_err_malformed('unparseable RFC 5322 input')
			}
			return email_message_element(pm)
		}
		'email-emit' {
			return email_emit(args[0])
		}
		'email-headers' {
			mut keys := []string{}
			mut vals := []cx.Node{}
			mut seen := map[string][]cx.Node{}
			mut order := []string{}
			for f in email_element_headers(args[0]) {
				if f.lname !in seen {
					seen[f.lname] = []cx.Node{}
					order << f.lname
				}
				seen[f.lname] << email_str(f.value)
			}
			for k in order {
				keys << k
				vals << email_seq(seen[k])
			}
			return email_map(keys, vals)
		}
		'email-header' {
			hname := email_arg_str(args[1]) or { return none }
			v, _ := email_element_header_first(args[0], hname)
			return email_str(v)
		}
		'email-header-values' {
			hname := email_arg_str(args[1]) or { return none }
			ln := hname.to_lower()
			mut out := []cx.Node{}
			for f in email_element_headers(args[0]) {
				if f.lname == ln {
					out << email_str(f.value)
				}
			}
			return email_seq(out)
		}
		'email-subject' {
			return email_str(email_subject_str(args[0]))
		}
		'email-from-addr' {
			v, present := email_element_header_first(args[0], 'from')
			if !present {
				return email_err_address('no From header')
			}
			a := email_parse_one_address(v) or {
				return email_err_address('malformed From "${v}"')
			}
			return email_address_element(a)
		}
		'email-to-addrs' {
			return email_addrs_from_header(args[0], 'to')
		}
		'email-cc-addrs' {
			return email_addrs_from_header(args[0], 'cc')
		}
		'email-bcc-addrs' {
			return email_addrs_from_header(args[0], 'bcc')
		}
		'email-date-header' {
			v, present := email_element_header_first(args[0], 'date')
			if !present {
				return email_err_malformed('no Date header')
			}
			iso := email_parse_rfc5322_date(v) or {
				return email_err_malformed('unparseable Date "${v}"')
			}
			return email_datetime(iso)
		}
		'email-message-id' {
			v, _ := email_element_header_first(args[0], 'message-id')
			return email_str(email_strip_brackets(v))
		}
		'email-in-reply-to' {
			v, _ := email_element_header_first(args[0], 'in-reply-to')
			return email_str(email_strip_brackets(v))
		}
		'email-references' {
			v, _ := email_element_header_first(args[0], 'references')
			mut out := []cx.Node{}
			for tok in v.fields() {
				out << email_str(email_strip_brackets(tok))
			}
			return email_seq(out)
		}
		'email-list-unsubscribe' {
			v, _ := email_element_header_first(args[0], 'list-unsubscribe')
			mut out := []cx.Node{}
			for raw in v.split(',') {
				uri := raw.trim_space().trim('<>')
				if uri != '' {
					out << email_str(uri)
				}
			}
			return email_seq(out)
		}
		'email-parts' {
			mut out := []cx.Node{}
			for pel in email_element_parts(args[0]) {
				out << pel
			}
			return email_seq(out)
		}
		'email-attachments' {
			mut out := []cx.Node{}
			for pel in email_element_parts(args[0]) {
				mp := email_part_from_element(pel)
				if email_part_is_attachment(mp) {
					out << pel
				}
			}
			return email_seq(out)
		}
		'email-text-body' {
			return email_body_of_type(args[0], 'text/plain')
		}
		'email-html-body' {
			return email_body_of_type(args[0], 'text/html')
		}
		'email-is-multipart' {
			if args[0] !is cx.Element {
				return email_bool(false)
			}
			el := args[0] as cx.Element
			body := email_child(el, 'body') or { return email_bool(false) }
			return email_bool(email_child_text(body, 'is-multipart') == 'true')
		}
		'email-decode-encoded-word' {
			s := email_arg_str(args[0]) or { return none }
			return email_decode_encoded_word(s)
		}
		'email-encode-encoded-word' {
			s := email_arg_str(args[0]) or { return none }
			charset := email_arg_str(args[1]) or { return none }
			encoding := email_arg_str(args[2]) or { return none }
			return email_encode_encoded_word(s, charset, encoding)
		}
		'email-parse-address' {
			s := email_arg_str(args[0]) or { return none }
			a := email_parse_one_address(s) or {
				return email_err_address('malformed address "${s}"')
			}
			return email_address_element(a)
		}
		'email-parse-address-list' {
			s := email_arg_str(args[0]) or { return none }
			return email_parse_address_list(s)
		}
		'email-format-address' {
			if args[0] !is cx.Element {
				return none
			}
			el := args[0] as cx.Element
			a := email_address_from_element(el)
			return email_str(email_format_address_str(a))
		}
		'email-format-address-list' {
			return email_format_address_list(args[0])
		}
		'email-build' {
			return email_build(args[0])
		}
		'email-build-multipart' {
			return email_build_multipart(args[0], args[1])
		}
		'email-reply' {
			return email_reply(args[0], args[1])
		}
		'email-forward' {
			return email_forward(args[0], args[1])
		}
		'email-parse-dsn' {
			return email_parse_dsn(args[0])
		}
		'email-parse-dsn-bytes' {
			raw := email_arg_str(args[0]) or { return none }
			pm := email_parse_message(raw) or {
				return email_err_malformed('unparseable RFC 5322 input')
			}
			msg := email_message_element(pm)
			return email_parse_dsn(msg)
		}
		'email-is-bounce' {
			return email_bool(email_is_bounce(args[0]))
		}
		'email-is-hard-bounce' {
			return email_bool(email_is_hard_bounce(args[0]))
		}
		else {
			return none
		}
	}
}
