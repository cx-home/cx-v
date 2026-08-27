@[has_globals]
module code

import cx
import os
import net
import net.mbedtls
import compress.gzip
import compress.zstd
import sync
import time

// stdlib_http.v — the RING-1 CLIENT half of `cx-stdlib/http`
// (spec/02-inprogress/stdlib_http.md; #651/#516 I3 seam H). This is the
// http-client PACK of the §4 cli profile (cx_partition.md): one-shot
// verbs, generic request, pooled send, PURE message construction +
// introspection (§3.4), and the SSE CLIENT (sse-connect / sse-events /
// source-open / last-event-id). The SERVE half — listen/accept/respond/
// stop, [$http:serve], serializers, SSE server push — lives in
// stdlib_http_serve.v (Ring 2, "http/net serve" per cx_partition.md §2).
//
// The client reaches the network two ways, both Ring-1-clean: the
// one-shot/pooled path dials V `net`/`net.mbedtls` directly
// (HttpPoolConn), and the SSE client rides the net-core buffered handle
// table (net_core.v — dial/read/close + §4.5 SSRF guard). Every network
// verb requires the `net` capability — http introduces NO new
// capability (§5).
//
// ── CAPABILITY ENFORCEMENT (§4.1, §5) ───────────────────────────────
//   The network verbs (get/post/put/del/patch/head/options/request/send,
//   sse-connect/sse-events) are impure and every effect point is gated
//   on `net` (the resource is the request URL's canonical host:port).
//   The FIRST thing every gated primitive does — after the pure
//   URL-shape / arg-shape validation that can surface CXER4525/CXER4539
//   even under a grant — is `cap_guard('net', resource)`, fail-closed
//   BEFORE any socket touch. Under the conformance harness's empty
//   capability set the guard returns the CXER0271 err VALUE and the verb
//   short-circuits, so the deterministic deny-lane suite sees CXER0271.
//   The capability-GRANTED live paths (real dial/request/stream) run
//   only behind a granted `net` cap (implementation-phase granted
//   harness / manual demo).
//
//   Capability-FREE (no guard — PURE introspection over a materialized
//   message value, §3.4): status, ok, header, headers, headers-named,
//   has-body, body-bytes, body-bytes-wire, body-text. Also capability-free
//   (pool/handle bookkeeping, no net access, §3.1/§5): client, close.
//
// ── ERROR BAND (§8) ─────────────────────────────────────────────────
//   http owns cx-err:CXER4525–CXER4543 (E_HTTP_*) — the next free block
//   above cx-stdlib/net's CXER4500–4524 (governance.md §9.6). The rev-5
//   draft proposed 4500-4518, which collided with net's final band; this
//   impl + the spec §8 table + the governance registry use 4525-4543.
//
// ── CX value model ──────────────────────────────────────────────────
//   int/string/bool/bytes/null scalars; sequence = Element{'__cx_seq__'};
//   bytes are a string ScalarValue carrying data_type=.bytes_type.
//   A [response]/[request] is a homoiconic element built by the caller as
//   a literal; introspection reads its attrs (status) + child elements
//   ([headers]/[header]/[body]). A client/server/exchange is an opaque
//   handle element ([http-client]/[http-server]/[exchange]).

// ── error codes (§8) — http owns CXER4525–CXER4543 ───────────────────
pub const http_err_url_invalid = 'cx-err:CXER4525' // E_HTTP_URL_INVALID
const http_err_invalid_response = 'cx-err:CXER4526' // E_HTTP_INVALID_RESPONSE
const http_err_redirect_loop = 'cx-err:CXER4527' // E_HTTP_REDIRECT_LOOP
const http_err_too_many_redirects = 'cx-err:CXER4528' // E_HTTP_TOO_MANY_REDIRECTS
const http_err_redirect_invalid = 'cx-err:CXER4529' // E_HTTP_REDIRECT_INVALID
const http_err_body_too_large = 'cx-err:CXER4530' // E_HTTP_BODY_TOO_LARGE
const http_err_request_timeout = 'cx-err:CXER4534' // E_HTTP_REQUEST_TIMEOUT (§4.5 whole-request deadline)
const http_err_content_decode = 'cx-err:CXER4532' // E_HTTP_CONTENT_DECODE
pub const http_err_arg_invalid = 'cx-err:CXER4539' // E_HTTP_ARG_INVALID
pub const http_err_respond_invalid = 'cx-err:CXER4541' // E_HTTP_RESPOND_INVALID
pub const http_err_no_request = 'cx-err:CXER4542' // E_HTTP_NO_REQUEST — clean EOF/idle: peer sent nothing (not a framing error)

// ── value builders ───────────────────────────────────────────────────
fn http_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn http_bytes(buf []u8) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(buf.bytestr())
		data_type: cx.ScalarType.bytes_type
	}
}

pub fn http_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

pub fn http_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

pub fn http_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

fn http_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// http_empty_nodeset is http's "absence channel" value (§2.5): an empty
// node-set (no result). Used by `header` on an absent field name.
fn http_empty_nodeset() cx.Node {
	return http_seq([])
}

// ── argument readers ─────────────────────────────────────────────────
pub fn http_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn http_arg_bytes(n cx.Node) ?[]u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	note_operand_fault('http', 'http-', 'bytes', n)
	return none
}

// ── message introspection helpers (operate on a [request]/[response]) ─
//
// http_elem returns the Element if n is one, else none.
pub fn http_elem(n cx.Node) ?cx.Element {
	if n is cx.Element {
		return n
	}
	return none
}

// http_attr reads a named attribute's string value off an element, or none.
pub fn http_attr(e cx.Element, name string) ?string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return none
}

// http_child returns the first child element with the given tag name.
pub fn http_child(e cx.Element, name string) ?cx.Element {
	for it in e.items {
		if it is cx.Element {
			if it.name == name {
				return it
			}
		}
	}
	return none
}

// http_is_response / http_is_request classify the message kind.
pub fn http_is_response(e cx.Element) bool {
	return e.name == 'response'
}

fn http_is_message(e cx.Element) bool {
	return e.name == 'response' || e.name == 'request'
}

// http_headers_block returns the [headers] child's [header …] elements, or
// an empty list. A message may carry headers either as a [headers] wrapper
// (the §2.2 locked shape: [response [headers [header …]]]) or, defensively,
// as direct [header …] children.
pub fn http_header_elems(e cx.Element) []cx.Element {
	mut out := []cx.Element{}
	if hb := http_child(e, 'headers') {
		for it in hb.items {
			if it is cx.Element {
				if it.name == 'header' {
					out << it
				}
			}
		}
		return out
	}
	for it in e.items {
		if it is cx.Element {
			if it.name == 'header' {
				out << it
			}
		}
	}
	return out
}

// http_body_bytes returns the [body] child's raw octets (total, §2.5):
// empty bytes for a missing or empty body. The [body] child holds a
// bytes/string scalar item (the §2.3 octets-only body rule).
pub fn http_body_octets(e cx.Element) []u8 {
	bb := http_child(e, 'body') or { return []u8{} }
	for it in bb.items {
		if it is cx.ScalarNode {
			v := it.value
			if v is string {
				return v.bytes()
			}
		}
	}
	return []u8{}
}

// http_has_body — structural body presence (§2.5): true iff a [body] child
// is framed (regardless of whether it is empty).
fn http_struct_has_body(e cx.Element) bool {
	if _ := http_child(e, 'body') {
		return true
	}
	return false
}

// http_charset extracts the charset token from the Content-Type header
// (a minimal inline scan, §3.4). Defaults to utf-8.
fn http_charset(e cx.Element) string {
	for h in http_header_elems(e) {
		name := http_attr(h, 'name') or { continue }
		if name.to_lower() == 'content-type' {
			val := http_attr(h, 'value') or { return 'utf-8' }
			low := val.to_lower()
			idx := low.index('charset=') or { return 'utf-8' }
			mut cs := low[idx + 'charset='.len..].trim_space()
			// stop at the next parameter separator
			if sc := cs.index(';') {
				cs = cs[..sc]
			}
			return cs.trim('"').trim_space()
		}
	}
	return 'utf-8'
}

// ── primitive dispatch ────────────────────────────────────────────────
//
// Gated network primitives of the CLIENT half — every name maps to the
// `net` capability and is guarded fail-closed AFTER the pure URL-shape /
// arg-shape validation (so a malformed URL surfaces CXER4525 / a bad arg
// CXER4539 even under a grant) but BEFORE any socket touch. The PURE
// introspection primitives (status/ok/header/headers/headers-named/
// has-body/body-*) and the pool-bookkeeping ones (client/close) are
// intentionally absent. The serve half's list is
// http_serve_gated_prims (stdlib_http_serve.v, seam H).
const http_gated_prims = ['http-get', 'http-post', 'http-put', 'http-del', 'http-patch',
	'http-head', 'http-options', 'http-request', 'http-send']

// http_client_stdlib_builtin — the env-free dispatch slice for the http
// CLIENT pack (Ring 1, cx_partition.md §4 cli profile). Chained directly
// in stdlib_dispatch.v; the serve half (http_serve_stdlib_builtin,
// stdlib_http_serve.v) registers on the Ring-1 registry instead (seam H).
// Name sets are disjoint, so dispatch order between the halves is
// behavior-neutral.
fn http_client_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// not an http primitive → let the dispatch chain continue
	if !name.starts_with('http-') {
		return none
	}

	match name {
		// ── §3.1 client construction (PURE bookkeeping, no net) ──────────
		'http-client' {
			return http_client_impl(args)
		}
		'http-close' {
			// §5: no capability — release a pool/server/exchange handle.
			// Idempotent (§2.1) — double close never raises CXER4535.
			return http_null()
		}

		// ── §3.4 introspection (PURE, §3.4 — no cap, total accessors) ────
		'http-status' {
			return http_status_impl(args)
		}
		'http-ok' {
			return http_ok_impl(args)
		}
		'http-header' {
			return http_header_impl(args)
		}
		'http-headers' {
			return http_headers_impl(args)
		}
		'http-headers-named' {
			return http_headers_named_impl(args)
		}
		'http-has-body' {
			e := http_elem(args[0]) or { return http_bool(false) }
			if !http_is_message(e) {
				return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: has-body expects a [request]/[response]')
			}
			return http_bool(http_struct_has_body(e))
		}
		'http-body-bytes', 'http-body-bytes-wire' {
			// total accessor (§2.5/§3.4): empty bytes for no/empty body.
			// body-bytes returns the DECODED entity (the [body] child);
			// body-bytes-wire returns the on-wire/compressed entity — the
			// [body-wire] child when §4.4 decoding ran, else the same [body]
			// (no decode happened → they coincide).
			e := http_elem(args[0]) or { return http_bytes([]u8{}) }
			if !http_is_message(e) {
				return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: body accessor expects a [request]/[response]')
			}
			if name == 'http-body-bytes-wire' {
				if w := http_child(e, 'body-wire') {
					for it in w.items {
						if it is cx.ScalarNode {
							v := it.value
							if v is string {
								return http_bytes(v.bytes())
							}
						}
					}
				}
			}
			return http_bytes(http_body_octets(e))
		}
		'http-body-text' {
			return http_body_text_impl(args)
		}

		// ── §3.2 one-shot verbs / §3.3 send (GATED on net) ───────────────
		'http-get', 'http-head', 'http-options', 'http-del' {
			return http_client_verb(name, args, false)
		}
		'http-post', 'http-put', 'http-patch' {
			return http_client_verb(name, args, true)
		}
		'http-request' {
			return http_request_verb(args)
		}
		'http-send' {
			return http_send_impl(args)
		}

		// ── §3.6 SSE / streaming (client read half) ──────────────────────
		'http-sse-connect' {
			return http_sse_connect_impl(args)
		}
		'http-sse-events' {
			return http_sse_events_impl(args)
		}
		'http-source-open' {
			return http_source_open_impl(args)
		}
		'http-last-event-id' {
			return http_last_event_id_impl(args)
		}
		else {
			return none
		}
	}
}

// ── §3.4 introspection impls (PURE) ──────────────────────────────────

fn http_status_impl(args []cx.Node) cx.Node {
	e := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: status expects a [response]')
	}
	if !http_is_response(e) {
		// status/ok on a [request] → CXER4539 (§3.4)
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: status is response-only')
	}
	s := http_attr(e, 'status') or { return http_int(0) }
	return http_int(s.i64())
}

fn http_ok_impl(args []cx.Node) cx.Node {
	e := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: ok expects a [response]')
	}
	if !http_is_response(e) {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: ok is response-only')
	}
	s := http_attr(e, 'status') or { return http_bool(false) }
	n := s.int()
	return http_bool(n >= 200 && n <= 299)
}

pub fn http_header_impl(args []cx.Node) cx.Node {
	e := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: header expects a [request]/[response]')
	}
	want := http_arg_str(args[1]) or { return http_empty_nodeset() }
	wl := want.to_lower()
	// case-insensitive (RFC 9110); returns the FIRST match (receive order),
	// or the absence channel (empty node-set) when absent (§2.5/§3.4).
	for h in http_header_elems(e) {
		hn := http_attr(h, 'name') or { continue }
		if hn.to_lower() == wl {
			return h
		}
	}
	return http_empty_nodeset()
}

fn http_headers_impl(args []cx.Node) cx.Node {
	e := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: headers expects a [request]/[response]')
	}
	mut out := []cx.Node{}
	for h in http_header_elems(e) {
		out << h
	}
	return http_seq(out)
}

fn http_headers_named_impl(args []cx.Node) cx.Node {
	e := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: headers-named expects a [request]/[response]')
	}
	want := http_arg_str(args[1]) or { return http_seq([]) }
	wl := want.to_lower()
	mut out := []cx.Node{}
	for h in http_header_elems(e) {
		hn := http_attr(h, 'name') or { continue }
		if hn.to_lower() == wl {
			out << h
		}
	}
	return http_seq(out)
}

pub fn http_body_text_impl(args []cx.Node) cx.Node {
	e := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: body-text expects a [request]/[response]')
	}
	if !http_is_message(e) {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: body-text expects a [request]/[response]')
	}
	octets := http_body_octets(e)
	cs := http_charset(e)
	// v1 guarantees utf-8 / ascii / latin-1 (§3.4). latin-1 is total over any
	// byte sequence; utf-8/ascii must validate or → CXER4532.
	match cs {
		'utf-8', 'utf8', 'ascii', 'us-ascii', '' {
			s := octets.bytestr()
			if !utf8_str_is_valid(s) {
				return mk_err('cx-err:CXER4532', 'E_HTTP_CONTENT_DECODE: body is not valid ${cs}')
			}
			return http_str(s)
		}
		'latin-1', 'latin1', 'iso-8859-1' {
			mut sb := []rune{}
			for b in octets {
				sb << rune(b)
			}
			return http_str(sb.string())
		}
		else {
			// other charsets: defined behavior is "use body-bytes + caller
			// decode" (§3.4); body-text does not silently mojibake.
			return mk_err('cx-err:CXER4532', 'E_HTTP_CONTENT_DECODE: charset ${cs} not supported by body-text v1')
		}
	}
}

// utf8_str_is_valid is a minimal UTF-8 validator (V's `str.bytes()` round
// trips, so we validate the decoded form).
fn utf8_str_is_valid(s string) bool {
	mut i := 0
	for i < s.len {
		c := s[i]
		if c < 0x80 {
			i++
		} else if c & 0xE0 == 0xC0 {
			if i + 1 >= s.len || s[i + 1] & 0xC0 != 0x80 {
				return false
			}
			i += 2
		} else if c & 0xF0 == 0xE0 {
			if i + 2 >= s.len || s[i + 1] & 0xC0 != 0x80 || s[i + 2] & 0xC0 != 0x80 {
				return false
			}
			i += 3
		} else if c & 0xF8 == 0xF0 {
			if i + 3 >= s.len || s[i + 1] & 0xC0 != 0x80 || s[i + 2] & 0xC0 != 0x80
				|| s[i + 3] & 0xC0 != 0x80 {
				return false
			}
			i += 4
		} else {
			return false
		}
	}
	return true
}

// ── §3.1 client construction (PURE — no net access at construction) ───
fn http_client_impl(args []cx.Node) cx.Node {
	// validate base-url eagerly (§3.1): if present it MUST be an absolute
	// http/https URL with an authority; else CXER4525. opts is the first arg
	// (defaulted {} positional, §3.1). No net touch here.
	mut base_url := ''
	if args.len > 0 {
		base_url = http_opts_str(args[0], 'base-url')
	}
	if base_url != '' {
		if e := http_validate_absolute_url(base_url) {
			return e
		}
	}
	mut attrs := [cx.Attribute{ name: 'state', value: cx.ScalarValue('open') }]
	if base_url != '' {
		attrs << cx.Attribute{ name: 'base-url', value: cx.ScalarValue(base_url) }
	}
	attrs << cx.Attribute{ name: 'on-close', value: cx.ScalarValue('http/close') }
	return cx.Element{
		name:  'http-client'
		attrs: attrs
	}
}

// http_opts_str reads a key from an opts map element ({k: v} → a map node)
// as a string, or '' when absent. The opts map is a [__cx_map__]-style
// element / map literal whose entries the evaluator materializes; we read
// any direct child attribute or a [k v]-style entry defensively.
fn http_opts_str(n cx.Node, key string) string {
	if n is cx.Element {
		// attribute form (e.g. opts rendered as attrs)
		for a in n.attrs {
			if a.name == key {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// http_map_entry_str reads `key` from a `{k: v}` map literal — a
// `__cx_map__` marker element whose entries are child elements named by
// the key (eval.v eval_map). Returns '' when absent / not a map. Bool/num
// values stringify (true → 'true'). Complements http_opts_str, which reads
// the attribute form used by the client-construction opts path.
pub fn http_map_entry_str(opts cx.Node, key string) string {
	if opts is cx.Element {
		if opts.name == '__cx_map__' {
			for it in opts.items {
				if it is cx.Element && it.name == key && it.items.len > 0 {
					v := it.items[0]
					if v is cx.ScalarNode {
						return cx.scalar_value_str_public(v.value)
					}
				}
			}
		}
		for a in opts.attrs {
			if a.name == key {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// ── real HTTP/1.1 client engine (on the net TCP core) ────────────────
// Opens an ephemeral TCP connection via V `net`, serializes the request,
// reads the full response (Connection: close), and parses it into the
// canonical [response …] value. https:// awaits the TLS sub-layer and fails
// honestly until then (no synthetic response — the no-stub rule).

fn http_verb_method(name string) string {
	return match name {
		'http-head' { 'HEAD' }
		'http-options' { 'OPTIONS' }
		'http-del' { 'DELETE' }
		'http-post' { 'POST' }
		'http-put' { 'PUT' }
		'http-patch' { 'PATCH' }
		else { 'GET' }
	}
}

// http_url_parts → (scheme, host, port, path?query); default port by scheme.
pub fn http_url_parts(url string) (string, string, int, string) {
	scheme, rest := http_split_scheme(url)
	host, port_s := http_authority(rest)
	mut path := '/'
	if sl := rest.index('/') {
		path = rest[sl..]
	}
	mut port := port_s.int()
	if port == 0 {
		port = if scheme == 'https' { 443 } else { 80 }
	}
	return scheme, host, port, path
}

fn http_arg_octets(n cx.Node) []u8 {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.bytes()
		}
	}
	return []u8{}
}

// http_opts_headers collects request headers from the opts map: an explicit
// `content-type` key + any `headers` sub-map (name→value).
fn http_opts_headers(opts cx.Node) [][]string {
	mut out := [][]string{}
	ct := http_map_entry_str(opts, 'content-type')
	if ct != '' {
		out << ['Content-Type', ct]
	}
	if opts is cx.Element && opts.name == '__cx_map__' {
		for it in opts.items {
			if it is cx.Element && it.name == 'headers' && it.items.len > 0 {
				hm := it.items[0]
				if hm is cx.Element {
					for he in hm.items {
						if he is cx.Element && he.items.len > 0 {
							hv := he.items[0]
							if hv is cx.ScalarNode {
								vv := hv.value
								if vv is string {
									out << [he.name, vv]
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

// http_response_complete reports whether `raw` already holds a full HTTP/1.1
// response: headers (CRLFCRLF) + either the whole Content-Length body or the
// chunked terminator. This lets the client stop WITHOUT waiting for the server
// to close the socket — a keep-alive server (e.g. picoev) never sends EOF, so a
// read-to-EOF client would hang. With neither length nor chunking, it returns
// false and the caller reads until the socket closes (Connection: close).
fn http_response_complete(raw []u8) bool {
	s := raw.bytestr()
	he := s.index('\r\n\r\n') or { return false }
	body_start := he + 4
	mut content_length := -1
	mut chunked := false
	for ln in s[..he].split('\r\n') {
		ci := ln.index(':') or { continue }
		hn := ln[..ci].trim_space().to_lower()
		hv := ln[ci + 1..].trim_space()
		if hn == 'content-length' {
			content_length = hv.int()
		} else if hn == 'transfer-encoding' && hv.to_lower().contains('chunked') {
			chunked = true
		}
	}
	if content_length >= 0 {
		return raw.len >= body_start + content_length
	}
	if chunked {
		return s.ends_with('\r\n0\r\n\r\n') || s.ends_with('\n0\r\n\r\n')
	}
	return false
}

// HttpReqOpts bundles the per-request behavior knobs (§3.1) that the verb layer
// parses from the opts map and threads through the request + redirect loop.
pub struct HttpReqOpts {
pub mut:
	tls_verify           bool = true
	tls_ca               string
	follow_redirects     bool = true
	max_redirects        int  = 10
	legacy_post_redirect bool
	auto_decompress      bool = true
	max_body_bytes       int  = 67108864 // 64 MiB (§3.1)
	// timeout: the §4.5 WHOLE-REQUEST deadline (connect + every redirect hop +
	// body read), default 30s, surfaced as CXER4534. Distinct from (and the
	// reason for existing despite) the net layer's bounds: connect is
	// select-bounded at 5s and each single read at the 30s socket default, but
	// a response that keeps dribbling bytes resets the per-read clock every
	// time — an LLM upstream streaming a generation holds a connection (and on
	// a served path, its reactor — cx #275) for MINUTES with no single read
	// ever timing out. Only a whole-request budget bounds that.
	timeout_ms           i64 = 30_000
	// deadline_at: absolute time.ticks() cutoff, stamped ONCE by
	// http_do_request so all redirect hops spend from the same budget. 0 =
	// not yet stamped.
	deadline_at          i64
}

// http_parse_req_opts reads the redirect/decompress/tls opts off the per-call
// (or client) opts map; absent keys keep the §3.1 defaults.
fn http_parse_req_opts(opts cx.Node) HttpReqOpts {
	mut o := HttpReqOpts{}
	o.tls_verify, o.tls_ca = http_opts_tls(opts)
	if v := http_map_entry_bool(opts, 'follow-redirects') {
		o.follow_redirects = v
	}
	if v := http_map_entry_int(opts, 'max-redirects') {
		o.max_redirects = v
	}
	if v := http_map_entry_bool(opts, 'legacy-post-redirect') {
		o.legacy_post_redirect = v
	}
	if v := http_map_entry_bool(opts, 'auto-decompress') {
		o.auto_decompress = v
	}
	if v := http_map_entry_int(opts, 'max-body-bytes') {
		o.max_body_bytes = v
	}
	// `timeout` is a duration scalar ({timeout: 5s} / {timeout: 1500ms}); an
	// absent, malformed, or non-positive value keeps the 30s §3.1 default
	// (same lenient-parse posture as the other opts). There is deliberately
	// no infinite opt-out — §3.1 bounds are "never unbounded"; a caller that
	// needs longer states how long.
	tstr := http_map_entry_str(opts, 'timeout')
	if tstr != '' {
		if ns := duration_to_ns(tstr) {
			if ns > 0 {
				o.timeout_ms = ns / 1_000_000
			}
		}
	}
	return o
}

// http_map_entry_bool / _int read a typed opt off the {k: v} map (or attrs),
// returning none when absent so the caller keeps its default.
fn http_map_entry_bool(opts cx.Node, key string) ?bool {
	s := http_map_entry_str(opts, key)
	if s == '' {
		return none
	}
	return s == 'true' || s == '1'
}

fn http_map_entry_int(opts cx.Node, key string) ?int {
	s := http_map_entry_str(opts, key)
	if s == '' {
		return none
	}
	return s.int()
}

// http_do_request performs a request and follows redirects per §4.3, then
// applies §4.4 content-decoding to the final response. The single-hop transport
// is http_do_single; this wraps it with the redirect state machine (method/body
// matrix, cross-origin Authorization/Cookie scrub, cycle + max-redirect bounds).
fn http_do_request(method string, url string, extra_headers [][]string, body []u8, opts HttpReqOpts) cx.Node {
	mut cur_method := method
	mut cur_url := url
	mut cur_body := body.clone()
	mut cur_headers := extra_headers.clone()
	mut visited := []string{}
	// §4.5: one whole-request budget, stamped here so every redirect hop —
	// connects, writes, and reads alike — spends from the same clock.
	mut dopts := opts
	dopts.deadline_at = time.ticks() + dopts.timeout_ms
	for hop := 0; ; hop++ {
		if time.ticks() >= dopts.deadline_at {
			return mk_err(http_err_request_timeout, 'E_HTTP_REQUEST_TIMEOUT: whole-request timeout (${dopts.timeout_ms}ms) exceeded after ${hop} redirect hop(s)')
		}
		resp := http_do_single(cur_method, cur_url, cur_headers, cur_body, dopts)
		if is_err_value(resp) {
			return resp
		}
		status := http_response_status(resp)
		if !opts.follow_redirects || status !in [301, 302, 303, 307, 308] {
			return http_decode_response(resp, opts)
		}
		// followable 3xx — enforce the redirect bound BEFORE the next hop.
		if hop >= opts.max_redirects {
			return mk_err(http_err_too_many_redirects, 'E_HTTP_TOO_MANY_REDIRECTS: exceeded max-redirects (${opts.max_redirects})')
		}
		loc := http_response_header(resp, 'location')
		if loc == '' {
			return mk_err(http_err_redirect_invalid, 'E_HTTP_REDIRECT_INVALID: 3xx with no Location')
		}
		next_url := http_join_url(cur_url, loc)
		if next_url == '' {
			return mk_err(http_err_redirect_invalid, 'E_HTTP_REDIRECT_INVALID: unparseable Location "${loc}"')
		}
		if next_url in visited || next_url == cur_url {
			return mk_err(http_err_redirect_loop, 'E_HTTP_REDIRECT_LOOP: cycle at ${next_url}')
		}
		visited << cur_url
		// §4.3 method/body matrix.
		mut next_method := cur_method
		mut next_body := cur_body.clone()
		match status {
			303 {
				// → GET (HEAD stays HEAD); body dropped.
				if cur_method != 'HEAD' {
					next_method = 'GET'
				}
				next_body = []u8{}
			}
			301, 302 {
				// preserve, unless legacy POST→GET rewrite is requested.
				if opts.legacy_post_redirect && cur_method == 'POST' {
					next_method = 'GET'
					next_body = []u8{}
				}
			}
			else {} // 307/308: method + body invariant
		}
		// cross-origin (scheme+host+port) → drop Authorization + Cookie (§4.3).
		if http_origin(next_url) != http_origin(cur_url) {
			cur_headers = http_drop_auth_cookie(cur_headers)
		}
		cur_method = next_method
		cur_body = next_body.clone()
		cur_url = next_url
	}
	return mk_err(http_err_redirect_loop, 'E_HTTP_REDIRECT_LOOP: redirect loop did not terminate')
}

// http_response_status reads the numeric status off a parsed [response].
fn http_response_status(resp cx.Node) int {
	if e := http_elem(resp) {
		if s := http_attr(e, 'status') {
			return s.int()
		}
	}
	return 0
}

// http_response_header returns the first response header whose name matches
// `name` case-insensitively, or '' (the parsed [response] carries [header
// name= value=] children under [headers], §2.2).
fn http_response_header(resp cx.Node, name string) string {
	e := http_elem(resp) or { return '' }
	ln := name.to_lower()
	for h in http_header_elems(e) {
		hn := http_attr(h, 'name') or { continue }
		if hn.to_lower() == ln {
			return http_attr(h, 'value') or { '' }
		}
	}
	return ''
}

// http_origin returns scheme://host:port (the effective port) for cross-origin
// comparison (§4.3 Authorization/Cookie scrub).
fn http_origin(url string) string {
	scheme, host, port, _ := http_url_parts(url)
	return '${scheme}://${host.to_lower()}:${port}'
}

// http_drop_auth_cookie removes Authorization + Cookie request headers (dropped
// on a cross-origin redirect, §4.3 — http carries no cookie state).
fn http_drop_auth_cookie(headers [][]string) [][]string {
	mut out := [][]string{}
	for h in headers {
		ln := h[0].to_lower()
		if ln == 'authorization' || ln == 'cookie' {
			continue
		}
		out << h
	}
	return out
}

// http_join_url resolves a (possibly relative) Location against the current URL
// per RFC 3986 §5 (the cases redirects use): absolute URL passes through; an
// absolute-path ("/x") replaces the path; a bare relative ref resolves against
// the current directory. Returns '' on an unusable Location.
fn http_join_url(base string, loc string) string {
	l := loc.trim_space()
	if l == '' {
		return ''
	}
	lscheme, _ := http_split_scheme(l)
	if lscheme == 'http' || lscheme == 'https' {
		return l // absolute
	}
	if l.starts_with('//') {
		// scheme-relative: inherit the base scheme.
		bscheme, _ := http_split_scheme(base)
		return '${bscheme}:${l}'
	}
	bscheme, brest := http_split_scheme(base)
	bauth := brest.all_before('/')
	if bauth == '' {
		return ''
	}
	if l.starts_with('/') {
		return '${bscheme}://${bauth}${l}' // absolute-path
	}
	// relative reference: resolve against the base's directory.
	mut bpath := '/'
	if sl := brest.index('/') {
		bpath = brest[sl..]
	}
	// strip query/fragment, then drop the last segment to get the directory.
	mut dir := bpath
	if q := dir.index('?') {
		dir = dir[..q]
	}
	if li := dir.last_index('/') {
		dir = dir[..li + 1]
	} else {
		dir = '/'
	}
	return '${bscheme}://${bauth}${dir}${l}'
}

// http_decode_response applies §4.4 content-decoding to the final response. A
// gzip/zstd Content-Encoding (incl. a stacked list, undone in reverse order of
// application) is decoded: the decoded octets become [body] (so body-bytes /
// body-text see the decoded entity), the compressed octets are preserved as
// [body-wire] (body-bytes-wire), the response gains content-decoded=true, and
// the wire headers (Content-Encoding + the original Content-Length) are left
// verbatim and inspectable. An unsupported coding (deflate/br/unknown) leaves the
// body raw with NO marker — the raw-passthrough fallback, no partial decode.
// Decode failure → CXER4532; a decoded length over max-body-bytes → CXER4530.
fn http_decode_response(resp cx.Node, opts HttpReqOpts) cx.Node {
	if !opts.auto_decompress {
		return resp
	}
	e := http_elem(resp) or { return resp }
	enc := http_response_header(resp, 'content-encoding').trim_space().to_lower()
	if enc == '' || enc == 'identity' {
		return resp
	}
	mut codings := []string{}
	for c in enc.split(',') {
		cc := c.trim_space()
		if cc != '' {
			codings << cc
		}
	}
	for c in codings {
		if c !in ['gzip', 'zstd', 'identity'] {
			return resp // raw-passthrough: any unsupported coding leaves the body raw
		}
	}
	wire := http_body_octets(e)
	mut data := wire.clone()
	for i := codings.len - 1; i >= 0; i-- {
		c := codings[i]
		if c == 'identity' {
			continue
		}
		decoded := if c == 'gzip' {
			gzip.decompress(data) or {
				return mk_err(http_err_content_decode, 'E_HTTP_CONTENT_DECODE: gzip decode failed: ${err.msg()}')
			}
		} else {
			zstd.decompress(data) or {
				return mk_err(http_err_content_decode, 'E_HTTP_CONTENT_DECODE: zstd decode failed: ${err.msg()}')
			}
		}
		if decoded.len > opts.max_body_bytes {
			return mk_err(http_err_body_too_large, 'E_HTTP_BODY_TOO_LARGE: decoded body exceeds max-body-bytes (${opts.max_body_bytes})')
		}
		data = decoded.clone()
	}
	return http_response_decoded(e, data, wire)
}

// http_response_decoded rebuilds a [response] with the decoded body as [body],
// the compressed entity preserved as [body-wire], and a content-decoded=true
// marker; all other attrs + the [headers] block are kept verbatim.
fn http_response_decoded(e cx.Element, decoded []u8, wire []u8) cx.Node {
	mut attrs := e.attrs.clone()
	attrs << cx.Attribute{
		name:  'content-decoded'
		value: cx.ScalarValue(true)
	}
	mut items := []cx.Node{}
	for it in e.items {
		if it is cx.Element && it.name == 'body' {
			continue // replaced below
		}
		items << it
	}
	items << cx.Node(cx.Element{
		name:  'body'
		items: [cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(decoded.bytestr())
			data_type: cx.ScalarType.string_type
		})]
	})
	items << cx.Node(cx.Element{
		name:  'body-wire'
		items: [cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(wire.bytestr())
			data_type: cx.ScalarType.string_type
		})]
	})
	return cx.Element{
		name:  'response'
		attrs: attrs
		items: items
	}
}

// ── #234 client connection pool (§5.2 keep-alive reuse) ───────────────────────
//
// http_do_single keeps the connection OPEN after a fully-framed keep-alive
// response and parks it in a process-global pool keyed by
// scheme://host:port + TLS identity (verify flag + CA), so the next request to
// the same origin reuses the TCP (and TLS session) instead of re-dialing —
// the client half of the §5.2 keep-alive the server has honored since #234.1.
// Discipline:
//   - a conn is poolable only when the response was DEFINITELY framed
//     (Content-Length satisfied / chunked terminator seen — never read-to-EOF)
//     AND the server did not say `Connection: close` AND it spoke HTTP/1.1;
//   - a pooled conn that proves stale (write fails, or zero response bytes —
//     the server closed it while parked) is dropped and the request REDIALS
//     ONCE on a fresh conn. The retry fires only when no response byte was
//     received, so a request is never replayed after a partial response;
//   - idle conns are evicted after http_pool_idle_ms (§5.2 60s) — lazily on
//     take, and by an opportunistic sweep on every park;
//   - per-key and total caps bound parked fds; overflow closes instead of parks.
// The pool holds only IDLE conns (a taken conn is owned exclusively by its
// request), so no two requests ever share a socket.

const http_pool_idle_ms = i64(60000) // §5.2: idle keep-alive eviction window
const http_pool_max_per_key = 8
const http_pool_max_total = 64

// HttpPoolConn — one client connection (plain TCP, or TLS when ssl is set).
@[heap]
struct HttpPoolConn {
mut:
	tcp     &net.TcpConn
	ssl     &mbedtls.SSLConn = unsafe { nil } // non-nil ⇒ https (TLS over tcp)
	last_ms i64 // time.ticks() when parked (idle-eviction clock)
}

__global (
	g_http_pool_mu    &sync.Mutex
	g_http_pool       map[string][]&HttpPoolConn
	g_http_pool_total int
)

// (the pool mutex/map are initialized in the module init() in stdlib_codec.v —
// one init per module — once, before any thread, so locking is race-free
// thereafter; same pattern as g_csrp_disco.)

// http_pool_key — pooled conns are origin- AND trust-scoped: two requests with
// different verify/CA settings never share a socket. The CA PEM rides in the
// key verbatim (a handful of origins at most — compactness is irrelevant,
// correctness is not).
fn http_pool_key(scheme string, host string, port int, verify bool, ca string) string {
	return '${scheme}://${host}:${port}|v=${verify}|ca=${ca}'
}

fn (mut c HttpPoolConn) pool_close() {
	if c.ssl != unsafe { nil } {
		c.ssl.close() or {}
	}
	c.tcp.close() or {}
}

fn (mut c HttpPoolConn) pool_write_string(s string) ! {
	if c.ssl != unsafe { nil } {
		c.ssl.write_string(s)!
		return
	}
	c.tcp.write_string(s)!
}

fn (mut c HttpPoolConn) pool_write(b []u8) ! {
	if c.ssl != unsafe { nil } {
		c.ssl.write(b)!
		return
	}
	c.tcp.write(b)!
}

fn (mut c HttpPoolConn) pool_read(mut buf []u8) !int {
	if c.ssl != unsafe { nil } {
		return c.ssl.read(mut buf)!
	}
	return c.tcp.read(mut buf)!
}

// http_pool_take pops the freshest idle conn for `key` (LIFO — the most
// recently parked is the least likely to have been closed by the server),
// closing any idle-expired ones it walks past.
fn http_pool_take(key string) ?&HttpPoolConn {
	g_http_pool_mu.lock()
	now := time.ticks()
	mut list := g_http_pool[key] or {
		g_http_pool_mu.unlock()
		return none
	}
	mut expired := []&HttpPoolConn{}
	mut found := &HttpPoolConn(unsafe { nil })
	for list.len > 0 {
		mut pc := list.pop()
		g_http_pool_total--
		if now - pc.last_ms <= http_pool_idle_ms {
			found = pc
			break
		}
		expired << pc
	}
	g_http_pool[key] = list
	g_http_pool_mu.unlock()
	for mut pc in expired {
		pc.pool_close()
	}
	if found == unsafe { nil } {
		return none
	}
	return found
}

// http_pool_put parks a conn for reuse, sweeping idle-expired conns across the
// whole pool while it holds the lock. Overflow (per-key or total cap) closes
// the conn instead of parking it.
fn http_pool_put(key string, mut pc HttpPoolConn) {
	now := time.ticks()
	pc.last_ms = now
	mut to_close := []&HttpPoolConn{}
	g_http_pool_mu.lock()
	// opportunistic sweep: drop idle-expired conns everywhere.
	for k, list in g_http_pool {
		mut kept := []&HttpPoolConn{cap: list.len}
		for c in list {
			if now - c.last_ms <= http_pool_idle_ms {
				kept << c
			} else {
				to_close << c
				g_http_pool_total--
			}
		}
		g_http_pool[k] = kept
	}
	mut list := g_http_pool[key] or { []&HttpPoolConn{} }
	if list.len >= http_pool_max_per_key || g_http_pool_total >= http_pool_max_total {
		g_http_pool_mu.unlock()
		for mut c in to_close {
			c.pool_close()
		}
		pc.pool_close()
		return
	}
	list << pc
	g_http_pool[key] = list
	g_http_pool_total++
	g_http_pool_mu.unlock()
	for mut c in to_close {
		c.pool_close()
	}
}

// http_conn_exchange writes one request and reads its response off `pc`.
// Returns (raw, complete, werr): werr != '' ⇒ the WRITE failed (no response
// byte consumed — safe to redial); werr == 'too-large' ⇒ the response blew the
// cap (hard error, never retried); otherwise raw holds whatever arrived
// (possibly empty ⇒ the conn was dead — a pooled caller redials, a fresh
// caller parses the empty read into the honest invalid-response error, exactly
// as before) and `complete` reports definite framing (poolability input).
fn http_conn_exchange(mut pc HttpPoolConn, method string, head string, body []u8, max_resp int, deadline_at i64) ([]u8, bool, string) {
	pc.pool_write_string(head) or { return []u8{}, false, 'write request: ${err.msg()}' }
	if body.len > 0 {
		pc.pool_write(body) or { return []u8{}, false, 'write body: ${err.msg()}' }
	}
	mut raw := []u8{}
	mut complete := false
	for {
		// §4.5 whole-request budget: each read may spend at most what remains
		// of THIS REQUEST's deadline — a per-read socket timeout alone is
		// defeated by a dribbling upstream (every arriving byte resets it).
		// The socket read timeout is (re)armed to the shrinking remainder
		// before every read, and a read failure PAST the deadline is the
		// timeout regardless of the error's shape (tcp and tls surface
		// deadline lapses differently; wall-clock classification covers both).
		rem_ms := deadline_at - time.ticks()
		if rem_ms <= 0 {
			return raw, complete, 'timeout'
		}
		pc.tcp.set_read_timeout(rem_ms * time.millisecond)
		if pc.ssl != unsafe { nil } {
			pc.ssl.read_timeout = rem_ms * time.millisecond
		}
		mut tmp := []u8{len: 8192}
		n := pc.pool_read(mut tmp) or {
			if time.ticks() >= deadline_at {
				return raw, complete, 'timeout'
			}
			break
		}
		if n <= 0 {
			break
		}
		raw << tmp[..n]
		if raw.len > max_resp {
			return raw, false, 'too-large'
		}
		if http_exchange_complete(raw, method) {
			complete = true
			break
		}
	}
	return raw, complete, ''
}

// http_exchange_complete — response completeness for the exchange loop. A HEAD
// response and the 204/304 statuses are complete at the header terminator:
// they NEVER carry a body, even when a Content-Length is advertised, so
// waiting on framing would hang against a keep-alive server (the old
// `Connection: close` client was rescued by the server's EOF; a pooled client
// must not rely on one). Everything else defers to http_response_complete
// (Content-Length / chunked framing).
fn http_exchange_complete(raw []u8, method string) bool {
	s := raw.bytestr()
	he := s.index('\r\n\r\n') or { return false }
	if method == 'HEAD' {
		return true
	}
	sl := s[..he].split('\r\n')[0].split(' ')
	if sl.len >= 2 {
		st := sl[1].int()
		if st == 204 || st == 304 {
			return true
		}
	}
	return http_response_complete(raw)
}

// http_conn_poolable — the response permits reuse: definitely framed (never
// read-to-EOF), HTTP/1.1, and no `Connection: close` from the server.
fn http_conn_poolable(raw []u8, complete bool) bool {
	if !complete {
		return false
	}
	s := raw.bytestr()
	he := s.index('\r\n\r\n') or { return false }
	lines := s[..he].split('\r\n')
	if lines.len == 0 || !lines[0].starts_with('HTTP/1.1') {
		return false
	}
	for i in 1 .. lines.len {
		ln := lines[i]
		ci := ln.index(':') or { continue }
		if ln[..ci].trim_space().to_lower() == 'connection' {
			return !ln[ci + 1..].trim_space().to_lower().contains('close')
		}
	}
	return true // HTTP/1.1 default: persistent
}

// http_dial_conn dials (and TLS-handshakes) a fresh connection. The error
// nodes are byte-identical to the pre-pool http_do_single dial paths.
fn http_dial_conn(scheme string, host string, pinned string, port int, tls_verify bool, tls_ca string) (&HttpPoolConn, cx.Node, bool) {
	nilconn := &HttpPoolConn(unsafe { nil })
	mut tcp := net.dial_tcp(net_join_host_port(pinned, port)) or {
		msg := err.msg()
		ecode := if msg.contains('refused') { 'cx-err:CXER4505' } else { 'cx-err:CXER4506' }
		hostlbl := if scheme == 'https' { pinned } else { host }
		return nilconn, mk_err(ecode, 'E_HTTP: connect ${hostlbl}:${port}: ${msg}'), false
	}
	if scheme != 'https' {
		return &HttpPoolConn{
			tcp: tcp
		}, http_null(), true
	}
	// real TLS via mbedTLS (net dial-tls config). verify defaults true against
	// the OS trust store (§3.6); opts.verify=false / opts.ca override.
	mut cfg := mbedtls.SSLConnectConfig{
		validate: tls_verify
	}
	if tls_ca != '' {
		cfg = mbedtls.SSLConnectConfig{
			validate:               tls_verify
			in_memory_verification: true
			verify:                 tls_ca
		}
	} else if tls_verify {
		cfg = mbedtls.SSLConnectConfig{
			validate: true
			verify:   http_os_ca_bundle()
		}
	}
	mut ssl := mbedtls.new_ssl_conn(cfg) or {
		tcp.close() or {}
		return nilconn, mk_err('cx-err:CXER4512', 'E_HTTP: TLS init: ${err.msg()}'), false
	}
	ssl.connect(mut tcp, host) or {
		tcp.close() or {}
		return nilconn, mk_err('cx-err:CXER4512', 'E_HTTP: TLS handshake ${host}:${port}: ${err.msg()}'), false
	}
	return &HttpPoolConn{
		tcp: tcp
		ssl: ssl
	}, http_null(), true
}

// http_do_single performs one real request/response, reusing a pooled
// keep-alive connection to the origin when one is parked (#234; fresh dial
// otherwise, redial-once when a pooled conn proves stale).
pub fn http_do_single(method string, url string, extra_headers [][]string, body []u8, opts_in HttpReqOpts) cx.Node {
	// Defensive stamp: http_do_request seeds the whole-request deadline; a
	// future direct caller that forgets must still get §4.5's bounded default
	// rather than an already-expired (or unbounded) budget.
	mut opts := opts_in
	if opts.deadline_at == 0 {
		opts.deadline_at = time.ticks() + opts.timeout_ms
	}
	tls_verify := opts.tls_verify
	tls_ca := opts.tls_ca
	scheme, host, port, path := http_url_parts(url)
	if scheme != 'http' && scheme != 'https' {
		return mk_err(http_err_url_invalid, 'E_HTTP_URL_INVALID: unsupported scheme ${scheme}')
	}
	// §4.5 SSRF / rebinding guard (shared with net dial): resolve + canonicalize
	// + capability host match + deny-set/override, then PIN the candidate.
	pinned, derr := net_ssrf_check(host, port)
	if e := derr {
		return e
	}
	mut head := '${method} ${path} HTTP/1.1\r\nHost: ${host}\r\n'
	mut have_ct := false
	for h in extra_headers {
		head += '${h[0]}: ${h[1]}\r\n'
		if h[0].to_lower() == 'content-type' {
			have_ct = true
		}
	}
	if body.len > 0 {
		head += 'Content-Length: ${body.len}\r\n'
		if !have_ct {
			head += 'Content-Type: application/octet-stream\r\n'
		}
	}
	// #234: advertise keep-alive (the HTTP/1.1 default, stated explicitly) so a
	// fully-framed exchange leaves the conn reusable; http_conn_poolable decides.
	head += 'Connection: keep-alive\r\n\r\n'
	max_resp := 64 * 1024 * 1024
	key := http_pool_key(scheme, host, port, tls_verify, tls_ca)
	// Pooled attempt (§5.2 reuse). A stale parked conn — write failure or zero
	// response bytes (the server closed it while idle) — is dropped and the
	// request falls through to ONE fresh dial. The retry fires only when no
	// response byte arrived, so a request is never replayed mid-response.
	if mut ppc := http_pool_take(key) {
		raw, complete, werr := http_conn_exchange(mut ppc, method, head, body, max_resp,
			opts.deadline_at)
		if werr == 'too-large' {
			ppc.pool_close()
			return mk_err('cx-err:CXER4530', 'E_HTTP_BODY_TOO_LARGE: response over ${max_resp} bytes')
		}
		if werr == 'timeout' {
			// The budget is spent — a redial could only time out again with
			// less budget. Fail the request here (§4.5).
			ppc.pool_close()
			return mk_err(http_err_request_timeout, 'E_HTTP_REQUEST_TIMEOUT: no complete response within the whole-request timeout')
		}
		if werr == '' && raw.len > 0 {
			if http_conn_poolable(raw, complete) {
				http_pool_put(key, mut ppc)
			} else {
				ppc.pool_close()
			}
			return http_parse_response(raw, method)
		}
		ppc.pool_close() // stale — redial once below
	}
	mut pc, errn, ok := http_dial_conn(scheme, host, pinned, port, tls_verify, tls_ca)
	if !ok {
		return errn
	}
	raw, complete, werr := http_conn_exchange(mut pc, method, head, body, max_resp,
		opts.deadline_at)
	if werr == 'too-large' {
		pc.pool_close()
		return mk_err('cx-err:CXER4530', 'E_HTTP_BODY_TOO_LARGE: response over ${max_resp} bytes')
	}
	if werr == 'timeout' {
		pc.pool_close()
		return mk_err(http_err_request_timeout, 'E_HTTP_REQUEST_TIMEOUT: no complete response within the whole-request timeout')
	}
	if werr != '' {
		pc.pool_close()
		return mk_err('cx-err:CXER4508', 'E_HTTP: ${werr}')
	}
	if http_conn_poolable(raw, complete) {
		http_pool_put(key, mut pc)
	} else {
		pc.pool_close()
	}
	return http_parse_response(raw, method)
}

// http_os_ca_bundle locates the platform CA trust store for https verify (§3.6
// verify defaults true). Empty when none found → a verify=true handshake then
// fails honestly rather than silently trusting anything.
pub fn http_os_ca_bundle() string {
	for p in ['/etc/ssl/cert.pem', '/etc/ssl/certs/ca-certificates.crt',
		'/etc/pki/tls/certs/ca-bundle.crt', '/opt/homebrew/etc/openssl@3/cert.pem',
		'/usr/local/etc/openssl@3/cert.pem'] {
		if os.exists(p) {
			return p
		}
	}
	return ''
}

// http_opts_tls reads the https trust settings from the opts map: `verify`
// (default true; `false` = audited dev opt-out, §3.6) and an in-memory `ca` PEM.
fn http_opts_tls(opts cx.Node) (bool, string) {
	mut verify := true
	if http_map_entry_str(opts, 'verify') == 'false' {
		verify = false
	}
	return verify, http_map_entry_str(opts, 'ca')
}

// http_parse_response parses status line + headers + body (Content-Length /
// chunked / read-to-EOF) into the canonical [response …] value.
fn http_parse_response(raw []u8, method string) cx.Node {
	s := raw.bytestr()
	term := s.index('\r\n\r\n') or {
		return mk_err(http_err_invalid_response, 'E_HTTP_INVALID_RESPONSE: no header terminator')
	}
	head := s[..term]
	body_start := term + 4
	lines := head.split('\r\n')
	if lines.len == 0 {
		return mk_err(http_err_invalid_response, 'E_HTTP_INVALID_RESPONSE: empty response')
	}
	sl := lines[0].split(' ')
	if sl.len < 2 {
		return mk_err(http_err_invalid_response, 'E_HTTP_INVALID_RESPONSE: bad status line')
	}
	status := sl[1].int()
	mut headers := [][]string{}
	mut content_length := -1
	mut chunked := false
	for i in 1 .. lines.len {
		ln := lines[i]
		ci := ln.index(':') or { continue }
		hn := ln[..ci].trim_space()
		hv := ln[ci + 1..].trim_space()
		headers << [hn, hv]
		lhn := hn.to_lower()
		if lhn == 'content-length' {
			content_length = hv.int()
		} else if lhn == 'transfer-encoding' && hv.to_lower().contains('chunked') {
			chunked = true
		}
	}
	mut body := []u8{}
	if method != 'HEAD' && body_start <= raw.len {
		rest := raw[body_start..]
		if chunked {
			body = http_dechunk(rest) or {
				return mk_err('cx-err:CXER4536', 'E_HTTP_PROTOCOL: bad chunked body')
			}
		} else if content_length >= 0 {
			take := if content_length < rest.len { content_length } else { rest.len }
			body = rest[..take].clone()
		} else {
			body = rest.clone()
		}
	}
	return http_build_response_node(status, headers, body)
}

fn http_dechunk(raw []u8) ?[]u8 {
	mut out := []u8{}
	mut pos := 0
	for pos < raw.len {
		mut le := pos
		for le + 1 < raw.len && !(raw[le] == `\r` && raw[le + 1] == `\n`) {
			le++
		}
		if le + 1 >= raw.len {
			return none
		}
		size := http_hex(raw[pos..le].bytestr().all_before(';').trim_space())
		data := le + 2
		if size == 0 {
			break
		}
		if data + size > raw.len {
			return none
		}
		out << raw[data..data + size]
		pos = data + size + 2
	}
	return out
}

fn http_hex(s string) int {
	mut v := 0
	for c in s {
		d := if c >= `0` && c <= `9` {
			int(c - `0`)
		} else if c >= `a` && c <= `f` {
			int(c - `a` + 10)
		} else if c >= `A` && c <= `F` {
			int(c - `A` + 10)
		} else {
			return v
		}
		v = v * 16 + d
	}
	return v
}

fn http_build_response_node(status int, headers [][]string, body []u8) cx.Node {
	mut hdr_items := []cx.Node{}
	for h in headers {
		hdr_items << cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(h[0])
				},
				cx.Attribute{
					name:  'value'
					value: cx.ScalarValue(h[1])
				},
			]
		}
	}
	mut items := []cx.Node{}
	items << cx.Element{
		name:  'headers'
		items: hdr_items
	}
	items << cx.Element{
		name:  'body'
		items: [
			cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(body.bytestr())
				data_type: cx.ScalarType.bytes_type
			}),
		]
	}
	return cx.Element{
		name:  'response'
		attrs: [
			cx.Attribute{
				name:  'status'
				value: cx.ScalarValue(i64(status))
			},
		]
		items: items
	}
}

// ── client verbs (GATED) ──────────────────────────────────────────────
//
// http_client_verb handles get/head/options/del (no body arg) and
// post/put/patch (a body arg at index 1). It validates the URL scheme
// (pure, §2.6) — non-http(s) → CXER4525 even under a grant — then guards
// `net` on the canonical host:port. Behind the grant it would open an
// ephemeral client, dial via net, write the request, parse the response.
fn http_client_verb(name string, args []cx.Node, has_body bool) cx.Node {
	url := http_arg_str(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: ${name} expects a URL string')
	}
	// CONNECT is out of scope v1 (§2.5) — but method here is fixed by verb.
	if e := http_validate_absolute_url(url) {
		return e
	}
	resource := http_url_resource(url)
	if d := cap_guard('net', resource) {
		return d
	}
	// real path: ephemeral client → dial → request/response over the net
	// TCP core. get/head/options/del carry opts at args[1]; post/put/patch
	// carry the body at args[1] and opts at args[2].
	method := http_verb_method(name)
	mut body := []u8{}
	mut opts_idx := 1
	if has_body {
		if args.len > 1 {
			body = http_arg_octets(args[1])
		}
		opts_idx = 2
	}
	mut hdrs := [][]string{}
	mut opts := HttpReqOpts{}
	if args.len > opts_idx {
		hdrs = http_opts_headers(args[opts_idx])
		opts = http_parse_req_opts(args[opts_idx])
	}
	return http_do_request(method, url, hdrs, body, opts)
}

// http_request_verb is the generic verb: ($method $url $opts{}). Validates
// the method + URL, then guards net.
pub fn http_request_verb(args []cx.Node) cx.Node {
	method := http_arg_str(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: request expects a method string')
	}
	url := http_arg_str(args[1]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: request expects a URL string')
	}
	if !http_method_valid(method) {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: invalid method ${method}')
	}
	if method.to_upper() == 'CONNECT' {
		// CONNECT tunnelling out of scope v1 (§2.5)
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: CONNECT is out of scope v1')
	}
	if e := http_validate_absolute_url(url) {
		return e
	}
	if d := cap_guard('net', http_url_resource(url)) {
		return d
	}
	mut hdrs := [][]string{}
	mut body := []u8{}
	mut opts := HttpReqOpts{}
	if args.len > 2 {
		hdrs = http_opts_headers(args[2])
		opts = http_parse_req_opts(args[2])
		bs := http_map_entry_str(args[2], 'body')
		if bs != '' {
			body = bs.bytes()
		}
	}
	return http_do_request(method.to_upper(), url, hdrs, body, opts)
}

// http_send_impl issues a client-form [request] (url=) through a pooled
// [http-client]. Validates that the request carries url= (not path=) and
// resolves a relative url against the client base-url; then guards net.
fn http_send_impl(args []cx.Node) cx.Node {
	client := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send expects an [http-client]')
	}
	req := http_elem(args[1]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send expects a [request]')
	}
	if req.name != 'request' {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send expects a [request]')
	}
	// client-issued [request] MUST carry url= and MUST NOT carry path= (§2.2)
	has_url := if _ := http_attr(req, 'url') { true } else { false }
	has_path := if _ := http_attr(req, 'path') { true } else { false }
	if has_path {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: a client-issued [request] carries url=, not path=')
	}
	if !has_url {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: send [request] missing url=')
	}
	url := http_attr(req, 'url') or { '' }
	base := http_attr(client, 'base-url') or { '' }
	abs := http_resolve_url(url, base) or {
		return mk_err(http_err_url_invalid, 'E_HTTP_URL_INVALID: relative url= with no base-url')
	}
	if e := http_validate_absolute_url(abs) {
		return e
	}
	if d := cap_guard('net', http_url_resource(abs)) {
		return d
	}
	method := http_attr(req, 'method') or { 'GET' }
	mut hdrs := [][]string{}
	for h in http_header_elems(req) {
		hn := http_attr(h, 'name') or { continue }
		hv := http_attr(h, 'value') or { '' }
		hdrs << [hn, hv]
	}
	body := http_body_octets(req)
	// honor the client's configured opts (follow-redirects / auto-decompress /
	// tls / max-*), read off the [http-client] element's attrs.
	return http_do_request(method.to_upper(), abs, hdrs, body, http_parse_req_opts(client))
}









// ── URL validation + resource canonicalization (PURE, §2.6/§5) ────────
//
// http_validate_absolute_url returns a CXER4525 err NODE when the URL is
// not an absolute http/https URL with an authority, else none (valid).
fn http_validate_absolute_url(url string) ?cx.Node {
	scheme, rest := http_split_scheme(url)
	if scheme != 'http' && scheme != 'https' {
		return mk_err(http_err_url_invalid, 'E_HTTP_URL_INVALID: non-http(s) or relative URL ${url}')
	}
	host, _ := http_authority(rest)
	if host == '' {
		return mk_err(http_err_url_invalid, 'E_HTTP_URL_INVALID: URL has no authority/host ${url}')
	}
	return none
}


// http_split_scheme returns (scheme, rest-after-scheme://). For a schemeless
// (relative) URL returns ('', url).
pub fn http_split_scheme(url string) (string, string) {
	if url.contains('://') {
		return url.all_before('://'), url.all_after('://')
	}
	return '', url
}

// http_authority extracts (host, port-string) from the authority portion
// (everything up to the first '/'); port '' when absent. Handles bracketed
// IPv6. host '' when the authority is empty.
pub fn http_authority(rest string) (string, string) {
	mut auth := rest
	if sl := auth.index('/') {
		auth = auth[..sl]
	}
	if auth == '' {
		return '', ''
	}
	if auth.starts_with('[') {
		// [::1]:443
		close := auth.index(']') or { return '', '' }
		host := auth[1..close]
		after := auth[close + 1..]
		if after.starts_with(':') {
			return host, after[1..]
		}
		return host, ''
	}
	if li := auth.last_index(':') {
		return auth[..li], auth[li + 1..]
	}
	return auth, ''
}

// http_url_resource returns the canonical host:port for the capability
// match (§5): lowercased host + the effective port (explicit, or the scheme
// default http→80 / https→443; net's parse-addr does NOT infer defaults).
fn http_url_resource(url string) string {
	scheme, rest := http_split_scheme(url)
	host, port := http_authority(rest)
	mut eff_port := port
	if eff_port == '' {
		eff_port = if scheme == 'https' { '443' } else { '80' }
	}
	return '${host.to_lower()}:${eff_port}'
}

// http_bind_resource returns the bind host:port for a net transport URL.
pub fn http_bind_resource(url string) string {
	_, rest := http_split_scheme(url)
	host, port := http_authority(rest)
	return '${host.to_lower()}:${port}'
}

// http_handle_resource returns a resource label for a handle-bound effect
// (accept-iter/respond/stop) where the target was checked at bind/dial.
pub fn http_handle_resource(args []cx.Node, op string) string {
	if args.len > 0 {
		if e := http_elem(args[0]) {
			if u := http_attr(e, 'url') {
				return http_bind_resource(u)
			}
			if u := http_attr(e, 'base-url') {
				return http_url_resource(u)
			}
		}
	}
	return op
}

// http_resolve_url resolves a possibly-relative url against base (§3.3).
// An absolute http(s) url passes through; a relative url with an empty base
// is an error (none → caller raises CXER4525).
fn http_resolve_url(url string, base string) ?string {
	sc, _ := http_split_scheme(url)
	if sc == 'http' || sc == 'https' {
		return url
	}
	if base == '' {
		return none
	}
	// minimal join: base authority + relative path (§3.3 defers full RFC-3986
	// join to cx-stdlib/url in the granted path; here we concat for the
	// resource derivation).
	if url.starts_with('/') {
		bscheme, brest := http_split_scheme(base)
		bhost, _ := http_authority(brest)
		// reuse base authority verbatim
		bauth := brest.all_before('/')
		_ = bhost
		return '${bscheme}://${bauth}${url}'
	}
	return base.trim_right('/') + '/' + url
}

// http_method_valid checks the method is an RFC 9110 token (no controls /
// separators). Methods are uppercase strings (§2.2); any non-empty token is
// accepted (custom methods allowed via `request`).
fn http_method_valid(m string) bool {
	if m == '' {
		return false
	}
	for c in m {
		if c <= 0x20 || c >= 0x7F {
			return false
		}
		if c in [`(`, `)`, `<`, `>`, `@`, `,`, `;`, `:`, `\\`, `"`, `/`, `[`, `]`, `?`,
			`=`, `{`, `}`] {
			return false
		}
	}
	return true
}



// ════════════════════════════════════════════════════════════════════
// §3.6 SSE / streaming — held-open server push + client read.
//
// Both halves share ONE pure `[event]` value: what the server frames with
// `send-event` parses back equal on the client via `sse-events` (the
// symmetry invariant, vcx/tests/http_sse_test.v). The framing codec
// (http_sse_frame_event / http_sse_parse_event) is the single shared
// implementation that makes the invariant hold by construction.
//
// The live held-open socket transport is REAL (built on the net layer, like the
// one-shot verbs + the low-level server loop): `sse` writes the event-stream
// prelude on the exchange's connection and holds it open; `send-event`/
// `heartbeat` flush real frames; `sse-connect` opens a real streaming GET and
// holds the response connection; `sse-events` reads live frames off it (a
// single-use streamed iterator with auto-reconnect). The pure accessors
// (stream-open/source-open/last-event-id) and the pure event-validation (empty →
// CXER4539, CR/LF → CXER4531) are exact. Behavioral coverage:
// vcx/tests/v08_http_sse_real_test.v (server push + client read over loopback).
// ════════════════════════════════════════════════════════════════════

// http_open_sse_streams counts live server-side SSE streams against the §3.6
// max-streams bound (default 1024). Incremented by `sse`, decremented when the
// stream's connection is closed.
__global (
	http_open_sse_streams int
)

pub const http_max_sse_streams = 1024

// http_sse_stream_closed releases a live SSE stream's slot against the §3.6
// max-streams bound (called by net_close_id when an sse-backed connection
// closes). Floored at 0 (idempotent double-close never underflows).
fn http_sse_stream_closed() {
	if http_open_sse_streams > 0 {
		http_open_sse_streams--
	}
}

// http_sse_streams_at_cap / http_sse_stream_opened — the serve half's
// (stdlib_http_serve.v, Ring 2) window onto the stream-count global. The
// counter lives HERE, beside net_close_id's release hook, because the
// close path is Ring-1 net-core territory; the Ring-2 server increments
// through these accessors instead of touching the global across the
// module seam (#651/#516 I3 seam H).
pub fn http_sse_streams_at_cap() bool {
	return http_open_sse_streams >= http_max_sse_streams
}

pub fn http_sse_stream_opened() {
	http_open_sse_streams++
}

// http_node_str extracts the string payload of a scalar node (the framing codec
// returns the wire frame as a string ScalarNode).
pub fn http_node_str(n cx.Node) string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return ''
}

// ── §8 SSE error codes (CXER4544–4551; 4531 = CR/LF-in-field) ────────
// All raised by the live transport:
//   4531 (CR/LF in a field, frame side), 4544 (send/heartbeat on a closed or
//   disconnected stream), 4545 (server max-streams bound), 4546 (write
//   backpressure — a stalled consumer past stream-write-timeout), 4547 (client
//   sse-connect got a 2xx that is not text/event-stream), 4548 (client
//   idle-timeout — no event/heartbeat within idle-timeout), 4549 (client
//   auto-reconnect exhausted past max-reconnect), 4550 (frame over
//   max-event-bytes), 4551 (malformed wire frame, parse side).
const http_err_field_invalid = 'cx-err:CXER4531' // E_HTTP_SSE_FIELD_INVALID (CR/LF in event/id/data)
pub const http_err_stream_closed = 'cx-err:CXER4544' // E_HTTP_STREAM_CLOSED
pub const http_err_stream_limit = 'cx-err:CXER4545' // E_HTTP_STREAM_LIMIT (server max-streams)
const http_err_stream_backpressure = 'cx-err:CXER4546' // E_HTTP_STREAM_BACKPRESSURE (best-effort, §3.6)
const http_err_sse_not_stream = 'cx-err:CXER4547' // E_HTTP_SSE_NOT_STREAM (2xx non-event-stream)
const http_err_sse_idle_timeout = 'cx-err:CXER4548' // E_HTTP_SSE_IDLE_TIMEOUT (best-effort, §3.6)
const http_err_sse_reconnect_exhausted = 'cx-err:CXER4549' // E_HTTP_SSE_RECONNECT_EXHAUSTED
const http_err_sse_frame_too_large = 'cx-err:CXER4550' // E_HTTP_SSE_FRAME_TOO_LARGE
const http_err_sse_parse = 'cx-err:CXER4551' // E_HTTP_SSE_PARSE

// http_sse_frame_event renders one [event …] as the canonical SSE wire
// frame (field lines + terminating blank line). Returns the wire text, or
// an error node when the [event] is empty / carries CR/LF in event|id.
// Field order: id, event, data (one `data:` line per \n split), retry.
// Exposed pub for the symmetry-invariant unit test (http_sse_test.v).
pub fn http_sse_frame_event(ev cx.Element) cx.Node {
	id := http_attr(ev, 'id') or { '' }
	event := http_attr(ev, 'event') or { '' }
	retry := http_attr(ev, 'retry') or { '' }
	has_data := if _ := http_attr(ev, 'data') { true } else { false }
	data := http_attr(ev, 'data') or { '' }
	// empty [event] (no SSE-meaningful field) → CXER4539. Unknown attrs do NOT
	// count as content: `[event foo="bar"]` carries nothing the wire can frame,
	// so it must fault rather than silently emit an empty frame (the prior
	// `&& ev.attrs.len == 0` let any unknown-attr event slip through as empty).
	if id == '' && event == '' && retry == '' && !has_data {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: empty [event] has nothing to send')
	}
	// CR/LF in event/id, OR CR in data, corrupts the line-framed wire → CXER4531.
	// LF in data is the legitimate multi-line separator (one `data:` line each);
	// a CR is not, and the prior framer left it unguarded so a `data` value
	// ending in CR was silently lost on parse (trim_right('\r')) — breaking the
	// frame↔parse symmetry invariant. Reject CR in data, both directions.
	if id.contains('\n') || id.contains('\r') || event.contains('\n') || event.contains('\r')
	   || data.contains('\r') {
		return mk_err(http_err_field_invalid, 'E_HTTP_SSE_FIELD_INVALID: CR/LF not allowed in event/id; CR not allowed in data')
	}
	mut sb := []string{}
	if id != '' {
		sb << 'id: ${id}'
	}
	if event != '' {
		sb << 'event: ${event}'
	}
	if has_data {
		// multi-line data splits on \n into one `data:` line each
		for line in data.split('\n') {
			sb << 'data: ${line}'
		}
	}
	if retry != '' {
		sb << 'retry: ${retry}'
	}
	return http_str(sb.join('\n') + '\n\n')
}

// http_sse_block_malformed reports whether a wire frame block is structurally
// corrupt: a line carrying an embedded CR (a CR that is not the CRLF line
// terminator stripped by trim_right). Our framer never emits such a byte (it
// rejects CR in every field, CXER4531), so its presence on the wire is a
// genuine framing fault → CXER4551. Comment/heartbeat/unknown-field frames are
// NOT malformed (they parse to `none` and are consumed silently).
pub fn http_sse_block_malformed(block string) bool {
	for raw in block.split('\n') {
		if raw.trim_right('\r').contains('\r') {
			return true
		}
	}
	return false
}

// http_sse_parse_event parses one SSE wire frame (a block of field lines)
// into an [event …]. Comment (`:`-leading) lines are dropped; a block with
// no event fields → none (a heartbeat/comment-only frame, consumed
// silently). data lines re-join with \n. Exposed pub for the
// symmetry-invariant unit test (http_sse_test.v).
pub fn http_sse_parse_event(block string) ?cx.Element {
	mut id := ''
	mut event := ''
	mut retry := ''
	mut data := []string{}
	mut any_field := false
	mut has_data := false
	for raw in block.split('\n') {
		line := raw.trim_right('\r')
		if line == '' {
			continue
		}
		if line.starts_with(':') {
			continue // comment / heartbeat
		}
		mut field := line
		mut value := ''
		if ci := line.index(':') {
			field = line[..ci]
			value = line[ci + 1..]
			if value.starts_with(' ') {
				value = value[1..]
			}
		}
		match field {
			'id' { id = value any_field = true }
			'event' { event = value any_field = true }
			'retry' { retry = value any_field = true }
			'data' { data << value has_data = true any_field = true }
			else {} // unknown field ignored per SSE spec
		}
	}
	if !any_field {
		return none
	}
	mut attrs := []cx.Attribute{}
	if id != '' {
		attrs << cx.Attribute{ name: 'id', value: cx.ScalarValue(id) }
	}
	if event != '' {
		attrs << cx.Attribute{ name: 'event', value: cx.ScalarValue(event) }
	}
	if has_data {
		attrs << cx.Attribute{ name: 'data', value: cx.ScalarValue(data.join('\n')) }
	}
	if retry != '' {
		// retry is the integer reconnect hint
		ri := retry.i64()
		attrs << cx.Attribute{ name: 'retry', value: cx.ScalarValue(ri) }
	}
	return cx.Element{
		name:  'event'
		attrs: attrs
	}
}






// http_sse_connect_impl — §3.6 client: open a REAL streaming GET. URL-first +
// net-gated like get. Dials (with the §4.5 SSRF guard), sends the GET with
// `Accept: text/event-stream` (+ `Last-Event-ID` on resume), reads the response
// status + headers, then HOLDS the connection open: a 2xx text/event-stream
// returns a live [sse-source fd=N] read handle; a 2xx that is NOT an event
// stream → CXER4547; a non-2xx is returned as a materialized [response] value
// (§2.4). The reconnect/idle/cap opts are carried on the source for sse-events.
fn http_sse_connect_impl(args []cx.Node) cx.Node {
	url := http_arg_str(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-connect expects a URL string')
	}
	if e := http_validate_absolute_url(url) {
		return e
	}
	if d := cap_guard('net', http_url_resource(url)) {
		return d
	}
	opts_node := if args.len > 1 { args[1] } else { http_null() }
	leid := http_map_entry_str(opts_node, 'last-event-id')
	return http_sse_open_source(url, opts_node, leid)
}

// http_sse_open_source performs the real streaming-GET handshake and returns the
// live [sse-source] (or a materialized [response] / an err). Shared by
// sse-connect and the sse-events auto-reconnect path (eval.v): `leid` is the
// Last-Event-ID to resume from (empty = none).
fn http_sse_open_source(url string, opts_node cx.Node, leid string) cx.Node {
	scheme, host, port, path := http_url_parts(url)
	pinned, derr := net_ssrf_check(host, port)
	if e := derr {
		return e
	}
	// dial via the net layer so we get a buffered NetHandle for frame reads.
	dialed := if scheme == 'https' {
		verify, ca := http_opts_tls(opts_node)
		ca_eff := if ca != '' { ca } else if verify { http_os_ca_bundle() } else { '' }
		tls_opts := http_tls_opts_node(verify, ca_eff)
		net_dial_tls_real(pinned, host, port, tls_opts, NetAddr{ host: host, port: port, scheme: 'tls' })
	} else {
		net_dial_tcp_real(NetAddr{ host: pinned, port: port, scheme: 'tcp' }, cx.Node(cx.Element{ name: '__cx_map__' }))
	}
	if is_err_value(dialed) {
		return dialed
	}
	fd := net_handle_id(dialed) or {
		return mk_err('cx-err:CXER4506', 'E_HTTP: sse-connect produced no handle')
	}
	mut h := net_lookup(fd) or {
		return mk_err('cx-err:CXER4506', 'E_HTTP: sse-connect produced no handle')
	}
	mut head := 'GET ${path} HTTP/1.1\r\nHost: ${host}\r\nAccept: text/event-stream\r\n'
	// #661: opts.headers reaches the subscription GET, exactly as it reaches
	// every other request (§3.6 'plus the parent client keys'). Without this
	// a caller cannot authenticate a stream at all — xap_identity_model §4.12
	// requires `GET /stream` to carry the same three XSP proof headers as any
	// other request, and they had nowhere to ride.
	//
	// Managed fields are ignored, not errors (§4.6): Host / Connection /
	// Content-Length / Transfer-Encoding are the implementation's. `Accept`
	// and `Last-Event-ID` join them here because they ARE this verb — Accept
	// selects the event stream (a non-stream 2xx is CXER4547) and
	// Last-Event-ID is owned by opts.last-event-id and the auto-reconnect
	// path. CR/LF in a name or value is request-splitting → CXER4531.
	for hdr in http_opts_headers(opts_node) {
		lname := hdr[0].to_lower()
		if lname in ['host', 'connection', 'content-length', 'transfer-encoding', 'accept',
			'last-event-id'] {
			continue
		}
		joined := hdr[0] + hdr[1]
		if joined.contains('\r') || joined.contains('\n') {
			net_close_id(fd)
			return mk_err(http_err_field_invalid, 'E_HTTP_HEADER_INVALID: CR/LF in sse-connect header "${hdr[0]}"')
		}
		head += '${hdr[0]}: ${hdr[1]}\r\n'
	}
	if leid != '' {
		head += 'Last-Event-ID: ${leid}\r\n'
	}
	head += 'Connection: keep-alive\r\n\r\n'
	net_h_write(mut h, head.bytes()) or {
		net_close_id(fd)
		return mk_err('cx-err:CXER4508', 'E_HTTP: sse-connect write GET: ${err.msg()}')
	}
	// read the response status line + header block off the held-open connection.
	status_line := net_read_line_buf(mut h) or {
		net_close_id(fd)
		return mk_err('cx-err:CXER4526', 'E_HTTP_INVALID_RESPONSE: sse-connect: empty response')
	}
	sl_parts := status_line.split(' ')
	if sl_parts.len < 2 {
		net_close_id(fd)
		return mk_err('cx-err:CXER4526', 'E_HTTP_INVALID_RESPONSE: malformed status line "${status_line}"')
	}
	status := sl_parts[1].int()
	mut content_type := ''
	mut content_length := 0
	mut resp_hdrs := []cx.Node{}
	for {
		line := net_read_line_buf(mut h) or { break }
		if line == '' {
			break
		}
		ci := line.index(':') or { continue }
		hn := line[..ci].trim_space()
		hv := line[ci + 1..].trim_space()
		lname := hn.to_lower()
		if lname == 'content-type' {
			content_type = hv.to_lower()
		}
		if lname == 'content-length' {
			content_length = hv.int()
		}
		resp_hdrs << cx.Node(cx.Element{
			name:  'header'
			attrs: [
				cx.Attribute{ name: 'name', value: cx.ScalarValue(hn) },
				cx.Attribute{ name: 'value', value: cx.ScalarValue(hv) },
			]
		})
	}
	if status < 200 || status >= 300 {
		// non-2xx → materialized [response] value (§2.4); drain the body.
		mut body := []u8{}
		if content_length > 0 {
			body = net_read_exact_buf(mut h, content_length)
		}
		net_close_id(fd)
		return cx.Element{
			name:  'response'
			attrs: [cx.Attribute{ name: 'status', value: cx.ScalarValue(i64(status)) }]
			items: [
				cx.Node(cx.Element{ name: 'headers', items: resp_hdrs }),
				cx.Node(cx.Element{
					name:  'body'
					items: [cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(body.bytestr())
						data_type: cx.ScalarType.string_type
					})]
				}),
			]
		}
	}
	if !content_type.starts_with('text/event-stream') {
		net_close_id(fd)
		return mk_err(http_err_sse_not_stream, 'E_HTTP_SSE_NOT_STREAM: 2xx response is ${content_type}, not text/event-stream')
	}
	mut attrs := [
		cx.Attribute{ name: 'fd', value: cx.ScalarValue(i64(fd)) },
		cx.Attribute{ name: 'url', value: cx.ScalarValue(url) },
		cx.Attribute{ name: 'open', value: cx.ScalarValue(true) },
		cx.Attribute{ name: 'on-close', value: cx.ScalarValue('http/close') },
	]
	if leid != '' {
		attrs << cx.Attribute{ name: 'last-event-id', value: cx.ScalarValue(leid) }
	}
	meb := http_map_entry_str(opts_node, 'max-event-bytes')
	if meb != '' {
		attrs << cx.Attribute{ name: 'max-event-bytes', value: cx.ScalarValue(meb.i64()) }
	}
	// reconnect policy (§3.6): default on, bounded by max-reconnect (default 10).
	reconnect := http_map_entry_str(opts_node, 'reconnect')
	if reconnect == 'false' {
		attrs << cx.Attribute{ name: 'reconnect', value: cx.ScalarValue('false') }
	}
	mr := http_map_entry_str(opts_node, 'max-reconnect')
	if mr != '' {
		attrs << cx.Attribute{ name: 'max-reconnect', value: cx.ScalarValue(mr.i64()) }
	}
	rt := http_map_entry_str(opts_node, 'retry')
	if rt != '' {
		attrs << cx.Attribute{ name: 'retry', value: cx.ScalarValue(rt.i64()) }
	}
	return cx.Element{
		name:  'sse-source'
		attrs: attrs
	}
}

// ── sse-events walker policy accessors (read off the [sse-source]) ──────
fn http_source_url(source cx.Node) string {
	if source is cx.Element {
		return http_attr(source, 'url') or { '' }
	}
	return ''
}

fn http_source_leid(source cx.Node) string {
	if source is cx.Element {
		return http_attr(source, 'last-event-id') or { '' }
	}
	return ''
}

// http_sse_retry_ms — reconnect backoff (the §3.6 `retry` opt; default 3000 ms).
fn http_sse_retry_ms(source cx.Node) int {
	if source is cx.Element {
		if v := http_attr(source, 'retry') {
			return v.int()
		}
	}
	return 3000
}

// http_event_id reads the `id` attr off a parsed [event] (for Last-Event-ID
// resume across reconnects); '' when the event carries no id.
fn http_event_id(ev cx.Node) string {
	if ev is cx.Element && ev.name == 'event' {
		return http_attr(ev, 'id') or { '' }
	}
	return ''
}

// http_sse_mark_consumed flips the source's connection handle to consumed so a
// second sse-events walk raises CXER0105 (single-use iterator, §3.6).
fn http_sse_mark_consumed(source cx.Node) {
	if id := net_handle_id(source) {
		if mut h := net_lookup(id) {
			h.consumed = true
		}
	}
}

// http_sse_is_source reports whether a node is a live [sse-source] (vs a
// materialized [response] / err returned by a reconnect attempt).
fn http_sse_is_source(n cx.Node) bool {
	return n is cx.Element && n.name == 'sse-source'
}

// http_sse_receive — `[?receive from=<sse-source> max=N deadline=ms]`.
// U1.8a ruled the sse-connect handle a delivery.md §4 subscription-contract
// value ("the general [?receive]/[?select] accept it" — http.md §3.6); this
// closes the spec-implementation gap W24 hit: `sse-events` is a SINGLE-USE
// whole-stream walk, so a long-lived consumer (a shell reading one event per
// select wake) had no legal spelling at all. Reads up to N framed events off
// the held-open stream; `deadline` bounds the WHOLE batch and expiry returns
// what arrived (a batch is a value, not a fault — §10.4.3). The
// single-message form (no max) does one blocking frame read. The per-read
// deadline rides the handle's own §3.7 mechanism and is restored after.
pub fn http_sse_receive(source cx.Node, max int, deadline i64) cx.Node {
	if !http_sse_is_source(source) {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: receive expects an [sse-source]')
	}
	id := net_handle_id(source) or {
		return mk_err('cx-err:CXER0105', 'E_ITERATOR_EXHAUSTED: receive on a closed/unknown sse source')
	}
	mut h := net_lookup(id) or {
		return mk_err('cx-err:CXER0105', 'E_ITERATOR_EXHAUSTED: receive on a closed/unknown sse source')
	}
	max_eb := http_sse_max_event_bytes(source)
	want := if max > 0 { max } else { 1 }
	started := time.now()
	prior := h.read_deadline_ms
	mut out := []cx.Node{}
	for out.len < want {
		if deadline >= 0 {
			elapsed := time.since(started).milliseconds()
			remaining := deadline - elapsed
			if remaining <= 0 {
				break
			}
			net_set_read_deadline_id(id, remaining)
		}
		frame := http_sse_read_frame(mut h, max_eb) or { break }
		if is_err_value(frame) {
			net_set_read_deadline_id(id, prior)
			if max > 0 {
				break
			}
			return frame
		}
		out << frame
	}
	net_set_read_deadline_id(id, prior)
	if max > 0 {
		return cx.Element{
			name:  seq_marker_name
			items: out
		}
	}
	if out.len > 0 {
		return out[0]
	}
	return mk_err(net_err_timeout, 'E_NET_TIMEOUT: no event before the receive deadline')
}

// http_tls_opts_node builds a {tls: {verify, ca}} opts map for net_dial_tls_real.
fn http_tls_opts_node(verify bool, ca string) cx.Node {
	mut tls_items := [cx.Node(cx.Element{
		name:  'verify'
		items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(verify), data_type: cx.ScalarType.bool_type })]
	})]
	if ca != '' {
		tls_items << cx.Node(cx.Element{
			name:  'ca'
			items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(ca), data_type: cx.ScalarType.string_type })]
		})
	}
	return cx.Element{
		name:  '__cx_map__'
		items: [cx.Node(cx.Element{ name: 'tls', items: [cx.Node(cx.Element{ name: '__cx_map__', items: tls_items })] })]
	}
}

// http_sse_events_impl — §3.6 client: return the live single-use [iterator
// element] that yields parsed [event]s as they arrive on the held-open
// connection (the frame read + auto-reconnect run in the iter_sse_events walker,
// eval.v). A second walk of an already-consumed source → CXER0105. Clean
// end-of-stream is the absence channel (the walker simply stops).
fn http_sse_events_impl(args []cx.Node) cx.Node {
	source := http_elem(args[0]) or {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-events expects an [sse-source]')
	}
	if source.name != 'sse-source' {
		return mk_err(http_err_arg_invalid, 'E_HTTP_ARG_INVALID: sse-events expects an [sse-source]')
	}
	if d := cap_guard('net', http_handle_resource(args, 'sse-events')) {
		return d
	}
	// single-use: a second sse-events walk of the same source → CXER0105.
	if id := net_handle_id(source) {
		if h := net_lookup(id) {
			if h.consumed {
				return mk_err('cx-err:CXER0105', 'E_ITERATOR_EXHAUSTED: sse-events is single-use; this source was already walked')
			}
		}
	}
	return cx.new_iterator(.iter_sse_events, [args[0]])
}

// http_sse_max_event_bytes / http_sse_reconnect_enabled / http_sse_max_reconnect
// read the §3.6 sse-events policy off the [sse-source] for the walker.
fn http_sse_max_event_bytes(source cx.Node) i64 {
	if source is cx.Element {
		if v := http_attr(source, 'max-event-bytes') {
			return v.i64()
		}
	}
	return i64(1048576)
}

fn http_sse_reconnect_enabled(source cx.Node) bool {
	if source is cx.Element {
		if v := http_attr(source, 'reconnect') {
			return v != 'false'
		}
	}
	return true
}

fn http_sse_max_reconnect(source cx.Node) int {
	if source is cx.Element {
		if v := http_attr(source, 'max-reconnect') {
			return v.int()
		}
	}
	return 10
}

// http_sse_read_frame reads ONE SSE frame (field lines up to the blank-line
// boundary) off the live source connection and returns the parsed [event], or:
//   - an err node (CXER4550 over-cap / CXER4551 malformed)
//   - none on clean end-of-stream (connection closed without a partial frame)
// Comment/heartbeat frames are consumed and the read continues to the next.
fn http_sse_read_frame(mut h NetHandle, max_event_bytes i64) ?cx.Node {
	for {
		mut lines := []string{}
		mut frame_bytes := 0
		mut saw_line := false
		for {
			line := net_read_line_buf(mut h) or {
				// connection closed. A partial frame in hand is end-of-stream too.
				if !saw_line {
					return none
				}
				break
			}
			if line == '' {
				break // frame boundary
			}
			saw_line = true
			frame_bytes += line.len + 1
			if max_event_bytes > 0 && i64(frame_bytes) > max_event_bytes {
				return cx.Node(mk_err(http_err_sse_frame_too_large,
					'E_HTTP_SSE_FRAME_TOO_LARGE: frame exceeds max-event-bytes (${max_event_bytes})'))
			}
			lines << line
		}
		if lines.len == 0 {
			// a bare blank line (keep-alive) → keep reading.
			if h.eof {
				return none
			}
			continue
		}
		block := lines.join('\n')
		if http_sse_block_malformed(block) {
			return cx.Node(mk_err(http_err_sse_parse, 'E_HTTP_SSE_PARSE: malformed SSE wire frame'))
		}
		ev := http_sse_parse_event(block) or {
			// comment / heartbeat-only frame → consume silently, read the next.
			if h.eof {
				return none
			}
			continue
		}
		return cx.Node(ev)
	}
	return none
}

// http_source_open_impl — §3.6 pure accessor.
fn http_source_open_impl(args []cx.Node) cx.Node {
	source := http_elem(args[0]) or { return http_bool(false) }
	if source.name != 'sse-source' {
		return http_bool(false)
	}
	if open := http_attr(source, 'open') {
		return http_bool(open != 'false')
	}
	return http_bool(false)
}

// http_last_event_id_impl — §3.6 pure accessor; absent → absence channel.
fn http_last_event_id_impl(args []cx.Node) cx.Node {
	source := http_elem(args[0]) or { return http_empty_nodeset() }
	if source.name != 'sse-source' {
		return http_empty_nodeset()
	}
	if leid := http_attr(source, 'last-event-id') {
		if leid != '' {
			return http_str(leid)
		}
	}
	return http_empty_nodeset()
}

// ── §3.6 SSE client [?for] walkers (Ring 1 — the client pack owns its
// live read loop; seam H moved these back from iter_walks_net_http.v,
// where they briefly lived while ALL of http was censused Ring 2.
// Dispatched DIRECTLY at the [?for] sites in eval.v, like the other
// Ring-1 kinds (.iter_iterate / .iter_unfold) — not via the Ring-2
// iterator registry). ─────────────────────────────────────────────
// iter_sse_events_walk / _streamed — http.md §3.6 client read loop for
// `[?for [in $ev [$http:sse-events $src]] …]`. Each pull reads one SSE frame off
// the held-open [sse-source] connection (http_sse_read_frame) and yields the
// parsed [event]. Clean end-of-stream is absence (the loop stops, marking the
// source consumed → CXER0105 on a second walk). When auto-reconnect is enabled
// (default), a clean disconnect re-dials with Last-Event-ID up to max-reconnect
// (beyond → CXER4549); a read fault (over-cap/malformed) is emitted then stops.
fn iter_sse_events_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut out []cx.Node, mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 1 {
		return
	}
	orig := source_val.source_args[0]
	mut cur_source := orig
	max_eb := http_sse_max_event_bytes(cur_source)
	reconnect := http_sse_reconnect_enabled(cur_source)
	max_rc := http_sse_max_reconnect(cur_source)
	retry_ms := http_sse_retry_ms(cur_source)
	url := http_source_url(cur_source)
	mut last_id := http_source_leid(cur_source)
	mut attempts := 0
	for {
		if limit_state.remaining == 0 {
			http_sse_mark_consumed(orig)
			return
		}
		mut h := net_mut_handle(cur_source) or {
			http_sse_mark_consumed(orig)
			return
		}
		frame := http_sse_read_frame(mut h, max_eb) or {
			// clean end-of-stream → reconnect (if enabled) or stop (absence).
			if reconnect && url != '' && attempts < max_rc {
				attempts++
				if retry_ms > 0 {
					time.sleep(retry_ms * time.millisecond)
				}
				reconn := http_sse_open_source(url, http_null(), last_id)
				if http_sse_is_source(reconn) {
					cur_source = reconn
					attempts = 0
					continue
				}
				if attempts >= max_rc {
					gen_emit_item(c, mk_err(http_err_sse_reconnect_exhausted,
						'E_HTTP_SSE_RECONNECT_EXHAUSTED: reconnect failed after ${max_rc} attempts'),
						clauses, idx, spec, mut env, mut out, mut limit_state)!
					return
				}
				continue
			}
			http_sse_mark_consumed(orig)
			return
		}
		if is_err_value(frame) {
			gen_emit_item(c, frame, clauses, idx, spec, mut env, mut out, mut limit_state)!
			http_sse_mark_consumed(orig)
			return
		}
		eid := http_event_id(frame)
		if eid != '' {
			last_id = eid
		}
		gen_emit_item(c, frame, clauses, idx, spec, mut env, mut out, mut limit_state)!
	}
}

fn iter_sse_events_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut ctx StreamCtx, mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 1 {
		return
	}
	orig := source_val.source_args[0]
	mut cur_source := orig
	max_eb := http_sse_max_event_bytes(cur_source)
	reconnect := http_sse_reconnect_enabled(cur_source)
	max_rc := http_sse_max_reconnect(cur_source)
	retry_ms := http_sse_retry_ms(cur_source)
	url := http_source_url(cur_source)
	mut last_id := http_source_leid(cur_source)
	mut attempts := 0
	for {
		if limit_state.remaining == 0 {
			http_sse_mark_consumed(orig)
			return
		}
		mut h := net_mut_handle(cur_source) or {
			http_sse_mark_consumed(orig)
			return
		}
		frame := http_sse_read_frame(mut h, max_eb) or {
			if reconnect && url != '' && attempts < max_rc {
				attempts++
				if retry_ms > 0 {
					time.sleep(retry_ms * time.millisecond)
				}
				reconn := http_sse_open_source(url, http_null(), last_id)
				if http_sse_is_source(reconn) {
					cur_source = reconn
					attempts = 0
					continue
				}
				if attempts >= max_rc {
					gen_emit_item_streamed(c, mk_err(http_err_sse_reconnect_exhausted,
						'E_HTTP_SSE_RECONNECT_EXHAUSTED: reconnect failed after ${max_rc} attempts'),
						clauses, idx, spec, mut env, mut ctx, mut limit_state)!
					return
				}
				continue
			}
			http_sse_mark_consumed(orig)
			return
		}
		if is_err_value(frame) {
			gen_emit_item_streamed(c, frame, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
			http_sse_mark_consumed(orig)
			return
		}
		eid := http_event_id(frame)
		if eid != '' {
			last_id = eid
		}
		gen_emit_item_streamed(c, frame, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
	}
}
