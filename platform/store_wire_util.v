module platform

import cx
import code {
	http_child,
}

// Shared store-wire utilities (R4.4 CSRP retirement, stage S1, 2026-08-08).
//
// These are generic CX node / response builders the store SERVER core reuses
// across wire framings — the profile-op pipeline (store_profile_ops.v) and the
// gRPC adapter both build the same cxd-text `[response]` values through them.
// They were historically prefixed `csrp_` and defined inside store_csrp.v, but
// carry no CSRP-specific semantics; relocated + renamed here so the surviving
// profile/gRPC core no longer depends on the doomed CSRP router file. The
// `sw_` prefix = store-wire. (The CSRP-CLIENT helpers — sw-less
// csrp_client_headers/op_url/client_admin/status_err — are genuinely
// CSRP-specific and die with the router in stage S3.)

// sw_attr returns the value of attribute `name` on element `e`, or '' if absent.
fn sw_attr(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// sw_has_attr reports whether attribute `name` is present on `e` (present-but-
// empty is distinct from absent — the refs-set CAS uses expect="" for
// "must not exist").
fn sw_has_attr(e cx.Element, name string) bool {
	for a in e.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

// sw_msg_esc makes an error message safe to embed in a double-quoted cxd
// response attribute.
fn sw_msg_esc(s string) string {
	return s.replace('"', "'")
}

fn sw_scalar(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	// A quoted string ("…") in cx data parses to a TextNode, not a ScalarNode —
	// the wire form [hash "…"] lands here on the client's list parse.
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// sw_query reads a named query-param value off the parsed [request]. The
// http exchange-request models query params as [query-params [<name> "<value>"]].
fn sw_query(req cx.Element, name string) string {
	qp := http_child(req, 'query-params') or { return '' }
	for it in qp.items {
		if it is cx.Element && it.name == name {
			for c in it.items {
				if c is cx.ScalarNode {
					return cx.scalar_value_str_public(c.value)
				}
			}
		}
	}
	return ''
}

// sw_err_code reads the `code` attribute from an [err code="…"] value, so a
// route can map a store-layer fault onto the right wire code.
fn sw_err_code(n cx.Node) string {
	if n is cx.Element && n.name == 'err' {
		for a in n.attrs {
			if a.name == 'code' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// sw_resp builds a server-form [response status=N [body "<text>"]] value.
fn sw_resp(status int, body string) cx.Node {
	return cx.Element{
		name:  'response'
		attrs: [
			cx.Attribute{
				name:  'status'
				value: cx.ScalarValue(i64(status))
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'body'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(body)
						data_type: cx.ScalarType.string_type
					}),
				]
			}),
		]
	}
}

// sw_resp_hdrs builds a response carrying explicit headers (the
// `[response [headers [header name= value=]] [body …]]` shape emitted by
// http_respond_impl). Used for the required `Retry-After` on 429/503 (#191) —
// sw_resp alone has no header channel.
fn sw_resp_hdrs(status int, body string, headers [][]string) cx.Node {
	mut hnodes := []cx.Node{}
	for h in headers {
		if h.len != 2 {
			continue
		}
		hnodes << cx.Node(cx.Element{
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
		})
	}
	return cx.Element{
		name:  'response'
		attrs: [
			cx.Attribute{
				name:  'status'
				value: cx.ScalarValue(i64(status))
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'headers'
				items: hnodes
			}),
			cx.Node(cx.Element{
				name:  'body'
				items: [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(body)
						data_type: cx.ScalarType.string_type
					}),
				]
			}),
		]
	}
}

// sw_resp_retry is a 429/503 with the required Retry-After header (#191).
// `secs` is the advised backoff in seconds.
fn sw_resp_retry(status int, body string, secs int) cx.Node {
	return sw_resp_hdrs(status, body, [['Retry-After', secs.str()]])
}

// sw_admin_op_err maps an admin-op store fault onto a server response.
fn sw_admin_op_err(r cx.Node) cx.Node {
	ecode := svc_err_code(r)
	emsg := sw_msg_esc(svc_err_msg(r))
	if ecode == 'cx-err:CXER1709' {
		return sw_resp(404, '[err code="cx-err:CXER1709" message="${emsg}"]')
	}
	if ecode == 'cx-err:CXER1110' {
		return sw_resp(400, '[err code="cx-err:CXER1701" message="E_STORE_REQUEST_MALFORMED: ${emsg}"]')
	}
	return sw_resp(500, '[err code="cx-err:CXER1707" message="E_STORE_SERVER_INTERNAL: ${emsg}"]')
}

// wire_req_header reads an HTTP-shaped request header value (case-insensitive),
// or '' when absent. Relocated from the retired store_csrp_wire.v (S3): it is a
// generic request-shape reader, not CSRP-specific.
fn wire_req_header(req cx.Element, name string) string {
	ln := name.to_lower()
	for it in req.items {
		if it is cx.Element && it.name == 'headers' {
			for h in it.items {
				if h is cx.Element && h.name == 'header' {
					if sw_attr(h, 'name').to_lower() == ln {
						return sw_attr(h, 'value')
					}
				}
			}
		}
	}
	return ''
}
