module code

import cx

// module_fetch — the Phase-2.14 live HTTPS module transport
// (spec code.md §12.1.3 / lockfile.md §5; remediation register R3.12,
// RULED (b) 2026-08-09). Rides the http-client pack by file suffix:
// an engine composed without the pack never compiles this file and
// module_fetch_transport refuses there instead — the on-disk cache and
// pre-registered pinned sources need no network and stay loadable.
//
// TLS verification is ALWAYS on for module fetches: this path passes no
// TLS knob whatsoever (HttpReqOpts defaults verify), the scheme is
// asserted https:// here as defense in depth, and http:// resolvers were
// already refused at parse (CXER0208). The fetch is capability-gated on
// `net` like every other outbound request.
fn module_fetch_https_live(url string) !string {
	if !url.starts_with('https://') {
		return error('MODULE_FETCH_TRANSPORT: refusing non-https module url `${url}` (TLS always on, code.md §12.1.3)')
	}
	if _ := cap_guard('net', 'module https fetch ${url}') {
		return error('MODULE_FETCH_TRANSPORT: the `net` capability is required to fetch module `${url}` (CXER0271)')
	}
	r := http_do_single('GET', url, [][]string{}, []u8{}, HttpReqOpts{})
	if r is cx.Element {
		if r.name == 'err' {
			return error('MODULE_FETCH_TRANSPORT: GET ${url}: ${render_canonical(r)}')
		}
		if r.name == 'response' {
			status := (r.attr('status')).int()
			if status != 200 {
				return error('MODULE_FETCH_TRANSPORT: GET ${url} answered status ${status} (only 200 loads a module)')
			}
			for it in r.items {
				if it is cx.Element && it.name == 'body' && it.items.len == 1 {
					b := it.items[0]
					if b is cx.ScalarNode {
						v := b.value
						if v is string {
							return v
						}
					}
				}
			}
			return error('MODULE_FETCH_TRANSPORT: GET ${url}: response carries no body')
		}
	}
	return error('MODULE_FETCH_TRANSPORT: GET ${url}: malformed transport reply')
}
