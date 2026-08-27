module code

// err_boundary.v — RULED: CO-2 (#975, ledger/rulings_2026_08_25_0170_closeout.md).
//
// Refusals refuse at the EFFECT boundary. In-process, an [err] element is a
// VALUE like any other — collection literals carry it (measured cells,
// confirmed by CO-2), channels transit it (stdlib/supervise's
// `([sup-note …], $err)` pair depends on that), pure functions format it
// (rendering an error to log it is legitimate). What an [err] must never do
// is leave the program SILENTLY: an effect that externalizes a document —
// a file write, a store document write, an http response — refuses when the
// document contains an [err] at any depth, naming the first one's code and
// path, unless the effect names the permission explicitly (`errs=:permit`,
// one spelling across every effect family). This closes the class where a
// generator reports success while its output carries refusals as data, and
// where a web client renders [err] into HTML — at the only honest place,
// the boundary. Blob/bytes writes are exempt by construction (bytes are
// opaque; there is no [err] in them to find).

import cx

// ErrAtRest names the first [err] found inside a value headed for an
// externalizing effect: its code attribute (may be empty — an [err] without
// a code is still an [err]) and a element-name path to it.
pub struct ErrAtRest {
pub:
	code string
	path string
}

// find_err_at_rest walks `n` depth-first and returns the FIRST [err]
// element encountered, with a readable path. Marker elements (sequence,
// array, map, document wrappers) contribute positional segments instead of
// their internal names. Attributes cannot carry elements, so only items are
// walked; early exit on the first hit keeps the common (err-free) case one
// pass with no allocation beyond the path scratch.
pub fn find_err_at_rest(n cx.Node) ?ErrAtRest {
	return find_err_at_rest_walk(n, '')
}

fn find_err_at_rest_walk(n cx.Node, path string) ?ErrAtRest {
	if n is cx.Element {
		if n.name == 'err' {
			mut ecode := ''
			for a in n.attrs {
				if a.name == 'code' {
					v := a.value
					if v is string {
						ecode = v
					}
				}
			}
			p := if path == '' { '/err' } else { '${path}/err' }
			return ErrAtRest{
				code: ecode
				path: p
			}
		}
		seg := match n.name {
			seq_marker_name, '__cx_arr__', map_marker_name, '__cx_document__' { path }
			else { '${path}/${n.name}' }
		}
		for i, it in n.items {
			sub := if n.name == seq_marker_name || n.name == '__cx_arr__' {
				'${seg}[${i + 1}]'
			} else {
				seg
			}
			if hit := find_err_at_rest_walk(it, sub) {
				return hit
			}
		}
	}
	return none
}

// errs_permitted_node reports whether an effect's opts value (a CX map
// literal materialized as a __cx_map__ envelope — entries ride as CHILD
// ELEMENTS, sometimes as attrs; both shapes collected, mirroring the
// store-open-opts lesson) or a bare element's attributes carry
// `errs: :permit` / `errs=:permit`. One word, one value, every effect
// family (CO-2's one-spelling rule).
pub fn errs_permitted_node(opts cx.Node) bool {
	if opts is cx.Element {
		for a in opts.attrs {
			if a.name == 'errs' && scalar_permits(a.value) {
				return true
			}
		}
		for it in opts.items {
			if it is cx.Element {
				if it.name == 'errs' && it.items.len == 1 {
					inner := it.items[0]
					if inner is cx.ScalarNode {
						if scalar_permits(inner.value) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// scalar_permits — true for the atom :permit however the carrier spells it
// (atom-typed scalars carry the bare word; a quoted spelling keeps the colon).
fn scalar_permits(v cx.ScalarValue) bool {
	if v is string {
		return v == 'permit' || v == ':permit'
	}
	return false
}

// err_boundary_refusal builds the typed CXER0275 refusal for `family`
// ('file write' / 'store write' / 'http response') over the first found
// [err]. The message names what was found, where, and the permission
// spelling — the operator reading this at 2 a.m. gets the whole story.
pub fn err_boundary_refusal(family string, hit ErrAtRest) cx.Node {
	code_part := if hit.code == '' { 'an [err] with no code' } else { hit.code }
	return cx.Element{
		name:  'err'
		attrs: [
			cx.Attribute{
				name:  'code'
				value: cx.ScalarValue('cx-err:CXER0275')
			},
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue('E_ERR_AT_BOUNDARY: refusing the ${family} — the document contains ${code_part} at ${hit.path}; a refusal must not leave the program as silent data (pass errs=:permit on the effect to externalize it deliberately)')
			},
			cx.Attribute{
				name:  'err-path'
				value: cx.ScalarValue(hit.path)
			},
			cx.Attribute{
				name:  'err-code'
				value: cx.ScalarValue(hit.code)
			},
		]
	}
}
