module platform

import cx
import code { cx_code_tier2_hash, mk_err, new_purity_checker }

// store_computation.v — cache admission for the computation/<addr> alias
// namespace (stream 5, #677 — computation_identity.md L102/L106).
//
// The [computation] record is constructed IN-LANGUAGE (cx:computation-id +
// cx:hash/store addresses + cx:env + caps + map literals); the cache is an
// alias on the EXISTING alias verbs — no new store API, and the explicit
// store-mediated lookup keeps the cache honest and visible. What makes it
// a cache and not a claim registry is THIS check: binding a result into
// computation/<addr> validates FAIL-LOUD at admission —
//
//   CXER1117 E_STORE_COMPUTATION_RECORD_INVALID — the <addr> segment is
//     not an address / no record is stored there / the stored value is
//     not a well-shaped [computation] record / the fn.code Tier-2 claim
//     does not recompute from fn.source / the record text does not
//     rehash to <addr> (recompute-and-refuse, never trust-the-name).
//   CXER1118 E_STORE_COMPUTATION_NOT_PURE — fn.source does not resolve
//     in this store, does not parse as a single [?def], does not DECLARE
//     pure, or fails the static purity checker (L106: the cache is
//     pure-only; the pure ⇒ deterministic theorem, code.md §6.5.1, is
//     what makes a cached result sound). Admission is a trust boundary
//     (the #702 posture): ANY checker refusal — including an
//     unclassified/unknown head — refuses; there is no dev-lane
//     swallowing here.
//   CXER1119 E_STORE_COMPUTATION_RESULT_NOT_CACHEABLE — the aliased
//     result is an err value of a never-cached class: the CXER0270–0279
//     runtime-environment band (budget exhaustion, stack/host limits,
//     cap denial) + the host-tunable CXER0153 par-width cap. These are
//     host/state artifacts, not computation answers. Input-dependent
//     [err]s (e.g. divide-by-zero) remain cacheable — they are
//     deterministic per the theorem.
//
// The daemon's aliases-set wire op routes through the same local arm
// (store_profile_ops.v → store_stdlib_builtin_inner), so admission holds
// with ONE authority on every surface.

// comp_map_get reads one entry of a map-shaped node — either the parsed
// cx.MapNode form or the evaluated `__cx_map__` marker-element form.
fn comp_map_get(n cx.Node, key string) ?cx.Node {
	if n is cx.MapNode {
		for e in n.entries {
			if cx.scalar_value_str_public(e.key_value) == key {
				return e.value
			}
		}
	}
	if n is cx.Element {
		if n.name == '__cx_map__' {
			for it in n.items {
				if it is cx.Element && it.name == key {
					if it.items.len == 1 {
						return it.items[0]
					}
				}
			}
		}
	}
	return none
}

// comp_str reads a string-valued scalar/text node.
fn comp_str(n cx.Node) ?string {
	if n is cx.TextNode {
		return n.value
	}
	if n is cx.ScalarNode {
		if n.data_type == .string_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	return none
}

fn comp_invalid(detail string) cx.Node {
	return mk_err('cx-err:CXER1117', 'E_STORE_COMPUTATION_RECORD_INVALID: ${detail}')
}

fn comp_not_pure(detail string) cx.Node {
	return mk_err('cx-err:CXER1118', 'E_STORE_COMPUTATION_NOT_PURE: ${detail}')
}

// comp_never_cached_code reports whether an err code is in the
// never-cached class (the 0270–0279 runtime-environment band + the
// host-tunable 0153 par-width cap).
fn comp_never_cached_code(errcode string) bool {
	num := errcode.all_after_last('CXER')
	if num.len != 4 {
		return false
	}
	n := num.int()
	return (n >= 270 && n <= 279) || n == 153
}

// store_computation_admission_check validates one bind into the
// computation/ namespace. `alias` starts with 'computation/'; `target`
// is the (already presence-checked) result address. Returns the refusal
// err node, or none when admission holds.
fn store_computation_admission_check(ms &MemStore, alias string, target string) ?cx.Node {
	addr := alias.all_after('computation/')
	if store_addr_shape_err(addr) != none {
		return comp_invalid('alias ${alias} — the segment after computation/ must be the record Tier-1 address; `${addr}` is not an address')
	}
	// The record itself must be stored (structured, not opaque) at <addr>.
	if !store_doc_present(ms, addr) {
		return comp_invalid('no computation record stored at ${addr} — put the record document first (the cache binds records, not bare names)')
	}
	if addr in ms.blob_kind {
		return comp_invalid('${addr} is an opaque document — a computation record is a structured value')
	}
	text := store_doc_text(ms, addr) or {
		return comp_invalid('record at ${addr} unreadable: ${err.msg()}')
	}
	// recompute-and-refuse: the alias name must BE the record's identity.
	rehash := cx.cx_text_hash(text) or {
		return comp_invalid('record at ${addr} does not canonicalize: ${err.msg()}')
	}
	if rehash != addr {
		return comp_invalid('record at ${addr} rehashes to ${rehash}')
	}
	doc := cx.parse(text) or {
		return comp_invalid('record at ${addr} undecodable: ${err.msg()}')
	}
	if doc.elements.len == 0 {
		return comp_invalid('record at ${addr} is empty')
	}
	rec := comp_map_get(doc.elements[0], 'computation') or {
		return comp_invalid('the value at ${addr} is not a [computation] record (no computation key)')
	}
	fnv := comp_map_get(rec, 'fn') or {
		return comp_invalid('record ${addr}: missing fn component')
	}
	for k in ['inputs', 'env', 'caps'] {
		comp_map_get(rec, k) or {
			return comp_invalid('record ${addr}: missing ${k} component')
		}
	}
	code_claim := comp_str(comp_map_get(fnv, 'code') or {
		return comp_invalid('record ${addr}: fn.code missing')
	}) or {
		return comp_invalid('record ${addr}: fn.code must be the computes-as: claim string')
	}
	src_addr := comp_str(comp_map_get(fnv, 'source') or {
		return comp_invalid('record ${addr}: fn.source missing')
	}) or {
		return comp_invalid('record ${addr}: fn.source must be a Tier-1 address string')
	}
	// The fn must resolve HERE, declare pure, and pass the checker (L106).
	// Def text is an OPAQUE document (F1': CX code stores by put-blob under
	// its raw-byte identity) — read through the blob path; accept a
	// structured doc too (a def stored as text through another surface).
	if !store_doc_present(ms, src_addr) {
		return comp_not_pure('fn.source ${src_addr} does not resolve in this store — the def text must be stored (put-blob) before its computations are cacheable')
	}
	src := if src_addr in ms.blob_kind {
		store_get_blob_local(ms, src_addr) or {
			return comp_not_pure('fn.source ${src_addr} unreadable: ${err.msg()}')
		}
	} else {
		store_doc_text(ms, src_addr) or {
			return comp_not_pure('fn.source ${src_addr} unreadable: ${err.msg()}')
		}
	}
	def := cx.parse_def(src) or {
		return comp_not_pure('fn.source ${src_addr} is not a single [?def …]: ${err.msg()}')
	}
	if def.purity != .pure_ {
		return comp_not_pure('fn `${def.name}` is declared impure — only pure computations are cacheable (pure ⇒ deterministic, code.md §6.5.1); wrap the effectful work as inputs (tapes are inputs, not axes)')
	}
	checker := new_purity_checker([&def])
	checker.check_def(&def) or {
		return comp_not_pure('fn `${def.name}` fails the purity check: ${err.msg()}')
	}
	// The Tier-2 claim must recompute from the stored source.
	t2 := cx_code_tier2_hash(src) or {
		return comp_not_pure('fn.source ${src_addr}: Tier-2 identity underivable: ${err.msg()}')
	}
	if code_claim != 'computes-as:${t2}' {
		return comp_invalid('record ${addr}: fn.code `${code_claim}` does not recompute from fn.source (expected computes-as:${t2})')
	}
	// The result must not be a never-cached err class. An opaque (blob)
	// result is ordinary bytes — admissible.
	if target !in ms.blob_kind {
		rtext := store_doc_text(ms, target) or { return none }
		rdoc := cx.parse(rtext) or { return none }
		if rdoc.elements.len > 0 {
			root := rdoc.elements[0]
			if root is cx.Element {
				if root.name == 'err' {
					ecode := sw_attr(root, 'code')
					if comp_never_cached_code(ecode) {
						return mk_err('cx-err:CXER1119', 'E_STORE_COMPUTATION_RESULT_NOT_CACHEABLE: the result at ${target} is `${ecode}` — budget/host-limit/runtime-environment errs are state artifacts, never computation answers (computation_identity.md); input-dependent errs remain cacheable')
					}
				}
			}
		}
	}
	return none
}
