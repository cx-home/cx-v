module code

// stdlib_xap_dist.v — native primitives backing the cx-xap DISTRIBUTION
// surface (spec/02-working/xap_feature_distribution_market.md §6.1, P0):
//
//   pkg-tree / pkg-seal / pkg-sign / pkg-publish / pkg-fetch / pkg-verify /
//   pkg-install / pkg-requires-closure
//
// §9 absence discipline (fixture-checked): this engine introduces NO parallel
// primitive — every store interaction goes through store_stdlib_builtin (the
// guarded public dispatcher: hashing, aliases, content addressing are the
// store's), signing/verification through crypto_stdlib_builtin /
// did_stdlib_builtin / vc_stdlib_builtin, and the feature install gate IS
// xap_compose_builtin (the one W1-W6 gate — no second compose gate).

import cx
import os

const xap_err_pkg_invalid = 'cx-err:CXER4880' // E_XAP_PKG_INVALID
const xap_err_pkg_hash_mismatch = 'cx-err:CXER4881' // E_XAP_PKG_HASH_MISMATCH
const xap_err_pkg_sig_invalid = 'cx-err:CXER4882' // E_XAP_PKG_SIG_INVALID
const xap_err_pkg_vc_invalid = 'cx-err:CXER4883' // E_XAP_PKG_VC_INVALID
const xap_err_pkg_gate_rejected = 'cx-err:CXER4884' // E_XAP_PKG_GATE_REJECTED
const xap_err_pkg_not_found = 'cx-err:CXER4886' // E_XAP_PKG_NOT_FOUND
const xap_err_pkg_alias_immutable = 'cx-err:CXER4887' // E_XAP_PKG_ALIAS_IMMUTABLE

// ── dispatch ─────────────────────────────────────────────────────────────────

fn xap_dist_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'xap-pkg-tree' { return xap_pkg_tree(args) }
		'xap-pkg-seal' { return xap_pkg_seal(args) }
		'xap-pkg-sign' { return xap_pkg_sign(args) }
		'xap-pkg-publish' { return xap_pkg_publish(args) }
		'xap-pkg-fetch' { return xap_pkg_fetch(args) }
		'xap-pkg-verify' { return xap_pkg_verify(args) }
		'xap-pkg-install' { return xap_pkg_install(args) }
		'xap-pkg-requires-closure' { return xap_pkg_requires_closure(args) }
		'xap-pkg-catalog' { return xap_pkg_catalog(args) }
		'xap-license-issue' { return xap_license_issue(args) }
		'xap-license-verify' { return xap_license_verify(args) }
		else { return none }
	}
}

// ── entitlements (§5/§5.1): license = attenuating VC ─────────────────────────
//
// A license is an ORDINARY VC whose claim is a §22.2 [delegation] carrying an
// [entitlement …] rider — no DRM subsystem, no new trust primitive (§9): the
// enable-time check is a PEP-style question ("does a verifying entitlement VC
// cover enabling this package?") answered by vc-verify + coverage. Every §5.1
// commercial model is an attenuation SHAPE of the same VC:
//   perpetual     — no expires; versions= range attenuation
//   subscription  — short-lived expires= + grace-until= (offline holders keep
//                   verifying through term + grace; lapse fails the NEXT
//                   verify point, never a running XAP — N-DIST-1)
//   per-seat      — an org VC (seats=N) delegated into principal-bound seat
//                   VCs (seat=k, parent embedded); the chain IS the count,
//                   each seat offline-verifiable, k>N fails attenuation
//   trial/gratis  — a time-boxed / subset-attenuated VC; not a special case
//   bundle        — [members …] set coverage; install stays per-package

// xap_license_issue (issuer-did, issuer-key, subject-did, terms-map) — builds
// the delegation+entitlement claim and issues the VC through the vc module.
// terms: package= versions= kind= seats= seat= grace-until= expires= bundle=
// members=([member package=… versions=…]…) parent=<org VC for seat issuance>.
fn xap_license_issue(args []cx.Node) ?cx.Node {
	if args.len < 4 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: license-issue expects (issuer-did, issuer-key, subject-did, terms)')
	}
	terms := args[3]
	package := xap_map_get_str(terms, 'package')
	bundle := xap_map_get_str(terms, 'bundle')
	if package == '' && bundle == '' {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: license terms need package= or bundle=')
	}
	mut ent_attrs := []cx.Attribute{}
	if package != '' {
		ent_attrs << xap_attr('package', package)
	}
	if bundle != '' {
		ent_attrs << xap_attr('bundle', bundle)
	}
	for k in ['versions', 'kind', 'seats', 'seat', 'grace-until', 'bundle-version'] {
		v := xap_map_get_str(terms, k)
		if v != '' {
			ent_attrs << xap_attr(k, v)
		}
	}
	mut ent_items := []cx.Node{}
	if ms := xap_map_get_node(terms, 'members') {
		mut mitems := []cx.Node{}
		for m in xap_gc_flatten(ms) {
			if m is cx.Element && m.name == 'member' {
				mitems << cx.Node(m)
			}
		}
		if mitems.len > 0 {
			ent_items << cx.Node(xap_elem('members', [], mitems))
		}
	}
	if pv := xap_map_get_node(terms, 'parent') {
		if p := xd_find_elem(pv, 'vc') {
			ent_items << cx.Node(xap_elem('parent', [], [cx.Node(p)]))
		}
	}
	over := if package != '' { 'pkg:${package}' } else { 'bundle:${bundle}' }
	claim := xap_elem('delegation', [], [
		cx.Node(xap_elem('capabilities', [], [cx.Node(xap_elem('enable', [], []))])),
		cx.Node(xap_elem('over', [], [cx.Node(xap_str(over))])),
		cx.Node(xap_elem('entitlement', ent_attrs, ent_items)),
	])
	mut vc_opts_items := []cx.Node{}
	if ex := xap_map_get_node(terms, 'expires') {
		vc_opts_items << cx.Node(xap_elem('expires', [], [ex]))
	}
	vc_opts := xap_elem('__cx_map__', [], vc_opts_items)
	vc := vc_stdlib_builtin('vc-issue', [args[0], args[1], args[2], cx.Node(claim),
		cx.Node(vc_opts)]) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: license issuance rejected its arguments')
	}
	return vc
}

// xap_license_ent extracts the [entitlement] rider from a license VC.
fn xap_license_ent(vc cx.Element) ?cx.Element {
	cl := xap_gc_child(vc, 'claim') or { return none }
	for it in cl.items {
		if it is cx.Element && it.name == 'delegation' {
			return xap_gc_child(it, 'entitlement')
		}
	}
	return none
}

// xap_license_version_in_range — '' / '*' cover all; 'M.x' covers major M;
// anything else is an exact match.
fn xap_license_version_in_range(version string, range_ string) bool {
	if range_ == '' || range_ == '*' {
		return true
	}
	if range_.ends_with('.x') {
		major := range_.all_before('.x')
		return version.starts_with('${major}.')
	}
	return version == range_
}

// xap_license_covers — package/version coverage against an entitlement rider
// (direct package= or bundle [members] membership).
fn xap_license_covers(ent cx.Element, package string, version string) bool {
	p := xap_elem_attr(ent, 'package')
	if p != '' {
		return p == package
			&& xap_license_version_in_range(version, xap_elem_attr(ent, 'versions'))
	}
	if ms := xap_gc_child(ent, 'members') {
		for m in xap_gc_children(ms, 'member') {
			if xap_elem_attr(m, 'package') == package
				&& xap_license_version_in_range(version, xap_elem_attr(m, 'versions')) {
				return true
			}
		}
	}
	return false
}

// xap_license_vc_check runs vc-verify with the §5.1 grace window: 'valid' is
// ok; 'expired' is still ok while now ≤ the rider's grace-until (offline
// subscription holders); anything else fails.
fn xap_license_vc_check(vc cx.Element, now cx.Node) (string, string) {
	res := vc_stdlib_builtin('vc-verify', [cx.Node(vc), now,
		cx.Node(xap_elem('__cx_map__', [], []))]) or { return '', 'malformed' }
	status := if e := xd_elem_of(res, 'vc-verification') {
		xap_elem_attr(e, 'status')
	} else {
		''
	}
	if status == 'valid' {
		return 'ok', ''
	}
	if status == 'expired' {
		if ent := xap_license_ent(vc) {
			grace := xap_elem_attr(ent, 'grace-until')
			if grace != '' && xd_str_of(now) <= grace {
				return 'grace', ''
			}
		}
	}
	return '', status
}

// xap_license_verify (vc, package, version, opts{now}) — the enable-time
// entitlement check: VC verifies (window + grace), the coverage holds, and a
// seat VC's chain attenuates correctly (seat ≤ parent seats; parent covers).
fn xap_license_verify(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: license-verify expects (vc, package, version, opts?)')
	}
	vc := xd_find_elem(args[0], 'vc') or {
		return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: not a [vc …] credential',
			[], [])
	}
	package := xap_arg_name(args[1])
	version := xap_arg_name(args[2])
	opts := if args.len > 3 { args[3] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	now := if n := xap_map_get_node(opts, 'now') {
		n
	} else {
		time_stdlib_builtin('time-now', []) or {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: no clock for entitlement verification (pass opts.now)')
		}
	}
	status, fail := xap_license_vc_check(vc, now)
	if status == '' {
		return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: entitlement VC status "${fail}"',
			[xap_attr('status', fail)], [])
	}
	ent := xap_license_ent(vc) or {
		return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: credential carries no [entitlement] rider',
			[], [])
	}
	seat := xap_elem_attr(ent, 'seat')
	if seat != '' {
		// per-seat chain: the org VC rides inside; issuer/subject must chain
		// (parent.subject == seat issuer) and the seat index must attenuate.
		pwrap := xap_gc_child(ent, 'parent') or {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: seat VC carries no parent org credential',
				[], [])
		}
		parent := xap_gc_child(pwrap, 'vc') or {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: seat VC parent is not a [vc …]',
				[], [])
		}
		pstatus, pfail := xap_license_vc_check(parent, now)
		if pstatus == '' {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: org credential status "${pfail}"',
				[xap_attr('status', pfail)], [])
		}
		org_subject := if s := xap_gc_child(parent, 'subject') {
			xd_text_content(s)
		} else {
			''
		}
		seat_issuer := if s := xap_gc_child(vc, 'issuer') {
			xd_text_content(s)
		} else {
			''
		}
		if org_subject == '' || org_subject != seat_issuer {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: seat issuer "${seat_issuer}" is not the org credential subject "${org_subject}"',
				[], [])
		}
		pent := xap_license_ent(parent) or {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: org credential carries no [entitlement] rider',
				[], [])
		}
		seats := xap_elem_attr(pent, 'seats').int()
		if seats <= 0 || seat.int() < 1 || seat.int() > seats {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: seat ${seat} exceeds the org entitlement (seats=${seats}) — attenuation violated',
				[xap_attr('seat', seat), xap_attr('seats', '${seats}')], [])
		}
		if !xap_license_covers(pent, package, version) {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: org entitlement does not cover ${package}@${version}',
				[xap_attr('package', package), xap_attr('version', version)], [])
		}
	} else if !xap_license_covers(ent, package, version) {
		// bundle-REFERENCE form (§5.3 "the suite as it grows"): the VC binds a
		// bundle id + version and carries no [members]; the member set is
		// resolved from the CATALOG OBJECT at verify time (opts.store).
		bref := xap_elem_attr(ent, 'bundle')
		bver := xap_elem_attr(ent, 'bundle-version')
		mut covered := false
		if bref != '' && bver != '' {
			if _ := xap_gc_child(ent, 'members') {
			} else if storen := xap_map_get_node(opts, 'store') {
				bdoc_ref := xd_store('store-get-alias', [storen, cx.Node(xap_str('${bref}@${bver}'))])
				bh := xd_str_of(bdoc_ref)
				if bh != '' {
					bdoc := xd_store('store-get-doc', [storen, cx.Node(xap_str(bh))])
					if b := xd_find_elem(bdoc, 'bundle') {
						for mm in xap_gc_children(b, 'member') {
							if xap_elem_attr(mm, 'package') == package
								&& xap_license_version_in_range(version, xap_elem_attr(mm, 'versions')) {
								covered = true
								break
							}
						}
					}
				}
			}
		}
		if !covered {
			return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: entitlement does not cover ${package}@${version}',
				[xap_attr('package', package), xap_attr('version', version)], [])
		}
	}
	return xap_elem('entitlement-verification', [xap_attr('status', status),
		xap_attr('package', package), xap_attr('version', version)], [])
}

// ── pkg-catalog: discovery over any store, local or served (§4.2 stage 2) ────
//
// Discovery composes the store's own surfaces and nothing else: on a store
// that holds aliases (a local/file registry) the alias table is authoritative;
// on a served cx-store:// handle (no alias verbs on the wire) discovery falls
// back to CXPATH QUERY PUSHDOWN — `//publisher` matches every package
// manifest server-side and each result carries its manifest hash. Trust never
// rests on discovery either way: install/verify re-run the full §3 chain on
// the fetched artifact.
fn xap_pkg_catalog(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-catalog expects (store, opts?)')
	}
	store := args[0]
	opts := if args.len > 1 { args[1] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	term := xap_map_get_str(opts, 'term')
	want_name := xap_map_get_str(opts, 'name')
	want_version := xap_map_get_str(opts, 'version')
	// 1. discovery — aliases when the store holds them, query pushdown otherwise.
	mut alias_of := map[string][]string{} // manifest hash → aliases
	mut hashes := []string{}
	aliases := xd_store('store-list-aliases', [store])
	for a in xap_gc_flatten(aliases) {
		if a is cx.Element && a.name == 'alias' {
			h := xap_elem_attr(a, 'hash')
			if h == '' {
				continue
			}
			alias_of[h] << xap_elem_attr(a, 'name')
			if h !in hashes {
				hashes << h
			}
		}
	}
	if hashes.len == 0 {
		q := xd_store('store-query', [store, cx.Node(xap_str('//publisher'))])
		if xd_is_err(q) {
			return q
		}
		for r in xap_gc_flatten(q) {
			if r is cx.Element && r.name == 'result' {
				h := xap_elem_attr(r, 'hash')
				if h != '' && h !in hashes {
					hashes << h
				}
			}
		}
	}
	// 2. project each manifest into a catalog entry (non-manifest docs skip).
	// A [bundle …] doc is a CATALOG OBJECT (§5.3 — a commercial grouping,
	// never a composite feature): it lists as a [bundle] entry with its
	// member set; nothing about it exists at runtime.
	mut keyed := map[string]cx.Node{}
	for h in hashes {
		mdoc := xd_store('store-get-doc', [store, cx.Node(xap_str(h))])
		if b := xd_find_elem(mdoc, 'bundle') {
			bname := xap_elem_attr(b, 'name')
			bversion := xap_elem_attr(b, 'version')
			if want_name != '' && bname != want_name {
				continue
			}
			if want_version != '' && bversion != want_version {
				continue
			}
			if term != '' && !bname.contains(term) {
				continue
			}
			mut bitems := []cx.Node{}
			for mm in xap_gc_children(b, 'member') {
				bitems << cx.Node(mm)
			}
			keyed['${bname}@${bversion}'] = cx.Node(xap_elem('bundle', [
				xap_attr('name', bname), xap_attr('version', bversion),
				xap_attr('manifest', h)], bitems))
			continue
		}
		m := xd_find_elem(mdoc, 'package') or { continue }
		name := xap_elem_attr(m, 'name')
		version := xap_elem_attr(m, 'version')
		if want_name != '' && name != want_name {
			continue
		}
		if want_version != '' && version != want_version {
			continue
		}
		mut surface := []string{}
		mut items := []cx.Node{}
		if g := xap_gc_child(m, 'grammar') {
			mut vitems := []cx.Node{}
			for v in xap_gc_children(g, 'verb') {
				vn := xap_elem_attr(v, 'name')
				surface << vn
				vitems << cx.Node(xap_elem('verb', [xap_attr('name', vn)], []))
			}
			for nn in xap_gc_children(g, 'noun') {
				surface << xap_elem_attr(nn, 'name')
			}
			if vitems.len > 0 {
				items << cx.Node(xap_elem('verbs', [], vitems))
			}
		}
		if ex := xap_gc_child(m, 'exports') {
			mut ditems := []cx.Node{}
			for d in xap_gc_children(ex, 'def') {
				dn := xap_elem_attr(d, 'name')
				surface << dn
				ditems << cx.Node(xap_elem('def', [xap_attr('name', dn)], []))
			}
			if ditems.len > 0 {
				items << cx.Node(xap_elem('exports', [], ditems))
			}
		}
		if term != '' {
			mut hit := name.contains(term)
			for sname in surface {
				if sname.contains(term) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		pub_did := if p := xap_gc_child(m, 'publisher') {
			xap_elem_attr(p, 'did')
		} else {
			''
		}
		keyed['${name}@${version}'] = cx.Node(xap_elem('package', [xap_attr('name', name),
			xap_attr('version', version), xap_attr('kind', xap_pkg_kind_of(m)),
			xap_attr('manifest', h), xap_attr('hash', xap_elem_attr(m, 'hash')),
			xap_attr('publisher', pub_did)], items))
	}
	mut keys := keyed.keys()
	keys.sort()
	mut out := []cx.Node{}
	for k in keys {
		out << keyed[k] or { continue } // k comes from keyed.keys(); absence impossible
	}
	return xap_elem('catalog', [], out)
}

// ── small helpers ────────────────────────────────────────────────────────────

// xd_store reports a store-surface result, mapping a dispatcher miss to a
// clean invalid-arg err (the store module owns every real error value).
fn xd_store(name string, args []cx.Node) cx.Node {
	if r := store_stdlib_builtin(name, args) {
		return r
	}
	return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: store surface "${name}" rejected its arguments')
}

fn xd_is_err(n cx.Node) bool {
	return n is cx.Element && (n as cx.Element).name == 'err'
}

fn xd_str_of(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// xd_elem_of returns the node as an element of the given name, or none.
fn xd_elem_of(n cx.Node, name string) ?cx.Element {
	if n is cx.Element && n.name == name {
		return n
	}
	return none
}

// xd_find_elem finds an element of the given name in the node OR any
// sequence/array packing around it — so a path-projected value (e.g.
// `$doc//package`) is as good as the element itself at every pkg-* seam.
fn xd_find_elem(n cx.Node, name string) ?cx.Element {
	for it in xap_gc_flatten(n) {
		if it is cx.Element && it.name == name {
			return it
		}
	}
	return none
}

// xd_text_content joins the text/scalar items of an element (an [entry …]'s
// payload, a manifest text field).
fn xd_text_content(e cx.Element) string {
	mut out := ''
	for it in e.items {
		out += xd_str_of(it)
	}
	return out
}

// xd_with_attr returns the element with attr `name` set to `val` (replacing).
fn xd_with_attr(e cx.Element, name string, val string) cx.Element {
	mut attrs := []cx.Attribute{}
	for a in e.attrs {
		if a.name != name {
			attrs << a
		}
	}
	attrs << xap_attr(name, val)
	return cx.Element{
		name:  e.name
		attrs: attrs
		items: e.items
	}
}

// xd_without_child returns the element with all children named `name` removed.
fn xd_without_child(e cx.Element, name string) cx.Element {
	mut items := []cx.Node{}
	for it in e.items {
		if it is cx.Element && it.name == name {
			continue
		}
		items << it
	}
	return cx.Element{
		name:  e.name
		attrs: e.attrs
		items: items
	}
}

// ── pkg-tree (pure): entries → the canonical content document ────────────────

// xap_pkg_tree builds the canonical [package-tree …]: entries sorted by path,
// so the same entry SET yields byte-identical canonical form — its store hash
// IS the package's Tier-1 hash. Path discipline is fail-closed: empty,
// absolute, '..'-traversing, or duplicate paths are CXER4880.
fn xap_pkg_tree(args []cx.Node) ?cx.Node {
	mut entries := []cx.Element{}
	for a in args {
		for n in xap_gc_flatten(a) {
			e := xd_elem_of(n, 'entry') or {
				return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-tree takes [entry path=… CONTENT] elements, got: ${render_canonical(n)}',
					[], [])
			}
			entries << e
		}
	}
	mut seen := map[string]bool{}
	for e in entries {
		p := xap_elem_attr(e, 'path')
		if p == '' {
			return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: entry with empty path', [],
				[])
		}
		if p.starts_with('/') || p.split('/').contains('..') {
			return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: entry path "${p}" must be relative and traversal-free',
				[xap_attr('path', p)], [])
		}
		if seen[p] {
			return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: duplicate entry path "${p}"',
				[xap_attr('path', p)], [])
		}
		seen[p] = true
	}
	entries.sort_with_compare(fn (a &cx.Element, b &cx.Element) int {
		pa := xap_elem_attr(*a, 'path')
		pb := xap_elem_attr(*b, 'path')
		if pa < pb {
			return -1
		}
		if pa > pb {
			return 1
		}
		return 0
	})
	mut items := []cx.Node{}
	for e in entries {
		items << cx.Node(e)
	}
	return xap_elem('package-tree', [], items)
}

// ── manifest validation (kind-aware, §2) ─────────────────────────────────────

// xap_pkg_kind_of reads the manifest kind, defaulting to feature (§1.1).
fn xap_pkg_kind_of(m cx.Element) string {
	k := xap_elem_attr(m, 'kind')
	if k == '' {
		return 'feature'
	}
	return k
}

// xap_pkg_validate_draft is the kind-aware §2 structural check shared by seal
// (draft: hash/signature not yet present) and publish (sealed+signed form).
fn xap_pkg_validate_draft(m cx.Element) ?cx.Node {
	if xap_elem_attr(m, 'name') == '' || xap_elem_attr(m, 'version') == '' {
		return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: manifest requires name= and version=',
			[], [])
	}
	kind := xap_pkg_kind_of(m)
	if kind !in ['feature', 'library', 'client'] {
		return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: kind "${kind}" is not feature|library|client',
			[xap_attr('kind', kind)], [])
	}
	pub_el := xap_gc_child(m, 'publisher') or {
		return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: manifest requires a [publisher did=…]',
			[], [])
	}
	if xap_elem_attr(pub_el, 'did') == '' {
		return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: publisher requires did=', [],
			[])
	}
	if kind == 'library' {
		if _ := xap_gc_child(m, 'needs') {
			return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: a kind=library package MUST NOT declare [needs] — libraries hold no authority (N-DIST-2)',
				[], [])
		}
		if _ := xap_gc_child(m, 'exports') {
		} else {
			return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: a kind=library package requires an [exports] listing',
				[], [])
		}
	}
	return none // valid — no error value
}

// ── pkg-seal: store the tree, pin its hash, store the manifest beside ────────

fn xap_pkg_seal(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-seal expects (store, tree, draft)')
	}
	tree := xd_find_elem(args[1], 'package-tree') or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-seal expects a [package-tree …] (see pkg-tree)')
	}
	draft := xd_find_elem(args[2], 'package') or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-seal expects a [package …] manifest draft')
	}
	if verr := xap_pkg_validate_draft(draft) {
		return verr
	}
	tput := xd_store('store-put-doc', [args[0], cx.Node(tree)])
	if xd_is_err(tput) {
		return tput
	}
	tier1 := xd_str_of(tput)
	sealed := xd_with_attr(draft, 'hash', tier1)
	mput := xd_store('store-put-doc', [args[0], cx.Node(sealed)])
	if xd_is_err(mput) {
		return mput
	}
	return xap_elem('sealed', [xap_attr('hash', tier1), xap_attr('manifest', xd_str_of(mput))],
		[])
}

// ── pkg-sign (pure): detached ed25519 over the Tier-1 hash string ────────────

fn xap_pkg_sign(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-sign expects (manifest, private-key)')
	}
	m := xd_find_elem(args[0], 'package') or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-sign expects a sealed [package …] manifest')
	}
	tier1 := xap_elem_attr(m, 'hash')
	if tier1 == '' {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-sign requires a SEALED manifest (hash= present; seal first)')
	}
	sig := crypto_stdlib_builtin('crypto-ed25519-sign', [args[1], cx.Node(xap_str(tier1))]) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: signing rejected its arguments')
	}
	if xd_is_err(sig) {
		return sig
	}
	hexv := bytes_stdlib_builtin('bytes-to-hex', [sig]) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: signature encoding failed')
	}
	unsigned := xd_without_child(m, 'signature')
	mut items := unsigned.items.clone()
	items << xap_elem('signature', [xap_attr('alg', 'ed25519'), xap_attr('key', 'key-1'),
		xap_attr('value', xd_str_of(hexv))], [])
	return cx.Element{
		name:  unsigned.name
		attrs: unsigned.attrs
		items: items
	}
}

// ── pkg-publish: alias name@version → manifest hash (immutably) ─────────────

fn xap_pkg_publish(args []cx.Node) ?cx.Node {
	if args.len < 4 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-publish expects (store, name, version, manifest-hash)')
	}
	name := xap_arg_name(args[1])
	version := xap_arg_name(args[2])
	mhash := xap_arg_name(args[3])
	if name == '' || version == '' || mhash == '' {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: publish requires name, version, manifest-hash')
	}
	mdoc := xd_store('store-get-doc', [args[0], cx.Node(xap_str(mhash))])
	if xd_is_err(mdoc) {
		return mk_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: no manifest object ${mhash} in the store')
	}
	m := xd_elem_of(mdoc, 'package') or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: object ${mhash} is not a [package …] manifest')
	}
	if _ := xap_gc_child(m, 'signature') {
	} else {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: publish requires a SIGNED manifest — sign from day one (§4.1)')
	}
	alias := '${name}@${version}'
	existing := xd_store('store-get-alias', [args[0], cx.Node(xap_str(alias))])
	prev := xd_str_of(existing)
	if prev != '' && prev != mhash {
		return xap_gc_err(xap_err_pkg_alias_immutable, 'E_XAP_PKG_ALIAS_IMMUTABLE: released alias "${alias}" already names ${prev} — a new artifact is a new version',
			[xap_attr('alias', alias)], [])
	}
	if prev != mhash {
		aset := xd_store('store-set-alias', [args[0], cx.Node(xap_str(alias)), cx.Node(xap_str(mhash))])
		if xd_is_err(aset) {
			return aset
		}
	}
	return xap_elem('published', [xap_attr('alias', alias), xap_attr('manifest', mhash)],
		[])
}

// ── pkg-fetch: hash or name@version → the manifest document ─────────────────

fn xap_pkg_fetch(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-fetch expects (store, ref)')
	}
	ref := xap_arg_name(args[1])
	mut mhash := ref
	if ref.contains('@') {
		got := xd_store('store-get-alias', [args[0], cx.Node(xap_str(ref))])
		mhash = xd_str_of(got)
		if mhash == '' {
			return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: no published alias "${ref}"',
				[xap_attr('ref', ref)], [])
		}
	}
	mdoc := xd_store('store-get-doc', [args[0], cx.Node(xap_str(mhash))])
	if xd_is_err(mdoc) {
		return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: no manifest object ${mhash}',
			[xap_attr('ref', ref)], [])
	}
	if _ := xd_elem_of(mdoc, 'package') {
		return mdoc
	}
	return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: object ${mhash} is not a [package …] manifest')
}

// ── pkg-verify: the §3 fail-closed chain ─────────────────────────────────────

// xap_pkg_verify_manifest runs stages 1-3 for an already-fetched manifest.
fn xap_pkg_verify_manifest(store cx.Node, m cx.Element, opts cx.Node) ?cx.Node {
	// (1) the pinned content loads and re-hashes to hash= — content addressing
	// is the store's own; a present-but-divergent object is CXER4881.
	tier1 := xap_elem_attr(m, 'hash')
	if tier1 == '' {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: manifest is unsealed (no hash=)')
	}
	tdoc := xd_store('store-get-doc', [store, cx.Node(xap_str(tier1))])
	if xd_is_err(tdoc) {
		return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: pinned content ${tier1} absent from the store',
			[xap_attr('hash', tier1)], [])
	}
	rehash := store_doc_hash(tdoc) or {
		return mk_err(xap_err_pkg_hash_mismatch, 'E_XAP_PKG_HASH_MISMATCH: content re-hash failed: ${err.msg()}')
	}
	if rehash != tier1 {
		return xap_gc_err(xap_err_pkg_hash_mismatch, 'E_XAP_PKG_HASH_MISMATCH: content re-hashes to ${rehash}, manifest pins ${tier1}',
			[xap_attr('expected', tier1), xap_attr('actual', rehash)], [])
	}
	// (2) the detached signature verifies against the publisher DID.
	pub_el := xap_gc_child(m, 'publisher') or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: manifest has no [publisher]')
	}
	did := xap_elem_attr(pub_el, 'did')
	sig_el := xap_gc_child(m, 'signature') or {
		return xap_gc_err(xap_err_pkg_sig_invalid, 'E_XAP_PKG_SIG_INVALID: manifest is unsigned',
			[xap_attr('publisher', did)], [])
	}
	if xap_elem_attr(sig_el, 'alg') != 'ed25519' {
		return xap_gc_err(xap_err_pkg_sig_invalid, 'E_XAP_PKG_SIG_INVALID: unsupported alg "${xap_elem_attr(sig_el,
			'alg')}"', [], [])
	}
	sig_bytes := bytes_stdlib_builtin('bytes-from-hex', [cx.Node(xap_str(xap_elem_attr(sig_el,
		'value')))]) or {
		return xap_gc_err(xap_err_pkg_sig_invalid, 'E_XAP_PKG_SIG_INVALID: signature value is not hex',
			[], [])
	}
	ok := did_stdlib_builtin('did-verify-control', [cx.Node(xap_str(did)), cx.Node(xap_str(tier1)),
		sig_bytes]) or {
		return xap_gc_err(xap_err_pkg_sig_invalid, 'E_XAP_PKG_SIG_INVALID: publisher DID "${did}" is not verifiable',
			[xap_attr('publisher', did)], [])
	}
	if xd_str_of(ok) != 'true' {
		return xap_gc_err(xap_err_pkg_sig_invalid, 'E_XAP_PKG_SIG_INVALID: signature does not verify against publisher DID "${did}"',
			[xap_attr('publisher', did)], [])
	}
	// (3) every supplied attestation VC verifies.
	if atts := xap_map_get_node(opts, 'attestations') {
		now := if n := xap_map_get_node(opts, 'now') {
			n
		} else {
			time_stdlib_builtin('time-now', []) or {
				return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: no clock for VC verification (pass opts.now)')
			}
		}
		for vcn in xap_gc_flatten(atts) {
			vres := vc_stdlib_builtin('vc-verify', [vcn, now, cx.Node(xap_elem('__cx_map__',
				[], []))]) or {
				return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: attestation is not a verifiable VC',
					[], [])
			}
			if xd_is_err(vres) {
				return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: attestation verification errored',
					[], [])
			}
			status := if ve := xd_elem_of(vres, 'vc-verification') {
				xap_elem_attr(ve, 'status')
			} else {
				''
			}
			if status != 'valid' && status != 'ok' {
				return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: attestation status "${status}"',
					[xap_attr('status', status)], [])
			}
		}
	}
	// (3.5) entitlement (§5, P2): a supplied license VC must verify AND cover
	// this package@version (grace-aware, seat-chain-aware); the consuming
	// XAP's policy may REQUIRE one (opts.require-entitlement) — price is a
	// market property, so the same artifact installs gratis where no policy
	// demands a VC (§5.1).
	mut has_ent := false
	if entn := xap_map_get_node(opts, 'entitlement') {
		has_ent = true
		lv := xap_license_verify([entn, cx.Node(xap_str(xap_elem_attr(m, 'name'))),
			cx.Node(xap_str(xap_elem_attr(m, 'version'))), opts]) or {
			return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: entitlement verification errored')
		}
		if xd_is_err(lv) {
			return lv
		}
	}
	if !has_ent && xap_map_get_str(opts, 'require-entitlement') == 'true' {
		return xap_gc_err(xap_err_pkg_vc_invalid, 'E_XAP_PKG_VC_INVALID: this install policy requires an entitlement VC and none was supplied',
			[xap_attr('name', xap_elem_attr(m, 'name'))], [])
	}
	return xap_elem('package-verification', [xap_attr('status', 'ok'),
		xap_attr('name', xap_elem_attr(m, 'name')), xap_attr('version', xap_elem_attr(m, 'version')),
		xap_attr('kind', xap_pkg_kind_of(m)), xap_attr('hash', tier1), xap_attr('publisher', did)],
		[])
}

fn xap_pkg_verify(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-verify expects (store, ref, opts?)')
	}
	fetched := xap_pkg_fetch(args[..2]) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: fetch failed')
	}
	if xd_is_err(fetched) {
		return fetched
	}
	m := fetched as cx.Element
	opts := if args.len > 2 { args[2] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	return xap_pkg_verify_manifest(args[0], m, opts)
}

// ── code-plane loading (§6.2): pkg: module references ───────────────────────
//
// xap_pkg_module_source resolves a `pkg:<name>@<version>[#<manifest-hash>]`
// [?lib] reference to verified module source text (the module loader's
// .pkg_url arm). The registry is bound by CX_REGISTRY (a store URL — the
// same binding the publish tooling uses); the store opens READ-ONLY (the
// `read` capability, like every file-path [?lib]). The bare form resolves
// name@version through the registry's alias table; the pinned #hash form
// fetches the manifest BY HASH — the alias table is never consulted, so a
// re-pointed or hostile registry cannot substitute code — and requires the
// manifest's name/version to match the reference (CXER4888). The full §3
// verify chain runs on EVERY load; the source is the tree's <name>.cx code
// entry (§1 layout). Errors carry the distribution-spec codes in-message so
// the loader's failure names the exact refusal lane.
fn xap_pkg_module_source(ref string) !string {
	spec := ref.all_after('pkg:')
	frag := if spec.contains('#') { spec.all_after_last('#') } else { '' }
	nv := if frag != '' { spec.all_before_last('#') } else { spec }
	if !nv.contains('@') || nv.all_before('@') == '' || nv.all_after('@') == '' {
		return error('MODULE_PKG_REF_MALFORMED: `${ref}` (want pkg:<name>@<version>[#<manifest-hash>]) (cx-err:CXER4880)')
	}
	name := nv.all_before('@')
	version := nv.all_after('@')
	reg_url := os.getenv('CX_REGISTRY')
	if reg_url == '' {
		return error('MODULE_PKG_REGISTRY_UNBOUND: CX_REGISTRY is unset — no registry bound for `${ref}` (cx-err:CXER4889)')
	}
	ro := xap_elem('opts', [xap_attr('read-only', 'true')], [])
	sh := xd_store('store-open-opts', [cx.Node(xap_str(reg_url)), cx.Node(ro)])
	if xd_is_err(sh) {
		return error('MODULE_PKG_REGISTRY_OPEN_FAILED: ${xd_err_message(sh)} (registry=${reg_url})')
	}
	mut m := cx.Element{}
	if frag != '' {
		mdoc := xd_store('store-get-doc', [sh, cx.Node(xap_str(frag))])
		me := xd_elem_of(mdoc, 'package') or {
			return error('MODULE_PKG_PIN_NOT_FOUND: no package manifest at pinned hash ${frag} for `${ref}` (cx-err:CXER4886)')
		}
		if xap_elem_attr(me, 'name') != name || xap_elem_attr(me, 'version') != version {
			return error('MODULE_PKG_PIN_MISMATCH: pinned manifest is ${xap_elem_attr(me, 'name')}@${xap_elem_attr(me, 'version')}, reference says ${name}@${version} (cx-err:CXER4888)')
		}
		m = me
	} else {
		fetched := xap_pkg_fetch([sh, cx.Node(xap_str(nv))]) or {
			return error('MODULE_PKG_NOT_FOUND: fetch of `${nv}` failed (cx-err:CXER4886)')
		}
		if xd_is_err(fetched) {
			return error('MODULE_PKG_NOT_FOUND: ${xd_err_message(fetched)} (cx-err:CXER4886)')
		}
		m = fetched as cx.Element
	}
	empty_opts := xap_elem('__cx_map__', [], [])
	verified := xap_pkg_verify_manifest(sh, m, cx.Node(empty_opts)) or {
		return error('MODULE_PKG_VERIFY_FAILED: verify chain errored for `${ref}`')
	}
	if xd_is_err(verified) {
		return error('MODULE_PKG_VERIFY_FAILED: ${xd_err_message(verified)}')
	}
	tree := xap_pkg_tree_of(sh, m) or {
		return error('MODULE_PKG_TREE_ABSENT: pinned content tree absent for `${ref}` (cx-err:CXER4886)')
	}
	src := xap_pkg_entry_exact_text(tree, '${name}.cx')
	if src == '' {
		return error('MODULE_PKG_NO_CODE_ENTRY: package `${nv}` has no ${name}.cx code entry (cx-err:CXER4880)')
	}
	return src
}

// xap_pkg_entry_exact_text: the text of the entry at exactly `path` ('' when absent).
fn xap_pkg_entry_exact_text(tree cx.Element, path string) string {
	for it in tree.items {
		if it is cx.Element && it.name == 'entry' && xap_elem_attr(it, 'path') == path {
			return xd_text_content(it)
		}
	}
	return ''
}

// xd_err_message: the message= of an err value ('' when not an err).
fn xd_err_message(n cx.Node) string {
	if n is cx.Element {
		if n.name == 'err' {
			return xap_elem_attr(n, 'message')
		}
	}
	return ''
}

// ── tree readers shared by the install gates ────────────────────────────────

// xap_pkg_tree_of loads the manifest's pinned content tree.
fn xap_pkg_tree_of(store cx.Node, m cx.Element) ?cx.Element {
	tdoc := xd_store('store-get-doc', [store, cx.Node(xap_str(xap_elem_attr(m, 'hash')))])
	return xd_elem_of(tdoc, 'package-tree')
}

// xap_pkg_entry_text returns the text content of the first tree entry whose
// path ends with `suffix` ('' when none).
fn xap_pkg_entry_text(tree cx.Element, suffix string) string {
	for it in tree.items {
		if it is cx.Element && it.name == 'entry' && xap_elem_attr(it, 'path').ends_with(suffix) {
			return xd_text_content(it)
		}
	}
	return ''
}

// xap_pkg_has_entry: true iff the tree carries an entry at exactly `path`.
fn xap_pkg_has_entry(tree cx.Element, path string) bool {
	for it in tree.items {
		if it is cx.Element && it.name == 'entry' && xap_elem_attr(it, 'path') == path {
			return true
		}
	}
	return false
}

// xap_pkg_feature_doc extracts and parses the packaged feature spec
// (<name>.feature.cxd) into its [feature …] grammar document.
fn xap_pkg_feature_doc(tree cx.Element) ?cx.Element {
	src := xap_pkg_entry_text(tree, '.feature.cxd')
	if src == '' {
		return none
	}
	doc := cx.parse(src) or { return none }
	for n in doc.elements {
		if n is cx.Element && n.name == 'feature' {
			return n
		}
	}
	return none
}

// ── per-kind install gates (§1.1) ────────────────────────────────────────────

// xap_pkg_gate_feature: THE compose gate — W1-W6 over enabled ∪ {candidate}
// via xap_compose_builtin (no second gate, §9 absence 6). `xap` is the
// deployment document; each enabled [feature] pin's tree contributes its
// packaged feature spec.
fn xap_pkg_gate_feature(xap cx.Element, store cx.Node, m cx.Element) ?cx.Node {
	tree := xap_pkg_tree_of(store, m) or {
		return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: pinned content tree absent',
			[], [])
	}
	cand := xap_pkg_feature_doc(tree) or {
		return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: a kind=feature package must carry its *.feature.cxd spec layer',
			[], [])
	}
	mut feats := []cx.Node{}
	if fl := xap_gc_child(xap, 'features') {
		for p in xap_gc_children(fl, 'feature') {
			ph := xap_elem_attr(p, 'hash')
			if ph == '' {
				continue
			}
			ptdoc := xd_store('store-get-doc', [store, cx.Node(xap_str(ph))])
			ptree := xd_elem_of(ptdoc, 'package-tree') or { continue }
			pf := xap_pkg_feature_doc(ptree) or { continue }
			feats << cx.Node(pf)
		}
	}
	feats << cx.Node(cand)
	composed := xap_compose_builtin(feats) or {
		return mk_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: compose gate errored')
	}
	if xd_is_err(composed) {
		ce := composed as cx.Element
		// carry the gate's own [conflict …] values through (behavior, §6.1)
		mut conflicts := []cx.Node{}
		for it in ce.items {
			conflicts << it
		}
		return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: the W1-W6 compose gate rejected the candidate',
			[xap_attr('stage', 'compose-gate')], conflicts)
	}
	// §1.2 runtime contract: a code entry (<name>.cx) and an [exports] listing
	// imply each other, and a declared surface must exist in the code — the
	// same module-surface check a library meets (shared helper, no second
	// scanner). Spec-only features (no code entry, no exports) pass untouched.
	has_code := xap_pkg_has_entry(tree, '${xap_elem_attr(m, 'name')}.cx')
	if ex := xap_gc_child(m, 'exports') {
		if !has_code {
			return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: the manifest declares [exports] but the tree has no ${xap_elem_attr(m, 'name')}.cx code entry (§1.2)',
				[xap_attr('stage', 'exports')], [])
		}
		if d := xap_pkg_exports_check(tree, ex) {
			return d
		}
	} else {
		if has_code {
			return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: the tree carries a code entry but the manifest declares no [exports] (§1.2)',
				[xap_attr('stage', 'exports')], [])
		}
	}
	return none // gate passed
}

// xap_pkg_gate_library: the module-surface check — every [exports] def is
// present among the tree's top-level [?def]s; a declared Tier-2 identity=
// must match the code's (computed by the store's own put-def, never a
// parallel hasher).
fn xap_pkg_gate_library(store cx.Node, m cx.Element) ?cx.Node {
	tree := xap_pkg_tree_of(store, m) or {
		return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: pinned content tree absent',
			[], [])
	}
	exports := xap_gc_child(m, 'exports') or {
		return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: library manifest has no [exports]',
			[], [])
	}
	return xap_pkg_exports_check(tree, exports)
}

// xap_pkg_exports_check: the module-surface check shared by the library gate
// and the §1.2 feature runtime-contract gate — every [exports] def is present
// among the tree's top-level [?def]s (via the module loader's OWN pass-1
// declaration scanner, never a parallel one; full load_module is wrong here:
// it resolves [?lib] imports the gate neither needs nor can satisfy), and a
// declared Tier-2 identity= must match the code's (computed by the store's
// own put-def, never a parallel hasher).
fn xap_pkg_exports_check(tree cx.Element, exports cx.Element) ?cx.Node {
	mut def_src := map[string]string{}
	for it in tree.items {
		if it is cx.Element && it.name == 'entry' && xap_elem_attr(it, 'path').ends_with('.cx') {
			src := xd_text_content(it)
			directives := module_loader_scan_directives(src) or { continue }
			for d in directives {
				if d.kind == .def {
					n := cx.parse_def(d.text) or { continue }
					def_src[n.name] = n.source or { d.text }
				}
			}
		}
	}
	for ex in xap_gc_children(exports, 'def') {
		dn := xap_elem_attr(ex, 'name')
		local := if dn.contains('/') { dn.all_after_last('/') } else { dn }
		if local !in def_src {
			return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: exported def "${dn}" is absent from the packaged code',
				[xap_attr('stage', 'exports'), xap_attr('def', dn)], [])
		}
		want := xap_elem_attr(ex, 'identity')
		if want != '' {
			scratch := xd_store('store-open', [cx.Node(xap_str('mem://'))])
			got := xd_store('store-put-def', [scratch, cx.Node(xap_str(def_src[local]))])
			if xd_str_of(got) != want {
				return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: def "${dn}" Tier-2 identity ${xd_str_of(got)} does not match the declared ${want}',
					[xap_attr('stage', 'exports'), xap_attr('def', dn)], [])
			}
		}
	}
	return none
}

// xap_pkg_gate_client: the packaged client spec layer must be present and
// structurally a [client …] document.
fn xap_pkg_gate_client(store cx.Node, m cx.Element) ?cx.Node {
	tree := xap_pkg_tree_of(store, m) or {
		return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: pinned content tree absent',
			[], [])
	}
	src := xap_pkg_entry_text(tree, 'client.cxd')
	if src == '' {
		return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: a kind=client package must carry client.cxd',
			[xap_attr('stage', 'client-spec')], [])
	}
	doc := cx.parse(src) or {
		return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: client.cxd does not parse: ${err.msg()}',
			[xap_attr('stage', 'client-spec')], [])
	}
	for n in doc.elements {
		if n is cx.Element && n.name == 'client' {
			return none
		}
	}
	return xap_gc_err(xap_err_pkg_gate_rejected, 'E_XAP_PKG_GATE_REJECTED: client.cxd carries no [client …] document',
		[xap_attr('stage', 'client-spec')], [])
}

// ── pkg-install: fetch → verify → gate → consent=grants → enable ─────────────

fn xap_pkg_install(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-install expects (xap, store, ref, opts?)')
	}
	// accept the [xap …] doc directly, a previous [installed …] report
	// (chaining: the report carries the updated doc), or a wrapper around
	// either (variadic/sequence packing).
	mut xap := cx.Element{}
	mut got_xap := false
	for n in xap_gc_flatten(args[0]) {
		if n is cx.Element {
			if n.name == 'xap' {
				xap = n
				got_xap = true
				break
			}
			if n.name == 'installed' {
				for it in n.items {
					if it is cx.Element && it.name == 'xap' {
						xap = it
						got_xap = true
						break
					}
				}
				if got_xap {
					break
				}
			}
		}
	}
	if !got_xap {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-install expects the [xap …] deployment document (or a previous [installed …] report) first')
	}
	store := args[1]
	opts := if args.len > 3 { args[3] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	fetched := xap_pkg_fetch([store, args[2]]) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: fetch failed')
	}
	if xd_is_err(fetched) {
		return fetched
	}
	m := fetched as cx.Element
	ver := xap_pkg_verify_manifest(store, m, opts) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: verification errored')
	}
	if xd_is_err(ver) {
		return ver
	}
	kind := xap_pkg_kind_of(m)
	// per-kind gate — a library never meets the compose gate; a feature never
	// skips it (§1.1).
	gate_err := match kind {
		'feature' { xap_pkg_gate_feature(xap, store, m) }
		'library' { xap_pkg_gate_library(store, m) }
		else { xap_pkg_gate_client(store, m) }
	}
	if ge := gate_err {
		return ge
	}
	// consent = grants (§6.6): issue EXACTLY the needs set into the runtime's
	// authority store; enabling IS granting. Libraries have no needs and
	// receive nothing (N-DIST-2).
	mut granted := []cx.Node{}
	if kind == 'feature' {
		if needs := xap_gc_child(m, 'needs') {
			mut caps := []string{}
			for r in xap_gc_children(needs, 'reads') {
				caps << xap_elem_attr(r, 'noun')
			}
			for s in xap_gc_children(needs, 'subscribes') {
				caps << xap_elem_attr(s, 'channel')
			}
			for g in xap_gc_children(needs, 'gateways') {
				caps << xap_elem_attr(g, 'kind')
			}
			caps = caps.filter(it != '')
			if caps.len > 0 {
				if rtn := xap_map_get_node(opts, 'runtime') {
					mut rt := xap_runtime_of(rtn) or {
						return mk_err('cx-err:CXER4859', 'E_XAP_RUNTIME_CLOSED: unknown runtime handle in opts.runtime')
					}
					grantee := if g := xap_map_get_node(opts, 'grantee') {
						xap_arg_name(g)
					} else {
						''
					}
					if grantee == '' {
						return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: consent requires opts.grantee alongside opts.runtime')
					}
					id := 'd-needs-${xap_elem_attr(m, 'name')}@${xap_elem_attr(m, 'version')}'
					deleg := xap_elem('delegation', [xap_attr('id', id), xap_attr('from', 'principal:'),
						xap_attr('to', grantee)], [])
					real := &AuthzDelegation{
						id:           id
						tenant:       rt.tenant
						from_kind:    'principal'
						from_id:      'principal:'
						to_kind:      xap_actor_kind(grantee)
						to_id:        grantee
						capabilities: caps
						over:         ''
						attenuates:   ''
						revocable:    true
						assurance:    't0'
						value:        deleg
					}
					if rt.authz != unsafe { nil } {
						rt.authz.delegations << real
					}
					rt.dials << deleg
				}
				for c in caps {
					granted << cx.Node(xap_elem('grant', [xap_attr('capability', c)], []))
				}
			}
		}
	}
	// enable: pin into the deployment document + resolve the requires closure.
	closure := xap_pkg_requires_closure([store, cx.Node(m)]) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: requires resolution errored')
	}
	if xd_is_err(closure) {
		return closure
	}
	mhash := store_doc_hash(cx.Node(m)) or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: manifest re-hash failed')
	}
	section := match kind {
		'feature' { 'features' }
		'library' { 'libraries' }
		else { 'clients' }
	}
	entry_name := match kind {
		'feature' { 'feature' }
		'library' { 'library' }
		else { 'client' }
	}
	mut pin_items := []cx.Node{}
	if closure is cx.Element {
		for it in closure.items {
			pin_items << it
		}
	}
	pin_attrs := [xap_attr('version', xap_elem_attr(m, 'version')),
		xap_attr('manifest', mhash), xap_attr('hash', xap_elem_attr(m, 'hash'))]
	pin_children := if pin_items.len > 0 {
		[cx.Node(xap_elem('requires', [], pin_items))]
	} else {
		[]cx.Node{}
	}
	mut pin_all_attrs := [xap_attr('name', xap_elem_attr(m, 'name'))]
	pin_all_attrs << pin_attrs
	pin := xap_elem(entry_name, pin_all_attrs, pin_children)
	// rebuild the xap doc with the pin MERGED into (or appended to / creating)
	// its section — one entry per name: an existing same-name row (a stage-0
	// path ref) is updated in place, its foreign attrs (package=, status=)
	// preserved and its prior pin attrs + [requires] closure replaced
	// (fixture xap-dist-045; a duplicated name would leave the deployment
	// doc ill-formed).
	pkg_name := xap_elem_attr(m, 'name')
	mut new_items := []cx.Node{}
	mut placed := false
	for it in xap.items {
		if it is cx.Element && it.name == section {
			mut sec_items := []cx.Node{}
			mut merged := false
			for se in it.items {
				if !merged && se is cx.Element && se.name == entry_name
					&& xap_elem_attr(se, 'name') == pkg_name {
					mut kept_attrs := []cx.Attribute{}
					for a in se.attrs {
						if a.name !in ['version', 'manifest', 'hash'] {
							kept_attrs << a
						}
					}
					kept_attrs << pin_attrs
					mut kept_items := []cx.Node{}
					for ch in se.items {
						if ch is cx.Element && ch.name == 'requires' {
							continue
						}
						kept_items << ch
					}
					kept_items << pin_children
					sec_items << cx.Node(cx.Element{
						name:  se.name
						attrs: kept_attrs
						items: kept_items
					})
					merged = true
				} else {
					sec_items << se
				}
			}
			if !merged {
				sec_items << cx.Node(pin)
			}
			new_items << cx.Node(cx.Element{
				name:  it.name
				attrs: it.attrs
				items: sec_items
			})
			placed = true
		} else {
			new_items << it
		}
	}
	if !placed {
		new_items << cx.Node(xap_elem(section, [], [cx.Node(pin)]))
	}
	updated := cx.Element{
		name:  xap.name
		attrs: xap.attrs
		items: new_items
	}
	return xap_elem('installed', [xap_attr('name', xap_elem_attr(m, 'name')),
		xap_attr('version', xap_elem_attr(m, 'version')), xap_attr('kind', kind),
		xap_attr('hash', xap_elem_attr(m, 'hash')), xap_attr('manifest', mhash)], [
		cx.Node(xap_elem('granted', [], granted)),
		cx.Node(updated),
	])
}

// ── pkg-requires-closure: the code plane, hash-resolved (§1.1/§7) ────────────

// xap_pkg_semver_key builds a sortable key from a semver-ish version string
// (numeric segments zero-padded; good enough for the P0 "latest in store").
fn xap_pkg_semver_key(v string) string {
	mut out := []string{}
	for seg in v.split('.') {
		mut digits := ''
		for ch in seg {
			if ch >= `0` && ch <= `9` {
				digits += ch.ascii_str()
			} else {
				break
			}
		}
		if digits == '' {
			digits = '0'
		}
		out << digits
	}
	mut padded := []string{}
	for d in out {
		mut p := d
		for p.len < 10 {
			p = '0' + p
		}
		padded << p
	}
	return padded.join('.')
}

// xap_pkg_resolve_version picks a published manifest hash for `library` from
// the store's aliases: an exact `versions=` pin resolves that alias; otherwise
// the highest semver-keyed published version wins.
fn xap_pkg_resolve_version(store cx.Node, library string, versions string) (string, string) {
	if versions != '' && !versions.contains('*') {
		got := xd_store('store-get-alias', [store, cx.Node(xap_str('${library}@${versions}'))])
		return versions, xd_str_of(got)
	}
	aliases := xd_store('store-list-aliases', [store])
	mut best_v := ''
	mut best_h := ''
	mut best_key := ''
	items := xap_gc_flatten(aliases)
	for a in items {
		if a is cx.Element && a.name == 'alias' {
			an := xap_elem_attr(a, 'name')
			if an.starts_with('${library}@') {
				v := an.all_after('@')
				k := xap_pkg_semver_key(v)
				if best_key == '' || k > best_key {
					best_key = k
					best_v = v
					best_h = xap_elem_attr(a, 'hash')
				}
			}
		}
	}
	return best_v, best_h
}

fn xap_pkg_requires_closure(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-requires-closure expects (store, manifest)')
	}
	m := xd_find_elem(args[1], 'package') or {
		return mk_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: pkg-requires-closure expects a [package …] manifest')
	}
	store := args[0]
	mut pins := map[string]cx.Node{}
	mut on_path := map[string]bool{}
	root := xap_elem_attr(m, 'name')
	on_path[root] = true
	e := xap_pkg_closure_walk(store, m, mut pins, mut on_path)
	if ce := e {
		return ce
	}
	mut keys := pins.keys()
	keys.sort()
	mut items := []cx.Node{}
	for k in keys {
		items << pins[k] or { continue } // k comes from pins.keys(); absence impossible
	}
	return xap_elem('closure', [], items)
}

fn xap_pkg_closure_walk(store cx.Node, m cx.Element, mut pins map[string]cx.Node, mut on_path map[string]bool) ?cx.Node {
	reqs := xap_gc_child(m, 'requires') or { return none }
	for r in xap_gc_children(reqs, 'require') {
		lib := xap_elem_attr(r, 'library')
		if lib == '' {
			continue
		}
		if on_path[lib] {
			return xap_gc_err(xap_err_pkg_invalid, 'E_XAP_PKG_INVALID: requires cycle through "${lib}"',
				[xap_attr('library', lib)], [])
		}
		if lib in pins {
			continue
		}
		v, mh := xap_pkg_resolve_version(store, lib, xap_elem_attr(r, 'versions'))
		if mh == '' {
			return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: no published version of required library "${lib}"',
				[xap_attr('library', lib)], [])
		}
		dm_doc := xd_store('store-get-doc', [store, cx.Node(xap_str(mh))])
		dm := xd_elem_of(dm_doc, 'package') or {
			return xap_gc_err(xap_err_pkg_not_found, 'E_XAP_PKG_NOT_FOUND: manifest ${mh} for "${lib}" absent',
				[xap_attr('library', lib)], [])
		}
		pins[lib] = cx.Node(xap_elem('pin', [xap_attr('library', lib), xap_attr('version', v),
			xap_attr('manifest', mh), xap_attr('hash', xap_elem_attr(dm, 'hash'))], []))
		on_path[lib] = true
		we := xap_pkg_closure_walk(store, dm, mut pins, mut on_path)
		on_path[lib] = false
		if ce := we {
			return ce
		}
	}
	return none
}
