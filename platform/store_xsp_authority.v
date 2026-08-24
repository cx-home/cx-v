module platform

import code {
	crypto_string_node,
	mk_err,
}
import cx
import time

// store_xsp_authority.v — the ONE authority model on the XSP store-profile
// listener (I5 stream 4 W4; spec/03-approved/xap/xsp_store_profile.md §6/§6.1,
// xap_identity_model.md §5). Attach is XSP-AUTH; authority is VC-compiled
// capability values over the SESSION's authority basis — a per-connection
// authz store seeded from the operator's `[xsp [grants …]]` config (the CSRP
// DidGrant table become ordinary delegations) and extended by verified
// presentations (`[vp …]` in the M3 attach or a later `phase=present`).
// Enforcement posture: grants configured ⇒ deny-by-default PEP on EVERY verb
// (the `[deny …]` value rides the wire VERBATIM in an error frame); no
// grants ⇒ the W3 open posture (data verbs open; admin verbs behind the
// CXER5018 mutual gate — re-scoped to open mode only).

const sx_err_authority = 'cx-err:CXER5021' // E_XSP_STORE_AUTHORITY (§4.2)

// SxMeter is one bounds-bearing delegation's live meter on this session —
// the per-stream v1 serialization point (one attach, one mount, ops
// serialized under the mount's op lock). rate = token bucket (refilled
// lazily on read); count = monotone. The PEP stays pure: readings cross
// into authz_decide as opts.meters, and the debit happens here at the verb
// commit point, after the permit.
struct SxMeter {
mut:
	tokens     f64
	last_ms    i64
	count_used i64
}

// sx_verb_capability — the v1 capability grammar: the four CSRP op-classes,
// kept class-for-class for the W7 parity gate (§6.1). Unknown verbs resolve
// to `admin` (deny-by-default; the verb table itself refuses unknowns first).
fn sx_verb_capability(verb string) string {
	return match verb {
		'get', 'list', 'iter', 'query', 'objects-have', 'objects-get', 'refs', 'aliases',
		'capabilities', 'session', 'feed', 'get-blob', 'journal-read', 'journal-slice',
		'journal-since', 'journal-query', 'journal-verify', 'journal-verify-slice',
		'journal-snapshot-verify' {
			'read'
		}
		'journal-fold', 'journal-fold-slice', 'journal-replay', 'journal-dry-run' {
			// S6 §4.3/§6.1: the compute-class pushdown verbs run
			// CLIENT-SUPPLIED code on the daemon — a DISTINCT grant, never
			// implied by read, never implying write (the family is read-only).
			'compute'
		}
		'put', 'put-blob', 'modify', 'objects-put', 'refs-set', 'aliases-set' {
			'write'
		}
		'delete', 'erase' {
			// an erase is delete-grade authority (§6.1) — its extra weight is
			// carried by attribution, not a class.
			'delete'
		}
		else {
			'admin'
		}
	}
}

// sx_authority_new seeds the SESSION's authority basis from the config
// grants that name this principal (or the floor). Each grant is a
// principal-rooted delegation from the daemon's identity — ordinary
// records, so attenuation/revocation/explain hold with no special cases.
fn sx_authority_new(cfg XspConfig, mount string, principal string) &AuthzStore {
	mut s := &AuthzStore{
		tenant:  mount
		is_open: true
	}
	mut n := 0
	for g in cfg.grants {
		matches := (g.did == '' && principal.starts_with('floor:'))
			|| (g.did != '' && g.did == principal)
		if !matches {
			continue
		}
		n++
		s.delegations << &AuthzDelegation{
			id:           'grant-${n}'
			tenant:       mount
			from_kind:    'principal'
			from_id:      cfg.identity_did
			to_kind:      'agent'
			to_id:        principal
			capabilities: g.caps.clone()
			over:         g.over
			assurance:    't1'
			revocable:    true
			gate:         cx.Node(cx.Element{})
			action:       cx.Node(cx.Element{})
			value:        cx.Node(cx.Element{})
			bounds_value: cx.Node(cx.Element{})
		}
	}
	return s
}

// sx_pep_decide runs the one decision function over the session basis with
// live meter readings, and DEBITS every bounds-bearing link on the permitted
// chain at the commit point. Returns the [permit]/[deny] value — the caller
// sends a deny VERBATIM as the error-frame payload (error transparency).
// `cap_name` is the capability class the caller resolved (sx_verb_capability,
// or `peer` for a revocations-plane feed). W5 §6.1: BEFORE deciding, every
// delegation compiled from a since-revoked VC is REMOVED from the session
// basis — revocation enforced locally at the next PEP check, never by
// remote reach-in; live sessions are never torn down, their authority
// narrows at the next decision.
fn sx_pep_decide(mut c SxConn, cap_name string, slice string, revoked map[string]bool) cx.Node {
	if revoked.len > 0 && c.vc_of.len > 0 {
		mut kept := []&AuthzDelegation{}
		mut dropped := false
		for d in c.authz.delegations {
			if vcid := c.vc_of[d.id] {
				if revoked[vcid] {
					dropped = true
					c.meters.delete(d.id)
					continue
				}
			}
			kept << d
		}
		if dropped {
			c.authz.delegations = kept
		}
	}
	now_ms := time.now().unix_milli()
	// meter readings — the materialized-snapshot posture (§6.1): refill the
	// rate buckets lazily, then hand authz_decide a pure snapshot.
	mut mitems := []cx.Node{}
	for d in c.authz.delegations {
		if !d.has_bounds {
			continue
		}
		mut m := c.meters[d.id] or {
			nm := &SxMeter{
				tokens:  f64(d.b_rate_n)
				last_ms: now_ms
			}
			c.meters[d.id] = nm
			nm
		}
		if d.b_rate_per > 0 {
			cap_f := f64(d.b_rate_n)
			m.tokens += f64(now_ms - m.last_ms) / 1000.0 * cap_f / f64(d.b_rate_per)
			if m.tokens > cap_f {
				m.tokens = cap_f
			}
			m.last_ms = now_ms
		}
		mitems << cx.Node(cx.Element{
			name:  'meter'
			attrs: [
				xap_attr('id', d.id),
				cx.Attribute{
					name:  'tokens'
					value: cx.ScalarValue(m.tokens)
				},
				cx.Attribute{
					name:  'count-used'
					value: cx.ScalarValue(m.count_used)
				},
			]
		})
	}
	mut req_items := [
		cx.Node(cx.Element{
			name:  'actor'
			items: [
				cx.Node(cx.Element{
					name:  'agent'
					attrs: [xap_attr('id', c.principal)]
				}),
			]
		}),
		cx.Node(cx.Element{
			name:  'capability'
			attrs: [xap_attr('name', cap_name)]
		}),
	]
	if slice != '' {
		req_items << cx.Node(cx.Element{
			name:  'slice'
			attrs: [xap_attr('path', slice)]
		})
	}
	req_items << cx.Node(cx.Element{
		name:  'tenant'
		attrs: [xap_attr('id', c.mount)]
	})
	req := cx.Element{
		name:  'authz-request'
		items: req_items
	}
	mut cfg := map[string]cx.Node{}
	cfg['meters'] = cx.Node(cx.Element{
		name:  'meters'
		items: mitems
	})
	dec := authz_decide(c.authz, req, cfg)
	if dec is cx.Element && dec.name == 'permit' {
		// commit-point debit: every bounds-bearing link on the via chain.
		for it in dec.items {
			if it is cx.Element && it.name == 'via' {
				for v in it.items {
					id := authz_node_text(v)
					if id == '' {
						continue
					}
					d := authz_find_rec(c.authz, id) or { continue }
					if !d.has_bounds {
						continue
					}
					mut m := c.meters[d.id] or { continue }
					if d.b_rate_per > 0 {
						m.tokens -= 1.0
						if m.tokens < 0 {
							m.tokens = 0
						}
					}
					if d.b_count > 0 {
						m.count_used++
					}
				}
			}
		}
	}
	return dec
}

// sx_m3_vp extracts a presentation from the M3 attach payload. THE CARRIAGE
// IS A SINGLE-SCALAR TEXT FIELD (`[vp "<canonical [vp …] text>"]`), forced
// by two independent constraints (both discovered the hard way): (1) the W2
// shape rule — M3 is transcript-signed, and a nested element child does not
// atomize, so fresh and decoded forms would sign DIFFERENT transcripts
// (xsp-auth-017's trap); (2) data-bin is lossy on element/attr duality
// (the L165 lane ruling), so a [vc …] crossing it re-canonicalizes
// differently and its SIGNATURE dies — signed content must ride a lossless
// lane, and canonical text in a string field is that lane.
fn sx_m3_vp_text(m3 cx.Element) ?string {
	attach := xsp_auth_child(m3, 'attach') or { return none }
	return xsp_auth_child_text(attach, 'vp') or { return none }
}

// sx_m3_vp_present reports whether the M3 attach carries a [vp] field AT ALL
// (child element or atomized attr). The caller uses it to distinguish "no
// presentation offered" (fine — the floor/anonymous posture decides) from
// "presentation in the WRONG carriage" (e.g. the nested [vp [vc …]] element
// the spec names as the likely mistake) — the latter refuses the attach
// loudly with CXER5021 (§6.1), never a silently under-authorized session
// (remediation register R3.1 / audit F-20).
fn sx_m3_vp_present(m3 cx.Element) bool {
	attach := xsp_auth_child(m3, 'attach') or { return false }
	if _ := xsp_auth_child(attach, 'vp') {
		return true
	}
	for a in attach.attrs {
		if a.name == 'vp' {
			return true
		}
	}
	return false
}

// sx_parse_vp_text parses the canonical presentation text into its [vp …]
// element (none = malformed, the caller refuses CXER5021).
fn sx_parse_vp_text(t string) ?cx.Element {
	doc := cx.parse(t) or { return none }
	if doc.elements.len == 0 {
		return none
	}
	first := doc.elements[0]
	if first is cx.Element && first.name == 'vp' {
		return first
	}
	return none
}

// sx_present_locked verifies and compiles one `[vp …]` presentation into the
// session's authority basis (identity model §5.1–§5.3). Chain order is
// root-first; every link must verify, walk issuer→subject, and STRICTLY
// attenuate (the four ⊆ axes — CXER4703 verbatim). The chain's terminal
// subject must be the session principal byte-for-byte
// (CXER-XSP-AUTH-SUBJECT); a floor session cannot present (CXER5021); a
// cross-tenant delegation is a FAULT (CXER4805 semantics); a bound this
// surface cannot meter (`spend` at v1) rejects fail-closed (CXER5021). An
// unrecognized ROOT compiles to NOTHING — inert, reported, never an error
// that voids the rest (N-TRUST-1: a foreign chain cannot conjure authority).
// Reply: [presented compiled=N inert=K].
fn sx_present_locked(mut srv StoreXspServer, mut c SxConn, vp cx.Element) cx.Node {
	if !c.mutual {
		return mk_err(sx_err_authority,
			'E_XSP_STORE_AUTHORITY: a floor session cannot present credentials (identity model §5.1)')
	}
	mut vcs := []cx.Element{}
	for it in vp.items {
		if it is cx.Element && it.name == 'vc' {
			vcs << it
		}
	}
	if vcs.len == 0 {
		return mk_err(sx_err_authority, 'E_XSP_STORE_AUTHORITY: [vp …] carries no [vc …]')
	}
	now := time.utc().format_rfc3339()
	// W5 §7: the daemon's revoked-set crosses into vc-verify as opts.revoked
	// — a revoked credential refuses at present time (the first of the two
	// local enforcement points). Caller holds srv.mu.
	verify_opts := cx.Node(cx.Element{
		name:  code.map_marker_name
		items: [
			session_kv('revoked', sx_revoked_set_locked(srv)),
		]
	})
	// pass 1 — verify every link and pre-validate the chain, so a bad link
	// compiles NOTHING (never a half-applied presentation).
	mut claims := []cx.Element{}
	mut subjects := []string{}
	mut issuers := []string{}
	for v in vcs {
		st := vc_do_verify([cx.Node(v), cx.Node(crypto_string_node(now)), verify_opts])
		mut status := ''
		if st is cx.Element {
			status = xap_elem_attr(st, 'status')
		}
		if status != 'valid' {
			return mk_err(sx_err_authority,
				'E_XSP_STORE_AUTHORITY: credential verification failed (${status})')
		}
		issuer := vc_child_text(v, 'issuer') or { '' }
		subject := vc_child_text(v, 'subject') or { '' }
		claim := vc_find_child(v, 'claim') or {
			return mk_err(sx_err_authority, 'E_XSP_STORE_AUTHORITY: [vc] carries no [claim]')
		}
		mut claim_del := cx.Element{}
		mut has_del := false
		for ci in claim.items {
			if ci is cx.Element && ci.name == 'delegation' {
				claim_del = ci
				has_del = true
			}
		}
		if !has_del {
			return mk_err(sx_err_authority,
				'E_XSP_STORE_AUTHORITY: the claim must be a [delegation …] value (vc.md §6)')
		}
		claims << claim_del
		subjects << subject
		issuers << issuer
	}
	// the handshake is the proof of possession: terminal subject = session
	// principal, byte-equal (no bearer credentials exist in this model).
	if subjects.last() != c.principal {
		return mk_err('cx-err:CXER-XSP-AUTH-SUBJECT',
			'E_XSP_AUTH_SUBJECT: the chain terminal subject "${subjects.last()}" is not the session principal "${c.principal}" (§5.1)')
	}
	// the delegation walks: link k's issuer is link k-1's subject.
	for i in 1 .. vcs.len {
		if issuers[i] != subjects[i - 1] {
			return mk_err(sx_err_authority,
				'E_XSP_STORE_AUTHORITY: broken chain — link ${i} issuer "${issuers[i]}" ≠ link ${i - 1} subject "${subjects[i - 1]}" (§5.2)')
		}
	}
	// pass 2 — compile, root-first. Root recognition is a LOCAL fact: the
	// root issuer must be a principal this deployment recognizes as holding
	// the root's capabilities (the daemon identity, or a configured grant
	// whose class set covers them). Unrecognized ⇒ the whole chain is inert.
	mut recognized := issuers[0] == srv.cfg.identity_did
	if !recognized {
		root_caps := authz_capabilities(claims[0])
		for g in srv.cfg.grants {
			if g.did != issuers[0] {
				continue
			}
			mut covers := true
			for rc in root_caps {
				if rc !in g.caps {
					covers = false
				}
			}
			if covers {
				recognized = true
			}
		}
	}
	if !recognized {
		return cx.Element{
			name:  'presented'
			attrs: [
				cx.Attribute{
					name:  'compiled'
					value: cx.ScalarValue(i64(0))
				},
				cx.Attribute{
					name:  'inert'
					value: cx.ScalarValue(i64(vcs.len))
				},
			]
		}
	}
	mut compiled := 0
	for ci, claim_el in claims {
		rec := authz_parse_delegation(cx.Node(claim_el), c.mount, false) or {
			// the tenant partition is a FAULT, not inert (§5.3, CXER4805
			// semantics); every other parse fault is a malformed presentation.
			if err.msg().contains('cross-tenant') {
				return mk_err('cx-err:CXER4805',
					'E_XSP_STORE_TENANT: ${err.msg()} — a cross-tenant grant is a fault, never inert (§5.3)')
			}
			return mk_err(sx_err_authority, 'E_XSP_STORE_AUTHORITY: ${err.msg()}')
		}
		if rec.b_has_spend {
			// fail-closed: this surface cannot meter spend at v1 (§6.1) — a
			// bound that cannot be enforced is never silently void.
			return mk_err(sx_err_authority,
				'E_XSP_STORE_AUTHORITY: [bounds [spend …]] is not meterable on this surface at v1 — presentation rejected fail-closed (§6.1)')
		}
		if !authz_attenuation_ok(c.authz, rec, time.now().unix() ) {
			return mk_err(authz_err_escalation,
				'E_AUTHZ_ESCALATION: the presented delegation conveys more than its issuer holds (§5.2/§4.2)')
		}
		mut nrec := rec
		authz_inherit_window(c.authz, mut nrec)
		c.authz.delegations << rec
		// remember the source VC per compiled record — the second local
		// enforcement point (§6.1): a later revocation of that VC drops
		// this delegation at the next PEP check.
		vcid := xap_elem_attr(vcs[ci], 'id')
		if vcid != '' {
			c.vc_of[rec.id] = vcid
		}
		compiled++
	}
	return cx.Element{
		name:  'presented'
		attrs: [
			cx.Attribute{
				name:  'compiled'
				value: cx.ScalarValue(i64(compiled))
			},
			cx.Attribute{
				name:  'inert'
				value: cx.ScalarValue(i64(0))
			},
		]
	}
}
