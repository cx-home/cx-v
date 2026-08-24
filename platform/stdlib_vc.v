module platform
import code {
	arg_bytes,
	arg_string,
	bytes_int_node,
	crypto_bool_node,
	crypto_string_node,
	mk_err,
	render_canonical,
}

import cx
import encoding.base58
import crypto.ed25519
import crypto.sha256

// stdlib_vc.v — native primitives backing the cx-stdlib/vc module
// (spec/std-lib/vc.md). A verifiable credential IS a portable, signed,
// attenuating §22.2 delegation (xap.md R9): the decentralized way to carry
// authority between DIDs, verifiable offline against the issuer's DID with no
// callback. The PEP (§22.3) and N-TRUST-1 are unchanged — vc is the transport.
//
// Signing payload = render_canonical(credential-without-proof) (the lossless,
// deterministic CX canonical form), signed with the issuer's Ed25519 key.
// Reuses shared `module code` helpers (arg_*/mk_err, crypto_* node builders,
// xap_elem/xap_attr/xap_map_get_node, render_canonical, journal_stdlib_builtin).

// CXER codes per spec/std-lib/vc.md §8.
const vc_err_key   = 'cx-err:CXER-VC-KEY-INVALID'
const vc_err_claim = 'cx-err:CXER-VC-CLAIM-INVALID'

// ── helpers ───────────────────────────────────────────────────────────────

fn vc_find_child(e cx.Element, name string) ?cx.Element {
	for it in e.items {
		if it is cx.Element {
			if it.name == name {
				return it
			}
		}
	}
	return none
}

fn vc_child_text(e cx.Element, name string) ?string {
	c := vc_find_child(e, name) or { return none }
	if c.items.len == 0 {
		return none
	}
	// A freshly ISSUED credential carries ScalarNode strings, but a PARSED one
	// (file, store, wire — the offline-portability path every committed VC
	// takes) carries barewords as TextNodes and dates as typed scalars.
	// Accepting only ScalarNode-strings made every round-tripped VC verify as
	// "malformed" while the same claim verified fresh — VCs must verify
	// offline by construction, so extract the text of whatever node shape the
	// parser produced.
	first := c.items[0]
	match first {
		cx.ScalarNode {
			return cx.scalar_value_str_public(first.value)
		}
		cx.TextNode {
			return first.value
		}
		else {
			return none
		}
	}
}

// vc_strip_proof returns the credential element with any `proof` child removed
// — the exact subject of the signature.
fn vc_strip_proof(e cx.Element) cx.Element {
	mut items := []cx.Node{}
	for it in e.items {
		if it is cx.Element {
			if it.name == 'proof' {
				continue
			}
		}
		items << it
	}
	return cx.Element{
		name:  e.name
		attrs: e.attrs
		items: items
	}
}

fn vc_status(s string) cx.Node {
	return xap_elem('vc-verification', [xap_attr('status', s)], [])
}

fn vc_status_full(s string, id string, issuer string) cx.Node {
	return xap_elem('vc-verification', [
		xap_attr('status', s),
		xap_attr('id', id),
		xap_attr('issuer', issuer),
	], [])
}

// vc_is_revoked accepts opts.revoked as a scalar id, a sequence of ids, or a
// [revoked-set [id …]] fold (the output of revoked-set).
// vc_text_of extracts text from a node however the tree was built — string
// scalars from constructed docs, atom scalars / text nodes from parsed ones
// (the §5.1 round-trip: VC content read back from a registry file).
fn vc_text_of(n cx.Node) ?string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

fn vc_is_revoked(opts cx.Node, id string) bool {
	r := xap_map_get_node(opts, 'revoked') or { return false }
	if s := vc_text_of(r) {
		return s == id
	}
	if r is cx.Element {
		for it in r.items {
			if s := vc_text_of(it) {
				if s == id {
					return true
				}
			} else if it is cx.Element {
				// [id "…"] inside a [revoked-set …]
				if it.items.len > 0 {
					if s := vc_text_of(it.items[0]) {
						if s == id {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// vc_build_unsigned assembles the credential element WITHOUT a proof, in a
// fixed field order so issue and verify canonicalize identically.
fn vc_build_unsigned(id string, issuer string, subject string, claim cx.Node, opts cx.Node) cx.Element {
	mut items := []cx.Node{}
	items << xap_elem('issuer', [], [crypto_string_node(issuer)])
	items << xap_elem('subject', [], [crypto_string_node(subject)])
	if n := xap_map_get_node(opts, 'issued-at') {
		items << xap_elem('issued-at', [], [n])
	}
	if n := xap_map_get_node(opts, 'expires') {
		items << xap_elem('expires', [], [n])
	}
	items << xap_elem('claim', [], [claim])
	return cx.Element{
		name:  'vc'
		attrs: [xap_attr('id', id)]
		items: items
	}
}

// vc_do_verify is the shared verification routine behind `verify` and `valid`.
fn vc_do_verify(args []cx.Node) cx.Node {
	if args.len < 2 {
		return vc_status('malformed')
	}
	vc_node := args[0]
	now := arg_string(args[1]) or { return vc_status('malformed') }
	opts := if args.len > 2 { args[2] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
	if vc_node !is cx.Element {
		return vc_status('malformed')
	}
	e := vc_node as cx.Element
	id := xap_elem_attr(e, 'id')
	issuer := vc_child_text(e, 'issuer') or { return vc_status('malformed') }
	proof := vc_find_child(e, 'proof') or { return vc_status('malformed') }
	// I1 stream 19 (L36/#702): the verifier READS the proof suite and
	// FAILS CLOSED on anything the registry does not verify — it
	// previously ignored `type=` and attempted ed25519 regardless.
	proof_type := xap_elem_attr(proof, 'type')
	// The signer emits the W3C `Ed25519Signature2020` spelling; the registry
	// key is the bare suite name. An ABSENT type= is NOT defaulted: a
	// stripped suite tag over a still-valid signature is the L36 downgrade
	// attack (crypto_agility §1.4, #691 §10) — '' falls through to the gate
	// and fails closed as :unsupported-suite.
	suite := match proof_type {
		'Ed25519Signature2020', 'ed25519-2020' { 'ed25519' }
		else { proof_type }
	}
	cx.cx_suite_verify_gate(suite) or { return vc_status('unsupported-suite') }
	sig_mb := vc_child_text(proof, 'signature') or { return vc_status('malformed') }
	if !sig_mb.starts_with('z') {
		return vc_status('bad-signature')
	}
	sig := base58.decode_bytes(sig_mb[1..].bytes()) or { return vc_status('bad-signature') }
	// did:key issuer ⇒ offline key recovery; did:web ⇒ resolve first (malformed here).
	key := did_key_bytes(issuer) or { return vc_status('malformed') }
	if sig.len != 64 {
		return vc_status('bad-signature')
	}
	canon := render_canonical(cx.Node(vc_strip_proof(e)))
	ok := ed25519.verify(ed25519.PublicKey(key), canon.bytes(), sig) or {
		return vc_status('bad-signature')
	}
	if !ok {
		return vc_status('bad-signature')
	}
	// validity window (ISO-8601 UTC lexical comparison)
	if ia := vc_child_text(e, 'issued-at') {
		if now < ia {
			return vc_status('not-yet-valid')
		}
	}
	if ex := vc_child_text(e, 'expires') {
		if now > ex {
			return vc_status('expired')
		}
	}
	if vc_is_revoked(opts, id) {
		return vc_status('revoked')
	}
	return vc_status_full('valid', id, issuer)
}

fn vc_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'vc-issue' {
			if args.len < 4 {
				return none
			}
			issuer := arg_string(args[0]) or { return none }
			issuer_key := arg_bytes(args[1]) or { return none }
			subject := arg_string(args[2]) or { return none }
			claim := args[3]
			opts := if args.len > 4 { args[4] } else { cx.Node(xap_elem('__cx_map__', [], [])) }
			if issuer_key.len != 32 {
				return mk_err(vc_err_key, 'vc/issue: Ed25519 seed must be 32 bytes, got ${issuer_key.len}')
			}
			if claim !is cx.Element || (claim as cx.Element).name != 'delegation' {
				return mk_err(vc_err_claim, 'vc/issue: claim must be a [delegation …] (§22.2)')
			}
			default_id := 'urn:vc:' + sha256.sum(render_canonical(claim).bytes()).hex()[..32]
			id := if s := xap_map_get_node(opts, 'id') {
				arg_string(s) or { default_id }
			} else {
				default_id
			}
			unsigned := vc_build_unsigned(id, issuer, subject, claim, opts)
			canon := render_canonical(cx.Node(unsigned))
			priv := ed25519.new_key_from_seed(issuer_key)
			sig := priv.sign(canon.bytes()) or {
				return mk_err(vc_err_key, 'vc/issue: signing failed')
			}
			sig_mb := 'z' + base58.encode_bytes(sig).bytestr()
			proof := xap_elem('proof', [xap_attr('type', 'Ed25519Signature2020')], [
				xap_elem('verification-method', [], [crypto_string_node(issuer + '#' +
					issuer.all_after_last(':'))]),
				xap_elem('signature', [], [crypto_string_node(sig_mb)]),
			])
			mut full := unsigned.items.clone()
			full << proof
			return cx.Element{
				name:  'vc'
				attrs: unsigned.attrs
				items: full
			}
		}
		'vc-verify' {
			return vc_do_verify(args)
		}
		'vc-valid' {
			res := vc_do_verify(args)
			if res is cx.Element {
				return crypto_bool_node(xap_elem_attr(res, 'status') == 'valid')
			}
			return crypto_bool_node(false)
		}
		'vc-present' {
			if args.len < 1 {
				return none
			}
			// v1: a [vp …] presentation envelope (holder proof-of-possession later).
			return xap_elem('vp', [], [args[0]])
		}
		'vc-revoke' {
			if args.len < 2 {
				return none
			}
			journal := args[0]
			vc_id := arg_string(args[1]) or { return none }
			// opts carries the journal attribution {actor, authority} — the
			// revoker must be attributed (journal forbids anonymous appends).
			attribution := if args.len > 2 {
				args[2]
			} else {
				cx.Node(xap_elem('__cx_map__', [], []))
			}
			event := cx.Node(xap_elem('revoke', [xap_attr('vc-id', vc_id)], []))
			return journal_stdlib_builtin('journal-append', [journal, event, attribution])
		}
		'vc-revoked-set' {
			if args.len < 1 {
				return none
			}
			journal := args[0]
			slice := journal_stdlib_builtin('journal-slice', [
				journal,
				bytes_int_node(0),
				bytes_int_node(i64(2147483647)),
				crypto_string_node(''),
			]) or { return none }
			mut ids := []cx.Node{}
			if slice is cx.Element {
				for it in slice.items {
					rid := vc_revoke_event_id(it) or { continue }
					ids << xap_elem('id', [], [crypto_string_node(rid)])
				}
			}
			return xap_elem('revoked-set', [], ids)
		}
		else {
			return none
		}
	}
	return none
}

// vc_revoke_event_id pulls the vc-id from a journaled revoke event. Events may
// be wrapped (e.g. [event … [revoke vc-id=…]]); descend one level to find it.
fn vc_revoke_event_id(n cx.Node) ?string {
	if n is cx.Element {
		if n.name == 'revoke' {
			v := xap_elem_attr(n, 'vc-id')
			if v != '' {
				return v
			}
		}
		for it in n.items {
			if r := vc_revoke_event_id(it) {
				return r
			}
		}
	}
	return none
}
