module platform
import code {
	arg_bytes,
	arg_string,
	crypto_bool_node,
	crypto_bytes_node,
	crypto_string_node,
	http_body_text_impl,
	http_request_verb,
	is_err_value,
	json_do_parse,
	mk_err,
	mk_err_with_cause,
}

import cx
import encoding.base58
import crypto.ed25519

// stdlib_did.v — native primitives backing the cx-stdlib/did module
// (spec/std-lib/did.md). DIDs are the decentralized identity source named in
// xap.md §22.1 (R9): a DID identifies a principal. did:key is self-describing
// and resolved entirely OFFLINE; did:web resolves over cx-stdlib/http.
//
// Bodies in /stdlib/did.cx call these primitives under unique `did-*` names.
// Reuses the shared `module code` helpers (arg_bytes/arg_string/mk_err from
// bytes+eval, crypto_string_node/crypto_bytes_node/crypto_bool_node from
// crypto, xap_elem/xap_attr from xap, http_request_verb/json_do_parse).

// CXER codes per spec/std-lib/did.md §8 (symbolic, matching xap.md's
// CXER-UNAUTHORIZED style for the trust stack).
const did_err_malformed     = 'cx-err:CXER-DID-MALFORMED'
const did_err_method_unsup  = 'cx-err:CXER-DID-METHOD-UNSUPPORTED'
const did_err_not_self_desc = 'cx-err:CXER-DID-NOT-SELF-DESCRIBING'
const did_err_doc_mismatch  = 'cx-err:CXER-DID-DOC-MISMATCH'
// #740: reaching the document is a different failure from the document
// being wrong about itself. DOC-MISMATCH is spec'd for "resolved did:web
// document id != the requested DID" (did.md §8) and was being raised when
// no document had been fetched at all — a capability denial, a non-2xx
// status, an unreachable host. RESOLVE-FAILED covers those.
const did_err_resolve_failed = 'cx-err:CXER-DID-RESOLVE-FAILED'
const did_err_key_unsup     = 'cx-err:CXER-DID-KEY-UNSUPPORTED'

// Ed25519 multicodec prefix (unsigned-varint 0xed 0x01) for did:key (§2.1).
const did_ed25519_multicodec = [u8(0xed), u8(0x01)]

struct DidParts {
	method string
	id     string // method-specific identifier (everything after `did:<method>:`)
}

// did_split decomposes `did:<method>:<id>`; the id may itself contain ':'
// (did:web path segments).
fn did_split(s string) ?DidParts {
	if !s.starts_with('did:') {
		return none
	}
	rest := s[4..]
	idx := rest.index(':') or { return none }
	method := rest[..idx]
	id := rest[idx + 1..]
	if method == '' || id == '' {
		return none
	}
	return DidParts{
		method: method
		id:     id
	}
}

// did_self_desc_mb returns the `z<base58btc>` multibase key identifier for a
// SELF-DESCRIBING DID — did:key (id = `z…`) or did:peer numalgo-0 (id = `0z…`,
// xap_identity_model §1: the same multicodec/multibase encoding as did:key with
// a `0` numalgo prefix; it is resolved by the SAME offline synthesis and
// differs only in its usage contract — a pairwise DID never published). Errors
// for methods that need the network (did:web).
fn did_self_desc_mb(parts DidParts) !string {
	match parts.method {
		'key' {
			if !parts.id.starts_with('z') {
				return error(did_err_malformed)
			}
			return parts.id
		}
		'peer' {
			// v1 supports numalgo-0 only: `did:peer:0z…`.
			if !parts.id.starts_with('0z') {
				return error(did_err_method_unsup)
			}
			return parts.id[1..] // strip the '0' numalgo prefix → `z…`
		}
		else {
			return error(did_err_not_self_desc)
		}
	}
}

// did_key_bytes recovers the 32-byte Ed25519 public key from a self-describing
// DID (did:key or did:peer:0).
fn did_key_bytes(s string) !([]u8) {
	parts := did_split(s) or { return error(did_err_malformed) }
	mb := did_self_desc_mb(parts)!
	decoded := base58.decode_bytes(mb[1..].bytes()) or { return error(did_err_malformed) }
	if decoded.len != 34 || decoded[0] != did_ed25519_multicodec[0]
		|| decoded[1] != did_ed25519_multicodec[1] {
		return error(did_err_key_unsup)
	}
	return decoded[2..].clone()
}

// did_key_document synthesizes the DID Document for a did:key — fully offline
// (§4). `mb` is the multibase identifier (parts.id, including the leading 'z').
fn did_key_document(did string, mb string) cx.Node {
	frag := did + '#' + mb
	vm := xap_elem('vm', [
		xap_attr('id', frag),
		xap_attr('type', 'Ed25519VerificationKey2020'),
		xap_attr('controller', did),
		xap_attr('public-key-multibase', mb),
	], [])
	return xap_elem('did-document', [], [
		xap_elem('id', [], [crypto_string_node(did)]),
		xap_elem('verification-method', [], [vm]),
		xap_elem('authentication', [], [crypto_string_node(frag)]),
		xap_elem('assertion-method', [], [crypto_string_node(frag)]),
	])
}

// did_web_url maps a did:web identifier to its did.json URL (§5).
fn did_web_url(id string) string {
	segs := id.split(':')
	domain := segs[0]
	if segs.len == 1 {
		return 'https://${domain}/.well-known/did.json'
	}
	return 'https://${domain}/' + segs[1..].join('/') + '/did.json'
}

// did_web_resolve performs the real HTTPS GET + parse + id-validation (§5).
fn did_web_resolve(did string, id string) cx.Node {
	url := did_web_url(id)
	resp := http_request_verb([crypto_string_node('get'), crypto_string_node(url)])
	if is_err_value(resp) {
		// #740: the fetch itself failed — a capability denial, a DNS/TLS
		// failure, a refused connection. The underlying err IS the answer and
		// says exactly what to fix ("grant via --allow-net"), so it propagates
		// UNCHANGED. Wrapping it re-labelled a denial as a document-id
		// mismatch and buried the real cause under `message=panic`, which is
		// an internal recovery detail rather than a description of anything.
		return resp
	}
	if resp is cx.Element {
		if st := resp.attr_val('status') {
			status_code := cx.scalar_value_str_public(st)
			if !status_code.starts_with('2') {
				// #740: a non-2xx means no document was fetched, so nothing
				// can mismatch. There is no inner err here to propagate — the
				// response is a well-formed HTTP failure — so it becomes a
				// RESOLVE-FAILED naming the status and the URL.
				return mk_err(did_err_resolve_failed,
					'did/resolve: ${url} answered HTTP ${status_code}')
			}
		}
		body_node := http_body_text_impl([cx.Node(resp)])
		body := arg_string(body_node) or { '' }
		if !body.contains(did) {
			return mk_err(did_err_doc_mismatch, 'did/resolve: ${url} does not describe ${did}')
		}
		parsed := json_do_parse(body, map[string]cx.Node{})
		// A faithful projection: the validated id plus the parsed source
		// document (callers read verification methods from /source).
		return xap_elem('did-document', [xap_attr('resolved-via', 'web')], [
			xap_elem('id', [], [crypto_string_node(did)]),
			xap_elem('source', [], [parsed]),
		])
	}
	return mk_err(did_err_resolve_failed, 'did/resolve: no response from ${url}')
}

// did_key_from_seed derives the did:key identifier for a 32-byte Ed25519
// seed (the offline-resolvable identity form the store client + gRPC edge
// use). Pure; the inverse of did_key_bytes for keys this process holds.
fn did_key_from_seed(seed []u8) !string {
	if seed.len != 32 {
		return error('seed must be 32 bytes, got ${seed.len}')
	}
	priv := ed25519.new_key_from_seed(seed)
	pubkey := []u8(priv.public_key())
	mut prefixed := []u8{cap: 34}
	prefixed << did_ed25519_multicodec
	prefixed << pubkey
	return 'did:key:z' + base58.encode_bytes(prefixed).bytestr()
}

fn did_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'did-key-create' {
			if args.len != 1 {
				return none
			}
			pubkey := arg_bytes(args[0]) or { return none }
			if pubkey.len != 32 {
				return mk_err(did_err_key_unsup, 'did/key-create: Ed25519 public key must be 32 bytes, got ${pubkey.len}')
			}
			mut prefixed := []u8{cap: 34}
			prefixed << did_ed25519_multicodec
			prefixed << pubkey
			mb := 'z' + base58.encode_bytes(prefixed).bytestr()
			return crypto_string_node('did:key:' + mb)
		}
		'did-peer-create' {
			// did:peer numalgo-0 (§1): same ed25519 multibase as did:key, with a
			// `0` numalgo prefix. Pairwise identity — never published.
			if args.len != 1 {
				return none
			}
			pubkey := arg_bytes(args[0]) or { return none }
			if pubkey.len != 32 {
				return mk_err(did_err_key_unsup, 'did/peer-create: Ed25519 public key must be 32 bytes, got ${pubkey.len}')
			}
			mut prefixed := []u8{cap: 34}
			prefixed << did_ed25519_multicodec
			prefixed << pubkey
			mb := 'z' + base58.encode_bytes(prefixed).bytestr()
			return crypto_string_node('did:peer:0' + mb)
		}
		'did-parse' {
			if args.len != 1 {
				return none
			}
			s := arg_string(args[0]) or { return none }
			parts := did_split(s) or {
				return mk_err(did_err_malformed, 'did/parse: not a valid DID: ${s}')
			}
			return xap_elem('did', [
				xap_attr('method', parts.method),
				xap_attr('id', parts.id),
				xap_attr('raw', s),
			], [])
		}
		'did-method' {
			if args.len != 1 {
				return none
			}
			s := arg_string(args[0]) or { return none }
			parts := did_split(s) or {
				return mk_err(did_err_malformed, 'did/method: not a valid DID: ${s}')
			}
			return crypto_string_node(parts.method)
		}
		'did-key-of' {
			if args.len != 1 {
				return none
			}
			s := arg_string(args[0]) or { return none }
			kb := did_key_bytes(s) or {
				return mk_err(err.msg(), 'did/key-of: ${err.msg()} for ${s}')
			}
			return crypto_bytes_node(kb)
		}
		'did-document' {
			if args.len != 1 {
				return none
			}
			s := arg_string(args[0]) or { return none }
			parts := did_split(s) or {
				return mk_err(did_err_malformed, 'did/document: not a valid DID: ${s}')
			}
			mb := did_self_desc_mb(parts) or {
				return mk_err(err.msg(), 'did/document: ${parts.method} is not self-describing — use resolve')
			}
			// validate the key decodes before synthesizing
			did_key_bytes(s) or { return mk_err(err.msg(), 'did/document: ${err.msg()}') }
			return did_key_document(s, mb)
		}
		'did-verify-control' {
			if args.len != 3 {
				return none
			}
			s := arg_string(args[0]) or { return none }
			challenge := arg_bytes(args[1]) or { return none }
			sig := arg_bytes(args[2]) or { return none }
			kb := did_key_bytes(s) or {
				return mk_err(err.msg(), 'did/verify-control: ${err.msg()}')
			}
			if sig.len != 64 {
				return crypto_bool_node(false)
			}
			ok := ed25519.verify(ed25519.PublicKey(kb), challenge, sig) or {
				return crypto_bool_node(false)
			}
			return crypto_bool_node(ok)
		}
		'did-resolve' {
			if args.len < 1 {
				return none
			}
			s := arg_string(args[0]) or { return none }
			parts := did_split(s) or {
				return mk_err(did_err_malformed, 'did/resolve: not a valid DID: ${s}')
			}
			match parts.method {
				'key', 'peer' {
					mb := did_self_desc_mb(parts) or {
						return mk_err(err.msg(), 'did/resolve: ${err.msg()}')
					}
					did_key_bytes(s) or { return mk_err(err.msg(), 'did/resolve: ${err.msg()}') }
					return did_key_document(s, mb)
				}
				'web' {
					return did_web_resolve(s, parts.id)
				}
				else {
					return mk_err(did_err_method_unsup, 'did/resolve: unsupported method ${parts.method}')
				}
			}
		}
		else {
			return none
		}
	}
	return none
}
