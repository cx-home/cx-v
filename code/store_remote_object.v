module code

import cx
import cxstore
import encoding.hex

// store_remote_object.v — the CLIENT side of the object-level wire (#129 PR-B / spec
// §3). RemoteObjectBackend is a cxstore.ObjectBackend whose has/get/put go to a CSRP
// daemon's objects-have/get/put verbs, and which resolves/advances refs. So a
// cx-store:// client decomposes a doc LOCALLY, asks the daemon which objects it is
// missing, uploads only those, and sets the ref — the client's object graph and the
// daemon's become ONE space (dedup + structural sharing span the network).
//
// The transport is injected (ObjWireTransport) so the §6 test runs HERMETICALLY by
// routing straight through store_csrp_route (no socket); the production transport
// (CsrpObjWireTransport) sends real CSRP requests over remote_http.

// ObjWireTransport — one object-wire request: (status, response-body-text, ok).
pub interface ObjWireTransport {
	send(op string, query string, body string) (int, string, bool)
}

@[heap]
pub struct RemoteObjectBackend {
mut:
	transport ObjWireTransport
	// #212 Defect A: has_object/get_object can't carry an error through the seam,
	// so a non-2xx (esp. 403) would be indistinguishable from absence and surface
	// upstream as CXER1120 (integrity mismatch) — masking an auth failure as data
	// corruption. Record the last non-2xx status so the doc-level path
	// (store_objwire_err) raises the real code (401/403 → CXER1131, 429 → 1132).
	fail_status int
	fail_op     string
}

fn (mut b RemoteObjectBackend) ow_note_fail(st int, op string) {
	b.fail_status = st
	b.fail_op = op
}

// ow_take_fail returns-and-clears the recorded transport failure.
pub fn (mut b RemoteObjectBackend) ow_take_fail() (int, string) {
	st, op := b.fail_status, b.fail_op
	b.fail_status = 0
	b.fail_op = ''
	return st, op
}

// ow_result_hashes collects the h="…" attrs of the [o …] children of a result doc.
fn ow_result_hashes(body string) []string {
	mut out := []string{}
	doc := cx.parse(body) or { return out }
	if doc.elements.len > 0 {
		top := doc.elements[0]
		if top is cx.Element {
			for it in top.items {
				if it is cx.Element && it.name == 'o' {
					h := csrp_attr(it, 'h')
					if h != '' {
						out << h
					}
				}
			}
		}
	}
	return out
}

pub fn (b &RemoteObjectBackend) has_object(hash []u8) bool {
	hx := hash.hex()
	st, body, ok := b.transport.send('objects-have', '', '[have [o h="${hx}"]]')
	if !ok || st != 200 {
		mut mb := unsafe { &RemoteObjectBackend(b) }
		mb.ow_note_fail(if ok { st } else { -1 }, 'objects-have')
		return false
	}
	// objects-have replies the MISSING hashes; present iff hx is NOT reported missing.
	return hx !in ow_result_hashes(body)
}

pub fn (b &RemoteObjectBackend) get_object(hash []u8) ?[]u8 {
	hx := hash.hex()
	st, body, ok := b.transport.send('objects-get', '', '[get [o h="${hx}"]]')
	if !ok || st != 200 {
		mut mb := unsafe { &RemoteObjectBackend(b) }
		mb.ow_note_fail(if ok { st } else { -1 }, 'objects-get')
		return none
	}
	doc := cx.parse(body) or { return none }
	if doc.elements.len == 0 {
		return none
	}
	top := doc.elements[0]
	if top is cx.Element {
		for it in top.items {
			if it is cx.Element && it.name == 'o' && csrp_attr(it, 'h') == hx {
				payload := hex.decode(csrp_attr(it, 'bytes')) or { return none }
				if cxstore.object_name(payload) != hash { // self-verify (spec §4)
					return none
				}
				return payload
			}
		}
	}
	return none
}

pub fn (mut b RemoteObjectBackend) put_object(payload []u8) ![]u8 {
	h := cxstore.object_name(payload)
	st, _, ok := b.transport.send('objects-put', '', '[put [o bytes="${payload.hex()}"]]')
	if !ok || st != 200 {
		b.ow_note_fail(if ok { st } else { -1 }, 'objects-put')
		return error('objects-put failed (transport/status ${st}): ${h.hex()}')
	}
	return h
}

// object_count — best-effort 0 (a remote daemon has no cheap object enumeration here).
pub fn (b &RemoteObjectBackend) object_count() int {
	return 0
}

// resolve_ref / set_ref — the ref layer over the wire (store-key → doc-root hash).
pub fn (b &RemoteObjectBackend) resolve_ref(key string) ?[]u8 {
	st, body, ok := b.transport.send('refs', '', '[refs [k key="${key}"]]')
	if !ok || st != 200 {
		mut mb := unsafe { &RemoteObjectBackend(b) }
		mb.ow_note_fail(if ok { st } else { -1 }, 'refs')
		return none
	}
	doc := cx.parse(body) or { return none }
	if doc.elements.len > 0 {
		top := doc.elements[0]
		if top is cx.Element {
			for it in top.items {
				if it is cx.Element && it.name == 'r' && csrp_attr(it, 'key') == key {
					return hex.decode(csrp_attr(it, 'root')) or { return none }
				}
			}
		}
	}
	return none
}

// set_ref advances the daemon's store-key → doc-root ref. Non-mut: it sends one
// request and holds no local state (the ref layer is authoritative on the daemon).
// Unconditional (last-writer-wins) — correct for content-addressed doc-key refs,
// which are immutable by construction; mutable-pointer advances use set_ref_cas.
pub fn (b &RemoteObjectBackend) set_ref(key string, root []u8) ! {
	st, _, ok := b.transport.send('refs-set', '', '[refs-set [r key="${key}" root="${root.hex()}"]]')
	if !ok || st != 200 {
		return error('refs-set failed (transport/status ${st}) for ${key}')
	}
}

// set_ref_cas conditionally advances the ref (#218): the daemon applies the
// record only if the ref's current root hex equals `expect` (expect == '' ⇒ the
// ref must not exist yet); a mismatch is a 409 CXER1704 on the wire, surfaced
// here as CXER1114 E_STORE_REF_CONFLICT semantics for the store layer. This is
// the wire primitive the mutable-pointer layer (alias/branch remoting) advances
// through — never last-writer-wins across clients.
pub fn (b &RemoteObjectBackend) set_ref_cas(key string, root []u8, expect string) ! {
	st, body, ok := b.transport.send('refs-set', '', '[refs-set [r key="${key}" root="${root.hex()}" expect="${expect}"]]')
	if ok && st == 409 {
		return error('E_STORE_REF_CONFLICT: ref ${key} moved (expected ${expect}): ${body}')
	}
	if !ok || st != 200 {
		return error('refs-set failed (transport/status ${st}) for ${key}')
	}
}

// ── doc-level wire (the live [$store] cx-store:// put-doc / get-doc path, §3) ──────
//
// push_doc / reconstruct are the verbs a cx-store:// CLIENT runs: a doc is decomposed
// into the subtree object graph LOCALLY, only the objects the daemon is MISSING travel,
// and the ref is advanced — then a reader resolves the ref over the wire and rebuilds
// the doc from the daemon's objects. The client's object graph and the daemon's are ONE
// space (dedup + structural sharing span the network), so this is "change the URL, same
// model": the same doc yields the same store-key and the same object hashes whether it
// is stored embedded or pushed to a daemon.

// push_doc decomposes a canonical doc, transfers ONLY the objects the daemon is missing
// (one objects-have probe + one objects-put of the missing set — the wire-economy
// primitive, spec §6.5), then advances the store-key → doc-root ref. Returns the
// store-key (= the doc's content hash, substrate-invariant).
pub fn (b &RemoteObjectBackend) push_doc(canonical string, model string) !string {
	store_key := cx.cx_text_hash(canonical)!
	mut sink := cxstore.ObjectSink{}
	root := if model == 'document' {
		// Degenerate model (spec §2/§4.6): the doc IS one raw object, no decompose.
		sink.put(canonical.bytes())
	} else {
		doc := cx.parse(canonical)!
		if doc.elements.len == 0 {
			return error('empty canonical doc')
		}
		cxstore.store_document(mut sink, doc, cxstore.default_fanout)
	}
	_ := b.push_sink(sink)!
	b.set_ref(store_key, root)!
	return store_key
}

// push_sink uploads a built graph's objects to the daemon, transferring only those it is
// MISSING (objects-have → objects-put of the missing set). Idempotent (content-address
// dedup), so re-pushing a doc that shares subtrees with one already on the daemon
// uploads only the new objects. Returns the number of objects actually transferred.
fn (b &RemoteObjectBackend) push_sink(sink cxstore.ObjectSink) !int {
	if sink.objects.len == 0 {
		return 0
	}
	mut have_body := '[have'
	for hk, _ in sink.objects {
		have_body += ' [o h="${hk}"]'
	}
	have_body += ']'
	hst, hbody, hok := b.transport.send('objects-have', '', have_body)
	if !hok || hst != 200 {
		return error('objects-have failed (transport/status ${hst})')
	}
	missing := ow_result_hashes(hbody) // the hashes the daemon reports it lacks
	if missing.len == 0 {
		return 0
	}
	mut put_body := '[put'
	for hk in missing {
		payload := sink.objects[hk] or { continue }
		put_body += ' [o bytes="${payload.hex()}"]'
	}
	put_body += ']'
	pst, _, pok := b.transport.send('objects-put', '', put_body)
	if !pok || pst != 200 {
		return error('objects-put failed (transport/status ${pst})')
	}
	return missing.len
}

// reconstruct rebuilds a doc's canonical text from the daemon's objects, resolving each
// over the wire (objects-get, self-verifying). A reachable-but-broken graph is a HARD
// error (spec §4 integrity), never a silent miss — the caller has already confirmed the
// ref resolves (resolve_ref) so absence vs corruption stay distinct.
pub fn (b &RemoteObjectBackend) reconstruct(root []u8, model string) !string {
	getter := cxstore.getter_of(b)
	if model == 'document' {
		payload := getter(root) or { return error('document object missing/corrupt') }
		return payload.bytestr()
	}
	doc := cxstore.load_document_from(getter, root) or {
		return error('doc failed to reconstruct from the object graph: ${err.msg()}')
	}
	if doc.elements.len == 0 {
		return error('doc reconstructed to an empty document')
	}
	return render_canonical(doc.elements[0])
}

// store_objwire_client returns the cx-store:// CLIENT object-wire backend if this store
// has one (a RemoteObjectBackend over CSRP). The doc verbs use it to put/get over the
// object wire (decompose + transfer-only-missing + ref) instead of the whole-doc
// document path, so an embedded client and a daemon share ONE object space.
fn store_objwire_client(ms &MemStore) ?&RemoteObjectBackend {
	if be := ms.obj_backend {
		if be is RemoteObjectBackend {
			return be
		}
	}
	return none
}

// store_objwire_err maps a recorded object-wire transport failure to the store
// error space (#212 Defect A): a 401/403 is an auth failure (CXER1131), a 429 is
// a backend rate limit (CXER1132), any other non-2xx is a transport error
// (CXER1101) — NOT CXER1120, which is reserved for a genuine hash-verification
// failure. Returns none when nothing was recorded (a genuine miss / real
// integrity problem), so the caller falls back to its default code.
fn store_objwire_err(mut ms MemStore) ?cx.Node {
	if mut be := ms.obj_backend {
		if mut be is RemoteObjectBackend {
			st, op := be.ow_take_fail()
			ms.obj_backend = be
			if st == 401 || st == 403 {
				return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: object-wire ${op} rejected (status ${st}) for ${ms.url}')
			}
			if st == 429 {
				return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: object-wire ${op} throttled for ${ms.url}')
			}
			if st != 0 {
				return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: object-wire ${op} failed (status ${st}) for ${ms.url}')
			}
		} else {
			ms.obj_backend = be
		}
	}
	return none
}

// ── production transport: CSRP requests over remote_http (store_csrp.v / store_remote.v) ──

struct CsrpObjWireTransport {
	rb &RemoteBackend
}

fn (t &CsrpObjWireTransport) send(op string, query string, body string) (int, string, bool) {
	resp, _, ok := remote_http('POST', csrp_op_url(t.rb, op, query), csrp_client_headers(t.rb,
		'application/cxd'), body.bytes())
	if !ok {
		return 0, '', false
	}
	return resp.status, resp.body.bytestr(), true
}

pub fn new_remote_object_backend(rb &RemoteBackend) &RemoteObjectBackend {
	return &RemoteObjectBackend{
		transport: ObjWireTransport(&CsrpObjWireTransport{
			rb: rb
		})
	}
}
