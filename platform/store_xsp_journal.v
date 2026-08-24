module platform

import code {
	is_err_value,
	mk_closure_sentinel,
	mk_err,
	render_canonical,
}
import cx

// store_xsp_journal.v — the journal pushdown verb family on the XSP store
// profile listener (S6, RULED: F3+F4+F5+R1.1(b); xsp_store_profile.md §4.3,
// journal.md §6.1). Eleven wire verbs run the journal §3 surface DAEMON-SIDE
// against the attach-bound mount's journal tenant:
//
//   read-class:    journal-read (request→reply), journal-slice /
//                  journal-since / journal-query (credit-governed event
//                  streams), journal-verify / journal-verify-slice /
//                  journal-snapshot-verify (verification values VERBATIM —
//                  a finding is data, §2.5/§3.6).
//   compute-class: journal-fold / journal-fold-slice / journal-replay /
//                  journal-dry-run — they run CLIENT-SUPPLIED code on the
//                  daemon, so they require the DISTINCT `compute` capability
//                  (§6.1) and the F4 evaluation budget.
//
// The fn carriage (F3a): fn= names an OPAQUE def document by address
// (put-blob; raw-byte identity verified on load); claim= carries the
// MANDATORY computation-identity claim the daemon recomputes over the parsed
// entry def and refuses on mismatch (CXER5023). The document must be a
// program of [?def]s ONLY (CXER5025 otherwise) — so fetching can never run
// load-time effects. Purity is the SAME server-side check the local surface
// applies (CXER4611 VERBATIM). The budget (F4a): each evaluation arms
// cfg.pushdown_steps + cfg.pushdown_mem_mb on a fresh env; the engine's
// thrown CXER0273 answers here as the profile's typed CXER5024 with
// [conjunct :steps|:memory]. Every verb attaches read-only — the family is
// read-only against the journal, so a refused evaluation leaves nothing
// half-applied.

const sxj_err_claim = 'cx-err:CXER5023' // E_XSP_STORE_PUSHDOWN_CLAIM (§4.2)
const sxj_err_budget = 'cx-err:CXER5024' // E_XSP_STORE_PUSHDOWN_BUDGET (§4.2)
const sxj_err_fn = 'cx-err:CXER5025' // E_XSP_STORE_PUSHDOWN_FN (§4.2)

const sxj_reply_verbs = ['journal-read', 'journal-verify', 'journal-verify-slice',
	'journal-snapshot-verify', 'journal-fold', 'journal-fold-slice', 'journal-replay',
	'journal-dry-run']
const sxj_stream_verbs = ['journal-slice', 'journal-since', 'journal-query']
const sxj_compute_verbs = ['journal-fold', 'journal-fold-slice', 'journal-replay',
	'journal-dry-run']

// sxj_verbs is the whole family — spliced into sx_verbs so the PEP and the
// known-verb gate see it.
const sxj_verbs = ['journal-read', 'journal-slice', 'journal-since', 'journal-query',
	'journal-verify', 'journal-verify-slice', 'journal-snapshot-verify', 'journal-fold',
	'journal-fold-slice', 'journal-replay', 'journal-dry-run']

// sxj_gate enforces the transcript-confirmed `store-journal` token (§4.3 —
// the family changes verb vocabulary, so it is transcript-bound; §3).
fn sxj_gate(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element) bool {
	if !c.confirmed_features.split(' ').contains('store-journal') {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_unsupported,
			'E_XSP_STORE_UNSUPPORTED: [${req.name}] is un-negotiated on this session — the transcript did not confirm store-journal (§4.3)'))
		return false
	}
	return true
}

fn sxj_int(n i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(n)
		data_type: cx.ScalarType.int_type
	}
}

// sxj_attach_ro attaches the verb's journal tenant on the mount, READ-ONLY.
// The handle is per-request (closed by the caller via sxj_close).
fn sxj_attach_ro(local cx.Node, tenant string) ?cx.Node {
	opts := cx.Node(cx.Element{
		name:  code.map_marker_name
		items: [session_kv('read-only', bus_str('true'))]
	})
	h := jrn_attach([local, store_str(tenant), opts])?
	return h
}

fn sxj_close(handle cx.Node) {
	jrn_close([handle]) or {}
}

// sxj_image renders one node as the framed-ast_bin `::bytes` hex the §4.1
// body lane uses (the get/iter imaging, applied to journal values).
fn sxj_image(n cx.Node) string {
	bin := cx.emit_ast_bin(cx.Document{
		elements: [n]
	})
	return bin.hex()
}

// sxj_decode_value extracts a `[<name>::bytes 0x…]` child and decodes the
// framed ast_bin document's single element as the carried VALUE.
fn sxj_decode_value(req cx.Element, name string) ?cx.Node {
	b := sx_bytes_child(req, name)?
	doc := cx.bin_to_doc(b) or { return none }
	if doc.elements.len == 0 {
		return none
	}
	return doc.elements[0]
}

// sxj_tenant reads the mandatory tenant= and refuses the empty form.
fn sxj_tenant(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element) ?string {
	t := req.attr('tenant')
	if t == '' {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: ${req.name} needs tenant= (the journal tenant within the attached mount)'))
		return none
	}
	return t
}

// sxj_send_result answers an op result: err values cross VERBATIM (§4.1
// error transparency; the engine's CXER0273 budget refusal answers as the
// profile's own CXER5024 row — the budget is the PROFILE's rule, §4.3);
// non-err results go through `image` to the reply envelope.
fn sxj_send_result(mut srv StoreXspServer, mut c SxConn, stream i64, r cx.Node, envelope fn (cx.Node) string) {
	if is_err_value(r) {
		if r is cx.Element {
			code_attr := sw_attr(r, 'code')
			if code_attr == 'cx-err:CXER0273' {
				msg := sw_attr(r, 'message')
				conjunct := if msg.contains('memory') { ':memory' } else { ':steps' }
				sx_error_locked(mut srv, c.id, stream, cx.Node(cx.Element{
					name: 'err'
					attrs: [
						cx.Attribute{
							name:  'code'
							value: cx.ScalarValue(sxj_err_budget)
						},
						cx.Attribute{
							name:  'message'
							value: cx.ScalarValue('E_XSP_STORE_PUSHDOWN_BUDGET: ${msg}')
						},
						cx.Attribute{
							name:  'conjunct'
							value: cx.ScalarValue(conjunct)
						},
					]
				}))
				return
			}
		}
		sx_error_locked(mut srv, c.id, stream, r)
		return
	}
	sx_reply_locked(mut srv, c.id, stream, envelope(r))
}

// sxj_load_fn discharges the F3(a) carriage for a compute verb: fetch the
// fn document (verifying blob read), enforce the defs-only program shape,
// resolve the entry def, RECOMPUTE the computation-identity claim and refuse
// a mismatch, then register the defs in a FRESH env armed with the F4
// budget. Returns (fv sentinel, armed env) or none after answering the
// refusal itself.
fn sxj_load_fn(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node) ?(cx.Node, code.MatchEnv) {
	fnaddr := req.attr('fn')
	claim := req.attr('claim')
	if fnaddr == '' || claim == '' {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: ${req.name} needs fn= (the def document address) and claim= (computes-as:<algo>:<hex>) — §4.3/F3'))
		return none
	}
	cx.cx_parse_tagged_address(fnaddr) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_address,
			'E_XSP_STORE_ADDRESS: fn=: ${err.msg()}'))
		return none
	}
	if !claim.starts_with('computes-as:') {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
			'E_XSP_STORE_WIRE: claim= must be the computation-identity claim form computes-as:<algo>:<hex> (§4.3/F3)'))
		return none
	}
	r := store_stdlib_builtin_inner('store-get-blob', [local, store_str(fnaddr)]) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
			'E_XSP_STORE_INTERNAL: fn document read failed'))
		return none
	}
	if is_err_value(r) {
		// absence and integrity faults cross VERBATIM (CXER1121 / CXER1120)
		sx_error_locked(mut srv, c.id, stream, r)
		return none
	}
	src := sw_scalar(r)
	if src == '' {
		sx_error_locked(mut srv, c.id, stream, mk_err(sxj_err_fn,
			'E_XSP_STORE_PUSHDOWN_FN: the fn document is empty'))
		return none
	}
	entry, hash := code.cx_program_entry_computation_id(src, req.attr('entry')) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sxj_err_fn,
			'E_XSP_STORE_PUSHDOWN_FN: ${err.msg()}'))
		return none
	}
	if 'computes-as:${hash}' != claim {
		sx_error_locked(mut srv, c.id, stream, mk_err(sxj_err_claim,
			'E_XSP_STORE_PUSHDOWN_CLAIM: the recomputed computation identity of entry `${entry}` is computes-as:${hash}, not the claimed ${claim} — refusing (tamper / version-skew guard, §4.3/F3)'))
		return none
	}
	// Fresh env, F4 budget armed BEFORE any evaluation — def registration
	// itself runs under the budget (defs-only, so registration evaluates
	// no user expressions and reaches no effect).
	mut env := code.new_env()
	code.arm_eval_budget(mut env, srv.cfg.pushdown_steps, srv.cfg.pushdown_mem_mb * 1024 * 1024)
	prog := cx.parse_program(src) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sxj_err_fn,
			'E_XSP_STORE_PUSHDOWN_FN: the fn document does not parse as a program: ${err.msg()}'))
		return none
	}
	code.eval(prog.body, mut env) or {
		if err.msg().contains('CXER0273') {
			sx_error_locked(mut srv, c.id, stream, mk_err(sxj_err_budget,
				'E_XSP_STORE_PUSHDOWN_BUDGET: ${err.msg()}'))
			return none
		}
		sx_error_locked(mut srv, c.id, stream, mk_err(sxj_err_fn,
			'E_XSP_STORE_PUSHDOWN_FN: registering the fn document failed: ${err.msg()}'))
		return none
	}
	return mk_closure_sentinel(entry), env
}

// sxj_reply_verb serves the eight request→reply family verbs. Caller holds
// the mount op lock (the same serialization every store verb rides — and
// what makes the F4 memory meter attributable to ONE evaluation, §4.3).
fn sxj_reply_verb(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node) {
	if !sxj_gate(mut srv, mut c, stream, req) {
		return
	}
	tenant := sxj_tenant(mut srv, mut c, stream, req) or { return }
	handle := sxj_attach_ro(local, tenant) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
			'E_XSP_STORE_INTERNAL: journal attach failed'))
		return
	}
	if is_err_value(handle) {
		sx_error_locked(mut srv, c.id, stream, handle)
		return
	}
	defer {
		sxj_close(handle)
	}
	strm := req.attr('stream')
	match req.name {
		'journal-read' {
			seqs := req.attr('seq')
			if seqs == '' {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: journal-read needs seq='))
				return
			}
			mut args := [handle, sxj_int(seqs.i64())]
			if strm != '' {
				args << bus_str(strm)
			}
			r := jrn_read(args) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: read failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			if r is cx.Element && r.name == 'entry' {
				sx_reply_locked(mut srv, c.id, stream, '[entry-result present=true [body::bytes 0x${sxj_image(r)}]]')
				return
			}
			// §2.5: out-of-range is the ABSENCE channel — data, never an error
			sx_reply_locked(mut srv, c.id, stream, '[entry-result present=false]')
		}
		'journal-verify' {
			mut opts_items := []cx.Node{}
			if req.has_attr('from') {
				opts_items << session_kv('from', sxj_int(req.attr('from').i64()))
			}
			if req.has_attr('to') {
				opts_items << session_kv('to', sxj_int(req.attr('to').i64()))
			}
			if strm != '' {
				opts_items << session_kv('stream', bus_str(strm))
			}
			opts := cx.Node(cx.Element{
				name:  code.map_marker_name
				items: opts_items
			})
			r := jrn_verify([handle, opts]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: verify failed'))
				return
			}
			// the [verification …] value rides VERBATIM — valid=false is a
			// FINDING (data), never an error frame (§3.6)
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, render_canonical(r))
		}
		'journal-verify-slice' {
			if !req.has_attr('from') || !req.has_attr('to') {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: journal-verify-slice needs from= and to='))
				return
			}
			mut args := [handle, sxj_int(req.attr('from').i64()), sxj_int(req.attr('to').i64())]
			if strm != '' {
				args << bus_str(strm)
			}
			r := jrn_verify_slice(args) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: verify-slice failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, render_canonical(r))
		}
		'journal-snapshot-verify' {
			snap := sxj_decode_value(req, 'snapshot') or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
					'E_XSP_STORE_BODY: journal-snapshot-verify needs a [snapshot::bytes 0x…] child (framed ast_bin)'))
				return
			}
			r := jrn_snapshot_verify([handle, snap]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: snapshot-verify failed'))
				return
			}
			if is_err_value(r) {
				sx_error_locked(mut srv, c.id, stream, r)
				return
			}
			sx_reply_locked(mut srv, c.id, stream, render_canonical(r))
		}
		'journal-fold', 'journal-fold-slice', 'journal-replay', 'journal-dry-run' {
			fv, env0 := sxj_load_fn(mut srv, mut c, stream, req, local) or { return }
			mut env := env0
			init := sxj_decode_value(req, 'init') or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
					'E_XSP_STORE_BODY: ${req.name} needs an [init::bytes 0x…] child (framed ast_bin)'))
				return
			}
			head := sw_attr(handle as cx.Element, 'head-seq').i64()
			match req.name {
				'journal-fold' {
					mut args := [handle, fv, init]
					if strm != '' {
						args << bus_str(strm)
					}
					r := journal_stdlib_builtin_env('journal-fold', args, mut env) or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
							'E_XSP_STORE_INTERNAL: fold failed'))
						return
					}
					sxj_send_result(mut srv, mut c, stream, r, fn [head] (n cx.Node) string {
						return '[fold-result to-seq=${head} [state::bytes 0x${sxj_image(n)}]]'
					})
				}
				'journal-fold-slice' {
					if !req.has_attr('from') || !req.has_attr('to') {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
							'E_XSP_STORE_WIRE: journal-fold-slice needs from= and to='))
						return
					}
					from := req.attr('from').i64()
					to := req.attr('to').i64()
					mut args := [handle, fv, init, sxj_int(from), sxj_int(to)]
					if strm != '' {
						args << bus_str(strm)
					}
					r := journal_stdlib_builtin_env('journal-fold-slice', args, mut env) or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
							'E_XSP_STORE_INTERNAL: fold-slice failed'))
						return
					}
					sxj_send_result(mut srv, mut c, stream, r, fn [from, to] (n cx.Node) string {
						return '[fold-result from=${from} to-seq=${to} [state::bytes 0x${sxj_image(n)}]]'
					})
				}
				'journal-replay' {
					mut opts_items := []cx.Node{}
					if req.has_attr('from') {
						opts_items << session_kv('from', sxj_int(req.attr('from').i64()))
					}
					if req.has_attr('to') {
						opts_items << session_kv('to', sxj_int(req.attr('to').i64()))
					}
					if req.has_attr('at-seq') {
						opts_items << session_kv('at-seq', sxj_int(req.attr('at-seq').i64()))
					}
					if strm != '' {
						opts_items << session_kv('stream', bus_str(strm))
					}
					opts := cx.Node(cx.Element{
						name:  code.map_marker_name
						items: opts_items
					})
					r := journal_stdlib_builtin_env('journal-replay', [handle, fv, init, opts], mut env) or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
							'E_XSP_STORE_INTERNAL: replay failed'))
						return
					}
					sxj_send_result(mut srv, mut c, stream, r, fn [head] (n cx.Node) string {
						return '[replay-result to-seq=${head} [state::bytes 0x${sxj_image(n)}]]'
					})
				}
				'journal-dry-run' {
					event := sxj_decode_value(req, 'event') or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
							'E_XSP_STORE_BODY: journal-dry-run needs an [event::bytes 0x…] child'))
						return
					}
					attribution := sxj_decode_value(req, 'attribution') or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_body,
							'E_XSP_STORE_BODY: journal-dry-run needs an [attribution::bytes 0x…] child (a map with actor + authority)'))
						return
					}
					r := journal_stdlib_builtin_env('journal-dry-run', [handle, event, attribution,
						fv, init], mut env) or {
						sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
							'E_XSP_STORE_INTERNAL: dry-run failed'))
						return
					}
					sxj_send_result(mut srv, mut c, stream, r, fn (n cx.Node) string {
						// [dry-run [state <projected>] [entry …]] decomposes to
						// the spec'd two-body reply (§4.3)
						mut state_hex := ''
						mut prov_hex := ''
						if n is cx.Element {
							for it in n.items {
								if it is cx.Element && it.name == 'state' && it.items.len > 0 {
									state_hex = sxj_image(it.items[0])
								}
								if it is cx.Element && it.name == 'entry' {
									prov_hex = sxj_image(it)
								}
							}
						}
						return '[dry-run-result [state::bytes 0x${state_hex}] [provisional-entry::bytes 0x${prov_hex}]]'
					})
				}
				else {}
			}
		}
		else {}
	}
}

// sxj_stream_items materializes the three streamed family verbs' result sets
// for the shared credit-governed stream tail (sx_stream_start_locked). none
// = the handler already answered a refusal.
fn sxj_stream_items(mut srv StoreXspServer, mut c SxConn, stream i64, req cx.Element, local cx.Node) ?[]string {
	if !sxj_gate(mut srv, mut c, stream, req) {
		return none
	}
	tenant := sxj_tenant(mut srv, mut c, stream, req) or { return none }
	handle := sxj_attach_ro(local, tenant) or {
		sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
			'E_XSP_STORE_INTERNAL: journal attach failed'))
		return none
	}
	if is_err_value(handle) {
		sx_error_locked(mut srv, c.id, stream, handle)
		return none
	}
	defer {
		sxj_close(handle)
	}
	strm := req.attr('stream')
	mut r := cx.Node(cx.Element{})
	match req.name {
		'journal-slice' {
			if !req.has_attr('from') || !req.has_attr('to') {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: journal-slice needs from= and to='))
				return none
			}
			mut args := [handle, sxj_int(req.attr('from').i64()), sxj_int(req.attr('to').i64())]
			if strm != '' {
				args << bus_str(strm)
			}
			r = jrn_slice(args) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: slice failed'))
				return none
			}
		}
		'journal-since' {
			if !req.has_attr('from') {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: journal-since needs from='))
				return none
			}
			mut args := [handle, sxj_int(req.attr('from').i64())]
			if strm != '' {
				args << bus_str(strm)
			}
			r = jrn_since(args) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: since failed'))
				return none
			}
		}
		'journal-query' {
			path := req.attr('path')
			if path == '' {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_wire,
					'E_XSP_STORE_WIRE: journal-query needs path='))
				return none
			}
			r = jrn_query([handle, bus_str(path)]) or {
				sx_error_locked(mut srv, c.id, stream, mk_err(sx_err_internal,
					'E_XSP_STORE_INTERNAL: query failed'))
				return none
			}
		}
		else {
			return none
		}
	}
	if is_err_value(r) {
		sx_error_locked(mut srv, c.id, stream, r)
		return none
	}
	// entries in seq order, one [entry [body::bytes …]] per frame (§4.3 —
	// the iter imaging applied to journal entries)
	mut items := []string{}
	if r is cx.Element {
		for it in r.items {
			if it is cx.Element && it.name == 'entry' {
				items << '[entry [body::bytes 0x${sxj_image(it)}]]'
			}
		}
	}
	return items
}
