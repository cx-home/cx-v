module platform

import cx
import code { MatchEnv, mk_err }

// journal_ingest.v — stream 9 (#681; distributed_store.md §2, ruling L173):
// replica-local stream ingestion — the journal half of sync. A replica's
// named stream joins the destination tenant as a DISJOINT AGGREGATE: no
// sequencer is consulted (tenant state is the caller's order-independent
// composition of per-stream folds), and every entry re-lands
// BYTE-IDENTICAL — the entry hash survives, so the chain verifies
// unchanged at the destination. `append` re-hashes by design (new
// seq/ts/prev-hash — an entry hash MUST NOT survive re-append); the
// identity-preserving path is ONLY this verb, and only into a stream key
// that is NEW to the destination or a clean prefix extension of what it
// already holds.
//
// Refusals (the CXER5050–5069 sync band, governance §9.6):
//   CXER5050 E_SYNC_STREAM_DIVERGENT — the destination already holds the
//     stream key with a DIFFERENT chain (a replica stream is a new
//     aggregate, never a merge into an origin stream — the §2 grounds).
//   CXER5051 E_SYNC_CHAIN_INVALID — the source chain fails verification,
//     has a gap, or is compacted below seq 1 (v1 ingests FULL chains;
//     compaction-aware seeding rides the retention wave, L177).
//   CXER5052 E_SYNC_STREAM_RESERVED — the default stream or a reserved
//     `cx:*` stream named as the ingest target: an origin's own stream
//     and the hold/erasure evidence streams are never ingest targets
//     (shred records reach replicas as feed data — stream 20's §6
//     handoff; a hand-ingested evidence stream would forge the M29
//     basis exactly like a hand-authored append, CXER4622's rationale).
//
// Payload docs ride along when present at the source and absent at the
// destination (content-addressed — the copy is a dedup no-op when the
// transfer verbs already moved them). A payload lawfully gone at the
// source (stream 20: chains verify with payloads destroyed) is NOT an
// ingest failure — the entry lands, the address stays covered by the
// evidence the erasure machinery replicates, and the count is visible on
// the report (`payloads-absent=`, emitted only when non-zero — the L119
// posture).

const sync_err_divergent = 'cx-err:CXER5050'
const sync_err_chain_invalid = 'cx-err:CXER5051'
const sync_err_reserved = 'cx-err:CXER5052'

fn jrn_ingest_stream(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: ingest-stream expects (journal, source-journal, stream)')
	}
	mut jd, derr, dok := jrn_get_open(args[0])
	if !dok {
		return derr
	}
	mut js, serr, sok := jrn_get_open(args[1])
	if !sok {
		return serr
	}
	stream := jrn_opt_stream(args, 2)
	if jrn_is_default(stream) || stream.starts_with('cx:') {
		return mk_err(sync_err_reserved, 'E_SYNC_STREAM_RESERVED: `${stream}` is not an ingest target — the default stream is the destination\'s own aggregate, and reserved cx:* streams are evidence surfaces whose records propagate on the feed (distributed_store §2; erasure_compliance §7)')
	}
	if jd.tenant != js.tenant {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: ingest-stream crosses tenants (`${jd.tenant}` ← `${js.tenant}`) — a stream key names an aggregate within ONE tenant')
	}
	// ── source chain: full, gapless, verified ─────────────────────────────
	jrn_refresh_head(mut js, stream)
	sst := js.named[stream] or { return jrn_empty() } // unknown stream → absence
	if sst.head_seq < 1 {
		return jrn_empty()
	}
	if sst.base_seq > 0 {
		return mk_err(sync_err_chain_invalid, 'E_SYNC_CHAIN_INVALID: source stream `${stream}` is compacted below seq 1 (base ${sst.base_seq}) — v1 ingests full chains; retention-anchored seeding is the sync surface\'s (distributed_store §5)')
	}
	mut texts := []string{cap: sst.head_seq}
	for s in 1 .. sst.head_seq + 1 {
		t := jrn_state_entry_text(sst, s) or {
			// #628 store fallback: a sibling handle's appends live in the
			// store but not this instance's cache.
			dh := jrn_store_get_alias(js.store_id, jrn_entry_alias_s(js.tenant, stream,
				s)) or {
				return mk_err(sync_err_chain_invalid, 'E_SYNC_CHAIN_INVALID: source stream `${stream}` has no entry at seq ${s} (gap)')
			}
			jrn_store_get_doc_text(js.store_id, dh) or {
				return mk_err(sync_err_chain_invalid, 'E_SYNC_CHAIN_INVALID: source stream `${stream}` entry doc unreadable at seq ${s}')
			}
		}
		texts << t
	}
	vst := StreamState{
		head_seq:  sst.head_seq
		head_hash: sst.head_hash
		base_seq:  0
		entries:   texts
	}
	v := jrn_walk_verify_state(&vst, js.hash_algo, 1, sst.head_seq, jrn_genesis_prev)
	if jrn_entry_attr_of(v) != 'true' {
		reason := if v is cx.Element { v.attr('reason') } else { '' }
		bad := if v is cx.Element { v.attr('broken-at') } else { '' }
		return mk_err(sync_err_chain_invalid, 'E_SYNC_CHAIN_INVALID: source stream `${stream}` fails verification at seq ${bad} (${reason}) — an unverifiable chain never lands')
	}
	src_hash_at := fn [texts] (seq int) string {
		e := jrn_parse_entry(texts[seq - 1]) or { return '' }
		return jrn_entry_attr(e, 'hash')
	}
	// ── destination: new stream, clean prefix, or divergence ─────────────
	jrn_refresh_head(mut jd, stream)
	mut dst_head := 0
	mut dst_head_hash := ''
	if dst_st := jd.named[stream] {
		dst_head = dst_st.head_seq
		dst_head_hash = dst_st.head_hash
	}
	if dst_head > 0 {
		if dst_head >= sst.head_seq {
			// Destination at-or-ahead: the source must be a prefix of it.
			dtext := jrn_ingest_dst_entry_text(jd, stream, sst.head_seq) or {
				return mk_err(sync_err_divergent, 'E_SYNC_STREAM_DIVERGENT: destination holds `${stream}` to seq ${dst_head} but its entry at ${sst.head_seq} is unreadable — cannot establish the prefix')
			}
			de := jrn_parse_entry(dtext) or {
				return mk_err(sync_err_divergent, 'E_SYNC_STREAM_DIVERGENT: destination entry at seq ${sst.head_seq} unparsable')
			}
			if jrn_entry_attr(de, 'hash') != sst.head_hash {
				return mk_err(sync_err_divergent, 'E_SYNC_STREAM_DIVERGENT: `${stream}` exists at the destination with a different chain (dst hash at ${sst.head_seq} ≠ source head) — a replica stream is a new aggregate, never a merge into an origin stream (distributed_store §2)')
			}
			return jrn_ingest_report(stream, sst.head_seq, 0, sst.head_seq, dst_head,
				dst_head_hash, 0)
		}
		if src_hash_at(dst_head) != dst_head_hash {
			return mk_err(sync_err_divergent, 'E_SYNC_STREAM_DIVERGENT: `${stream}` exists at the destination with a different chain (source hash at ${dst_head} ≠ dst head) — a replica stream is a new aggregate, never a merge into an origin stream (distributed_store §2)')
		}
	}
	// ── land the tail under ONE durable scope (the append discipline) ────
	mut msh := store_lookup(jd.store_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: destination store handle gone')
	}
	store_flush_hold(mut msh)
	mut ingested := 0
	mut payloads_absent := 0
	for s in dst_head + 1 .. sst.head_seq + 1 {
		e := jrn_parse_entry(texts[s - 1]) or {
			store_flush_release(mut msh) or {}
			return mk_err(sync_err_chain_invalid, 'E_SYNC_CHAIN_INVALID: source entry at seq ${s} unparsable')
		}
		// Payload doc: copy when the source still holds it and the
		// destination does not (content-addressed — a dedup no-op when the
		// transfer verbs already moved it). Lawfully-gone payloads land
		// their entry regardless (the chain covers the ADDRESS — L184).
		paddr := jrn_entry_attr(e, 'payload')
		if paddr != '' {
			if jrn_store_get_doc_text(jd.store_id, paddr) == none {
				if ptext := jrn_store_get_doc_text(js.store_id, paddr) {
					pdoc := cx.parse(ptext) or { cx.Document{} }
					if pdoc.elements.len > 0 {
						jrn_store_put_doc(jd.store_id, pdoc.elements[0]) or {
							store_flush_release(mut msh) or {}
							return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: payload doc write failed at seq ${s}')
						}
					}
				} else {
					payloads_absent++
				}
			}
		}
		dhash := jrn_store_put_doc(jd.store_id, cx.Node(e)) or {
			store_flush_release(mut msh) or {}
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: entry doc write failed at seq ${s}')
		}
		if werr := jrn_store_set_alias(jd.store_id, jrn_entry_alias_s(jd.tenant, stream,
			s), dhash)
		{
			store_flush_release(mut msh) or {}
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: entry pointer write failed at seq ${s}',
				werr)
		}
		ingested++
	}
	if werr := jrn_set_meta_alias(jd.store_id, jrn_head_alias_s(jd.tenant, stream), jrn_head_doc(sst.head_seq,
		sst.head_hash))
	{
		store_flush_release(mut msh) or {}
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: head advance failed',
			werr)
	}
	if dst_head == 0 {
		if werr := jrn_index_stream(jd.store_id, jd.tenant, stream) {
			store_flush_release(mut msh) or {}
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: stream index write failed',
				werr)
		}
	}
	store_flush_release(mut msh) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: durable flush failed: ${err.msg()}')
	}
	// In-memory state: keep the contiguous cache honest (the #628 rule —
	// only extend when gap-free from base_seq).
	mut st := jrn_named_state(mut jd, stream)
	for s in dst_head + 1 .. sst.head_seq + 1 {
		if st.base_seq + st.entries.len == s - 1 {
			st.entries << texts[s - 1]
		}
	}
	st.head_seq = sst.head_seq
	st.head_hash = sst.head_hash
	return jrn_ingest_report(stream, sst.head_seq, ingested, sst.head_seq - ingested,
		sst.head_seq, sst.head_hash, payloads_absent)
}

// jrn_ingest_dst_entry_text reads a destination entry with the #628 store
// fallback (a sibling handle's appends live in the store, not this cache).
fn jrn_ingest_dst_entry_text(j &Journal, stream string, seq int) ?string {
	if st := j.named[stream] {
		if t := jrn_state_entry_text(st, seq) {
			return t
		}
	}
	dh := jrn_store_get_alias(j.store_id, jrn_entry_alias_s(j.tenant, stream, seq))?
	return jrn_store_get_doc_text(j.store_id, dh)
}

// jrn_entry_attr_of reads `valid=` off a verification node ('' when absent).
fn jrn_entry_attr_of(v cx.Node) string {
	if v is cx.Element {
		return v.attr('valid')
	}
	return ''
}

// jrn_ingest_report is the §9.1-shaped balanced account: entries = ingested
// + already-present; `payloads-absent` appears only when non-zero (L119).
fn jrn_ingest_report(stream string, entries int, ingested int, already int, head int, head_hash string, payloads_absent int) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		},
		cx.Attribute{
			name:  'entries'
			value: cx.ScalarValue(i64(entries))
		},
		cx.Attribute{
			name:  'ingested'
			value: cx.ScalarValue(i64(ingested))
		},
		cx.Attribute{
			name:  'already-present'
			value: cx.ScalarValue(i64(already))
		},
		cx.Attribute{
			name:  'head'
			value: cx.ScalarValue(i64(head))
		},
		cx.Attribute{
			name:  'hash'
			value: cx.ScalarValue(head_hash)
		},
	]
	if payloads_absent > 0 {
		attrs << cx.Attribute{
			name:  'payloads-absent'
			value: cx.ScalarValue(i64(payloads_absent))
		}
	}
	return cx.Node(cx.Element{
		name:  'ingest-report'
		attrs: attrs
	})
}

// ── W5: replica registration (register-or-refuse retention, L177) ──────────
//
// A replica MAY register at the origin, buying the retention hold under the
// extended cover rule (the stream-3 materialization-registration pattern —
// the SAME consultation at retain): a prune boundary above a registered
// replica's synced cursor refuses CXER4616 loud. The alternative is
// client-anchored (cheap, no origin state): a cursor below the compacted
// boundary gets the loud re-seed refusal the shipped machinery already
// gives (ingest CXER5051 on a compacted source; resume CXER4617; live
// CXER5073). Both spec'd; the deployment chooses.

fn jrn_replica_alias(tenant string, stream string, id string) string {
	if jrn_is_default(stream) {
		return 'cx-replica/${tenant}/${id}'
	}
	return 'cx-replica/${tenant}/s/${stream}/${id}'
}

fn jrn_register_replica(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: register-replica expects (journal, id, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	id := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: register-replica expects a string replica id')
	}
	if id == '' || id.contains('/') {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: replica id must be a non-empty name without `/`')
	}
	mut stream := ''
	mut seq := i64(0)
	if args.len > 2 {
		if v := jrn_map_get(args[2], 'stream') {
			stream = v
		}
		if v := jrn_map_get_int(args[2], 'seq') {
			seq = i64(v)
		}
	}
	reg := cx.Element{
		name:  'replica-registration'
		attrs: [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue(id)
			},
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(if jrn_is_default(stream) { ':default' } else { stream })
			},
			cx.Attribute{
				name:  'seq'
				value: cx.ScalarValue(seq)
			},
		]
	}
	dhash := jrn_store_put_doc(j.store_id, cx.Node(reg)) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: replica registration doc write failed')
	}
	if e := jrn_store_set_alias(j.store_id, jrn_replica_alias(j.tenant, stream, id), dhash) {
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: replica registration alias write failed',
			e)
	}
	return cx.Node(reg)
}

fn jrn_deregister_replica(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: deregister-replica expects (journal, id, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	id := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: deregister-replica expects a string replica id')
	}
	mut stream := ''
	if args.len > 2 {
		if v := jrn_map_get(args[2], 'stream') {
			stream = v
		}
	}
	mut ms := store_lookup(j.store_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: store handle gone')
	}
	existed := store_alias_delete_local(mut ms, jrn_replica_alias(j.tenant, stream, id))
	return cx.Node(cx.Element{
		name:  'deregistered'
		attrs: [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue(id)
			},
			cx.Attribute{
				name:  'existed'
				value: cx.ScalarValue(existed)
			},
		]
	})
}

// jrn_registered_replica_below finds a registered replica whose synced
// cursor sits BELOW the prune boundary — the retain refusal's evidence.
fn jrn_registered_replica_below(j &Journal, stream string, boundary int) ?(string, i64) {
	ms := store_lookup(j.store_id) or { return none }
	prefix := if jrn_is_default(stream) {
		'cx-replica/${j.tenant}/'
	} else {
		'cx-replica/${j.tenant}/s/${stream}/'
	}
	for k, dh in ms.aliases {
		if !k.starts_with(prefix) {
			continue
		}
		rest := k[prefix.len..]
		if jrn_is_default(stream) && rest.contains('/') {
			continue // a named-stream registration under /s/… — not this stream's
		}
		text := jrn_store_get_doc_text(j.store_id, dh) or { continue }
		doc := cx.parse(text) or { continue }
		if doc.elements.len == 0 {
			continue
		}
		reg := doc.elements[0]
		if reg is cx.Element {
			seq := reg.attr('seq').i64()
			if seq < i64(boundary) {
				return reg.attr('id'), seq
			}
		}
	}
	return none
}

// ── W5: the shred-reach worker (stream 20's joint requirement) ─────────────
//
// [$journal:apply-erasures $replica $origin]: consume the origin's
// journaled shred-requests (the reserved cx:erasure stream) and execute the
// REPLICA'S OWN local shred walk per record — each application is the
// replica's own erase-subject command under the SAME (subject,
// request-token) key, so it journals the replica's own attributed record,
// emits the replica's own balanced report, and is idempotent (a record
// already applied answers [deduped …]). A record refused at the replica
// (a LOCAL legal hold — hold-beats-shred holds here too) is a LOUD [held]
// child, never a skip: held= > 0 means the fleet has not converged.
fn jrn_apply_erasures(args []cx.Node, mut env code.MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: apply-erasures expects (journal, origin)')
	}
	jr, rerr, rok := jrn_get_open(args[0])
	if !rok {
		return rerr
	}
	mut jo, oerr, ook := jrn_get_open(args[1])
	if !ook {
		return oerr
	}
	if jr.tenant != jo.tenant {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: apply-erasures crosses tenants (`${jr.tenant}` ← `${jo.tenant}`)')
	}
	jrn_refresh_head(mut jo, jrn_erase_stream)
	ost := jo.named[jrn_erase_stream] or {
		return jrn_apply_erasures_report(0, 0, 0, []cx.Node{})
	}
	mut applied := 0
	mut deduped := 0
	mut held := 0
	mut children := []cx.Node{}
	mut records := 0
	for seqn in 1 .. ost.head_seq + 1 {
		items := jrn_state_collect_range_of(jo, jrn_erase_stream, ost, seqn, seqn)
		if items.len == 0 {
			continue
		}
		entry := items[0]
		if entry !is cx.Element {
			continue
		}
		ee := entry as cx.Element
		mut payload := cx.Element{}
		for ch in ee.items {
			if ch is cx.Element && ch.name == 'event' && ch.items.len > 0 {
				p := ch.items[0]
				if p is cx.Element {
					payload = p
				}
			}
		}
		if payload.name != 'erase-subject' {
			continue
		}
		records++
		subject := jrn_erase_child_text(payload, 'subject')
		request := jrn_erase_child_text(payload, 'request')
		actor := jrn_entry_attr(ee, 'actor')
		authority := jrn_entry_attr(ee, 'authority')
		attribution := cx.Node(cx.Element{
			name:  'map'
			items: [
				cx.Node(cx.Element{
					name:  'actor'
					items: [jrn_str(actor)]
				}),
				cx.Node(cx.Element{
					name:  'authority'
					items: [jrn_str(authority)]
				}),
			]
		})
		opts := cx.Node(cx.Element{
			name:  'map'
			items: [
				cx.Node(cx.Element{
					name:  'request'
					items: [jrn_str(request)]
				}),
			]
		})
		// DIRECT-INNER call (the #779 discipline): the env dispatch wrapper
		// holds this journal's jmu for the WHOLE apply — re-dispatching
		// through it would self-deadlock (non-reentrant mutex); the lock we
		// already hold is exactly the erase-subject serialization.
		r := jrn_erase_subject([args[0],
			cx.Node(cx.ScalarNode{
				value:     cx.ScalarValue(subject)
				data_type: cx.ScalarType.string_type
			}), attribution, opts], mut env) or { cx.Node(cx.ScalarNode{}) }
		if r is cx.Element {
			match r.name {
				'deduped' {
					deduped++
					children << cx.Node(r)
				}
				'shred-report' {
					applied++
					children << cx.Node(r)
				}
				'err' {
					held++
					children << cx.Node(cx.Element{
						name:  'held'
						attrs: [
							cx.Attribute{
								name:  'subject'
								value: cx.ScalarValue(subject)
							},
							cx.Attribute{
								name:  'request'
								value: cx.ScalarValue(request)
							},
							cx.Attribute{
								name:  'code'
								value: cx.ScalarValue(r.attr('code'))
							},
						]
					})
				}
				else {
					children << cx.Node(r)
				}
			}
		}
	}
	return jrn_apply_erasures_report(records, applied, deduped, children, held)
}

fn jrn_apply_erasures_report(records int, applied int, deduped int, children []cx.Node, held ...int) cx.Node {
	h := if held.len > 0 { held[0] } else { 0 }
	mut attrs := [
		cx.Attribute{
			name:  'records'
			value: cx.ScalarValue(i64(records))
		},
		cx.Attribute{
			name:  'applied'
			value: cx.ScalarValue(i64(applied))
		},
		cx.Attribute{
			name:  'deduped'
			value: cx.ScalarValue(i64(deduped))
		},
	]
	if h > 0 {
		attrs << cx.Attribute{
			name:  'held'
			value: cx.ScalarValue(i64(h))
		}
	}
	return cx.Node(cx.Element{
		name:  'erasure-sync'
		attrs: attrs
		items: children
	})
}
