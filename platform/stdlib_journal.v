@[has_globals]
module platform
import code {
	MatchEnv,
	apply_fn_value,
	builtin_is_impure,
	crypto_random_octets,
	decode_datetime,
	err_to_node,
	idem_drop_keys,
	idem_matching_keys,
	is_err_value,
	iterate,
	mk_err,
	node_calls_impure_builtin,
	render_canonical,
	resolve_closure,
	select_path_on_node,
	time_datetime_node,
}

import cx
import crypto.ed25519
import sync
import time

// stdlib_journal.v — native primitives + in-process chain state for the
// `cx-stdlib/journal` append-only, hash-chained, tenant-partitioned event
// log + fold→state (spec/02-inprogress/xap/stdlib_journal.md).
//
// journal is a THIN module (N-IMPL-1): ordered append + fold + verify, built
// ON TOP of the shipped cx-stdlib/store (persistence) + cx-stdlib/hash (chain
// links) + cx-stdlib/crypto (snapshot signing). It adds NO new persistence,
// digest, or signing mechanism, and NO new capability — persistence is gated
// by store's existing capability model (a file:// journal needs read/write;
// mem:// is capability-free; remote needs net).
//
// STATE MODEL. A journal is mutable in-process state (an append advances a
// commit lock + head), which cannot be expressed as a pure CX value (CX
// values are immutable). So — exactly like stdlib_store.v — each open journal
// is a heap Journal registered in a process-global registry and referenced by
// an integer handle carried on the returned `[journal handle=N …]` element.
// The chain head (head-seq / head-hash) lives in the registry; append's "new
// tail" is modelled by mutating the registry record + persisting through the
// underlying store, never by in-place mutation of a CX value. Entries are
// persisted as docs in the underlying store (so a file:// journal survives
// across opens); the registry also caches the in-`seq`-order entry list so a
// read need not round-trip the store.
//
// FOUR-CHANNEL MODEL (code.md §9.1.2, spec §2.4–§2.5):
//   committed entry      → a present [entry] VALUE (value channel)
//   failed-precondition  → [err] (failure channel: stale-tail/closed/denied)
//   empty/out-of-range   → absence (empty node-set `()`), NEVER null
//   verify-invalid       → a present [verification valid=false …] VALUE (a
//                          FINDING, not a fault — SAP §1)
//
// The $fn-taking verbs (fold / fold-slice / fold-value / replay / dry-run /
// snapshot / fold-from) invoke a CX callable and MUST enforce its purity
// (CXER4611). They cannot route through the env-less stdlib_builtin chain;
// they are reached via journal_stdlib_builtin_env(name, args, mut env) from
// the env-aware dispatch path in eval.v (alongside fp/validate/prof/http),
// applying the callable with apply_fn_value and asserting purity with
// node_calls_impure_builtin over the closure body. Every other verb routes
// through the env-free journal_stdlib_builtin(name, args) chain in
// stdlib_dispatch.v.

// ── error band CXER4600–4649 (spec §8) ───────────────────────────────────

const jrn_err_open_failed     = 'cx-err:CXER4600' // E_JOURNAL_OPEN_FAILED
const jrn_err_not_found       = 'cx-err:CXER4601' // E_JOURNAL_NOT_FOUND
const jrn_err_algo_mismatch   = 'cx-err:CXER4602' // E_JOURNAL_ALGO_MISMATCH
const jrn_err_read_only       = 'cx-err:CXER4603' // E_JOURNAL_READ_ONLY
const jrn_err_stale_tail      = 'cx-err:CXER1114' // E_STORE_REF_CONFLICT (I1 row 15 / audit M21: CXER4604 RETIRED — optimistic-concurrency conflicts unify on the ONE ref-conflict code)
const jrn_err_chain_broken    = 'cx-err:CXER4605' // E_JOURNAL_CHAIN_BROKEN
const jrn_err_seq_out_range   = 'cx-err:CXER4606' // E_JOURNAL_SEQ_OUT_OF_RANGE
const jrn_err_hash_unsupported = 'cx-err:CXER4607' // E_JOURNAL_HASH_UNSUPPORTED
const jrn_err_event_unser     = 'cx-err:CXER4608' // E_JOURNAL_EVENT_UNSERIALIZABLE
const jrn_err_attr_invalid    = 'cx-err:CXER4609' // E_JOURNAL_ATTRIBUTION_INVALID
const jrn_err_arg_invalid     = 'cx-err:CXER4610' // E_JOURNAL_ARG_INVALID
const jrn_err_fold_impure     = 'cx-err:CXER4611' // E_JOURNAL_FOLD_IMPURE
const jrn_err_closed          = 'cx-err:CXER4612' // E_JOURNAL_CLOSED
const jrn_err_snap_sig        = 'cx-err:CXER4613' // E_JOURNAL_SNAPSHOT_SIG_INVALID
const jrn_err_snap_unsigned   = 'cx-err:CXER4614' // E_JOURNAL_SNAPSHOT_UNSIGNED
const jrn_err_snap_seq        = 'cx-err:CXER4615' // E_JOURNAL_SNAPSHOT_SEQ_MISMATCH
const jrn_err_retention       = 'cx-err:CXER4616' // E_JOURNAL_RETENTION_UNCOVERED

// I1 stream 19 (L38): the algo-neutral genesis sentinel — 'b3:GENESIS' was
// a blake3-tagged literal emitted on sha256 chains.
const jrn_genesis_prev = 'genesis:' // genesis sentinel prev-hash (§4.2)

// I1 stream 19 (L35): multiformats registry names — one registry everywhere.
const jrn_supported_algos = ['sha2-256', 'sha2-384', 'sha2-512', 'blake3']

// ── registry ──────────────────────────────────────────────────────────────

// Journal is the in-process state for one open `[journal]` handle. The chain
// head (head_seq / head_hash) + the in-`seq`-order entry texts live here; the
// commit lock is the single-threaded mutation discipline (§2.1). `store_id`
// is the underlying store handle (mem:// or file://); `owns_store` records
// whether `close` should also close the store (an `open` owns it; an `attach`
// does not — §3.1).
@[heap]
struct Journal {
mut:
	tenant     string
	hash_algo  string
	read_only  bool
	is_open    bool
	store_id   int
	owns_store bool
	head_seq   int
	head_hash  string
	// base_seq is the seq BEFORE the first cached entry: entries[i] is the
	// canonical doc text of the entry at seq = base_seq + 1 + i. A genesis
	// chain has base_seq=0 (entries[0] is seq=1). A COMPACTED segment starts at
	// the retention boundary B, so base_seq=B and entries[0] is seq=B+1 — the
	// seam (§4.10). The seam entry's prev-hash anchors to the snapshot anchor.
	base_seq int
	// seam_anchor is the prev-hash the first cached entry must link to: the
	// genesis sentinel for a fresh chain, or the snapshot anchor-hash at a
	// compaction seam (§4.10).
	seam_anchor string
	entries     []string
	// named holds the per-aggregate streams (§2.1.1). The flat fields above are
	// the `:default` stream and remain byte-identical to the pre-stream module;
	// every NAMED stream is its own independent chain here, keyed by stream name.
	// A stream is the unit of contention/ordering — disjoint streams are
	// independent chains with their own seq/head (R2, stdlib_journal.md §2.1.1).
	named map[string]&StreamState
	// jmu serializes ALL ops on THIS journal instance (#642): the entries
	// cache, head state, and named-stream map are shared mutable state, and
	// the fabric daemon's pump now reads (journal-since) CONCURRENTLY with
	// the sequencer's appends — before #642 the daemon's global srv.mu
	// serialized every journal touch, which made every consumer's re-pump
	// render block every publisher. Taken by the journal_stdlib_builtin
	// dispatch funnel; ops never nest, so a plain (non-reentrant) mutex is
	// correct.
	jmu &sync.Mutex = unsafe { nil }
	// [$journal:subscribe] cursors (§3.3; RULED: U1.13a — #762): per-sub
	// (stream, position); closing the journal terminates every
	// subscription (jrn_close leaves the records — a closed journal's
	// receive answers E_JOURNAL_CLOSED through jrn_get_open).
	subs        map[int]&JrnSubRecord
	next_sub_id int
	// declared_consistency is the handle floor (stream 7, L123 —
	// consistency_vocabulary.md): the `consistency` open/attach opts tokens,
	// validated ONCE at declaration against jrn_guarantee_advert. Empty =
	// undeclared (the pre-vocabulary behavior, byte-identical).
	declared_consistency []string
	// reserved_append_ok — stream 20 (#692, erasure_compliance §7): set ONLY
	// by the erase-subject command around its OWN internal append to the
	// reserved `cx:erasure` stream; a direct append there refuses CXER4622
	// (a hand-authored erasure record would forge the M29 evidence basis).
	// Set/cleared under the backing store's op-lock, which every append on
	// this handle serializes on (#628).
	reserved_append_ok bool
}

// JrnSubRecord — one local tail-follow subscription (§3.3): the consumer's
// per-stream cursor (entries strictly above `pos` deliver next).
@[heap]
struct JrnSubRecord {
mut:
	stream string
	pos    int
	closed bool
}

// StreamState is one named stream's chain state — the same shape as the flat
// `:default` fields on Journal. seq/head/chain are per-stream (§2.1.1).
struct StreamState {
mut:
	head_seq    int
	head_hash   string
	base_seq    int
	seam_anchor string
	entries     []string
}

// jrn_default_stream is the implicit stream when a caller names none. It is
// represented by the ABSENCE of a stream coordinate everywhere (no stream attr
// in the entry, no stream in the canonical bytes, the legacy alias path), so a
// journal that only ever uses it behaves byte-identically to the pre-stream
// module (the backward-compat invariant, §2.1.1).
const jrn_default_stream = ':default'

// jrn_is_default reports whether a stream key denotes the invisible default.
fn jrn_is_default(stream string) bool {
	return stream == '' || stream == jrn_default_stream
}

// jrn_named_state returns (creating if absent) the named stream's mutable state.
// MUST NOT be called for the default stream (that uses the flat fields).
fn jrn_named_state(mut j Journal, stream string) &StreamState {
	if st := j.named[stream] {
		return st
	}
	st := &StreamState{
		head_hash:   jrn_genesis_prev
		seam_anchor: jrn_genesis_prev
	}
	j.named[stream] = st
	return st
}

@[heap]
struct JournalRegistry {
mut:
	journals map[int]&Journal
	next_id  int
}

__global (
	g_journal_reg voidptr
)

fn journal_reg() &JournalRegistry {
	if g_journal_reg == unsafe { nil } {
		r := &JournalRegistry{
			journals: map[int]&Journal{}
		}
		g_journal_reg = voidptr(r)
	}
	return unsafe { &JournalRegistry(g_journal_reg) }
}

// g_journal_reg_lock guards the registry map (#642: pump threads look
// journals up concurrently with registration — same posture as
// g_store_reg_lock).
const g_journal_reg_lock = &sync.Mutex(sync.new_mutex())

fn journal_register(j &Journal) int {
	mut l := unsafe { g_journal_reg_lock }
	l.@lock()
	mut reg := journal_reg()
	reg.next_id++
	id := reg.next_id
	reg.journals[id] = j
	l.unlock()
	return id
}

fn journal_lookup(id int) ?&Journal {
	mut l := unsafe { g_journal_reg_lock }
	l.@lock()
	reg := journal_reg()
	r := reg.journals[id] or {
		l.unlock()
		return none
	}
	l.unlock()
	return r
}

// ── value helpers ───────────────────────────────────────────────────────

fn jrn_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn jrn_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn jrn_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// jrn_empty is the absence channel: the empty node-set (`code.md` §9.1.2).
// An out-of-range / empty read is "nothing here" — absence, NOT null.
fn jrn_empty() cx.Node {
	return cx.Element{
		name:  code.seq_marker_name
		items: []
	}
}

fn jrn_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  code.seq_marker_name
		items: items
	}
}

fn jrn_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn jrn_arg_int(n cx.Node) ?int {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return int(v)
		}
	}
	return none
}

// jrn_map_get reads a string-valued key from a `{k: v}` map literal — a
// `__cx_map__` marker element whose entries are child elements named by the
// key (eval.v eval_map), with an attribute-form fallback for handle/opts
// elements rendered as attrs. Returns none when absent.
fn jrn_map_get(m cx.Node, key string) ?string {
	if m is cx.Element {
		if m.name == '__cx_map__' || m.name == 'map' {
			for it in m.items {
				if it is cx.Element && it.name == key {
					if it.items.len > 0 {
						v := it.items[0]
						if v is cx.ScalarNode {
							return cx.scalar_value_str_public(v.value)
						}
						return ''
					}
					return ''
				}
			}
		}
		for a in m.attrs {
			if a.name == key {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return none
}

// jrn_map_get_seq reads a sequence-valued opts key as its items' scalar
// strings (a single scalar value reads as a one-item list).
fn jrn_map_get_seq(m cx.Node, key string) ?[]string {
	if m is cx.Element {
		for it in m.items {
			if it is cx.Element && it.name == key {
				mut out := []string{}
				for v in it.items {
					if v is cx.Element && (v.name == code.seq_marker_name || v.name == '') {
						for s in v.items {
							if s is cx.ScalarNode {
								sv := s.value
								if sv is string {
									out << sv
								}
							}
						}
					} else if v is cx.ScalarNode {
						sv := v.value
						if sv is string {
							out << sv
						}
					}
				}
				if out.len > 0 {
					return out
				}
				return none
			}
		}
	}
	return none
}

fn jrn_map_get_int(m cx.Node, key string) ?int {
	s := jrn_map_get(m, key) or { return none }
	return s.int()
}

fn jrn_map_has(m cx.Node, key string) bool {
	if _ := jrn_map_get(m, key) {
		return true
	}
	return false
}

// jrn_handle_of reads the integer journal handle off a `[journal handle=N …]`.
fn jrn_handle_of(n cx.Node) ?int {
	if n is cx.Element {
		if n.name == 'journal' {
			for a in n.attrs {
				if a.name == 'handle' {
					return cx.scalar_value_str_public(a.value).int()
				}
			}
		}
	}
	return none
}

// jrn_get_open resolves a journal argument to its live Journal. On a closed
// handle → CXER4612; on a bad handle → CXER4610.
fn jrn_get_open(arg cx.Node) (&Journal, cx.Node, bool) {
	id := jrn_handle_of(arg) or {
		return unsafe { nil }, mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: expected a [journal] handle'), false
	}
	j := journal_lookup(id) or {
		return unsafe { nil }, mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: unknown journal handle ${id}'), false
	}
	if !j.is_open {
		return unsafe { nil }, mk_err(jrn_err_closed, 'E_JOURNAL_CLOSED: operation on a closed journal'), false
	}
	return j, jrn_null(), true
}

// jrn_guarantee_advert is the guarantee set THIS journal surface advertises
// (stream 7, L123 — journal.md §4.4): the §4.4 committed-prefix contract,
// the replay/snapshot/fold-from position pins, the §3.7 signed head-set,
// forward-only head refresh, and gapless-under-the-read-guard.
// `read-your-writes` is advertised only over a local backing store (mem://,
// file://) — a byte-source remote cannot prove its own writes visible back
// through a caching layer; the store-advert refinement is stream-7 W4's.
fn jrn_guarantee_advert(store_id int) []string {
	mut adv := ['prefix-consistent', 'at-seq-pinned', 'at-head-set', 'monotonic-reads', 'gapless']
	if ms := store_lookup(store_id) {
		// Local backings: mem + every local-filesystem model (the subtree
		// default resolves a bare file:// to cxpack; document+file:// to
		// file; object-per-key to cxobj — all one local mount). A
		// remote-active or byte-source backing (s3, http) never advertises
		// read-your-writes.
		if ms.backend in ['mem', 'file', 'cxobj', 'cxpack'] && !store_remote_active(ms) {
			adv << 'read-your-writes'
		}
	}
	return adv
}

// jrn_floor_declared reports whether the handle's declared consistency floor
// carries a token.
fn jrn_floor_declared(j &Journal, token string) bool {
	return token in j.declared_consistency
}

// jrn_handle_element builds the opaque `[journal …]` handle value.
fn jrn_handle_element(id int, j &Journal) cx.Node {
	mut e := cx.Element{
		name:  'journal'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'tenant'
				value: cx.ScalarValue(j.tenant)
			},
			cx.Attribute{
				name:  'state'
				value: cx.ScalarValue(if j.is_open { 'open' } else { 'closed' })
			},
			cx.Attribute{
				name:  'head-seq'
				value: cx.ScalarValue(i64(j.head_seq))
			},
			cx.Attribute{
				name:  'head-hash'
				value: cx.ScalarValue(j.head_hash)
			},
			cx.Attribute{
				name:  'hash-algo'
				value: cx.ScalarValue(j.hash_algo)
			},
			cx.Attribute{
				name:  'read-only'
				value: cx.ScalarValue(j.read_only)
			},
			cx.Attribute{
				name:  'on-close'
				value: cx.ScalarValue('journal/close')
			},
		]
	}
	// Stream 7 (L123): the declared floor is inspectable on the handle —
	// inspection answers VALUES; only declarations refuse. Undeclared
	// handles carry no attribute (byte-identical to the pre-vocabulary
	// handle).
	if j.declared_consistency.len > 0 {
		mut toks := []string{}
		for t in j.declared_consistency {
			toks << ':${t}'
		}
		e.attrs << cx.Attribute{
			name:  'consistency'
			value: cx.ScalarValue(toks.join(' '))
		}
	}
	return e
}

// ── store-partition keys ──────────────────────────────────────────────────
//
// Entries are persisted as docs in the underlying store; aliases give a stable
// per-tenant namespace so an open re-reads the chain head + entry index. A
// store doc is content-addressed by hash, so the alias `entry/<tenant>/<seq>`
// → doc-hash is the seq→doc index, and `head/<tenant>` carries `seq:hash`.

fn jrn_entry_alias(tenant string, seq int) string {
	return 'cx-journal/entry/${tenant}/${seq}'
}

fn jrn_head_alias(tenant string) string {
	return 'cx-journal/head/${tenant}'
}

// Stream-aware alias variants (§2.1.1). The default stream uses the legacy paths
// above (no stream segment) so its on-store layout is byte-identical; a named
// stream gets a disjoint `/s/<stream>/` sub-namespace within the same tenant.
fn jrn_entry_alias_s(tenant string, stream string, seq int) string {
	if jrn_is_default(stream) {
		return jrn_entry_alias(tenant, seq)
	}
	return 'cx-journal/entry/${tenant}/s/${stream}/${seq}'
}

fn jrn_head_alias_s(tenant string, stream string) string {
	if jrn_is_default(stream) {
		return jrn_head_alias(tenant)
	}
	return 'cx-journal/head/${tenant}/s/${stream}'
}

// jrn_state_entry_node returns the live [entry] node at absolute seq from a
// named stream's cache (mirrors jrn_entry_node for the default flat fields).
fn jrn_state_entry_node(st &StreamState, seq int) ?cx.Node {
	idx := seq - st.base_seq - 1
	if idx < 0 || idx >= st.entries.len {
		return none
	}
	e := jrn_parse_entry(st.entries[idx]) or { return none }
	return cx.Node(e)
}

// jrn_state_entry_node_of is jrn_state_entry_node with a STORE fallback
// (#628): on a shared root, a sibling handle's appends live in the store but
// not this instance's cache — resolve the entry through its alias so reads
// see the live tail, not just what this handle wrote/loaded.
fn jrn_state_entry_node_of(j &Journal, stream string, st &StreamState, seq int) ?cx.Node {
	if node := jrn_state_entry_node(st, seq) {
		return jrn_hydrate_entry(j.store_id, node)
	}
	dhash := jrn_store_get_alias(j.store_id, jrn_entry_alias_s(j.tenant, stream, seq)) or {
		return none
	}
	text := jrn_store_get_doc_text(j.store_id, dhash) or { return none }
	e := jrn_parse_entry(text) or { return none }
	return jrn_hydrate_entry(j.store_id, cx.Node(e))
}

// jrn_state_collect_range_of is jrn_state_collect_range through the store-
// fallback entry resolver (#628): sibling-appended entries collect too.
fn jrn_state_collect_range_of(j &Journal, stream string, st &StreamState, from int, to int) []cx.Node {
	mut items := []cx.Node{}
	mut lo := from
	if lo < st.base_seq + 1 {
		lo = st.base_seq + 1
	}
	mut hi := to
	if hi > st.head_seq {
		hi = st.head_seq
	}
	for s in lo .. hi + 1 {
		if node := jrn_state_entry_node_of(j, stream, st, s) {
			items << node
		}
	}
	return items
}

// jrn_stream_base is one stream's retained floor: the seq BEFORE the first
// retained entry (0 on an unpruned chain; the compaction boundary B on a
// segment — §4.10). The stream-7 read guards key off it.
fn jrn_stream_base(j &Journal, stream string) int {
	if jrn_is_default(stream) {
		return j.base_seq
	}
	if st := j.named[stream] {
		return st.base_seq
	}
	return 0
}

// jrn_refresh_head re-reads the DURABLE head of one stream into this
// instance's cache (#628): writable opens of one root share the live store,
// so a sibling handle's appends advance the durable head past this handle's
// cache. Forward-only (a durable head can never legitimately be behind the
// cache this instance just advanced under the commit lock).
fn jrn_refresh_head(mut j Journal, stream string) {
	if jrn_is_default(stream) {
		if hd := jrn_get_meta_doc(j.store_id, jrn_head_alias(j.tenant)) {
			hs := jrn_entry_attr(hd, 'seq').int()
			hh := jrn_entry_attr(hd, 'hash')
			if hs > j.head_seq && hh != '' {
				j.head_seq = hs
				j.head_hash = hh
			}
		}
		return
	}
	mut st := jrn_named_state(mut j, stream)
	if hd := jrn_get_meta_doc(j.store_id, jrn_head_alias_s(j.tenant, stream)) {
		hs := jrn_entry_attr(hd, 'seq').int()
		hh := jrn_entry_attr(hd, 'hash')
		if hs > st.head_seq && hh != '' {
			st.head_seq = hs
			st.head_hash = hh
		}
	}
}

// jrn_state_collect_range collects a named stream's entries in [from,to] (seq).
fn jrn_state_collect_range(st &StreamState, from int, to int) []cx.Node {
	mut items := []cx.Node{}
	mut lo := from
	if lo < st.base_seq + 1 {
		lo = st.base_seq + 1
	}
	mut hi := to
	if hi > st.head_seq {
		hi = st.head_seq
	}
	for s in lo .. hi + 1 {
		if node := jrn_state_entry_node(st, s) {
			items << node
		}
	}
	return items
}

fn jrn_algo_alias(tenant string) string {
	return 'cx-journal/algo/${tenant}'
}

// ── canonical entry hashing (composes hash via cx_text_hash) ──────────────
//
// The entry hash is computed over the canonical CX bytes of the chain-relevant
// fields (seq + tenant + actor + authority + ts + prev-hash + the [event]
// payload), via the same Layer-1 text hash the store + `cx hash` CLI use.
// hash-algo selects sha256/384/512/blake3; cx_text_hash is sha256 (the §4.2
// default + the only digest needed for the conformance tier). The algo tag
// prefixes the hex so `verify` is unambiguous and the genesis sentinel is
// distinguishable from a real digest.

// I1 row 11 (#720 / erasure L184, audit C1): the entry-canonical preimage
// carries the payload's own Tier-1 tagged ADDRESS as an envelope field —
// the payload body child is gone (ONE entry form, no dual-accept). The
// chain covers the address, which is intact after a lawful shred, so
// verify's three checks pass with payloads destroyed — exactly the
// mandate. Wrapper element, field order, and the non-default-only
// `stream` binding are unchanged (the journal.md-normative form).
fn jrn_canonical_bytes(seq int, tenant string, stream string, actor string, authority string, ts string, prev_hash string, payload_addr string) string {
	mut attrs := [
		cx.Attribute{
			name:  'seq'
			value: cx.ScalarValue(i64(seq))
		},
		cx.Attribute{
			name:  'tenant'
			value: cx.ScalarValue(tenant)
		},
	]
	// `stream` is bound into the hash for NON-default streams only (§2.1.1): a
	// default-stream entry omits it, so its canonical bytes — and thus its hash —
	// are byte-identical to the pre-stream module. Binding `stream` for named
	// streams makes relabeling an entry across streams a detectable tamper (§4.2).
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << cx.Attribute{
		name:  'actor'
		value: cx.ScalarValue(actor)
	}
	attrs << cx.Attribute{
		name:  'authority'
		value: cx.ScalarValue(authority)
	}
	attrs << cx.Attribute{
		name:  'ts'
		value: cx.ScalarValue(ts)
	}
	attrs << cx.Attribute{
		name:  'prev-hash'
		value: cx.ScalarValue(prev_hash)
	}
	attrs << cx.Attribute{
		name:  'payload'
		value: cx.ScalarValue(payload_addr)
	}
	rec := cx.Element{
		name:  'entry-canonical'
		attrs: attrs
	}
	return render_canonical(rec)
}

fn jrn_compute_hash(algo string, canonical string) ?string {
	// Route to the REAL per-algo digest (§4.2). I1 stream 19 (L31/L35):
	// cx_text_hash_algo now RETURNS the self-describing tagged address
	// (`sha2-256:<hex>`, multiformats registry names) — the journal's
	// private `sha256:`/`b3:` prefixes are gone with the epoch, one
	// registry everywhere.
	return cx.cx_text_hash_algo(canonical, algo) or { return none }
}

// ── building / parsing the [entry] value ──────────────────────────────────

fn jrn_build_entry(seq int, tenant string, stream string, actor string, authority string, ts string, prev_hash string, hash string, payload_addr string) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'seq'
			value: cx.ScalarValue(i64(seq))
		},
		cx.Attribute{
			name:  'tenant'
			value: cx.ScalarValue(tenant)
		},
	]
	// stream attr is present only for non-default streams; its absence means
	// `:default` (§2.1.1) — keeping default entries render-identical.
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << [
		cx.Attribute{
			name:  'actor'
			value: cx.ScalarValue(actor)
		},
		cx.Attribute{
			name:  'authority'
			value: cx.ScalarValue(authority)
		},
		cx.Attribute{
			name:  'ts'
			value: cx.ScalarValue(ts)
		},
		cx.Attribute{
			name:  'prev-hash'
			value: cx.ScalarValue(prev_hash)
		},
		cx.Attribute{
			name:  'payload'
			value: cx.ScalarValue(payload_addr)
		},
		cx.Attribute{
			name:  'hash'
			value: cx.ScalarValue(hash)
		},
	]
	// I1 row 11 (#720/L184): the PERSISTED entry carries the payload
	// ADDRESS only — embedding the event bytes here would defeat lawful
	// shredding (destroying the payload doc must destroy the bytes). The
	// read surface re-hydrates the [event] child from the store.
	return cx.Element{
		name:  'entry'
		attrs: attrs
	}
}

// jrn_parse_entry reparses a stored entry doc text back to its node.
fn jrn_parse_entry(text string) ?cx.Element {
	parsed := cx.parse(text) or { return none }
	if parsed.elements.len > 0 {
		e := parsed.elements[0]
		if e is cx.Element {
			return e
		}
	}
	return none
}

// jrn_entry_attr reads a string attr off a parsed [entry].
fn jrn_entry_attr(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// jrn_entry_event extracts the [event …] payload node from a parsed entry (the
// single child of the [event] wrapper).
fn jrn_entry_event(e cx.Element) cx.Node {
	for it in e.items {
		if it is cx.Element {
			if it.name == 'event' {
				if it.items.len == 1 {
					return it.items[0]
				}
				return jrn_seq(it.items.clone())
			}
		}
	}
	return jrn_null()
}

// jrn_entry_idx maps an absolute seq to the 0-based index in the entries cache
// (accounting for a compacted segment's base_seq), or none if out of range.
fn jrn_entry_idx(j &Journal, seq int) ?int {
	idx := seq - j.base_seq - 1
	if idx < 0 || idx >= j.entries.len {
		return none
	}
	return idx
}

// jrn_entry_text returns the cached canonical doc text for an absolute seq.
fn jrn_entry_text(j &Journal, seq int) ?string {
	if idx := jrn_entry_idx(j, seq) {
		return j.entries[idx]
	}
	// #628: a sibling handle on a shared root may have appended past this
	// instance's cache — resolve through the store (the durable truth).
	dhash := jrn_store_get_alias(j.store_id, jrn_entry_alias(j.tenant, seq)) or { return none }
	return jrn_store_get_doc_text(j.store_id, dhash) or { return none }
}

// jrn_entry_node returns the live [entry] node for seq (absolute) from the
// registry cache, or none if out of range.
fn jrn_entry_node(j &Journal, seq int) ?cx.Node {
	text := jrn_entry_text(j, seq) or { return none }
	e := jrn_parse_entry(text) or { return none }
	return jrn_hydrate_entry(j.store_id, cx.Node(e))
}

// jrn_hydrate_entry re-attaches the [event] child to a persisted entry by
// resolving its payload ADDRESS (I1 row 11, #720/L184: the persisted form
// carries only the address; the READ surface presents the event). A
// missing payload doc — a lawful shred — leaves the entry event-less; a
// TOMBSTONED payload (the store answers the `[erased …]` tombstone text
// for the address — erasure_compliance §6) attaches the typed tombstone
// as a direct child, NEVER an [event]: the tombstone is the record OF the
// payload's destruction, not the entry's event — has-event stays false,
// so the L119 pass-through/erased= accounting is unchanged and readers
// get the attribution on the value channel.
fn jrn_hydrate_entry(store_id int, n cx.Node) cx.Node {
	if n is cx.Element {
		if n.name == 'entry' {
			addr := jrn_entry_attr(n, 'payload')
			if addr != '' {
				if text := jrn_store_get_doc_text(store_id, addr) {
					if tomb := jrn_tombstone_of(text, addr) {
						mut e := n
						e.items << cx.Node(tomb)
						return cx.Node(e)
					}
					if parsed := jrn_parse_entry(text) {
						mut e := n
						e.items << cx.Node(cx.Element{
							name:  'event'
							items: [cx.Node(parsed)]
						})
						return cx.Node(e)
					}
					// Non-element payloads (scalar/text docs) hydrate via
					// the generic parse.
					if doc := cx.parse(text) {
						if doc.elements.len > 0 {
							mut e := n
							e.items << cx.Node(cx.Element{
								name:  'event'
								items: [doc.elements[0]]
							})
							return cx.Node(e)
						}
					} else {
						return n
					}
				}
			}
		}
	}
	return n
}

// jrn_tombstone_of discriminates a doc-read answer that is the `[erased …]`
// tombstone rather than the payload itself: through `get-doc-text` a
// tombstoned address answers the tombstone's text VERBATIM (#720 item 1),
// which by construction does NOT re-hash to the address (payload docs
// self-identify: hash(text) == addr; the tombstone is a different doc).
// Both marks are required — the rehash mismatch alone would misclassify
// corruption, the name alone would misclassify a user payload spelled
// `[erased …]` (which, stored normally, re-hashes to its own address).
fn jrn_tombstone_of(text string, addr string) ?cx.Element {
	if !text.starts_with('[erased ') {
		return none
	}
	if rehash := cx.cx_text_hash(text) {
		if rehash == addr {
			return none // a genuine payload that happens to be spelled [erased …]
		}
	}
	doc := cx.parse(text) or { return none }
	if doc.elements.len == 0 {
		return none
	}
	e0 := doc.elements[0]
	if e0 is cx.Element && e0.name == 'erased' {
		return e0
	}
	return none
}

// jrn_live_hash returns the stored content hash of the entry at absolute seq,
// or '' when out of range.
fn jrn_live_hash(j &Journal, seq int) string {
	text := jrn_entry_text(j, seq) or { return '' }
	e := jrn_parse_entry(text) or { return '' }
	return jrn_entry_attr(e, 'hash')
}

// ── clock ─────────────────────────────────────────────────────────────────
//
// The default clock is a controllable monotonic counter so fixtures are
// byte-stable (§4.3). opts.clock="2026-..." pins a fixed ts; otherwise the ts
// is derived deterministically from seq (a synthetic monotonic UTC), keeping
// `ts`/`hash` reproducible without a real wall-clock read (which would also
// pull a `clock` capability journal does not own). seq is the authority; ts is
// metadata (§4.3).

fn jrn_ts_for(opts cx.Node, seq int) string {
	if fixed := jrn_map_get(opts, 'clock') {
		if fixed != '' {
			return fixed
		}
	}
	// Synthetic monotonic UTC: the Unix epoch plus seq seconds, emitted as
	// a REAL ISO-8601 UTC-Z instant (I1 row 10, #712 / bitemporal L116 /
	// stream-12 ruling 20). The deterministic capability-free semantics
	// keep — epoch-anchored, monotonic non-decreasing with seq, byte-stable
	// per seq — but the FORM is now a spec-conformant datetime (the old
	// `epoch:HH:MM:SS` spelling was not a datetime and silently wrapped at
	// 24h). Real wall-clock ts remains the opts.clock opt-in.
	t := time.unix(i64(seq))
	return '${t.year:04}-${t.month:02}-${t.day:02}T${t.hour:02}:${t.minute:02}:${t.second:02}Z'
}

// ── reload from the underlying store ───────────────────────────────────────
//
// On open/attach over a backend that already holds a chain (a reopened file://
// store), rebuild the registry entry cache + head from the persisted aliases.

// ── named-stream index (for reload across close/reopen, §2.1.1) ────────────
// A per-tenant doc listing the named streams ever appended to, so jrn_reload can
// repopulate them. The default stream needs no index (its head alias is fixed).

fn jrn_streams_index_alias(tenant string) string {
	return 'cx-journal/streams/${tenant}'
}

fn jrn_read_stream_index(store_id int, tenant string) []string {
	mut names := []string{}
	doc := jrn_get_meta_doc(store_id, jrn_streams_index_alias(tenant)) or { return names }
	// names are carried in a `name` ATTR (attrs round-trip through the store
	// losslessly; a bare child value can reparse as an element, not a string).
	for child in doc.items {
		if child is cx.Element {
			if child.name == 's' {
				nm := jrn_entry_attr(child, 'name')
				if nm != '' {
					names << nm
				}
			}
		}
	}
	return names
}

// jrn_write_stream_index persists the stream index. Returns the [err] on
// failure, none on success (#644 — the index write is a wire op on remote).
fn jrn_write_stream_index(store_id int, tenant string, names []string) ?cx.Node {
	mut items := []cx.Node{}
	for n in names {
		items << cx.Node(cx.Element{
			name:  's'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(n)
				},
			]
		})
	}
	if e := jrn_set_meta_alias(store_id, jrn_streams_index_alias(tenant), cx.Element{
		name:  'journal-streams'
		items: items
	})
	{
		return e
	}
	return none
}

// jrn_index_stream records a newly-seen named stream in the persisted index.
// Returns the [err] on failure, none on success (#644).
fn jrn_index_stream(store_id int, tenant string, stream string) ?cx.Node {
	mut names := jrn_read_stream_index(store_id, tenant)
	if stream !in names {
		names << stream
		if e := jrn_write_stream_index(store_id, tenant, names) {
			return e
		}
	}
	return none
}

fn jrn_reload(mut j Journal) {
	// Resolve the head pointer doc → seq + hash; if absent the partition is
	// empty. (The pointer is a [journal-head] doc, not a raw "seq:hash" alias
	// value — see jrn_set_meta_alias: the store rejects non-doc-hash values.)
	hd := jrn_get_meta_doc(j.store_id, jrn_head_alias(j.tenant)) or {
		j.head_seq = 0
		j.head_hash = jrn_genesis_prev
		jrn_reload_named(mut j)
		return
	}
	hs := jrn_entry_attr(hd, 'seq').int()
	hh := jrn_entry_attr(hd, 'hash')
	if hs < 1 || hh == '' {
		j.head_seq = 0
		j.head_hash = jrn_genesis_prev
		jrn_reload_named(mut j)
		return
	}
	mut loaded := []string{}
	for s in 1 .. hs + 1 {
		dhash := jrn_store_get_alias(j.store_id, jrn_entry_alias(j.tenant, s)) or { break }
		text := jrn_store_get_doc_text(j.store_id, dhash) or { break }
		loaded << text
	}
	j.entries = loaded
	j.head_seq = hs
	j.head_hash = hh
	jrn_reload_named(mut j)
}

// jrn_reload_named repopulates the named streams (§2.1.1) from the persisted
// index + each stream's head alias + entry aliases (for file:// across reopen).
fn jrn_reload_named(mut j Journal) {
	for name in jrn_read_stream_index(j.store_id, j.tenant) {
		shd := jrn_get_meta_doc(j.store_id, jrn_head_alias_s(j.tenant, name)) or { continue }
		shs := jrn_entry_attr(shd, 'seq').int()
		shh := jrn_entry_attr(shd, 'hash')
		if shs < 1 || shh == '' {
			continue
		}
		mut sloaded := []string{}
		for s in 1 .. shs + 1 {
			dhash := jrn_store_get_alias(j.store_id, jrn_entry_alias_s(j.tenant, name, s)) or {
				break
			}
			text := jrn_store_get_doc_text(j.store_id, dhash) or { break }
			sloaded << text
		}
		j.named[name] = &StreamState{
			head_seq:    shs
			head_hash:   shh
			base_seq:    0
			seam_anchor: jrn_genesis_prev
			entries:     sloaded
		}
	}
}

// ── store composition helpers (call store native prims directly) ───────────

// jrn_flush_hold / jrn_flush_release scope a #614 group commit over the
// journal's backing store: N appends inside the scope stage in memory and
// land as ONE backend flush at release. The caller must not acknowledge
// any append in the scope until release returns.
fn jrn_flush_hold(jnode cx.Node) {
	j, _, ok := jrn_get_open(jnode)
	if !ok {
		return
	}
	mut ms := store_lookup(j.store_id) or { return }
	store_flush_hold(mut ms)
}

fn jrn_flush_release(jnode cx.Node) ! {
	j, _, ok := jrn_get_open(jnode)
	if !ok {
		return
	}
	mut ms := store_lookup(j.store_id) or { return }
	store_flush_release(mut ms)!
}

fn jrn_store_put_doc(store_id int, doc cx.Node) ?string {
	h, _ := jrn_store_put_doc_err(store_id, doc)
	if h == '' {
		return none
	}
	return h
}

// jrn_store_put_doc_err is the cause-carrying variant (#644): returns
// (hash, none) on success, ('', the underlying [err]) on failure — so the
// append path can surface WHY a persist failed (capability denial, auth
// rejection, transport) instead of the bare "could not persist" mask that
// cost the reporter a debugging round.
fn jrn_store_put_doc_err(store_id int, doc cx.Node) (string, ?cx.Node) {
	r := store_stdlib_builtin('store-put-doc', [jrn_store_handle(store_id), doc]) or {
		return '', none
	}
	if r is cx.ScalarNode {
		v := r.value
		if v is string {
			return v, none
		}
	}
	if is_err_value(r) {
		return '', r
	}
	return '', none
}

fn jrn_store_get_doc_text(store_id int, hash string) ?string {
	// Route through the BUILTIN arm, not the internal doc reads: the arm
	// carries the per-backend resolution paths — object-graph stores keep
	// docs in the graph, and a cx-store:// client resolves the ref +
	// reconstructs over the OBJECT WIRE (#644; the internal
	// store_doc_present/store_doc_text pair sees only local state and made
	// remote meta docs — head/algo pointers — unreadable on reattach). The
	// store funnel is reentrant (#628), so this is safe under a held
	// group-commit scope.
	r := store_stdlib_builtin_inner('store-get-doc-text', [jrn_store_handle(store_id),
		jrn_str(hash)]) or { return none }
	if r is cx.ScalarNode {
		v := r.value
		if v is string {
			return v
		}
	}
	return none // absence or err → the caller's absent-meta path
}

// jrn_err_caused builds a journal error carrying the underlying failure as
// its [cause] child (#644): the persist mask ("could not persist entry …")
// hid the real reason (a capability denial, an auth rejection, a transport
// failure) and cost the reporter a debugging round.
fn jrn_err_caused(errcode string, message string, cause cx.Node) cx.Node {
	return cx.Element{
		name:  'err'
		attrs: [
			cx.Attribute{
				name:  'code'
				value: cx.ScalarValue(errcode)
			},
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue(message)
			},
		]
		items: [
			cx.Node(cx.Element{
				name:  'cause'
				items: [cause]
			}),
		]
	}
}

// jrn_store_set_alias writes one chain pointer. Returns the [err] node on
// failure, none on success (the cap_guard shape: `if e := … { return e }`).
// Reporting failure matters (#644): on a remote-backed store an alias write
// is a wire op that can genuinely fail (auth, transport, target refusal),
// and swallowing it silently strands the entry pointer / head — the chain
// would read as shorter than its durable entries.
fn jrn_store_set_alias(store_id int, name string, hash string) ?cx.Node {
	r := store_stdlib_builtin('store-set-alias', [jrn_store_handle(store_id), jrn_str(name),
		jrn_str(hash)]) or { return none }
	if is_err_value(r) {
		return r
	}
	return none
}

fn jrn_store_get_alias(store_id int, name string) ?string {
	r := store_stdlib_builtin('store-get-alias', [jrn_store_handle(store_id), jrn_str(name)]) or {
		return none
	}
	if r is cx.ScalarNode {
		v := r.value
		if v is string {
			return v
		}
	}
	return none // absence (empty seq) → no alias
}

// ── doc-backed metadata pointers (head + algo) ─────────────────────────────
//
// The store's alias model is CONTENT-ADDRESSED: store-set-alias REJECTS any
// value that is not an existing doc-hash (store.v → CXER1121). So a raw
// "seq:hash" head pointer or a bare algo name CANNOT be stored as an alias
// value — store-set-alias silently fails and the pointer never persists.
// That is why reopen never rehydrated the chain (head pointer absent) and why
// stashing the algo string in the alias then comparing it to the algo NAME
// conflated a doc-hash with a name (the CXER4602-on-reopen bug). Both pointers
// are therefore persisted as tiny DOCS and the alias references the doc-hash,
// exactly like entry docs; reads resolve the alias → doc → attribute.

// jrn_set_meta_alias persists a metadata doc and points its alias at it.
// Returns the [err] node on failure, none on success (#644 — see
// jrn_store_set_alias). A failed doc put is reported the same way.
fn jrn_set_meta_alias(store_id int, name string, doc cx.Node) ?cx.Node {
	h, put_err := jrn_store_put_doc_err(store_id, doc)
	if h == '' {
		if pe := put_err {
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: could not persist metadata doc for ${name}',
				pe)
		}
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: could not persist metadata doc for ${name}')
	}
	if e := jrn_store_set_alias(store_id, name, h) {
		return e
	}
	return none
}

// jrn_get_meta_doc resolves an alias to its backing metadata-doc element.
fn jrn_get_meta_doc(store_id int, name string) ?cx.Element {
	dhash := jrn_store_get_alias(store_id, name) or { return none }
	text := jrn_store_get_doc_text(store_id, dhash) or { return none }
	return jrn_parse_entry(text)
}

fn jrn_head_doc(seq int, hash string) cx.Node {
	return cx.Element{
		name:  'journal-head'
		attrs: [
			cx.Attribute{
				name:  'seq'
				value: cx.ScalarValue(i64(seq))
			},
			cx.Attribute{
				name:  'hash'
				value: cx.ScalarValue(hash)
			},
		]
	}
}

fn jrn_algo_doc_node(algo string) cx.Node {
	return cx.Element{
		name:  'journal-algo'
		attrs: [cx.Attribute{
			name:  'algo'
			value: cx.ScalarValue(algo)
		}]
	}
}

// jrn_read_algo returns the persisted chain algo for a tenant ('' if none).
fn jrn_read_algo(store_id int, tenant string) string {
	e := jrn_get_meta_doc(store_id, jrn_algo_alias(tenant)) or { return '' }
	return jrn_entry_attr(e, 'algo')
}

// jrn_store_handle re-materializes a `[store handle=N …]` element for a store
// id (store native prims read the handle off the element).
fn jrn_store_handle(store_id int) cx.Node {
	ms := store_lookup(store_id) or {
		return cx.Element{
			name:  'store'
			attrs: [cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(store_id))
			}]
		}
	}
	return store_handle_element(store_id, ms)
}

// ── env-free primitive dispatch (no $fn verbs) ─────────────────────────────

// journal_stdlib_builtin is the journal-op funnel. #642: every op on an
// EXISTING handle serializes on that journal's OWN mutex (jmu) — append,
// read, since, verify, and compact share the entries cache / head state /
// named-stream map, and the fabric daemon's pump reads run CONCURRENTLY
// with the sequencer's appends once they leave srv.mu. open/attach CREATE
// the instance and take no instance lock; ops never nest, so the plain
// mutex is correct. An op whose handle doesn't resolve falls through
// unlocked — the inner arm answers with its precise invalid-handle error.
fn journal_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if name == 'journal-open' {
		return jrn_open(args)
	}
	if name == 'journal-attach' {
		return jrn_attach(args)
	}
	mut jl := &sync.Mutex(unsafe { nil })
	if args.len > 0 {
		if id := jrn_handle_of(args[0]) {
			if j := journal_lookup(id) {
				jl = j.jmu
			}
		}
	}
	if jl != unsafe { nil } {
		jl.@lock()
	}
	r := journal_stdlib_builtin_op(name, args) or {
		if jl != unsafe { nil } {
			jl.unlock()
		}
		return none
	}
	if jl != unsafe { nil } {
		jl.unlock()
	}
	return r
}

fn journal_stdlib_builtin_op(name string, args []cx.Node) ?cx.Node {
	match name {
		'journal-close' {
			return jrn_close(args)
		}
		'journal-append' {
			return jrn_append(args)
		}
		'journal-read' {
			return jrn_read(args)
		}
		'journal-slice' {
			return jrn_slice(args)
		}
		'journal-since' {
			return jrn_since(args)
		}
		'journal-query' {
			return jrn_query(args)
		}
		'journal-source' {
			return jrn_source(args)
		}
		'journal-head' {
			return jrn_head(args)
		}
		'journal-head-fresh' {
			return jrn_head_fresh(args)
		}
		'journal-streams' {
			return jrn_streams(args)
		}
		'journal-verify' {
			return jrn_verify(args)
		}
		'journal-verify-slice' {
			return jrn_verify_slice(args)
		}
		'journal-ingest-stream' {
			// stream 9 (#681, L173): replica-local stream ingestion — the
			// identity-preserving re-land (append re-hashes by design).
			return jrn_ingest_stream(args)
		}
		'journal-register-replica' {
			return jrn_register_replica(args)
		}
		'journal-deregister-replica' {
			return jrn_deregister_replica(args)
		}
		'journal-saga-status' {
			return coord_saga_status(args)
		}
		'journal-temporal-slice' {
			return jrn_temporal_slice(args)
		}
		'journal-legal-holds' {
			return jrn_legal_holds(args)
		}
		'journal-shred-generation' {
			return jrn_shred_generation(args)
		}
		'journal-segment-disposed' {
			return jrn_segment_disposed(args)
		}
		'journal-lineage-path' {
			return jrn_lineage_path(args)
		}
		'journal-overlaps' {
			return jrn_overlaps(args)
		}
		'journal-contains-instant' {
			return jrn_contains_instant(args)
		}
		'journal-snapshot-verify' {
			return jrn_snapshot_verify(args)
		}
		'journal-retain' {
			return jrn_retain(args)
		}
		'journal-seq-at' {
			return jrn_seq_at(args)
		}
		'journal-compact' {
			return jrn_compact(args)
		}
		'journal-rotate' {
			return jrn_rotate(args)
		}
		else {
			return none
		}
	}
}

// ── open / attach / close ──────────────────────────────────────────────────

// The AT-REST posture keys a journal open forwards to its backing store open
// (store.md §9 + §3 framing). #785: before this, `journal-open` had no at-rest
// spelling at all — sealing a journal's backing store meant opening the store
// yourself (`store-open-opts`) and reaching the chain through
// `journal-attach`, so every DERIVED open (a rotate/compact target) was
// PLAINTEXT by construction.
const jrn_at_rest_keys = ['encrypt-key-id', 'encoding', 'compression']

// jrn_at_rest_attrs answers the store-open options a DERIVED open — a rotate
// or compact TARGET — must inherit from the source chain's backing store
// (#785). Opening the target bare had three costs: an encrypted journal could
// not rotate at all (the fresh target opened plaintext and the payload-doc
// carry then refused CXER1144 custody — correctly, leaving the composition
// unusable); a rotation carrying no subject payload silently DOWNGRADED the
// at-rest posture at every segment boundary; and an EXISTING encrypted store
// named as the target failed outright (self-describing reopen needs the key).
// `head-fresh` already performs exactly this inheritance for its read-only
// substrate reopen (§4.4) — rotate/compact now speak the same rule.
//
// Precedence, highest first:
//  1. an EXPLICIT key on the caller's rotate/compact `opts` — key-per-segment
//     policies (each sealed segment under its own KEK) ride here;
//  2. the target URL's own `?encoding=` / `?compression=` query, when it
//     states one (framing has a URI spelling; `encrypt-key-id` has none);
//  3. the source store's posture.
//
// Framing (`encoding`/`compression`) inherits only ACROSS THE SAME SCHEME: a
// `file://` → `sqlite://` rotation must not carry `object-per-key` into a
// substrate with no such framing. `encrypt-key-id` inherits ALWAYS — a target
// that cannot seal then refuses LOUDLY (store.md §9 fail-closed), which is the
// only honest answer; it must never degrade to a silent plaintext write.
fn jrn_at_rest_attrs(src_store int, target_url string, opts cx.Node) []cx.Attribute {
	mut out := []cx.Attribute{}
	ms := store_lookup(src_store) or { return out }
	mut key_id := ms.enc_key_id
	if v := jrn_map_get(opts, 'encrypt-key-id') {
		key_id = v
	}
	if key_id != '' {
		out << cx.Attribute{
			name:  'encrypt-key-id'
			value: cx.ScalarValue(key_id)
		}
	}
	_, qparams, _ := store_normalize_uri(target_url)
	same_scheme := store_url_scheme(target_url) == store_url_scheme(ms.url)
	// The source's EFFECTIVE framing: a store reopened self-describingly
	// records its framing in the backend, while `encoding` stays the neutral
	// `cxbin` — so read object-per-key off the backend or a rotation would
	// land the new hot window in a pack while the source was object-per-key.
	mut src_encoding := ms.encoding
	if ms.backend == 'cxobj' && src_encoding in ['', 'cxbin'] {
		src_encoding = 'object-per-key'
	}
	for pair in [['encoding', src_encoding], ['compression', ms.compression]] {
		key := pair[0]
		if v := jrn_map_get(opts, key) {
			if v != '' {
				out << cx.Attribute{
					name:  key
					value: cx.ScalarValue(v)
				}
			}
			continue
		}
		if key in qparams {
			continue
		}
		if same_scheme && pair[1] != '' {
			out << cx.Attribute{
				name:  key
				value: cx.ScalarValue(pair[1])
			}
		}
	}
	return out
}

fn jrn_open(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: open expects (store-url, tenant)')
	}
	url := jrn_arg_str(args[0]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: open expects a store URL string')
	}
	tenant := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: open expects a tenant string')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	mut algo := jrn_map_get(opts, 'hash-algo') or { 'sha2-256' }
	if algo == '' {
		algo = 'sha2-256'
	}
	if algo !in jrn_supported_algos {
		return mk_err(jrn_err_hash_unsupported, 'E_JOURNAL_HASH_UNSUPPORTED: unknown hash-algo "${algo}"')
	}
	read_only := (jrn_map_get(opts, 'read-only') or { 'false' }) == 'true'
	create := (jrn_map_get(opts, 'create') or { 'true' }) != 'false'

	// Open the underlying store (gated by store's capability model — CXER0271
	// at the store effect point; mem:// is free). A read-only journal opens the
	// store read-only, and the AT-REST posture keys (#785) ride through to the
	// store open — a journal whose chain is sealed at rest is opened by naming
	// its key here, not by the store-open-then-attach detour.
	mut open_attrs := []cx.Attribute{}
	if read_only {
		open_attrs << cx.Attribute{
			name:  'read-only'
			value: cx.ScalarValue('true')
		}
	}
	for k in jrn_at_rest_keys {
		if v := jrn_map_get(opts, k) {
			if v != '' {
				open_attrs << cx.Attribute{
					name:  k
					value: cx.ScalarValue(v)
				}
			}
		}
	}
	store_res := if open_attrs.len > 0 {
		open_opts := cx.Element{
			name:  'map'
			attrs: open_attrs
		}
		store_stdlib_builtin('store-open-opts', [args[0], open_opts]) or {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: ${url}')
		}
	} else {
		store_stdlib_builtin('store-open', [args[0]]) or {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: ${url}')
		}
	}
	// A store-open error (e.g. CXER0271 denial, CXER1100 bad URL) propagates as
	// the failure channel unchanged (§5 — journal adds no capability).
	if is_err_value(store_res) {
		return store_res
	}
	store_id := store_handle_of(store_res) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: store handle missing for ${url}')
	}

	mut j := &Journal{
		tenant:     tenant
		hash_algo:  algo
		read_only:  read_only
		is_open:    true
		store_id:   store_id
		owns_store: true
		head_seq:   0
		head_hash:  jrn_genesis_prev
		entries:    []
		jmu:        sync.new_mutex()
	}
	// Algo-fix check (§4.2): if the partition already records a different algo,
	// reject. Otherwise stamp the algo.
	existing_algo := jrn_read_algo(store_id, tenant)
	had_head := jrn_store_get_alias(store_id, jrn_head_alias(tenant)) or { '' }
	if existing_algo != '' && existing_algo != algo {
		return mk_err(jrn_err_algo_mismatch, 'E_JOURNAL_ALGO_MISMATCH: chain created with "${existing_algo}", reopened with "${algo}"')
	}
	if had_head == '' && existing_algo == '' && !create {
		return mk_err(jrn_err_not_found, 'E_JOURNAL_NOT_FOUND: no partition for tenant "${tenant}" and create=false')
	}
	jrn_reload(mut j)
	if !read_only && existing_algo == '' {
		// The algo stamp failing at OPEN must fail the open (#644): on a remote
		// store this is the first write on the mount — an unreachable/denied
		// store surfaces HERE, loud at boot, never lazily at seq 1.
		if e := jrn_set_meta_alias(store_id, jrn_algo_alias(tenant), jrn_algo_doc_node(algo)) {
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: journal store rejected the open-time algo stamp for ${store_url_redact_userinfo(url)}',
				e)
		}
	}
	// stream-3 W4 (live modes L134): the adapter-stream declaration rides
	// the stream-7 handle floor — checked once at open.
	if dnode := jrn_map_get_node(opts, 'declare') {
		if e := jrn_declare_adapter_stream(j, dnode) {
			return e
		}
	}
	// Stream 7 (L122/L123): the consistency floor — the declared tokens are
	// validated ONCE here against the surface's advertised guarantee set;
	// an unsatisfiable declaration refuses the open (CXER4990), it never
	// opens degraded.
	cdecl, cerr, cok := cst_read_declared(opts, 'journal:open')
	if !cok {
		return cerr
	}
	if cdecl.len > 0 {
		if e := cst_check_floor(cdecl, 'journal:open', jrn_guarantee_advert(store_id)) {
			return e
		}
		j.declared_consistency = cdecl
	}
	id := journal_register(j)
	return jrn_handle_element(id, j)
}

fn jrn_attach(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: attach expects (store, tenant)')
	}
	store_id := store_handle_of(args[0]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: attach expects an open [store] handle')
	}
	if store_lookup(store_id) == none {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: unknown store handle ${store_id}')
	}
	tenant := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: attach expects a tenant string')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	mut algo := jrn_map_get(opts, 'hash-algo') or { 'sha2-256' }
	if algo == '' {
		algo = 'sha2-256'
	}
	if algo !in jrn_supported_algos {
		return mk_err(jrn_err_hash_unsupported, 'E_JOURNAL_HASH_UNSUPPORTED: unknown hash-algo "${algo}"')
	}
	read_only := (jrn_map_get(opts, 'read-only') or { 'false' }) == 'true'
	existing_algo := jrn_read_algo(store_id, tenant)
	if existing_algo != '' && existing_algo != algo {
		return mk_err(jrn_err_algo_mismatch, 'E_JOURNAL_ALGO_MISMATCH: chain "${existing_algo}" vs "${algo}"')
	}
	mut j := &Journal{
		tenant:     tenant
		hash_algo:  algo
		read_only:  read_only
		is_open:    true
		store_id:   store_id
		owns_store: false
		head_seq:   0
		head_hash:  jrn_genesis_prev
		entries:    []
		jmu:        sync.new_mutex()
	}
	jrn_reload(mut j)
	if !read_only && existing_algo == '' {
		// Same loud-at-attach contract as jrn_open (#644).
		if e := jrn_set_meta_alias(store_id, jrn_algo_alias(tenant), jrn_algo_doc_node(algo)) {
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: journal store rejected the attach-time algo stamp',
				e)
		}
	}
	// stream-3 W4 (live modes L134): the adapter-stream declaration rides
	// the stream-7 handle floor — attach is the same floor as open.
	if dnode := jrn_map_get_node(opts, 'declare') {
		if e := jrn_declare_adapter_stream(j, dnode) {
			return e
		}
	}
	// Stream 7 (L122/L123): attach is the same consistency floor as open.
	cdecl, cerr, cok := cst_read_declared(opts, 'journal:attach')
	if !cok {
		return cerr
	}
	if cdecl.len > 0 {
		if e := cst_check_floor(cdecl, 'journal:attach', jrn_guarantee_advert(store_id)) {
			return e
		}
		j.declared_consistency = cdecl
	}
	id := journal_register(j)
	return jrn_handle_element(id, j)
}

fn jrn_close(args []cx.Node) ?cx.Node {
	id := jrn_handle_of(args[0]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: close expects a [journal] handle')
	}
	mut j := journal_lookup(id) or {
		// idempotent: an unknown/already-released handle closes to null.
		return jrn_null()
	}
	if j.is_open && j.owns_store {
		store_stdlib_builtin('store-close', [jrn_store_handle(j.store_id)]) or { cx.Node(jrn_null()) }
	}
	j.is_open = false
	return jrn_null()
}

// ── append (the single mutating verb) ──────────────────────────────────────

fn jrn_append(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: append expects (journal, event, attribution)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	if j.read_only {
		return mk_err(jrn_err_read_only, 'E_JOURNAL_READ_ONLY: append on a read-only journal')
	}
	event := args[1]
	attribution := args[2]
	actor := jrn_map_get(attribution, 'actor') or { '' }
	authority := jrn_map_get(attribution, 'authority') or { '' }
	if actor == '' || authority == '' {
		return mk_err(jrn_err_attr_invalid, 'E_JOURNAL_ATTRIBUTION_INVALID: append requires non-empty actor + authority (no anonymous appends)')
	}
	// Target stream (§2.1.1): the optional attribution `stream` key; absent/`:default`
	// → the invisible default stream (the flat fields, byte-identical path).
	stream := jrn_map_get(attribution, 'stream') or { '' }
	is_def := jrn_is_default(stream)
	// Adapter-stream exclusivity (stream 3 W4, live modes L134): a stream
	// declared with a writer principal refuses appends from any other —
	// the guarantee ladder is void under interleaved writers; a checked
	// posture, enforced HERE at append. (Embedded tier: the actor claim is
	// the ambient process principal; the served tier's session layer is
	// where principals are proven.)
	if w := jrn_declared_writer(j, stream) {
		if actor != w {
			return mk_err(live_err_exclusive_writer, 'E_LIVE_EXCLUSIVE_WRITER: stream `${stream}` is an adapter stream with declared writer `${w}` — append by `${actor}` refused (adapter-is-only-client, live modes L134)')
		}
	}
	// #628: the WHOLE append (head read → entry doc → entry alias → head
	// advance) runs inside the backing store's group-commit scope, which also
	// holds the store's reentrant op-lock — so on a shared root two appenders
	// serialize and the hash chain can never interleave; and the scope's one
	// release flushes the append's four mutations as one durable unit (#614).
	mut msh := store_lookup(j.store_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: backing store is gone')
	}
	tr := fab_trace_on()
	t0 := time.sys_mono_now()
	store_flush_hold(mut msh)
	// Rebase on the DURABLE stream head under the lock — a sibling handle on
	// a shared root may have advanced it past this instance's cache.
	jrn_refresh_head(mut j, stream)
	t_head := time.sys_mono_now()
	// Current head/seq of the TARGET stream — the commit lock is per stream, so
	// disjoint streams never contend (§2.1.1).
	mut cur_seq := 0
	mut cur_hash := ''
	if is_def {
		cur_seq = j.head_seq
		cur_hash = j.head_hash
	} else {
		st := jrn_named_state(mut j, stream)
		cur_seq = st.head_seq
		cur_hash = st.head_hash
	}
	// Optimistic-concurrency check (§3.2), per stream: expect-pos must equal
	// the target stream's head_seq. (I5 stream 1 R2 / L84: `expect-pos`
	// is THE position encoding of the ONE CAS vocabulary — the former
	// `expect-prev-seq` spelling retired cutover-first.)
	if jrn_map_has(attribution, 'expect-pos') {
		expect := jrn_map_get_int(attribution, 'expect-pos') or { -1 }
		if expect != cur_seq {
			store_flush_release(mut msh) or {}
			return mk_err(jrn_err_stale_tail, 'E_JOURNAL_STALE_TAIL: expected head-seq ${expect}, was ${cur_seq}')
		}
	}
	// Reject an unserializable event defensively: rendering must succeed.
	seq := cur_seq + 1
	prev_hash := cur_hash
	ts := jrn_ts_for(if args.len > 3 { args[3] } else { cx.Node(cx.Element{ name: 'map' }) },
		seq)
	// Stream 20 (erasure_compliance §3): a subject-bearing payload's nonce
	// must not be derivable from journal coordinates — byte-equality with any
	// coordinate refuses. (Presence, length, and the sealed subject-key put
	// are enforced by the store's subject arm when the payload doc lands
	// below; only THIS site knows the coordinates.)
	if subj := store_subject_attr(event) {
		if nonce := store_nonce_attr(event) {
			if nonce == '${seq}' || nonce == ts || nonce == prev_hash || nonce == stream
				|| nonce == j.tenant || nonce == actor || nonce == authority
				|| nonce == subj {
				store_flush_release(mut msh) or {}
				return mk_err('cx-err:CXER4619', 'E_ERASURE_NONCE_REQUIRED: nonce equals a journal coordinate — a derivable nonce is recomputable by the adversary the oracle defense exists to defeat (erasure_compliance §3)')
			}
		}
	}
	// Stream 20 (erasure_compliance §8): the reserved hold-stream accepts
	// ONLY well-formed SIGNED [legal-hold] claims — write-time enforcement
	// (entries are immutable; a malformed hold recorded once would poison
	// the fail-closed load forever, and an unsigned hold binds nothing).
	if stream == jrn_hold_stream {
		jrn_hold_parse(event) or {
			store_flush_release(mut msh) or {}
			return mk_err(jrn_err_hold_invalid, 'E_ERASURE_HOLD_INVALID: ${err.msg()} — the ${jrn_hold_stream} stream records only well-formed signed [legal-hold] claims (erasure_compliance §8)')
		}
	}
	// Stream 20 (erasure_compliance §7): the reserved erasure stream records
	// ONLY the erase-subject command's own shred-request entries — a
	// hand-authored record would forge the M29 read-time evidence basis (and
	// the durable dedup record). Same write-time posture as the hold stream.
	if stream == jrn_erase_stream && !j.reserved_append_ok {
		store_flush_release(mut msh) or {}
		return mk_err(jrn_err_erasure_reserved, 'E_ERASURE_RECORD_RESERVED: the ${jrn_erase_stream} stream records only erase-subject command records journaled by the command itself — a hand-authored erasure record would forge the M29 evidence basis (erasure_compliance §7); use [$journal:erase-subject]')
	}
	// I1 row 11 (#720/L184): the payload is stored as its OWN doc first;
	// the entry preimage covers its Tier-1 tagged ADDRESS. Same
	// group-commit scope — the payload doc, entry doc, and head advance
	// flush as one durable unit.
	payload_addr, pay_err := jrn_store_put_doc_err(j.store_id, event)
	if payload_addr == '' {
		store_flush_release(mut msh) or {}
		if pe := pay_err {
			if pe is cx.Element {
				return cx.Node(pe)
			}
		}
		return mk_err(jrn_err_event_unser, 'E_JOURNAL_EVENT_UNSERIALIZABLE: cannot store event payload at seq ${seq}')
	}
	canonical := jrn_canonical_bytes(seq, j.tenant, stream, actor, authority, ts, prev_hash,
		payload_addr)
	hash := jrn_compute_hash(j.hash_algo, canonical) or {
		store_flush_release(mut msh) or {}
		return mk_err(jrn_err_event_unser, 'E_JOURNAL_EVENT_UNSERIALIZABLE: cannot hash event at seq ${seq}')
	}
	entry := jrn_build_entry(seq, j.tenant, stream, actor, authority, ts, prev_hash, hash,
		payload_addr)
	t_hashed := time.sys_mono_now()
	// Persist the entry doc + advance the (per-stream) head alias.
	dhash, put_err := jrn_store_put_doc_err(j.store_id, entry)
	if dhash == '' {
		store_flush_release(mut msh) or {}
		// Surface the CAUSE (#644): a capability denial / auth rejection /
		// transport failure on a remote mount was masked by this message and
		// indistinguishable from a local disk fault.
		if pe := put_err {
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: could not persist entry at seq ${seq}',
				pe)
		}
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: could not persist entry at seq ${seq}')
	}
	t_put := time.sys_mono_now()
	// Chain-pointer writes FAIL the append loudly (#644): on a remote store
	// these are wire ops; a swallowed failure would leave the entry durable
	// but unreachable (entry alias) or the head un-advanced — a chain that
	// reads shorter than its entries. The err carries the real cause
	// (auth/transport/refusal), not a generic mask.
	if e := jrn_store_set_alias(j.store_id, jrn_entry_alias_s(j.tenant, stream, seq),
		dhash)
	{
		store_flush_release(mut msh) or {}
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: entry pointer write failed at seq ${seq}',
			e)
	}
	if e := jrn_set_meta_alias(j.store_id, jrn_head_alias_s(j.tenant, stream), jrn_head_doc(seq,
		hash))
	{
		store_flush_release(mut msh) or {}
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: head advance failed at seq ${seq}',
			e)
	}
	t_alias := time.sys_mono_now()
	if !is_def && seq == 1 {
		// Record the stream in the persisted index on its genesis so a later
		// reattach (file://) can repopulate it (§2.1.1, jrn_reload_named) —
		// inside the scope, so the index rides the same durable release.
		if e := jrn_index_stream(j.store_id, j.tenant, stream) {
			store_flush_release(mut msh) or {}
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: stream index write failed at seq ${seq}',
				e)
		}
	}
	// The append is durable only when the scope's release lands (#614) — the
	// receipt below must not be returned on a failed flush.
	store_flush_release(mut msh) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: durable flush failed at seq ${seq}: ${err.msg()}')
	}
	// Advance the in-process head + cache (the linearized commit) on the target
	// stream. The entries cache is a CONTIGUOUS run from base_seq — on a shared
	// root a sibling's appends can leave a gap, in which case this entry stays
	// store-resolved (jrn_entry_text's #628 fallback) instead of corrupting the
	// cache's index math.
	if is_def {
		if j.base_seq + j.entries.len == seq - 1 {
			j.entries << render_canonical(entry)
		}
		j.head_seq = seq
		j.head_hash = hash
	} else {
		mut st := jrn_named_state(mut j, stream)
		if st.base_seq + st.entries.len == seq - 1 {
			st.entries << render_canonical(entry)
		}
		st.head_seq = seq
		st.head_hash = hash
	}
	if tr {
		t_done := time.sys_mono_now()
		eprintln('[fab-trace side=journal step=append stream=${stream} seq=${seq} head-us=${(t_head - t0) / 1000} hash-us=${(t_hashed - t_head) / 1000} put-us=${(t_put - t_hashed) / 1000} alias-us=${(t_alias - t_put) / 1000} tail-us=${(t_done - t_alias) / 1000} total-us=${(t_done - t0) / 1000}]')
	}
	// The RETURN surface presents the hydrated view (event child attached
	// — the same shape read/fold present); only the PERSISTED entry is
	// address-only (I1 row 11).
	if entry is cx.Element {
		mut ret := entry as cx.Element
		ret.items << cx.Node(cx.Element{
			name:  'event'
			items: [event]
		})
		return cx.Node(ret)
	}
	return entry
}

// ── reads ───────────────────────────────────────────────────────────────

// jrn_opt_stream reads an optional trailing stream key off args[idx]; absent or
// non-string → '' (the default stream, §2.1.1).
fn jrn_opt_stream(args []cx.Node, idx int) string {
	if args.len > idx {
		if s := jrn_arg_str(args[idx]) {
			return s
		}
	}
	return ''
}

fn jrn_read(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: read expects (journal, seq)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	seq := jrn_arg_int(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: read expects an integer seq')
	}
	if seq < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: seq < 1')
	}
	stream := jrn_opt_stream(args, 2)
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() } // unknown stream → absence
		node := jrn_state_entry_node(st, seq) or { return jrn_empty() }
		return jrn_hydrate_entry(j.store_id, node)
	}
	node := jrn_entry_node(j, seq) or {
		return jrn_empty() // out-of-range read → absence, not null/err (§2.5)
	}
	return node
}

fn jrn_collect_range(j &Journal, from int, to int) []cx.Node {
	mut items := []cx.Node{}
	mut lo := from
	if lo < j.base_seq + 1 {
		lo = j.base_seq + 1
	}
	mut hi := to
	if hi > j.head_seq {
		hi = j.head_seq
	}
	for s in lo .. hi + 1 {
		if node := jrn_entry_node(j, s) {
			items << node
		}
	}
	return items
}

fn jrn_slice(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: slice expects (journal, from, to)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	from := jrn_arg_int(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: slice from')
	}
	to := jrn_arg_int(args[2]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: slice to')
	}
	if from > to {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: from > to')
	}
	stream := jrn_opt_stream(args, 3)
	// #628: reads see the live tail on a shared root — refresh the durable
	// head, and resolve cache-missed entries through the store.
	jrn_refresh_head(mut j, stream)
	// Stream 7 (L122 :gapless — journal.md §4.4): under a declared :gapless
	// floor an explicit-`from` read below the retained floor refuses loudly
	// instead of silently clamping to the seam.
	base := jrn_stream_base(j, stream)
	if jrn_floor_declared(j, 'gapless') && base > 0 && from <= base {
		return cst_pin_refusal('journal:slice', 'gapless', from, base,
			'read from above the retained floor, or fold-from over the covering snapshot')
	}
	items := if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		jrn_state_collect_range_of(j, stream, st, from, to)
	} else {
		jrn_collect_range(j, from, to)
	}
	projected, perr, pok := jrn_read_opts_project(args, 4, 'slice', items)
	if !pok {
		return perr
	}
	if projected.len == 0 {
		return jrn_empty() // empty window → absence (§2.5)
	}
	return jrn_seq(projected)
}

// jrn_read_opts_project applies the §3.8 valid-at projection to a range
// read's collected entries when a trailing opts map carries it. `at-seq`
// does NOT ride slice/since — their explicit range IS the TX axis — so its
// presence is a teaching refusal, never a silent ignore.
fn jrn_read_opts_project(args []cx.Node, idx int, verb string, items []cx.Node) ([]cx.Node, cx.Node, bool) {
	if args.len <= idx {
		return items, jrn_null(), true
	}
	opts := args[idx]
	if _ := jrn_map_get_int(opts, 'at-seq') {
		return []cx.Node{}, mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: at-seq does not ride ${verb} — the explicit range IS the TX axis; pin with fold/replay opts or cut with temporal-slice'), false
	}
	has_vt, vt_ns, verr, vok := jrn_opt_valid_at(opts)
	if !vok {
		return []cx.Node{}, verr, false
	}
	if !has_vt {
		return items, jrn_null(), true
	}
	out, errn, ok := jrn_temporal_project(items, false, 0, true, vt_ns)
	if !ok {
		return []cx.Node{}, errn, false
	}
	return out, jrn_null(), true
}

fn jrn_since(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: since expects (journal, from)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	from := jrn_arg_int(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: since from')
	}
	stream := jrn_opt_stream(args, 2)
	// #628: reads see the live tail on a shared root (see jrn_slice).
	jrn_refresh_head(mut j, stream)
	// Stream 7 (L122 :gapless — see jrn_slice).
	base := jrn_stream_base(j, stream)
	if jrn_floor_declared(j, 'gapless') && base > 0 && from <= base {
		return cst_pin_refusal('journal:since', 'gapless', from, base,
			'read from above the retained floor, or fold-from over the covering snapshot')
	}
	items := if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		jrn_state_collect_range_of(j, stream, st, from, st.head_seq)
	} else {
		jrn_collect_range(j, from, j.head_seq)
	}
	projected, perr, pok := jrn_read_opts_project(args, 3, 'since', items)
	if !pok {
		return perr
	}
	if projected.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(projected)
}

// jrn_source implements [$journal:source]: the stream's retained committed
// [entry] sequence in seq order (`:default` when the stream key is omitted)
// — THE journal-stream source-reference form for planar comprehensions
// (code.md §7.8, ruling L97; journal.md §3.3). Equivalent to `since 1` over
// the stream, subject to the §2.8 retention floor; the reference's E3
// position is the stream's head-seq.
fn jrn_source(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: source expects (journal, stream?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	stream := jrn_opt_stream(args, 1)
	// #628: reads see the live tail on a shared root (see jrn_slice).
	jrn_refresh_head(mut j, stream)
	items := if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		jrn_state_collect_range_of(j, stream, st, 1, st.head_seq)
	} else {
		jrn_collect_range(j, 1, j.head_seq)
	}
	if items.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(items)
}

// jrn_streams enumerates the journal's non-empty stream keys (§2.1.1): the
// `:default` stream (if it has any entries) followed by each named stream in
// insertion order. Empty journal → absence ().
fn jrn_streams(args []cx.Node) ?cx.Node {
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	mut items := []cx.Node{}
	if j.head_seq > 0 {
		items << jrn_str(jrn_default_stream)
	}
	for name, st in j.named {
		if st.head_seq > 0 {
			items << jrn_str(name)
		}
	}
	if items.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(items)
}

fn jrn_head(args []cx.Node) ?cx.Node {
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	stream := jrn_opt_stream(args, 1)
	// #628: the head read sees the live tail on a shared root.
	jrn_refresh_head(mut j, stream)
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		if st.head_seq < 1 {
			return jrn_empty()
		}
		return jrn_state_entry_node_of(j, stream, st, st.head_seq) or { return jrn_empty() }
	}
	if j.head_seq < 1 {
		return jrn_empty() // empty journal → absence (§3.3)
	}
	node := jrn_entry_node(j, j.head_seq) or { return jrn_empty() }
	return node
}

// jrn_head_fresh implements [$journal:head-fresh] — the DECLARED-FRESH head
// verb (stream 7 F1, #714 item 1; journal.md §4.4): `head` answers the
// handle's cached view and makes NO freshness claim; this distinct, IMPURE
// verb re-resolves the durable head through the SUBSTRATE first.
//   - mem://: the live in-process instance IS the substrate — nothing to
//     re-take.
//   - remote-active backing: every alias read already asks the daemon's
//     table over the wire (#645) — the refresh below IS substrate-fresh.
//   - read-only LOCAL handle (file/cxobj/cxpack): the private-snapshot view
//     (exactly where the silent-stale class lives — the supported
//     cross-process shape is one writer + N read-only readers) is re-TAKEN
//     from disk through the normal capability-gated open path, then swapped
//     in place (store_swap_read_view). A capability denial or integrity
//     refusal propagates loudly — never a silently-unrefreshed answer.
// After the substrate step, the ordinary forward-only head refresh + the
// store read-through answer the fresh head [entry] (absence on an empty
// stream, like `head`).
fn jrn_head_fresh(args []cx.Node) ?cx.Node {
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	stream := jrn_opt_stream(args, 1)
	mut ms := store_lookup(j.store_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: backing store is gone')
	}
	if ms.read_only && ms.backend in ['file', 'cxobj', 'cxpack'] && !store_remote_active(ms) {
		mut ro_attrs := [cx.Attribute{
			name:  'read-only'
			value: cx.ScalarValue('true')
		}]
		if ms.enc_key_id != '' {
			ro_attrs << cx.Attribute{
				name:  'encrypt-key-id'
				value: cx.ScalarValue(ms.enc_key_id)
			}
		}
		if ms.encoding != '' {
			ro_attrs << cx.Attribute{
				name:  'encoding'
				value: cx.ScalarValue(ms.encoding)
			}
		}
		if ms.compression != '' {
			ro_attrs << cx.Attribute{
				name:  'compression'
				value: cx.ScalarValue(ms.compression)
			}
		}
		ro_opts := cx.Element{
			name:  'map'
			attrs: ro_attrs
		}
		res := store_stdlib_builtin('store-open-opts', [jrn_str(ms.url), ro_opts]) or {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: head-fresh substrate reopen failed for ${store_url_redact_userinfo(ms.url)}')
		}
		if is_err_value(res) {
			return res
		}
		scratch_id := store_handle_of(res) or {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: head-fresh scratch handle missing')
		}
		mut fresh := store_lookup(scratch_id) or {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: head-fresh scratch store lost')
		}
		store_lock_enter(mut ms)
		store_swap_read_view(mut ms, mut fresh)
		store_lock_exit(mut ms)
		store_stdlib_builtin('store-close', [res]) or { cx.Node(jrn_null()) }
	}
	jrn_refresh_head(mut j, stream)
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		if st.head_seq < 1 {
			return jrn_empty()
		}
		return jrn_state_entry_node_of(j, stream, st, st.head_seq) or { return jrn_empty() }
	}
	if j.head_seq < 1 {
		return jrn_empty()
	}
	node := jrn_entry_node(j, j.head_seq) or { return jrn_empty() }
	return node
}

// jrn_query filters entries whose hydrated form matches a CXPath (§3.3;
// store.md §6 query semantics). Returns matching entries in seq order;
// empty when none match.
//
// The path is evaluated by the REAL engine against each hydrated entry
// bound as $doc — the same evaluator `cx select` and an inline `$doc/…`
// read use — so a predicate means what CXPath says it means. It used to
// be stripped: `index('[')` cut the trailing predicate off and the verb
// matched the last element-name step alone, so
// `/event/promo[@valid-from]` answered with EVERY entry carrying a
// promo, a silent SUPERSET of what was asked (#782). A deliberate subset
// would have been defensible; a silent one is not, and answering the
// real predicate is the direction the spec text already promises.
fn jrn_query(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: query expects (journal, cxpath)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	path_text := (jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: query expects a CXPath string')
	}).trim_space()
	if path_text.len == 0 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: query expects a non-empty CXPath')
	}
	// The query path is ENTRY-RELATIVE: §3.3's own example is
	// '/event/do[@*=…]', where the leading step addresses the entry's
	// [event] child, and "or envelope attrs" reaches the entry's own
	// attributes ('/@actor'). The engine's bare `/…` is root-NAMED
	// (`/entry/event/do` under `cx select`), so the surface path is
	// anchored to the entry with an explicit $doc — same evaluator,
	// the documented rooting.
	expr := if path_text.starts_with('$') {
		path_text
	} else if path_text.starts_with('/') {
		'\$doc' + path_text
	} else {
		'\$doc/' + path_text
	}
	mut items := []cx.Node{}
	for s in 1 .. j.head_seq + 1 {
		node := jrn_entry_node(j, s) or { continue }
		if node !is cx.Element {
			continue
		}
		res := select_path_on_node(node, expr) or {
			// A path the engine refuses is the CALLER's error, reported
			// once for the query rather than silently narrowing it to the
			// entries that happened to parse.
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: query path ${path_text}: ${err.msg()}')
		}
		if res.count > 0 {
			items << node
		}
	}
	if items.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(items)
}

// ── verify (a finding, not a fault — §3.6) ─────────────────────────────────

fn jrn_verification(valid bool, checked_from int, checked_to int, head_hash string, first_bad int, reason string) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'valid'
			value: cx.ScalarValue(valid)
		},
		cx.Attribute{
			name:  'checked-from'
			value: cx.ScalarValue(i64(checked_from))
		},
		cx.Attribute{
			name:  'checked-to'
			value: cx.ScalarValue(i64(checked_to))
		},
	]
	if valid {
		attrs << cx.Attribute{
			name:  'head-hash'
			value: cx.ScalarValue(head_hash)
		}
	} else {
		attrs << cx.Attribute{
			name:  'first-bad-seq'
			value: cx.ScalarValue(i64(first_bad))
		}
		attrs << cx.Attribute{
			name:  'reason'
			value: cx.ScalarValue(':' + reason)
		}
	}
	return cx.Element{
		name:  'verification'
		attrs: attrs
	}
}

// jrn_walk_verify re-hashes every entry in [from..to], checking content hash,
// prev-hash links, and seq density. `prev_anchor` is the hash the first entry's
// prev-hash must equal (the genesis sentinel, or a predecessor / snapshot
// anchor at a seam). Returns the verification finding VALUE.
fn jrn_walk_verify(j &Journal, from int, to int, prev_anchor string) cx.Node {
	mut expected_prev := prev_anchor
	mut prev_seq := from - 1
	mut head_h := j.head_hash
	for s in from .. to + 1 {
		text := jrn_entry_text(j, s) or {
			return jrn_verification(false, from, to, '', s, 'seq-gap')
		}
		e := jrn_parse_entry(text) or {
			return jrn_verification(false, from, to, '', s, 'seq-gap')
		}
		got_seq := jrn_entry_attr(e, 'seq').int()
		if got_seq != prev_seq + 1 {
			return jrn_verification(false, from, to, '', s, 'seq-gap')
		}
		prev_seq = got_seq
		got_prev := jrn_entry_attr(e, 'prev-hash')
		// Genesis check only when the walk begins at seq=1 of a non-compacted
		// chain (base_seq=0); a compaction seam anchors against the snapshot
		// anchor-hash instead of the genesis sentinel (§4.10).
		if s == 1 && j.base_seq == 0 {
			if got_prev != jrn_genesis_prev {
				return jrn_verification(false, from, to, '', s, 'genesis-invalid')
			}
		}
		if got_prev != expected_prev {
			return jrn_verification(false, from, to, '', s, 'link-broken')
		}
		// re-hash the canonical bytes and compare.
		stored_hash := jrn_entry_attr(e, 'hash')
		// I1 row 11: verify covers the payload ADDRESS — no payload fetch,
		// so all three checks pass with payloads lawfully destroyed.
		canonical := jrn_canonical_bytes(got_seq, jrn_entry_attr(e, 'tenant'),
			jrn_entry_attr(e, 'stream'), jrn_entry_attr(e, 'actor'),
			jrn_entry_attr(e, 'authority'), jrn_entry_attr(e, 'ts'), got_prev, jrn_entry_attr(e, 'payload'))
		recomputed := jrn_compute_hash(j.hash_algo, canonical) or {
			return jrn_verification(false, from, to, '', s, 'hash-mismatch')
		}
		if recomputed != stored_hash {
			return jrn_verification(false, from, to, '', s, 'hash-mismatch')
		}
		expected_prev = stored_hash
		head_h = stored_hash
	}
	return jrn_verification(true, from, to, head_h, 0, '')
}

// jrn_state_entry_text returns a named stream's cached entry doc text at seq.
fn jrn_state_entry_text(st &StreamState, seq int) ?string {
	idx := seq - st.base_seq - 1
	if idx < 0 || idx >= st.entries.len {
		return none
	}
	return st.entries[idx]
}

// jrn_state_live_hash returns the stored hash of a named stream's entry at seq.
fn jrn_state_live_hash(st &StreamState, seq int) string {
	text := jrn_state_entry_text(st, seq) or { return '' }
	e := jrn_parse_entry(text) or { return '' }
	return jrn_entry_attr(e, 'hash')
}

// jrn_walk_verify_state mirrors jrn_walk_verify for a NAMED stream's chain
// (§2.1.1) — same per-entry checks (dense seq, link, genesis, hash recompute
// over the canonical bytes incl. the stream attr), reading the stream's cache.
fn jrn_walk_verify_state(st &StreamState, hash_algo string, from int, to int, prev_anchor string) cx.Node {
	mut expected_prev := prev_anchor
	mut prev_seq := from - 1
	mut head_h := st.head_hash
	for s in from .. to + 1 {
		text := jrn_state_entry_text(st, s) or {
			return jrn_verification(false, from, to, '', s, 'seq-gap')
		}
		e := jrn_parse_entry(text) or {
			return jrn_verification(false, from, to, '', s, 'seq-gap')
		}
		got_seq := jrn_entry_attr(e, 'seq').int()
		if got_seq != prev_seq + 1 {
			return jrn_verification(false, from, to, '', s, 'seq-gap')
		}
		prev_seq = got_seq
		got_prev := jrn_entry_attr(e, 'prev-hash')
		if s == 1 && st.base_seq == 0 {
			if got_prev != jrn_genesis_prev {
				return jrn_verification(false, from, to, '', s, 'genesis-invalid')
			}
		}
		if got_prev != expected_prev {
			return jrn_verification(false, from, to, '', s, 'link-broken')
		}
		stored_hash := jrn_entry_attr(e, 'hash')
		// I1 row 11: verify covers the payload ADDRESS — no payload fetch,
		// so all three checks pass with payloads lawfully destroyed.
		canonical := jrn_canonical_bytes(got_seq, jrn_entry_attr(e, 'tenant'),
			jrn_entry_attr(e, 'stream'), jrn_entry_attr(e, 'actor'),
			jrn_entry_attr(e, 'authority'), jrn_entry_attr(e, 'ts'), got_prev, jrn_entry_attr(e, 'payload'))
		recomputed := jrn_compute_hash(hash_algo, canonical) or {
			return jrn_verification(false, from, to, '', s, 'hash-mismatch')
		}
		if recomputed != stored_hash {
			return jrn_verification(false, from, to, '', s, 'hash-mismatch')
		}
		expected_prev = stored_hash
		head_h = stored_hash
	}
	return jrn_verification(true, from, to, head_h, 0, '')
}

// ── §3.6 verify reconciliation (erasure_compliance §6, audit M29) ──────────
//
// The chain verdict stays SYNTACTIC (hashes cover the payload ADDRESS —
// valid=true with payloads lawfully gone, :payload-missing is never a
// chain-break reason). Payload integrity is the ADDITIVE report axis: every
// detached payload in the walked range is fetched and re-hashed
// (payloads-verified=M), and every payload-missing entry MUST reconcile
// against an ATTRIBUTED erasure record — the journaled shred-request whose
// [docs] scope covers the address, or the address's own [erased …] tombstone
// (redacted=N). A payload gone with NEITHER is evidence of tampering or key
// loss, never silently counted among the redactions: unattributed-missing=K,
// and any K>0 is a LOUD finding. The axis attrs appear only when the
// accounting engaged (N+K>0 — the L119 present-when-non-zero posture), all
// three together (the §9.1 balanced-account shape).

// jrn_erasure_covered collects every doc address named in the tenant's
// journaled erase-subject records ([docs [d <hash>]…] on the reserved
// cx:erasure stream) — THE evidence basis for an attributed redaction
// (audit M33: never key/payload absence alone).
fn jrn_erasure_covered(j &Journal) map[string]bool {
	mut covered := map[string]bool{}
	st := j.named[jrn_erase_stream] or { return covered }
	for s in st.base_seq + 1 .. st.head_seq + 1 {
		text := jrn_state_entry_text(st, s) or { continue }
		e := jrn_parse_entry(text) or { continue }
		addr := jrn_entry_attr(e, 'payload')
		if addr == '' {
			continue
		}
		rtxt := jrn_store_get_doc_text(j.store_id, addr) or { continue }
		rdoc := cx.parse(rtxt) or { continue }
		if rdoc.elements.len == 0 {
			continue
		}
		r0 := rdoc.elements[0]
		if r0 !is cx.Element {
			continue
		}
		re := r0 as cx.Element
		if re.name != 'erase-subject' {
			continue
		}
		for it in re.items {
			if it is cx.Element && it.name == 'docs' {
				for d in it.items {
					if d is cx.Element && d.name == 'd' && d.items.len > 0 {
						v := d.items[0]
						if v is cx.ScalarNode {
							covered[cx.scalar_value_str_public(v.value)] = true
						} else if v is cx.TextNode {
							covered[v.value] = true
						}
					}
				}
			}
		}
	}
	return covered
}

// jrn_payload_axis runs the payload accounting over one chain's [from..to]
// (stream '' = the default chain). Returns (payloads-verified, redacted,
// unattributed-missing).
fn jrn_payload_axis(j &Journal, stream string, from int, to int) (int, int, int) {
	mut verified := 0
	mut redacted := 0
	mut unattributed := 0
	mut covered := map[string]bool{}
	mut covered_built := false
	for s in from .. to + 1 {
		text := if jrn_is_default(stream) {
			jrn_entry_text(j, s) or { continue }
		} else {
			st := j.named[stream] or { continue }
			jrn_state_entry_text(st, s) or { continue }
		}
		e := jrn_parse_entry(text) or { continue }
		addr := jrn_entry_attr(e, 'payload')
		if addr == '' {
			continue
		}
		mut missing := true
		if ptxt := jrn_store_get_doc_text(j.store_id, addr) {
			if rehash := cx.cx_text_hash(ptxt) {
				if rehash == addr {
					verified++
					continue
				}
			}
			if _ := jrn_tombstone_of(ptxt, addr) {
				// The tombstone IS the attribution (it carries shred-request=).
				redacted++
				continue
			}
			// Present but re-hashes wrong and is no tombstone: corrupt —
			// reconciled like a missing payload (fail-closed, never silently
			// counted verified).
			missing = true
		}
		if missing {
			if !covered_built {
				covered = jrn_erasure_covered(j)
				covered_built = true
			}
			if addr in covered {
				redacted++
			} else {
				unattributed++
			}
		}
	}
	return verified, redacted, unattributed
}

// jrn_axis_attach appends the engaged reconciliation axis to a valid
// [verification …] value.
fn jrn_axis_attach(v cx.Node, verified int, redacted int, unattributed int) cx.Node {
	if redacted + unattributed == 0 {
		return v
	}
	if v is cx.Element {
		mut e := v
		e.attrs << cx.Attribute{
			name:  'redacted'
			value: cx.ScalarValue(i64(redacted))
		}
		e.attrs << cx.Attribute{
			name:  'payloads-verified'
			value: cx.ScalarValue(i64(verified))
		}
		e.attrs << cx.Attribute{
			name:  'unattributed-missing'
			value: cx.ScalarValue(i64(unattributed))
		}
		return cx.Node(e)
	}
	return v
}

// jrn_verify_with_axis wraps a syntactic walk verdict with the payload
// accounting (valid verdicts only — a broken chain reports its first fault).
fn jrn_verify_with_axis(j &Journal, stream string, from int, to int, v cx.Node) cx.Node {
	if v is cx.Element {
		if jrn_entry_attr(v, 'valid') != 'true' {
			return v
		}
	}
	verified, redacted, unattributed := jrn_payload_axis(j, stream, from, to)
	return jrn_axis_attach(v, verified, redacted, unattributed)
}

fn jrn_verify(args []cx.Node) ?cx.Node {
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: 'map' }) }
	// Stream-scoped verify (§2.1.1): opts.stream selects a named stream's chain.
	stream := jrn_map_get(opts, 'stream') or { '' }
	if !jrn_is_default(stream) {
		st := j.named[stream] or {
			return jrn_verification(true, 0, 0, jrn_genesis_prev, 0, '') // unknown → vacuously valid
		}
		sfrom := jrn_map_get_int(opts, 'from') or { st.base_seq + 1 }
		sto := jrn_map_get_int(opts, 'to') or { st.head_seq }
		if sto > st.head_seq || sfrom < st.base_seq + 1 {
			return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: verify [${sfrom}..${sto}] beyond stream head ${st.head_seq}')
		}
		if st.head_seq == st.base_seq {
			return jrn_verification(true, 0, 0, jrn_genesis_prev, 0, '')
		}
		sanchor := if sfrom == st.base_seq + 1 && st.base_seq > 0 {
			st.seam_anchor
		} else if sfrom > 1 {
			jrn_entry_attr(jrn_parse_entry(jrn_state_entry_text(st, sfrom - 1) or { '' }) or {
				cx.Element{}
			}, 'hash')
		} else {
			jrn_genesis_prev
		}
		return jrn_verify_with_axis(j, stream, sfrom, sto, jrn_walk_verify_state(st,
			j.hash_algo, sfrom, sto, sanchor))
	}
	from := jrn_map_get_int(opts, 'from') or { j.base_seq + 1 }
	to := jrn_map_get_int(opts, 'to') or { j.head_seq }
	if to > j.head_seq || from < j.base_seq + 1 {
		return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: verify [${from}..${to}] beyond head ${j.head_seq}')
	}
	if j.head_seq == j.base_seq {
		return jrn_verification(true, 0, 0, jrn_genesis_prev, 0, '')
	}
	// The anchor for the first verified entry: the genesis sentinel for a fresh
	// chain, or the compaction-seam anchor (§4.10) for a compacted segment.
	anchor := if from == j.base_seq + 1 && j.base_seq > 0 {
		j.seam_anchor
	} else if from > 1 {
		jrn_entry_attr(jrn_parse_entry(jrn_entry_text(j, from - 1) or { '' }) or { cx.Element{} },
			'hash')
	} else {
		jrn_genesis_prev
	}
	return jrn_verify_with_axis(j, '', from, to, jrn_walk_verify(j, from, to, anchor))
}

fn jrn_verify_slice(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: verify-slice expects (journal, from, to)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	from := jrn_arg_int(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: verify-slice from')
	}
	to := jrn_arg_int(args[2]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: verify-slice to')
	}
	if from > to || from < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: verify-slice from > to or from < 1')
	}
	if to > j.head_seq {
		return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: verify-slice to ${to} beyond head ${j.head_seq}')
	}
	// Anchor prev-hash of `from` against from-1's stored hash (or genesis).
	mut anchor := jrn_genesis_prev
	if from == j.base_seq + 1 && j.base_seq > 0 {
		anchor = j.seam_anchor
	} else if from > 1 {
		ptext := jrn_entry_text(j, from - 1) or {
			return mk_err(jrn_err_chain_broken, 'E_JOURNAL_CHAIN_BROKEN: predecessor of ${from} unreadable')
		}
		pe := jrn_parse_entry(ptext) or {
			return mk_err(jrn_err_chain_broken, 'E_JOURNAL_CHAIN_BROKEN: predecessor of ${from} unreadable')
		}
		anchor = jrn_entry_attr(pe, 'hash')
	}
	return jrn_verify_with_axis(j, '', from, to, jrn_walk_verify(j, from, to, anchor))
}

// ── §2.9 valid time & corrections — the reserved payload vocabulary +
//    the coherence verb (stream 8, bitemporal.md L115/L117) ─────────────────
//
// verify stays SYNTACTIC (hashes, links, density — §3.6). `coherence` is the
// semantic linter over the stream-8 reserved payload vocabulary: it walks the
// retained entries, checks the valid-from/valid-to carriers (half-open
// [from, to) — from strictly before to; an open end is the ABSENT attribute,
// never null) and the [supersedes hash= relation=] linkage (relation is
// TYPE-STRICT: the atom :correction or :amendment — :assertion is the
// no-supersedes classification, never a spelling on a linkage), then resolves
// each well-formed supersedes target against the tenant's retained entry
// hashes. Everything it reports is a FINDING value — never an [err], never a
// chain break. A target missing from a journal with a pruned floor is
// honestly :supersedes-unverifiable (it may live in pruned history), never a
// false :dangling-supersedes claim. Shredded payloads cannot be checked and
// are counted visibly (erased=N — the L119 honest-reporting posture).

// jrn_attr_lookup returns (value-as-string, data_type-or-''/'null', present)
// for one attribute of an element-shaped payload.
fn jrn_attr_lookup(e cx.Element, name string) (string, string, bool) {
	for a in e.attrs {
		if a.name == name {
			if a.value is cx.NullValue {
				return '', 'null', true
			}
			dt := a.data_type() or { '' }
			return cx.scalar_value_str_public(a.value), dt, true
		}
	}
	return '', '', false
}

// jrn_vt_instant decodes a valid-from/valid-to carrier (ISO date or
// datetime/instant text) to comparable nanoseconds, or none when the value
// is not a temporal scalar. Lexicographic comparison is NOT sound here
// (mixed date/datetime grains and fractional seconds), so the carriers
// decode through the one datetime core.
fn jrn_vt_instant(v string) ?i64 {
	if v == '' {
		return none
	}
	dt := decode_datetime(time_datetime_node(v)) or { return none }
	return dt.instant_ns()
}

// jrn_coh_finding builds one [finding …] child for the [coherence] value.
fn jrn_coh_finding(kind string, stream string, seq int, hash string, reason string) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'kind'
			value: cx.ScalarValue(':${kind}')
		},
	]
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << cx.Attribute{
		name:  'seq'
		value: cx.ScalarValue(i64(seq))
	}
	if hash != '' {
		attrs << cx.Attribute{
			name:  'hash'
			value: cx.ScalarValue(hash)
		}
	}
	if reason != '' {
		attrs << cx.Attribute{
			name:  'reason'
			value: cx.ScalarValue(reason)
		}
	}
	return cx.Node(cx.Element{
		name:  'finding'
		attrs: attrs
	})
}

// jrn_coh_check_payload runs the vocabulary + linkage checks over one
// element-shaped event payload. `hashes` is the tenant-wide retained entry
// hash set; `pruned` reports whether any of the tenant's chains has a
// pruned floor (compacted segment / retention boundary).
fn jrn_coh_check_payload(p cx.Element, stream string, seq int, hashes map[string]bool, pruned bool) []cx.Node {
	mut out := []cx.Node{}
	vf, vfdt, vfp := jrn_attr_lookup(p, 'valid-from')
	vt, vtdt, vtp := jrn_attr_lookup(p, 'valid-to')
	mut vf_ns := i64(0)
	mut vt_ns := i64(0)
	mut vf_ok := false
	mut vt_ok := false
	if vfp {
		if vfdt != 'null' {
			if ns := jrn_vt_instant(vf) {
				vf_ns = ns
				vf_ok = true
			}
		}
		if !vf_ok {
			out << jrn_coh_finding('temporal-vocab-invalid', stream, seq, '', 'valid-from is not a date/datetime')
		}
	}
	if vtp {
		if vtdt != 'null' {
			if ns := jrn_vt_instant(vt) {
				vt_ns = ns
				vt_ok = true
			}
		}
		if !vt_ok {
			out << jrn_coh_finding('temporal-vocab-invalid', stream, seq, '', 'valid-to is not a date/datetime')
		}
	}
	if vf_ok && vt_ok && vf_ns >= vt_ns {
		out << jrn_coh_finding('temporal-vocab-invalid', stream, seq, '', 'valid-from must be before valid-to (half-open [from, to))')
	}
	for it in p.items {
		if it is cx.Element {
			if it.name != 'supersedes' {
				continue
			}
			h, _, hp := jrn_attr_lookup(it, 'hash')
			r, rdt, rp := jrn_attr_lookup(it, 'relation')
			if !hp || h == '' {
				out << jrn_coh_finding('temporal-vocab-invalid', stream, seq, '', 'supersedes missing hash=')
				continue
			}
			if !h.contains(':') {
				out << jrn_coh_finding('temporal-vocab-invalid', stream, seq, '', 'supersedes hash= is not a content address')
				continue
			}
			if !rp || rdt != 'atom' || r !in ['correction', 'amendment'] {
				out << jrn_coh_finding('temporal-vocab-invalid', stream, seq, '', 'relation must be the atom :correction or :amendment')
				continue
			}
			// Well-formed linkage — resolve the target. A malformed
			// [supersedes] above is never also resolved (one finding per
			// defect).
			if h in hashes {
				continue
			}
			if pruned {
				out << jrn_coh_finding('supersedes-unverifiable', stream, seq, h, '')
			} else {
				out << jrn_coh_finding('dangling-supersedes', stream, seq, h, '')
			}
		}
	}
	return out
}

// jrn_coh_scan walks one stream's retained entries, appending findings and
// bumping checked/erased counts. Returns (checked, erased).
fn jrn_coh_scan(j &Journal, stream string, hashes map[string]bool, pruned bool, mut findings []cx.Node) (int, int) {
	mut checked := 0
	mut erased := 0
	if jrn_is_default(stream) {
		for s in j.base_seq + 1 .. j.head_seq + 1 {
			node := jrn_entry_node(j, s) or { continue }
			if node is cx.Element {
				if !jrn_entry_has_event(node) {
					erased++
					continue
				}
				checked++
				ev := jrn_entry_event(node)
				if ev is cx.Element {
					findings << jrn_coh_check_payload(ev, stream, s, hashes, pruned)
				}
			}
		}
		return checked, erased
	}
	st := j.named[stream] or { return 0, 0 }
	for s in st.base_seq + 1 .. st.head_seq + 1 {
		node := jrn_state_entry_node_of(j, stream, st, s) or { continue }
		if node is cx.Element {
			if !jrn_entry_has_event(node) {
				erased++
				continue
			}
			checked++
			ev := jrn_entry_event(node)
			if ev is cx.Element {
				findings << jrn_coh_check_payload(ev, stream, s, hashes, pruned)
			}
		}
	}
	return checked, erased
}

// jrn_entry_has_event reports whether a hydrated entry carries its [event]
// child — absent means the payload doc was lawfully shredded (I1 row 11).
fn jrn_entry_has_event(e cx.Element) bool {
	for it in e.items {
		if it is cx.Element {
			if it.name == 'event' {
				return true
			}
		}
	}
	return false
}

fn jrn_coherence(args []cx.Node, mut env MatchEnv) ?cx.Node {
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: 'map' }) }
	scope := jrn_map_get(opts, 'stream') or { '' }
	// §3.9 (stream 21, L151): a given upcast chain engages the coverage
	// pre-flight — "would this fold cover all N entries?" — findings, never
	// aborts (verify stays syntactic; coherence owns coverage).
	mut has_up := false
	mut chain := jrn_null()
	if c := jrn_map_get_node(opts, 'upcast') {
		if e := jrn_chain_check(c, mut env) {
			return e
		}
		has_up = true
		chain = c
	}
	// Tenant-wide retained hash set + pruned-floor flag: linkage may cross
	// streams, so targets resolve against every retained chain regardless of
	// the walk's scope.
	mut hashes := map[string]bool{}
	mut pruned := j.base_seq > 0
	for s in j.base_seq + 1 .. j.head_seq + 1 {
		text := jrn_entry_text(j, s) or { continue }
		e := jrn_parse_entry(text) or { continue }
		hashes[jrn_entry_attr(e, 'hash')] = true
	}
	for _, st in j.named {
		if st.base_seq > 0 {
			pruned = true
		}
		for s in st.base_seq + 1 .. st.head_seq + 1 {
			text := jrn_state_entry_text(st, s) or { continue }
			e := jrn_parse_entry(text) or { continue }
			hashes[jrn_entry_attr(e, 'hash')] = true
		}
	}
	// Walk order is deterministic: the default stream first, named streams
	// sorted (the W6 set-snapshot convention). A scoped walk covers exactly
	// the named stream; an unknown stream is vacuously coherent (mirrors
	// verify's posture on unknown streams).
	mut findings := []cx.Node{}
	mut checked := 0
	mut erased := 0
	mut scoped := false
	if _ := jrn_map_get(opts, 'stream') {
		scoped = true
	}
	if scoped {
		c, er := jrn_coh_scan(j, scope, hashes, pruned, mut findings)
		checked += c
		erased += er
		if has_up {
			jrn_cov_scan(j, scope, chain, mut findings, mut env)
		}
	} else {
		c0, er0 := jrn_coh_scan(j, '', hashes, pruned, mut findings)
		checked += c0
		erased += er0
		mut names := j.named.keys()
		names.sort()
		for name in names {
			c, er := jrn_coh_scan(j, name, hashes, pruned, mut findings)
			checked += c
			erased += er
		}
		if has_up {
			jrn_cov_scan(j, '', chain, mut findings, mut env)
			for name in names {
				jrn_cov_scan(j, name, chain, mut findings, mut env)
			}
		}
	}
	mut attrs := [
		cx.Attribute{
			name:  'tenant'
			value: cx.ScalarValue(j.tenant)
		},
	]
	if scoped && !jrn_is_default(scope) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(scope)
		}
	}
	attrs << cx.Attribute{
		name:  'checked'
		value: cx.ScalarValue(i64(checked))
	}
	attrs << cx.Attribute{
		name:  'findings'
		value: cx.ScalarValue(i64(findings.len))
	}
	if erased > 0 {
		attrs << cx.Attribute{
			name:  'erased'
			value: cx.ScalarValue(i64(erased))
		}
	}
	return cx.Node(cx.Element{
		name:  'coherence'
		attrs: attrs
		items: findings
	})
}

// ── §3.8 the bitemporal read — {at-seq, valid-at} (stream 8, L118) ──────────
//
// A substrate-provided PURE projection [sequence entry] → [sequence entry],
// parameterized (tx-position, valid-instant), composed BEFORE the fold — the
// fold contract is untouched, and stream 21's upcasters take the SAME seam
// (a pure entry-sequence → entry-sequence stage ahead of the reducer).
// `at-seq` is the TX cut (quadrants 1–2 are the raw shipped reads); a given
// `valid-at` ENGAGES the projection (quadrants 3–4): the §2.9 as-of collapse
// — every in-cut :correction target is excluded across its whole extent
// (restoring a corrected fact is a NEW assertion, never un-dropping);
// every :amendment clamps its target's valid-to to the amender's own
// valid-from (the earliest clamp wins) — then the valid-at filter keeps the
// entries whose effective half-open [from, to) contains the instant.
// Entries without valid-time vocabulary are valid always. An event-less
// (shredded) entry cannot be judged and PASSES THROUGH VISIBLY — filtering
// it out would silently under-report a redaction (L119). Malformed reserved
// vocabulary under an ENGAGED projection refuses CXER4618 loudly — the
// chain's vocabulary, distinct from CXER4610 (the caller's own args).

const jrn_err_temporal = 'cx-err:CXER4618' // E_JOURNAL_TEMPORAL_INVALID

// Open-interval sentinels for the valid-at filter (absent bound = unbounded).
const jrn_vt_neg_inf = i64(-9223372036854775807) - 1
const jrn_vt_pos_inf = i64(9223372036854775807)

// jrn_temporal_project applies (optional) TX cut + (optional) valid-at
// projection over materialized entries. Returns (out, errnode, ok).
fn jrn_temporal_project(entries []cx.Node, has_cut bool, at_seq int, has_vt bool, vt_ns i64) ([]cx.Node, cx.Node, bool) {
	mut cut := []cx.Node{}
	for n in entries {
		if n is cx.Element {
			if has_cut && jrn_entry_attr(n, 'seq').int() > at_seq {
				continue
			}
			cut << n
		}
	}
	if !has_vt {
		return cut, jrn_null(), true
	}
	// Pass 1 — the collapse maps from the in-cut correctors. A corrector's
	// own later supersession never restores its target (dropped-ness is
	// membership in ANY in-cut correction's target set).
	mut dropped := map[string]bool{}
	mut clamps := map[string]i64{}
	for n in cut {
		if n is cx.Element {
			sq := jrn_entry_attr(n, 'seq')
			ev := jrn_entry_event(n)
			if ev is cx.Element {
				for it in ev.items {
					if it is cx.Element {
						if it.name != 'supersedes' {
							continue
						}
						h, _, hp := jrn_attr_lookup(it, 'hash')
						r, rdt, rp := jrn_attr_lookup(it, 'relation')
						if !hp || h == '' {
							return []cx.Node{}, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: supersedes missing hash= (seq ${sq})'), false
						}
						if !h.contains(':') {
							return []cx.Node{}, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: supersedes hash= is not a content address (seq ${sq})'), false
						}
						if !rp || rdt != 'atom' || r !in ['correction', 'amendment'] {
							return []cx.Node{}, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: relation must be the atom :correction or :amendment (seq ${sq})'), false
						}
						if r == 'correction' {
							dropped[h] = true
						} else {
							// :amendment closes the target at the amender's OWN
							// valid-from — absent, the close point is undefined.
							avf, avfdt, avfp := jrn_attr_lookup(ev, 'valid-from')
							if !avfp || avfdt == 'null' {
								return []cx.Node{}, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: an :amendment requires its own valid-from (the close point) (seq ${sq})'), false
							}
							ns := jrn_vt_instant(avf) or {
								return []cx.Node{}, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: valid-from is not a date/datetime (seq ${sq})'), false
							}
							if h !in clamps || ns < clamps[h] {
								clamps[h] = ns
							}
						}
					}
				}
			}
		}
	}
	// Pass 2 — the valid-at filter over the surviving entries.
	mut out := []cx.Node{}
	for n in cut {
		if n is cx.Element {
			hash := jrn_entry_attr(n, 'hash')
			if hash in dropped {
				continue
			}
			sq := jrn_entry_attr(n, 'seq')
			if !jrn_entry_has_event(n) {
				out << n // shredded — unjudgeable, kept VISIBLE (L119)
				continue
			}
			ev := jrn_entry_event(n)
			if ev is cx.Element {
				lo, mut hi, verr, vok := jrn_vt_bounds(ev, 'seq ${sq}')
				if !vok {
					return []cx.Node{}, verr, false
				}
				if hash in clamps && clamps[hash] < hi {
					hi = clamps[hash]
				}
				if lo <= vt_ns && vt_ns < hi {
					out << n
				}
			} else {
				out << n // non-element payload — no vocabulary, valid always
			}
		}
	}
	return out, jrn_null(), true
}

// jrn_vt_bounds extracts the half-open [lo, hi) bounds from an element's
// valid-from/valid-to vocabulary (absent = unbounded). `label` names the
// offender in the CXER4618 refusal ('seq N' on chain walks, the verb name on
// direct calls). Returns (lo, hi, errnode, ok).
fn jrn_vt_bounds(e cx.Element, label string) (i64, i64, cx.Node, bool) {
	vf, vfdt, vfp := jrn_attr_lookup(e, 'valid-from')
	vt, vtdt, vtp := jrn_attr_lookup(e, 'valid-to')
	mut lo := jrn_vt_neg_inf
	mut hi := jrn_vt_pos_inf
	if vfp {
		if vfdt == 'null' {
			return 0, 0, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: valid-from is null — an open end is the ABSENT attribute (${label})'), false
		}
		lo = jrn_vt_instant(vf) or {
			return 0, 0, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: valid-from is not a date/datetime (${label})'), false
		}
	}
	if vtp {
		if vtdt == 'null' {
			return 0, 0, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: valid-to is null — an open end is the ABSENT attribute (${label})'), false
		}
		hi = jrn_vt_instant(vt) or {
			return 0, 0, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: valid-to is not a date/datetime (${label})'), false
		}
	}
	if vfp && vtp && lo >= hi {
		return 0, 0, mk_err(jrn_err_temporal, 'E_JOURNAL_TEMPORAL_INVALID: valid-from must be before valid-to (half-open [from, to)) (${label})'), false
	}
	return lo, hi, jrn_null(), true
}

// jrn_bool builds a bool scalar node.
fn jrn_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

// ── the interval verbs — [$journal:overlaps] / [$journal:contains-instant]
//    (stream 8, L118: "interval builtins land with the vocabulary"). They
//    land as journal MODULE verbs, not §6.5 core builtins: the §6.5 tables
//    are CLOSED and identity-bearing (stream 5's builtin-set id hashes
//    them), and the vocabulary's home is journal §2.9. Both are PURE.

// jrn_overlaps: [$journal:overlaps $a $b] — do two vocabulary-bearing
// elements' half-open validity windows intersect?
fn jrn_overlaps(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: overlaps expects (element, element)')
	}
	a := args[0]
	b := args[1]
	if a !is cx.Element || b !is cx.Element {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: overlaps expects two vocabulary-bearing elements')
	}
	alo, ahi, aerr, aok := jrn_vt_bounds(a as cx.Element, 'overlaps arg 1')
	if !aok {
		return aerr
	}
	blo, bhi, berr, bok := jrn_vt_bounds(b as cx.Element, 'overlaps arg 2')
	if !bok {
		return berr
	}
	lo := if alo > blo { alo } else { blo }
	hi := if ahi < bhi { ahi } else { bhi }
	return jrn_bool(lo < hi)
}

// jrn_contains_instant: [$journal:contains-instant $a $t] — does the
// element's half-open validity window contain the instant?
fn jrn_contains_instant(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: contains-instant expects (element, instant)')
	}
	a := args[0]
	if a !is cx.Element {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: contains-instant expects a vocabulary-bearing element')
	}
	ts := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: contains-instant expects a date/datetime instant')
	}
	t := jrn_vt_instant(ts) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: contains-instant expects a date/datetime instant')
	}
	lo, hi, verr, vok := jrn_vt_bounds(a as cx.Element, 'contains-instant')
	if !vok {
		return verr
	}
	return jrn_bool(lo <= t && t < hi)
}

// jrn_opt_valid_at reads opts.valid-at. Returns (present, ns, errnode, ok).
fn jrn_opt_valid_at(opts cx.Node) (bool, i64, cx.Node, bool) {
	if v := jrn_map_get(opts, 'valid-at') {
		ns := jrn_vt_instant(v) or {
			return true, 0, mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: valid-at is not a date/datetime'), false
		}
		return true, ns, jrn_null(), true
	}
	return false, 0, jrn_null(), true
}

// jrn_temporal_slice is the PURE projection verb over already-materialized
// entries (the fold-value twin): [$journal:temporal-slice $entries $opts].
fn jrn_temporal_slice(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: temporal-slice expects (entries, opts?)')
	}
	entries := iterate(args[0])
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: 'map' }) }
	mut has_cut := false
	mut at := 0
	if v := jrn_map_get_int(opts, 'at-seq') {
		has_cut = true
		at = v
	}
	has_vt, vt_ns, verr, vok := jrn_opt_valid_at(opts)
	if !vok {
		return verr
	}
	out, errn, ok := jrn_temporal_project(entries, has_cut, at, has_vt, vt_ns)
	if !ok {
		return errn
	}
	if out.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(out)
}

// ── §3.9 the upcaster seam — {upcast: $chain} (stream 21, L146/L151) ────────
//
// Upcasters are PURE entry→entry projections composed at the SAME pre-fold
// seam as the §3.8 bitemporal read — the chain is caller-supplied (one pure
// def; its Tier-1 source address is its trust identity, the stream-5 dual
// form) and the journal recognizes the seam, never the domain. Order is
// upcast THEN the temporal projection: an upcaster may synthesize §2.9
// valid-time vocabulary for entries that predate it. The chain sees the
// hydrated [entry] and returns an [entry] whose PAYLOAD it may rewrite —
// the envelope is the journal's: the seam carries the original envelope and
// non-event children forward and takes ONLY the [event] child of the chain's
// output; an output that is not an [entry], drops the payload, or rewrites
// the identity pair (seq=, hash=) refuses CXER4642 loudly. An entry the
// chain refuses (an [err] return or raise) is CXER4641 at fold time —
// naming seq, hash, and the declared schema= (§2.10) — never absence, never
// a skip (L151). Event-less (shredded) entries pass through WITHOUT chain
// application, exactly as the §3.8 projection keeps them (L119).

const jrn_err_upcast_uncovered = 'cx-err:CXER4641' // E_JOURNAL_UPCAST_UNCOVERED
const jrn_err_upcast_invalid = 'cx-err:CXER4642' // E_JOURNAL_UPCAST_INVALID
const jrn_err_fold_id = 'cx-err:CXER4640' // E_JOURNAL_FOLD_ID_MISMATCH (L147)

// jrn_entry_schema reads the declared payload-schema identity (the §2.10
// reserved `schema=` attribute) off a hydrated entry's element-shaped event
// payload; '' when undeclared or not element-shaped.
fn jrn_entry_schema(e cx.Element) string {
	ev := jrn_entry_event(e)
	if ev is cx.Element {
		s, _, p := jrn_attr_lookup(ev, 'schema')
		if p {
			return s
		}
	}
	return ''
}

// jrn_err_text reads the message= off an [err] VALUE (mk_err shape) for
// re-wrapping in the seam's own refusal.
fn jrn_err_text(n cx.Node) string {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'message' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return ''
}

// jrn_upcast_label names an entry for the CXER4641/4642 refusals: seq, hash,
// and the declared schema (or its visible absence).
fn jrn_upcast_label(e cx.Element) string {
	sq := jrn_entry_attr(e, 'seq')
	h := jrn_entry_attr(e, 'hash')
	sch := jrn_entry_schema(e)
	if sch == '' {
		return 'seq ${sq}, hash ${h}, schema undeclared'
	}
	return 'seq ${sq}, hash ${h}, schema ${sch}'
}

// ── the derived chain (RULED: SEA-1g) — [schema-lineage]+[derived] as the
// chain value, applied natively. The mechanical translators `cx schema
// compat` derives (schema.md §16.5.2) ride the Lane-2 claim as DATA (a
// generated pure def cannot spell a lossless rewrite — [?modify] is ruled
// impure, code.md §6.5.0); the seam applies the closed rule vocabulary
// (set-default / rename-attr / drop-attr / rename-elem / drop-elem) with
// lossless field-level surgery. Chain-wise discriminator (SEA-1b): an entry
// declaring schema= UNKNOWN to the claim set refuses (→ CXER4641); no
// declared schema passes through; each claim applies exactly where the
// entry's current address equals its [from], restamping to its [to]. The
// fn-chain surface is byte-identically untouched.

const jrn_derived_rule_names = ['set-default', 'rename-attr', 'drop-attr', 'rename-elem',
	'drop-elem']

// jrn_chain_derived_claims: the chain value as derived-form claims — one
// [schema-lineage] element or a sequence of them (lineage-path's output
// shape). Empty when the chain is not the derived form (a fn chain).
fn jrn_chain_derived_claims(chain cx.Node) []cx.Element {
	items := iterate(chain)
	mut out := []cx.Element{}
	for n in items {
		if n is cx.Element && n.name == 'schema-lineage' {
			out << n
		} else {
			return []cx.Element{}
		}
	}
	return out
}

// jrn_claim_derived: the claim's [derived …] rules child.
fn jrn_claim_derived(c cx.Element) ?cx.Element {
	for it in c.items {
		if it is cx.Element && it.name == 'derived' {
			return it
		}
	}
	return none
}

// jrn_chain_check validates a chain value at every engagement site: the
// derived form is structure-checked (fail-closed); a fn chain is held to the
// §2.7 purity bar exactly as before.
fn jrn_chain_check(chain cx.Node, mut env MatchEnv) ?cx.Node {
	claims := jrn_chain_derived_claims(chain)
	if claims.len == 0 {
		return jrn_assert_pure(chain, mut env)
	}
	for i, c in claims {
		edge, celem := jrn_lineage_parse(cx.Node(c), i) or {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: derived chain: ${err.msg()}')
		}
		_ = edge
		_ = celem
		d := jrn_claim_derived(c) or {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: derived chain: claim ${
				i + 1} carries no [derived] rules — a hand-written upcaster is a fn chain, never guessed from a claim (SEA-1g)')
		}
		for it in d.items {
			if it is cx.Element {
				if it.name !in jrn_derived_rule_names {
					return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: derived chain: unknown rule [${it.name}] — the closed vocabulary is set-default / rename-attr / drop-attr / rename-elem / drop-elem')
				}
			}
		}
	}
	return none
}

// jrn_elem_attr_txt reads one attribute's text off an element ('' absent).
fn jrn_elem_attr_txt(e cx.Element, name string) string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// jrn_derived_attr materializes a [set-default] value as a typed attribute
// (vtype = the schema-declared type of the defaulted field).
fn jrn_derived_attr(name string, v string, vt string) cx.Attribute {
	if vt in ['i8', 'i16', 'i32', 'i64', 'int', 'u8', 'u16', 'u32', 'u64'] {
		return cx.new_attribute(name, cx.ScalarValue(v.i64()), cx.AttributeMeta{})
	}
	if vt in ['f16', 'f32', 'f64', 'float'] {
		return cx.new_attribute(name, cx.ScalarValue(v.f64()), cx.AttributeMeta{})
	}
	if vt == 'bool' {
		return cx.new_attribute(name, cx.ScalarValue(v == 'true'), cx.AttributeMeta{})
	}
	if vt == 'atom' {
		av := if v.starts_with(':') { v[1..] } else { v }
		return cx.new_attribute(name, cx.ScalarValue(av), cx.AttributeMeta{
			data_type: ?string('atom')
		})
	}
	return cx.new_attribute(name, cx.ScalarValue(v), cx.AttributeMeta{})
}

// jrn_payload_put_attr sets/replaces one attribute on the payload element.
fn jrn_payload_put_attr(p cx.Element, na cx.Attribute) cx.Element {
	mut attrs := []cx.Attribute{cap: p.attrs.len + 1}
	mut done := false
	for a in p.attrs {
		if a.name == na.name {
			attrs << na
			done = true
		} else {
			attrs << a
		}
	}
	if !done {
		attrs << na
	}
	return cx.Element{
		name:  p.name
		attrs: attrs
		items: p.items
	}
}

// jrn_apply_derived_rules applies one claim's [derived] rules to the payload
// element — lossless field-level surgery: everything not named by a rule
// rides through untouched (SEA-1b).
fn jrn_apply_derived_rules(payload cx.Element, d cx.Element) cx.Element {
	mut p := payload
	for it in d.items {
		if it is cx.Element {
			match it.name {
				'set-default' {
					an := jrn_elem_attr_txt(it, 'attr')
					if an != '' {
						_, _, present := jrn_attr_lookup(p, an)
						if !present {
							p = jrn_payload_put_attr(p, jrn_derived_attr(an, jrn_elem_attr_txt(it,
								'value'), jrn_elem_attr_txt(it, 'vtype')))
						}
					}
				}
				'rename-attr' {
					from := jrn_elem_attr_txt(it, 'from')
					to := jrn_elem_attr_txt(it, 'to')
					if from != '' && to != '' {
						mut attrs := []cx.Attribute{cap: p.attrs.len}
						for a in p.attrs {
							if a.name == from {
								attrs << cx.Attribute{
									...a
									name: to
								}
							} else {
								attrs << a
							}
						}
						p = cx.Element{
							name:  p.name
							attrs: attrs
							items: p.items
						}
					}
				}
				'drop-attr' {
					an := jrn_elem_attr_txt(it, 'attr')
					if an != '' {
						mut attrs := []cx.Attribute{cap: p.attrs.len}
						for a in p.attrs {
							if a.name == an {
								continue
							}
							attrs << a
						}
						p = cx.Element{
							name:  p.name
							attrs: attrs
							items: p.items
						}
					}
				}
				'rename-elem' {
					from := jrn_elem_attr_txt(it, 'from')
					to := jrn_elem_attr_txt(it, 'to')
					if from != '' && to != '' {
						mut kids := []cx.Node{cap: p.items.len}
						for k in p.items {
							if k is cx.Element && k.name == from {
								kids << cx.Node(cx.Element{
									name:  to
									attrs: k.attrs
									items: k.items
								})
							} else {
								kids << k
							}
						}
						p = cx.Element{
							name:  p.name
							attrs: p.attrs
							items: kids
						}
					}
				}
				'drop-elem' {
					en := jrn_elem_attr_txt(it, 'elem')
					if en != '' {
						mut kids := []cx.Node{cap: p.items.len}
						for k in p.items {
							if k is cx.Element && k.name == en {
								continue
							}
							kids << k
						}
						p = cx.Element{
							name:  p.name
							attrs: p.attrs
							items: kids
						}
					}
				}
				else {}
			}
		}
	}
	return p
}

// jrn_upcast_apply_derived applies a derived claim chain to one hydrated
// entry: the SEA-1b chain-wise discriminator + native rule application.
// Same (out, errcode, reason) contract as jrn_upcast_raw.
fn jrn_upcast_apply_derived(entry cx.Element, claims []cx.Element) (cx.Node, string, string) {
	ev := jrn_entry_event(entry)
	if ev !is cx.Element {
		return cx.Node(entry), '', '' // non-element payload declares no schema=
	}
	mut payload := ev as cx.Element
	sch, _, has_sch := jrn_attr_lookup(payload, 'schema')
	if !has_sch || sch == '' {
		return cx.Node(entry), '', '' // no claim to translate — passes (SEA-1b)
	}
	mut known := map[string]bool{}
	for c in claims {
		known[jrn_lineage_child_text(c, 'from') or { '' }] = true
		known[jrn_lineage_child_text(c, 'to') or { '' }] = true
	}
	if sch !in known {
		return jrn_null(), jrn_err_upcast_uncovered, 'entry declares a schema the derived chain does not relate (${sch})'
	}
	mut cur := sch
	mut changed := false
	for c in claims {
		from := jrn_lineage_child_text(c, 'from') or { '' }
		if from != cur {
			continue
		}
		to := jrn_lineage_child_text(c, 'to') or { '' }
		if d := jrn_claim_derived(c) {
			payload = jrn_apply_derived_rules(payload, d)
		}
		payload = jrn_payload_put_attr(payload, cx.new_attribute('schema', cx.ScalarValue(to),
			cx.AttributeMeta{}))
		cur = to
		changed = true
	}
	if !changed {
		return cx.Node(entry), '', '' // already at the chain's terminal address
	}
	mut items := []cx.Node{cap: entry.items.len}
	for it in entry.items {
		if it is cx.Element && it.name == 'event' {
			items << cx.Node(cx.Element{
				name:  it.name
				attrs: it.attrs
				items: [cx.Node(payload)]
			})
		} else {
			items << it
		}
	}
	return cx.Node(cx.Element{
		name:  entry.name
		attrs: entry.attrs
		items: items
	}), '', ''
}

// jrn_upcast_raw applies the chain to one hydrated entry and re-assembles the
// result on the ORIGINAL envelope. Returns (out, errcode, reason) — errcode
// '' on success; jrn_err_upcast_uncovered/_invalid with the BARE reason
// otherwise (the fold seam wraps it into an [err]; the coverage pre-flight
// turns it into a finding).
fn jrn_upcast_raw(entry cx.Element, chain cx.Node, mut env MatchEnv) (cx.Node, string, string) {
	dclaims := jrn_chain_derived_claims(chain)
	if dclaims.len > 0 {
		return jrn_upcast_apply_derived(entry, dclaims)
	}
	r := apply_fn_value(chain, [cx.Node(entry)], mut env) or {
		return jrn_null(), jrn_err_upcast_uncovered, err.msg()
	}
	if is_err_value(r) {
		return jrn_null(), jrn_err_upcast_uncovered, jrn_err_text(r)
	}
	if r is cx.Element {
		if r.name != 'entry' {
			return jrn_null(), jrn_err_upcast_invalid, 'the chain must return an [entry]'
		}
		if jrn_entry_attr(r, 'seq') != jrn_entry_attr(entry, 'seq')
			|| jrn_entry_attr(r, 'hash') != jrn_entry_attr(entry, 'hash') {
			return jrn_null(), jrn_err_upcast_invalid, "the envelope is the journal's — the chain rewrote seq=/hash="
		}
		if !jrn_entry_has_event(r) || jrn_entry_event(r) !is cx.Element {
			return jrn_null(), jrn_err_upcast_invalid, 'the chain dropped the [event] payload — an upcaster never shreds'
		}
		// Original envelope + non-event children carried forward; the chain's
		// output supplies the [event] wrapper (payload) only.
		mut items := []cx.Node{cap: entry.items.len}
		for it in entry.items {
			if it is cx.Element && it.name == 'event' {
				for rit in r.items {
					if rit is cx.Element && rit.name == 'event' {
						items << rit
					}
				}
			} else {
				items << it
			}
		}
		return cx.Node(cx.Element{
			name:  entry.name
			attrs: entry.attrs
			items: items
		}), '', ''
	}
	return jrn_null(), jrn_err_upcast_invalid, 'the chain must return an [entry]'
}

// jrn_upcast_one is the fold-seam form: jrn_upcast_raw wrapped into a loud
// typed [err] naming the entry (L151 — never absence, never a skip).
fn jrn_upcast_one(entry cx.Element, chain cx.Node, mut env MatchEnv) (cx.Node, cx.Node, bool) {
	out, ecode, reason := jrn_upcast_raw(entry, chain, mut env)
	if ecode == '' {
		return out, jrn_null(), true
	}
	if ecode == jrn_err_upcast_uncovered {
		return jrn_null(), mk_err(ecode, 'E_JOURNAL_UPCAST_UNCOVERED: no upcaster covers entry (${jrn_upcast_label(entry)}): ${reason}'), false
	}
	return jrn_null(), mk_err(ecode, 'E_JOURNAL_UPCAST_INVALID: ${reason} (${jrn_upcast_label(entry)})'), false
}

// jrn_cov_finding builds one coverage finding (:uncovered-entry /
// :upcast-invalid) — seq + hash + the declared schema= made visible.
fn jrn_cov_finding(kind string, stream string, e cx.Element, reason string) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'kind'
			value: cx.ScalarValue(':${kind}')
		},
	]
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << cx.Attribute{
		name:  'seq'
		value: cx.ScalarValue(i64(jrn_entry_attr(e, 'seq').int()))
	}
	attrs << cx.Attribute{
		name:  'hash'
		value: cx.ScalarValue(jrn_entry_attr(e, 'hash'))
	}
	sch := jrn_entry_schema(e)
	if sch != '' {
		attrs << cx.Attribute{
			name:  'schema'
			value: cx.ScalarValue(sch)
		}
	}
	if reason != '' {
		attrs << cx.Attribute{
			name:  'reason'
			value: cx.ScalarValue(reason)
		}
	}
	return cx.Node(cx.Element{
		name:  'finding'
		attrs: attrs
	})
}

// jrn_cov_check dry-applies the chain to one entry, appending a coverage
// finding on refusal — findings, never aborts (the L151 pre-flight).
fn jrn_cov_check(n cx.Node, stream string, chain cx.Node, mut findings []cx.Node, mut env MatchEnv) {
	if n is cx.Element {
		if !jrn_entry_has_event(n) {
			return // shredded — counted erased= by the linkage walk (L119)
		}
		_, ecode, reason := jrn_upcast_raw(n, chain, mut env)
		if ecode == '' {
			return
		}
		kind := if ecode == jrn_err_upcast_invalid { 'upcast-invalid' } else { 'uncovered-entry' }
		findings << jrn_cov_finding(kind, stream, n, reason)
	}
}

// jrn_cov_scan applies the chain over one stream's retained entries — the
// same entries the fold would see.
fn jrn_cov_scan(j &Journal, stream string, chain cx.Node, mut findings []cx.Node, mut env MatchEnv) {
	if jrn_is_default(stream) {
		for n in jrn_collect_range(j, j.base_seq + 1, j.head_seq) {
			jrn_cov_check(n, stream, chain, mut findings, mut env)
		}
		return
	}
	st := j.named[stream] or { return }
	for entry in jrn_state_collect_range(st, st.base_seq + 1, st.head_seq) {
		jrn_cov_check(jrn_hydrate_entry(j.store_id, entry), stream, chain, mut findings, mut env)
	}
}

// jrn_upcast_entries maps the chain over materialized entries — the generic
// pure entry-seq → entry-seq stage ahead of the reducer. Event-less entries
// pass through untouched; non-element items pass through unchanged.
fn jrn_upcast_entries(entries []cx.Node, chain cx.Node, mut env MatchEnv) ([]cx.Node, cx.Node, bool) {
	mut out := []cx.Node{cap: entries.len}
	for n in entries {
		if n is cx.Element {
			if !jrn_entry_has_event(n) {
				out << n // shredded — unjudgeable, kept VISIBLE (L119)
				continue
			}
			u, errn, ok := jrn_upcast_one(n, chain, mut env)
			if !ok {
				return []cx.Node{}, errn, false
			}
			out << u
		} else {
			out << n
		}
	}
	return out, jrn_null(), true
}

// jrn_upcast_stage is the composition point the fold surfaces call: the
// upcast stage when a chain is engaged, the identity stage otherwise —
// always ahead of the §3.8 projection (upcast THEN valid-time, L146).
fn jrn_upcast_stage(entries []cx.Node, has_up bool, chain cx.Node, mut env MatchEnv) ([]cx.Node, cx.Node, bool) {
	if !has_up {
		return entries, jrn_null(), true
	}
	return jrn_upcast_entries(entries, chain, mut env)
}

// jrn_upcast is the PURE seam verb over already-materialized entries (the
// temporal-slice twin): [$journal:upcast $entries $chain].
fn jrn_upcast(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: upcast expects (entries, chain)')
	}
	chain := args[1]
	if e := jrn_chain_check(chain, mut env) {
		return e
	}
	entries := iterate(args[0])
	out, errn, ok := jrn_upcast_entries(entries, chain, mut env)
	if !ok {
		return errn
	}
	if out.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(out)
}

// ── §3.9 the lineage load — [schema-lineage] claims → a chain (stream 21) ───
//
// The lineage graph is a set of Lane-2 [schema-lineage [from A] [to B]
// [relation :additive|:narrowing|:split|:merge] [upcaster …]] claim VALUES
// (L149 — the type-binding shape; endpoints are schema CONTENT ADDRESSES,
// never version strings). lineage-path is the REGISTRY LOAD: it validates
// the whole graph fail-closed — a duplicate edge, a cycle, or ANY pair of
// endpoints admitting two paths refuses CXER4643 (an ambiguous graph must
// never silently pick a chain) — then returns the claims along the UNIQUE
// from→to path in composition order. No path between the asked endpoints
// is CXER4644 (loud — the pre-execution twin of the seam's CXER4641).
// Malformed claims are the caller's args: CXER4610.

const jrn_err_lineage_ambiguous = 'cx-err:CXER4643' // E_JOURNAL_LINEAGE_AMBIGUOUS
const jrn_err_lineage_no_path = 'cx-err:CXER4644' // E_JOURNAL_LINEAGE_NO_PATH

const jrn_lineage_relations = ['additive', 'narrowing', 'split', 'merge']

// jrn_lineage_child_text reads a claim child's scalar/text content.
fn jrn_lineage_child_text(e cx.Element, name string) ?string {
	for it in e.items {
		if it is cx.Element && it.name == name {
			if it.items.len > 0 {
				v := it.items[0]
				if v is cx.ScalarNode {
					return cx.scalar_value_str_public(v.value)
				}
				if v is cx.TextNode {
					return v.value
				}
			}
			return none
		}
	}
	return none
}

struct JrnLineageEdge {
	from string
	to   string
	idx  int
}

// jrn_lineage_parse validates one claim element and returns its edge.
fn jrn_lineage_parse(n cx.Node, idx int) !(JrnLineageEdge, cx.Element) {
	if n !is cx.Element {
		return error('claim ${idx + 1} is not a [schema-lineage] element')
	}
	e := n as cx.Element
	if e.name != 'schema-lineage' {
		return error('claim ${idx + 1} is not a [schema-lineage] element (got [${e.name}])')
	}
	from := jrn_lineage_child_text(e, 'from') or {
		return error('claim ${idx + 1} missing [from <address>]')
	}
	to := jrn_lineage_child_text(e, 'to') or {
		return error('claim ${idx + 1} missing [to <address>]')
	}
	if !from.contains(':') || !to.contains(':') {
		return error('claim ${idx + 1} endpoints must be content addresses')
	}
	rel := jrn_lineage_child_text(e, 'relation') or {
		return error('claim ${idx + 1} missing [relation :additive|:narrowing|:split|:merge]')
	}
	if rel !in jrn_lineage_relations {
		return error('claim ${idx + 1} relation must be :additive, :narrowing, :split, or :merge (got ${rel})')
	}
	return JrnLineageEdge{
		from: from
		to:   to
		idx:  idx
	}, e
}

// jrn_lineage_count_paths counts simple from→to walks on a DAG (bounded by
// the cycle check having already passed).
fn jrn_lineage_count_paths(adj map[string][]string, from string, to string) int {
	if from == to {
		return 1
	}
	mut total := 0
	for nxt in adj[from] {
		total += jrn_lineage_count_paths(adj, nxt, to)
		if total > 1 {
			return total // early out — two is already ambiguous
		}
	}
	return total
}

// jrn_lineage_has_cycle DFS-colors the graph.
fn jrn_lineage_has_cycle(adj map[string][]string, node string, mut state map[string]int) bool {
	state[node] = 1
	for nxt in adj[node] {
		st := state[nxt]
		if st == 1 {
			return true
		}
		if st == 0 && jrn_lineage_has_cycle(adj, nxt, mut state) {
			return true
		}
	}
	state[node] = 2
	return false
}

// jrn_lineage_path is the pure load verb:
// [$journal:lineage-path $claims $from $to].
fn jrn_lineage_path(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: lineage-path expects (claims, from, to)')
	}
	from_q := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: lineage-path from must be a schema address')
	}
	to_q := jrn_arg_str(args[2]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: lineage-path to must be a schema address')
	}
	claims := iterate(args[0])
	mut edges := []JrnLineageEdge{}
	mut claim_elems := []cx.Element{}
	mut adj := map[string][]string{}
	mut seen_edge := map[string]bool{}
	mut nodes := map[string]bool{}
	for i, n in claims {
		edge, elem := jrn_lineage_parse(n, i) or {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: ${err.msg()}')
		}
		key := '${edge.from} -> ${edge.to}'
		if key in seen_edge {
			return mk_err(jrn_err_lineage_ambiguous, 'E_JOURNAL_LINEAGE_AMBIGUOUS: two claims relate ${key} — an ambiguous graph is rejected at load, fail-closed')
		}
		seen_edge[key] = true
		adj[edge.from] << edge.to
		nodes[edge.from] = true
		nodes[edge.to] = true
		edges << edge
		claim_elems << elem
	}
	// Cycles first (they would defeat simple-path counting), then the
	// global unique-path invariant: EVERY pair, not just the asked one.
	mut state := map[string]int{}
	for node, _ in nodes {
		if state[node] == 0 {
			if jrn_lineage_has_cycle(adj, node, mut state) {
				return mk_err(jrn_err_lineage_ambiguous, 'E_JOURNAL_LINEAGE_AMBIGUOUS: the lineage graph has a cycle — evolution is a DAG; rejected at load, fail-closed')
			}
		}
	}
	for u, _ in nodes {
		for w, _ in nodes {
			if u != w && jrn_lineage_count_paths(adj, u, w) > 1 {
				return mk_err(jrn_err_lineage_ambiguous, 'E_JOURNAL_LINEAGE_AMBIGUOUS: two paths relate ${u} -> ${w} — an ambiguous graph is rejected at load, fail-closed')
			}
		}
	}
	if from_q == to_q {
		return jrn_empty() // the identity chain — nothing to compose
	}
	// The unique walk, collecting claims in composition order.
	mut out := []cx.Node{}
	mut cur := from_q
	for cur != to_q {
		mut advanced := false
		for i, edge in edges {
			if edge.from == cur {
				if jrn_lineage_count_paths(adj, edge.to, to_q) > 0 || edge.to == to_q {
					out << cx.Node(claim_elems[i])
					cur = edge.to
					advanced = true
					break
				}
			}
		}
		if !advanced {
			return mk_err(jrn_err_lineage_no_path, 'E_JOURNAL_LINEAGE_NO_PATH: no lineage path relates ${from_q} -> ${to_q} — the graph does not cover this evolution')
		}
	}
	return jrn_seq(out)
}

// ── snapshot machinery (shared between env + env-free verbs) ───────────────

// jrn_snapshot_canonical builds the signed bytes: (state + at-seq + anchor +
// algo) canonical.
fn jrn_snapshot_canonical(state cx.Node, at_seq int, stream string, anchor string, algo string, fold_id string) string {
	mut attrs := [
		cx.Attribute{
			name:  'at-seq'
			value: cx.ScalarValue(i64(at_seq))
		},
	]
	// stream bound into the signed bytes for non-default streams only (omitted
	// when :default → default snapshot signatures are byte-identical, §2.1.1).
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << cx.Attribute{
		name:  'anchor-hash'
		value: cx.ScalarValue(anchor)
	}
	attrs << cx.Attribute{
		name:  'hash-algo'
		value: cx.ScalarValue(algo)
	}
	// fold-id fills the §4.8 RESERVED signed-preimage slot (I1 epoch, audit
	// C1; stream 21 L147): omitted while unset, so pre-stream-21 snapshot
	// signatures are byte-identical.
	if fold_id != '' {
		attrs << cx.Attribute{
			name:  'fold-id'
			value: cx.ScalarValue(fold_id)
		}
	}
	rec := cx.Element{
		name:  'snapshot-canonical'
		attrs: attrs
		items: [state]
	}
	return render_canonical(rec)
}

// jrn_sign signs the canonical snapshot bytes with the ed25519 seed (a crypto
// key handle = 32-byte seed bytes). Composes crypto.ed25519 (the same RFC-8032
// engine cx-stdlib/crypto exposes — journal adds no signing primitive, §4.8).
fn jrn_sign(canonical string, seed []u8) ?string {
	if seed.len != 32 {
		return none
	}
	priv := ed25519.new_key_from_seed(seed)
	sig := priv.sign(canonical.bytes()) or { return none }
	return sig.hex()
}

fn jrn_snapshot_verify_sig(canonical string, sig_hex string, pub_bytes []u8) bool {
	sig := jrn_hex_to_bytes(sig_hex) or { return false }
	if pub_bytes.len != 32 || sig.len != 64 {
		return false
	}
	ok := ed25519.verify(ed25519.PublicKey(pub_bytes), canonical.bytes(), sig) or { return false }
	return ok
}

fn jrn_hex_to_bytes(s string) ?[]u8 {
	if s.len % 2 != 0 {
		return none
	}
	mut out := []u8{cap: s.len / 2}
	for i := 0; i < s.len; i += 2 {
		hi := jrn_hex_nibble(s[i]) or { return none }
		lo := jrn_hex_nibble(s[i + 1]) or { return none }
		out << u8(hi * 16 + lo)
	}
	return out
}

fn jrn_hex_nibble(c u8) ?int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a` + 10)
	}
	if c >= `A` && c <= `F` {
		return int(c - `A` + 10)
	}
	return none
}

// jrn_build_snapshot builds the [snapshot …] value. `signer` (S6.4, §4.8) is
// the UNSIGNED outer hint — recorded alongside sig-algo=/signature= on signed
// snapshots only, never part of the frozen snapshot-canonical preimage.
fn jrn_build_snapshot(tenant string, at_seq int, stream string, anchor string, algo string, fold_id string, signed bool, sig_hex string, pub_hex string, signer string, state cx.Node) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'tenant'
			value: cx.ScalarValue(tenant)
		},
		cx.Attribute{
			name:  'at-seq'
			value: cx.ScalarValue(i64(at_seq))
		},
	]
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << cx.Attribute{
		name:  'anchor-hash'
		value: cx.ScalarValue(anchor)
	}
	attrs << cx.Attribute{
		name:  'hash-algo'
		value: cx.ScalarValue(algo)
	}
	if fold_id != '' {
		attrs << cx.Attribute{
			name:  'fold-id'
			value: cx.ScalarValue(fold_id)
		}
	}
	if signed {
		attrs << cx.Attribute{
			name:  'sig-algo'
			value: cx.ScalarValue('ed25519')
		}
		attrs << cx.Attribute{
			name:  'signature'
			value: cx.ScalarValue(sig_hex)
		}
		attrs << cx.Attribute{
			name:  'verify-key'
			value: cx.ScalarValue(pub_hex)
		}
		if signer != '' {
			attrs << cx.Attribute{
				name:  'signer'
				value: cx.ScalarValue(signer)
			}
		}
	} else {
		attrs << cx.Attribute{
			name:  'sig-algo'
			value: cx.ScalarValue('none')
		}
	}
	return cx.Element{
		name:  'snapshot'
		attrs: attrs
		items: [
			cx.Element{
				name:  'state'
				items: [state]
			},
		]
	}
}

fn jrn_snapshot_state(snap cx.Element) cx.Node {
	for it in snap.items {
		if it is cx.Element {
			if it.name == 'state' {
				if it.items.len == 1 {
					return it.items[0]
				}
				return jrn_seq(it.items.clone())
			}
		}
	}
	return jrn_null()
}

fn jrn_snapshot_attr(snap cx.Element, name string) string {
	for a in snap.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// jrn_snapshot_check validates a [snapshot] against the chain + its signature.
// Returns (valid, reason). reason is '' on valid, else the finding reason.
fn jrn_snapshot_check(j &Journal, snap cx.Element) (bool, string) {
	at_seq := jrn_snapshot_attr(snap, 'at-seq').int()
	anchor := jrn_snapshot_attr(snap, 'anchor-hash')
	algo := jrn_snapshot_attr(snap, 'hash-algo')
	stream := jrn_snapshot_attr(snap, 'stream') // '' → default (§2.1.1)
	if algo != '' && algo != j.hash_algo {
		return false, 'algo-mismatch'
	}
	// anchor-hash must equal the live hash of entry at-seq, on the snapshot's stream.
	live := if !jrn_is_default(stream) {
		st := j.named[stream] or { return false, 'anchor-mismatch' }
		jrn_state_live_hash(st, at_seq)
	} else {
		jrn_live_hash(j, at_seq)
	}
	if live == '' || live != anchor {
		return false, 'anchor-mismatch'
	}
	sig_algo := jrn_snapshot_attr(snap, 'sig-algo')
	if sig_algo == 'none' || sig_algo == '' {
		if jrn_snapshot_attr(snap, 'signature') != '' {
			// A signature riding the snapshot with its suite tag stripped
			// (or tagged none) is the L36 downgrade attack, not the unsigned
			// tier (crypto_agility §1.4, #691 §10) — fail closed.
			return false, 'unsupported-suite'
		}
		// unsigned: anchor-only validity, a valid=true caveat (§3.7).
		return true, 'unsigned'
	}
	// I1 stream 19 (L36/#702): FAIL CLOSED on any suite the registry does
	// not verify — never a fall-through attempt with the wrong primitive
	// (the check previously assumed ed25519 whatever the attr said).
	cx.cx_suite_verify_gate(sig_algo) or { return false, 'unsupported-suite' }
	state := jrn_snapshot_state(snap)
	canonical := jrn_snapshot_canonical(state, at_seq, stream, anchor, algo,
		jrn_snapshot_attr(snap, 'fold-id'))
	sig_hex := jrn_snapshot_attr(snap, 'signature')
	// S6.4 key resolution (§3.7/§4.8): a signer= outer hint, when present,
	// is the ONLY key source — resolved offline from the self-describing DID
	// (did:key/did:peer:0), never from the unsigned verify-key= field. A
	// mismatched signer/key therefore fails the signature check below; an
	// unresolvable signer is its own finding. Absent signer, the pre-S6.4
	// verify-key= path is unchanged.
	signer := jrn_snapshot_attr(snap, 'signer')
	pub_bytes := if signer != '' {
		did_key_bytes(signer) or { return false, 'signer-unresolvable' }
	} else {
		pub_hex := jrn_snapshot_attr(snap, 'verify-key')
		jrn_hex_to_bytes(pub_hex) or { return false, 'signature-invalid' }
	}
	if !jrn_snapshot_verify_sig(canonical, sig_hex, pub_bytes) {
		return false, 'signature-invalid'
	}
	return true, ''
}

fn jrn_snapshot_verification(valid bool, reason string, at_seq int) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'valid'
			value: cx.ScalarValue(valid)
		},
		cx.Attribute{
			name:  'at-seq'
			value: cx.ScalarValue(i64(at_seq))
		},
	]
	if reason != '' {
		attrs << cx.Attribute{
			name:  'reason'
			value: cx.ScalarValue(':' + reason)
		}
	}
	return cx.Element{
		name:  'snapshot-verification'
		attrs: attrs
	}
}

// ── §3.7 multi-stream: the tenant SET snapshot (stream 7 W6, #679) ────────
//
// A tenant snapshot (no stream=) over a journal WITH named streams records
// the SET of stream heads {(stream, at-seq, anchor-hash)} plus each member's
// folded state, under ONE signature — the verifiable multi-stream READ
// coordinate (`:at-head-set` — the CUT is taken under the journal op funnel,
// one instant across all streams). The tenant-wide composition of the member
// states stays the CALLER's (§3.4 — the journal cannot merge opaque user
// states); `fold-slice` seeded by a member's state consumes a member.
// The set preimage is a NEW synthetic element (`snapshot-set-canonical`) —
// ADDITIVE: every existing single-stream preimage is byte-unmoved (§4.8).

// jrn_set_member builds one [h (stream=)? at-seq= anchor-hash= [state V]]
// member — shared verbatim by the canonical (signed bytes) and the artifact,
// so verify re-renders the artifact's own members byte-identically.
fn jrn_set_member(stream string, at_seq int, anchor string, state cx.Node) cx.Element {
	mut attrs := []cx.Attribute{}
	if !jrn_is_default(stream) {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	attrs << cx.Attribute{
		name:  'at-seq'
		value: cx.ScalarValue(i64(at_seq))
	}
	attrs << cx.Attribute{
		name:  'anchor-hash'
		value: cx.ScalarValue(anchor)
	}
	return cx.Element{
		name:  'h'
		attrs: attrs
		items: [
			cx.Node(cx.Element{
				name:  'state'
				items: [state]
			}),
		]
	}
}

// jrn_snapshot_set_canonical renders the signed bytes of a SET snapshot:
// [snapshot-set-canonical hash-algo=A [h …]…] — members in build order
// (default chain first, then named streams sorted by name).
fn jrn_snapshot_set_canonical(members []cx.Element, algo string) string {
	mut items := []cx.Node{}
	for m in members {
		items << cx.Node(m)
	}
	rec := cx.Element{
		name:  'snapshot-set-canonical'
		attrs: [
			cx.Attribute{
				name:  'hash-algo'
				value: cx.ScalarValue(algo)
			},
		]
		items: items
	}
	return render_canonical(rec)
}

// jrn_snapshot_is_set reports the set form (discriminated by [h] members).
fn jrn_snapshot_is_set(snap cx.Element) bool {
	for it in snap.items {
		if it is cx.Element && it.name == 'h' {
			return true
		}
	}
	return false
}

fn jrn_snapshot_members(snap cx.Element) []cx.Element {
	mut out := []cx.Element{}
	for it in snap.items {
		if it is cx.Element && it.name == 'h' {
			out << it
		}
	}
	return out
}

// jrn_snapshot_set_verification builds the SET-form finding.
fn jrn_snapshot_set_verification(valid bool, reason string, stream string) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'valid'
			value: cx.ScalarValue(valid)
		},
		cx.Attribute{
			name:  'form'
			value: cx.ScalarValue('set')
		},
	]
	if stream != '' {
		attrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	if reason != '' {
		attrs << cx.Attribute{
			name:  'reason'
			value: cx.ScalarValue(':' + reason)
		}
	}
	return cx.Element{
		name:  'snapshot-verification'
		attrs: attrs
	}
}

// jrn_snapshot_check_set verifies a SET snapshot: per-member anchor vs the
// live chain (naming the failing stream), algo match, and the one signature
// over the set canonical (same key-resolution rules as the single form).
fn jrn_snapshot_check_set(j &Journal, snap cx.Element) cx.Node {
	algo := jrn_snapshot_attr(snap, 'hash-algo')
	if algo != '' && algo != j.hash_algo {
		return jrn_snapshot_set_verification(false, 'algo-mismatch', '')
	}
	members := jrn_snapshot_members(snap)
	if members.len == 0 {
		return jrn_snapshot_set_verification(false, 'anchor-mismatch', '')
	}
	for m in members {
		stream := jrn_entry_attr(m, 'stream')
		at_seq := jrn_entry_attr(m, 'at-seq').int()
		anchor := jrn_entry_attr(m, 'anchor-hash')
		live := if !jrn_is_default(stream) {
			st := j.named[stream] or {
				return jrn_snapshot_set_verification(false, 'anchor-mismatch', stream)
			}
			jrn_state_live_hash(st, at_seq)
		} else {
			jrn_live_hash(j, at_seq)
		}
		if live == '' || live != anchor {
			return jrn_snapshot_set_verification(false, 'anchor-mismatch', stream)
		}
	}
	sig_algo := jrn_snapshot_attr(snap, 'sig-algo')
	if sig_algo == 'none' || sig_algo == '' {
		if jrn_snapshot_attr(snap, 'signature') != '' {
			return jrn_snapshot_set_verification(false, 'unsupported-suite', '')
		}
		return jrn_snapshot_set_verification(true, 'unsigned', '')
	}
	cx.cx_suite_verify_gate(sig_algo) or {
		return jrn_snapshot_set_verification(false, 'unsupported-suite', '')
	}
	canonical := jrn_snapshot_set_canonical(members, algo)
	sig_hex := jrn_snapshot_attr(snap, 'signature')
	signer := jrn_snapshot_attr(snap, 'signer')
	pub_bytes := if signer != '' {
		did_key_bytes(signer) or {
			return jrn_snapshot_set_verification(false, 'signer-unresolvable', '')
		}
	} else {
		pub_hex := jrn_snapshot_attr(snap, 'verify-key')
		jrn_hex_to_bytes(pub_hex) or {
			return jrn_snapshot_set_verification(false, 'signature-invalid', '')
		}
	}
	if !jrn_snapshot_verify_sig(canonical, sig_hex, pub_bytes) {
		return jrn_snapshot_set_verification(false, 'signature-invalid', '')
	}
	return jrn_snapshot_set_verification(true, '', '')
}

fn jrn_snapshot_verify(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: snapshot-verify expects (journal, snapshot)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	if args[1] !is cx.Element {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: snapshot-verify expects a [snapshot]')
	}
	snap := args[1] as cx.Element
	if snap.name != 'snapshot' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: not a [snapshot]')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	// S6.4 (§6.1): over a cx-store(+xsp):// handle the crypto check rides the
	// pushdown journal-snapshot-verify — ONE exchange, the anchor checked
	// against the daemon's AUTHORITATIVE chain, the finding (or refusal)
	// crossing verbatim. The appointment layer below is client-side either
	// way — the registry handle is local.
	mut finding := cx.Node(cx.Element{})
	mut have := false
	if ms := store_lookup(j.store_id) {
		if ms.remote != unsafe { nil } && ms.remote.xsp != unsafe { nil } {
			hex := sxj_image(cx.Node(snap))
			r, okx := xcl_exchange(ms.remote, 'journal-snapshot-verify', '[journal-snapshot-verify tenant="${j.tenant}" [snapshot::bytes 0x${hex}]]')
			if !okx || is_err_value(r) {
				return r
			}
			finding = r
			have = true
		}
	}
	if !have {
		if jrn_snapshot_is_set(snap) {
			finding = jrn_snapshot_check_set(j, snap)
		} else {
			at_seq := jrn_snapshot_attr(snap, 'at-seq').int()
			valid, reason := jrn_snapshot_check(j, snap)
			finding = jrn_snapshot_verification(valid, reason, at_seq)
		}
	}
	return jrn_snapshot_appointment(snap, opts, finding)
}

// jrn_map_element extracts an element child named `name` from a `{key: [name …]}`
// map entry (the jrn_map_snapshot traversal, generalized).
fn jrn_map_element(m cx.Node, key string, name string) ?cx.Element {
	if m is cx.Element {
		for it in m.items {
			if it is cx.Element {
				if it.name == key && it.items.len > 0 {
					inner := it.items[0]
					if inner is cx.Element && inner.name == name {
						return inner
					}
				}
				if it.name == name {
					return it
				}
			}
		}
	}
	return none
}

// jrn_snapshot_appointment applies the S6.4 opt-in appointment layer (§3.7):
// under opts.require-appointed the crypto-valid snapshot's signature-bound
// signer= DID must hold the `snapshot-sign` capability — over opts.scope when
// given — in the caller-designated [authz-store] registry (opts.authz), the
// same VC-compiled capability calculus as the profile's §6.1 rows. Failure is
// the FINDING valid=false reason=:not-appointed (the registry's [deny …] as
// its child) — never a fault; a missing/closed registry handle is the misuse
// CXER4610. Without require-appointed the crypto finding passes through
// untouched (the pre-S6.4 shape).
fn jrn_snapshot_appointment(snap cx.Element, opts cx.Node, finding cx.Node) ?cx.Node {
	if (jrn_map_get(opts, 'require-appointed') or { '' }) != 'true' {
		return finding
	}
	az := jrn_map_element(opts, 'authz', 'authz-store') or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: require-appointed needs opts.authz (an open [authz-store …] registry handle)')
	}
	s := authz_store_from_arg(cx.Node(az)) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: require-appointed needs opts.authz (an open [authz-store …] registry handle)')
	}
	if finding !is cx.Element {
		return finding
	}
	fe := finding as cx.Element
	if jrn_snapshot_attr(fe, 'valid') != 'true' {
		// the crypto reason dominates — an artifact that fails the pure check
		// is never additionally adjudicated.
		return finding
	}
	at_seq := jrn_snapshot_attr(fe, 'at-seq').int()
	signer := jrn_snapshot_attr(snap, 'signer')
	if signer == '' || jrn_snapshot_attr(fe, 'reason') == ':unsigned' {
		// no signature-bound signer to adjudicate — an unsigned snapshot or a
		// hint-less signed one cannot be the appointed signer's (fail closed).
		return jrn_snapshot_verification(false, 'not-appointed', at_seq)
	}
	scope := jrn_map_get(opts, 'scope') or { '' }
	mut req_items := [
		cx.Node(cx.Element{
			name:  'actor'
			items: [
				cx.Node(cx.Element{
					name:  'agent'
					attrs: [cx.Attribute{
						name:  'id'
						value: cx.ScalarValue(signer)
					}]
				}),
			]
		}),
		cx.Node(cx.Element{
			name:  'capability'
			attrs: [cx.Attribute{
				name:  'name'
				value: cx.ScalarValue('snapshot-sign')
			}]
		}),
	]
	if scope != '' {
		req_items << cx.Node(cx.Element{
			name:  'slice'
			attrs: [cx.Attribute{
				name:  'path'
				value: cx.ScalarValue(scope)
			}]
		})
	}
	req_items << cx.Node(cx.Element{
		name:  'tenant'
		attrs: [cx.Attribute{
			name:  'id'
			value: cx.ScalarValue(s.tenant)
		}]
	})
	dec := authz_decide(s, cx.Element{ name: 'authz-request', items: req_items },
		map[string]cx.Node{})
	if dec is cx.Element && dec.name == 'permit' {
		return finding
	}
	return cx.Element{
		name:  'snapshot-verification'
		attrs: [
			cx.Attribute{
				name:  'valid'
				value: cx.ScalarValue(false)
			},
			cx.Attribute{
				name:  'at-seq'
				value: cx.ScalarValue(i64(at_seq))
			},
			cx.Attribute{
				name:  'reason'
				value: cx.ScalarValue(':not-appointed')
			},
		]
		items: [dec]
	}
}

// ── retention ──────────────────────────────────────────────────────────────

// jrn_map_get_node reads an ELEMENT-valued opts entry (jrn_map_get reads
// scalars only).
fn jrn_map_get_node(m cx.Node, key string) ?cx.Node {
	if m is cx.Element {
		if m.name == '__cx_map__' || m.name == 'map' {
			for it in m.items {
				if it is cx.Element && it.name == key {
					if it.items.len > 0 {
						return it.items[0]
					}
				}
			}
		}
	}
	return none
}

// jrn_declare_adapter_stream applies an open-time `declare=` opt — the
// stream-7 handle-floor slice the live-modes adapter contract mandates
// (L134: the guarantee ladder is DECLARED per adapter stream; "one
// declaration mechanism — stream 7's"). The declaration persists in the
// journal's own store behind `cx-live/adapter/<tenant>[/s/<stream>]`;
// re-declaration is idempotent, a CONFLICTING re-declaration refuses
// (the fabric §9.1 group-policy precedent). Returns the refusal, or none.
fn jrn_declare_adapter_stream(j &Journal, dnode cx.Node) ?cx.Node {
	if dnode !is cx.Element {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: declare= expects an [adapter-stream stream= rung= writer=] element')
	}
	el := dnode as cx.Element
	if el.name != 'adapter-stream' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: declare= expects an [adapter-stream …] element (got [${el.name}])')
	}
	stream := el.attr('stream')
	rung := el.attr('rung')
	writer := el.attr('writer')
	if rung !in [':complete-ordered', ':coalesced-rescan', ':snapshot-diff'] {
		return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: adapter-stream declaration — rung `${rung}` is not a ladder atom (:complete-ordered | :coalesced-rescan | :snapshot-diff)')
	}
	if writer == '' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: adapter-stream declaration needs a writer= principal (adapter-is-only-client)')
	}
	if j.read_only {
		return mk_err(jrn_err_read_only, 'E_JOURNAL_READ_ONLY: adapter-stream declaration on a read-only journal')
	}
	sname := if jrn_is_default(stream) { '' } else { stream }
	key := live_adapter_decl_alias(j.tenant, sname)
	// existing declaration: idempotent match, conflicting refusal.
	if existing := jrn_read_adapter_decl(j, sname) {
		if existing.attr('rung') == rung && existing.attr('writer') == writer {
			return none
		}
		return mk_err(live_err_policy_invalid, 'E_LIVE_POLICY_INVALID: adapter-stream `${stream}` is already declared (rung=${existing.attr('rung')} writer=${existing.attr('writer')}) — a conflicting re-declaration is refused; the declaration is checked once at the handle floor')
	}
	doc := cx.Element{
		name:  'adapter-stream'
		attrs: [
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(stream)
			},
			cx.Attribute{
				name:  'rung'
				value: cx.ScalarValue(rung)
			},
			cx.Attribute{
				name:  'writer'
				value: cx.ScalarValue(writer)
			},
		]
	}
	if e := jrn_set_meta_alias(j.store_id, key, cx.Node(doc)) {
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: adapter-stream declaration write failed', e)
	}
	return none
}

// jrn_read_adapter_decl loads a stream's [adapter-stream] declaration doc
// from the journal's own store, or none.
fn jrn_read_adapter_decl(j &Journal, sname string) ?cx.Element {
	ms := store_lookup(j.store_id) or { return none }
	_, target := live_alias_pos(ms, live_adapter_decl_alias(j.tenant, sname))
	if target == '' {
		return none
	}
	text := store_doc_text(ms, target) or { return none }
	root := store_decode_doc(text)
	if root is cx.Element {
		if root.name == 'adapter-stream' {
			return root
		}
	}
	return none
}

// jrn_declared_writer answers a stream's declared writer principal, or none.
fn jrn_declared_writer(j &Journal, stream string) ?string {
	sname := if jrn_is_default(stream) { '' } else { stream }
	d := jrn_read_adapter_decl(j, sname) or { return none }
	w := d.attr('writer')
	if w == '' {
		return none
	}
	return w
}

// ── [$journal:subscribe] / [$journal:seq-at] (§3.3; RULED: U1.13a/U1.14a) ────
//
// NOTE: both run inside the dispatch funnel, which HOLDS j.jmu (a plain,
// non-reentrant mutex) — every read here is direct field access, never a
// nested journal_stdlib_builtin call.

// jrn_stream_view reads (head, floor) for one stream, refreshing the head
// from the durable store first (shared roots).
fn jrn_stream_view(mut j Journal, stream string) (int, int) {
	jrn_refresh_head(mut j, stream)
	if jrn_is_default(stream) {
		return j.head_seq, j.base_seq
	}
	st := jrn_named_state(mut j, stream)
	return st.head_seq, st.base_seq
}

// jrn_subscribe — the local tail-follow (§3.3): a delivery-contract
// subscription over one stream, delivering committed [entry] elements in
// seq order, strictly above opts.from (default: the current head — a live
// tail). opts.from below the retained floor refuses CXER4617; beyond the
// head refuses CXER4610. Closeable; closing the journal terminates it.
fn jrn_subscribe(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: subscribe expects (journal, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	jid := jrn_handle_of(args[0]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: subscribe expects a [journal] handle')
	}
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{ name: 'map' }) }
	stream := jrn_map_get(opts, 'stream') or { '' }
	head, floor := jrn_stream_view(mut j, stream)
	mut from := head // default: the live tail
	if fv := jrn_map_get(opts, 'from') {
		from = fv.int()
	}
	if from < floor {
		return mk_err('cx-err:CXER4617', 'E_JOURNAL_RESUME_GAP: from=${from} is below the retained floor (${floor}) — the resume-below-retention refusal; re-seed from a covering snapshot or the floor')
	}
	if from > head {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: subscribe from=${from} is beyond the stream head (${head})')
	}
	j.next_sub_id++
	sid := j.next_sub_id
	j.subs[sid] = &JrnSubRecord{
		stream: stream
		pos:    from
	}
	sub := cx.Element{
		name:  'journal-sub'
		attrs: [
			bus_attr_int('handle', jid),
			bus_attr_int('id', sid),
			bus_attr('stream', stream),
			bus_attr('rung', ':complete-ordered'),
			bus_attr('sharing', 'independent'),
			bus_attr('flow', 'pull'),
			bus_attr_int('from', from),
			bus_attr('retention', 'window'),
			bus_attr('on-close', 'journal-unsubscribe'),
		]
	}
	return bus_stamp_closeable(cx.Node(sub), 'journal-unsubscribe', fn [jid, sid] () ! {
		mut j2 := journal_lookup(jid) or { return }
		mut rec := j2.subs[sid] or { return }
		rec.closed = true
	}, mut env)
}

// jrn_seq_at — time-addressed positions (§3.3; RULED: U1.14a): the largest
// seq in the stream whose commit ts ≤ $ts, or the ABSENCE channel when the
// stream has no entry at-or-before $ts. Time is an index into positions,
// never a cursor form. Runs under jmu — direct reads only.
fn jrn_seq_at(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: seq-at expects (journal, ts, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	mut ts := ''
	if args[1] is cx.ScalarNode {
		ts = cx.scalar_value_str_public((args[1] as cx.ScalarNode).value)
	}
	if ts == '' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: seq-at expects a datetime ts')
	}
	opts := if args.len > 2 { args[2] } else { cx.Node(cx.Element{ name: 'map' }) }
	stream := jrn_map_get(opts, 'stream') or { '' }
	head, floor := jrn_stream_view(mut j, stream)
	// ts is monotonic non-decreasing with seq per stream (§4.3), and the
	// synthesized/committed forms are uniform UTC-Z text — lexicographic
	// comparison is time order. Walk down from the head.
	for s := head; s > floor; s-- {
		text := if jrn_is_default(stream) {
			jrn_entry_text(j, s) or { continue }
		} else {
			st := jrn_named_state(mut j, stream)
			jrn_state_entry_text(st, s) or { continue }
		}
		e := jrn_parse_entry(text) or { continue }
		ets := jrn_entry_attr(e, 'ts')
		if ets != '' && ets <= ts {
			return cx.Element{
				name:  'position'
				attrs: [
					bus_attr_int('seq', s),
					bus_attr('ts', ets),
				]
			}
		}
	}
	return jrn_empty() // the absence channel — no entry at-or-before $ts
}

// ── the journal-sub consumption arms (Ring2SubOps; #762) ─────────────────────

fn jrn_sub_of(sub cx.Node) ?(int, int) {
	if sub is cx.Element {
		if sub.name == 'journal-sub' {
			return sub.attr('handle').int(), sub.attr('id').int()
		}
	}
	return none
}

// jrn_sub_receive — [?receive] over a journal-sub: committed entries
// strictly above the cursor, in seq order. max=0 answers ONE entry (or
// the absence channel when the tail is quiet — the journal's own
// empty-answer posture; a worker context blocks, cancel-aware); max>0 is
// the batch form. A closed journal or a closed subscription answers
// E_JOURNAL_CLOSED (the module's closed-and-drained terminal); a cursor
// that fell below the retained floor answers CXER4617.
fn jrn_sub_receive(sub cx.Node, max int, deadline_ms i64, mut env MatchEnv) cx.Node {
	jid, sid := jrn_sub_of(sub) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: not a [journal-sub] handle')
	}
	mut j := journal_lookup(jid) or {
		return mk_err(jrn_err_closed, 'E_JOURNAL_CLOSED: the subscription\'s journal is closed')
	}
	if !j.is_open {
		return mk_err(jrn_err_closed, 'E_JOURNAL_CLOSED: the subscription\'s journal is closed')
	}
	mut rec := j.subs[sid] or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: unknown journal subscription')
	}
	if rec.closed {
		return mk_err(jrn_err_closed, 'E_JOURNAL_CLOSED: the subscription is closed')
	}
	handle := jrn_handle_element(jid, j)
	want := if max > 0 { max } else { 1 }
	mut out := []cx.Node{}
	sw := time.new_stopwatch()
	for {
		r := journal_stdlib_builtin('journal-since', [handle, cx.Node(jrn_int(rec.pos)),
			cx.Node(jrn_str(rec.stream))]) or { jrn_empty() }
		if is_err_value(r) {
			return r
		}
		if r is cx.Element {
			if r.name == 'err' {
				return r
			}
			for it in r.items {
				if out.len >= want {
					break
				}
				if it is cx.Element {
					if it.name == 'entry' {
						seq := jrn_entry_attr(it, 'seq').int()
						if seq <= rec.pos {
							continue
						}
						rec.pos = seq
						out << cx.Node(it)
					}
				}
			}
		}
		if out.len >= want {
			break
		}
		if max > 0 {
			if deadline_ms >= 0 && sw.elapsed().milliseconds() < deadline_ms {
				time.sleep(time.millisecond)
				continue
			}
			break
		}
		// unbatched, quiet tail: block in a worker; the absence channel on
		// the main-thread substrate.
		if env.current_worker == unsafe { nil } {
			break
		}
		if env.current_worker.cancelled {
			return mk_err('cx-err:CXER0260', 'operation cancelled')
		}
		time.sleep(time.millisecond)
	}
	if max > 0 {
		return cx.Element{
			name:  code.seq_marker_name
			items: out
		}
	}
	if out.len == 1 {
		return out[0]
	}
	return jrn_empty()
}

// jrn_sub_ready — the non-consuming readiness probe.
fn jrn_sub_ready(sub cx.Node, mut env MatchEnv) bool {
	_ = env
	jid, sid := jrn_sub_of(sub) or { return false }
	mut j := journal_lookup(jid) or { return false }
	if !j.is_open {
		return true // the E_JOURNAL_CLOSED terminal surfaces on receive
	}
	rec := j.subs[sid] or { return false }
	if rec.closed {
		return false
	}
	head, _ := jrn_stream_view(mut j, rec.stream)
	return head > rec.pos
}

// jrn_registered_materialization reports a live materialization registered
// on this journal stream (stream 3's L133 retention cover extension). The
// registration lives in the journal's OWN store under the
// `cx-live/materialization/<tenant>[/s/<stream>]/<name>` alias namespace
// (the fabric-offset pattern: derived-position artifacts as store data).
fn jrn_registered_materialization(j &Journal, stream string) ?string {
	mut ms := store_lookup(j.store_id) or { return none }
	prefix := if jrn_is_default(stream) {
		'cx-live/materialization/${j.tenant}/'
	} else {
		'cx-live/materialization/${j.tenant}/s/${stream}/'
	}
	store_lock_enter(mut ms)
	defer {
		store_lock_exit(mut ms)
	}
	for k, _ in ms.aliases {
		if k.starts_with(prefix) {
			rest := k[prefix.len..]
			if jrn_is_default(stream) && rest.contains('/') {
				continue // a named-stream registration under /s/… — not this stream's
			}
			return rest
		}
	}
	return none
}

fn jrn_retain(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: retain expects (journal, policy)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	policy := args[1]
	// Stream-scoped retention (§2.1.1): policy.stream targets a named stream; the
	// boundary, the covering snapshot, and (later) the compact all resolve on it.
	stream := jrn_map_get(policy, 'stream') or { '' }
	is_def_ret := jrn_is_default(stream)
	head := if is_def_ret {
		j.head_seq
	} else {
		st := j.named[stream] or { &StreamState{} }
		st.head_seq
	}
	// Compute the prune boundary B from the policy.
	mut boundary := 0
	if v := jrn_map_get_int(policy, 'keep-after-seq') {
		boundary = v // prune everything <= v
	} else if v := jrn_map_get_int(policy, 'keep-N') {
		boundary = head - v
		if boundary < 0 {
			boundary = 0
		}
	} else if tsv := jrn_map_get(policy, 'keep-after-time') {
		// #712 item 2 (bitemporal L116): TS resolves to the seq boundary
		// B = the highest seq whose entry ts <= TS — well-defined by §4.3
		// per-stream ts monotonicity (the same walk seq-at rides; UTC-Z
		// text is uniform, so lexicographic comparison is time order).
		// Formerly a spec'd no-op (boundary=0 unconditionally, silently
		// keep-all). A non-datetime value is the CXER4610 policy misuse.
		if !cx.is_datetime(tsv) {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: keep-after-time `${tsv}` is not a datetime')
		}
		floor := if is_def_ret {
			j.base_seq
		} else {
			(j.named[stream] or { &StreamState{} }).base_seq
		}
		for s := head; s > floor; s-- {
			text := if is_def_ret {
				jrn_entry_text(j, s) or { continue }
			} else {
				st := j.named[stream] or { &StreamState{} }
				jrn_state_entry_text(st, s) or { continue }
			}
			e := jrn_parse_entry(text) or { continue }
			ets := jrn_entry_attr(e, 'ts')
			if ets != '' && ets <= tsv {
				boundary = s
				break
			}
		}
	} else {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: policy needs keep-after-seq / keep-N / keep-after-time')
	}
	if boundary > head {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: prune boundary ${boundary} beyond head ${head}')
	}
	// The retention cover rule EXTENDS to registered materializations
	// (stream 3, live_modes L133 / live.md §7): a journal-source relation
	// is the stream's ENTIRE history — the fold's recompute basis
	// (maintained ≡ recompute, quartet leg 4; the derived-state posture:
	// a lost checkpoint means full replay). History under a registered
	// materialization may not be compacted away; client-anchored
	// observers get the honest CXER5073 refusal instead.
	if boundary > 0 {
		if mname := jrn_registered_materialization(j, stream) {
			return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: a registered materialization (`${mname}`) pins this stream\'s history — the retention cover rule extends to registered materializations (live modes L133); remove the registration alias before pruning')
		}
		// Stream 9 (L177 — register-or-refuse): the cover rule extends to
		// REGISTERED REPLICAS: a boundary above a replica's synced cursor
		// would strand it below the compacted floor — refuse loud; advance
		// the registration (a later sync) or deregister before pruning.
		if rid, rseq := jrn_registered_replica_below(j, stream, boundary) {
			return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: registered replica `${rid}` is synced to seq ${rseq} < boundary ${boundary} — the retention hold extends to registered replicas (distributed_store §5); advance its registration or deregister before pruning')
		}
	}
	// The covering snapshot must verify valid + signed and cover B (§4.9).
	snap_node := jrn_map_snapshot(policy, 'snapshot') or {
		return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: policy needs a covering snapshot')
	}
	cover_seq := jrn_snapshot_attr(snap_node, 'at-seq').int()
	if cover_seq < boundary {
		return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: snapshot covers seq ${cover_seq} < boundary ${boundary}')
	}
	valid, reason := jrn_snapshot_check(j, snap_node)
	if !valid {
		return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: covering snapshot invalid (${reason})')
	}
	if reason == 'unsigned' {
		return mk_err(jrn_err_snap_unsigned, 'E_JOURNAL_SNAPSHOT_UNSIGNED: an unsigned snapshot cannot be a retention cover')
	}
	// §4.9 (stream 21, L147/#716 item 2): the cover rule reads
	// covered-under-the-CURRENT-fold. A caller declaring its current fold
	// (policy.fold-id) makes the reading binding: a cover frozen under any
	// other fold — or under none — permits pruning a prefix the current
	// fold can no longer interpret, the data-loss path this closes.
	// Re-snapshot under the current fold, then prune.
	if cur_id := jrn_map_get(policy, 'fold-id') {
		if cur_id != '' {
			cover_id := jrn_snapshot_attr(snap_node, 'fold-id')
			if cover_id != cur_id {
				named := if cover_id == '' { 'no fold identity' } else { 'fold ${cover_id}' }
				return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: the cover carries ${named} but the current fold is ${cur_id} — covered-under-the-current-fold: re-derive the cover with [\$journal:resnapshot] (§3.7) before pruning')
			}
		}
	}
	mut rattrs := [
		cx.Attribute{
			name:  'boundary'
			value: cx.ScalarValue(i64(boundary))
		},
		cx.Attribute{
			name:  'covered-by-seq'
			value: cx.ScalarValue(i64(cover_seq))
		},
	]
	if !is_def_ret {
		rattrs << cx.Attribute{
			name:  'stream'
			value: cx.ScalarValue(stream)
		}
	}
	return cx.Element{
		name:  'retention'
		attrs: rattrs
	}
}

// jrn_map_snapshot extracts a `[snapshot …]` from a `{snapshot: [snapshot …]}`
// map entry (a `__cx_map__` child element named `key` whose items[0] is the
// snapshot), or a directly-embedded [snapshot] child.
fn jrn_map_snapshot(m cx.Node, key string) ?cx.Element {
	if m is cx.Element {
		for it in m.items {
			if it is cx.Element {
				if it.name == key && it.items.len > 0 {
					inner := it.items[0]
					if inner is cx.Element && inner.name == 'snapshot' {
						return inner
					}
				}
				if it.name == 'snapshot' {
					return it
				}
			}
		}
	}
	return none
}

// ── compact (copy-forward, source intact — §4.10) ──────────────────────────

// ── rotation (#640 — segmentation + eviction as ONE composed operation) ────
//
// `journal-rotate (journal, opts)` seals the live chain at a retention
// boundary and moves the HOT WINDOW to a fresh store, composing the three
// §4.9/§4.10 primitives (snapshot → retain → compact) with a persisted
// SEGMENT INDEX so history stays discoverable:
//
//   opts: {keep-after-seq: N | keep-n: N, stream?: S, target: <new store url>,
//          signing-key: <ed25519 seed hex> | snapshot: [snapshot …]}
//
//   1. the covering snapshot: a caller-supplied signed [snapshot], or a
//      minimal ROTATION COVER built here (state = [rotation-cover], signed
//      with opts.signing-key — the fabric daemon signs with its identity
//      seed). The §4.9 contract is unchanged: no signature, no retention.
//   2. retain validates the boundary against the cover (§4.9);
//   3. compact copies the retained tail (B+1..head) into `target`, seam-
//      anchored at B (§4.10) — the target becomes the NEW HOT journal;
//   4. the segment index (`cx-journal/segments/<tenant>` in the TARGET
//      store) records the sealed predecessor (range, anchor, redacted
//      store URL) APPENDED to the predecessors it already carried — a
//      chain of rotations stays walkable from the newest hot store alone.
//
// The SOURCE journal/store are never mutated: rotation is copy-then-swap,
// so a crash mid-rotate leaves the live chain intact (retry with a fresh
// target). EVICTION is the swap itself — the caller (the fabric mount, an
// embedded deployment) repoints at the returned journal and closes the old
// handle; per-op cost then tracks the hot window, not lifetime volume.
// Credentials never enter the index: the recorded segment URL is
// userinfo-redacted (rehydration supplies its own grant at mount time).
//
// STREAMS: `stream: S` rotates one chain; `streams: 'all'` rotates the whole
// tenant journal — the default chain plus every named stream, each sealed at
// its OWN boundary (head_s − keep-n, floored at 0) — which is what a fabric
// mount swap requires: any stream not copied into the target would vanish
// from the hot window. A stream whose boundary floors at 0 is copied whole
// (nothing sealed, no index entry). `keep-after-seq` and a caller-supplied
// `snapshot` are single-stream-mode options.
fn jrn_rotate(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: rotate expects (journal, opts)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	opts := args[1]
	target := jrn_map_get(opts, 'target') or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: rotate needs opts.target (the new hot store URL)')
	}
	all_mode := (jrn_map_get(opts, 'streams') or { '' }) == 'all'
	keep_after := jrn_map_get_int(opts, 'keep-after-seq') or { -1 }
	keep_n := jrn_map_get_int(opts, 'keep-n') or { -1 }
	if keep_after < 0 && keep_n < 0 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: rotate needs keep-after-seq or keep-n')
	}
	if all_mode && keep_n < 0 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: streams=all rotation takes keep-n (per-stream boundaries)')
	}
	key_hex := jrn_map_get(opts, 'signing-key') or { '' }
	mut supplied_snap := cx.Element{}
	mut have_snap := false
	if sn := jrn_map_snapshot(opts, 'snapshot') {
		supplied_snap = sn
		have_snap = true
	}
	if !have_snap && key_hex == '' {
		return mk_err(jrn_err_snap_unsigned, 'E_JOURNAL_SNAPSHOT_UNSIGNED: rotate needs opts.snapshot (signed) or opts.signing-key')
	}
	if all_mode && have_snap {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: streams=all builds its own per-stream covers — pass signing-key, not snapshot')
	}
	// the streams to move: one, or the whole tenant journal.
	mut streams := []string{}
	if all_mode {
		if j.head_seq > 0 {
			streams << jrn_default_stream
		}
		for name, _ in j.named {
			streams << name
		}
		if streams.len == 0 {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: rotate found no streams to move')
		}
	} else {
		streams << (jrn_map_get(opts, 'stream') or { '' })
	}
	// open the target ONCE — every stream compacts into the same instance
	// (repeated opens would fragment non-shared substrates like mem://).
	if target == jrn_store_url(j.store_id) {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate target collides with the live source chain')
	}
	// The target is a DERIVED open: it inherits the source's at-rest posture
	// (#785) and the source's hash-algo. A default-algo target would be
	// stamped `sha2-256` while carrying entries hashed under the source's
	// algo — a segment that fails its own `verify`.
	mut rot_opts := cx.Element{
		name:  'map'
		attrs: jrn_at_rest_attrs(j.store_id, target, opts)
	}
	rot_opts.attrs << cx.Attribute{
		name:  'hash-algo'
		value: cx.ScalarValue(j.hash_algo)
	}
	seg_res := jrn_open([jrn_str(target), jrn_str(j.tenant), rot_opts]) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate target')
	}
	if is_err_value(seg_res) {
		return seg_res
	}
	seg_hid := jrn_handle_of(seg_res) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate target handle')
	}
	mut seg_jm := journal_lookup(seg_hid) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate segment lost')
	}
	mut sealed := []cx.Node{}
	mut moved := 0
	mut seg := cx.Node(cx.Element{})
	mut sealed_any := false
	for stream in streams {
		is_def_rot := jrn_is_default(stream)
		head := if is_def_rot {
			j.head_seq
		} else {
			st := j.named[stream] or { &StreamState{} }
			st.head_seq
		}
		mut boundary := 0
		if keep_after >= 0 {
			boundary = keep_after
		} else {
			boundary = head - keep_n
			if boundary < 0 {
				boundary = 0
			}
		}
		if boundary > head {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: rotate boundary ${boundary} beyond head ${head} (stream ${stream})')
		}
		if !all_mode && boundary <= 0 {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: rotate boundary ${boundary} seals nothing')
		}
		anchor := if boundary >= 1 {
			if is_def_rot {
				jrn_live_hash(j, boundary)
			} else {
				st := j.named[stream] or { &StreamState{} }
				jrn_state_live_hash(st, boundary)
			}
		} else {
			jrn_genesis_prev
		}
		// boundary 0 (all-mode) seals NOTHING for this stream: it is copied
		// whole into the target, which needs no retention cover — synthesize
		// the boundary-0 descriptor for compact directly. A sealing boundary
		// (>0) takes the full §4.9 path: signed cover → retain validation.
		mut retention := cx.Node(cx.Element{})
		if boundary == 0 {
			mut zattrs := [
				cx.Attribute{
					name:  'boundary'
					value: cx.ScalarValue(i64(0))
				},
			]
			if !is_def_rot {
				zattrs << cx.Attribute{
					name:  'stream'
					value: cx.ScalarValue(stream)
				}
			}
			retention = cx.Element{
				name:  'retention'
				attrs: zattrs
			}
		} else {
			// the covering snapshot: supplied (single mode) or the signed rotation cover.
			mut snap := supplied_snap
			if !have_snap {
				seed := jrn_hex_to_bytes(key_hex) or {
					return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: signing-key must be hex')
				}
				cover_state := cx.Node(cx.Element{
					name: 'rotation-cover'
				})
				canonical := jrn_snapshot_canonical(cover_state, boundary, stream, anchor,
					j.hash_algo, '')
				sig_hex := jrn_sign(canonical, seed) or {
					return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: rotation-cover signing failed (stream ${stream})')
				}
				pub_hex := jrn_derive_pub(seed) or { '' }
				sb := jrn_build_snapshot(j.tenant, boundary, stream, anchor, j.hash_algo, '',
					true, sig_hex, pub_hex, '', cover_state)
				if sb is cx.Element {
					snap = sb
				}
			}
			// retain (§4.9 validation) for THIS stream.
			mut retain_items := [
				session_kv('keep-after-seq', bus_int(boundary)),
				cx.Node(cx.Element{
					name:  'snapshot'
					items: [cx.Node(snap)]
				}),
			]
			if !is_def_rot {
				retain_items << session_kv('stream', bus_str(stream))
			}
			retention = jrn_retain([args[0], cx.Node(cx.Element{
				name:  code.map_marker_name
				items: retain_items
			})]) or {
				return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: rotate retain failed (stream ${stream})')
			}
			if is_err_value(retention) {
				return retention
			}
		}
		mut ret_el := cx.Element{}
		if retention is cx.Element {
			ret_el = retention
		}
		sr := jrn_compact_into(j, mut seg_jm, seg_hid, ret_el) or {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate compact failed (stream ${stream})')
		}
		if is_err_value(sr) {
			return sr
		}
		seg = sr
		moved++
		if boundary > 0 {
			mut sealed_attrs := [
				cx.Attribute{
					name:  'to'
					value: cx.ScalarValue(i64(boundary))
				},
				cx.Attribute{
					name:  'anchor'
					value: cx.ScalarValue(anchor)
				},
				cx.Attribute{
					name:  'store'
					value: cx.ScalarValue(store_url_redact_userinfo(jrn_store_url(j.store_id)))
				},
			]
			if !is_def_rot {
				sealed_attrs << cx.Attribute{
					name:  'stream'
					value: cx.ScalarValue(stream)
				}
			}
			sealed << cx.Node(cx.Element{
				name:  'segment'
				attrs: sealed_attrs
			})
			sealed_any = true
		}
	}
	seg_id := jrn_handle_of(seg) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate segment handle lost')
	}
	seg_j := journal_lookup(seg_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate segment journal lost')
	}
	// the segment index in the NEW store: sealed entries appended to the
	// predecessors the OLD store already recorded — the rotation chain stays
	// walkable from the newest hot store alone.
	mut seg_items := jrn_read_segment_index(j.store_id, j.tenant)
	prior := seg_items.len
	for s in sealed {
		seg_items << s
	}
	if sealed_any || prior > 0 {
		if e := jrn_set_meta_alias(seg_j.store_id, jrn_segments_alias(j.tenant), cx.Element{
			name:  'journal-segments'
			items: seg_items
		})
		{
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate segment-index write failed',
				e)
		}
	}
	// opts.carry — alias-name prefixes whose entries (doc + pointer) ride into
	// the new hot store: the consumer plane's durable state (fabric group
	// offsets / policies / delivery records) lives beside the chain, and a
	// rotation that left it behind would silently reset every consumer group.
	if carry := jrn_map_get_seq(opts, 'carry') {
		lst := store_stdlib_builtin('store-list-aliases', [jrn_store_handle(j.store_id)]) or {
			cx.Node(jrn_null())
		}
		if lst is cx.Element {
			for it in lst.items {
				if it is cx.Element && it.name == 'alias' {
					aname := it.attr('name')
					mut matched_prefix := false
					for p in carry {
						if p != '' && aname.starts_with(p) {
							matched_prefix = true
							break
						}
					}
					if !matched_prefix {
						continue
					}
					ahash := it.attr('hash')
					text := jrn_store_get_doc_text(j.store_id, ahash) or { continue }
					doc := cx.parse(text) or { continue }
					if doc.elements.len == 0 {
						continue
					}
					nh, cerr := jrn_store_put_doc_err(seg_j.store_id, doc.elements[0])
					if nh == '' {
						if ce := cerr {
							return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate carry failed for alias ${aname}',
								ce)
						}
						return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate carry failed for alias ${aname}')
					}
					if ce := jrn_store_set_alias(seg_j.store_id, aname, nh) {
						return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: rotate carry pointer failed for ${aname}',
							ce)
					}
				}
			}
		}
	}
	return cx.Element{
		name:  'rotated'
		attrs: [
			cx.Attribute{
				name:  'streams'
				value: cx.ScalarValue(i64(moved))
			},
			cx.Attribute{
				name:  'sealed'
				value: cx.ScalarValue(i64(sealed.len))
			},
			cx.Attribute{
				name:  'segments'
				value: cx.ScalarValue(i64(seg_items.len))
			},
			cx.Attribute{
				name:  'target'
				value: cx.ScalarValue(store_url_redact_userinfo(target))
			},
		]
		items: [seg]
	}
}

// jrn_segments_alias names the per-tenant segment index (the sealed-history
// chain walkable from the newest hot store).
fn jrn_segments_alias(tenant string) string {
	return 'cx-journal/segments/${tenant}'
}

// jrn_read_segment_index returns the store's recorded sealed segments
// ([] when none — a first rotation).
fn jrn_read_segment_index(store_id int, tenant string) []cx.Node {
	e := jrn_get_meta_doc(store_id, jrn_segments_alias(tenant)) or { return []cx.Node{} }
	if e.name != 'journal-segments' {
		return []cx.Node{}
	}
	mut out := []cx.Node{}
	for it in e.items {
		if it is cx.Element && it.name == 'segment' {
			out << it
		}
	}
	return out
}

fn jrn_compact(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: compact expects (journal, opts)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	opts := args[1]
	retention := jrn_map_retention(opts) or {
		return mk_err(jrn_err_retention, 'E_JOURNAL_RETENTION_UNCOVERED: compact needs an opts.retention from retain')
	}
	target := jrn_map_get(opts, 'target') or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: compact needs opts.target store URL')
	}
	// Collision guard: a target that names the SAME live store URL as the
	// source → CXER4600 (never compact onto a live chain).
	src_url := jrn_store_url(j.store_id)
	if target == src_url {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact target collides with the live source chain')
	}
	// Open the new segment store + journal (a fresh tenant chain). Stream 7
	// (L123): a compact target is itself an open — the caller's
	// `consistency` key rides through as the segment handle's floor
	// (journal.md §4.4).
	// The segment is a DERIVED open: the source's at-rest posture (#785) and
	// hash-algo carry, so the copy-forward lands sealed-as-the-source and the
	// segment's stamped algo matches the hashes its entries were written with.
	mut seg_opts := cx.Element{
		name:  'map'
		attrs: jrn_at_rest_attrs(j.store_id, target, opts)
	}
	seg_opts.attrs << cx.Attribute{
		name:  'hash-algo'
		value: cx.ScalarValue(j.hash_algo)
	}
	if cnode := jrn_map_get_node(opts, 'consistency') {
		seg_opts.items << cx.Node(cx.Element{
			name:  'consistency'
			items: [cnode]
		})
	}
	seg_res := jrn_open([jrn_str(target), jrn_str(j.tenant), seg_opts]) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact target')
	}
	if is_err_value(seg_res) {
		return seg_res
	}
	seg_id := jrn_handle_of(seg_res) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact target handle')
	}
	mut seg := journal_lookup(seg_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact segment lost')
	}
	return jrn_compact_into(j, mut seg, seg_id, retention)
}

// jrn_compact_into copies one stream's retained tail into an ALREADY-OPEN
// segment journal (#640: a multi-stream rotation opens the target ONCE and
// compacts every stream into the same instance — repeated jrn_open would
// land each stream in a fresh store for non-shared substrates like mem://).
// jrn_copy_payload_doc carries an entry's DETACHED payload doc into the
// segment store (I1 row 11, #720/L184): rotation copies entry docs
// verbatim, and the payload doc must travel too or the rotated chain
// would read event-less. An already-shredded payload copies nothing —
// the shred SURVIVES rotation, by design. Address stability holds by
// construction (put-doc recomputes the same canonical-text address).
fn jrn_copy_payload_doc(src_store int, dst_store int, e cx.Element) {
	addr := jrn_entry_attr(e, 'payload')
	if addr == '' {
		return
	}
	text := jrn_store_get_doc_text(src_store, addr) or { return }
	doc := cx.parse(text) or { return }
	if doc.elements.len == 0 {
		return
	}
	_ := jrn_store_put_doc(dst_store, doc.elements[0]) or { return }
}

fn jrn_compact_into(j &Journal, mut seg Journal, seg_id int, retention cx.Element) ?cx.Node {
	boundary := jrn_retention_attr(retention, 'boundary').int()
	// Per-stream compact (§2.1.1): if the retention is stream-scoped, copy that
	// named stream's retained tail into the segment's SAME named stream, with the
	// seam on the named chain. The default chain is left untouched in the segment.
	cstream := jrn_retention_attr(retention, 'stream')
	if !jrn_is_default(cstream) {
		src_st := j.named[cstream] or {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: compact unknown stream "${cstream}"')
		}
		mut seg_st := jrn_named_state(mut seg, cstream)
		seg_st.base_seq = boundary
		seg_st.seam_anchor = jrn_state_live_hash(src_st, boundary)
		for s in boundary + 1 .. src_st.head_seq + 1 {
			text := jrn_state_entry_text(src_st, s) or { break }
			e := jrn_parse_entry(text) or { break }
			jrn_copy_payload_doc(j.store_id, seg.store_id, e)
			dhash := jrn_store_put_doc(seg.store_id, e) or { break }
			if perr := jrn_store_set_alias(seg.store_id, jrn_entry_alias_s(seg.tenant, cstream,
				s), dhash)
			{
				return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact entry pointer write failed at seq ${s}',
					perr)
			}
			seg_st.entries << text
		}
		if seg_st.entries.len > 0 {
			last := jrn_parse_entry(seg_st.entries[seg_st.entries.len - 1]) or { cx.Element{} }
			seg_st.head_seq = jrn_entry_attr(last, 'seq').int()
			seg_st.head_hash = jrn_entry_attr(last, 'hash')
			if perr := jrn_set_meta_alias(seg.store_id, jrn_head_alias_s(seg.tenant, cstream),
				jrn_head_doc(seg_st.head_seq, seg_st.head_hash))
			{
				return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact head write failed',
					perr)
			}
			if perr := jrn_index_stream(seg.store_id, seg.tenant, cstream) {
				return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact stream index write failed',
					perr)
			}
		} else {
			seg_st.head_seq = boundary
			seg_st.head_hash = seg_st.seam_anchor
		}
		return jrn_handle_element(seg_id, seg)
	}
	// The segment starts at the retention boundary: its first retained entry is
	// seq=boundary+1 (the seam), anchored against entry boundary's hash — which
	// equals the covering snapshot's anchor-hash (§4.10).
	seg.base_seq = boundary
	seg.seam_anchor = jrn_live_hash(j, boundary)
	// Copy the retained tail (boundary+1 .. head) verbatim into the new segment
	// (bytes unchanged — same seq/prev-hash/hash; §4.10). The source is read
	// only; never edited.
	for s in boundary + 1 .. j.head_seq + 1 {
		text := jrn_entry_text(j, s) or { break }
		e := jrn_parse_entry(text) or { break }
		jrn_copy_payload_doc(j.store_id, seg.store_id, e)
		dhash := jrn_store_put_doc(seg.store_id, e) or { break }
		if perr := jrn_store_set_alias(seg.store_id, jrn_entry_alias(seg.tenant, s), dhash) {
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact entry pointer write failed at seq ${s}',
				perr)
		}
		seg.entries << text
	}
	if seg.entries.len > 0 {
		last := jrn_parse_entry(seg.entries[seg.entries.len - 1]) or { cx.Element{} }
		seg.head_seq = jrn_entry_attr(last, 'seq').int()
		seg.head_hash = jrn_entry_attr(last, 'hash')
		if perr := jrn_set_meta_alias(seg.store_id, jrn_head_alias(seg.tenant), jrn_head_doc(seg.head_seq,
			seg.head_hash))
		{
			return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: compact head write failed',
				perr)
		}
	} else {
		seg.head_seq = boundary
		seg.head_hash = seg.seam_anchor
	}
	return jrn_handle_element(seg_id, seg)
}

fn jrn_map_retention(m cx.Node) ?cx.Element {
	if m is cx.Element {
		for it in m.items {
			if it is cx.Element {
				if it.name == 'retention' && it.items.len > 0 {
					inner := it.items[0]
					if inner is cx.Element && inner.name == 'retention' {
						return inner
					}
				}
				if it.name == 'retention' {
					return it
				}
			}
		}
	}
	return none
}

fn jrn_retention_attr(r cx.Element, name string) string {
	for a in r.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

fn jrn_store_url(store_id int) string {
	ms := store_lookup(store_id) or { return '' }
	return ms.url
}

// ── env-aware dispatch ($fn verbs: fold/replay/dry-run/snapshot/fold-from) ──
//
// Reached from dispatch_call_l in eval.v BEFORE the env-free chain. Returns
// none for every non-journal-env name so the caller falls through.

// journal_stdlib_builtin_env carries the callable-applying verbs. Same
// per-journal serialization as journal_stdlib_builtin (#642); the fold
// callbacks are purity-enforced (CXER4611), so they can never re-enter a
// journal op and the plain mutex cannot self-deadlock.
fn journal_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	mut jl := &sync.Mutex(unsafe { nil })
	if args.len > 0 {
		if id := jrn_handle_of(args[0]) {
			if j := journal_lookup(id) {
				jl = j.jmu
			}
		}
	}
	if jl != unsafe { nil } {
		jl.@lock()
	}
	r := journal_stdlib_builtin_env_op(name, args, mut env) or {
		if jl != unsafe { nil } {
			jl.unlock()
		}
		return none
	}
	if jl != unsafe { nil } {
		jl.unlock()
	}
	return r
}

fn journal_stdlib_builtin_env_op(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'journal-subscribe' {
			return jrn_subscribe(args, mut env)
		}
		'journal-fold' {
			return jrn_fold(args, mut env)
		}
		'journal-fold-slice' {
			return jrn_fold_slice(args, mut env)
		}
		'journal-fold-value' {
			return jrn_fold_value(args, mut env)
		}
		'journal-replay' {
			return jrn_replay(args, mut env)
		}
		'journal-dry-run' {
			return jrn_dry_run(args, mut env)
		}
		'journal-snapshot' {
			return jrn_snapshot(args, mut env)
		}
		'journal-resnapshot' {
			// §3.7 (RULED: SEA-1): re-derive a checkpoint under the CURRENT
			// fold quadruple — the L147 maintenance discipline as a verb.
			return jrn_resnapshot(args, mut env)
		}
		'journal-fold-from' {
			return jrn_fold_from(args, mut env)
		}
		'journal-coherence' {
			// stream 21 (L151): the coverage pre-flight applies the caller's
			// upcast chain, so coherence lives on the env chain.
			return jrn_coherence(args, mut env)
		}
		'journal-upcast' {
			return jrn_upcast(args, mut env)
		}
		'journal-saga-run' {
			// stream 10 (#682): the Ring-2 saga runner — steps invoke
			// commands through the env chain.
			return coord_saga_run(args, mut env)
		}
		'journal-apply-erasures' {
			// stream 9 (the stream-20 joint requirement): each application
			// is the replica's OWN erase-subject — same env-chain reach.
			return jrn_apply_erasures(args, mut env)
		}
		'journal-erase-subject' {
			// stream 20: the recorded command reaches the in-process dedup
			// registry (stream-6 records) through the env chain.
			return jrn_erase_subject(args, mut env)
		}
		else {
			return none
		}
	}
}

// jrn_assert_pure checks a $fn value is pure (§2.7 determinism guard). A
// closure-sentinel whose body calls any impure builtin → CXER4611. A builtin
// fn value is pure iff the builtin itself is not impure-classified.
fn jrn_assert_pure(fv cx.Node, mut env MatchEnv) ?cx.Node {
	cl := resolve_closure(fv, env) or {
		return mk_err(jrn_err_fold_impure, 'E_JOURNAL_FOLD_IMPURE: fold expects a callable $fn')
	}
	if cl.builtin_name != '' {
		if builtin_is_impure(cl.builtin_name) {
			return mk_err(jrn_err_fold_impure, 'E_JOURNAL_FOLD_IMPURE: $fn `${cl.builtin_name}` is impure')
		}
		return none
	}
	if cl.body.len > 0 {
		if node_calls_impure_builtin(cl.body_node()) {
			return mk_err(jrn_err_fold_impure, 'E_JOURNAL_FOLD_IMPURE: $fn calls an impure operation; fold must be deterministic')
		}
	}
	return none
}

// jrn_fold_upcast_default folds the default chain 1..to under an optional
// §3.9 chain (fn or derived form) — the snapshot/resnapshot fold body
// (RULED: SEA-1). Without a chain it is jrn_fold_entries byte-identically.
fn jrn_fold_upcast_default(j &Journal, to int, init cx.Node, fv cx.Node, has_up bool, chain cx.Node, mut env MatchEnv) cx.Node {
	if !has_up {
		return jrn_fold_entries(j, 1, to, init, fv, mut env)
	}
	items := jrn_collect_range(j, 1, to)
	uitems, uerr, uok := jrn_upcast_stage(items, true, chain, mut env)
	if !uok {
		return uerr
	}
	mut acc := init
	for entry in uitems {
		acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
	}
	return acc
}

// jrn_fold_upcast_stream is the named-stream twin of jrn_fold_upcast_default.
fn jrn_fold_upcast_stream(store_id int, st &StreamState, to int, init cx.Node, fv cx.Node, has_up bool, chain cx.Node, mut env MatchEnv) cx.Node {
	if !has_up {
		return jrn_fold_state_entries(store_id, st, 1, to, init, fv, mut env)
	}
	mut items := []cx.Node{}
	for entry in jrn_state_collect_range(st, 1, to) {
		items << jrn_hydrate_entry(store_id, entry)
	}
	uitems, uerr, uok := jrn_upcast_stage(items, true, chain, mut env)
	if !uok {
		return uerr
	}
	mut acc := init
	for entry in uitems {
		acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
	}
	return acc
}

// jrn_fold_entries folds [from..to] with the pure $fn over init. The pure
// check is enforced by the caller; here we just apply.
// jrn_fold_entries always yields a node: the final state, or an err-node VALUE
// if the reducer raised (errors-are-values, §4 / code.md §9.1.2). It never
// returns `none`.
fn jrn_fold_entries(j &Journal, from int, to int, init cx.Node, fv cx.Node, mut env MatchEnv) cx.Node {
	mut acc := init
	items := jrn_collect_range(j, from, to)
	for entry in items {
		acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
	}
	return acc
}

// jrn_fold_state_entries folds a NAMED stream's range (§2.1.1). Tenant-wide state
// is the caller's order-independent composition of per-stream folds — the journal
// exposes per-stream fold + `streams`, but cannot merge opaque user states itself.
fn jrn_fold_state_entries(store_id int, st &StreamState, from int, to int, init cx.Node, fv cx.Node, mut env MatchEnv) cx.Node {
	mut acc := init
	for entry in jrn_state_collect_range(st, from, to) {
		// I1 row 11: folds see the HYDRATED entry (event re-attached).
		hydrated := jrn_hydrate_entry(store_id, entry)
		acc = apply_fn_value(fv, [acc, hydrated], mut env) or { return err_to_node(err) }
	}
	return acc
}

fn jrn_fold(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold expects (journal, fn, init)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	fv := args[1]
	init := args[2]
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	stream := jrn_opt_stream(args, 3)
	// §3.8 (stream 8, L118): trailing opts carry the bitemporal axes —
	// at-seq (the TX pin; the stream-7 L125 always-on guard rides it exactly
	// as on replay) and valid-at (engages the pre-fold projection). Without
	// either, the shipped fold path runs byte-identically.
	opts := if args.len > 4 { args[4] } else { cx.Node(cx.Element{ name: 'map' }) }
	mut pinned := false
	mut at := 0
	if v := jrn_map_get_int(opts, 'at-seq') {
		pinned = true
		at = v
	}
	has_vt, vt_ns, verr, vok := jrn_opt_valid_at(opts)
	if !vok {
		return verr
	}
	// §3.9 (stream 21, L146): a given upcast chain engages the seam — the
	// SAME pure pre-fold stage as §3.8, composed upcast-THEN-projection.
	mut has_up := false
	mut chain := jrn_null()
	if c := jrn_map_get_node(opts, 'upcast') {
		if e := jrn_chain_check(c, mut env) {
			return e
		}
		has_up = true
		chain = c
	}
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return init } // empty/unknown stream → fold of nothing = init
		if !pinned && !has_vt && !has_up {
			return jrn_fold_state_entries(j.store_id, st, 1, st.head_seq, init, fv, mut env)
		}
		mut to := st.head_seq
		if pinned {
			if at > st.head_seq || at < 1 {
				return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: fold at-seq ${at} beyond stream head ${st.head_seq}')
			}
			if st.base_seq > 0 {
				return cst_pin_refusal('journal:fold', 'at-seq-pinned', at, st.base_seq,
					'fold-from over the covering snapshot reconstructs the pinned state')
			}
			to = at
		}
		mut items := []cx.Node{}
		for entry in jrn_state_collect_range(st, 1, to) {
			items << jrn_hydrate_entry(j.store_id, entry)
		}
		uitems, uerr, uok := jrn_upcast_stage(items, has_up, chain, mut env)
		if !uok {
			return uerr
		}
		out, perr, pok := jrn_temporal_project(uitems, false, 0, has_vt, vt_ns)
		if !pok {
			return perr
		}
		mut acc := init
		for entry in out {
			acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
		}
		return acc
	}
	if !pinned && !has_vt && !has_up {
		return jrn_fold_entries(j, 1, j.head_seq, init, fv, mut env)
	}
	mut to := j.head_seq
	if pinned {
		if at > j.head_seq || at < 1 {
			return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: fold at-seq ${at} beyond head ${j.head_seq}')
		}
		if j.base_seq > 0 {
			return cst_pin_refusal('journal:fold', 'at-seq-pinned', at, j.base_seq,
				'fold-from over the covering snapshot reconstructs the pinned state')
		}
		to = at
	}
	items := jrn_collect_range(j, 1, to)
	uitems, uerr, uok := jrn_upcast_stage(items, has_up, chain, mut env)
	if !uok {
		return uerr
	}
	out, perr, pok := jrn_temporal_project(uitems, false, 0, has_vt, vt_ns)
	if !pok {
		return perr
	}
	mut acc := init
	for entry in out {
		acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
	}
	return acc
}

fn jrn_fold_slice(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 5 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-slice expects (journal, fn, init, from, to)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	fv := args[1]
	init := args[2]
	from := jrn_arg_int(args[3]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-slice from')
	}
	to := jrn_arg_int(args[4]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-slice to')
	}
	if from > to {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: from > to')
	}
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	stream := jrn_opt_stream(args, 5)
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return init }
		return jrn_fold_state_entries(j.store_id, st, from, to, init, fv, mut env)
	}
	return jrn_fold_entries(j, from, to, init, fv, mut env)
}

// jrn_fold_value folds an already-materialized [sequence element] of entries —
// the PURE core; no backend access (§3.4/§4.6).
fn jrn_fold_value(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-value expects (entries, fn, init)')
	}
	entries := args[0]
	fv := args[1]
	mut acc := args[2]
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	items := iterate(entries)
	for entry in items {
		acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
	}
	return acc
}

fn jrn_replay(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: replay expects (journal, fn, init)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	fv := args[1]
	init := args[2]
	opts := if args.len > 3 { args[3] } else { cx.Node(cx.Element{ name: 'map' }) }
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	// §3.9 (stream 21, L146): the upcast chain — TODAY'S chain, even under an
	// at-seq pin (a past-state read is a function of (entries, chain, fn,
	// init), never of a date).
	mut has_up := false
	mut chain := jrn_null()
	if c := jrn_map_get_node(opts, 'upcast') {
		if e := jrn_chain_check(c, mut env) {
			return e
		}
		has_up = true
		chain = c
	}
	stream := jrn_map_get(opts, 'stream') or { '' }
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return init }
		mut sfrom := jrn_map_get_int(opts, 'from') or { 1 }
		mut sto := jrn_map_get_int(opts, 'to') or { st.head_seq }
		mut spinned := false
		if at := jrn_map_get_int(opts, 'at-seq') {
			sfrom = 1
			sto = at
			spinned = true
		}
		if sto > st.head_seq || sfrom < 1 {
			return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: replay [${sfrom}..${sto}] beyond stream head ${st.head_seq}')
		}
		// Stream 7 (L122/L125 — journal.md §4.4): an at-seq pin IS a
		// declaration, always-on: the pinned state needs the full genesis
		// prefix, so a retention-pruned chain refuses (CXER4991) instead of
		// silently folding a wrong state from the seam. Under a declared
		// :gapless floor an explicit `from` below the floor refuses the
		// same way.
		if spinned && st.base_seq > 0 {
			return cst_pin_refusal('journal:replay', 'at-seq-pinned', sto, st.base_seq,
				'fold-from over the covering snapshot reconstructs the pinned state')
		}
		if jrn_floor_declared(j, 'gapless') && st.base_seq > 0 && sfrom <= st.base_seq {
			return cst_pin_refusal('journal:replay', 'gapless', sfrom, st.base_seq,
				'read from above the retained floor, or fold-from over the covering snapshot')
		}
		// §3.8 (stream 8): a given valid-at engages the pre-fold projection.
		shas_vt, svt_ns, sverr, svok := jrn_opt_valid_at(opts)
		if !svok {
			return sverr
		}
		if shas_vt || has_up {
			mut sitems := []cx.Node{}
			for entry in jrn_state_collect_range(st, sfrom, sto) {
				sitems << jrn_hydrate_entry(j.store_id, entry)
			}
			suitems, suerr, suok := jrn_upcast_stage(sitems, has_up, chain, mut env)
			if !suok {
				return suerr
			}
			sout, sperr, spok := jrn_temporal_project(suitems, false, 0, shas_vt, svt_ns)
			if !spok {
				return sperr
			}
			mut sacc := init
			for entry in sout {
				sacc = apply_fn_value(fv, [sacc, entry], mut env) or { return err_to_node(err) }
			}
			return sacc
		}
		return jrn_fold_state_entries(j.store_id, st, sfrom, sto, init, fv, mut env)
	}
	mut from := jrn_map_get_int(opts, 'from') or { 1 }
	mut to := jrn_map_get_int(opts, 'to') or { j.head_seq }
	mut pinned := false
	if at := jrn_map_get_int(opts, 'at-seq') {
		from = 1
		to = at
		pinned = true
	}
	if to > j.head_seq || from < 1 {
		return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: replay [${from}..${to}] beyond head ${j.head_seq}')
	}
	// Stream 7 (L122/L125): see the named-stream branch above.
	if pinned && j.base_seq > 0 {
		return cst_pin_refusal('journal:replay', 'at-seq-pinned', to, j.base_seq,
			'fold-from over the covering snapshot reconstructs the pinned state')
	}
	if jrn_floor_declared(j, 'gapless') && j.base_seq > 0 && from <= j.base_seq {
		return cst_pin_refusal('journal:replay', 'gapless', from, j.base_seq,
			'read from above the retained floor, or fold-from over the covering snapshot')
	}
	// §3.8 (stream 8): a given valid-at engages the pre-fold projection.
	has_vt, vt_ns, verr, vok := jrn_opt_valid_at(opts)
	if !vok {
		return verr
	}
	if has_vt || has_up {
		items := jrn_collect_range(j, from, to)
		uitems, uerr, uok := jrn_upcast_stage(items, has_up, chain, mut env)
		if !uok {
			return uerr
		}
		out, perr, pok := jrn_temporal_project(uitems, false, 0, has_vt, vt_ns)
		if !pok {
			return perr
		}
		mut acc := init
		for entry in out {
			acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
		}
		return acc
	}
	return jrn_fold_entries(j, from, to, init, fv, mut env)
}

// jrn_dry_run previews an append WITHOUT committing: fold to head + one
// provisional $fn step over an uncommitted [entry seq=head+1 …]. Head unmoved.
fn jrn_dry_run(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 5 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: dry-run expects (journal, event, attribution, fn, init)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	event := args[1]
	attribution := args[2]
	fv := args[3]
	init := args[4]
	actor := jrn_map_get(attribution, 'actor') or { '' }
	authority := jrn_map_get(attribution, 'authority') or { '' }
	if actor == '' || authority == '' {
		return mk_err(jrn_err_attr_invalid, 'E_JOURNAL_ATTRIBUTION_INVALID: dry-run requires actor + authority')
	}
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	// fold to head
	base := jrn_fold_entries(j, 1, j.head_seq, init, fv, mut env)
	if is_err_value(base) {
		return base
	}
	// build a PROVISIONAL (uncommitted) entry at seq=head+1
	seq := j.head_seq + 1
	prev_hash := j.head_hash
	ts := jrn_ts_for(cx.Element{ name: 'map' }, seq)
	// dry-run previews against the default stream (named-stream dry-run is a
	// deferred edge, §2.1.1 follow-on); pass '' → default canonical/build.
	// I1 row 11: the provisional preimage covers the payload ADDRESS the
	// real append would store — computed here WITHOUT persisting (put-doc
	// addresses are cx_text_hash of the canonical text, so the dry-run
	// hash equals the committed one byte-for-byte).
	payload_addr := cx.cx_text_hash(render_canonical(event)) or {
		return mk_err(jrn_err_event_unser, 'E_JOURNAL_EVENT_UNSERIALIZABLE')
	}
	canonical := jrn_canonical_bytes(seq, j.tenant, '', actor, authority, ts, prev_hash,
		payload_addr)
	hash := jrn_compute_hash(j.hash_algo, canonical) or {
		return mk_err(jrn_err_event_unser, 'E_JOURNAL_EVENT_UNSERIALIZABLE')
	}
	provisional := jrn_build_entry(seq, j.tenant, '', actor, authority, ts, prev_hash, hash,
		payload_addr)
	projected := apply_fn_value(fv, [base, provisional], mut env) or { return err_to_node(err) }
	// NOTHING persisted; head_seq/head_hash unmoved (§3.5).
	return cx.Element{
		name:  'dry-run'
		items: [
			cx.Element{
				name:  'state'
				items: [projected]
			},
			provisional,
		]
	}
}

// jrn_snapshot folds to at-seq + signs the result + anchor (§3.7).
fn jrn_snapshot(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: snapshot expects (journal, fn, init)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	fv := args[1]
	init := args[2]
	opts := if args.len > 3 { args[3] } else { cx.Node(cx.Element{ name: 'map' }) }
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	// Stream-scoped snapshot (§2.1.1): opts.stream snapshots a named stream's
	// chain; head/fold/anchor all resolve on that stream.
	stream := jrn_map_get(opts, 'stream') or { '' }
	is_def_snap := jrn_is_default(stream)
	// §4.8/§3.7 (stream 21, L147): opts.fold-id fills the reserved
	// signed-preimage slot — the snapshot CARRIES its fold identity (a
	// computation address: fn ⊕ chain ⊕ env), making the fold-from mismatch
	// check trustworthy. Omitted while unset.
	fold_id := jrn_map_get(opts, 'fold-id') or { '' }
	if fold_id != '' && !fold_id.contains(':') {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-id must be a computation address (`${fold_id}` is not an address)')
	}
	// §3.7 (RULED: SEA-1): opts.upcast engages the §3.9 chain over the folded
	// prefix exactly as on fold — a snapshot UNDER THE CURRENT FOLD is
	// spellable when that fold includes a chain (fn or derived form).
	mut has_up := false
	mut chain := jrn_null()
	if c := jrn_map_get_node(opts, 'upcast') {
		if e := jrn_chain_check(c, mut env) {
			return e
		}
		has_up = true
		chain = c
	}
	// §3.7 multi-stream (stream 7 W6): a TENANT snapshot (no stream=) over a
	// journal WITH named streams records the SET of stream heads + member
	// states under one signature — the :at-head-set cut. The pre-W6 behavior
	// silently snapshotted the (possibly empty) default chain: a FALSE
	// artifact ([state 0] at genesis) presented as the tenant state — the
	// silent-wrong-answer class this stream closes (#714). A journal with no
	// named streams keeps the single default form byte-identically.
	if is_def_snap && j.named.len > 0 {
		// The SET preimage (§3.7) reserves NO fold-id slot — carrying one
		// would be a second signing epoch (the forbidden shape). Teach the
		// per-stream path instead of silently dropping the declaration.
		if fold_id != '' {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: the tenant SET snapshot preimage carries no fold-id slot — snapshot each stream (stream= + fold-id=) to record fold identity')
		}
		return jrn_snapshot_set(j, fv, init, opts, has_up, chain, mut env)
	}
	shead := if is_def_snap {
		j.head_seq
	} else {
		st := j.named[stream] or { &StreamState{} }
		st.head_seq
	}
	at_seq := jrn_map_get_int(opts, 'at-seq') or { shead }
	if at_seq > shead || at_seq < 0 {
		return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: snapshot at-seq ${at_seq} beyond head ${shead}')
	}
	// Stream 7 (L122/L125 — journal.md §4.4): a snapshot signs "state at
	// at-seq", which needs the full genesis prefix — on a retention-pruned
	// chain it refuses (CXER4991) rather than SIGNING a wrong state folded
	// from the seam. Always-on: the pin is the snapshot's own semantics.
	sbase := jrn_stream_base(j, stream)
	if sbase > 0 {
		return cst_pin_refusal('journal:snapshot', 'at-seq-pinned', at_seq, sbase,
			'snapshot the intact source chain, or fold-from over the covering snapshot')
	}
	state := if is_def_snap {
		jrn_fold_upcast_default(j, at_seq, init, fv, has_up, chain, mut env)
	} else {
		st := j.named[stream] or { &StreamState{} }
		jrn_fold_upcast_stream(j.store_id, st, at_seq, init, fv, has_up, chain, mut env)
	}
	if is_err_value(state) {
		return state
	}
	anchor := if at_seq >= 1 {
		if is_def_snap {
			jrn_live_hash(j, at_seq)
		} else {
			st := j.named[stream] or { &StreamState{} }
			jrn_state_live_hash(st, at_seq)
		}
	} else {
		jrn_genesis_prev
	}
	// Signing (§4.8): opts.signing-key (a hex-encoded ed25519 seed) signs;
	// opts.sign=false → an explicitly unsigned mem:// snapshot; absent key and
	// sign not false → CXER4614.
	sign_off := (jrn_map_get(opts, 'sign') or { '' }) == 'false'
	key_hex := jrn_map_get(opts, 'signing-key') or { '' }
	if !sign_off && key_hex == '' {
		return mk_err(jrn_err_snap_unsigned, 'E_JOURNAL_SNAPSHOT_UNSIGNED: snapshot needs opts.signing-key (or opts.sign=false)')
	}
	// S6.4 (§3.7/§4.8): opts.signer records the UNSIGNED outer signer= hint —
	// meaningful only when a signature binds it, so an unsigned snapshot
	// carrying one is an authoring-time misuse (loud, like the absent-key
	// case), never a silently-ignored forgeable claim.
	mut signer := jrn_map_get(opts, 'signer') or { '' }
	if sign_off {
		if signer != '' {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: opts.signer on an unsigned snapshot (sign=false) — no signature binds the hint')
		}
		return jrn_build_snapshot(j.tenant, at_seq, stream, anchor, j.hash_algo, fold_id,
			false, '', '', '', state)
	}
	seed := jrn_hex_to_bytes(key_hex) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: signing-key must be hex')
	}
	if signer == '' {
		// Default (§3.7): the handle's own identity, recorded ONLY when it IS
		// the signing key's identity (the handle DID equals the key's derived
		// did:key) — a hint that could not verify is never manufactured, and
		// artifacts of every other existing flow stay byte-identical. rb.did
		// is the one identity slot both service wires fill from open-opts
		// xsp-did (the profile mirrors it into the session; the gRPC edge
		// signs each call with it).
		if ms := store_lookup(j.store_id) {
			if ms.remote != unsafe { nil } && ms.remote.did != '' {
				if ms.remote.did == (did_key_from_seed(seed) or { '' }) {
					signer = ms.remote.did
				}
			}
		}
	}
	canonical := jrn_snapshot_canonical(state, at_seq, stream, anchor, j.hash_algo, fold_id)
	sig_hex := jrn_sign(canonical, seed) or {
		return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: signing failed')
	}
	// derive the verify key from the seed via crypto keypair-from-seed: the
	// ed25519 public key is the seed's derived public. We re-derive by signing
	// a known value is not enough; instead persist the supplied public via
	// opts.verify-key if provided, else derive from the seed.
	pub_hex := jrn_map_get(opts, 'verify-key') or { jrn_derive_pub(seed) or { '' } }
	return jrn_build_snapshot(j.tenant, at_seq, stream, anchor, j.hash_algo, fold_id,
		true, sig_hex, pub_hex, signer, state)
}

// jrn_resnapshot — the L147 maintenance discipline as a verb (§3.7,
// RULED: SEA-1): re-derive $snapshot at its OWN at-seq/stream under the
// CURRENT fold quadruple (fn, init, opts.upcast chain, opts.fold-id),
// signing per §4.8. Idempotent when the snapshot already carries the
// declared identity (SEA-1f — nothing landed, nothing re-derives). All
// refusals are existing codes; resnapshot mints none.
fn jrn_resnapshot(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 4 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: resnapshot expects (journal, fn, init, snapshot)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	_ = j
	if args[3] !is cx.Element {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: resnapshot expects a [snapshot]')
	}
	snap := args[3] as cx.Element
	if snap.name != 'snapshot' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: not a [snapshot]')
	}
	opts := if args.len > 4 { args[4] } else { cx.Node(cx.Element{ name: 'map' }) }
	if jrn_snapshot_is_set(snap) {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: resnapshot consumes a single-stream snapshot — re-derive each member per stream (stream= + at-seq pin its chain)')
	}
	want_id := jrn_map_get(opts, 'fold-id') or { '' }
	if want_id == '' || !want_id.contains(':') {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: resnapshot requires opts.fold-id — the CURRENT fold identity (a computation address) to stamp on the re-derived snapshot')
	}
	// Idempotent (SEA-1f): the snapshot already carries the declared identity.
	if jrn_snapshot_attr(snap, 'fold-id') == want_id {
		return cx.Node(snap)
	}
	// The OLD snapshot must verify against the chain before anything
	// re-derives (anchor → CXER4615; signature, when present → CXER4613).
	valid, reason := jrn_snapshot_check(j, snap)
	if !valid {
		if reason == 'signature-invalid' {
			return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: forged/corrupt snapshot signature')
		}
		return mk_err(jrn_err_snap_seq, 'E_JOURNAL_SNAPSHOT_SEQ_MISMATCH: snapshot diverges from the chain (${reason})')
	}
	at_seq := jrn_snapshot_attr(snap, 'at-seq').int()
	stream := jrn_snapshot_attr(snap, 'stream')
	// Re-derive: jrn_snapshot at the SAME at-seq/stream, with the caller's
	// signing + upcast + fold-id opts riding through (pruned prefix / uncovered
	// entries / unsigned tier all refuse per the snapshot rules).
	nopts := jrn_opts_override(opts, at_seq, stream)
	return jrn_snapshot([args[0], args[1], args[2], nopts], mut env)
}

// jrn_opts_override copies an opts map, pinning at-seq (and stream when
// non-default) — the resnapshot → snapshot handoff.
fn jrn_opts_override(opts cx.Node, at_seq int, stream string) cx.Node {
	mut items := []cx.Node{}
	mut attrs := []cx.Attribute{}
	if opts is cx.Element {
		for it in opts.items {
			if it is cx.Element && it.name in ['at-seq', 'stream'] {
				continue
			}
			items << it
		}
		for a in opts.attrs {
			if a.name in ['at-seq', 'stream'] {
				continue
			}
			attrs << a
		}
	}
	items << cx.Node(cx.Element{
		name:  'at-seq'
		items: [jrn_int(at_seq)]
	})
	if !jrn_is_default(stream) {
		items << cx.Node(cx.Element{
			name:  'stream'
			items: [jrn_str(stream)]
		})
	}
	return cx.Node(cx.Element{
		name:  '__cx_map__'
		attrs: attrs
		items: items
	})
}

// jrn_snapshot_set folds + signs the §3.7 tenant SET snapshot (see the
// builders above). Members: the default chain first (when non-empty), then
// every non-empty named stream sorted by name — a deterministic cut order.
// A retention-pruned member refuses CXER4991 exactly like the single form
// (a set state needs every member's full prefix). opts.at-seq is refused:
// the set cuts at the heads; pin a single stream with stream= + at-seq.
fn jrn_snapshot_set(j &Journal, fv cx.Node, init cx.Node, opts cx.Node, has_up bool, chain cx.Node, mut env MatchEnv) ?cx.Node {
	if _ := jrn_map_get_int(opts, 'at-seq') {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: a tenant set snapshot cuts at the stream heads — pin a single stream with stream= + at-seq')
	}
	mut members := []cx.Element{}
	if j.head_seq > 0 {
		if j.base_seq > 0 {
			return cst_pin_refusal('journal:snapshot', 'at-seq-pinned', j.head_seq, j.base_seq,
				'snapshot the intact source chain, or fold-from over the covering snapshot')
		}
		state := jrn_fold_upcast_default(j, j.head_seq, init, fv, has_up, chain, mut env)
		if is_err_value(state) {
			return state
		}
		members << jrn_set_member('', j.head_seq, jrn_live_hash(j, j.head_seq), state)
	}
	mut names := j.named.keys()
	names.sort()
	for name in names {
		st := j.named[name] or { continue }
		if st.head_seq < 1 {
			continue
		}
		if st.base_seq > 0 {
			return cst_pin_refusal('journal:snapshot', 'at-seq-pinned', st.head_seq, st.base_seq,
				'snapshot the intact source chain, or fold-from over the covering snapshot')
		}
		state := jrn_fold_upcast_stream(j.store_id, st, st.head_seq, init, fv, has_up,
			chain, mut env)
		if is_err_value(state) {
			return state
		}
		members << jrn_set_member(name, st.head_seq, jrn_state_live_hash(st, st.head_seq),
			state)
	}
	// Signing — the single form's §4.8 rules verbatim, over the SET canonical.
	sign_off := (jrn_map_get(opts, 'sign') or { '' }) == 'false'
	key_hex := jrn_map_get(opts, 'signing-key') or { '' }
	if !sign_off && key_hex == '' {
		return mk_err(jrn_err_snap_unsigned, 'E_JOURNAL_SNAPSHOT_UNSIGNED: snapshot needs opts.signing-key (or opts.sign=false)')
	}
	mut signer := jrn_map_get(opts, 'signer') or { '' }
	if sign_off {
		if signer != '' {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: opts.signer on an unsigned snapshot (sign=false) — no signature binds the hint')
		}
		return jrn_build_snapshot_set(j.tenant, j.hash_algo, false, '', '', '', members)
	}
	seed := jrn_hex_to_bytes(key_hex) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: signing-key must be hex')
	}
	if signer == '' {
		if ms := store_lookup(j.store_id) {
			if ms.remote != unsafe { nil } && ms.remote.did != '' {
				if ms.remote.did == (did_key_from_seed(seed) or { '' }) {
					signer = ms.remote.did
				}
			}
		}
	}
	canonical := jrn_snapshot_set_canonical(members, j.hash_algo)
	sig_hex := jrn_sign(canonical, seed) or {
		return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: signing failed')
	}
	pub_hex := jrn_map_get(opts, 'verify-key') or { jrn_derive_pub(seed) or { '' } }
	return jrn_build_snapshot_set(j.tenant, j.hash_algo, true, sig_hex, pub_hex, signer,
		members)
}

// jrn_build_snapshot_set assembles the SET artifact: [snapshot tenant=
// hash-algo= sig-algo= … [h …]…] — no top-level at-seq/anchor-hash (the
// members carry the cut); the [h] children are the SAME elements the
// canonical signed, so verify re-renders them byte-identically.
fn jrn_build_snapshot_set(tenant string, algo string, signed bool, sig_hex string, pub_hex string, signer string, members []cx.Element) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'tenant'
			value: cx.ScalarValue(tenant)
		},
		cx.Attribute{
			name:  'hash-algo'
			value: cx.ScalarValue(algo)
		},
	]
	if signed {
		attrs << cx.Attribute{
			name:  'sig-algo'
			value: cx.ScalarValue('ed25519')
		}
		attrs << cx.Attribute{
			name:  'signature'
			value: cx.ScalarValue(sig_hex)
		}
		attrs << cx.Attribute{
			name:  'verify-key'
			value: cx.ScalarValue(pub_hex)
		}
		if signer != '' {
			attrs << cx.Attribute{
				name:  'signer'
				value: cx.ScalarValue(signer)
			}
		}
	} else {
		attrs << cx.Attribute{
			name:  'sig-algo'
			value: cx.ScalarValue('none')
		}
	}
	mut items := []cx.Node{}
	for m in members {
		items << cx.Node(m)
	}
	return cx.Element{
		name:  'snapshot'
		attrs: attrs
		items: items
	}
}

// jrn_derive_pub derives the ed25519 public key (hex) from a 32-byte seed via
// crypto.ed25519 (the public is derived from the seed by the RFC-8032 key
// expansion — no fresh randomness).
fn jrn_derive_pub(seed []u8) ?string {
	if seed.len != 32 {
		return none
	}
	priv := ed25519.new_key_from_seed(seed)
	pubkey := priv.public_key()
	return []u8(pubkey).hex()
}

fn jrn_fold_from(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-from expects (journal, snapshot, fn)')
	}
	j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	if args[1] !is cx.Element {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-from expects a [snapshot]')
	}
	snap := args[1] as cx.Element
	if snap.name != 'snapshot' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: not a [snapshot]')
	}
	fv := args[2]
	if e := jrn_assert_pure(fv, mut env) {
		return e
	}
	opts := if args.len > 3 { args[3] } else { cx.Node(cx.Element{ name: 'map' }) }
	// §3.7 SET form (stream 7 W6): fold-from consumes a SINGLE-stream
	// snapshot — a set member carries its own [state] and position, and the
	// tenant-wide composition of member states is the CALLER's (§3.4: the
	// journal cannot merge opaque user states). The refusal teaches the
	// consumption path instead of guessing a merge.
	if jrn_snapshot_is_set(snap) {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: fold-from consumes a single-stream snapshot — a set snapshot member carries its own [state] and at-seq; fold each member forward with fold-slice (from=at-seq+1, init=the member state) and compose per §3.4')
	}
	// §3.7/§4.8 (stream 21, L147): the fold-identity check — CONDITIONAL on
	// the caller declaring its current fold. A declared fold-id against a
	// snapshot carrying a DIFFERENT identity, or carrying NONE, is the loud
	// typed mismatch: the snapshot is frozen output of some other fold and
	// silently-stale state is the exact data-loss shape this closes.
	// Undeclared keeps the shipped path byte-identically.
	want_id := jrn_map_get(opts, 'fold-id') or { '' }
	if want_id != '' {
		snap_id := jrn_snapshot_attr(snap, 'fold-id')
		if snap_id == '' {
			return mk_err(jrn_err_fold_id, 'E_JOURNAL_FOLD_ID_MISMATCH: the snapshot carries no fold identity (declared ${want_id}) — re-derive it under the current fold with [\$journal:resnapshot] (§3.7)')
		}
		if snap_id != want_id {
			return mk_err(jrn_err_fold_id, 'E_JOURNAL_FOLD_ID_MISMATCH: snapshot fold ${snap_id} != declared ${want_id} — re-derive it under the current fold with [\$journal:resnapshot] (§3.7)')
		}
	}
	// §3.9: the upcast chain covers the TAIL entries (the snapshotted prefix
	// is already state — a vocabulary change there is exactly what the
	// fold-id check above refuses).
	mut has_up := false
	mut chain := jrn_null()
	if c := jrn_map_get_node(opts, 'upcast') {
		if e := jrn_chain_check(c, mut env) {
			return e
		}
		has_up = true
		chain = c
	}
	// snapshot-verify against the chain BEFORE folding (§3.7).
	valid, reason := jrn_snapshot_check(j, snap)
	if !valid {
		if reason == 'signature-invalid' {
			return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: forged/corrupt snapshot signature')
		}
		return mk_err(jrn_err_snap_seq, 'E_JOURNAL_SNAPSHOT_SEQ_MISMATCH: snapshot diverges from the chain (${reason})')
	}
	at_seq := jrn_snapshot_attr(snap, 'at-seq').int()
	state := jrn_snapshot_state(snap)
	stream := jrn_snapshot_attr(snap, 'stream')
	// fold ONLY entries at-seq+1 .. head onto the snapshot state, on the snapshot's stream.
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return state }
		if has_up {
			mut sitems := []cx.Node{}
			for entry in jrn_state_collect_range(st, at_seq + 1, st.head_seq) {
				sitems << jrn_hydrate_entry(j.store_id, entry)
			}
			uitems, uerr, uok := jrn_upcast_stage(sitems, true, chain, mut env)
			if !uok {
				return uerr
			}
			mut acc := state
			for entry in uitems {
				acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
			}
			return acc
		}
		return jrn_fold_state_entries(j.store_id, st, at_seq + 1, st.head_seq, state, fv, mut env)
	}
	if has_up {
		items := jrn_collect_range(j, at_seq + 1, j.head_seq)
		uitems, uerr, uok := jrn_upcast_stage(items, true, chain, mut env)
		if !uok {
			return uerr
		}
		mut acc := state
		for entry in uitems {
			acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
		}
		return acc
	}
	return jrn_fold_entries(j, at_seq + 1, j.head_seq, state, fv, mut env)
}

// ── bundled module source ──────────────────────────────────────────────────
//
// The canonical cx-stdlib/journal surface (stdlib/journal.cx) is embedded
// as stdlib_src_journal in Ring-1 stdlib_bundle.v with the other bundle
// sources (relocated at I3 seam H). Bodies forward to the native
// primitives above. The $fn-taking verbs forward to `journal-*` names
// reached via the eval.v env-hook (journal_stdlib_builtin_env); the rest
// reach the env-free journal_stdlib_builtin chain.

// ── stream 20 (#692): legal holds — the Lane-2 hold claim + the hold-stream ──
//
// A legal hold is a SIGNED Lane-2 `[legal-hold]` claim VALUE, journaled to the
// reserved per-tenant hold-stream (erasure_compliance §8): it binds from its
// journaled position onward — a hold not yet journaled does not bind (the
// honest rule). Enforcement is W4's erase-subject PRECONDITION (hold-beats-
// shred; the head pin + commit-lock re-check); this surface is the substrate:
// write-time validation (an unbindable hold must never be RECORDED — the
// §2.11 write-time posture; entries are immutable, so a malformed hold would
// poison the stream forever) and the fail-closed load (defense-in-depth: a
// malformed hold reached some other way fails LOUD at load, never a skip —
// the lineage-path posture).
//
// Claim shape (Ring-0 vocabulary, erasure_compliance §9):
//   [legal-hold [subject "…"]|[hash "sha2-256:…"] [signer "did:…"] [at "…"]
//               [sig alg=:ed25519 value=<128-hex> key=<64-hex pub>]]
// The signature covers the claim's STRICT CANONICAL TEXT with the [sig] child
// removed (the detached-signature pattern). Verification proves the claim was
// signed by the holder of `key`; binding `key` to the named signer identity
// is authz/vc's domain (the §2.6 attribution posture) — the load reports
// both, verbatim.

const jrn_hold_stream = 'cx:legal-hold'
const jrn_err_hold_invalid = 'cx-err:CXER4620' // E_ERASURE_HOLD_INVALID

struct JrnHold {
	seq     int
	subject string
	hash    string
	signer  string
	at      string
}

fn jrn_hold_child_text(e cx.Element, name string) string {
	for it in e.items {
		if it is cx.Element && it.name == name {
			if it.items.len > 0 {
				v := it.items[0]
				if v is cx.ScalarNode {
					return cx.scalar_value_str_public(v.value)
				}
				// a store-rehydrated (parsed) claim carries string items as
				// TextNode — same text, different node kind.
				if v is cx.TextNode {
					return v.value
				}
			}
			return ''
		}
	}
	return ''
}

// jrn_hold_parse validates ONE hold claim fail-closed: shape (exactly one
// scope of [subject]/[hash]; non-empty [signer] + [at]) and the detached
// ed25519 signature. The error text is the reason the hold cannot bind.
fn jrn_hold_parse(payload cx.Node) !JrnHold {
	if payload !is cx.Element {
		return error('payload is not a [legal-hold] element')
	}
	e := payload as cx.Element
	if e.name != 'legal-hold' {
		return error('payload is not a [legal-hold] element')
	}
	subject := jrn_hold_child_text(e, 'subject')
	hashv := jrn_hold_child_text(e, 'hash')
	if (subject == '') == (hashv == '') {
		return error('scope must be exactly one of [subject …] / [hash …]')
	}
	signer := jrn_hold_child_text(e, 'signer')
	if signer == '' {
		return error('missing [signer …]')
	}
	at := jrn_hold_child_text(e, 'at')
	if at == '' {
		return error('missing [at …]')
	}
	mut sig_val := ''
	mut sig_key := ''
	mut sig_alg := 'ed25519'
	mut found := false
	mut sans := cx.Element{
		name:  e.name
		attrs: e.attrs
	}
	for it in e.items {
		if it is cx.Element && it.name == 'sig' {
			found = true
			for a in it.attrs {
				match a.name {
					'value' { sig_val = cx.scalar_value_str_public(a.value) }
					'key' { sig_key = cx.scalar_value_str_public(a.value) }
					'alg' { sig_alg = cx.scalar_value_str_public(a.value).trim_string_left(':') }
					else {}
				}
			}
			continue
		}
		sans.items << it
	}
	if !found || sig_val == '' || sig_key == '' {
		return error('missing/incomplete [sig value= key=] — an unsigned hold binds nothing (fail-closed)')
	}
	if sig_alg != 'ed25519' {
		return error('unsupported hold signature algorithm `${sig_alg}`')
	}
	pub_bytes := jrn_hex_to_bytes(sig_key) or { return error('sig key= is not hex') }
	rendered := render_canonical(cx.Node(sans))
	preimage := cx.cx_text_canonical(rendered) or {
		return error('claim does not canonicalize: ${err.msg()}')
	}
	if !jrn_snapshot_verify_sig(preimage, sig_val, pub_bytes) {
		return error('signature does not verify over the claim canonical text (sans [sig])')
	}
	return JrnHold{
		seq:     0
		subject: subject
		hash:    hashv
		signer:  signer
		at:      at
	}
}

// jrn_legal_holds implements [$journal:legal-holds $j $opts] — the hold-stream
// load: every retained hold entry validates fail-closed (CXER4620 naming seq
// — never a skip), the result carries the stream head (the position W4's
// erase precondition pins) and each binding hold's coordinates. opts filter:
// {subject: "…"} / {hash: "…"}.
fn jrn_legal_holds(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: legal-holds expects (journal, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	opts := if args.len > 1 { args[1] } else { cx.Node(cx.Element{
			name: 'map'
		}) }
	f_subject := jrn_map_get(opts, 'subject') or { '' }
	f_hash := jrn_map_get(opts, 'hash') or { '' }
	jrn_refresh_head(mut j, jrn_hold_stream)
	mut head := 0
	mut items := []cx.Node{}
	if st := j.named[jrn_hold_stream] {
		head = st.head_seq
		items = jrn_state_collect_range_of(j, jrn_hold_stream, st, 1, st.head_seq)
	}
	mut holds := []cx.Node{}
	for it in items {
		mut seq := 0
		mut claim := cx.Node(cx.Element{})
		if it is cx.Element {
			for a in it.attrs {
				if a.name == 'seq' {
					seq = cx.scalar_value_str_public(a.value).int()
				}
			}
			for ch in it.items {
				if ch is cx.Element && ch.name == 'event' {
					if ch.items.len > 0 {
						claim = ch.items[0]
					}
				}
			}
		}
		h := jrn_hold_parse(claim) or {
			return mk_err(jrn_err_hold_invalid, 'E_ERASURE_HOLD_INVALID: hold-stream entry seq=${seq}: ${err.msg()} — a hold that cannot bind fails LOUD at load, never a skip (erasure_compliance §8)')
		}
		if f_subject != '' && h.subject != f_subject {
			continue
		}
		if f_hash != '' && h.hash != f_hash {
			continue
		}
		mut attrs := [
			cx.Attribute{
				name:  'seq'
				value: cx.ScalarValue(i64(seq))
			},
		]
		if h.subject != '' {
			attrs << cx.Attribute{
				name:  'subject'
				value: cx.ScalarValue(h.subject)
			}
		} else {
			attrs << cx.Attribute{
				name:  'hash'
				value: cx.ScalarValue(h.hash)
			}
		}
		attrs << cx.Attribute{
			name:  'signer'
			value: cx.ScalarValue(h.signer)
		}
		attrs << cx.Attribute{
			name:  'at'
			value: cx.ScalarValue(h.at)
		}
		holds << cx.Node(cx.Element{
			name:  'hold'
			attrs: attrs
		})
	}
	return cx.Node(cx.Element{
		name:  'holds'
		attrs: [
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(jrn_hold_stream)
			},
			cx.Attribute{
				name:  'head'
				value: cx.ScalarValue(i64(head))
			},
			cx.Attribute{
				name:  'count'
				value: cx.ScalarValue(i64(holds.len))
			},
		]
		items: holds
	})
}

// ── stream 20 (#692): erase-subject — the recorded RTBF command + shred walk ──
//
// The M5 worked example's verb (erasure_compliance §7): an RTBF request is
// RECORDED as an `[erase-subject]` command entry on the reserved per-tenant
// stream below (attributed — actor + authority journaled), and only then
// EXECUTED: the KMS destroy is strictly POST-COMMIT (the forward-only pivot,
// M30 — once the record commits with the hold pin satisfied, no later hold
// can bind that shred, by position, visibly). The journaled record is also
// the command's DURABLE dedup record (audit M31): a resubmission for the
// same subject answers `[deduped <the recorded report>]` and re-runs only
// the idempotent walk (self-heal — never a second destructive act). The
// eval-layer `[idempotent]` clause is deliberately NOT used here: its
// derived key is subject-derivable (the digest oracle M31 forbids) and its
// registry is in-process only; the record's `request=` id is the opaque
// CSPRNG token, and records are seq-keyed journal entries — no
// subject-keyed digest namespace exists.
//
// The hold precondition (§8, M30): an UNLOCKED pass loads the hold stream
// fail-closed and pins its head; the store op-lock is then held for the
// WHOLE command (the #779/#628 posture — every append on this root
// serializes on it, so it IS the writing commit lock) and the holds
// re-validate under it against the full enumerated doc scope. A binding
// hold refuses CXER4621 — atomically: the shred-generation never advances,
// so no snapshot goes stale and no re-snapshot is forced (the "blocks shred
// AND re-snapshot" suspension is structural).

const jrn_erase_stream = 'cx:erasure'
const jrn_err_held = 'cx-err:CXER4621' // E_ERASURE_HELD
const jrn_err_erasure_reserved = 'cx-err:CXER4622' // E_ERASURE_RECORD_RESERVED

// jrn_shred_gen_alias names the per-tenant shred-generation meta doc — the
// ENV-quadrant input (§7): callers bind it into their fold identity, so a
// committed shred moves every current fold-id and the CXER4640 staleness
// machinery invalidates pre-shred snapshots with no new mechanism.
fn jrn_shred_gen_alias(tenant string) string {
	return 'cx-journal/shred-generation/${tenant}'
}

fn jrn_shred_generation_read(store_id int, tenant string) int {
	e := jrn_get_meta_doc(store_id, jrn_shred_gen_alias(tenant)) or { return 0 }
	if e.name != 'shred-generation' {
		return 0
	}
	return e.attr('value').int()
}

// jrn_shred_generation implements [$journal:shred-generation $j] — the
// tenant's current shred-generation (0 before any committed erase).
fn jrn_shred_generation(args []cx.Node) ?cx.Node {
	if args.len < 1 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: shred-generation expects (journal)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	return jrn_int(i64(jrn_shred_generation_read(j.store_id, j.tenant)))
}

// jrn_erase_binding_hold loads + validates the hold stream FAIL-CLOSED
// (CXER4620 on any unbindable entry — never a skip) and returns the stream
// head plus the first hold binding this erase: subject-scoped match on
// `subject`, or hash-scoped match against the enumerated doc set.
fn jrn_erase_binding_hold(mut j Journal, subject string, docs []string) !(int, JrnHold, bool) {
	jrn_refresh_head(mut j, jrn_hold_stream)
	mut head := 0
	mut items := []cx.Node{}
	if st := j.named[jrn_hold_stream] {
		head = st.head_seq
		items = jrn_state_collect_range_of(j, jrn_hold_stream, st, 1, st.head_seq)
	}
	for it in items {
		mut seq := 0
		mut claim := cx.Node(cx.Element{})
		if it is cx.Element {
			for a in it.attrs {
				if a.name == 'seq' {
					seq = cx.scalar_value_str_public(a.value).int()
				}
			}
			for ch in it.items {
				if ch is cx.Element && ch.name == 'event' {
					if ch.items.len > 0 {
						claim = ch.items[0]
					}
				}
			}
		}
		h := jrn_hold_parse(claim) or {
			return error('hold-stream entry seq=${seq}: ${err.msg()} — a hold that cannot bind fails LOUD, never a skip (erasure_compliance §8)')
		}
		bh := JrnHold{
			seq:     seq
			subject: h.subject
			hash:    h.hash
			signer:  h.signer
			at:      h.at
		}
		if bh.subject != '' && bh.subject == subject {
			return head, bh, true
		}
		if bh.hash != '' && bh.hash in docs {
			return head, bh, true
		}
	}
	return head, JrnHold{}, false
}

// jrn_erase_held_err builds the loud typed refusal naming the hold claim,
// holder, and scope (§8: hold-beats-shred; never a partial shred).
fn jrn_erase_held_err(h JrnHold, subject string) cx.Node {
	scope := if h.subject != '' { 'subject `${h.subject}`' } else { 'hash `${h.hash}`' }
	return mk_err(jrn_err_held, 'E_ERASURE_HELD: erase-subject `${subject}` refused — legal hold at ${jrn_hold_stream} seq=${h.seq} by ${h.signer} (at ${h.at}) binds ${scope}; hold-beats-shred, and the hold suspends the forced re-snapshot with it (erasure_compliance §8)')
}

// jrn_erase_child_text — child-element text on a (possibly store-rehydrated)
// record; the jrn_hold_child_text pattern.
fn jrn_erase_child_text(e cx.Element, name string) string {
	return jrn_hold_child_text(e, name)
}

// jrn_erasure_record_for scans the reserved stream for the committed record
// matching (subject, request) — the durable dedup lookup (M31): a
// RESUBMISSION carries the same opaque request token and answers
// `[deduped …]`; a NEW request for the same subject is a NEW command (data
// re-landed after an earlier erase must be erasable — the earlier record
// must never absorb every future RTBF act, which is exactly the
// subject-keyed behavior M31 forbids). Returns (record payload, entry
// envelope, found).
fn jrn_erasure_record_for(mut j Journal, subject string, request string) (cx.Element, cx.Element, bool) {
	jrn_refresh_head(mut j, jrn_erase_stream)
	st := j.named[jrn_erase_stream] or { return cx.Element{}, cx.Element{}, false }
	items := jrn_state_collect_range_of(j, jrn_erase_stream, st, 1, st.head_seq)
	for it in items {
		if it is cx.Element {
			for ch in it.items {
				if ch is cx.Element && ch.name == 'event' && ch.items.len > 0 {
					payload := ch.items[0]
					if payload is cx.Element && payload.name == 'erase-subject' {
						if jrn_erase_child_text(payload, 'subject') == subject
							&& jrn_erase_child_text(payload, 'request') == request {
							return payload, it, true
						}
					}
				}
			}
		}
	}
	return cx.Element{}, cx.Element{}, false
}

// jrn_erase_targets opens every non-disposed store the segment index names
// (predecessors + their archive copies — §7 "rotation targets + segment
// index, archived predecessors, archive= stores"). Fail-closed: a
// non-disposed segment store that will not open is a LOUD error (missing an
// enumerated surface is a compliance failure); a disposed one counts
// visibly. Returns (handles, urls, disposed-count).
fn jrn_erase_targets(mut j Journal, enc_key_id string) !([]cx.Node, []string, int) {
	mut handles := []cx.Node{}
	mut urls := []string{}
	mut disposed := 0
	segs := jrn_read_segment_index(j.store_id, j.tenant)
	for s in segs {
		if s !is cx.Element {
			continue
		}
		se := s as cx.Element
		mut targets := []string{}
		if se.attr('disposed') == 'true' {
			disposed++
		} else {
			u := se.attr('store')
			if u != '' {
				targets << u
			}
		}
		at := se.attr('archived-to')
		if at != '' {
			targets << at
		}
		for u in targets {
			if u in urls {
				continue
			}
			mut auth := map[string]string{}
			if enc_key_id != '' {
				auth['encrypt-key-id'] = enc_key_id
			}
			h := store_open_impl(u, '', '', false, true, auth)
			if is_err_value(h) {
				jrn_erase_close_targets(handles)
				return error('sealed segment store ${store_url_redact_userinfo(u)} did not open — the shred walk must reach every enumerated surface (erasure_compliance §7): ${svc_err_text(h)}')
			}
			// A sealed segment is never empty (rotation moves entries + their
			// pointers into it) — but file:// stores CREATE on open, so a
			// missing predecessor would silently open as a fresh empty store
			// and read as "clean". Fail closed: an empty open here means the
			// sealed segment store is MISSING, not erased.
			mut pms, _, pok := store_get_open(h)
			if pok && pms.doc_order.len == 0 && pms.aliases.len == 0 && pms.erased.len == 0 {
				store_stdlib_builtin_inner('store-close', [h]) or { cx.Node(cx.Element{}) }
				jrn_erase_close_targets(handles)
				return error('sealed segment store ${store_url_redact_userinfo(u)} opened EMPTY — the recorded segment is missing (a file:// open creates a fresh store); record its disposition (journal-segment-disposed) or restore it: the shred walk must reach every enumerated surface (erasure_compliance §7)')
			}
			handles << h
			urls << u
		}
	}
	return handles, urls, disposed
}

// jrn_shred_report builds the §9.1-shaped balanced report:
// docs = erased + already-erased.
fn jrn_shred_report(subject string, request string, docs int, erased int, already int, subject_keys int, derived int, checkpoints int, dedup int, stores int, disposed int, generation int, holds_head int) cx.Element {
	return cx.Element{
		name:  'shred-report'
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
				name:  'docs'
				value: cx.ScalarValue(i64(docs))
			},
			cx.Attribute{
				name:  'erased'
				value: cx.ScalarValue(i64(erased))
			},
			cx.Attribute{
				name:  'already-erased'
				value: cx.ScalarValue(i64(already))
			},
			cx.Attribute{
				name:  'subject-keys'
				value: cx.ScalarValue(i64(subject_keys))
			},
			cx.Attribute{
				name:  'derived'
				value: cx.ScalarValue(i64(derived))
			},
			cx.Attribute{
				name:  'checkpoints'
				value: cx.ScalarValue(i64(checkpoints))
			},
			cx.Attribute{
				name:  'dedup-records'
				value: cx.ScalarValue(i64(dedup))
			},
			cx.Attribute{
				name:  'stores'
				value: cx.ScalarValue(i64(stores))
			},
			cx.Attribute{
				name:  'disposed'
				value: cx.ScalarValue(i64(disposed))
			},
			cx.Attribute{
				name:  'generation'
				value: cx.ScalarValue(i64(generation))
			},
			cx.Attribute{
				name:  'holds-head'
				value: cx.ScalarValue(i64(holds_head))
			},
		]
	}
}

// jrn_erase_close_targets closes the walk's opened segment handles.
fn jrn_erase_close_targets(handles []cx.Node) {
	for h in handles {
		store_stdlib_builtin_inner('store-close', [h]) or { cx.Node(cx.Element{}) }
	}
}

// jrn_erase_walk_all runs the per-store walk over the hot store + every
// opened segment handle. The report is the committed PLAN (deterministic
// under the held lock); the walk's own counts converge on it, so only its
// errors surface. `at`/`actor`/`authority` attribute the tombstones (the
// committed record's coordinates).
fn jrn_erase_walk_all(mut msh MemStore, handles []cx.Node, subject string, request string, actor string, authority string, at string, needles []string) ! {
	store_erase_subject_walk(mut msh, subject, request, actor, authority, at, needles)!
	for h in handles {
		mut pms, _, pok := store_get_open(h)
		if !pok {
			return error('sealed segment handle unusable mid-walk')
		}
		store_erase_subject_walk(mut pms, subject, request, actor, authority, at, needles)!
	}
}

// jrn_erase_subject implements [$journal:erase-subject $j $subject
// $attribution $opts?] — see the section comment above.
fn jrn_erase_subject(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: erase-subject expects (journal, subject, attribution, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	if j.read_only {
		return mk_err(jrn_err_read_only, 'E_JOURNAL_READ_ONLY: erase-subject on a read-only journal')
	}
	subject := jrn_arg_str(args[1]) or { '' }
	if subject == '' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: erase-subject needs a non-empty subject id')
	}
	attribution := args[2]
	actor := jrn_map_get(attribution, 'actor') or { '' }
	authority := jrn_map_get(attribution, 'authority') or { '' }
	if actor == '' || authority == '' {
		return mk_err(jrn_err_attr_invalid, 'E_JOURNAL_ATTRIBUTION_INVALID: erase-subject requires non-empty actor + authority — the erasure act is journaled with declared authority (erasure_compliance §7)')
	}
	opts := if args.len > 3 { args[3] } else { cx.Node(cx.Element{
			name: 'map'
		}) }
	mut request := jrn_map_get(opts, 'request') or { '' }
	if request == '' {
		rb := crypto_random_octets(16) or { []u8{} }
		if rb.len < 16 {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: erase-subject could not mint the CSPRNG request token')
		}
		request = 'shred-${rb.hex()}'
	}
	mut msh := store_lookup(j.store_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: backing store is gone')
	}
	if store_remote_active(msh) {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: erase-subject is a local-custody act — erasure over the wire is the stream-4/9 joint surface; erase on the daemon host')
	}
	if _ := store_objwire_client(msh) {
		return mk_err('cx-err:CXER1144', 'E_STORE_SUBJECT_UNSUPPORTED: erase-subject is a local-custody act — erasure over the wire is the stream-4/9 joint surface; erase on the daemon host')
	}
	// ── the UNLOCKED precondition pass: the hold-stream head PINS here (M30);
	//    a subject-scoped hold fails fast. Hash-scoped holds re-check below
	//    against the full doc scope, under the lock.
	pin_head, pin_hold, pin_found := jrn_erase_binding_hold(mut j, subject, []string{}) or {
		return mk_err(jrn_err_hold_invalid, 'E_ERASURE_HOLD_INVALID: ${err.msg()}')
	}
	if pin_found {
		return jrn_erase_held_err(pin_hold, subject)
	}
	// ── the writing commit lock: the WHOLE command serializes on the backing
	//    store's op-lock (#628/#779) — no hold, no sibling append, and no
	//    concurrent erase can interleave between re-check, commit, and walk.
	store_lock_enter(mut msh)
	defer {
		store_lock_exit(mut msh)
	}
	// The durable dedup record (M31): a resubmission (same subject + same
	// opaque request token) → deduped replay (self-heal: the walk re-runs
	// idempotently; never a second destructive act). A NEW token is a NEW
	// command — re-landed subject data stays erasable.
	rec, entry, rfound := jrn_erasure_record_for(mut j, subject, request)
	if rfound {
		return jrn_erase_replay(mut j, mut msh, rec, entry, subject, mut env)
	}
	// Open every enumerated segment store (predecessors + archives).
	handles, _, disposed := jrn_erase_targets(mut j, msh.enc_key_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: ${err.msg()}')
	}
	defer {
		jrn_erase_close_targets(handles)
	}
	// ── plan: per-store scope (sek + whole-doc set), unioned. ──
	mut docs_union := []string{}
	mut seks := []string{}
	mut per_store_docs := 0
	mut plan_already := 0
	hot_sek, hot_scope := store_erase_plan(mut msh, subject)
	if hot_sek != '' {
		seks << hot_sek
	}
	per_store_docs += hot_scope.len
	for h in hot_scope {
		if h !in docs_union {
			docs_union << h
		}
	}
	for h in handles {
		mut pms, _, pok := store_get_open(h)
		if !pok {
			return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: sealed segment handle unusable during planning')
		}
		psek, pscope := store_erase_plan(mut pms, subject)
		if psek != '' && psek !in seks {
			seks << psek
		}
		per_store_docs += pscope.len
		for hh in pscope {
			if hh !in docs_union {
				docs_union << hh
			}
		}
		for hh in pscope {
			if hh in pms.erased {
				plan_already++
			}
		}
	}
	for hh in hot_scope {
		if hh in msh.erased {
			plan_already++
		}
	}
	docs_union.sort()
	// derived/checkpoint plan counts (the union needles reach cross-store
	// references) + the in-process dedup registry scan (stream-6 records:
	// shred reach beats the retention window; the exempt record is the
	// journaled one, M31).
	mut needles := [subject]
	needles << docs_union
	mut plan_derived := 0
	mut plan_ckpts := 0
	plan_derived += store_erase_computation_victims(mut msh, needles).len
	plan_ckpts += store_erase_checkpoint_victims(mut msh).len
	for h in handles {
		mut pms, _, pok := store_get_open(h)
		if pok {
			plan_derived += store_erase_computation_victims(mut pms, needles).len
			plan_ckpts += store_erase_checkpoint_victims(mut pms).len
		}
	}
	idem_keys := idem_matching_keys(env, needles)
	// ── the hold RE-CHECK under the commit lock (M30): entries past the pin
	//    re-validate, and the FULL hold set checks against the enumerated doc
	//    scope (hash-scoped holds bind through their covered addresses).
	re_head, re_hold, re_found := jrn_erase_binding_hold(mut j, subject, docs_union) or {
		return mk_err(jrn_err_hold_invalid, 'E_ERASURE_HOLD_INVALID: ${err.msg()}')
	}
	_ = pin_head // the pin's audit value is the recorded holds-head below
	if re_found {
		return jrn_erase_held_err(re_hold, subject)
	}
	generation := jrn_shred_generation_read(j.store_id, j.tenant) + 1
	// head-set scope: the tenant's DATA streams at commit (the reserved cx:*
	// streams are the command's own machinery, not its scope).
	jrn_refresh_head(mut j, '')
	mut head_set := []cx.Node{}
	head_set << cx.Node(cx.Element{
		name:  's'
		attrs: [
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(':default')
			},
			cx.Attribute{
				name:  'head'
				value: cx.ScalarValue(i64(j.head_seq))
			},
		]
	})
	mut snames := j.named.keys()
	snames.sort()
	for sn in snames {
		if sn.starts_with('cx:') {
			continue
		}
		st := j.named[sn] or { continue }
		head_set << cx.Node(cx.Element{
			name:  's'
			attrs: [
				cx.Attribute{
					name:  'stream'
					value: cx.ScalarValue(sn)
				},
				cx.Attribute{
					name:  'head'
					value: cx.ScalarValue(i64(st.head_seq))
				},
			]
		})
	}
	report := jrn_shred_report(subject, request, per_store_docs, per_store_docs - plan_already,
		plan_already, seks.len, plan_derived, plan_ckpts, idem_keys.len, 1 + handles.len,
		disposed, generation, re_head)
	// ── the record (the value journaled to the reserved stream). Children,
	//    not reserved root attrs: the record itself must never demand a
	//    nonce + SEK seal.
	mut rec_items := []cx.Node{}
	rec_items << cx.Node(cx.Element{
		name:  'subject'
		items: [jrn_str(subject)]
	})
	rec_items << cx.Node(cx.Element{
		name:  'request'
		items: [jrn_str(request)]
	})
	for sk in seks {
		rec_items << cx.Node(cx.Element{
			name:  'sek'
			items: [jrn_str(sk)]
		})
	}
	rec_items << cx.Node(cx.Element{
		name:  'holds-head'
		items: [jrn_int(i64(re_head))]
	})
	rec_items << cx.Node(cx.Element{
		name:  'generation'
		items: [jrn_int(i64(generation))]
	})
	rec_items << cx.Node(cx.Element{
		name:  'head-set'
		items: head_set
	})
	mut doc_items := []cx.Node{}
	for dh in docs_union {
		doc_items << cx.Node(cx.Element{
			name:  'd'
			items: [jrn_str(dh)]
		})
	}
	rec_items << cx.Node(cx.Element{
		name:  'docs'
		items: doc_items
	})
	rec_items << cx.Node(report)
	record := cx.Node(cx.Element{
		name:  'erase-subject'
		items: rec_items
	})
	// ── COMMIT: the record entry + the generation advance land as ONE
	//    durable unit (#614 — the flush-hold scope nests through the append).
	attr_map := cx.Node(cx.Element{
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
			cx.Node(cx.Element{
				name:  'stream'
				items: [jrn_str(jrn_erase_stream)]
			}),
		]
	})
	store_flush_hold(mut msh)
	j.reserved_append_ok = true
	appended := jrn_append([args[0], record, attr_map]) or {
		j.reserved_append_ok = false
		store_flush_release(mut msh) or {}
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: erase-subject record append failed')
	}
	j.reserved_append_ok = false
	if is_err_value(appended) {
		store_flush_release(mut msh) or {}
		return appended
	}
	if e := jrn_set_meta_alias(j.store_id, jrn_shred_gen_alias(j.tenant), cx.Element{
		name:  'shred-generation'
		attrs: [
			cx.Attribute{
				name:  'value'
				value: cx.ScalarValue(i64(generation))
			},
		]
	})
	{
		store_flush_release(mut msh) or {}
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: shred-generation advance failed',
			e)
	}
	store_flush_release(mut msh) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: erase-subject durable flush failed: ${err.msg()}')
	}
	// ── POST-COMMIT: the forward-only pivot. The walk executes the recorded
	//    plan; a failure here is LOUD and the committed record self-heals on
	//    the deduped replay. Tombstones carry the entry's own coordinates.
	mut at := ''
	if appended is cx.Element {
		at = appended.attr('ts')
	}
	jrn_erase_walk_all(mut msh, handles, subject, request, actor, authority, at, needles) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: the shred walk failed AFTER the record committed — resubmit erase-subject to self-heal (deduped replay re-runs the idempotent walk): ${err.msg()}')
	}
	idem_drop_keys(mut env, idem_keys)
	return cx.Node(report)
}

// jrn_erase_replay answers a resubmission from the committed record: re-run
// the idempotent walk (self-heal — a crashed walk completes here; destroy of
// an absent key and re-erase of a tombstoned doc are no-ops) and return
// `[deduped <the recorded report>]` (stream-6 R13: a PRESENT value carrying
// the original outcome, never the absence channel).
fn jrn_erase_replay(mut j Journal, mut msh MemStore, rec cx.Element, entry cx.Element, subject string, mut env MatchEnv) ?cx.Node {
	request := jrn_erase_child_text(rec, 'request')
	actor := entry.attr('actor')
	authority := entry.attr('authority')
	at := entry.attr('ts')
	mut docs := []string{}
	for it in rec.items {
		if it is cx.Element && it.name == 'docs' {
			for d in it.items {
				if d is cx.Element && d.name == 'd' && d.items.len > 0 {
					v := d.items[0]
					if v is cx.ScalarNode {
						docs << cx.scalar_value_str_public(v.value)
					} else if v is cx.TextNode {
						docs << v.value
					}
				}
			}
		}
	}
	mut report := cx.Element{
		name: 'shred-report'
	}
	for it in rec.items {
		if it is cx.Element && it.name == 'shred-report' {
			report = it
		}
	}
	handles, _, _ := jrn_erase_targets(mut j, msh.enc_key_id) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: ${err.msg()}')
	}
	defer {
		jrn_erase_close_targets(handles)
	}
	mut needles := [subject]
	needles << docs
	jrn_erase_walk_all(mut msh, handles, subject, request, actor, authority, at, needles) or {
		return mk_err(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: the self-heal walk failed — resubmit erase-subject: ${err.msg()}')
	}
	keys := idem_matching_keys(env, needles)
	idem_drop_keys(mut env, keys)
	return cx.Node(cx.Element{
		name:  'deduped'
		items: [cx.Node(report)]
	})
}

// jrn_segment_disposed implements the internal 'journal-segment-disposed'
// builtin: the retention layer records its disposition on the segment index
// (archived-to=<url> after a clone; disposed=true after an archive="none"
// drop) so the index stays TRUTHFUL — the erase walk follows it (§7
// "archived predecessors, archive= stores"). Returns whether a segment row
// matched.
fn jrn_segment_disposed(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: segment-disposed expects (journal, sealed-store-url, disposition)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	sealed_url := jrn_arg_str(args[1]) or { '' }
	disposition := jrn_arg_str(args[2]) or { '' }
	if sealed_url == '' || disposition == '' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: segment-disposed needs the sealed store URL and a disposition (`none` or the archive URL)')
	}
	segs := jrn_read_segment_index(j.store_id, j.tenant)
	mut out := []cx.Node{}
	mut touched := false
	for s in segs {
		if s is cx.Element && s.attr('store') == sealed_url {
			mut attrs := []cx.Attribute{}
			for a in s.attrs {
				if a.name == 'disposed' || a.name == 'archived-to' {
					continue
				}
				attrs << a
			}
			if disposition == 'none' {
				attrs << cx.Attribute{
					name:  'disposed'
					value: cx.ScalarValue(true)
				}
			} else {
				attrs << cx.Attribute{
					name:  'archived-to'
					value: cx.ScalarValue(disposition)
				}
			}
			out << cx.Node(cx.Element{
				name:  'segment'
				attrs: attrs
				items: s.items
			})
			touched = true
			continue
		}
		out << s
	}
	if !touched {
		return jrn_bool(false)
	}
	if e := jrn_set_meta_alias(j.store_id, jrn_segments_alias(j.tenant), cx.Element{
		name:  'journal-segments'
		items: out
	})
	{
		return jrn_err_caused(jrn_err_open_failed, 'E_JOURNAL_OPEN_FAILED: segment-index disposition write failed',
			e)
	}
	return jrn_bool(true)
}
