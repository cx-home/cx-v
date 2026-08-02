@[has_globals]
module code

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
const jrn_err_stale_tail      = 'cx-err:CXER4604' // E_JOURNAL_STALE_TAIL
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

const jrn_genesis_prev = 'b3:GENESIS' // genesis sentinel prev-hash (§4.2)

const jrn_supported_algos = ['sha256', 'sha384', 'sha512', 'blake3']

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
		name:  seq_marker_name
		items: []
	}
}

fn jrn_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  seq_marker_name
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
					if v is cx.Element && (v.name == seq_marker_name || v.name == '') {
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

// jrn_handle_element builds the opaque `[journal …]` handle value.
fn jrn_handle_element(id int, j &Journal) cx.Node {
	return cx.Element{
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
		return node
	}
	dhash := jrn_store_get_alias(j.store_id, jrn_entry_alias_s(j.tenant, stream, seq)) or {
		return none
	}
	text := jrn_store_get_doc_text(j.store_id, dhash) or { return none }
	e := jrn_parse_entry(text) or { return none }
	return cx.Node(e)
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

fn jrn_canonical_bytes(seq int, tenant string, stream string, actor string, authority string, ts string, prev_hash string, event cx.Node) string {
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
	rec := cx.Element{
		name:  'entry-canonical'
		attrs: attrs
		items: [event]
	}
	return render_canonical(rec)
}

fn jrn_algo_tag(algo string) string {
	return match algo {
		'blake3' { 'b3' }
		else { algo }
	}
}

fn jrn_compute_hash(algo string, canonical string) ?string {
	// Route to the REAL per-algo digest (§4.2). A prior tier hashed every
	// algo with sha256 and merely re-labelled it, so sha256/sha384/sha512/
	// blake3 produced byte-identical 64-hex digests — the algorithm choice
	// was cosmetic and tamper-evidence under a "stronger" algo was a lie.
	// Now sha512 really is a 128-hex SHA-512 of the canonical bytes, etc.
	// sha256 stays byte-identical to the previous value (cx_text_hash), so
	// existing sha256 chains/fixtures are unaffected.
	digest := cx.cx_text_hash_algo(canonical, algo) or { return none }
	return jrn_algo_tag(algo) + ':' + digest
}

// ── building / parsing the [entry] value ──────────────────────────────────

fn jrn_build_entry(seq int, tenant string, stream string, actor string, authority string, ts string, prev_hash string, hash string, event cx.Node) cx.Node {
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
			name:  'hash'
			value: cx.ScalarValue(hash)
		},
	]
	return cx.Element{
		name:  'entry'
		attrs: attrs
		items: [
			cx.Element{
				name:  'event'
				items: [event]
			},
		]
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
	return cx.Node(e)
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
	// Synthetic monotonic UTC: a fixed epoch plus seq seconds. Deterministic,
	// monotonic non-decreasing with seq, and capability-free.
	secs := seq
	mm := (secs / 60) % 60
	ss := secs % 60
	hh := (secs / 3600) % 24
	return 'epoch:${hh:02}:${mm:02}:${ss:02}'
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
		'journal-head' {
			return jrn_head(args)
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
		'journal-snapshot-verify' {
			return jrn_snapshot_verify(args)
		}
		'journal-retain' {
			return jrn_retain(args)
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
	mut algo := jrn_map_get(opts, 'hash-algo') or { 'sha256' }
	if algo == '' {
		algo = 'sha256'
	}
	if algo !in jrn_supported_algos {
		return mk_err(jrn_err_hash_unsupported, 'E_JOURNAL_HASH_UNSUPPORTED: unknown hash-algo "${algo}"')
	}
	read_only := (jrn_map_get(opts, 'read-only') or { 'false' }) == 'true'
	create := (jrn_map_get(opts, 'create') or { 'true' }) != 'false'

	// Open the underlying store (gated by store's capability model — CXER0271
	// at the store effect point; mem:// is free). A read-only journal opens the
	// store read-only.
	store_open_name := if read_only { 'store-open-opts' } else { 'store-open' }
	store_res := if read_only {
		ro_opts := cx.Element{
			name:  'map'
			attrs: [cx.Attribute{
				name:  'read-only'
				value: cx.ScalarValue('true')
			}]
		}
		store_stdlib_builtin(store_open_name, [args[0], ro_opts]) or {
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
	mut algo := jrn_map_get(opts, 'hash-algo') or { 'sha256' }
	if algo == '' {
		algo = 'sha256'
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
	// Optimistic-concurrency check (§3.2), per stream: expect-prev-seq must equal
	// the target stream's head_seq.
	if jrn_map_has(attribution, 'expect-prev-seq') {
		expect := jrn_map_get_int(attribution, 'expect-prev-seq') or { -1 }
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
	canonical := jrn_canonical_bytes(seq, j.tenant, stream, actor, authority, ts, prev_hash,
		event)
	hash := jrn_compute_hash(j.hash_algo, canonical) or {
		store_flush_release(mut msh) or {}
		return mk_err(jrn_err_event_unser, 'E_JOURNAL_EVENT_UNSERIALIZABLE: cannot hash event at seq ${seq}')
	}
	entry := jrn_build_entry(seq, j.tenant, stream, actor, authority, ts, prev_hash, hash,
		event)
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
		return jrn_state_entry_node(st, seq) or { return jrn_empty() }
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
	items := if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		jrn_state_collect_range_of(j, stream, st, from, to)
	} else {
		jrn_collect_range(j, from, to)
	}
	if items.len == 0 {
		return jrn_empty() // empty window → absence (§2.5)
	}
	return jrn_seq(items)
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
	items := if !jrn_is_default(stream) {
		st := j.named[stream] or { return jrn_empty() }
		jrn_state_collect_range_of(j, stream, st, from, st.head_seq)
	} else {
		jrn_collect_range(j, from, j.head_seq)
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

// jrn_query filters entries whose [event …] payload matches a CXPath element-
// name step (the mem:// store query subset, §3.3/§9). Returns matching entries
// in seq order; empty when none match.
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
	mut descendant := false
	mut target := path_text
	if target.starts_with('//') {
		descendant = true
		target = target[2..]
	} else if target.starts_with('/') {
		target = target[1..]
	}
	// Strip a trailing predicate `[...]` — match on the element-name step only
	// for the mem:// subset (`/event/do[...]` → match docs whose event subtree
	// contains a `do`). Take the LAST name step.
	if bi := target.index('[') {
		target = target[..bi]
	}
	steps := target.split('/')
	leaf := if steps.len > 0 { steps[steps.len - 1] } else { target }
	mut items := []cx.Node{}
	for s in 1 .. j.head_seq + 1 {
		node := jrn_entry_node(j, s) or { continue }
		if node is cx.Element {
			event := jrn_entry_event(node)
			mut matches := []cx.Node{}
			jrn_collect_by_name(event, leaf, true || descendant, mut matches)
			// also allow the event payload's own head to match
			if event is cx.Element {
				if event.name == leaf {
					matches << event
				}
			}
			if matches.len > 0 {
				items << node
			}
		}
	}
	if items.len == 0 {
		return jrn_empty()
	}
	return jrn_seq(items)
}

fn jrn_collect_by_name(node cx.Node, target string, descendant bool, mut out []cx.Node) {
	if node is cx.Element {
		for child in node.items {
			if child is cx.Element {
				if child.name == target {
					out << child
				}
			}
			if descendant {
				jrn_collect_by_name(child, target, descendant, mut out)
			}
		}
	}
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
		event := jrn_entry_event(e)
		canonical := jrn_canonical_bytes(got_seq, jrn_entry_attr(e, 'tenant'),
			jrn_entry_attr(e, 'stream'), jrn_entry_attr(e, 'actor'),
			jrn_entry_attr(e, 'authority'), jrn_entry_attr(e, 'ts'), got_prev, event)
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
		event := jrn_entry_event(e)
		canonical := jrn_canonical_bytes(got_seq, jrn_entry_attr(e, 'tenant'),
			jrn_entry_attr(e, 'stream'), jrn_entry_attr(e, 'actor'),
			jrn_entry_attr(e, 'authority'), jrn_entry_attr(e, 'ts'), got_prev, event)
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
		return jrn_walk_verify_state(st, j.hash_algo, sfrom, sto, sanchor)
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
	return jrn_walk_verify(j, from, to, anchor)
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
	return jrn_walk_verify(j, from, to, anchor)
}

// ── snapshot machinery (shared between env + env-free verbs) ───────────────

// jrn_snapshot_canonical builds the signed bytes: (state + at-seq + anchor +
// algo) canonical.
fn jrn_snapshot_canonical(state cx.Node, at_seq int, stream string, anchor string, algo string) string {
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

// jrn_build_snapshot builds the [snapshot …] value.
fn jrn_build_snapshot(tenant string, at_seq int, stream string, anchor string, algo string, signed bool, sig_hex string, pub_hex string, state cx.Node) cx.Node {
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
		// unsigned: anchor-only validity, a valid=true caveat (§3.7).
		return true, 'unsigned'
	}
	state := jrn_snapshot_state(snap)
	canonical := jrn_snapshot_canonical(state, at_seq, stream, anchor, algo)
	sig_hex := jrn_snapshot_attr(snap, 'signature')
	pub_hex := jrn_snapshot_attr(snap, 'verify-key')
	pub_bytes := jrn_hex_to_bytes(pub_hex) or { return false, 'signature-invalid' }
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
	at_seq := jrn_snapshot_attr(snap, 'at-seq').int()
	valid, reason := jrn_snapshot_check(j, snap)
	return jrn_snapshot_verification(valid, reason, at_seq)
}

// ── retention ──────────────────────────────────────────────────────────────

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
	} else if _ := jrn_map_get(policy, 'keep-after-time') {
		// time-based retention maps to a seq boundary via the entry ts; for the
		// hermetic tier this is treated as keep-all unless a snapshot covers it.
		boundary = 0
	} else {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: policy needs keep-after-seq / keep-N / keep-after-time')
	}
	if boundary > head {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: prune boundary ${boundary} beyond head ${head}')
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
	seg_res := jrn_open([jrn_str(target), jrn_str(j.tenant), cx.Element{ name: 'map' }]) or {
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
					j.hash_algo)
				sig_hex := jrn_sign(canonical, seed) or {
					return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: rotation-cover signing failed (stream ${stream})')
				}
				pub_hex := jrn_derive_pub(seed) or { '' }
				sb := jrn_build_snapshot(j.tenant, boundary, stream, anchor, j.hash_algo,
					true, sig_hex, pub_hex, cover_state)
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
				name:  map_marker_name
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
	// Open the new segment store + journal (a fresh tenant chain).
	seg_res := jrn_open([jrn_str(target), jrn_str(j.tenant), cx.Element{ name: 'map' }]) or {
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
		'journal-fold-from' {
			return jrn_fold_from(args, mut env)
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
fn jrn_fold_state_entries(st &StreamState, from int, to int, init cx.Node, fv cx.Node, mut env MatchEnv) cx.Node {
	mut acc := init
	for entry in jrn_state_collect_range(st, from, to) {
		acc = apply_fn_value(fv, [acc, entry], mut env) or { return err_to_node(err) }
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
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return init } // empty/unknown stream → fold of nothing = init
		return jrn_fold_state_entries(st, 1, st.head_seq, init, fv, mut env)
	}
	return jrn_fold_entries(j, 1, j.head_seq, init, fv, mut env)
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
		return jrn_fold_state_entries(st, from, to, init, fv, mut env)
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
	stream := jrn_map_get(opts, 'stream') or { '' }
	if !jrn_is_default(stream) {
		st := j.named[stream] or { return init }
		mut sfrom := jrn_map_get_int(opts, 'from') or { 1 }
		mut sto := jrn_map_get_int(opts, 'to') or { st.head_seq }
		if at := jrn_map_get_int(opts, 'at-seq') {
			sfrom = 1
			sto = at
		}
		if sto > st.head_seq || sfrom < 1 {
			return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: replay [${sfrom}..${sto}] beyond stream head ${st.head_seq}')
		}
		return jrn_fold_state_entries(st, sfrom, sto, init, fv, mut env)
	}
	mut from := jrn_map_get_int(opts, 'from') or { 1 }
	mut to := jrn_map_get_int(opts, 'to') or { j.head_seq }
	if at := jrn_map_get_int(opts, 'at-seq') {
		from = 1
		to = at
	}
	if to > j.head_seq || from < 1 {
		return mk_err(jrn_err_seq_out_range, 'E_JOURNAL_SEQ_OUT_OF_RANGE: replay [${from}..${to}] beyond head ${j.head_seq}')
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
	canonical := jrn_canonical_bytes(seq, j.tenant, '', actor, authority, ts, prev_hash, event)
	hash := jrn_compute_hash(j.hash_algo, canonical) or {
		return mk_err(jrn_err_event_unser, 'E_JOURNAL_EVENT_UNSERIALIZABLE')
	}
	provisional := jrn_build_entry(seq, j.tenant, '', actor, authority, ts, prev_hash, hash, event)
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
	state := if is_def_snap {
		jrn_fold_entries(j, 1, at_seq, init, fv, mut env)
	} else {
		st := j.named[stream] or { &StreamState{} }
		jrn_fold_state_entries(st, 1, at_seq, init, fv, mut env)
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
	if sign_off {
		return jrn_build_snapshot(j.tenant, at_seq, stream, anchor, j.hash_algo, false, '',
			'', state)
	}
	seed := jrn_hex_to_bytes(key_hex) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: signing-key must be hex')
	}
	canonical := jrn_snapshot_canonical(state, at_seq, stream, anchor, j.hash_algo)
	sig_hex := jrn_sign(canonical, seed) or {
		return mk_err(jrn_err_snap_sig, 'E_JOURNAL_SNAPSHOT_SIG_INVALID: signing failed')
	}
	// derive the verify key from the seed via crypto keypair-from-seed: the
	// ed25519 public key is the seed's derived public. We re-derive by signing
	// a known value is not enough; instead persist the supplied public via
	// opts.verify-key if provided, else derive from the seed.
	pub_hex := jrn_map_get(opts, 'verify-key') or { jrn_derive_pub(seed) or { '' } }
	return jrn_build_snapshot(j.tenant, at_seq, stream, anchor, j.hash_algo, true, sig_hex,
		pub_hex, state)
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
		return jrn_fold_state_entries(st, at_seq + 1, st.head_seq, state, fv, mut env)
	}
	return jrn_fold_entries(j, at_seq + 1, j.head_seq, state, fv, mut env)
}

// ── bundled module source ──────────────────────────────────────────────────
//
// The canonical cx-stdlib/journal surface. Bodies forward to the native
// primitives above. The $fn-taking verbs forward to `journal-*` names reached
// via the eval.v env-hook (journal_stdlib_builtin_env); the rest reach the
// env-free journal_stdlib_builtin chain.

const stdlib_src_journal = $embed_file('../stdlib/journal.cx').to_string()
