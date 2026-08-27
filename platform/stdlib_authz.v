@[has_globals]
module platform
import code {
	decode_datetime,
	is_err_value,
	mk_err,
}

import cx
import sync

// stdlib_authz.v — native primitives + in-process trust state for the
// `cx-stdlib/authz` authorization module: principals, capabilities,
// attenuating/time-bounded/revocable delegations, guardian grants behind an
// incapacity-typed `[gate …]`, the signed+versioned incapacity-predicate
// library, and the single PEP decision function `check`/`authorize`
// (spec/02-working/stdlib_authz.md).
//
// authz is the DECISION layer (Tier-B). It COMPOSES the shipped modules and
// adds NO crypto, NO transport, NO session, and NO new `caps`-capability of
// its own (§0/§1/§5):
//   - signature/tier verification is delegated to cx-stdlib/crypto;
//   - the (principal, tenant) actor identity comes from cx-stdlib/session;
//   - persistence/attribution is cx-stdlib/journal + cx-stdlib/store.
// Its only effects are reads/writes of trust state, gated by store's existing
// capability model — so, like journal/session, authz adds NO effect_alignment
// entry. For the hermetic in-memory store (the conformance posture) it is
// capability-free, mirroring journal's mem:// / session's registry.
//
// ── FOUR-CHANNEL MODEL (SAP §1, spec §2.4/§2.5) ─────────────────────────
//   a decision           → a present [permit]/[deny] VALUE (value channel);
//                          a [deny] carries cx-err:CXER4700 as DATA, it is NOT
//                          an [err]. `check` is TOTAL — always permit or deny.
//   a genuine fault       → [err] (malformed grant, bright-line violation,
//                          signature/tier failure, unknown predicate, store
//                          fault): the decision could not be computed.
//   an absent delegation  → the absence channel (empty node-set ()): a
//                          revoked/expired/never-issued grant. NOT null, NOT a
//                          [deny]. `null` is NEVER produced by any authz verb.
//
// ── FAIL-CLOSED (§4) ─────────────────────────────────────────────────────
//   deny by default. The absence of a matching, unrevoked, unexpired,
//   attenuating, principal-rooted grant of THIS capability over a slice that
//   COVERS the request, in THIS tenant, at the required tier (and, for a
//   guardian grant, with its incapacity gate holding) → [deny]. Any ambiguity
//   denies. A guardian grant permits ONLY while its gate holds and ONLY its
//   pinned [action …] — the instant the principal re-engages (the gate's
//   incapacity predicate becomes false) `check` flips to [deny] with no
//   explicit revoke (falsifiable-by-presence, §4.4 invariant 3).
//
// ── BRIGHT LINE as a TYPE CONSTRAINT (§4.4, the most load-bearing thing) ──
//   a guardian [gate …] admits ONLY `incapacity` (signed-library name@version)
//   and `state` (CXPath threshold) leaves. A leaf branching on a principal's
//   CHOICE (declined/refused/consent/agrees/…) is rejected at AUTHORING with
//   CXER4701 — a refusal-triggered grant is NOT a value this language can
//   produce. A gate needs ≥1 incapacity (a state-only gate could fire while
//   the principal is present and declining) → else CXER4702.
//
// ── ERROR BAND CXER4700–4799 (§8) ────────────────────────────────────────
//   4700 UNAUTHORIZED (carried as data in every [deny]; RAISED only under
//   authorize raise-on-deny=true) / 4701 REFUSAL_TRIGGER / 4702 GATE_ILLFORMED
//   / 4703 ESCALATION / 4704 VERIFY_FAILED / 4705 EXPIRED (hard-failure dual)
//   / 4706 UNKNOWN_PREDICATE / 4707 REVOKED (dual) / 4708 TENANT_MISMATCH
//   (dual) / 4709 NO_RELATIONSHIP (dual) / 4710 STORE_FAULT / 4711 ARG_INVALID
//   / 4712 HANDLE_CLOSED. Cancellation = core CXER0260; `caps` denial = core
//   CXER0271 (both inherited, never authz codes).

// ── error band CXER4700–4799 (§8) ────────────────────────────────────────
const authz_err_unauthorized   = 'cx-err:CXER4700' // E_AUTHZ_UNAUTHORIZED
const authz_err_refusal_trigger = 'cx-err:CXER4701' // E_AUTHZ_REFUSAL_TRIGGER
const authz_err_gate_illformed = 'cx-err:CXER4702' // E_AUTHZ_GATE_ILLFORMED
const authz_err_escalation     = 'cx-err:CXER4703' // E_AUTHZ_ESCALATION
const authz_err_verify_failed  = 'cx-err:CXER4704' // E_AUTHZ_VERIFY_FAILED
const authz_err_expired        = 'cx-err:CXER4705' // E_AUTHZ_EXPIRED
const authz_err_unknown_pred   = 'cx-err:CXER4706' // E_AUTHZ_UNKNOWN_PREDICATE
const authz_err_revoked        = 'cx-err:CXER4707' // E_AUTHZ_REVOKED
const authz_err_tenant_mismatch = 'cx-err:CXER4708' // E_AUTHZ_TENANT_MISMATCH
const authz_err_no_relationship = 'cx-err:CXER4709' // E_AUTHZ_NO_RELATIONSHIP
const authz_err_store_fault    = 'cx-err:CXER4710' // E_AUTHZ_STORE_FAULT
const authz_err_arg_invalid    = 'cx-err:CXER4711' // E_AUTHZ_ARG_INVALID
const authz_err_handle_closed  = 'cx-err:CXER4712' // E_AUTHZ_HANDLE_CLOSED
const authz_err_budget         = 'cx-err:CXER4713' // E_AUTHZ_BUDGET_EXHAUSTED (§2.2 bounds)
const authz_err_proposal       = 'cx-err:CXER4714' // E_AUTHZ_PROPOSAL_INVALID (§3.9 — address/version/tier/divergence)
const authz_err_propose_only   = 'cx-err:CXER4715' // E_AUTHZ_PROPOSE_ONLY (§3.9 — a propose-only basis can never ground a commit)
const authz_err_cap_unresolved = 'cx-err:CXER4716' // E_AUTHZ_CAP_UNRESOLVED (§3.9 — a cap: trust input that cannot be proven live)

// The set of leaf names that branch on a principal's CHOICE — the bright
// line. Any of these as a gate leaf → CXER4701 at authoring (§2.2/§4.4).
const authz_refusal_leaves = ['declined', 'refused', 'consent', 'agrees',
	'agree', 'consents', 'approval', 'approves', 'rejects', 'opts-out',
	'opts-in', 'choice', 'willing', 'unwilling']

// The six initial signed incapacity predicates (§2.3 / §10.8). Each ships with
// its required-params schema, will-independence rationale, attested signal
// note, and (in a real deployment) a crypto signature. The bundled library is
// versioned as a whole; each predicate is referenced as `name@version`.
struct AuthzPredicate {
	name      string
	version   string
	params    []string // required param atom names (without leading colon)
	rationale string
	attested  bool   // physiological/safety → requires an attested signal source
}

const authz_library_version = 'v1'

const authz_bundled_predicates = [
	AuthzPredicate{
		name:      'no-ack-within'
		version:   'v1'
		params:    ['duration', 'of']
		rationale: 'a request was issued and no acknowledgement arrived within the window — truth depends on the elapsed clock + the absence of an ack event, never on the principal willing it; an ack the instant it arrives makes it false'
		attested:  false
	},
	AuthzPredicate{
		name:      'unreachable'
		version:   'v1'
		params:    ['principal', 'via', 'for']
		rationale: 'all contact channels failed for a duration — observed from transport delivery failures; a single reachable channel makes it false'
		attested:  false
	},
	AuthzPredicate{
		name:      'session-lost'
		version:   'v1'
		params:    ['principal', 'for']
		rationale: 'the session dropped / heartbeat lapsed for a duration — observed from the session heartbeat log; a returning heartbeat makes it false'
		attested:  false
	},
	AuthzPredicate{
		name:      'quorum-lost'
		version:   'v1'
		params:    ['role', 'need', 'for']
		rationale: 'fewer than N of a role were reachable for a duration — observed from per-principal reachability; the Nth principal returning makes it false'
		attested:  false
	},
	AuthzPredicate{
		name:      'escalation-exhausted'
		version:   'v1'
		params:    ['chain']
		rationale: 'every tier of an escalation chain was tried and none acked — observed from the escalation log; any tier acking makes it false'
		attested:  false
	},
	AuthzPredicate{
		name:      'operator-incapacitated'
		version:   'v1'
		params:    ['signal', 'for']
		rationale: 'an attested sensor-derived incapacity persisted for a duration — derived ONLY from an attested independent signal source, never the agent\'s own judgement (no-self-assertion); the operator re-engaging makes it false'
		attested:  true
	},
]

// ── store registry (the per-tenant trust-state backend) ──────────────────
//
// An authority store is mutable in-process state (delegations issue/revoke,
// the head advances) which cannot be a pure CX value. Like stdlib_journal.v /
// stdlib_store.v, each open store is a heap AuthzStore in a process-global
// registry, referenced by an integer handle on the returned
// `[authz-store handle=N tenant=…]` element. The decision verbs (check /
// effective / dry-run / …) are PURE over a materialized snapshot of this
// state — referentially transparent, which is exactly what makes dry-run a
// deterministic regression gate (§3.4/§3.7/§10.10.4).
@[heap]
struct AuthzDelegation {
mut:
	id           string
	tenant       string
	guardian     bool   // [mode :guardian]
	from_kind    string // 'principal' | 'agent' | …
	from_id      string
	to_kind      string
	to_id        string
	capabilities []string
	over         string // the CXPath slice it is scoped to ('' = unrestricted)
	attenuates   string // parent delegation id ('' = principal-rooted)
	until_secs   i64    // resolved expiry instant (Unix secs; 0 = no expiry)
	revocable    bool
	revoked      bool
	assurance    string // 't0' | 't1' | 't2' (without leading colon)
	gate         cx.Node // the [gate …] element (guardian only)
	action       cx.Node // the pinned [action …] element (guardian only)
	signed_ok    bool    // whether the recorded signature verified at issue
	value        cx.Node // the canonicalized [delegation …] value
	// [bounds …] — the quantitative budget axis (§2.2, stream 6 L112).
	// has_bounds gates everything; absent bounds on a child = the SHARED
	// issuer meter (a pool never multiplies authority). rate is a token
	// bucket (capacity b_rate_n, refill b_rate_n per b_rate_per seconds);
	// count is monotone. spend is carried + ⊆-checked but not metered by
	// the pure decision layer (commit-point debit is the effect surface's).
	// propose-only (stream 6 W6b, L113): a grant-side attenuation flag —
	// a delegation carrying [propose-only] can ground PROPOSALS but never
	// a commit; inherited down the chain (narrowing-only; screened at
	// commit, §3.9).
	propose_only bool
	has_bounds   bool
	b_rate_n     i64
	b_rate_per   i64 // seconds; 0 = no rate conjunct
	b_count      i64 // 0 = no count conjunct
	b_spend_amt  f64
	b_spend_cur  string
	b_spend_per  i64  // seconds; 0 = no window
	b_has_spend  bool
	bounds_value cx.Node // the verbatim [bounds …] element (materialize carries it)
}

// AuthzStore is the mutable trust state a PEP decides against.
//
// ── THE SERIALIZATION POINT (#997) ──────────────────────────────────────────
// `delegations` is a plain V array, and V's `array.push` is not atomic: it
// reallocates the buffer (`ensure_cap` swaps `data` and `cap`), copies the new
// element in, and THEN bumps `len` — three unordered stores. A second thread
// appending concurrently loses appends outright (measured on two `[$xap:dial]`
// workers, 3000 each: 12 runs in 12 came back corrupt — 11 SIGSEGV inside the
// evaluator, 1 surviving with 42 grants of 6000 silently absent), and a thread
// WALKING the array while another appends can read a slot past the old buffer
// or one whose element store is not yet visible — a garbage `&AuthzDelegation`
// that the decision then dereferences. So a store's basis must never grow in
// place while anything can be reading it, and there are three tiers that hold
// one:
//
//   XAP RUNTIME (`XapRuntime.authz`, stdlib_xap.v) — `authz_grants_lock`, the
//     rwmutex below. A live `[$xap:dial]` / `[$xap:revoke]` /
//     `[$xap:pkg-enable]` runs under its WRITE lock; every PEP decision
//     (xap_pep_admits, xap_why_allowed) and every `rt.dials` walk runs under
//     its READ lock. That is the pair #997 names: a running §3.1.2 source pump
//     decides on its own thread while a deployment worker dials on another,
//     and a torn DENY there is skip-and-ack — an entry dropped permanently.
//     Concurrent decisions still run in parallel; only a dial excludes them.
//
//   XSP STORE (`SxConn.authz`, store_xsp_authority.v) — `srv.mu`, the
//     listener's one serialization point (#986): every PEP decision runs under
//     it (sx_conn_reader holds it across sx_dispatch_locked), so a grant
//     re-fold taken under the same lock is atomic against every in-flight
//     verb. Its mutations ALSO go through the helpers below — redundant there,
//     and kept so that no tier can reintroduce an in-place append.
//
//   `[authz-store]` REGISTRY (the CX authz verbs) — writes serialized by the
//     helpers below, reads bracketed as of #1024. The 19 verb entry points that
//     reach `authz_store_from_arg` were classified by hand (the table on
//     authz_grants_rlock names every one) into three sets, because the naive
//     whole-verb read bracket self-deadlocks: a pthread rwlock does not upgrade,
//     and four of these verbs re-enter the authz verb table or the evaluator
//     from inside what would have been the bracket.
//
// Every mutation of the `delegations` ARRAY goes through authz_grants_append /
// authz_grants_append_many / authz_grants_set — enforced by the guard in
// vcx/tests/xap_umbrella_test.v, because a new `<<` site is exactly how this
// discipline would rot back out. Flipping `revoked` on a delegation ALREADY in
// the basis is not an array mutation and carries none of the tearing class
// (revocation is absence, §2.5 — the row stays), but it goes through
// authz_grants_mark_revoked anyway so the flip is one act with everything else a
// revoking caller does — #1024 closed the registry tier's last two bare in-place
// `revoked = true` sites (authz_revoke_impl and the replay path).
//
// Every READ WALK of the array is bracketed too, as of #1024, and that roster is
// pinned by NAME by a second guard in the same file. authz_revoke_cascade is no
// longer the exception #997 recorded: it journals per link and recurses, so it
// still holds no lock across its body, but it now collects each LEVEL's children
// under one read bracket and applies them after the release.
@[heap]
struct AuthzStore {
mut:
	tenant      string
	is_open     bool
	delegations []&AuthzDelegation // in receive order
	// Durable tier (#713 item 4, stream 6 W3 — R6/R7/R8): when a
	// journal handle is bound via `store opts.journal` (§3.1), every
	// persisting verb appends the §2.6 attributed event to the named
	// `authz` stream BEFORE mutating in-process state (journal-first,
	// fail-closed — CXER4710 on fault, mutation not applied), and a
	// fresh `store {tenant, journal}` REPLAYS the stream to rebuild
	// trust state — the persisted-grant-then-reopen path. No journal
	// bound = the in-process tier, unchanged.
	has_journal    bool
	journal_handle cx.Node
}

// authz_journal_stream is the named journal stream authority transitions
// ride (W3 R8): [authz-issued <delegation>] / [authz-revoked id=…].
const authz_journal_stream = 'authz'

@[heap]
struct AuthzRegistry {
mut:
	stores  map[int]&AuthzStore
	next_id int
}

__global (
	g_authz_reg voidptr
	// #997: the authority-basis serialization point — see the AuthzStore doc
	// comment for which tier uses it and why the other two do not read through
	// it. REFERENCE-typed and allocated in authz_init_globals(): a value-typed
	// zeroed sync.RwMutex global is a silently non-locking pthread rwlock on
	// Darwin, the identical defect #303 hit on the SSE registries — a lock that
	// does not lock would leave this file's whole discipline vacuous.
	authz_grants_lock &sync.RwMutex
)

// authz_init_globals allocates this file's real reference mutex. Called from
// the platform module's init() (platform_init.v), before any thread exists.
fn authz_init_globals() {
	authz_grants_lock = sync.new_rwmutex()
}

// ── authority-basis mutation (#997) ─────────────────────────────────────────
//
// The ONLY four ways a store's delegation basis changes. Each is a leaf call —
// nothing inside takes another lock — so a caller already holding srv.mu (the
// XSP tier) cannot deadlock against a caller holding nothing (the XAP tier).

// authz_grants_append adds one delegation to a store's basis.
fn authz_grants_append(mut s AuthzStore, d &AuthzDelegation) {
	authz_grants_lock.lock()
	s.delegations << d
	authz_grants_lock.unlock()
}

// authz_grants_append_many adds several delegations as ONE act — a caller that
// seats a whole table (the XSP tier's config roots) must not publish it half
// applied.
fn authz_grants_append_many(mut s AuthzStore, ds []&AuthzDelegation) {
	authz_grants_lock.lock()
	for d in ds {
		s.delegations << d
	}
	authz_grants_lock.unlock()
}

// authz_grants_set replaces a store's basis wholesale — the drop half of a
// re-fold (revoked VCs, superseded config roots).
fn authz_grants_set(mut s AuthzStore, rows []&AuthzDelegation) {
	authz_grants_lock.lock()
	s.delegations = rows
	authz_grants_lock.unlock()
}

// authz_grants_mark_revoked flips `revoked` on every live delegation carrying
// `id` and reports whether it found one. Revocation is ABSENCE (§2.5) — the row
// stays in the basis, so this mutates no array; it takes the write lock anyway
// so a concurrent reader sees the flag flip as one act with everything else a
// revoking caller does.
fn authz_grants_mark_revoked(mut s AuthzStore, id string) bool {
	authz_grants_lock.lock()
	mut found := false
	for mut d in s.delegations {
		if d.id == id && !d.revoked {
			d.revoked = true
			found = true
		}
	}
	authz_grants_lock.unlock()
	return found
}

// authz_grants_rlock / authz_grants_runlock bracket a READ WALK of a store's
// basis (a PEP decision, a `rt.dials` chain render). Concurrent readers proceed
// in parallel; a dial excludes them. NEVER call a write helper inside the
// bracket — a pthread rwlock does not upgrade, so that self-deadlocks.
//
// ── THE REGISTRY TIER'S READ BRACKETS (#1024) ───────────────────────────────
//
// THE FACT THAT MAKES THIS TRACTABLE. `delegations` is `[]&AuthzDelegation` —
// heap POINTERS. What tears is the ARRAY (ensure_cap swaps data/cap, the
// element is copied, len is bumped last), never the records: a delegation is
// immutable once installed except for its `revoked` flag, and it never moves.
// So a `&AuthzDelegation` obtained under a bracket stays a valid, stable object
// after the bracket releases, and a verb may carry one out of its bracket and
// keep reading it. That is why a bracket only has to cover the WALK, and never
// has to cover the journal I/O or the decision a walk feeds.
//
// THE THREE SETS, by hand over the 19 verbs reaching authz_store_from_arg:
//
//   BASIS-UNTOUCHED (4) — no bracket, because there is nothing to bracket.
//     `close` (flips is_open, not the basis), `verify-tier` and `approve` (both
//     resolve the handle for the tenant partition and then `_ = s`),
//     `allocation-expire` (folds the JOURNAL's allocation state; never reads
//     `delegations`).
//
//   BASIS READ-ONLY (12) — bracketed. `check` / `authorize` / `dry-run` (one
//     entry point, authz_check_impl), `find`, `grants-of`, `effective`,
//     `trace`, `resolve-cap` are pure basis reads with no I/O and no re-entry,
//     so the bracket is the WHOLE verb: those get a consistent snapshot, not
//     merely a safe one. `meters`, `allocate`, `debit` and `commit` are
//     read-only ON THE BASIS but write the JOURNAL and/or re-enter — see below.
//
//   BASIS READ-THEN-WRITE (3) — `delegate`, `grant-guardian`, `revoke`. These
//     are the ones a whole-verb read bracket would have deadlocked. They are
//     restructured read-then-decide-then-write instead of taking the write lock
//     for the whole verb, because the write lock would then be held across the
//     journal append — an fsync — serializing every PEP decision in the process
//     behind disk I/O, and creating an authz→journal lock order where today
//     authz_grants_lock is a leaf. Soundness of releasing between the read and
//     the write: the only mutation a concurrent thread can make to a record the
//     read phase examined is `revoked = true` (records are otherwise immutable
//     and the array only grows), and a revoked ancestor fails the chain walk at
//     every subsequent DECISION (authz_chain_to_principal, §2.5/§4.1). So a
//     stale attenuation verdict cannot convey authority — it can only install a
//     grant that then denies. The append itself stays atomic (the helpers).
//
// WHY FOUR VERBS ARE BRACKETED BY REGION AND NOT WHOLE (the deadlock set):
//   `meters` / `allocate` / `debit` fold the journal (jrn_* + a journal APPEND)
//     around their basis walks. A bracket spanning that would hold a read lock
//     across journal I/O and, on `debit`, across authz_journal_append.
//   `commit` is the sharp one: inside the body it calls authz_resolve_cap_impl
//     and authz_debit_impl — other VERBS, each with its own bracket — and then
//     code.command_commit_execute, which runs arbitrary CX and can therefore
//     re-enter ANY authz verb including `delegate`. A whole-verb bracket there
//     self-deadlocks on the nested read and deadlocks outright on the nested
//     write. Its one basis read (authz_chain_propose_only) is bracketed alone.
//
// THE RULE THAT KEEPS THIS DEADLOCK-FREE, and what the standing guard in
// vcx/tests/xap_umbrella_test.v pins:
//   (1) brackets live at VERB entry points (or a straight-line region inside
//       one) — never inside a helper, so brackets cannot nest;
//   (2) no read helper takes the lock: authz_find_rec, authz_decide,
//       authz_effective_set, authz_effective_intersect, authz_has_relationship,
//       authz_attenuation_ok, authz_nearest_bounds, authz_inherit_window,
//       authz_chain_to_principal, authz_chain_propose_only, authz_budget_check
//       and authz_meter_fold all read under the CALLER's bracket;
//   (3) no bracket encloses a jrn_*, an authz_journal_append, another
//       authz_*_impl, or a code.command_* call.
// Together: no thread holds this lock while acquiring it again (no self-
// deadlock), and no thread holds it while acquiring any OTHER lock, so it
// remains a leaf and can participate in no cycle (no deadlock at all).
@[inline]
fn authz_grants_rlock() {
	authz_grants_lock.rlock()
}

@[inline]
fn authz_grants_runlock() {
	authz_grants_lock.runlock()
}

// authz_reset_state clears the process-global authority-store registry.
// Called from matcher.v::new_env at the start of each evaluated program so
// the trust state (delegations / guardian grants) never leaks across
// independent programs — the same per-program reset prof/session use.
pub fn authz_reset_state() {
	if g_authz_reg == unsafe { nil } {
		return
	}
	mut reg := unsafe { &AuthzRegistry(g_authz_reg) }
	reg.stores = map[int]&AuthzStore{}
	reg.next_id = 0
}

fn authz_reg() &AuthzRegistry {
	if g_authz_reg == unsafe { nil } {
		r := &AuthzRegistry{
			stores: map[int]&AuthzStore{}
		}
		g_authz_reg = voidptr(r)
	}
	return unsafe { &AuthzRegistry(g_authz_reg) }
}

fn authz_register(s &AuthzStore) int {
	mut reg := authz_reg()
	reg.next_id++
	id := reg.next_id
	reg.stores[id] = s
	return id
}

fn authz_lookup(id int) ?&AuthzStore {
	reg := authz_reg()
	return reg.stores[id] or { return none }
}

// ── value builders ───────────────────────────────────────────────────────
fn authz_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn authz_atom(s string) cx.Node {
	// atoms store WITHOUT the leading colon (eval stores `:t1` as `t1`); the
	// renderer re-adds it.
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.atom_type
	}
}

fn authz_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn authz_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn authz_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// authz_absence is the absence channel (§2.5): an empty node-set. NOT null,
// NOT a fault — the normal "no such delegation" state.
fn authz_absence() cx.Node {
	return authz_seq([])
}

fn authz_str_attr(name string, s string) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(s), cx.AttributeMeta{})
}

fn authz_kv(name string, v cx.Node) cx.Node {
	return cx.Element{
		name:  name
		items: [v]
	}
}

// ── argument readers ───────────────────────────────────────────────────────
fn authz_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			string { return v }
			i64 { return v.str() }
			f64 { return v.str() }
			bool { return v.str() }
			else { return none }
		}
	}
	return none
}

fn authz_opts(n cx.Node) map[string]cx.Node {
	mut m := map[string]cx.Node{}
	if n is cx.Element && n.name == '__cx_map__' {
		for e in n.items {
			if e is cx.Element && e.items.len > 0 {
				m[e.name] = e.items[0]
			}
		}
	}
	return m
}

fn authz_opt_str(m map[string]cx.Node, key string, def string) string {
	n := m[key] or { return def }
	if s := authz_arg_str(n) {
		return s
	}
	return def
}

fn authz_opt_bool(m map[string]cx.Node, key string, def bool) bool {
	n := m[key] or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return def
}

fn authz_opt_node(m map[string]cx.Node, key string) ?cx.Node {
	return m[key] or { return none }
}

// authz_scalar_text reads any scalar/text node's text (atom colon stripped
// already, datetime/int as text). Element-body content barewords/quoted
// values parse as TextNode; literal-position scalars as ScalarNode — handle
// BOTH. '' for an element / non-textual node.
fn authz_scalar_text(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// authz_node_text is the same reader, used at every leading-id / first-child
// extraction site so TextNode body content is read uniformly.
fn authz_node_text(n cx.Node) string {
	return authz_scalar_text(n)
}

// authz_err_with_cause builds an [err code=… [cause …]] carrying an inherited
// fault verbatim (§2.6/§8).
fn authz_err_with_cause(err_code string, message string, cause cx.Node) cx.Node {
	mut e := mk_err(err_code, message) as cx.Element
	e.items << cx.Node(cx.Element{
		name:  'cause'
		items: [cause]
	})
	return e
}

// ── store handle materialization ───────────────────────────────────────────
fn authz_store_element(id int, s &AuthzStore) cx.Node {
	return cx.Element{
		name:  'authz-store'
		attrs: [
			authz_str_attr('handle', id.str()),
			authz_str_attr('tenant', s.tenant),
			authz_str_attr('state', if s.is_open { 'open' } else { 'closed' }),
			authz_str_attr('on-close', 'authz/close'),
		]
	}
}

// authz_store_from_arg resolves an `[authz-store handle=N …]` value back to its
// live &AuthzStore. Returns a CXER4711/4712 fault VALUE on a bad/closed handle.
fn authz_store_from_arg(arg cx.Node) !&AuthzStore {
	if arg !is cx.Element || (arg as cx.Element).name != 'authz-store' {
		return error('arg')
	}
	el := arg as cx.Element
	hs := el.attr('handle')
	if hs == '' {
		return error('arg')
	}
	id := hs.int()
	s := authz_lookup(id) or { return error('arg') }
	if !s.is_open {
		return error('closed')
	}
	return s
}

// ── datetime / duration helpers (compose cx-stdlib/time) ─────────────────────
//
// Resolve a node carrying a datetime / Unix-int / RFC-3339 string into Unix
// seconds. 0 when absent / unparseable.
fn authz_secs_of(n cx.Node) i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
	}
	if dt := decode_datetime(n) {
		return dt.instant_ns() / code.ns_per_s
	}
	return 0
}

// authz_opt_secs reads a cfg/opts key as a decision/expiry instant (Unix secs).
fn authz_opt_secs(m map[string]cx.Node, key string) i64 {
	n := m[key] or { return 0 }
	return authz_secs_of(n)
}

// ── element field extraction (parsing a [delegation …] literal) ──────────────
fn authz_child(el cx.Element, name string) ?cx.Element {
	for it in el.items {
		if it is cx.Element && it.name == name {
			return it
		}
	}
	return none
}

fn authz_children(el cx.Element, name string) []cx.Element {
	mut out := []cx.Element{}
	for it in el.items {
		if it is cx.Element && it.name == name {
			out << it
		}
	}
	return out
}

// authz_party reads a [from [principal X]] / [to [agent Y]] party wrapper into
// (kind, id). A wrapper carrying a single child element [KIND ID …] yields
// (KIND, ID); a wrapper with an `id`/named-child form is also accepted.
fn authz_party(el cx.Element, wrapper string) (string, string) {
	w := authz_child(el, wrapper) or { return '', '' }
	for it in w.items {
		if it is cx.Element {
			// [principal dana] → name='principal', first item-or-attr is the id
			id := authz_party_id(it)
			return it.name, id
		}
	}
	// inline form: [from kind=principal id=dana]
	return w.attr('kind'), w.attr('id')
}

// authz_party_id reads the principal/agent id off a [principal dana …] element:
// the `id` attr if present, else the first bareword/text item, else ''.
fn authz_party_id(el cx.Element) string {
	if v := el.attr_val('id') {
		s := cx.scalar_value_str_public(v)
		if s != '' {
			return s
		}
	}
	for it in el.items {
		t := authz_node_text(it)
		if t != '' {
			return t
		}
	}
	return ''
}

// authz_capabilities reads the [capabilities [a] [b] …] child into a name list.
fn authz_capabilities(el cx.Element) []string {
	mut out := []string{}
	caps := authz_child(el, 'capabilities') or { return out }
	for it in caps.items {
		if it is cx.Element {
			if it.name != '' {
				out << it.name
			} else if it.items.len > 0 {
				t := authz_node_text(it.items[0])
				if t != '' {
					out << t
				}
			}
		} else {
			t := authz_node_text(it)
			if t != '' {
				out << t
			}
		}
	}
	return out
}

// authz_first_arg_id reads the leading positional id of a tag like
// `[delegation d-recon-77 …]` — the `id` attr, else the element's first
// bareword child, else ''.
fn authz_leading_id(el cx.Element) string {
	if v := el.attr_val('id') {
		s := cx.scalar_value_str_public(v)
		if s != '' {
			return s
		}
	}
	for it in el.items {
		t := authz_node_text(it)
		if t != '' {
			return t
		}
		if it is cx.Element && it.items.len == 0 && it.attrs.len == 0 {
			// a bare childless element is a leading bareword (e.g. d-recon-77)
			return it.name
		}
	}
	return ''
}

// authz_assurance_of reads [assurance :tN] → 'tN' (atom colon stripped). The
// default is 't1' for delegations / guardian grants (§2.2/§2.7).
fn authz_assurance_of(el cx.Element, def string) string {
	a := authz_child(el, 'assurance') or { return def }
	for it in a.items {
		t := authz_node_text(it)
		if t != '' {
			return t.to_lower()
		}
	}
	if v := a.attr_val('tier') {
		return cx.scalar_value_str_public(v).to_lower()
	}
	return def
}

// authz_mode_is_guardian reports whether the delegation literal carries
// [mode :guardian] or a [gate …] child (either marks the guardian view, §2.2).
fn authz_mode_is_guardian(el cx.Element) bool {
	if _ := authz_child(el, 'gate') {
		return true
	}
	m := authz_child(el, 'mode') or { return false }
	for it in m.items {
		if authz_node_text(it) == 'guardian' {
			return true
		}
	}
	return false
}

// authz_tenant_of reads [tenant X] → the tenant id.
fn authz_tenant_of(el cx.Element) string {
	t := authz_child(el, 'tenant') or { return '' }
	return authz_party_id(t)
}

// authz_until_secs resolves the [until <instant>] child into Unix secs (0 = no
// expiry). Accepts a datetime scalar or a Unix-int.
fn authz_until_secs(el cx.Element) i64 {
	u := authz_child(el, 'until') or { return 0 }
	for it in u.items {
		s := authz_secs_of(it)
		if s != 0 {
			return s
		}
	}
	if v := u.attr_val('at') {
		return authz_secs_of(cx.ScalarNode{ value: v, data_type: .string_type })
	}
	return 0
}

// authz_revocable_of reads [revocable true/false]; default true (§2.2).
fn authz_revocable_of(el cx.Element) bool {
	r := authz_child(el, 'revocable') or { return true }
	for it in r.items {
		if it is cx.ScalarNode {
			v := it.value
			if v is bool {
				return v
			}
		}
		t := authz_node_text(it)
		if t == 'false' {
			return false
		}
		if t == 'true' {
			return true
		}
	}
	return true
}

// authz_over_of reads the [over /path…] scope slice → its CXPath text ('' =
// unrestricted, i.e. covers everything the issuer holds).
fn authz_over_of(el cx.Element) string {
	o := authz_child(el, 'over') or { return '' }
	for it in o.items {
		t := authz_node_text(it)
		if t != '' {
			return t
		}
	}
	if v := o.attr_val('path') {
		return cx.scalar_value_str_public(v)
	}
	return ''
}

// ── [bounds …] parsing (§2.2 — the quantitative budget child) ────────────────

// authz_dur_secs resolves a duration item: an integer is seconds; a string
// takes an s/m/h/d suffix ('90s', '1m', '2h', '1d'). 0 = unparseable.
fn authz_dur_secs(n cx.Node) i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
		if v is string {
			return authz_dur_str_secs(v)
		}
	}
	if n is cx.TextNode {
		return authz_dur_str_secs(n.value)
	}
	return 0
}

fn authz_dur_str_secs(s string) i64 {
	if s.len < 2 {
		return 0
	}
	unit := s[s.len - 1]
	num := s[..s.len - 1].i64()
	if num <= 0 {
		return 0
	}
	return match unit {
		`s` { num }
		`m` { num * 60 }
		`h` { num * 3600 }
		`d` { num * 86400 }
		else { 0 }
	}
}

// authz_parse_bounds validates a [bounds …] child into the delegation record.
// Conjunct grammar (commands_effects §4 / authz.md §2.2, verbatim):
//   [rate N :per DUR]  — token bucket, capacity N, refill N per DUR
//   [count N]          — monotone, no replenishment
//   [spend AMT::decimal :currency :CUR :per DUR] — carried + ⊆-checked; the
//                        pure decision layer never meters it (commit-point
//                        debit is the effect surface's job)
// Anything else in [bounds …] is CXER4711 — an unenforceable bound must be
// unissuable, never silently void.
fn authz_parse_bounds(el cx.Element, mut rec AuthzDelegation) ! {
	b := authz_child(el, 'bounds') or { return }
	rec.has_bounds = true
	rec.bounds_value = cx.Node(b)
	mut any := false
	for it in b.items {
		if it !is cx.Element {
			continue
		}
		c := it as cx.Element
		match c.name {
			'rate' {
				mut n := i64(0)
				mut per := i64(0)
				mut saw_per := false
				for sub in c.items {
					if sub is cx.ScalarNode && !saw_per {
						v := sub.value
						if v is i64 {
							n = v
						}
					}
					t := authz_node_text(sub)
					if saw_per {
						per = authz_dur_secs(sub)
						saw_per = false
					} else if t == 'per' {
						saw_per = true
					}
				}
				if n < 1 || per < 1 {
					return error('E_AUTHZ_ARG_INVALID: [bounds [rate …]] needs N ≥ 1 and :per DUR (§2.2)')
				}
				rec.b_rate_n = n
				rec.b_rate_per = per
				any = true
			}
			'count' {
				mut n := i64(0)
				for sub in c.items {
					if sub is cx.ScalarNode {
						v := sub.value
						if v is i64 {
							n = v
						}
					}
				}
				if n < 1 {
					return error('E_AUTHZ_ARG_INVALID: [bounds [count …]] needs N ≥ 1 (§2.2)')
				}
				rec.b_count = n
				any = true
			}
			'spend' {
				mut amt := f64(0)
				mut cur := ''
				mut per := i64(0)
				mut expect := '' // '' | 'currency' | 'per'
				for sub in c.items {
					if sub is cx.ScalarNode && expect == '' {
						// AMOUNT::decimal (§2.2): decimal-ascribed scalars
						// carry string-backed values — read through the
						// f64 view, not raw f64/i64 matching (stream-6 W4:
						// the raw match silently rejected every `100.0`
						// spend bound; authz-072/073 pin the fix).
						a := authz_node_f64(sub)
						if a > 0 {
							amt = a
						}
					}
					t := authz_node_text(sub)
					match expect {
						'currency' {
							cur = t
							expect = ''
						}
						'per' {
							per = authz_dur_secs(sub)
							expect = ''
						}
						else {
							if t == 'currency' {
								expect = 'currency'
							} else if t == 'per' {
								expect = 'per'
							}
						}
					}
				}
				if amt <= 0 || cur == '' {
					return error('E_AUTHZ_ARG_INVALID: [bounds [spend …]] needs AMOUNT > 0 and :currency :CUR (§2.2)')
				}
				rec.b_spend_amt = amt
				rec.b_spend_cur = cur
				rec.b_spend_per = per
				rec.b_has_spend = true
				any = true
			}
			else {
				return error('E_AUTHZ_ARG_INVALID: unknown [bounds …] conjunct [${c.name}] — an unenforceable bound is unissuable (§2.2)')
			}
		}
	}
	if !any {
		return error('E_AUTHZ_ARG_INVALID: [bounds …] names no conjunct (rate/count/spend, §2.2)')
	}
}

// ── slice cover (CXPath prefix containment) ──────────────────────────────────
//
// A grant scoped to `grant_slice` COVERS a request `req_slice` iff the grant is
// unrestricted ('') OR the request path is at-or-below the grant path. We use a
// conservative path-prefix containment over the structural prefix of the
// CXPath (everything up to the first predicate `[`): grant /orders covers
// /orders, /orders/9, /orders/9/lines; it does NOT cover /payments. A grant
// carrying a predicate ([?…]) covers only when its structural prefix covers AND
// the request is not strictly shallower — fail-closed: a request that cannot be
// proven covered is treated as NOT covered. (Predicate-level narrowing beyond
// the structural prefix conservatively requires the request to name the same
// or a deeper path; the predicate itself is a runtime narrowing the bus
// evaluates against state — here we never widen.)
fn authz_path_prefix(p string) string {
	idx := p.index('[') or { return p }
	return p[..idx]
}

fn authz_slice_covers(grant_slice string, req_slice string) bool {
	if grant_slice == '' {
		return true // unrestricted grant covers any slice
	}
	g := authz_path_prefix(grant_slice).trim_right('/')
	r := authz_path_prefix(req_slice).trim_right('/')
	if g == '' {
		return true
	}
	if r == '' {
		// grant is restricted but the request names no slice — fail-closed.
		return false
	}
	if g == r {
		return true
	}
	// r is at-or-below g iff r starts with g + '/'
	return r.starts_with(g + '/')
}

// ── primitive dispatch (env-free; authz has no $fn-taking verb, §3) ──────────
fn authz_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	if !name.starts_with('authz-') {
		return none
	}
	match name {
		'authz-store'           { return authz_store_impl(args) }
		'authz-close'           { return authz_close_impl(args) }
		'authz-delegate'        { return authz_delegate_impl(args) }
		'authz-revoke'          { return authz_revoke_impl(args) }
		'authz-grant-guardian'  { return authz_grant_guardian_impl(args) }
		'authz-check'           { return authz_check_impl(args, false) }
		'authz-authorize'       { return authz_check_impl(args, true) }
		'authz-find'            { return authz_find_impl(args) }
		'authz-grants-of'       { return authz_grants_of_impl(args) }
		'authz-predicate'       { return authz_predicate_impl(args) }
		'authz-predicates'      { return authz_predicates_impl(args) }
		'authz-gate-wellformed' { return authz_gate_wellformed_impl(args) }
		'authz-verify-tier'     { return authz_verify_tier_impl(args) }
		'authz-effective'       { return authz_effective_impl(args) }
		'authz-dry-run'         { return authz_dry_run_impl(args) }
		'authz-explain'         { return authz_explain_impl(args) }
		'authz-trace'           { return authz_trace_impl(args) }
		'authz-meters'          { return authz_meters_impl(args) }
		'authz-debit'           { return authz_debit_impl(args) }
		'authz-allocate'        { return authz_allocate_impl(args) }
		'authz-allocation-expire' { return authz_allocation_expire_impl(args) }
		'authz-approve'         { return authz_approve_impl(args) }
		'authz-resolve-cap'     { return authz_resolve_cap_impl(args) }
		else                    { return none }
	}
}

// ── §3.1 store / close ───────────────────────────────────────────────────────
fn authz_store_impl(args []cx.Node) cx.Node {
	cfg := if args.len > 0 { authz_opts(args[0]) } else { map[string]cx.Node{} }
	tenant := authz_opt_str(cfg, 'tenant', '')
	if tenant == '' {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: store requires a `tenant` (the hard partition, §4.6)')
	}
	mut s := &AuthzStore{
		tenant:      tenant
		is_open:     true
		delegations: []&AuthzDelegation{}
	}
	// Durable tier (W3 R6): bind + REPLAY the tenant journal when
	// opts.journal is present (§3.1 "the [$journal:…] handle grants/
	// decisions are appended to"). An unusable journal at open is the
	// store fault CXER4710 (the backend is the trust substrate).
	if jn := cfg['journal'] {
		_, errn, ok := jrn_get_open(jn)
		if !ok {
			return authz_err_with_cause(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: store opts.journal is not an open journal handle (§3.1/§5)',
				errn)
		}
		s.has_journal = true
		s.journal_handle = jn
		if fault := authz_replay_journal(mut s) {
			return fault
		}
	}
	id := authz_register(s)
	return authz_store_element(id, s)
}

// authz_replay_journal rebuilds trust state from the bound journal's
// `authz` stream (W3 R6 — the persisted-grant-then-reopen path). Replay
// applies events WITHOUT re-running issue-time validation (R7: the log
// is the authority; attenuation/gate checks ran at issue) but DOES
// re-run window inheritance (deterministic over the same fold order).
// Cross-tenant events on a shared journal are SKIPPED (the §4.6 hard
// partition: this store only sees its tenant); a malformed authz event
// is the corrupt-log store fault CXER4710. Returns the fault err VALUE,
// or none on success.
fn authz_replay_journal(mut s AuthzStore) ?cx.Node {
	mut j, errn, ok := jrn_get_open(s.journal_handle)
	if !ok {
		return authz_err_with_cause(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: bound journal unavailable at replay',
			errn)
	}
	jrn_refresh_head(mut j, authz_journal_stream)
	st := jrn_named_state(mut j, authz_journal_stream)
	entries := jrn_state_collect_range_of(j, authz_journal_stream, st, 1, st.head_seq)
	for en in entries {
		if en !is cx.Element {
			continue
		}
		ev := jrn_entry_event(en as cx.Element)
		if ev !is cx.Element {
			continue
		}
		evel := ev as cx.Element
		match evel.name {
			'authz-issued' {
				if evel.items.len != 1 || evel.items[0] !is cx.Element {
					return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: malformed authz-issued event at replay (corrupt trust log)')
				}
				del := evel.items[0] as cx.Element
				if authz_tenant_of(del) != s.tenant {
					continue // §4.6 hard partition — another tenant's grant
				}
				rec := authz_parse_delegation(evel.items[0], s.tenant, authz_mode_is_guardian(del)) or {
					return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: unparseable delegation in trust log at replay: ${err.msg()}')
				}
				// #1024: the window-inheritance read is bracketed (the append
				// takes the write lock itself). Replay runs before the handle
				// reaches CX, but the lock is process-global and a second
				// thread may be replaying its own store through it.
				mut nrec := rec
				authz_grants_rlock()
				authz_inherit_window(s, mut nrec)
				authz_grants_runlock()
				authz_grants_append(mut s, rec)
			}
			'authz-revoked' {
				id := authz_el_attr(evel, 'id')
				if id == '' {
					return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: authz-revoked event without id at replay (corrupt trust log)')
				}
				// #1024: walk + flip as ONE act under the write lock — this was
				// the other bare in-place `revoked = true` in the registry tier.
				authz_grants_mark_revoked(mut s, id)
				// unknown id: another tenant's revocation on a shared
				// journal, or an idempotent re-revoke — both skips.
			}
			else {
				// foreign event on the stream — not authz's to interpret.
			}
		}
	}
	return none
}

// authz_el_attr reads a scalar attribute by name ('' when absent).
fn authz_el_attr(el cx.Element, name string) string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

// authz_journal_append appends one §2.6 attributed authority-transition
// event to the bound journal's authz stream (W3 R7: journal-FIRST — the
// caller mutates in-process state only after this returns none).
// Returns the CXER4710 fault err VALUE on any append failure; none on
// success or when no journal is bound (the in-process tier).
fn authz_journal_append(s &AuthzStore, event cx.Node, actor string, authority string, clock string) ?cx.Node {
	if !s.has_journal {
		return none
	}
	attribution := cx.Element{
		name:  '__cx_map__'
		items: [
			cx.Node(cx.Element{
				name:  'actor'
				items: [cx.Node(jrn_str(actor))]
			}),
			cx.Node(cx.Element{
				name:  'authority'
				items: [cx.Node(jrn_str(authority))]
			}),
			cx.Node(cx.Element{
				name:  'stream'
				items: [cx.Node(jrn_str(authz_journal_stream))]
			}),
		]
	}
	mut ap_args := [s.journal_handle, event, cx.Node(attribution)]
	if clock != '' {
		// pin the entry ts (the journal's controllable-clock posture) —
		// the debit fold's time coordinate (W4 R10).
		ap_args << cx.Node(cx.Element{
			name:  '__cx_map__'
			items: [
				cx.Node(cx.Element{
					name:  'clock'
					items: [cx.Node(jrn_str(clock))]
				}),
			]
		})
	}
	res := jrn_append(ap_args) or {
		return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: trust-log append failed (§2.6); the transition was NOT applied')
	}
	if is_err_value(res) {
		return authz_err_with_cause(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: trust-log append refused (§2.6); the transition was NOT applied',
			res)
	}
	return none
}

fn authz_close_impl(args []cx.Node) cx.Node {
	// Idempotent + closeable: never raises CXER0108. A bad handle is a no-op.
	if args.len == 0 {
		return authz_null()
	}
	mut s := authz_store_from_arg(args[0]) or { return authz_null() }
	s.is_open = false
	return authz_null()
}

fn authz_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// ── delegation parsing → AuthzDelegation ─────────────────────────────────────
//
// Parse a `[delegation …]` literal into the in-process record. `want_guardian`
// asserts the guardian/ordinary shape (§7 footnotes 1/2). Returns the record or
// a CXER4711 fault VALUE.
fn authz_parse_delegation(arg cx.Node, store_tenant string, want_guardian bool) !&AuthzDelegation {
	if arg !is cx.Element || (arg as cx.Element).name != 'delegation' {
		return error('E_AUTHZ_ARG_INVALID: expected a [delegation …] value')
	}
	el := arg as cx.Element
	is_guardian := authz_mode_is_guardian(el)
	if want_guardian && !is_guardian {
		return error('E_AUTHZ_ARG_INVALID: grant-guardian requires a guardian shape ([mode :guardian] + [gate …]); use delegate for an ordinary delegation')
	}
	if !want_guardian && is_guardian {
		return error('E_AUTHZ_ARG_INVALID: a guardian-shaped value (carries [mode :guardian]/[gate …]) must be issued via grant-guardian, not delegate')
	}
	id := authz_leading_id(el)
	if id == '' {
		return error('E_AUTHZ_ARG_INVALID: delegation has no id')
	}
	tenant := authz_tenant_of(el)
	if tenant == '' {
		return error('E_AUTHZ_ARG_INVALID: delegation has no [tenant …]')
	}
	// Tenant is a HARD partition (§4.6): cross-tenant issuance is unissuable.
	if store_tenant != '' && tenant != store_tenant {
		return error('E_AUTHZ_ARG_INVALID: cross-tenant delegation — grant tenant `${tenant}` ≠ store tenant `${store_tenant}` (the partition is structural, §4.6)')
	}
	from_kind, from_id := authz_party(el, 'from')
	to_kind, to_id := authz_party(el, 'to')
	if to_id == '' {
		return error('E_AUTHZ_ARG_INVALID: delegation has no [to …] grantee')
	}
	caps := authz_capabilities(el)
	atten := authz_atten_of(el)
	ponly_el := authz_child(el, 'propose-only') or { cx.Element{} }
	mut rec := &AuthzDelegation{
		id:           id
		tenant:       tenant
		guardian:     is_guardian
		from_kind:    from_kind
		from_id:      from_id
		to_kind:      to_kind
		to_id:        to_id
		capabilities: caps
		over:         authz_over_of(el)
		attenuates:   atten
		until_secs:   authz_until_secs(el)
		revocable:    authz_revocable_of(el)
		revoked:      false
		assurance:    authz_assurance_of(el, 't1')
		propose_only: ponly_el.name == 'propose-only'
		gate:         cx.Node(cx.Element{})
		action:       cx.Node(cx.Element{})
		value:        arg
	}
	if is_guardian {
		if g := authz_child(el, 'gate') {
			rec.gate = g
		}
		if a := authz_child(el, 'action') {
			rec.action = a
		} else {
			return error('E_AUTHZ_ARG_INVALID: a guardian grant requires a pinned [action …]')
		}
	}
	authz_parse_bounds(el, mut rec)!
	return rec
}

fn authz_atten_of(el cx.Element) string {
	a := authz_child(el, 'attenuates') or { return '' }
	for it in a.items {
		t := authz_node_text(it)
		if t != '' {
			return t
		}
		if it is cx.Element && it.items.len == 0 && it.attrs.len == 0 {
			return it.name
		}
	}
	return ''
}

// authz_find_rec finds an active-or-revoked delegation record by id in a store.
fn authz_find_rec(s &AuthzStore, id string) ?&AuthzDelegation {
	for d in s.delegations {
		if d.id == id {
			return d
		}
	}
	return none
}

// ── attenuation (§4.2) ───────────────────────────────────────────────────────
//
// A new grant's (capabilities ∩ slice) MUST be ⊆ the issuer's own held
// authority — the `[attenuates …]` parent. A principal-rooted grant (no parent)
// is the authority origin (N-TRUST-1) and may convey anything it names (the
// principal IS the source). A grant naming a parent that the issuer does not
// actually hold (active, unrevoked, unexpired, covering the caps+slice) →
// CXER4703.
fn authz_attenuation_ok(s &AuthzStore, rec &AuthzDelegation, now_secs i64) bool {
	if rec.attenuates == '' {
		// principal-rooted — the origin of authority. (N-TRUST-1: authority
		// originates from a principal; a from-principal root may convey what it
		// names.) Require the `from` to be a principal for a rootless grant.
		return rec.from_kind == 'principal' || rec.from_kind == ''
	}
	parent := authz_find_rec(s, rec.attenuates) or { return false } // no such parent → cannot attenuate
	if parent.revoked {
		return false
	}
	if parent.until_secs > 0 && now_secs > 0 && now_secs > parent.until_secs {
		return false
	}
	// caps ⊆ parent caps (unless parent is unrestricted on caps — empty caps
	// list means "all the issuer's" only for a principal root, never here).
	for c in rec.capabilities {
		if c !in parent.capabilities {
			return false
		}
	}
	// slice ⊆ parent slice: the parent must COVER the child's slice.
	if !authz_slice_covers(parent.over, rec.over) {
		return false
	}
	// window ⊆ (§4.2 four-axis pin): a child cannot outlive its parent. A
	// child with NO until under a windowed parent INHERITS it at issue
	// (authz_inherit_window) — checked here for the explicit-later case.
	if parent.until_secs > 0 && rec.until_secs > parent.until_secs {
		return false
	}
	// bounds ⊆ (§2.2/§4.2): a child naming its own bounds must name a ⊆
	// budget per conjunct against the nearest bounds-bearing ancestor;
	// absent child bounds = the shared meter (always ⊆).
	if rec.has_bounds {
		if anc := authz_nearest_bounds(s, parent) {
			if !authz_bounds_subset(rec, anc) {
				return false
			}
		}
	}
	return true
}

// authz_nearest_bounds walks up from `start` (inclusive) to the nearest
// bounds-bearing delegation — the meter owner for shared-meter children.
fn authz_nearest_bounds(s &AuthzStore, start &AuthzDelegation) ?&AuthzDelegation {
	mut cur := start
	mut seen := map[string]bool{}
	for {
		if seen[cur.id] {
			return none
		}
		seen[cur.id] = true
		if cur.has_bounds {
			return cur
		}
		if cur.attenuates == '' {
			return none
		}
		cur = authz_find_rec(s, cur.attenuates) or { return none }
	}
	return none
}

// authz_bounds_subset — per-conjunct ⊆ (a bound never widens): rate compares
// both capacity (N) and per-second refill (cross-multiplied, no float);
// count compares the monotone total; spend compares amount at equal currency
// and at-most-equal window — an incomparable spend pair (currency mismatch)
// is FAIL-CLOSED (cannot prove ⊆).
fn authz_bounds_subset(child &AuthzDelegation, parent &AuthzDelegation) bool {
	if child.b_rate_per > 0 && parent.b_rate_per > 0 {
		if child.b_rate_n > parent.b_rate_n {
			return false
		}
		// child refill rate ≤ parent's: c_n/c_per ≤ p_n/p_per
		if child.b_rate_n * parent.b_rate_per > parent.b_rate_n * child.b_rate_per {
			return false
		}
	}
	if child.b_count > 0 && parent.b_count > 0 && child.b_count > parent.b_count {
		return false
	}
	if child.b_has_spend && parent.b_has_spend {
		if child.b_spend_cur != parent.b_spend_cur {
			return false
		}
		if child.b_spend_amt > parent.b_spend_amt {
			return false
		}
		if parent.b_spend_per > 0 && (child.b_spend_per == 0 || child.b_spend_per > parent.b_spend_per) {
			return false
		}
	}
	return true
}

// authz_inherit_window — a child with NO [until] under a windowed parent
// inherits the parent's window at issue (§4.2: it cannot outlive it).
fn authz_inherit_window(s &AuthzStore, mut rec AuthzDelegation) {
	if rec.attenuates == '' || rec.until_secs != 0 {
		return
	}
	parent := authz_find_rec(s, rec.attenuates) or { return }
	if parent.until_secs > 0 {
		rec.until_secs = parent.until_secs
	}
}

// ── §3.2 delegate / revoke ───────────────────────────────────────────────────
fn authz_delegate_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: delegate expects (store, delegation)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: delegate on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: delegate expects an open [authz-store] handle')
		}
	}
	rec := authz_parse_delegation(args[1], s.tenant, false) or {
		return mk_err(authz_err_arg_invalid, err.msg())
	}
	now_secs := authz_store_clock(args, 2)
	// #1024 — READ-THEN-WRITE, restructured rather than upgraded. Both basis READS
	// (the attenuation check and the window inheritance) run in ONE read bracket
	// here; the journal append runs unlocked; then authz_grants_append takes the
	// WRITE lock. A pthread rwlock cannot upgrade, so a read bracket spanning the
	// append would self-deadlock; taking the WRITE lock for the whole verb instead
	// would hold it across the trust-log fsync and stall every PEP decision in the
	// process behind disk I/O.
	//
	// WHY THE GAP IS SOUND. Releasing between the check and the append leaves a
	// window in which another thread could revoke the parent this grant attenuates.
	// The result is a grant installed under a now-revoked parent — which is not an
	// escalation: authz_chain_to_principal re-walks the chain on EVERY decision and
	// a revoked ancestor breaks it (§2.5/§4.1), so the grant simply denies. The
	// records themselves are immutable but for `revoked`, and the array only grows,
	// so there is no other mutation the read phase could have been fooled by.
	//
	// authz_inherit_window moved ABOVE the journal append (it was below): it sets
	// the parsed `until_secs`, never `rec.value`, so the journaled authz-issued
	// event is byte-identical, and this now matches authz_replay_journal's own
	// parse → inherit → append order.
	authz_grants_rlock()
	atten_ok := authz_attenuation_ok(s, rec, now_secs)
	mut nrec := rec
	if atten_ok {
		authz_inherit_window(s, mut nrec)
	}
	authz_grants_runlock()
	// attenuation — privilege escalation is structurally impossible (§4.2).
	if !atten_ok {
		return mk_err(authz_err_escalation, 'E_AUTHZ_ESCALATION: the grant conveys more than the issuer holds (attenuation violation, §4.2)')
	}
	// Journal-FIRST (W3 R7, §2.6): the attributed issue-event lands in
	// the trust log BEFORE the in-process mutation; a fault is CXER4710
	// and the grant is NOT installed. In-process tier (no journal
	// bound): append is a no-op and the registry IS the attributed log.
	if fault := authz_journal_append(s, cx.Node(cx.Element{
		name:  'authz-issued'
		items: [rec.value]
	}), rec.from_id, authz_issue_basis(rec), '')
	{
		return fault
	}
	authz_grants_append(mut s, rec)
	return authz_materialize_delegation(rec)
}

// authz_issue_basis names the §2.6 authority basis of an issuance: the
// [attenuates …] parent id, or `principal` for a principal-rooted grant.
fn authz_issue_basis(rec &AuthzDelegation) string {
	if rec.attenuates != '' {
		return rec.attenuates
	}
	return 'principal'
}

fn authz_revoke_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: revoke expects (store, id)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: revoke on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: revoke expects an open [authz-store] handle')
		}
	}
	id := authz_arg_str(args[1]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: revoke expects an id string')
	}
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	cascade := authz_opt_bool(cfg, 'cascade', false)
	// #1024: the lookup is the basis read, bracketed; `rec` is carried out (stable
	// heap record). The flip below then goes through authz_grants_mark_revoked's
	// WRITE lock instead of the bare `rec.revoked = true` this used to do — the
	// registry tier was the one caller still flipping in place, so it was the one
	// tier where a revocation was not one act with everything else.
	authz_grants_rlock()
	target := authz_find_rec(s, id)
	authz_grants_runlock()
	rec := target or {
		// Idempotent: revoking an absent id is a no-op → absence (§2.5/§3.2).
		// No event either — nothing transitioned (§2.6 records transitions).
		return authz_absence()
	}
	if rec.revoked {
		// already revoked → absence (revocation is absence for check, §2.5).
		return authz_absence()
	}
	// Journal-FIRST per affected id (W3 R7/R8): each authz-revoked event
	// is appended and, on success, applied immediately — on a mid-cascade
	// fault both the log and live state hold the same PREFIX (consistency
	// at every prefix; the remainder re-runs idempotently).
	if fault := authz_journal_append(s, authz_revoked_event(id), rec.from_id, authz_issue_basis(rec), '') {
		return fault
	}
	authz_grants_mark_revoked(mut s, id)
	if cascade {
		if fault := authz_revoke_cascade(mut s, id) {
			return fault
		}
	}
	return authz_materialize_delegation(rec)
}

// authz_revoked_event builds the §2.6 revocation event (W3 R8).
fn authz_revoked_event(id string) cx.Node {
	return cx.Element{
		name:  'authz-revoked'
		attrs: [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue(id)
			},
		]
	}
}

// #1024: the cascade journals per link and RECURSES, so it can hold no lock
// across its body — #997 named it the one deliberate exception. It no longer has
// to be: each LEVEL's live children are collected under one read bracket, and the
// journal-then-apply of each child runs after the release. Order is unchanged
// (basis order per level, depth-first per child) and so is the prefix guarantee —
// on a mid-cascade fault the log and live state still hold the same prefix. The
// flip goes through the write helper now, and its own `&& !d.revoked` guard makes
// a child two concurrent cascades both collected idempotent.
fn authz_revoke_cascade(mut s AuthzStore, parent_id string) ?cx.Node {
	authz_grants_rlock()
	mut kids := []&AuthzDelegation{}
	for d in s.delegations {
		if d.attenuates == parent_id && !d.revoked {
			kids << d
		}
	}
	authz_grants_runlock()
	for d in kids {
		if d.revoked {
			continue // a concurrent cascade reached this link first
		}
		if fault := authz_journal_append(s, authz_revoked_event(d.id), d.from_id,
			authz_issue_basis(d), '')
		{
			return fault
		}
		authz_grants_mark_revoked(mut s, d.id)
		if fault := authz_revoke_cascade(mut s, d.id) {
			return fault
		}
	}
	return none
}

// authz_store_clock reads an `as-of`/`now`/`clock` instant from a trailing opts
// arg at index `idx` (Unix secs; 0 = no clock, i.e. nothing has expired).
fn authz_store_clock(args []cx.Node, idx int) i64 {
	if args.len <= idx {
		return 0
	}
	cfg := authz_opts(args[idx])
	mut t := authz_opt_secs(cfg, 'as-of')
	if t == 0 {
		t = authz_opt_secs(cfg, 'now')
	}
	if t == 0 {
		t = authz_opt_secs(cfg, 'clock')
	}
	return t
}

// ── §3.3 grant-guardian (the two-validator authoring check) ──────────────────
fn authz_grant_guardian_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: grant-guardian expects (store, grant)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: grant-guardian on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: grant-guardian expects an open [authz-store] handle')
		}
	}
	rec := authz_parse_delegation(args[1], s.tenant, true) or {
		return mk_err(authz_err_arg_invalid, err.msg())
	}
	// (two-validator authoring check — raises, never stores a bad grant, §2.8.)
	// 1. gate well-formedness (structural + semantic + bright-line).
	gate_check := authz_validate_gate(rec.gate)
	if is_err_value(gate_check) {
		return gate_check // CXER4701 / 4702 / 4706
	}
	// 2. assurance tier: guardian = T1 minimum; a T0 guardian is rejected (§2.7
	//    / §10.9 footnote 9). T2 required if any capability is irreversible.
	if rec.assurance == 't0' {
		return mk_err(authz_err_verify_failed, 'E_AUTHZ_VERIFY_FAILED: a guardian grant is T1 minimum — a T0 (session-attributed) guardian grant is rejected at authoring (§2.7)')
	}
	if !authz_tier_satisfiable(rec) {
		return mk_err(authz_err_verify_failed, 'E_AUTHZ_VERIFY_FAILED: irreversible capability requires T2 co-signing (M-of-N), grant declares ${rec.assurance}')
	}
	// 3. attenuation — the pinned [action …] within the grantor's authority.
	//
	// #1024: the same read-then-write restructure as authz_delegate_impl — both
	// basis reads in one bracket, journal unlocked, append under the write lock.
	// Steps 1 and 2 above (gate well-formedness, assurance tier) read only the
	// PRESENTED grant, never the basis, so they stay outside.
	now_secs := authz_store_clock(args, 2)
	authz_grants_rlock()
	atten_ok := authz_attenuation_ok(s, rec, now_secs)
	mut nrec := rec
	if atten_ok {
		authz_inherit_window(s, mut nrec)
	}
	authz_grants_runlock()
	if !atten_ok {
		return mk_err(authz_err_escalation, 'E_AUTHZ_ESCALATION: the guardian action conveys more than the grantor holds (§4.2)')
	}
	// Journal-FIRST (W3 R7, §2.6) — guardian grants ride the same
	// authz-issued event (the guardian shape is IN the value, R8).
	if fault := authz_journal_append(s, cx.Node(cx.Element{
		name:  'authz-issued'
		items: [rec.value]
	}), rec.from_id, authz_issue_basis(rec), '')
	{
		return fault
	}
	// store dormant-until-gate (§3.3).
	authz_grants_append(mut s, rec)
	return authz_materialize_delegation(rec)
}

// authz_tier_satisfiable — an irreversible capability must be T2 (§2.7). We
// recognize irreversibility by an `irreversible` marker on the grant or a
// conventional capability-name prefix. Conservative/fail-closed: an
// irreversibly-marked grant below T2 fails.
fn authz_tier_satisfiable(rec &AuthzDelegation) bool {
	mut irreversible := false
	if rec.value is cx.Element {
		el := rec.value as cx.Element
		if _ := authz_child(el, 'irreversible') {
			irreversible = true
		}
		for it in el.items {
			if it is cx.Element && it.name == 'capabilities' {
				if v := it.attr_val('irreversible') {
					if cx.scalar_value_str_public(v) == 'true' {
						irreversible = true
					}
				}
			}
		}
	}
	if irreversible && rec.assurance != 't2' {
		return false
	}
	return true
}

// ── gate validation — the two-validator + bright-line (§2.8 / §4.4) ──────────
//
// Returns an [err] (CXER4701/4702/4706) on failure, or a [valid] element on
// success. This is the function grant-guardian + gate-wellformed? share.
fn authz_validate_gate(gate cx.Node) cx.Node {
	if gate !is cx.Element || (gate as cx.Element).name != 'gate' {
		return mk_err(authz_err_gate_illformed, 'E_AUTHZ_GATE_ILLFORMED: expected a [gate …] value')
	}
	el := gate as cx.Element
	bright_line_violation, incapacity_count := authz_gate_scan(el)
	if bright_line_violation != '' {
		// a refusal-trigger or an unknown/inline predicate.
		if bright_line_violation.starts_with('refusal:') {
			return mk_err(authz_err_refusal_trigger, 'E_AUTHZ_REFUSAL_TRIGGER: gate leaf `${bright_line_violation[8..]}` branches on a principal\'s choice — the bright line: a refusal-triggered grant is unexpressible (§4.4)')
		}
		if bright_line_violation.starts_with('unknown:') {
			return mk_err(authz_err_unknown_pred, 'E_AUTHZ_UNKNOWN_PREDICATE: gate references `${bright_line_violation[8..]}` — not in the signed library; inline/ad-hoc incapacity logic is rejected (§2.3/§3.5)')
		}
		return mk_err(authz_err_gate_illformed, 'E_AUTHZ_GATE_ILLFORMED: ${bright_line_violation}')
	}
	if incapacity_count < 1 {
		return mk_err(authz_err_gate_illformed, 'E_AUTHZ_GATE_ILLFORMED: a gate needs ≥ 1 incapacity predicate — a state-only gate could fire while the principal is present and declining (§4.4)')
	}
	return cx.Element{ name: 'valid' }
}

// authz_gate_scan walks the gate's combinator tree (all/any over
// incapacity/state leaves), counting incapacity leaves and detecting bright-
// line violations. Returns '' when clean, or a tagged reason
// ('refusal:<leaf>' / 'unknown:<name@version>' / a free-form ill-formed msg).
fn authz_gate_scan(el cx.Element) (string, int) {
	mut incapacity_count := 0
	for it in el.items {
		if it !is cx.Element {
			// A non-element gate term is a BRIGHT-LINE violation, not something
			// to skip. The critical case: `not` is the CX symbolic operator, so
			// `[not [incapacity x]]` written in a gate is EAGERLY EVALUATED to a
			// bare scalar `false` before authz ever sees the gate — the old
			// `continue` then silently dropped that term, weakening (potentially
			// WIDENING) a multi-term gate with zero diagnostic. `not` is NOT an
			// admissible gate combinator (§2.2 narrowed to all/any over
			// incapacity/state); a collapsed scalar term is rejected fail-closed.
			if it is cx.ScalarNode {
				return 'a gate term collapsed to a bare scalar — `not`/operator forms are not gate combinators; a gate is all/any over incapacity/state leaves only (§2.2)', incapacity_count
			}
			continue
		}
		child := it as cx.Element
		match child.name {
			'all', 'any' {
				r, c := authz_gate_scan(child)
				incapacity_count += c
				if r != '' {
					return r, incapacity_count
				}
			}
			'incapacity' {
				// must resolve by name@version in the signed library (§2.3).
				nv := authz_incapacity_name_version(child)
				if nv == '' {
					return 'unknown:(inline)', incapacity_count
				}
				if !authz_predicate_known(nv) {
					return 'unknown:${nv}', incapacity_count
				}
				incapacity_count++
			}
			'state' {
				// a harm/world threshold — always allowed (ANDed in only, but
				// the ≥1-incapacity rule is enforced by the caller).
			}
			else {
				// any other leaf naming a principal's CHOICE is the bright line.
				if child.name in authz_refusal_leaves {
					return 'refusal:${child.name}', incapacity_count
				}
				return 'unrecognized gate leaf `${child.name}` — only `incapacity`/`state` leaves and `all`/`any` combinators are admissible (§2.2)', incapacity_count
			}
		}
	}
	return '', incapacity_count
}

// authz_incapacity_name_version reads the name@version a leaf references:
// [incapacity [no-ack-within@v1 …]] or [incapacity name=no-ack-within version=v1].
fn authz_incapacity_name_version(el cx.Element) string {
	// child element whose name carries name@version or just name.
	for it in el.items {
		if it is cx.Element {
			n := it.name
			if n.contains('@') {
				return n
			}
			if n != '' {
				// bare name — default to the bundled library version.
				ver := it.attr('version')
				if ver != '' {
					return '${n}@${ver}'
				}
				return '${n}@${authz_library_version}'
			}
		}
		st := authz_node_text(it)
		if st != '' {
			if st.contains('@') {
				return st
			}
			return '${st}@${authz_library_version}'
		}
	}
	if v := el.attr_val('name') {
		name := cx.scalar_value_str_public(v)
		ver := el.attr('version')
		if name != '' {
			if ver != '' {
				return '${name}@${ver}'
			}
			return '${name}@${authz_library_version}'
		}
	}
	return ''
}

fn authz_split_name_version(nv string) (string, string) {
	idx := nv.index('@') or { return nv, '' }
	return nv[..idx], nv[idx + 1..]
}

fn authz_find_predicate(nv string) ?AuthzPredicate {
	name, ver := authz_split_name_version(nv)
	for p in authz_bundled_predicates {
		if p.name == name && (ver == '' || p.version == ver) {
			return p
		}
	}
	return none
}

fn authz_predicate_known(nv string) bool {
	authz_find_predicate(nv) or { return false }
	return true
}

// ── §3.4 check / authorize / find / grants-of ────────────────────────────────
//
// The PEP decision function. PURE over the materialized store snapshot; returns
// a present [permit]/[deny] VALUE. `strict` is the `authorize` alias: with
// opts.raise-on-deny=true it RAISES CXER4700 carrying the [deny].
fn authz_check_impl(args []cx.Node, strict bool) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: check expects (store, request)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: check on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: check expects an open [authz-store] handle')
		}
	}
	if args[1] !is cx.Element || (args[1] as cx.Element).name != 'authz-request' {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: check expects an [authz-request …] value')
	}
	req := args[1] as cx.Element
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	// Stream 8 (bitemporal L121): the decision value carries both temporal
	// coordinates when the caller supplies them — see authz_stamp_coordinates.
	//
	// #1024: the ENTIRE decision runs under one read bracket. authz_decide walks
	// the basis twice (the individual capability union, then the grant scan) and
	// chases [attenuates] chains between them, so a bracket per walk would be
	// memory-safe but could still decide against two different bases. Nothing in
	// authz_decide does I/O or re-enters a verb — it is the pure PEP — so the
	// whole call is bracketable, and a decision that PERMITS is then a decision
	// some single state of the basis actually authorized.
	authz_grants_rlock()
	verdict := authz_decide(s, req, cfg)
	authz_grants_runlock()
	decision := authz_stamp_coordinates(verdict, cfg)
	if strict && authz_opt_bool(cfg, 'raise-on-deny', false) {
		if decision is cx.Element && (decision as cx.Element).name == 'deny' {
			// a budget-exhausted deny raises its own carried code (CXER4713,
			// §2.2/§8); every other denial raises the canonical CXER4700.
			mut dcode := authz_err_unauthorized
			mut msg := 'E_AUTHZ_UNAUTHORIZED: authorization denied (raise-on-deny)'
			for it in (decision as cx.Element).items {
				if it is cx.Element && it.name == 'code' && it.items.len > 0 {
					if authz_node_text(it.items[0]) == authz_err_budget {
						dcode = authz_err_budget
						msg = 'E_AUTHZ_BUDGET_EXHAUSTED: budget exhausted (raise-on-deny)'
					}
				}
			}
			return authz_err_with_cause(dcode, msg, decision)
		}
	}
	return decision
}

// authz_request fields.
struct AuthzReq {
	actor_kind string
	actor_id   string
	capability string
	slice      string
	tenant     string
	as_of      i64
	require_tier string
}

fn authz_read_request(req cx.Element, cfg map[string]cx.Node) AuthzReq {
	ak, ai := authz_party(req, 'actor')
	mut cap := ''
	if c := authz_child(req, 'capability') {
		cap = authz_party_id(c)
		if cap == '' {
			cap = c.attr('name')
		}
	}
	mut slice := ''
	if sl := authz_child(req, 'slice') {
		for it in sl.items {
			t := authz_node_text(it)
			if t != '' {
				slice = t
			}
		}
		if slice == '' {
			slice = sl.attr('path')
		}
	}
	tenant := authz_tenant_of(req)
	mut as_of := authz_until_secs_field(req, 'as-of')
	if as_of == 0 {
		as_of = authz_opt_secs(cfg, 'as-of')
	}
	mut tier := ''
	if rt := authz_child(req, 'require-tier') {
		for it in rt.items {
			t := authz_node_text(it)
			if t != '' {
				tier = t.to_lower()
			}
		}
	}
	if tier == '' {
		tier = authz_opt_str(cfg, 'require-tier', '').to_lower()
	}
	return AuthzReq{
		actor_kind:   ak
		actor_id:     ai
		capability:   cap
		slice:        slice
		tenant:       tenant
		as_of:        as_of
		require_tier: tier
	}
}

fn authz_until_secs_field(el cx.Element, field string) i64 {
	c := authz_child(el, field) or { return 0 }
	for it in c.items {
		s := authz_secs_of(it)
		if s != 0 {
			return s
		}
	}
	return 0
}

// authz_decide is the total decision (§3.4). It returns a present [permit] or
// [deny] VALUE — never absence, never null, never [err] (faults are caught by
// authz_check_impl's argument validation upstream).
fn authz_decide(s &AuthzStore, req cx.Element, cfg map[string]cx.Node) cx.Node {
	r := authz_read_request(req, cfg)
	if r.actor_id == '' || r.capability == '' {
		return authz_deny(r, 'malformed-request', cx.Node(cx.Element{}))
	}
	// tenant is the hard partition (§4.6).
	if r.tenant != '' && r.tenant != s.tenant {
		return authz_deny(r, 'tenant-mismatch', cx.Node(cx.Element{}))
	}
	// the effective envelope clamps every decision (§3.6). We clamp ONLY when a
	// recorded envelope is actually in force (most-restrictive-wins); absent an
	// envelope the individual grants gate directly.
	mut indiv := []string{}
	for d in s.delegations {
		if !d.revoked && d.to_id == r.actor_id {
			for c in d.capabilities {
				if c !in indiv {
					indiv << c
				}
			}
		}
	}
	envelope, envelope_constrains := authz_effective_intersect(s, r.actor_id, indiv, cfg)
	// walk every grant to the actor for an unbroken, unrevoked, unexpired,
	// attenuating, principal-rooted chain conveying `capability` over a slice
	// that covers `slice`, at the required tier, with the gate holding.
	meters := authz_meter_readings(cfg)
	mut best_reason := 'no-grant'
	mut budget_conjunct := ''
	mut budget_retry := i64(0)
	for d in s.delegations {
		if d.to_id != r.actor_id {
			continue
		}
		if d.to_kind != '' && r.actor_kind != '' && d.to_kind != r.actor_kind {
			continue
		}
		if d.revoked {
			continue // revocation is absence — keep scanning (§2.5)
		}
		if r.capability !in d.capabilities {
			continue
		}
		if !authz_slice_covers(d.over, r.slice) {
			if best_reason == 'no-grant' {
				best_reason = 'out-of-slice'
			}
			continue
		}
		// expiry (§2.5: in check, expiry is a [deny [reason :expired]] value).
		if d.until_secs > 0 && r.as_of > 0 && r.as_of > d.until_secs {
			if best_reason == 'no-grant' || best_reason == 'out-of-slice' {
				best_reason = 'expired'
			}
			continue
		}
		// tier (§2.7): the grant's assurance must meet the required tier.
		if !authz_tier_meets(d.assurance, r.require_tier) {
			best_reason = 'tier-unmet'
			continue
		}
		// principal-rooted, attenuating chain (N-TRUST-1, §4.1).
		via := authz_chain_to_principal(s, d, r.as_of)
		if via.len == 0 {
			if best_reason == 'no-grant' { best_reason = 'no-principal-root' }
			continue
		}
		// guardian: the gate must hold as-of, and only the pinned action (§3.3).
		if d.guardian {
			if !authz_action_matches(d, r) {
				best_reason = 'action-not-pinned'
				continue
			}
			if !authz_gate_holds(d.gate, cfg) {
				best_reason = 'gate-not-holding'
				continue
			}
		}
		// envelope clamp (§3.6): when a recorded envelope is in force the
		// capability must be within the effective allowed-set (most-restrictive-
		// wins); absent an envelope the individual grants gate directly.
		if envelope_constrains && r.capability !in envelope {
			best_reason = 'envelope-clamped'
			continue
		}
		// budget (§2.2): every bounds-bearing link on this chain must have
		// meter headroom — the last conjunct checked (D-C1: independent of
		// scope), so the denial names exactly what failed. Another grant may
		// still convey the capability with headroom: keep scanning.
		bv := authz_budget_check(s, d, meters)
		if bv.exhausted {
			best_reason = 'budget-exhausted'
			budget_conjunct = bv.conjunct
			budget_retry = bv.retry_after
			continue
		}
		// PERMIT.
		return authz_permit(d, via, r)
	}
	if best_reason == 'budget-exhausted' {
		mut extra := [cx.Node(authz_kv('conjunct', authz_atom(budget_conjunct)))]
		if budget_retry > 0 {
			extra << cx.Node(authz_kv('retry-after', authz_int(budget_retry)))
		}
		return authz_deny_coded(r, 'budget-exhausted', authz_err_budget, extra)
	}
	return authz_deny(r, best_reason, cx.Node(cx.Element{}))
}

// ── budget meters (§2.2 — the PEP reads the meter as supplied context) ──────
//
// The decision layer STAYS PURE: meter state arrives in the opts as
// `{meters: [meters [meter id=… tokens=… count-used=…]…]}` — the
// materialized-snapshot posture (commands_effects §4). An ABSENT meter
// reading is a FRESH meter (no recorded usage): meters RESTRICT authority,
// so absence of usage records means unspent budget — unlike gate evidence,
// which ENABLES authority and is absent-means-false.
struct AuthzMeterReading {
	has_tokens bool
	tokens     f64
	count_used i64
	// spend axis (stream 6 W4, R11): supplied by the meter fold so a
	// PEP-side denial can name ANY failing conjunct (D-C1). Absent =
	// no recorded spend (fresh, like the other axes).
	has_spend  bool
	spend_used f64
}

fn authz_meter_readings(cfg map[string]cx.Node) map[string]AuthzMeterReading {
	mut out := map[string]AuthzMeterReading{}
	n := cfg['meters'] or { return out }
	if n !is cx.Element {
		return out
	}
	for it in (n as cx.Element).items {
		if it is cx.Element && it.name == 'meter' {
			id := it.attr('id')
			if id == '' {
				continue
			}
			mut rd := AuthzMeterReading{}
			if tv := it.attr_val('tokens') {
				rd = AuthzMeterReading{
					...rd
					has_tokens: true
					tokens:     authz_node_f64(cx.ScalarNode{ value: tv, data_type: .string_type })
				}
			}
			if cv := it.attr_val('count-used') {
				mut cu := i64(0)
				if cv is i64 {
					cu = cv
				}
				rd = AuthzMeterReading{
					...rd
					count_used: cu
				}
			}
			if sv := it.attr_val('spend-used') {
				rd = AuthzMeterReading{
					...rd
					has_spend:  true
					spend_used: authz_node_f64(cx.ScalarNode{ value: sv, data_type: .string_type })
				}
			}
			out[id] = rd
		}
	}
	return out
}

struct AuthzBudgetVerdict {
	exhausted   bool
	conjunct    string // 'rate' | 'count'
	retry_after i64    // secs; 0 = none (count never replenishes)
}

// authz_budget_check walks the chain from the granting delegation up,
// checking EVERY bounds-bearing link against its meter reading — a shared
// pool governs its whole subtree, and a child's own bounds ADD a cap, never
// replace the pool (a pool never multiplies authority, §2.2).
fn authz_budget_check(s &AuthzStore, d &AuthzDelegation, meters map[string]AuthzMeterReading) AuthzBudgetVerdict {
	mut cur := d
	mut seen := map[string]bool{}
	for {
		if seen[cur.id] {
			break
		}
		seen[cur.id] = true
		if cur.has_bounds {
			rd := meters[cur.id] or { AuthzMeterReading{} } // absent = fresh
			if cur.b_count > 0 && rd.count_used >= cur.b_count {
				return AuthzBudgetVerdict{
					exhausted: true
					conjunct:  'count'
				}
			}
			// spend (stream 6 W4, R11): exhausted when the window's
			// recorded spend has reached the limit — no retry-after
			// (only rate replenishes, the §8 rule; the window turnover
			// is the caller's clock concern).
			if cur.b_has_spend && rd.has_spend && rd.spend_used >= cur.b_spend_amt {
				return AuthzBudgetVerdict{
					exhausted: true
					conjunct:  'spend'
				}
			}
			if cur.b_rate_per > 0 {
				tokens := if rd.has_tokens { rd.tokens } else { f64(cur.b_rate_n) }
				if tokens < 1.0 {
					// retry-after = the bucket's next-token interval:
					// (1 - tokens) at a refill rate of N per PER seconds.
					raf := (1.0 - tokens) * f64(cur.b_rate_per) / f64(cur.b_rate_n)
					mut ra := i64(raf)
					if f64(ra) < raf {
						ra++
					}
					if ra < 1 {
						ra = 1
					}
					return AuthzBudgetVerdict{
						exhausted:   true
						conjunct:    'rate'
						retry_after: ra
					}
				}
			}
		}
		if cur.attenuates == '' {
			break
		}
		cur = authz_find_rec(s, cur.attenuates) or { break }
	}
	return AuthzBudgetVerdict{}
}

// authz_tier_meets — does an assurance tier meet a required tier? Ordering
// t0 < t1 < t2. An empty required tier accepts any. Fail-closed: an
// unrecognized assurance is treated as t0 (weakest).
fn authz_tier_rank(t string) int {
	return match t {
		't2' { 2 }
		't1' { 1 }
		't0' { 0 }
		else { 0 }
	}
}

fn authz_tier_meets(assurance string, required string) bool {
	if required == '' {
		return true
	}
	return authz_tier_rank(assurance) >= authz_tier_rank(required)
}

// authz_chain_to_principal walks the [attenuates …] chain to a principal root,
// returning the ordered list of delegation ids (root-first) or [] if the chain
// is broken / not principal-rooted / a link is revoked-or-expired. N-TRUST-1.
fn authz_chain_to_principal(s &AuthzStore, start &AuthzDelegation, as_of i64) []string {
	mut chain := []string{}
	mut cur := start
	mut seen := map[string]bool{}
	for {
		if seen[cur.id] {
			return [] // cycle → broken
		}
		seen[cur.id] = true
		if cur.revoked {
			return []
		}
		if cur.until_secs > 0 && as_of > 0 && as_of > cur.until_secs {
			return []
		}
		chain.prepend(cur.id)
		if cur.attenuates == '' {
			// root: must originate from a principal (N-TRUST-1).
			if cur.from_kind == 'principal' || cur.from_kind == '' {
				return chain
			}
			return []
		}
		parent := authz_find_rec(s, cur.attenuates) or { return [] }
		cur = parent
	}
	return []
}

// authz_action_matches — a guardian grant permits ONLY its pinned [action …].
// The request capability must match the pinned action's intent.
fn authz_action_matches(d &AuthzDelegation, r AuthzReq) bool {
	if d.action !is cx.Element {
		return false
	}
	act := d.action as cx.Element
	// [action [do :pause-payment-gateway]] — the do-intent atom names the cap.
	for it in act.items {
		if it is cx.Element {
			// [do :cap] → the atom child names the capability.
			for sub in it.items {
				if authz_node_text(sub) == r.capability {
					return true
				}
			}
			if it.name == r.capability {
				return true
			}
		}
	}
	// A guardian grant permits ONLY its pinned [action …] (§3.3/§4.4): if the
	// requested capability is not the pinned action, it is NOT permitted — even
	// when it appears in the grant's capability set. FAIL-CLOSED.
	return false
}

// authz_gate_holds evaluates a guardian gate as-of the decision context (§3.4).
// FAIL-CLOSED: an incapacity predicate's truth comes ONLY from the supplied
// context (opts.with-context / opts.context / opts.state); ABSENT evidence =
// FALSE (the principal is presumed present — falsifiable-by-presence, §4.4
// invariant 3). A `state` threshold is read from the same context.
fn authz_gate_holds(gate cx.Node, cfg map[string]cx.Node) bool {
	if gate !is cx.Element {
		return false
	}
	ctx := authz_context_map(cfg)
	return authz_gate_eval(gate as cx.Element, ctx)
}

// authz_context_map lifts opts.with-context / context / state (a [context …] or
// __cx_map__ element) into a flat name→truthiness map. A key present and truthy
// asserts that fact (e.g. `no-ack-within` true, `charge-error-rate` 0.2).
fn authz_context_map(cfg map[string]cx.Node) map[string]cx.Node {
	mut ctx := map[string]cx.Node{}
	for key in ['with-context', 'context', 'state'] {
		n := cfg[key] or { continue }
		if n is cx.Element {
			if n.name == '__cx_map__' {
				for e in n.items {
					if e is cx.Element && e.items.len > 0 {
						ctx[e.name] = e.items[0]
					}
				}
			} else {
				for it in n.items {
					if it is cx.Element {
						if it.items.len > 0 {
							ctx[it.name] = it.items[0]
						} else {
							ctx[it.name] = authz_bool(true)
						}
					}
				}
			}
		}
	}
	return ctx
}

fn authz_node_truthy(n cx.Node) bool {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			bool { return v }
			string { return v == 'true' }
			i64 { return v != 0 }
			f64 { return v != 0 }
			else { return false }
		}
	}
	if n is cx.TextNode {
		return n.value == 'true'
	}
	return false
}

fn authz_node_f64(n cx.Node) f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			string { return v.f64() }
			else { return 0 }
		}
	}
	if n is cx.TextNode {
		return n.value.f64()
	}
	return 0
}

// authz_gate_eval evaluates the combinator tree against the context. An
// `incapacity` leaf is true iff the context asserts the predicate name true; a
// `state` leaf is the CXPath threshold over the context. FAIL-CLOSED default.
fn authz_gate_eval(el cx.Element, ctx map[string]cx.Node) bool {
	match el.name {
		'gate', 'all' {
			mut all_true := true
			mut any_leaf := false
			for it in el.items {
				if it is cx.Element {
					any_leaf = true
					if !authz_gate_eval(it, ctx) {
						all_true = false
					}
				}
			}
			return if any_leaf { all_true } else { false }
		}
		'any' {
			for it in el.items {
				if it is cx.Element {
					if authz_gate_eval(it, ctx) {
						return true
					}
				}
			}
			return false
		}
		'not' {
			for it in el.items {
				if it is cx.Element {
					return !authz_gate_eval(it, ctx)
				}
			}
			return false
		}
		'incapacity' {
			nv := authz_incapacity_name_version(el)
			name, _ := authz_split_name_version(nv)
			// context asserts the predicate by its bare name (falsifiable-by-
			// presence: absent → false → principal presumed present).
			v := ctx[name] or { return false }
			return authz_node_truthy(v)
		}
		'state' {
			return authz_state_eval(el, ctx)
		}
		else {
			return false // unrecognized leaf → fail-closed
		}
	}
}

// authz_state_eval reads a [state [<op> /path value]] threshold against the
// context. The /path's terminal segment names the context key. Supported ops:
// gt/ge/lt/le/eq/ne.
fn authz_state_eval(el cx.Element, ctx map[string]cx.Node) bool {
	for it in el.items {
		if it is cx.Element {
			op := it.name
			mut path := ''
			mut threshold := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(i64(0)), data_type: .int_type })
			mut have_threshold := false
			for sub in it.items {
				st := authz_node_text(sub)
				if st.starts_with('/') {
					path = st
				} else if sub is cx.ScalarNode && !have_threshold {
					threshold = sub
					have_threshold = true
				} else if st != '' && !have_threshold {
					threshold = sub
					have_threshold = true
				}
			}
			key := authz_path_terminal(path)
			actual := ctx[key] or { return false } // no evidence → fail-closed
			a := authz_node_f64(actual)
			t := authz_node_f64(threshold)
			return match op {
				'gt' { a > t }
				'ge' { a >= t }
				'lt' { a < t }
				'le' { a <= t }
				'eq' { a == t }
				'ne' { a != t }
				else { false }
			}
		}
	}
	return false
}

fn authz_path_terminal(p string) string {
	if p == '' {
		return ''
	}
	parts := p.trim_left('/').split('/')
	if parts.len == 0 {
		return ''
	}
	return parts[parts.len - 1]
}

fn authz_find_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: find expects (store, id)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: find on a closed authority store')
		} else {
			authz_absence()
		}
	}
	id := authz_arg_str(args[1]) or { return authz_absence() }
	// #1024: the bracket covers the WALK. `rec` is a stable heap record — it does
	// not move and cannot be removed — so reading it after the release is sound.
	authz_grants_rlock()
	found := authz_find_rec(s, id)
	authz_grants_runlock()
	rec := found or { return authz_absence() }
	// revoked → absence (§2.5). Expired is also absence if a clock is known —
	// but find has no clock arg; we surface revoked as absence and an active
	// (possibly-expired-by-now) record as the value (the caller filters by
	// as-of in check).
	if rec.revoked {
		return authz_absence()
	}
	return authz_materialize_delegation(rec)
}

fn authz_grants_of_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: grants-of expects (store, actor)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: grants-of on a closed authority store')
		} else {
			authz_absence()
		}
	}
	actor_kind, actor_id := authz_actor_arg(args[1])
	if actor_id == '' {
		return authz_absence()
	}
	mut out := []cx.Node{}
	// #1024: one bracket over the whole walk — a caller listing an actor's grants
	// gets one basis, not a sample of two.
	authz_grants_rlock()
	for d in s.delegations {
		if d.revoked {
			continue
		}
		if d.to_id == actor_id && (d.to_kind == '' || actor_kind == '' || d.to_kind == actor_kind) {
			out << authz_materialize_delegation(d)
		}
	}
	authz_grants_runlock()
	return authz_seq(out)
}

// authz_actor_arg reads an [agent X] / [principal X] / [actor [agent X]] value.
fn authz_actor_arg(arg cx.Node) (string, string) {
	if arg !is cx.Element {
		return '', ''
	}
	el := arg as cx.Element
	if el.name == 'actor' {
		return authz_party(cx.Element{ name: 'w', items: [cx.Node(el)] }, 'w')
	}
	return el.name, authz_party_id(el)
}

// ── §3.5 predicate / predicates / gate-wellformed? / verify-tier ─────────────
fn authz_predicate_impl(args []cx.Node) cx.Node {
	// (store, name@version) — store arg is accepted for signature; the bundled
	// library is the default resolution source (§3.1 library opt).
	mut nv := ''
	if args.len >= 2 {
		nv = authz_arg_str(args[1]) or { '' }
	} else if args.len == 1 {
		nv = authz_arg_str(args[0]) or { '' }
	}
	if nv == '' {
		return authz_absence()
	}
	p := authz_find_predicate(nv) or { return authz_absence() } // unknown → absence (§3.5)
	return authz_materialize_predicate(p)
}

fn authz_predicates_impl(_args []cx.Node) cx.Node {
	mut out := []cx.Node{}
	for p in authz_bundled_predicates {
		out << authz_materialize_predicate(p)
	}
	return authz_seq(out)
}

fn authz_materialize_predicate(p AuthzPredicate) cx.Node {
	mut param_items := []cx.Node{}
	for pn in p.params {
		param_items << cx.Node(cx.Element{ name: pn })
	}
	mut items := [
		cx.Node(cx.Element{ name: 'params', items: param_items }),
		cx.Node(authz_kv('rationale', authz_str(p.rationale))),
	]
	if p.attested {
		items << cx.Node(cx.Element{ name: 'attested-signal-source', attrs: [authz_str_attr('required', 'true')] })
	}
	// (a real entry carries a crypto signature; the bundled library is signed
	// as a whole — we mark it verified.)
	items << cx.Node(authz_kv('signature', authz_str('bundled-library:${p.name}@${p.version}')))
	return cx.Element{
		name:  'predicate'
		attrs: [
			authz_str_attr('name', p.name),
			authz_str_attr('version', p.version),
		]
		items: items
	}
}

fn authz_gate_wellformed_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: gate-wellformed? expects a [gate …]')
	}
	check := authz_validate_gate(args[0])
	if is_err_value(check) {
		// return a [invalid [reason …] [code …]] VALUE, NOT an [err] (§3.5).
		ce := check as cx.Element
		err_code := ce.attr('code')
		msg := ce.attr('message')
		reason := match err_code {
			authz_err_refusal_trigger { 'refusal-trigger' }
			authz_err_gate_illformed { 'gate-illformed' }
			authz_err_unknown_pred { 'unknown-predicate' }
			else { 'invalid' }
		}
		return cx.Element{
			name:  'invalid'
			items: [
				cx.Node(authz_kv('reason', authz_atom(reason))),
				cx.Node(authz_kv('code', authz_str(err_code))),
				cx.Node(authz_kv('detail', authz_str(msg))),
			]
		}
	}
	return cx.Element{ name: 'valid' }
}

// verify-tier — verifies a grant's assurance tier (§3.5). Impure (touches the
// store/keys). Returns [verified [tier …]] or RAISES CXER4704. For T0 it is
// session-presence (no signature); T1/T2 verify via crypto. A guardian grant
// verifies on two axes (own signature + library signature). For the hermetic
// posture the bundled library is trusted-signed; a grant carrying an explicit
// `signature=invalid` / `[signature invalid]` marker fails (fail-closed).
fn authz_verify_tier_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: verify-tier expects (store, grant, tier?)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: verify-tier on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: verify-tier expects an open [authz-store] handle')
		}
	}
	_ = s
	if args[1] !is cx.Element {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: verify-tier expects a [delegation …] grant')
	}
	grant := args[1] as cx.Element
	mut tier := authz_assurance_of(grant, 't1')
	if args.len > 2 {
		if t := authz_arg_str(args[2]) {
			tt := t.to_lower()
			if tt != '' {
				tier = tt
			}
		}
	}
	// expiry: a grant past `until` used in a HARD verification → CXER4705.
	until := authz_until_secs(grant)
	now := authz_store_clock(args, 3)
	if until > 0 && now > 0 && now > until {
		return mk_err(authz_err_expired, 'E_AUTHZ_EXPIRED: grant past its `until` instant (hard verification, §8)')
	}
	is_guardian := authz_mode_is_guardian(grant)
	if is_guardian && tier == 't0' {
		return mk_err(authz_err_verify_failed, 'E_AUTHZ_VERIFY_FAILED: a guardian grant cannot be T0 (§2.7)')
	}
	// signature axis — fail-closed on a bad/absent signature for T1/T2.
	if tier == 't1' || tier == 't2' {
		if !authz_signature_ok(grant, tier) {
			return mk_err(authz_err_verify_failed, 'E_AUTHZ_VERIFY_FAILED: ${tier} signature verification failed (bad/absent signature, or M-of-N quorum unmet)')
		}
	}
	mut items := [cx.Node(authz_kv('tier', authz_atom(tier)))]
	if is_guardian {
		// two-axis: the predicate library signature is verified too.
		items << cx.Node(authz_kv('library-verified', authz_bool(true)))
	}
	return cx.Element{
		name:  'verified'
		items: items
	}
}

// authz_signature_ok — fail-closed signature/quorum check. A grant carrying a
// [signature …] child whose value is non-empty and not the literal 'invalid'
// verifies for T1; for T2 it also requires an M-of-N [signatures …] quorum
// (need ≤ count). A grant with an explicit [signature invalid] / no signature
// fails. (Composes crypto in a real deployment; here it gates on the recorded
// signature marker so negatives are testable hermetically.)
fn authz_signature_ok(grant cx.Element, tier string) bool {
	if tier == 't2' {
		sigs := authz_child(grant, 'signatures') or {
			return false // T2 requires M-of-N — no signatures block → fail
		}
		need := sigs.attr('need').int()
		mut count := 0
		mut valid := 0
		for it in sigs.items {
			if it is cx.Element && it.name == 'signature' {
				count++
				v := authz_sig_value(it)
				if v != '' && v != 'invalid' {
					valid++
				}
			}
		}
		if need <= 0 {
			return false
		}
		return valid >= need
	}
	// T1 single signature.
	sig := authz_child(grant, 'signature') or {
		return false // no signature → fail-closed
	}
	v := authz_sig_value(sig)
	return v != '' && v != 'invalid'
}

fn authz_sig_value(el cx.Element) string {
	for it in el.items {
		t := authz_node_text(it)
		if t != '' {
			return t
		}
	}
	if v := el.attr_val('value') {
		return cx.scalar_value_str_public(v)
	}
	if v := el.attr_val('by') {
		// [signature by=dana] with no explicit value → treat as present/valid
		_ := v
		return 'present'
	}
	return ''
}

// ── §3.6 effective envelope ──────────────────────────────────────────────────
//
// The effective allowed-set = individual ∩ ⋂(superior, managing-agent,
// collective gates). Intersection only — most-restrictive-wins, never expands.
// An envelope-setter without a RECORDED authority relationship is IGNORED.
fn authz_effective_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: effective expects (store, actor)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: effective on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: effective expects an open [authz-store] handle')
		}
	}
	actor_kind, actor_id := authz_actor_arg(args[1])
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	// #1024: authz_effective_set walks the basis for the individual set and then
	// authz_effective_intersect walks it again per envelope (the recorded-
	// relationship check) — one bracket over both, so the envelope is intersected
	// against the same basis the individual set came from.
	authz_grants_rlock()
	allowed := authz_effective_set(s, actor_kind, actor_id, cfg)
	authz_grants_runlock()
	mut cap_items := []cx.Node{}
	for c in allowed {
		cap_items << cx.Node(cx.Element{ name: c })
	}
	return cx.Element{
		name:  'envelope'
		attrs: [authz_str_attr('actor', actor_id)]
		items: [cx.Node(cx.Element{ name: 'capabilities', items: cap_items })]
	}
}

// authz_effective_set computes the intersected allowed capability-set. The
// individual set is the union of the actor's own active grants' capabilities.
// Each envelope in opts.context/envelopes that names a RECORDED relationship
// (a delegation from the setter to the actor exists) intersects; an unrecorded
// envelope is ignored. An empty result here means "no envelope constraint
// recorded" and `check` treats it as unconstrained (the individual grants gate).
fn authz_effective_set(s &AuthzStore, actor_kind string, actor_id string, cfg map[string]cx.Node) []string {
	mut individual := []string{}
	for d in s.delegations {
		if d.revoked {
			continue
		}
		if d.to_id == actor_id && (d.to_kind == '' || actor_kind == '' || d.to_kind == actor_kind) {
			for c in d.capabilities {
				if c !in individual {
					individual << c
				}
			}
		}
	}
	set, _ := authz_effective_intersect(s, actor_id, individual, cfg)
	return set
}

// authz_effective_intersect returns (allowed-set, constrained?). The allowed-
// set is the individual set intersected with every RECORDED envelope; the
// boolean reports whether any recorded envelope actually clamped it (so `check`
// clamps only when an envelope is in force, never against an empty individual
// set when no envelope was supplied — §3.6/§4.3).
fn authz_effective_intersect(s &AuthzStore, actor_id string, individual []string, cfg map[string]cx.Node) ([]string, bool) {
	// envelopes from opts: [envelopes [envelope from=… [allow [cap]…]] …]
	envs := authz_opt_node(cfg, 'envelopes') or { return individual.clone(), false }
	if envs !is cx.Element {
		return individual.clone(), false
	}
	mut result := individual.clone()
	mut any_recorded := false
	for it in (envs as cx.Element).items {
		if it !is cx.Element {
			continue
		}
		env := it as cx.Element
		setter_id := env.attr('from')
		// recorded-relationship check: a delegation from the setter to the
		// actor must exist (the setter has legitimate authority over the actor).
		if !authz_has_relationship(s, setter_id, actor_id) {
			continue // unrecorded → ignored (§4.3)
		}
		any_recorded = true
		mut allow := []string{}
		for sub in env.items {
			if sub is cx.Element && (sub.name == 'allow' || sub.name == 'capabilities') {
				for c in sub.items {
					if c is cx.Element {
						allow << c.name
					}
				}
			}
		}
		// intersect — most-restrictive-wins (§3.6).
		mut next := []string{}
		for c in result {
			if c in allow {
				next << c
			}
		}
		result = next.clone()
	}
	return result, any_recorded
}

fn authz_has_relationship(s &AuthzStore, setter_id string, actor_id string) bool {
	if setter_id == '' {
		return false
	}
	for d in s.delegations {
		if d.revoked {
			continue
		}
		if d.from_id == setter_id && d.to_id == actor_id {
			return true
		}
	}
	return false
}

// ── §3.7 dry-run / explain / trace ───────────────────────────────────────────
//
// dry-run runs check over an explicit scenario WITHOUT any journal write — same
// [permit]/[deny] value, deterministic. Identical to check here (check is
// already pure + write-free), with opts.state seeding the gate context.
fn authz_dry_run_impl(args []cx.Node) cx.Node {
	return authz_check_impl(args, false)
}

// explain — turn a [permit]/[deny] into a human-/agent-readable [explanation …]
// (the authority chain on a permit, or the first failing link on a deny).
fn authz_explain_impl(args []cx.Node) cx.Node {
	if args.len < 1 || args[0] !is cx.Element {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: explain expects a [permit]/[deny] value')
	}
	d := args[0] as cx.Element
	match d.name {
		'permit' {
			// the principal-rooted authority chain.
			mut chain := []cx.Node{}
			if via := authz_child(d, 'via') {
				for it in via.items {
					t := authz_node_text(it)
					if t != '' {
						chain << cx.Node(authz_kv('step', authz_str(t)))
					}
				}
			}
			return cx.Element{
				name:  'explanation'
				attrs: [authz_str_attr('outcome', 'permit')]
				items: [
					cx.Node(authz_kv('accountable', authz_str(d.attr('rooted-principal')))),
					cx.Node(cx.Element{ name: 'authority-chain', items: chain }),
				]
			}
		}
		'deny' {
			mut reason := ''
			if rc := authz_child(d, 'reason') {
				for it in rc.items {
					t := authz_node_text(it)
					if t != '' {
						reason = t
					}
				}
			}
			return cx.Element{
				name:  'explanation'
				attrs: [authz_str_attr('outcome', 'deny')]
				items: [
					cx.Node(authz_kv('first-failing-link', authz_atom(if reason != '' { reason } else { 'no-grant' }))),
					cx.Node(authz_kv('code', authz_str(authz_err_unauthorized))),
				]
			}
		}
		else {
			return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: explain expects a [permit]/[deny] value, got [${d.name}]')
		}
	}
}

// trace — the ordered policy-stack evaluation behind explain (every chain step
// + gate predicate truth + attenuation check) for a request. Pure.
fn authz_trace_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: trace expects (store, request)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: trace on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: trace expects an open [authz-store] handle')
		}
	}
	if args[1] !is cx.Element || (args[1] as cx.Element).name != 'authz-request' {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: trace expects an [authz-request …] value')
	}
	req := args[1] as cx.Element
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	r := authz_read_request(req, cfg)
	mut steps := []cx.Node{}
	// #1024: trace is the diagnostic view of the same walk `check` decides on, and
	// it chases a chain per step (authz_chain_to_principal) — so it gets the same
	// whole-walk bracket. A trace stitched from two bases would explain a decision
	// that never happened.
	authz_grants_rlock()
	for d in s.delegations {
		if d.to_id != r.actor_id {
			continue
		}
		mut notes := []cx.Node{}
		notes << cx.Node(authz_kv('id', authz_str(d.id)))
		notes << cx.Node(authz_kv('revoked', authz_bool(d.revoked)))
		notes << cx.Node(authz_kv('conveys-capability', authz_bool(r.capability in d.capabilities)))
		notes << cx.Node(authz_kv('covers-slice', authz_bool(authz_slice_covers(d.over, r.slice))))
		notes << cx.Node(authz_kv('tier-meets', authz_bool(authz_tier_meets(d.assurance, r.require_tier))))
		via := authz_chain_to_principal(s, d, r.as_of)
		notes << cx.Node(authz_kv('principal-rooted', authz_bool(via.len > 0)))
		if d.guardian {
			notes << cx.Node(authz_kv('gate-holds', authz_bool(authz_gate_holds(d.gate, cfg))))
		}
		steps << cx.Node(cx.Element{ name: 'step', items: notes })
	}
	authz_grants_runlock()
	return authz_seq(steps)
}

// ── value materializers ──────────────────────────────────────────────────────
fn authz_materialize_delegation(d &AuthzDelegation) cx.Node {
	mut attrs := [
		authz_str_attr('id', d.id),
		authz_str_attr('mode', if d.guardian { 'guardian' } else { 'delegated' }),
		authz_str_attr('state', if d.revoked { 'revoked' } else { 'active' }),
	]
	mut items := []cx.Node{}
	items << cx.Node(cx.Element{ name: 'tenant', attrs: [authz_str_attr('id', d.tenant)] })
	items << cx.Node(authz_kv('to', cx.Element{ name: if d.to_kind != '' { d.to_kind } else { 'agent' }, attrs: [authz_str_attr('id', d.to_id)] }))
	if d.from_id != '' {
		items << cx.Node(authz_kv('from', cx.Element{ name: if d.from_kind != '' { d.from_kind } else { 'principal' }, attrs: [authz_str_attr('id', d.from_id)] }))
	}
	mut cap_items := []cx.Node{}
	for c in d.capabilities {
		cap_items << cx.Node(cx.Element{ name: c })
	}
	items << cx.Node(cx.Element{ name: 'capabilities', items: cap_items })
	if d.over != '' {
		items << cx.Node(authz_kv('over', authz_str(d.over)))
	}
	if d.attenuates != '' {
		items << cx.Node(authz_kv('attenuates', authz_str(d.attenuates)))
	}
	items << cx.Node(authz_kv('assurance', authz_atom(d.assurance)))
	if d.until_secs > 0 {
		items << cx.Node(authz_kv('until', authz_int(d.until_secs)))
	}
	if d.has_bounds {
		items << d.bounds_value // the verbatim [bounds …] element (§2.2)
	}
	if d.guardian {
		items << cx.Node(authz_kv('dormant-until-gate', authz_bool(true)))
	}
	return cx.Element{
		name:  'delegation'
		attrs: attrs
		items: items
	}
}

// ── the bitemporal coherence rule (stream 8, bitemporal.md L121) ────────────
//
// The decision value records BOTH temporal coordinates for audit: `as-of`
// (the valid-time decision instant, when supplied) and the CONTEXT's
// transaction-time position (when opts.with-context is a journal [snapshot]
// — at-seq= for the single form, the [at-head-set …] member list for the
// §3.7 set form). "What would we have decided at position P, for instant T"
// is thereby specifiable and auditable; a context that makes no TX claim
// (a bare folded state) stamps nothing — the incoherent pair is
// constructible only explicitly, and its absence of a coordinate is VISIBLE
// on the decision. Decisions without these opts are byte-identical.
fn authz_stamp_coordinates(decision cx.Node, cfg map[string]cx.Node) cx.Node {
	if decision is cx.Element {
		if decision.name != 'permit' && decision.name != 'deny' {
			return decision
		}
		mut e := decision as cx.Element
		if asof := cfg['as-of'] {
			txt := authz_node_text(asof)
			if txt != '' {
				e.attrs << authz_str_attr('as-of', txt)
			}
		}
		for key in ['with-context', 'context', 'state'] {
			ctx := cfg[key] or { continue }
			if ctx is cx.Element {
				if ctx.name == 'snapshot' {
					if ctx.attr('form') == 'set' {
						mut members := []cx.Node{}
						for it in ctx.items {
							if it is cx.Element {
								if it.name == 'h' {
									mut hattrs := []cx.Attribute{}
									if it.attr('stream') != '' {
										hattrs << authz_str_attr('stream', it.attr('stream'))
									}
									hattrs << cx.Attribute{
										name:  'at-seq'
										value: cx.ScalarValue(i64(it.attr('at-seq').int()))
									}
									members << cx.Node(cx.Element{
										name:  'h'
										attrs: hattrs
									})
								}
							}
						}
						e.items << cx.Node(cx.Element{
							name:  'at-head-set'
							items: members
						})
					} else if ctx.attr('at-seq') != '' {
						e.attrs << cx.Attribute{
							name:  'at-seq'
							value: cx.ScalarValue(i64(ctx.attr('at-seq').int()))
						}
					}
				}
			}
			break
		}
		return cx.Node(e)
	}
	return decision
}

fn authz_permit(d &AuthzDelegation, via []string, r AuthzReq) cx.Node {
	mut via_items := []cx.Node{}
	for id in via {
		via_items << authz_str(id)
	}
	// the rooted principal is the `from` of the chain root.
	return cx.Element{
		name:  'permit'
		attrs: [authz_str_attr('rooted-principal', d.from_id)]
		items: [
			cx.Node(authz_kv('delegation', authz_str(d.id))),
			cx.Node(cx.Element{ name: 'via', items: via_items }),
			cx.Node(authz_kv('tier', authz_atom(d.assurance))),
			cx.Node(authz_kv('capability', authz_str(r.capability))),
		]
	}
}

fn authz_deny(r AuthzReq, reason string, _detail cx.Node) cx.Node {
	return authz_deny_coded(r, reason, authz_err_unauthorized, []cx.Node{})
}

// authz_deny_coded builds the [deny …] value with an explicit carried code
// (CXER4700 for authority denials, CXER4713 for budget exhaustion) and any
// extra detail items placed right after [reason …] — D-C1: the denial names
// the failing conjunct.
fn authz_deny_coded(r AuthzReq, reason string, dcode string, extra []cx.Node) cx.Node {
	mut items := [
		cx.Node(authz_kv('code', authz_str(dcode))),
		cx.Node(authz_kv('reason', authz_atom(reason))),
	]
	items << extra
	items << cx.Node(authz_kv('capability', authz_str(r.capability)))
	if r.slice != '' {
		items << cx.Node(authz_kv('slice', authz_str(r.slice)))
	}
	mut attrs := [authz_str_attr('actor', r.actor_id)]
	if r.tenant != '' {
		items << cx.Node(cx.Element{ name: 'tenant', attrs: [authz_str_attr('id', r.tenant)] })
	}
	return cx.Element{
		name:  'deny'
		attrs: attrs
		items: items
	}
}

// ── §3.8 budgets (stream 6 W4, L112): meter-as-fold + commit-point debit ──────
//
// A debit is a §2.6 authority-transition event (R9): `[authz-debited
// id=<granting delegation> count=N (spend=AMT currency=CUR)?]` on the SAME
// named `authz` stream — the journal's per-stream group-commit lock IS the
// L112 "stream's commit lock" (linearizable for free; per-stream v1 scoping
// falls out). The event records the GRANTING delegation; the FOLD attributes
// usage up the [attenuates …] chain to every bounds-bearing ancestor (shared
// meters deplete for the whole subtree — replay-stable, the chain lives in
// the same log).
//
// `meters` (R10) folds those events into the EXACT `[meters [meter …]…]`
// element the pure PEP reads ({meters: …} opts — check STAYS PURE; the
// caller folds-then-checks, the with-context materialized-snapshot posture).
// `debit` (R11) re-folds INSIDE the commit path before appending: exhausted
// at commit → the CXER4713-carrying [deny …] VALUE and NO event (the
// two-times enforcement table — the PEP decided on a snapshot, live facts
// re-check at commit).

// AuthzDebitEvent is one folded usage record.
struct AuthzDebitEvent {
mut:
	grant_id string
	ts_secs  i64
	count    i64
	spend    f64
	currency string
	alloc    string // '' = a direct draw; else the allocation it draws from
}

// AuthzMeterState is one meter's folded reading.
struct AuthzMeterState {
mut:
	count_used i64
	tokens     f64
	spend_used f64
	newest_ts  i64
}

// ── §3 escrow allocations (stream 10, cross_stream_coordination §3) ─────────
//
// A sub-delegation may RESERVE from its parent's meter: `[authz-allocated
// alloc= from= count= spend= currency=]` on the same authz stream — the
// reservation debits the PARENT chain at reservation time (window
// attribution pinned there: the fold uses the reservation event's ts, so a
// draw near a window boundary counts against the window the reservation was
// made in). Draws carrying alloc= deplete the ALLOCATION's own remainder
// (never the parent — one draw, one meter) and are checked at the debit
// commit. `[authz-allocation-expired alloc=]` reclaims the un-drawn
// remainder — NOT replenishment: after expiry the parent's consumption for
// that allocation is exactly what was DRAWN (the un-drawn part never left
// the window's budget). Scope: count/spend ONLY — `rate` is a flow
// property with no coherent cross-stream reservation (a reserved rate is
// waste or double-counted flow); it meters locally, un-escrowed.

struct AuthzAllocState {
mut:
	alloc       string
	from        string
	count_res   i64
	spend_res   f64
	currency    string
	ts_secs     i64
	expired     bool
	count_drawn i64
	spend_drawn f64
}

// authz_collect_raw walks the authz stream ONCE: raw debits (alloc-tagged
// kept), allocations, expiries — in seq order.
fn authz_collect_raw(s &AuthzStore) ([]AuthzDebitEvent, map[string]AuthzAllocState, ?cx.Node) {
	mut events := []AuthzDebitEvent{}
	mut allocs := map[string]AuthzAllocState{}
	mut j, errn, ok := jrn_get_open(s.journal_handle)
	if !ok {
		return events, allocs, authz_err_with_cause(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: bound journal unavailable for the meter fold',
			errn)
	}
	jrn_refresh_head(mut j, authz_journal_stream)
	st := jrn_named_state(mut j, authz_journal_stream)
	entries := jrn_state_collect_range_of(j, authz_journal_stream, st, 1, st.head_seq)
	for en in entries {
		if en !is cx.Element {
			continue
		}
		enel := en as cx.Element
		ev := jrn_entry_event(enel)
		if ev !is cx.Element {
			continue
		}
		evel := ev as cx.Element
		ts := jrn_entry_attr(enel, 'ts')
		mut ts_secs := i64(0)
		if ts != '' {
			ts_secs = authz_secs_of(cx.ScalarNode{
				value:     cx.ScalarValue(ts)
				data_type: .string_type
			})
		}
		match evel.name {
			'authz-debited' {
				mut e := AuthzDebitEvent{
					grant_id: authz_el_attr(evel, 'id')
					count:    1
					ts_secs:  ts_secs
					alloc:    authz_el_attr(evel, 'alloc')
				}
				if cv := evel.attr_val('count') {
					if cv is i64 {
						e.count = cv
					}
				}
				if sv := evel.attr_val('spend') {
					e.spend = authz_node_f64(cx.ScalarNode{ value: sv, data_type: .string_type })
				}
				e.currency = authz_el_attr(evel, 'currency')
				events << e
				if e.alloc != '' {
					if mut a := allocs[e.alloc] {
						a.count_drawn += e.count
						a.spend_drawn += e.spend
						allocs[e.alloc] = a
					}
				}
			}
			'authz-allocated' {
				mut a := AuthzAllocState{
					alloc:    authz_el_attr(evel, 'alloc')
					from:     authz_el_attr(evel, 'from')
					currency: authz_el_attr(evel, 'currency')
					ts_secs:  ts_secs
				}
				if cv := evel.attr_val('count') {
					if cv is i64 {
						a.count_res = cv
					}
				}
				if sv := evel.attr_val('spend') {
					a.spend_res = authz_node_f64(cx.ScalarNode{ value: sv, data_type: .string_type })
				}
				allocs[a.alloc] = a
			}
			'authz-allocation-expired' {
				aid := authz_el_attr(evel, 'alloc')
				if mut a := allocs[aid] {
					a.expired = true
					allocs[aid] = a
				}
			}
			else {}
		}
	}
	return events, allocs, none
}

// authz_collect_debits reads the bound journal's authz stream and returns
// the PARENT-VISIBLE debit events in seq order (the meter-fold input):
// direct draws verbatim; each allocation as ONE synthetic parent debit at
// the RESERVATION instant — reserved amounts while active, exactly the
// DRAWN amounts once expired (the reclaim rule); alloc-tagged draws are
// excluded (their budget left the parent at reservation — one draw never
// meters twice). Fault → the CXER4710 err VALUE in the second slot.
fn authz_collect_debits(s &AuthzStore) ([]AuthzDebitEvent, ?cx.Node) {
	raw, allocs, fault := authz_collect_raw(s)
	if f := fault {
		return []AuthzDebitEvent{}, f
	}
	mut events := []AuthzDebitEvent{}
	for e in raw {
		if e.alloc == '' {
			events << e
		}
	}
	for _, a in allocs {
		mut e := AuthzDebitEvent{
			grant_id: a.from
			ts_secs:  a.ts_secs
			currency: a.currency
		}
		if a.expired {
			e.count = a.count_drawn
			e.spend = a.spend_drawn
		} else {
			e.count = a.count_res
			e.spend = a.spend_res
		}
		if e.count == 0 && e.spend == 0 {
			continue
		}
		events << e
	}
	events.sort(a.ts_secs < b.ts_secs)
	return events, none
}

// authz_meter_fold computes every bounds-bearing delegation's meter state
// from the debit events (R10): rate = token-bucket replay over event
// timestamps; count = monotone event-count sum; spend = the sum inside the
// CURRENT UTC-Z epoch-aligned window containing `now`.
fn authz_meter_fold(s &AuthzStore, events []AuthzDebitEvent, now_secs i64) map[string]AuthzMeterState {
	mut byid := map[string]&AuthzDelegation{}
	for d in s.delegations {
		byid[d.id] = d
	}
	// per-meter event lists (chain attribution — every bounds-bearing
	// ancestor of the granting delegation meters the event).
	mut per := map[string][]AuthzDebitEvent{}
	for e in events {
		mut cur := byid[e.grant_id] or { continue }
		mut seen := map[string]bool{}
		for {
			if seen[cur.id] {
				break
			}
			seen[cur.id] = true
			if cur.has_bounds {
				per[cur.id] << e
			}
			if cur.attenuates == '' {
				break
			}
			cur = byid[cur.attenuates] or { break }
		}
	}
	mut out := map[string]AuthzMeterState{}
	for d in s.delegations {
		if !d.has_bounds {
			continue
		}
		evs := per[d.id] or { []AuthzDebitEvent{} }
		mut st := AuthzMeterState{
			tokens: f64(d.b_rate_n)
		}
		mut last_ts := i64(0)
		mut first := true
		for e in evs {
			st.count_used += e.count
			if d.b_rate_per > 0 {
				if !first {
					st.tokens = authz_bucket_refill(st.tokens, f64(d.b_rate_n), f64(d.b_rate_per),
						e.ts_secs - last_ts)
				}
				st.tokens -= f64(e.count)
			}
			if d.b_has_spend && d.b_spend_per > 0 {
				if authz_window_start(e.ts_secs, d.b_spend_per) == authz_window_start(now_secs,
					d.b_spend_per)
				{
					st.spend_used += e.spend
				}
			}
			last_ts = e.ts_secs
			first = false
			if e.ts_secs > st.newest_ts {
				st.newest_ts = e.ts_secs
			}
		}
		if d.b_rate_per > 0 && !first && now_secs > last_ts {
			st.tokens = authz_bucket_refill(st.tokens, f64(d.b_rate_n), f64(d.b_rate_per),
				now_secs - last_ts)
		}
		out[d.id] = st
	}
	return out
}

@[inline]
fn authz_bucket_refill(tokens f64, cap_n f64, per_secs f64, elapsed i64) f64 {
	mut t := tokens + f64(elapsed) * cap_n / per_secs
	if t > cap_n {
		t = cap_n
	}
	return t
}

// authz_window_start — the UTC-Z epoch-aligned window containing `ts`
// (floor(ts/per)·per): the deterministic implementation of the ruled
// "UTC-Z calendar-aligned" rule (W4 R10; never tenant-local midnight).
@[inline]
fn authz_window_start(ts i64, per i64) i64 {
	if per <= 0 {
		return 0
	}
	mut w := (ts / per) * per
	if ts < 0 && ts % per != 0 {
		w -= per
	}
	return w
}

// authz_num emits an integral f64 as an int scalar (tokens=1) and a
// fractional one as a float scalar (tokens=1.5) — the reading parser
// accepts both.
fn authz_num(v f64) cx.Node {
	if v == f64(i64(v)) {
		return authz_int(i64(v))
	}
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.float_type
	}
}

// authz_float always emits a float scalar (money axes: spend-used=50.0).
fn authz_float(v f64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.float_type
	}
}

// authz_meters_impl — `[$authz:meters store opts]` (R10). opts.now pins the
// fold instant (controllable clock); default = the newest debit ts
// (data-derived — the fold stays deterministic with no ambient clock read).
fn authz_meters_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: meters expects (store)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: meters on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: meters expects an open [authz-store] handle')
		}
	}
	if !s.has_journal {
		return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: meters needs the journal-bound (durable) tier — an unbound store has no debit log (§3.8)')
	}
	events, fault := authz_collect_debits(s)
	if f := fault {
		return f
	}
	cfg := if args.len > 1 { authz_opts(args[1]) } else { map[string]cx.Node{} }
	mut now_secs := authz_opt_secs(cfg, 'now')
	if now_secs == 0 {
		for e in events {
			if e.ts_secs > now_secs {
				now_secs = e.ts_secs
			}
		}
	}
	// #1024: `meters` is read-only ON THE BASIS but its input is a JOURNAL fold, so
	// the bracket starts AFTER authz_collect_debits — a read lock held across
	// jrn_* would put the authority basis behind journal I/O and give
	// authz_grants_lock a lock-order edge it does not have today (it is a leaf).
	// The fold and the emit walk are one bracket: authz_meter_fold indexes the
	// basis by id and walks it again for the bounds-bearing rows, and the emit
	// walk below reads `folded` against those same rows.
	authz_grants_rlock()
	folded := authz_meter_fold(s, events, now_secs)
	mut items := []cx.Node{}
	for d in s.delegations {
		if !d.has_bounds {
			continue
		}
		st := folded[d.id] or { AuthzMeterState{} }
		mut attrs := [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue(d.id)
			},
		]
		if d.b_rate_per > 0 {
			tn := authz_num(st.tokens)
			if tn is cx.ScalarNode {
				attrs << cx.Attribute{
					name:  'tokens'
					value: tn.value
				}
			}
		}
		if d.b_count > 0 {
			attrs << cx.Attribute{
				name:  'count-used'
				value: cx.ScalarValue(st.count_used)
			}
		}
		if d.b_has_spend {
			sn := authz_float(st.spend_used)
			if sn is cx.ScalarNode {
				attrs << cx.Attribute{
					name:  'spend-used'
					value: sn.value
				}
			}
		}
		items << cx.Node(cx.Element{
			name:  'meter'
			attrs: attrs
		})
	}
	authz_grants_runlock()
	return cx.Element{
		name:  'meters'
		items: items
	}
}

// authz_debit_deny builds the commit-point exhaustion VALUE (R11) — the
// same CXER4713-as-data shape the PEP emits, minus the request context a
// debit does not have, plus the failing meter owner.
fn authz_debit_deny(conjunct string, meter_id string, retry_after i64) cx.Node {
	mut items := [
		cx.Node(authz_kv('code', authz_str('cx-err:CXER4713'))),
		cx.Node(authz_kv('reason', authz_atom('budget-exhausted'))),
		cx.Node(authz_kv('conjunct', authz_atom(conjunct))),
	]
	if retry_after > 0 {
		items << cx.Node(authz_kv('retry-after', authz_int(retry_after)))
	}
	items << cx.Node(authz_kv('delegation', authz_str(meter_id)))
	return cx.Element{
		name:  'deny'
		items: items
	}
}

// authz_debit_impl — `[$authz:debit store id opts]` (R9/R11): the L112
// commit-point primitive. Validates (journal-bound tier; known id;
// positive axes; declared currency), re-folds headroom AT the debit's
// effective instant, appends the event (ts pinned by opts.at), and
// returns a `[debited …]` receipt. Exhausted → the deny VALUE, no event.
// authz_allocate_impl — `[$authz:allocate store alloc-id {from, count?,
// spend?, currency?}]`: reserve from the parent's meter UNDER the commit
// path (headroom re-folded at the reservation instant; a reservation the
// parent cannot cover is the CXER4713 deny naming the failing conjunct).
// `rate` is refused — un-escrowable by rule.
fn authz_allocate_impl(args []cx.Node) cx.Node {
	if args.len < 3 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate expects (store, alloc-id, {from, count?|spend?})')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate expects an open [authz-store] handle')
	}
	if !s.has_journal {
		return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: allocate needs the journal-bound (durable) tier (§3.8)')
	}
	aid := authz_arg_str(args[1]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate expects an allocation id string')
	}
	cfg := authz_opts(args[2])
	from := authz_opt_str(cfg, 'from', '')
	if from == '' {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate needs opts.from (the parent delegation)')
	}
	if _ := cfg['rate'] {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: rate is a FLOW property — a cross-stream rate reservation is unused capacity or double-counted flow; a sub-delegation carrying rate meters it locally, un-escrowed (cross_stream_coordination §3)')
	}
	// #1024: the parent-exists check is a basis walk — bracketed on its own. The
	// journal folds below must not run under it (see the note on `meters`).
	authz_grants_rlock()
	parent_known := authz_find_rec(s, from) != none
	authz_grants_runlock()
	if !parent_known {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate names an unknown parent delegation `${from}`')
	}
	mut count := i64(0)
	if cn := cfg['count'] {
		if cn is cx.ScalarNode {
			cv := cn.value
			if cv is i64 {
				count = cv
			}
		}
	}
	mut spend := f64(0)
	if sn := cfg['spend'] {
		spend = authz_node_f64(sn)
	}
	if count < 1 && spend <= 0 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate needs count >= 1 and/or spend > 0 (count and spend are the escrowable axes)')
	}
	currency := authz_opt_str(cfg, 'currency', '')
	_, allocs, fault0 := authz_collect_raw(s)
	if f := fault0 {
		return f
	}
	if aid in allocs {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation `${aid}` already exists — allocation ids are single-use (reserve once, draw, expire)')
	}
	// headroom UNDER the commit path: fold the parent-visible events at the
	// reservation instant and walk the from-chain (the same walk debit runs).
	events, fault := authz_collect_debits(s)
	if f := fault {
		return f
	}
	at := authz_opt_str(cfg, 'at', '')
	mut eff_secs := i64(0)
	if at != '' {
		eff_secs = authz_secs_of(cx.ScalarNode{
			value:     cx.ScalarValue(at)
			data_type: .string_type
		})
	} else {
		for e in events {
			if e.ts_secs > eff_secs {
				eff_secs = e.ts_secs
			}
		}
	}
	// #1024: fold + index, one bracket. Once `byid` holds the records the chain
	// walk below touches no array — the records are stable heap objects — so the
	// headroom walk (which returns from inside) runs OUTSIDE the bracket and
	// cannot leak it.
	authz_grants_rlock()
	folded := authz_meter_fold(s, events, eff_secs)
	mut byid := map[string]&AuthzDelegation{}
	for d in s.delegations {
		byid[d.id] = d
	}
	authz_grants_runlock()
	mut cur := byid[from] or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocate names an unknown parent delegation `${from}`')
	}
	mut seen := map[string]bool{}
	for {
		if seen[cur.id] {
			break
		}
		seen[cur.id] = true
		if cur.has_bounds {
			st := folded[cur.id] or { AuthzMeterState{} }
			if cur.b_count > 0 && count > 0 && st.count_used + count > cur.b_count {
				return authz_debit_deny('count', cur.id, 0)
			}
			if cur.b_spend_per > 0 && spend > 0 && st.spend_used + spend > cur.b_spend_amt {
				return authz_debit_deny('spend', cur.id, 0)
			}
		}
		if cur.attenuates == '' {
			break
		}
		cur = byid[cur.attenuates] or { break }
	}
	mut attrs := [
		cx.Attribute{
			name:  'alloc'
			value: cx.ScalarValue(aid)
		},
		cx.Attribute{
			name:  'from'
			value: cx.ScalarValue(from)
		},
	]
	if count > 0 {
		attrs << cx.Attribute{
			name:  'count'
			value: cx.ScalarValue(count)
		}
	}
	if spend > 0 {
		attrs << cx.Attribute{
			name:  'spend'
			value: cx.ScalarValue(spend)
		}
	}
	if currency != '' {
		attrs << cx.Attribute{
			name:  'currency'
			value: cx.ScalarValue(currency)
		}
	}
	ev := cx.Node(cx.Element{
		name:  'authz-allocated'
		attrs: attrs
	})
	if fault2 := authz_journal_append(s, ev, authz_opt_str(cfg, 'actor', 'escrow'),
		from, at)
	{
		return fault2
	}
	return cx.Node(cx.Element{
		name:  'allocated'
		attrs: attrs
	})
}

// authz_allocation_expire_impl — `[$authz:allocation-expire store alloc-id
// opts?]`: journal the reclaim. The un-drawn remainder returns to the
// parent's availability (never replenishment — it never left the window's
// budget); typically armed via a sched durable timer.
fn authz_allocation_expire_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation-expire expects (store, alloc-id, opts?)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation-expire expects an open [authz-store] handle')
	}
	if !s.has_journal {
		return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: allocation-expire needs the journal-bound (durable) tier (§3.8)')
	}
	aid := authz_arg_str(args[1]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation-expire expects an allocation id string')
	}
	_, allocs, fault := authz_collect_raw(s)
	if f := fault {
		return f
	}
	a := allocs[aid] or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation-expire names an unknown allocation `${aid}`')
	}
	if a.expired {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation `${aid}` is already expired')
	}
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	ev := cx.Node(cx.Element{
		name:  'authz-allocation-expired'
		attrs: [
			cx.Attribute{
				name:  'alloc'
				value: cx.ScalarValue(aid)
			},
		]
	})
	if fault2 := authz_journal_append(s, ev, authz_opt_str(cfg, 'actor', 'escrow'),
		a.from, authz_opt_str(cfg, 'at', ''))
	{
		return fault2
	}
	return cx.Node(cx.Element{
		name:  'allocation-expired'
		attrs: [
			cx.Attribute{
				name:  'alloc'
				value: cx.ScalarValue(aid)
			},
			cx.Attribute{
				name:  'reclaimed-count'
				value: cx.ScalarValue(a.count_res - a.count_drawn)
			},
			cx.Attribute{
				name:  'reclaimed-spend'
				value: cx.ScalarValue(a.spend_res - a.spend_drawn)
			},
		]
	})
}

fn authz_debit_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit expects (store, id)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: debit on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit expects an open [authz-store] handle')
		}
	}
	if !s.has_journal {
		return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: debit needs the journal-bound (durable) tier — an unbound store has no commit point (§3.8; a meter that resets on restart is not a budget, L112)')
	}
	id := authz_arg_str(args[1]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit expects a delegation id string')
	}
	// #1024: the id lookup is the basis walk; `rec` is carried past the release
	// (stable heap record) and the journal folds below stay outside the bracket.
	authz_grants_rlock()
	target := authz_find_rec(s, id)
	authz_grants_runlock()
	rec := target or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit names an unknown delegation `${id}`')
	}
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	mut count := i64(1)
	if cn := cfg['count'] {
		if cn is cx.ScalarNode {
			cv := cn.value
			if cv is i64 {
				count = cv
			}
		}
	}
	if count < 1 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit count must be >= 1 — budgets meter authority exercised, refunds never credit back (L112)')
	}
	mut spend := f64(0)
	mut has_spend := false
	if sn := cfg['spend'] {
		spend = authz_node_f64(sn)
		has_spend = true
	}
	if has_spend && spend <= 0 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit spend must be > 0 — budgets meter authority exercised, refunds never credit back (L112)')
	}
	currency := authz_opt_str(cfg, 'currency', '')
	at := authz_opt_str(cfg, 'at', '')
	// Escrow draw (stream 10, §3): a debit naming opts.allocation draws
	// the RESERVED allocation — one draw, one meter (the parent was
	// debited at reservation; drawing it again would double-count). The
	// remainder checks at THIS commit; the deny names the failing
	// conjunct.
	alloc_id := authz_opt_str(cfg, 'allocation', '')
	if alloc_id != '' {
		_, allocs, afault := authz_collect_raw(s)
		if f := afault {
			return f
		}
		a := allocs[alloc_id] or {
			return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit names an unknown allocation `${alloc_id}`')
		}
		if a.expired {
			return authz_debit_deny('allocation-expired', alloc_id, 0)
		}
		if a.from != id {
			return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: allocation `${alloc_id}` reserves from `${a.from}`, not `${id}` — a draw names its own meter')
		}
		if a.count_res > 0 && a.count_drawn + count > a.count_res {
			return authz_debit_deny('allocation-count', alloc_id, 0)
		}
		if a.spend_res > 0 && has_spend && a.spend_drawn + spend > a.spend_res {
			return authz_debit_deny('allocation-spend', alloc_id, 0)
		}
		mut aattrs := [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue(id)
			},
			cx.Attribute{
				name:  'alloc'
				value: cx.ScalarValue(alloc_id)
			},
			cx.Attribute{
				name:  'count'
				value: cx.ScalarValue(count)
			},
		]
		if has_spend {
			aattrs << cx.Attribute{
				name:  'spend'
				value: cx.ScalarValue(spend)
			}
		}
		if currency != '' {
			aattrs << cx.Attribute{
				name:  'currency'
				value: cx.ScalarValue(currency)
			}
		}
		aev := cx.Node(cx.Element{
			name:  'authz-debited'
			attrs: aattrs
		})
		if fault3 := authz_journal_append(s, aev, authz_opt_str(cfg, 'actor', 'escrow'),
			id, at)
		{
			return fault3
		}
		return cx.Node(cx.Element{
			name:  'debited'
			attrs: aattrs
		})
	}
	// Headroom re-check UNDER the commit path (R11): fold at the debit's
	// effective instant, then verify every bounds-bearing chain link
	// admits this charge.
	events, fault := authz_collect_debits(s)
	if f := fault {
		return f
	}
	mut eff_secs := i64(0)
	if at != '' {
		eff_secs = authz_secs_of(cx.ScalarNode{
			value:     cx.ScalarValue(at)
			data_type: .string_type
		})
	} else {
		for e in events {
			if e.ts_secs > eff_secs {
				eff_secs = e.ts_secs
			}
		}
	}
	// #1024: fold + index under one bracket; the headroom chain walk below reads
	// only `byid`/`folded` and returns from inside, so it runs after the release.
	authz_grants_rlock()
	folded := authz_meter_fold(s, events, eff_secs)
	mut byid := map[string]&AuthzDelegation{}
	for d in s.delegations {
		byid[d.id] = d
	}
	authz_grants_runlock()
	mut cur := rec
	mut seen := map[string]bool{}
	for {
		if seen[cur.id] {
			break
		}
		seen[cur.id] = true
		if cur.has_bounds {
			st := folded[cur.id] or { AuthzMeterState{
				tokens: f64(cur.b_rate_n)
			} }
			if cur.b_count > 0 && st.count_used + count > cur.b_count {
				return authz_debit_deny('count', cur.id, 0)
			}
			if cur.b_rate_per > 0 && st.tokens < f64(count) {
				raf := (f64(count) - st.tokens) * f64(cur.b_rate_per) / f64(cur.b_rate_n)
				mut ra := i64(raf)
				if f64(ra) < raf {
					ra++
				}
				if ra < 1 {
					ra = 1
				}
				return authz_debit_deny('rate', cur.id, ra)
			}
			if cur.b_has_spend && has_spend {
				if currency != cur.b_spend_cur {
					return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: debit currency `${currency}` does not match the declared spend currency `${cur.b_spend_cur}` (§2.2)')
				}
				if st.spend_used + spend > cur.b_spend_amt {
					return authz_debit_deny('spend', cur.id, 0)
				}
			}
		}
		if cur.attenuates == '' {
			break
		}
		cur = byid[cur.attenuates] or { break }
	}
	// Append the transition event (journal-FIRST is trivially true here —
	// a debit has no in-process mutation; the log IS the meter).
	mut ev_attrs := [
		cx.Attribute{
			name:  'id'
			value: cx.ScalarValue(id)
		},
		cx.Attribute{
			name:  'count'
			value: cx.ScalarValue(count)
		},
	]
	if has_spend {
		sn := authz_float(spend)
		if sn is cx.ScalarNode {
			ev_attrs << cx.Attribute{
				name:  'spend'
				value: sn.value
			}
		}
		ev_attrs << cx.Attribute{
			name:  'currency'
			value: cx.ScalarValue(currency)
		}
	}
	event := cx.Node(cx.Element{
		name:  'authz-debited'
		attrs: ev_attrs
	})
	if fault2 := authz_journal_append(s, event, rec.to_id, id, at) {
		return fault2
	}
	mut rc_items := [cx.Node(authz_kv('delegation', authz_str(id))),
		cx.Node(authz_kv('count', authz_int(count)))]
	if has_spend {
		rc_items << cx.Node(authz_kv('spend', authz_float(spend)))
		rc_items << cx.Node(authz_kv('currency', authz_str(currency)))
	}
	return cx.Element{
		name:  'debited'
		items: rc_items
	}
}

// ── §3.9 propose-mode disposition (stream 6 W6b, L113/L114) ──────────────────
//
// The engine constructs proposals (cx:propose); authz DISPOSES: `approve`
// mints the Lane-2 claim binding the proposal's Tier-1 ADDRESS (never a
// name or args — forgeable); `commit` verifies fail-closed and executes;
// `resolve-cap` resolves a cap: authority-artifact address against the
// LIVE registry view. Codes: CXER4714 (proposal invalid — address /
// version / tier / divergence), CXER4715 (propose-only basis at commit),
// CXER4716 (cap: unresolved).

// authz_approve_impl — `[$authz:approve store proposal opts]`. Builds
// `[approval [subject hash=…] [by …] [tier :tN] [signature …]]`. The
// signature is caller-supplied and verified per the SHIPPED tier posture
// (authz_signature_ok — T1 single, T2 M-of-N; crypto composes in
// deployment). The store handle pins the tenant partition.
fn authz_approve_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: approve expects (store, proposal)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: approve on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: approve expects an open [authz-store] handle')
		}
	}
	if args[1] !is cx.Element || (args[1] as cx.Element).name != 'proposal' {
		return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: approve expects a [proposal …] value (cx:propose) (cx-err:CXER4714)')
	}
	addr_n := code.value_tier1_address(args[1])
	if is_err_value(addr_n) {
		return authz_err_with_cause(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: the proposal has no Tier-1 address', addr_n)
	}
	addr := authz_scalar_text(addr_n)
	cfg := if args.len > 2 { authz_opts(args[2]) } else { map[string]cx.Node{} }
	by := authz_opt_str(cfg, 'by', '')
	if by == '' {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: approve requires opts.by (the approving principal)')
	}
	tier := authz_opt_str(cfg, 'tier', 't1')
	sig := authz_opt_str(cfg, 'signature', '')
	if sig == '' {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: approve requires opts.signature (suite slot mandatory — verifiers fail closed, L113)')
	}
	_ = s
	return cx.Element{
		name:  'approval'
		items: [
			cx.Node(cx.Element{
				name:  'subject'
				attrs: [
					cx.Attribute{
						name:  'hash'
						value: cx.ScalarValue(addr)
					},
				]
			}),
			cx.Node(authz_kv('by', authz_str(by))),
			cx.Node(authz_kv('tier', authz_atom(tier))),
			cx.Node(authz_kv('signature', authz_str(sig))),
		]
	}
}

// authz_chain_propose_only walks the [attenuates …] chain from `id`
// upward: any link carrying [propose-only] poisons the basis for
// COMMIT (inheritance is narrowing-only — a child of a propose-only
// parent is propose-only).
fn authz_chain_propose_only(s &AuthzStore, id string) bool {
	mut byid := map[string]&AuthzDelegation{}
	for d in s.delegations {
		byid[d.id] = d
	}
	mut cur := byid[id] or { return false }
	mut seen := map[string]bool{}
	for {
		if seen[cur.id] {
			return false
		}
		seen[cur.id] = true
		if cur.propose_only {
			return true
		}
		if cur.attenuates == '' {
			return false
		}
		cur = byid[cur.attenuates] or { return false }
	}
	return false
}

// authz_resolve_cap_impl — `[$authz:resolve-cap store 'cap:…' opts]`
// (L114): resolves an authority-artifact ADDRESS against the LIVE
// registry view — the artifact must exist, be un-revoked, and be
// un-expired at the resolution instant. FAIL-CLOSED: anything else is
// CXER4716 (a trust input that cannot be proven live is refused).
fn authz_resolve_cap_impl(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: resolve-cap expects (store, cap-ref)')
	}
	s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: resolve-cap on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: resolve-cap expects an open [authz-store] handle')
		}
	}
	refs := authz_arg_str(args[1]) or {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: resolve-cap expects a cap: reference string')
	}
	if !refs.starts_with('cap:') {
		return mk_err(authz_err_cap_unresolved, 'E_AUTHZ_CAP_UNRESOLVED: `${refs}` is not a cap: reference (governance §12.3) (cx-err:CXER4716)')
	}
	want := refs[4..] // the tagged address after the domain separator
	now_secs := authz_store_clock(args, 2)
	// #1024: the walk is bracketed, and it MATCHES ONLY — every `return` that used
	// to sit inside the loop moved out below it. A read bracket with returns inside
	// leaks the lock on the way out, and a leaked read lock is worse than no lock:
	// the next dial blocks forever instead of racing. The bracket therefore has
	// exactly one exit, and the fail-closed dispositions are decided after it on
	// the matched record (stable heap object — safe to read unbracketed).
	mut hit := &AuthzDelegation(unsafe { nil })
	authz_grants_rlock()
	for d in s.delegations {
		addr_n := code.value_tier1_address(d.value)
		if is_err_value(addr_n) {
			continue
		}
		if authz_scalar_text(addr_n) != want {
			continue
		}
		hit = d
		break
	}
	authz_grants_runlock()
	if hit == unsafe { nil } {
		return mk_err(authz_err_cap_unresolved, 'E_AUTHZ_CAP_UNRESOLVED: `${refs}` resolves to no live authority artifact in tenant `${s.tenant}` (cx-err:CXER4716)')
	}
	if hit.revoked {
		return mk_err(authz_err_cap_unresolved, 'E_AUTHZ_CAP_UNRESOLVED: `${refs}` names a REVOKED grant — fail-closed (cx-err:CXER4716)')
	}
	if hit.until_secs > 0 && now_secs > 0 && now_secs > hit.until_secs {
		return mk_err(authz_err_cap_unresolved, 'E_AUTHZ_CAP_UNRESOLVED: `${refs}` names an EXPIRED grant — fail-closed (cx-err:CXER4716)')
	}
	return authz_materialize_delegation(hit)
}

// authz_commit_impl — `[$authz:commit store proposal approval command
// opts]` (env-aware; R17): the fail-closed disposition chain, in order:
// (a) the proposal re-hashes to the approval's subject; (c) the
// approval verifies per its tier (the shipped posture); (d) no
// propose-only link grounds a commit (opts.basis names the presented
// delegation); [requires 'cap:…'] clauses re-resolve fail-closed;
// then the ENGINE half (b/e/i — version binding, precondition
// re-evaluation, execution: code.command_commit_execute); (h) an
// opts.debit charges the meter under the stream's commit lock; (j) the
// committed transition is journaled with actor + authority basis.
fn authz_commit_impl(args []cx.Node, mut env code.MatchEnv) cx.Node {
	if args.len < 4 {
		return mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: commit expects (store, proposal, approval, command)')
	}
	mut s := authz_store_from_arg(args[0]) or {
		return if err.msg() == 'closed' {
			mk_err(authz_err_handle_closed, 'E_AUTHZ_HANDLE_CLOSED: commit on a closed authority store')
		} else {
			mk_err(authz_err_arg_invalid, 'E_AUTHZ_ARG_INVALID: commit expects an open [authz-store] handle')
		}
	}
	if !s.has_journal {
		return mk_err(authz_err_store_fault, 'E_AUTHZ_STORE_FAULT: commit needs the journal-bound (durable) tier — no commit point without the trust log (§3.9)')
	}
	if args[1] !is cx.Element || (args[1] as cx.Element).name != 'proposal' {
		return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: commit expects a [proposal …] value (cx-err:CXER4714)')
	}
	proposal := args[1] as cx.Element
	// (a) address binding: the proposal re-hashes to the approval subject.
	addr_n := code.value_tier1_address(args[1])
	if is_err_value(addr_n) {
		return authz_err_with_cause(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: the proposal has no Tier-1 address', addr_n)
	}
	paddr := authz_scalar_text(addr_n)
	if args[2] !is cx.Element || (args[2] as cx.Element).name != 'approval' {
		return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: commit expects an [approval …] claim (cx-err:CXER4714)')
	}
	approval := args[2] as cx.Element
	mut subj := ''
	mut appr_by := ''
	mut appr_tier := 't1'
	for it in approval.items {
		if it is cx.Element {
			match it.name {
				'subject' {
					for a in it.attrs {
						if a.name == 'hash' {
							subj = cx.scalar_value_str_public(a.value)
						}
					}
				}
				'by' {
					if it.items.len == 1 {
						appr_by = authz_scalar_text(it.items[0])
					}
				}
				'tier' {
					if it.items.len == 1 {
						appr_tier = authz_scalar_text(it.items[0]).trim_left(':')
					}
				}
				else {}
			}
		}
	}
	if subj == '' || subj != paddr {
		return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: the approval binds address `${subj}` but the presented proposal re-hashes to `${paddr}` — a re-lowered/tampered proposal is a DIFFERENT proposal (L113/L139) (cx-err:CXER4714)')
	}
	// (c) approval verification per its tier — the shipped posture.
	if appr_tier == 't1' || appr_tier == 't2' {
		if !authz_signature_ok(approval, appr_tier) {
			return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: approval ${appr_tier} signature verification failed — verifiers fail closed (L113) (cx-err:CXER4714)')
		}
	}
	cfg := if args.len > 4 { authz_opts(args[4]) } else { map[string]cx.Node{} }
	// (d) propose-only screening over the presented basis chain.
	//
	// #1024: this is commit's ONLY read of the delegation basis, and it is the only
	// thing here that may be bracketed. Everything below re-enters: the [requires
	// 'cap:…'] loop calls authz_resolve_cap_impl and the (h) debit calls
	// authz_debit_impl — both verbs that take this same read lock — and
	// code.command_commit_execute runs arbitrary CX, which can reach ANY authz
	// verb including [$authz:delegate] and its WRITE lock. A whole-verb bracket
	// here self-deadlocks on the first nested read (a pthread rwlock does not
	// nest) and deadlocks outright on a nested write. So: one bracket, one call.
	basis := authz_opt_str(cfg, 'basis', '')
	mut basis_propose_only := false
	if basis != '' {
		authz_grants_rlock()
		basis_propose_only = authz_chain_propose_only(s, basis)
		authz_grants_runlock()
	}
	if basis_propose_only {
		return mk_err(authz_err_propose_only, 'E_AUTHZ_PROPOSE_ONLY: delegation `${basis}` (or an ancestor) is propose-only — it can ground a proposal but never a commit (L113) (cx-err:CXER4715)')
	}
	// [requires 'cap:…'] clauses re-resolve fail-closed at commit (L114).
	for it in proposal.items {
		if it is cx.Element && it.name == 'requires' {
			for r in it.items {
				rs := authz_scalar_text(r)
				if rs.starts_with('cap:') {
					rr := authz_resolve_cap_impl([args[0], cx.Node(authz_str(rs))])
					if is_err_value(rr) {
						return rr
					}
				}
			}
		}
	}
	// engine VERIFY pass: version binding + precondition re-check (the
	// M5 order — a refused commit exercises no authority: no debit, no
	// body; W7 fix, authz-083 pins it with the exec counter).
	vres := code.command_commit_execute(args[3], proposal, true, false, mut env)
	if vres.refusal != '' {
		if vres.refusal == 'not-command' {
			return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: the presented value is not a command definition (cx-err:CXER4714)')
		}
		if vres.refusal == 'version-mismatch' {
			return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: the presented command definition does not match the approved Tier-1 def-text address — commit runs the EXACT approved version (L139) (cx-err:CXER4714)')
		}
		return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: ${vres.refusal} — commit re-checks live facts (L113) (cx-err:CXER4714)')
	}
	// [requires-at] (stream 10, L156/M26): the B3 ADMISSION read, at the
	// commit point, before any authority is exercised — the target
	// stream's head at-or-past the pinned seq with the entry
	// hash-matching, else CXER4950 (the commit refused, no debit, no
	// body). Admission is bracketed around the execute pass and never
	// outlives this commit.
	mut pin_src := ''
	if strm, pseq, phash := code.command_pin_of(args[3], mut env) {
		if refusal := coord_pin_check(s.journal_handle, strm, pseq, phash) {
			return refusal
		}
		if sa := code.command_pin_src_addr(args[3], mut env) {
			pin_src = sa
		}
	}
	// (h) the commit-point debit, under the stream's commit lock —
	// BEFORE the body runs (M5: "debits the spend meter under the
	// stream's commit lock"): an exhausted meter refuses with the body
	// never executed and no dedup record written.
	if dn := cfg['debit'] {
		if dn is cx.Element && dn.name == '__cx_map__' {
			dcfg := authz_opts(dn)
			did := authz_opt_str(dcfg, 'id', basis)
			mut d_args := [args[0], cx.Node(authz_str(did))]
			d_args << dn
			dr := authz_debit_impl(d_args)
			if is_err_value(dr) || (dr is cx.Element && (dr as cx.Element).name == 'deny') {
				return dr
			}
		}
	}
	// engine EXECUTE pass (preconditions already checked — once). The
	// pin admission brackets EXACTLY this call — set after every refusal
	// path (debit included), cleared before any return.
	if pin_src != '' {
		code.command_pin_admit(mut env, pin_src)
	}
	res := code.command_commit_execute(args[3], proposal, false, true, mut env)
	if pin_src != '' {
		code.command_pin_clear(mut env, pin_src)
	}
	if res.refusal != '' {
		return mk_err(authz_err_proposal, 'E_AUTHZ_PROPOSAL_INVALID: ${res.refusal} (cx-err:CXER4714)')
	}
	// (j) journal the committed transition — actor + authority basis.
	actor := authz_opt_str(cfg, 'actor', appr_by)
	authority := if basis != '' { basis } else { 'principal' }
	ev := cx.Node(cx.Element{
		name:  'command-committed'
		attrs: [
			cx.Attribute{
				name:  'proposal'
				value: cx.ScalarValue(paddr)
			},
		]
	})
	if fault := authz_journal_append(s, ev, actor, authority, authz_opt_str(cfg, 'at', '')) {
		return fault
	}
	return res.outcome
}

// authz_stdlib_builtin_env is the env-aware authz dispatcher (commit
// executes the command body — it needs the evaluator). Registered via
// ring2_env_register_main (ring2_register.v).
pub fn authz_stdlib_builtin_env(name string, args []cx.Node, mut env code.MatchEnv) ?cx.Node {
	match name {
		'authz-commit' { return authz_commit_impl(args, mut env) }
		else { return none }
	}
}
