@[has_globals]
module code

import cx

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
}

@[heap]
struct AuthzStore {
mut:
	tenant      string
	is_open     bool
	delegations []&AuthzDelegation // in receive order
}

@[heap]
struct AuthzRegistry {
mut:
	stores  map[int]&AuthzStore
	next_id int
}

__global (
	g_authz_reg voidptr
)

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
		return dt.instant_ns() / ns_per_s
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
	s := &AuthzStore{
		tenant:      tenant
		is_open:     true
		delegations: []&AuthzDelegation{}
	}
	id := authz_register(s)
	return authz_store_element(id, s)
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
	return true
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
	// attenuation — privilege escalation is structurally impossible (§4.2).
	if !authz_attenuation_ok(s, rec, now_secs) {
		return mk_err(authz_err_escalation, 'E_AUTHZ_ESCALATION: the grant conveys more than the issuer holds (attenuation violation, §4.2)')
	}
	s.delegations << rec
	// (record an attributed issue-event — a real deployment appends via
	// [$journal:append …]; the in-memory store IS the attributed log here.)
	return authz_materialize_delegation(rec)
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
	mut rec := authz_find_rec(s, id) or {
		// Idempotent: revoking an absent id is a no-op → absence (§2.5/§3.2).
		return authz_absence()
	}
	if rec.revoked {
		// already revoked → absence (revocation is absence for check, §2.5).
		return authz_absence()
	}
	rec.revoked = true
	if cascade {
		authz_revoke_cascade(mut s, id)
	}
	return authz_materialize_delegation(rec)
}

fn authz_revoke_cascade(mut s AuthzStore, parent_id string) {
	for mut d in s.delegations {
		if d.attenuates == parent_id && !d.revoked {
			d.revoked = true
			authz_revoke_cascade(mut s, d.id)
		}
	}
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
	now_secs := authz_store_clock(args, 2)
	if !authz_attenuation_ok(s, rec, now_secs) {
		return mk_err(authz_err_escalation, 'E_AUTHZ_ESCALATION: the guardian action conveys more than the grantor holds (§4.2)')
	}
	// store dormant-until-gate (§3.3).
	s.delegations << rec
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
	decision := authz_decide(s, req, cfg)
	if strict && authz_opt_bool(cfg, 'raise-on-deny', false) {
		if decision is cx.Element && (decision as cx.Element).name == 'deny' {
			return authz_err_with_cause(authz_err_unauthorized, 'E_AUTHZ_UNAUTHORIZED: authorization denied (raise-on-deny)', decision)
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
	mut best_reason := 'no-grant'
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
		// PERMIT.
		return authz_permit(d, via, r)
	}
	return authz_deny(r, best_reason, cx.Node(cx.Element{}))
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
	rec := authz_find_rec(s, id) or { return authz_absence() }
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
	for d in s.delegations {
		if d.revoked {
			continue
		}
		if d.to_id == actor_id && (d.to_kind == '' || actor_kind == '' || d.to_kind == actor_kind) {
			out << authz_materialize_delegation(d)
		}
	}
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
	allowed := authz_effective_set(s, actor_kind, actor_id, cfg)
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
	if d.guardian {
		items << cx.Node(authz_kv('dormant-until-gate', authz_bool(true)))
	}
	return cx.Element{
		name:  'delegation'
		attrs: attrs
		items: items
	}
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
	mut items := [
		cx.Node(authz_kv('code', authz_str(authz_err_unauthorized))),
		cx.Node(authz_kv('reason', authz_atom(reason))),
		cx.Node(authz_kv('capability', authz_str(r.capability))),
	]
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
