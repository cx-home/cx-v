@[has_globals]
module code

import sync

import cx

// stdlib_caps.v — capability-based effect enforcement (spec/core/security.md).
//
// A CX evaluation runs under an explicit capability set; deny-by-default
// (no ambient authority). Any operation with external effect checks the
// active set at the effect point and raises E_CAP_DENIED (CXER0271) when
// the matching capability is absent — fail-closed, BEFORE any type/domain
// validation (§4).
//
// v1 carries the active set in a process-global behind a nil-default
// `voidptr` (the proven store/random pattern — `@[has_globals]` enables
// module-level state without the -enable-globals flag). nil = the empty
// set = pure-only (deny everything effectful). The host/CLI/runner sets it
// via the public `caps_set_*` surface before eval; `[?with-caps]` narrows
// it for a dynamic extent via save/restore.
//
// SCOPING (§6 C1, coarse v1): path roots / host globs / env names /
// executables are carried but enforced lazily as each domain lands; the
// boolean grant is the v1 gate.
//
// NORMALIZATION (L104, #713 item 3): the `--allow-all` opt-out is NOT a
// distinct state — it normalizes to the explicit full nine-grant set plus
// the `private_range_allowed` policy field (the one behavior the opt-out
// adds: bypassing the §4.5 private-range deny set). One canonical form,
// not two — load-bearing for the C4 caps-as-CX-value and the stream-5
// computation record.
//
// THREAD-SAFETY: the global is process-wide; parallel (`:par`) evaluation
// shares it. v1 enforcement targets the single-threaded conformance +
// CLI path. A per-evaluation (env-threaded) set is the documented
// follow-up if parallel effect isolation is needed.

const cap_denied_code = 'cx-err:CXER0271'

@[heap]
struct CapSet {
mut:
	// private_range_allowed is the L104 private-range-policy field: the
	// §4.5 private-range deny set is bypassed (the --allow-all opt-out's
	// one extra behavior beyond the explicit full grant set). Never set
	// by an explicit grant list; cleared by any narrowing.
	private_range_allowed bool
	read          bool
	write         bool
	net           bool
	env           bool
	clock         bool
	random        bool
	subprocess    bool
	eval          bool
	secret_reveal bool
	// coarse scopes (v1: carried, not yet all enforced)
	read_roots  []string
	write_roots []string
	net_hosts   []string
	env_names   []string
	exec_allow  []string
}

__global (
	g_active_caps voidptr
)

// caps_set_empty installs the empty (deny-all / pure-only) set — the
// spec default. Effectful operations raise CXER0271 until a grant lands.
pub fn caps_set_empty() {
	g_active_caps = unsafe { nil }
}

// caps_set_all installs a full grant (the `--allow-all` opt-out, and the
// conformance runner's grant for non-deny behavior cases). L104: the
// opt-out NORMALIZES to the explicit nine-grant set + the private-range
// policy field — there is no distinct allow-all state.
pub fn caps_set_all() {
	mut c := &CapSet{
		private_range_allowed: true
	}
	for cap in capability_names() {
		set_cap_flag(mut c, cap, true)
	}
	g_active_caps = voidptr(c)
}

// caps_set_list installs an explicit least-privilege set granting exactly
// the named capabilities (Effort B per-fixture `[grant …]`). An unknown
// name is a LOUD typed error (CXER0274, #713 — never a silent no-grant:
// a typo'd grant that silently denies makes denial fixtures false-green)
// and the active set is NOT modified. The empty list is equivalent to
// `caps_set_empty`.
pub fn caps_set_list(caps []string) ! {
	mut c := &CapSet{}
	for cap in caps {
		if cap !in capability_names() {
			return error(cap_unknown_msg(cap))
		}
		set_cap_flag(mut c, cap, true)
	}
	g_active_caps = voidptr(c)
}

// cap_unknown_msg builds the E_CAP_UNKNOWN (CXER0274) refusal, naming the
// bad token and the full accepted set (§4 actionable error).
fn cap_unknown_msg(token string) string {
	return 'E_CAP_UNKNOWN: unknown capability grant name `${token}` — accepted: ${capability_names().join(', ')}, all (cx-err:CXER0274)'
}

// caps_set_net_hosts records host:port (or host-glob) scopes for the net grant
// (security.md §6 C1 coarse scoping; net.md §4.5 host-match + override). An empty
// list = the bare `--allow-net` grant (all hosts, but the §4.5 deny-set still
// applies on dial). No-op if no set is installed or it is allow-all.
pub fn caps_set_net_hosts(hosts []string) {
	if g_active_caps == unsafe { nil } {
		return
	}
	mut c := unsafe { &CapSet(g_active_caps) }
	if c.private_range_allowed {
		// the --allow-all opt-out form ignores later scoping (callers never
		// mix them; the guard keeps the invariant if one ever does).
		return
	}
	c.net_hosts = hosts.clone()
}

// cap_net_specs returns the granted net host scopes ([] = bare grant / all hosts).
fn cap_net_specs() []string {
	if g_active_caps == unsafe { nil } {
		return []
	}
	c := unsafe { &CapSet(g_active_caps) }
	return c.net_hosts.clone()
}

// cap_net_is_all reports whether the net grant is unscoped (bare --allow-net or
// allow-all) — i.e. step-1 host match is satisfied for any candidate.
fn cap_net_is_all() bool {
	if g_active_caps == unsafe { nil } {
		return false
	}
	c := unsafe { &CapSet(g_active_caps) }
	return c.net_hosts.len == 0
}

// cap_private_range_allowed reports whether the §4.5 private-range deny set is
// bypassed — the L104 policy field, set ONLY by the --allow-all opt-out and
// distinct from a merely unscoped net grant (bare --allow-net keeps the deny
// set: it is the secure default for any net grant absent a literal-IP scope —
// #47). Formerly `cap_allow_all` (the retired distinct allow-all state).
fn cap_private_range_allowed() bool {
	if g_active_caps == unsafe { nil } {
		return false
	}
	c := unsafe { &CapSet(g_active_caps) }
	return c.private_range_allowed
}

// caps_apply_spec installs the capability set described by a host grant
// spec string (the ABI `cx_code_eval_caps` `caps` arg / the CLI's combined
// `--allow-*` set). Deny-by-default: '' ⇒ empty (pure-only); 'all' / '*' ⇒
// full grant; otherwise a comma/space/tab-separated capability list.
// `cap=resource` is THE scope spelling (L114/#713: the former `cap:resource`
// token is GONE — `cap:` is the reserved capability-value address prefix,
// governance §12.3; one spelling, one meaning — a token containing `:` is
// refused, cutover-first, no dual-accept). An unknown capability name is a
// LOUD typed error (CXER0274). On any refusal the active set is NOT
// modified.
pub fn caps_apply_spec(spec string) ! {
	s := spec.trim_space()
	if s == '' {
		caps_set_empty()
		return
	}
	if s == 'all' || s == '*' {
		caps_set_all()
		return
	}
	mut caps := []string{}
	mut net_hosts := []string{}
	for tok in s.split_any(' \t,') {
		t := tok.trim_space()
		if t == '' {
			continue
		}
		if t.contains(':') && !t.all_before(':').contains('=') {
			// a `:` before any `=` is the retired `cap:resource` spelling —
			// it collides with the `cap:` address prefix (L114). Refuse and
			// name the one spelling.
			return error('E_CAP_UNKNOWN: grant token `${t}` uses the retired `:` scope spelling — scope with `cap=resource` (e.g. `net=${t.all_after(':')}`); the `cap:` spelling is reserved for capability-value addresses (L114) (cx-err:CXER0274)')
		}
		// split a `cap=resource` scope suffix → bare cap + scope.
		cap_name := t.all_before('=')
		if cap_name !in capability_names() {
			return error(cap_unknown_msg(cap_name))
		}
		// #1059's fail-open, on the ABI grant surface (the CLI's five parse
		// sites got the refusal; this is the sixth sibling): read/write/env
		// scoping is NOT IMPLEMENTED, so a `cap=resource` suffix on those
		// three refuses instead of silently installing BLANKET authority —
		// the caller asked for narrower and would have received wider, with
		// nothing to say so. Real path/name scoping is cx-home/cx-private#1061;
		// `net=host[:port]` is the one scope enforced today.
		if t.contains('=') && cap_name in ['read', 'write', 'env'] {
			return error('E_CAP_SCOPE_UNENFORCED: grant token `${t}` — ${cap_name} scoping is NOT IMPLEMENTED; the resource would be IGNORED and the grant would be BLANKET ${cap_name} authority, not the narrowing this spells. Grant the bare `${cap_name}` explicitly; real scoping is tracked at cx-home/cx-private#1061 (cx-err:CXER0274)')
		}
		caps << cap_name
		// A `net=<host>[:<port>]` token additionally records a host scope, so
		// the net grant is least-privilege (only the named host is dialable)
		// AND a literal-IP / `localhost` scope overrides the §4.5
		// private-range deny set (net.md §4.5; #47). A bare `net` stays
		// unscoped (all hosts; the deny set still applies on dial).
		if cap_name == 'net' && t.contains('=') {
			scope := t.all_after('=').trim_space()
			if scope != '' {
				net_hosts << scope
			}
		}
	}
	caps_set_list(caps)!
	if net_hosts.len > 0 {
		caps_set_net_hosts(net_hosts)
	}
}

// caps_snapshot / caps_restore support `[?with-caps]` narrowing: snapshot
// the active set, install a narrowed copy for the body, restore after.
fn caps_snapshot() voidptr {
	return g_active_caps
}

fn caps_restore(saved voidptr) {
	g_active_caps = saved
}

// ── §10.5.7.2 cancellation-revokes-capabilities (thread-scoped, #541) ────────
//
// Once a task is cancelled its capability set narrows to EMPTY for the
// remainder of the task. The lazy substrate narrowed the global set around
// the (single-threaded) drive; with eager spawned futures the narrowing
// must be per-thread: the future's thread id registers here when its
// cancel flag is raised, and cap_allowed denies everything on a revoked
// thread. The registry entry clears when the thread publishes its
// terminal state (run_future_thread's defer). Cancellation POINTS still
// observe the flag FIRST and report CXER0260 — the §10.5.7.2 precedence
// is theirs; this is the backstop for raw effects reached between points.
const g_revoked_tids_lock = &sync.RwMutex(sync.new_rwmutex())

__global (
	g_revoked_tids map[u64]bool
)

pub fn cap_thread_id() u64 {
	return u64(C.pthread_self())
}

pub fn caps_revoke_thread(tid u64) {
	mut l := unsafe { g_revoked_tids_lock }
	l.lock()
	defer { l.unlock() }
	g_revoked_tids[tid] = true
}

pub fn caps_unrevoke_thread(tid u64) {
	mut l := unsafe { g_revoked_tids_lock }
	l.lock()
	defer { l.unlock() }
	g_revoked_tids.delete(tid)
}

fn cap_thread_revoked() bool {
	mut l := unsafe { g_revoked_tids_lock }
	l.rlock()
	defer { l.runlock() }
	if g_revoked_tids.len == 0 {
		return false
	}
	return cap_thread_id() in g_revoked_tids
}

// cap_allowed reports whether `capability` is granted by the active set.
// nil set (empty/default) denies everything.
fn cap_allowed(capability string) bool {
	if cap_thread_revoked() {
		return false // §10.5.7.2 — cancelled task, capability set is EMPTY
	}
	if g_active_caps == unsafe { nil } {
		return false
	}
	c := unsafe { &CapSet(g_active_caps) }
	return match capability {
		'read' { c.read }
		'write' { c.write }
		'net' { c.net }
		'env' { c.env }
		'clock' { c.clock }
		'random' { c.random }
		'subprocess' { c.subprocess }
		'eval' { c.eval }
		'secret-reveal' { c.secret_reveal }
		else { false }
	}
}

// cap_deny builds the spec E_CAP_DENIED (CXER0271) err VALUE, naming the
// missing capability + the requested resource (§4 actionable error).
fn cap_deny(capability string, resource string) cx.Node {
	return mk_err(cap_denied_code, 'E_CAP_DENIED: ${capability} capability required for ${resource}; none granted (grant via --allow-${capability})')
}

// cap_guard returns the denial err VALUE when `capability` is not granted,
// or none when the effect may proceed. Effect points call:
//   if d := cap_guard('env', name) { return d }
pub fn cap_guard(capability string, resource string) ?cx.Node {
	if cap_allowed(capability) {
		// The one choke point every §2.1 effect point crosses: an
		// ADMITTED effect records on the out-effects witness trace
		// (stream 22 W1 — order and count become corpus-checkable).
		effects_trace_record(capability, resource)
		return none
	}
	return cap_deny(capability, resource)
}

// cap_current_flags materialises the active set as an explicit-boolean
// CapSet value — expanding the two implicit forms (nil = empty/deny-all,
// allow_all = grant-all) into concrete per-capability bools. This is the
// basis for `[?with-caps]` narrowing: we need a concrete set to clear
// individual capabilities from, even when the inherited set is implicit.
fn cap_current_flags() CapSet {
	caps := ['read', 'write', 'net', 'env', 'clock', 'random', 'subprocess',
		'eval', 'secret-reveal']
	mut c := CapSet{}
	for cap in caps {
		set_cap_flag(mut c, cap, cap_allowed(cap))
	}
	// Preserve carried scopes from the current explicit set (if any) so a
	// narrowing that does not touch a scoped capability keeps its scope.
	if g_active_caps != unsafe { nil } {
		cur := unsafe { &CapSet(g_active_caps) }
		c.private_range_allowed = cur.private_range_allowed
		c.read_roots = cur.read_roots.clone()
		c.write_roots = cur.write_roots.clone()
		c.net_hosts = cur.net_hosts.clone()
		c.env_names = cur.env_names.clone()
		c.exec_allow = cur.exec_allow.clone()
	}
	return c
}

// set_cap_flag sets one capability bool on a CapSet by name.
// capability_names returns every capability name the grant surface accepts
// (`--allow-<name>` on the CLI, `[grant ...]` in fixtures). The CLI help is
// generated from THIS list (vcx/cmd/main.v usage_text, #417) so the
// documented set cannot drift from the accepted set — keep it in lockstep
// with the set_cap_flag match below (same names, same order as the CapSet
// fields).
pub fn capability_names() []string {
	return ['read', 'write', 'net', 'env', 'clock', 'random', 'subprocess', 'eval', 'secret-reveal']
}

// common_capability_names is `capability_names()` MINUS `secret-reveal` —
// the grant set behind `--allow-common` (RULED 833-1a).
//
// It exists because there was no broad grant a guide could recommend.
// Capabilities are deny-by-default, so any effectful script needs grants,
// and the one broad grant CX shipped was `--allow-all` — which includes
// `secret-reveal`, the capability that DECLASSIFIES a secret value
// (security.md §45, cxdm.md §12). A getting-started page cannot hand a
// newcomer the flag that also turns off secret protection, so the docs were
// left enumerating capabilities per example.
//
// This is a grant-set convenience and nothing more: no new capability, no
// change to the capability model, no evaluation / identity / canonical-form
// consequence. In particular `--allow-all` keeps its exact behaviour — it
// is load-bearing for the concurrency soundness gate (which starts servers
// with it) and the release path (which publishes the registry with it), and
// five test files assert on its exact combined stdout+stderr.
//
// The name says what the set IS — the common working set — rather than
// claiming "safe" or "dev-only", neither of which it guarantees: everything
// in it is still an effect, and a script granted `write` + `net` can still
// do real damage. What it guarantees is narrower and checkable: a secret
// stays sealed.
pub fn common_capability_names() []string {
	return capability_names().filter(it != 'secret-reveal')
}

// caps_set_common installs the `--allow-common` set: every capability in
// the common working set, and NOT `secret-reveal` — so a declassification
// under this grant refuses with CXER0271 exactly as it does under an
// explicit least-privilege set.
//
// `private_range_allowed` stays FALSE. That field is `--allow-all`'s one
// behaviour beyond the explicit full grant set (L104), and the rule on it is
// "never set by an explicit grant list; cleared by any narrowing" —
// `--allow-common` is a narrowing. So `--allow-all` remains strictly wider
// than every other grant in exactly the way the capabilities guide already
// documents, and a broad grant we are about to RECOMMEND does not quietly
// open the §4.5 private-range deny set. A local-service example asks for the
// scope it needs (`--allow-net=127.0.0.1:PORT`), which is the narrower and
// more honest thing for a tutorial to teach anyway.
pub fn caps_set_common() {
	mut c := &CapSet{}
	for cap in common_capability_names() {
		set_cap_flag(mut c, cap, true)
	}
	g_active_caps = voidptr(c)
}

fn set_cap_flag(mut c CapSet, capability string, val bool) {
	match capability {
		'read' { c.read = val }
		'write' { c.write = val }
		'net' { c.net = val }
		'env' { c.env = val }
		'clock' { c.clock = val }
		'random' { c.random = val }
		'subprocess' { c.subprocess = val }
		'eval' { c.eval = val }
		'secret-reveal' { c.secret_reveal = val }
		else {}
	}
}

// caps_push_effects_narrowed installs a KEEP-ONLY narrowed copy of the
// active set for a command body's dynamic extent (code.md §12.2.7,
// stream 6 L110): every capability NOT in the def's declared
// `[effects …]` set is cleared, so the body runs under
// (caller's grant ∩ declared set). Strictly a narrowing — a declared
// capability the caller did NOT grant stays denied (cap_current_flags
// materializes only granted caps). The private-range policy field
// clears (interior set, the L104 rule). Returns the prior pointer for
// caps_restore, exactly like caps_push_narrowed.
fn caps_push_effects_narrowed(allowed []string) voidptr {
	saved := g_active_caps
	mut c := cap_current_flags()
	c.private_range_allowed = false
	for cap in capability_names() {
		if cap !in allowed {
			set_cap_flag(mut c, cap, false)
		}
	}
	nc := &CapSet{
		...c
	}
	g_active_caps = voidptr(nc)
	return saved
}

// caps_push_narrowed installs a NARROWED copy of the active set with each
// capability in `denied` cleared (spec/core/security.md §3 — in-program
// narrowing is deny-only; a program can never widen). Returns the prior
// `g_active_caps` pointer so the caller restores it via `caps_restore`
// after the `[?with-caps]` body's dynamic extent (including on error).
fn caps_push_narrowed(denied []string) voidptr {
	saved := g_active_caps
	mut c := cap_current_flags()
	// a narrowed set never bypasses the private-range deny set (L104: the
	// policy field belongs to the host opt-out, not to any interior set).
	c.private_range_allowed = false
	for d in denied {
		set_cap_flag(mut c, d, false)
	}
	nc := &CapSet{
		...c
	}
	g_active_caps = voidptr(nc)
	return saved
}

// ── C4: the capability set as a CX value (L104, #713 item 5) ─────────────────
//
// security.md C4: the ACTIVE set is exposed as an introspectable CX value —
// a canonical map over the closed nine-name list. Canonical form (L104):
//   - granted-unscoped capability  → `true`
//   - granted-scoped capability    → a SORTED sequence of canonicalized
//     scope strings (host globs lower-cased; path roots trailing-slash
//     normalized; env names / executables sorted case-sensitively)
//   - ungranted capability         → ABSENT (the canonical minimal form)
//   - the private-range-policy field (`private-range-allowed: true`) rides
//     ONLY when set — so the --allow-all opt-out and the explicit nine-name
//     grant list produce two DIFFERENT canonical values differing exactly
//     in the one behavior that differs.
// Entries are emitted pre-sorted by key so the constructed value IS its
// canonical form. This is the caps component of the stream-5 [computation]
// record and the [$caps] introspection result.

// caps_scope_canonical canonicalizes one scope list for the C4 value:
// lower-case iff `lower` (host globs — DNS names are case-insensitive),
// strip a trailing '/' from path roots (never the bare root itself),
// dedupe, sort.
fn caps_scope_canonical(scopes []string, lower bool) []string {
	mut out := []string{cap: scopes.len}
	for s in scopes {
		mut t := s.trim_space()
		if t == '' {
			continue
		}
		if lower {
			t = t.to_lower()
		}
		for t.len > 1 && t.ends_with('/') {
			t = t[..t.len - 1]
		}
		if t !in out {
			out << t
		}
	}
	out.sort()
	return out
}

// caps_value_scope_for returns the canonicalized scope list attached to one
// capability name ([] = unscoped).
fn caps_value_scope_for(c &CapSet, cap string) []string {
	return match cap {
		'read' { caps_scope_canonical(c.read_roots, false) }
		'write' { caps_scope_canonical(c.write_roots, false) }
		'net' { caps_scope_canonical(c.net_hosts, true) }
		'env' { caps_scope_canonical(c.env_names, false) }
		'subprocess' { caps_scope_canonical(c.exec_allow, false) }
		else { []string{} }
	}
}

// caps_to_cx_value materialises the ACTIVE capability set as the C4
// canonical CX map value. The empty (nil) set is the empty map.
pub fn caps_to_cx_value() cx.Node {
	mut entries := []cx.Node{}
	if g_active_caps == unsafe { nil } || cap_thread_revoked() {
		return cx.Node(cx.Element{ name: map_marker_name })
	}
	c := unsafe { &CapSet(g_active_caps) }
	// capability_names() is not sorted (it mirrors the CapSet field order);
	// the canonical value sorts keys, with the policy field in its sorted slot.
	mut keys := capability_names().clone()
	if c.private_range_allowed {
		keys << 'private-range-allowed'
	}
	keys.sort()
	for k in keys {
		if k == 'private-range-allowed' {
			entries << cx.Node(cx.Element{
				name:  k
				items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(true), data_type: .bool_type })]
			})
			continue
		}
		if !cap_allowed(k) {
			continue // ungranted = absent (canonical minimal form)
		}
		scopes := caps_value_scope_for(c, k)
		if scopes.len == 0 {
			entries << cx.Node(cx.Element{
				name:  k
				items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(true), data_type: .bool_type })]
			})
			continue
		}
		mut items := []cx.Node{cap: scopes.len}
		for s in scopes {
			items << cx.Node(cx.ScalarNode{ value: cx.ScalarValue(s), data_type: .string_type })
		}
		entries << cx.Node(cx.Element{
			name:  k
			items: [cx.Node(cx.Element{ name: seq_marker_name, items: items })]
		})
	}
	return cx.Node(cx.Element{ name: map_marker_name, items: entries })
}
