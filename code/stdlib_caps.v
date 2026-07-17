@[has_globals]
module code

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
// boolean grant is the v1 gate. `allow_all` is the `--allow-all` opt-out.
//
// THREAD-SAFETY: the global is process-wide; parallel (`:par`) evaluation
// shares it. v1 enforcement targets the single-threaded conformance +
// CLI path. A per-evaluation (env-threaded) set is the documented
// follow-up if parallel effect isolation is needed.

const cap_denied_code = 'cx-err:CXER0271'

@[heap]
struct CapSet {
mut:
	allow_all     bool
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
// conformance runner's grant for non-deny behavior cases).
pub fn caps_set_all() {
	c := &CapSet{
		allow_all: true
	}
	g_active_caps = voidptr(c)
}

// caps_set_list installs an explicit least-privilege set granting exactly
// the named capabilities (Effort B per-fixture `[grant …]`). Unknown names
// are ignored. The empty list is equivalent to `caps_set_empty`.
pub fn caps_set_list(caps []string) {
	mut c := &CapSet{}
	for cap in caps {
		set_cap_flag(mut c, cap, true)
	}
	g_active_caps = voidptr(c)
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
	if c.allow_all {
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
	return c.allow_all || c.net_hosts.len == 0
}

// cap_allow_all reports whether the FULL opt-out grant (--allow-all) is active
// — distinct from a merely unscoped net grant (bare --allow-net). Only
// --allow-all bypasses the §4.5 private-range deny set; bare --allow-net keeps
// it (the deny set is the secure default for any net grant absent a literal-IP
// scope — #47).
fn cap_allow_all() bool {
	if g_active_caps == unsafe { nil } {
		return false
	}
	c := unsafe { &CapSet(g_active_caps) }
	return c.allow_all
}

// caps_apply_spec installs the capability set described by a host grant
// spec string (the ABI `cx_code_eval_caps` `caps` arg / the CLI's combined
// `--allow-*` set). Deny-by-default: '' ⇒ empty (pure-only); 'all' / '*' ⇒
// full grant; otherwise a comma/space/tab-separated capability list. A
// `cap:resource` token contributes the bare capability (per-resource
// scoping is a v1 follow-up). Unknown names are ignored.
pub fn caps_apply_spec(spec string) {
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
		// drop a `cap:resource` / `cap=resource` scope suffix → bare cap.
		cap_name := t.all_before(':').all_before('=')
		caps << cap_name
		// A `net:<host>[:<port>]` (or `net=<host>…`) token additionally records a
		// host scope, so the net grant is least-privilege (only the named host is
		// dialable) AND a literal-IP / `localhost` scope overrides the §4.5
		// private-range deny set (net.md §4.5; #47). A bare `net` stays unscoped
		// (all hosts; the deny set still applies on dial).
		if cap_name == 'net' {
			mut scope := ''
			if t.contains(':') {
				scope = t.all_after(':').trim_space()
			} else if t.contains('=') {
				scope = t.all_after('=').trim_space()
			}
			if scope != '' {
				net_hosts << scope
			}
		}
	}
	caps_set_list(caps)
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

// cap_allowed reports whether `capability` is granted by the active set.
// nil set (empty/default) denies everything.
fn cap_allowed(capability string) bool {
	if g_active_caps == unsafe { nil } {
		return false
	}
	c := unsafe { &CapSet(g_active_caps) }
	if c.allow_all {
		return true
	}
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
fn cap_guard(capability string, resource string) ?cx.Node {
	if cap_allowed(capability) {
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

// caps_push_narrowed installs a NARROWED copy of the active set with each
// capability in `denied` cleared (spec/core/security.md §3 — in-program
// narrowing is deny-only; a program can never widen). Returns the prior
// `g_active_caps` pointer so the caller restores it via `caps_restore`
// after the `[?with-caps]` body's dynamic extent (including on error).
fn caps_push_narrowed(denied []string) voidptr {
	saved := g_active_caps
	mut c := cap_current_flags()
	c.allow_all = false // an explicit narrowed set is never allow-all
	for d in denied {
		set_cap_flag(mut c, d, false)
	}
	nc := &CapSet{
		...c
	}
	g_active_caps = voidptr(nc)
	return saved
}
