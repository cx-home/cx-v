module code

import os
import sync
import time
import cx

// #251 — runtime config reload (§2.6, CSRP §3.13). Validate-then-swap,
// fail-closed: the candidate config is fully parsed + cross-validated before
// anything applies, and a refusal (invalid candidate, or a restart-required
// section changed) leaves the running config byte-for-byte untouched. Apply is
// an atomic snapshot swap: request handlers resolve the CURRENT snapshot at
// dispatch entry (svc_ctx_live), so an in-flight request finishes under the
// config it started with and the next request observes the new one.
//
// Section classification is the Appendix-A table. The diff is computed on the
// CANONICAL EMIT of each top-level config section — attr-exact by construction
// (the same §2.2 posture: nothing an operator wrote is silently ignored),
// independent of struct-equality quirks (provider caches, parsed key nodes).

// Hot sections apply without restart; restart sections refuse the reload WHOLE
// (all-or-nothing — hot changes riding in the same candidate are not applied).
const svc_hot_sections = ['tls', 'timeouts', 'auth', 'limits', 'observability']
const svc_restart_sections = ['bind', 'grpc', 'stores', 'workers']

const e_svc_cfg_restart = 'cx-err:CXER1712' // E_SVC_CONFIG_RESTART_REQUIRED (§3.13)

// SvcHotState is one immutable hot-config snapshot. ServeContext consumers
// never read it directly — svc_ctx_live projects it over the context.
pub struct SvcHotState {
pub:
	auth            AuthConfig
	log_json        bool
	tracer          &TraceExporter = unsafe { nil }
	read_timeout_ms i64
	idle_timeout_ms i64
}

// SvcConfigBox owns the daemon's live config state: the current hot snapshot,
// the last-applied full config + its canonical section map (the reload diff
// baseline), and the PEM material the listeners currently present. One box per
// daemon, shared by every worker + both listeners; all access under mu.
@[heap]
pub struct SvcConfigBox {
mut:
	mu       &sync.Mutex = unsafe { nil }
	snap     SvcHotState
	sections map[string]string // canonical emit per top-level section, last applied
	tls_cert string            // live PEM content ('' = no TLS)
	tls_key  string
	tls_ca   string
	gen      int // successful applies since start (0 = startup config)
}

// new_svc_config_box seeds the box from the startup config. `src` is the
// parsed-and-validated config document source; the TLS PEMs are the resolved
// CONTENT the listeners were bound with (svc_load_pem output, not paths).
pub fn new_svc_config_box(cfg ServiceConfig, src string, tls_cert string, tls_key string, tls_ca string) &SvcConfigBox {
	tracer := new_trace_exporter(cfg.observability.otel_enabled, cfg.observability.otel_endpoint,
		'cxstore')
	return &SvcConfigBox{
		mu:       sync.new_mutex()
		snap:     SvcHotState{
			auth:            cfg.auth
			log_json:        cfg.observability.log_format == 'json'
			tracer:          tracer
			read_timeout_ms: cfg.read_timeout_ms
			idle_timeout_ms: cfg.idle_timeout_ms
		}
		sections: svc_config_sections(src)
		tls_cert: tls_cert
		tls_key:  tls_key
		tls_ca:   tls_ca
	}
}

// snapshot returns the current hot state (one consistent view per call).
pub fn (mut b SvcConfigBox) snapshot() SvcHotState {
	b.mu.lock()
	defer {
		b.mu.unlock()
	}
	return b.snap
}

// generation returns the applied-reload count (0 = startup config).
pub fn (mut b SvcConfigBox) generation() int {
	b.mu.lock()
	defer {
		b.mu.unlock()
	}
	return b.gen
}

// svc_config_sections maps each top-level section of a (pre-validated)
// `[cxstore-service …]` document to its canonical emit — the reload diff unit.
// The source is known-parseable (parse_service_config accepted it first).
fn svc_config_sections(src string) map[string]string {
	mut out := map[string]string{}
	doc := cx.parse(src) or { return out }
	if doc.elements.len == 0 {
		return out
	}
	root := doc.elements[0]
	if root !is cx.Element {
		return out
	}
	for item in (root as cx.Element).items {
		if item is cx.Element {
			out[item.name] = cx.cx_emit_node_str(item, true)
		}
	}
	return out
}

// ReloadOutcome is one reload attempt's result — shared verbatim by the SIGHUP
// watcher and the CSRP/gRPC `config-reload` op (§2.6: one implementation, one
// outcome shape).
pub struct ReloadOutcome {
pub:
	applied  bool
	gen      int
	changed  []string // hot sections that differed (applied), sorted
	err_code string   // '' = success; else CXER1711 / CXER1712
	err_msg  string
}

// metric_outcome maps the outcome onto the F.1 label set.
fn (o ReloadOutcome) metric_outcome() string {
	if o.err_code == e_svc_cfg_restart {
		return 'restart-required'
	}
	if o.err_code != '' {
		return 'invalid'
	}
	if o.applied {
		return 'applied'
	}
	return 'noop'
}

// ReloadDeps is everything one reload needs, captured once at daemon startup —
// the config path the daemon was started with (the op never carries config
// content over the wire), the shared limiter/metrics instances, and the live
// TLS listener handle ids (empty when serving plaintext).
pub struct ReloadDeps {
pub:
	config_path string
	limiter     &Limiter         = unsafe { nil }
	metrics     &MetricsRegistry = unsafe { nil }
	tls_listeners []int
}

// svc_reloader_deps assembles ReloadDeps from the daemon CLI's live pieces —
// resolving listener nodes to registry ids here because net_handle_id is
// module-internal. Pass ONLY the TLS listeners (plaintext needs no rotation).
pub fn svc_reloader_deps(config_path string, lim &Limiter, metrics &MetricsRegistry, tls_listeners []cx.Node) ReloadDeps {
	mut ids := []int{}
	for l in tls_listeners {
		if id := net_handle_id(l) {
			ids << id
		}
	}
	return ReloadDeps{
		config_path:   config_path
		limiter:       lim
		metrics:       metrics
		tls_listeners: ids
	}
}

// svc_reload_config is THE reload path (§2.6): re-read the daemon's own config
// source, validate whole, refuse on any restart-required change, then apply the
// changed hot sections atomically. Every attempt books one metric sample and is
// logged by the caller (svc_reload_log).
pub fn svc_reload_config(mut box SvcConfigBox, deps ReloadDeps) ReloadOutcome {
	out := svc_reload_config_inner(mut box, deps)
	if deps.metrics != unsafe { nil } {
		mut m := deps.metrics
		m.record_reload(out.metric_outcome())
	}
	return out
}

fn svc_reload_config_inner(mut box SvcConfigBox, deps ReloadDeps) ReloadOutcome {
	gen0 := box.generation()
	src := os.read_file(deps.config_path) or {
		return ReloadOutcome{
			gen:      gen0
			err_code: e_svc_cfg
			err_msg:  'E_SVC_CONFIG_INVALID: read ${deps.config_path}: ${err.msg()}'
		}
	}
	cand := parse_service_config(src) or {
		return ReloadOutcome{
			gen:      gen0
			err_code: e_svc_cfg
			err_msg:  err.msg()
		}
	}
	new_sections := svc_config_sections(src)
	box.mu.lock()
	old_sections := box.sections.clone()
	box.mu.unlock()
	// Restart-required diff: refuse WHOLE on any change (added, removed, or
	// edited section), naming every offender.
	mut restart_changed := []string{}
	for s in svc_restart_sections {
		if old_sections[s] or { '' } != new_sections[s] or { '' } {
			restart_changed << s
		}
	}
	if restart_changed.len > 0 {
		offenders := restart_changed.join(', ')
		return ReloadOutcome{
			gen:      gen0
			err_code: e_svc_cfg_restart
			err_msg:  'E_SVC_CONFIG_RESTART_REQUIRED: restart-required section(s) changed: ${offenders} — reload refused whole, nothing applied'
		}
	}
	// Hot diff. TLS is special: the section text may be unchanged while the
	// FILES it points at rotated — re-resolve the PEM sources and compare
	// CONTENT (the whole point of cert rotation; ${env:VAR} re-resolves to the
	// startup environment, spec §2.6: env is rotation-blind by design).
	mut changed := []string{}
	for s in svc_hot_sections {
		if s == 'tls' {
			continue // content-compared below
		}
		if old_sections[s] or { '' } != new_sections[s] or { '' } {
			changed << s
		}
	}
	mut new_cert := ''
	mut new_key := ''
	mut new_ca := ''
	if t := cand.tls {
		new_cert = svc_load_pem(t.cert) or {
			return ReloadOutcome{
				gen:      gen0
				err_code: e_svc_cfg
				err_msg:  'E_SVC_CONFIG_INVALID: TLS cert: ${err.msg()}'
			}
		}
		new_key = svc_load_pem(t.key) or {
			return ReloadOutcome{
				gen:      gen0
				err_code: e_svc_cfg
				err_msg:  'E_SVC_CONFIG_INVALID: TLS key: ${err.msg()}'
			}
		}
		if t.ca != '' {
			new_ca = svc_load_pem(t.ca) or {
				return ReloadOutcome{
					gen:      gen0
					err_code: e_svc_cfg
					err_msg:  'E_SVC_CONFIG_INVALID: TLS ca: ${err.msg()}'
				}
			}
		}
	}
	box.mu.lock()
	tls_changed := new_cert != box.tls_cert || new_key != box.tls_key || new_ca != box.tls_ca
	box.mu.unlock()
	if tls_changed {
		changed << 'tls'
	}
	changed.sort()
	if changed.len == 0 {
		return ReloadOutcome{
			applied: false
			gen:     gen0
		}
	}
	// Apply. TLS rotation goes FIRST — it is the only fallible apply, so a
	// failure here (e.g. unparseable rotated PEM) leaves EVERYTHING untouched.
	// If the second listener fails after the first rotated, roll the first
	// back to the running identity (best-effort symmetric rotate).
	if tls_changed && deps.tls_listeners.len > 0 {
		box.mu.lock()
		old_cert, old_key, old_ca := box.tls_cert, box.tls_key, box.tls_ca
		box.mu.unlock()
		mut rotated := []int{}
		for id in deps.tls_listeners {
			net_rotate_listener_tls(id, new_cert, new_key, new_ca) or {
				for rid in rotated {
					net_rotate_listener_tls(rid, old_cert, old_key, old_ca) or {}
				}
				return ReloadOutcome{
					gen:      gen0
					err_code: e_svc_cfg
					err_msg:  'E_SVC_CONFIG_INVALID: TLS rotate: ${err.msg()} — running config untouched'
				}
			}
			rotated << id
		}
	}
	// Snapshot swap (auth / limits / observability / timeouts). The previous
	// tracer is intentionally NOT torn down: in-flight requests hold the old
	// snapshot and may still export through it; its worker parks on an idle
	// channel — bounded by the number of observability reloads (rare), which is
	// the lifetime-safe trade against a use-after-close on the request path.
	box.mu.lock()
	if 'observability' in changed {
		box.snap = SvcHotState{
			...box.snap
			log_json: cand.observability.log_format == 'json'
			tracer:   new_trace_exporter(cand.observability.otel_enabled, cand.observability.otel_endpoint,
				'cxstore')
		}
	}
	if 'auth' in changed {
		// Provider caches (JWKS / did:web) are allocated fresh by the parse —
		// stale keys never outlive the providers that fetched them (§2.6).
		box.snap = SvcHotState{
			...box.snap
			auth: cand.auth
		}
	}
	if 'timeouts' in changed {
		box.snap = SvcHotState{
			...box.snap
			read_timeout_ms: cand.read_timeout_ms
			idle_timeout_ms: cand.idle_timeout_ms
		}
		g_svc_drain_grace_ms = cand.drain_ms // next shutdown's grace (§2.6)
	}
	box.tls_cert = new_cert
	box.tls_key = new_key
	box.tls_ca = new_ca
	box.sections = new_sections.clone()
	box.gen++
	gen := box.gen
	box.mu.unlock()
	if 'limits' in changed && deps.limiter != unsafe { nil } {
		mut lim := deps.limiter
		lim.set_config(cand.limits) // buckets/in-flight preserved (§2.6)
	}
	return ReloadOutcome{
		applied: true
		gen:     gen
		changed: changed
	}
}

// svc_reload_response maps an outcome onto the §3.13 wire shape.
pub fn svc_reload_response(out ReloadOutcome) cx.Node {
	if out.err_code != '' {
		return csrp_resp(400, '[err code="${out.err_code}" message="${csrp_msg_esc(out.err_msg)}"]')
	}
	ch := out.changed.join(' ')
	return csrp_resp(200, '[config-reload applied=${out.applied} generation=${out.gen} changed="${ch}"]')
}

// svc_reload_log renders the one structured log record per attempt (§2.6).
pub fn svc_reload_log(out ReloadOutcome, trigger string) string {
	if out.err_code != '' {
		return 'cx store-serve: config-reload trigger=${trigger} outcome=${out.metric_outcome()} generation=${out.gen} error="${out.err_msg}"'
	}
	ch := out.changed.join(' ')
	return 'cx store-serve: config-reload trigger=${trigger} outcome=${out.metric_outcome()} generation=${out.gen} changed="${ch}"'
}

// ── SIGHUP trigger (opt-in, daemon-CLI only — the lib never installs signal
// handlers automatically, same posture as svc_install_shutdown_signals) ───────

fn svc_reload_signal_handler(sig os.Signal) {
	g_svc_reload = g_svc_reload + 1 // async-signal-safe single write
}

// svc_install_reload_signal arms SIGHUP → config reload. The watcher runs the
// SAME reload closure the CSRP/gRPC op uses (§2.6: one implementation) and
// logs each attempt. Call once, from the daemon CLI only.
pub fn svc_install_reload_signal(reload fn () ReloadOutcome) {
	g_svc_reload = 0
	os.signal_opt(.hup, svc_reload_signal_handler) or {}
	spawn svc_reload_watcher(reload)
}

fn svc_reload_watcher(reload fn () ReloadOutcome) {
	mut seen := 0
	for {
		if g_svc_reload > seen {
			seen = g_svc_reload
			out := reload()
			eprintln(svc_reload_log(out, 'sighup'))
		}
		time.sleep(100 * time.millisecond)
	}
}
