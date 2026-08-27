module main

import os
import net.http
import cx
import code
import platform

// `cx store-serve --config <path> [--allow-net[=host:port]]` — the Phase-2
// single-node CSRP service daemon (#105). Loads + validates a CX config
// (cxstore.service.cx), opens the store mount, binds the listener, and runs the
// multi-threaded accept loop (platform.run_serve_loop) until SIGTERM/SIGINT, then
// drains gracefully (§2.5).
//
// Graceful-shutdown signal handling is provided by the lib as opt-in functions
// (platform.svc_install_shutdown_signals / platform.svc_shutdown_requested), invoked
// ONLY here — the lib never installs signal handlers automatically, so a binding
// loading libcx never hijacks SIGTERM.

fn run_store_serve(args []string) {
	mut config_path := ''
	mut allow_all := false
	mut allow_caps := []string{}
	mut net_specs := []string{}
	mut stdin_tether := false

	mut i := 0
	for i < args.len {
		arg := args[i]
		if arg == '--allow-all' {
			allow_all = true
			i++
			continue
		}
		if arg == '--exit-on-stdin-eof' {
			// #648: spawner-tethered lifetime — drain gracefully when stdin
			// reaches EOF (the harness holds a pipe; its death closes it).
			stdin_tether = true
			i++
			continue
		}
		if arg.starts_with('--allow-') {
			rest := arg['--allow-'.len..]
			cap_name := rest.all_before('=')
			if cap_name != '' {
				// #1059: an unenforceable scope suffix refuses here rather
				// than granting the blanket capability behind it.
				refuse_unenforced_grant_scope('cx store-serve', arg, cap_name, rest)
				allow_caps << cap_name
				if cap_name == 'net' && rest.contains('=') {
					net_specs << rest.all_after('=')
				}
			}
			i++
			continue
		}
		if arg.starts_with('--config=') {
			config_path = arg['--config='.len..]
			i++
			continue
		}
		if arg == '--config' {
			if i + 1 >= args.len {
				eprintln('cx store-serve: --config needs a path')
				exit(2)
			}
			config_path = args[i + 1]
			i += 2
			continue
		}
		eprintln('cx store-serve: unknown arg "${arg}"')
		exit(2)
	}
	if config_path == '' {
		eprintln('cx store-serve: --config <path> is required')
		exit(2)
	}

	src := os.read_file(config_path) or {
		eprintln('cx store-serve: read ${config_path}: ${err}')
		exit(2)
	}
	cfg := platform.parse_service_config(src) or {
		eprintln('cx store-serve: ${err}')
		exit(2)
	}


	// Single-store-per-daemon: multi-store-in-one-daemon needs a CSRP store-name
	// path extension (client + server + the approved protocol), paired with
	// tenant routing in the authZ sub-area. Fail honestly rather than silently
	// serve one of several configured mounts.
	// Capabilities — deny-by-default (security.md §3). Serving binds a socket, so
	// `net` must be granted (--allow-net[=host:port] or --allow-all).
	if allow_all {
		code.caps_set_all()
	} else {
		code.caps_set_list(allow_caps) or {
			eprintln('cx: ${err.msg()}')
			exit(2)
		}
		if net_specs.len > 0 {
			code.caps_set_net_hosts(net_specs)
		}
	}

	// Open every mount; requests route by store-name (sole-store form when one).
	mut mounts := map[string]cx.Node{}
	mut names := []string{}
	for m in cfg.stores {
		h := platform.svc_open_store(m.url)
		if platform.svc_is_err(h) {
			eprintln('cx store-serve: open store ${m.name} (${m.url}): ${platform.svc_err_text(h)}')
			exit(1)
		}
		mounts[m.name] = h
		// #644: redact userinfo — ftp/sftp mounts carry user:pass in the URL
		// and a banner is log-retained forever.
		names << '${m.name} (${platform.store_url_redact_userinfo(m.url)})'
	}

	// #180: thread the TLS cert/key PEM into the listener (they were parsed then
	// discarded). Read the PEM (file path or ${env:VAR}-injected content) once and
	// reuse for both the CSRP and gRPC listeners; a read failure fails fast.
	mut tls_cert := ''
	mut tls_key := ''
	mut tls_ca := ''
	if t := cfg.tls {
		tls_cert = platform.svc_load_pem(t.cert) or {
			eprintln('cx store-serve: TLS cert: ${err.msg()}')
			exit(1)
		}
		tls_key = platform.svc_load_pem(t.key) or {
			eprintln('cx store-serve: TLS key: ${err.msg()}')
			exit(1)
		}
		if t.ca != '' {
			tls_ca = platform.svc_load_pem(t.ca) or {
				eprintln('cx store-serve: TLS ca: ${err.msg()}')
				exit(1)
			}
		}
	}
	bind_url := if _ := cfg.tls { 'tls://${cfg.bind}' } else { 'tcp://${cfg.bind}' }
	server := if _ := cfg.tls {
		platform.svc_listen_tls(bind_url, tls_cert, tls_key, tls_ca)
	} else {
		platform.svc_listen(bind_url)
	}
	if platform.svc_is_err(server) {
		eprintln('cx store-serve: bind ${bind_url}: ${platform.svc_err_text(server)}')
		exit(1)
	}

	platform.svc_install_shutdown_signals(server, cfg.drain_ms)
	if stdin_tether {
		platform.svc_install_stdin_tether('cx store-serve')
	}

	// gRPC (decision 2b): opt-in second listener on its own addr, bound BEFORE
	// the ServeContext so the #251 reloader can rotate BOTH TLS listeners.
	mut grpc_server := cx.Node(cx.ScalarNode{})
	mut grpc_bound := false
	if cfg.grpc.enabled {
		grpc_url := if _ := cfg.tls { 'tls://${cfg.grpc.addr}' } else { 'tcp://${cfg.grpc.addr}' }
		grpc_server = if _ := cfg.tls {
			platform.svc_listen_tls(grpc_url, tls_cert, tls_key, tls_ca)
		} else {
			platform.svc_listen(grpc_url)
		}
		if platform.svc_is_err(grpc_server) {
			eprintln('cx store-serve: bind gRPC ${grpc_url}: ${platform.svc_err_text(grpc_server)}')
			exit(1)
		}
		// #211: register the gRPC listener so the shutdown watcher closes it too
		// (unblocking its accept) and its in-flight streams drain rather than being
		// severed on exit.
		platform.svc_register_grpc_listener(grpc_server)
		grpc_bound = true
		eprintln('cx store-serve: gRPC listening on ${grpc_url} (CSRP-parity, ${cfg.query_pool} workers)')
	}

	// XSP store-profile listener (I5 stream 4 W3): opt-in third listener on its
	// own addr, bound BEFORE the ServeContext like gRPC so both extra listeners
	// exist when the reloader captures the TLS set.
	mut xsp_server := cx.Node(cx.ScalarNode{})
	mut xsp_bound := false
	if cfg.xsp.enabled {
		xsp_url := if _ := cfg.tls { 'tls://${cfg.xsp.addr}' } else { 'tcp://${cfg.xsp.addr}' }
		xsp_server = if _ := cfg.tls {
			platform.svc_listen_tls(xsp_url, tls_cert, tls_key, tls_ca)
		} else {
			platform.svc_listen(xsp_url)
		}
		if platform.svc_is_err(xsp_server) {
			eprintln('cx store-serve: bind XSP ${xsp_url}: ${platform.svc_err_text(xsp_server)}')
			exit(1)
		}
		// register with the shutdown watcher so its accept() unblocks on drain
		// (the #211 lesson, applied at birth).
		platform.svc_register_xsp_listener(xsp_server)
		xsp_bound = true
		eprintln('cx store-serve: XSP store profile listening on ${xsp_url} (responder ${cfg.xsp.identity_did})')
	}

	// #251 runtime config reload (§2.6): the hot-config box (auth / limits /
	// observability / timeouts / TLS identity) + ONE reload closure shared by
	// SIGHUP and the CSRP/gRPC config-reload op. The box owns the tracer so an
	// observability reload can swap it.
	limiter := platform.new_limiter(cfg.limits) // DoS fairness, default-on
	metrics := platform.new_metrics_registry(version) // /metrics, scope-gated (6a)
	mut box := platform.new_svc_config_box(cfg, src, tls_cert, tls_key, tls_ca)
	mut tls_nodes := []cx.Node{}
	if _ := cfg.tls {
		tls_nodes << server
		if grpc_bound {
			tls_nodes << grpc_server
		}
		if xsp_bound {
			tls_nodes << xsp_server
		}
	}
	reload_deps := platform.svc_reloader_deps(config_path, limiter, metrics, tls_nodes)
	reload_fn := fn [mut box, reload_deps] () platform.ReloadOutcome {
		return platform.svc_reload_config(mut box, reload_deps)
	}
	platform.svc_install_reload_signal(reload_fn) // SIGHUP → reload (systemd ExecReload)

	serve_ctx := platform.ServeContext{
		mounts:          mounts
		limiter:         limiter
		metrics:         metrics
		tracer:          box.snapshot().tracer // OTel export off unless [observability [otel enabled=true]]
		read_timeout_ms: cfg.read_timeout_ms // #187 per-connection read deadline
		idle_timeout_ms: cfg.idle_timeout_ms // #234.1 keep-alive idle timeout
		log_json:        cfg.observability.log_format == 'json' // #207.2
		cfgbox:          box // #251: dispatch resolves the live snapshot per request
		reloader:        reload_fn
		// W6: advertise the profile listener in the bootstrap capabilities
		xsp_addr: if cfg.xsp.enabled { cfg.xsp.addr } else { '' }
		xsp_did:  if cfg.xsp.enabled { cfg.xsp.identity_did } else { '' }
		// S3 (RULED G1a): the gRPC edge's per-call XSP-AUTH runs under the SAME
		// [xsp …] config as the profile listener — one authority calculus.
		xsp_cfg: cfg.xsp
	}
	auth_mode := if cfg.xsp.grants.len > 0 {
		'auth ENFORCED (XSP-AUTH, ${cfg.xsp.grants.len} grant(s))'
	} else {
		'auth OPEN — no [xsp [grants …]] configured, anonymous full access (configure grants for production)'
	}

	// Spawned on its own thread so the CSRP accept loop remains the main thread;
	// gRPC reuses the same store pipeline (svc_handle_request) via the dispatch
	// adapter — no logic dup; the shared cfgbox gives it the same live config.
	if grpc_bound {
		grpc_queue := if cfg.query_pool > 0 { cfg.query_pool * 4 } else { 16 }
		spawn platform.run_grpc_serve_loop(grpc_server, serve_ctx, cfg.query_pool, grpc_queue,
			platform.svc_shutdown_requested)
	}
	// The profile listener drives the SAME op core through the same live
	// ServeContext (mounts + reloader) — one truth, three framings.
	if xsp_bound {
		spawn platform.run_store_xsp_serve_loop(xsp_server, cfg.xsp, serve_ctx, platform.svc_shutdown_requested)
	}

	mut state := platform.new_service_state()
	queue := if cfg.query_pool > 0 { cfg.query_pool * 4 } else { 16 }
	eprintln('cx store-serve: listening on ${bind_url} — ${mounts.len} store(s): ${names.join(', ')}, ${cfg.query_pool} workers, ${auth_mode}')
	platform.svc_sd_notify_ready() // systemd Type=notify READY=1 (no-op when not under systemd)
	platform.svc_sd_watchdog_start() // #181: WATCHDOG=1 pings if WatchdogSec is set (no-op otherwise)

	platform.run_serve_loop(server, mut state, serve_ctx, cfg.query_pool, queue, platform.svc_shutdown_requested)
	// #186 defect 4: checkpoint (flush) every mounted store before exit — a final
	// durability barrier on top of the per-op flush, so a graceful shutdown never
	// leaves an unflushed write.
	platform.svc_shutdown_checkpoint(mounts)
	eprintln('cx store-serve: drained, exiting cleanly')
}

// run_store_health is the readiness probe (Docker HEALTHCHECK / systemd / LB):
// `cx store-health --url <ready-url>` exits 0 iff the daemon reports accepting,
// else non-zero. A plain V http client (not the cx-capability-gated path) — it
// is a CLI utility like `cx hash`, not a CX program.
fn run_store_health(args []string) {
	mut url := ''
	mut i := 0
	for i < args.len {
		a := args[i]
		if a.starts_with('--url=') {
			url = a['--url='.len..]
			i++
			continue
		}
		if a == '--url' {
			if i + 1 >= args.len {
				eprintln('cx store-health: --url needs a value')
				exit(2)
			}
			url = args[i + 1]
			i += 2
			continue
		}
		eprintln('cx store-health: unknown arg "${a}"')
		exit(2)
	}
	if url == '' {
		eprintln('cx store-health: --url <ready-url> is required')
		exit(2)
	}
	resp := http.get(url) or {
		eprintln('cx store-health: ${err}')
		exit(1)
	}
	if resp.status_code == 200 && resp.body.contains('[accepting true]') {
		exit(0)
	}
	eprintln('cx store-health: not ready (status ${resp.status_code}): ${resp.body}')
	exit(1)
}
