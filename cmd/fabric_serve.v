module main

import os
import code

// `cx fabric-serve --config <path> [--allow-net[=host:port]] [--allow-*]` —
// the cx-fabric SERVED tier (spec/03-approved/xap/fabric.md §13/§19.6, issue #531
// P1): a single-node daemon that mounts named fabrics (journal-backed durable
// streams + transient channels), accepts XSP-AUTH attaches over raw XSP/TCP,
// sequences durable publishes, pushes delivery under the bounded pending
// window, and hosts sticky-exclusive consumer-group assignment with
// liveness-window failover. Rides the store-serve daemon plumbing: the same
// capability flags, listener helpers, graceful-shutdown signals (installed
// ONLY here, never by the lib), and an unauthenticated health/ready probe
// endpoint compatible with `cx store-health --url`.

fn run_fabric_serve(args []string) {
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
				eprintln('cx fabric-serve: --config needs a path')
				exit(2)
			}
			config_path = args[i + 1]
			i += 2
			continue
		}
		eprintln('cx fabric-serve: unknown arg "${arg}"')
		exit(2)
	}
	if config_path == '' {
		eprintln('cx fabric-serve: --config <path> is required')
		exit(2)
	}

	src := os.read_file(config_path) or {
		eprintln('cx fabric-serve: read ${config_path}: ${err}')
		exit(2)
	}
	cfg := code.parse_fabric_service_config(src) or {
		eprintln('cx fabric-serve: ${err}')
		exit(2)
	}

	// Capabilities — deny-by-default (security.md §3): binding sockets needs
	// `net`; file-backed journals need read/write at store's effect points.
	if allow_all {
		code.caps_set_all()
	} else {
		code.caps_set_list(allow_caps)
		if net_specs.len > 0 {
			code.caps_set_net_hosts(net_specs)
		}
	}

	mut srv := code.new_fabric_server(cfg) or {
		eprintln('cx fabric-serve: ${err}')
		exit(1)
	}

	// TLS reuses the store-serve identity plumbing (#180: PEM content — file
	// path or ${env:VAR}-injected — read once, in-memory).
	mut tls_cert := ''
	mut tls_key := ''
	mut tls_ca := ''
	if t := cfg.tls {
		tls_cert = code.svc_load_pem(t.cert) or {
			eprintln('cx fabric-serve: TLS cert: ${err.msg()}')
			exit(1)
		}
		tls_key = code.svc_load_pem(t.key) or {
			eprintln('cx fabric-serve: TLS key: ${err.msg()}')
			exit(1)
		}
		if t.ca != '' {
			tls_ca = code.svc_load_pem(t.ca) or {
				eprintln('cx fabric-serve: TLS ca: ${err.msg()}')
				exit(1)
			}
		}
	}
	bind_url := if _ := cfg.tls { 'tls://${cfg.bind}' } else { 'tcp://${cfg.bind}' }
	server := if _ := cfg.tls {
		code.svc_listen_tls(bind_url, tls_cert, tls_key, tls_ca)
	} else {
		code.svc_listen(bind_url)
	}
	if code.svc_is_err(server) {
		eprintln('cx fabric-serve: bind ${bind_url}: ${code.svc_err_text(server)}')
		exit(1)
	}
	code.svc_install_shutdown_signals(server, cfg.drain_ms)
	if stdin_tether {
		code.svc_install_stdin_tether('cx fabric-serve')
	}

	// Optional unauthenticated health/ready listener (§13: only
	// health/capabilities unauthenticated). Registered with the shutdown
	// watcher beside the main listener so a signal unblocks BOTH accepts.
	if cfg.health != '' {
		health := code.svc_listen('tcp://${cfg.health}')
		if code.svc_is_err(health) {
			eprintln('cx fabric-serve: bind health ${cfg.health}: ${code.svc_err_text(health)}')
			exit(1)
		}
		code.svc_register_grpc_listener(health)
		spawn code.fabric_serve_health_loop(mut srv, health)
	}

	spawn code.fabric_liveness_sweeper(mut srv)
	// #636: the retention sweeper evaluates per-stream hot windows and drives
	// the #640 rotation. Returns immediately when no policy is configured.
	spawn code.fabric_retention_sweeper(mut srv)

	mut names := []string{}
	for m in cfg.mounts {
		// #644: never print the raw store URL — a cx-store:// mount carries its
		// bearer token in the userinfo, and a banner is log-retained forever.
		names << '${m.name} (tenant ${m.tenant}, ${code.store_url_redact_userinfo(m.store_url)})'
	}
	policy := if cfg.mutual { 'mutual' } else { 'floor (${cfg.floor})' }
	eprintln('cx fabric-serve: listening on ${bind_url} — ${cfg.mounts.len} fabric(s): ${names.join(', ')}; policy ${policy}; pending-window ${cfg.pending_window}; liveness ${cfg.liveness_ms}ms')
	code.svc_sd_notify_ready()
	code.svc_sd_watchdog_start()

	code.fabric_serve_accept_loop(mut srv, server, code.svc_shutdown_requested)
	code.fabric_serve_shutdown(mut srv)
	eprintln('cx fabric-serve: drained, exiting cleanly')
}
