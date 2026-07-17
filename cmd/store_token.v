module main

import crypto.rand
import crypto.sha256
import os

// `cx store-token --id <name> [--roles <r1,r2>] [--tenant <spec>]` — the
// first-secured-setup helper (store management console spec §4.5, #249):
// generates a cryptographically-random bearer token and prints the
// ready-to-paste `[static [token …]]` config stanza, so operators never
// hand-roll `sha256:` secret-hashes.
//
// The STANZA goes to stdout (pipeable into a config edit); the SECRET goes to
// stderr, shown ONCE and never stored — the config file carries only the hash
// (the daemon's existing at-rest posture). Apply by pasting the stanza inside
// the config's [auth …] section, then `kill -HUP` / the `config-reload` admin
// op (service-tier §2.6) — or one restart for the very first token on an open
// daemon (adding it flips the daemon to deny-by-default).

fn run_store_token(args []string) {
	mut id := ''
	mut roles := 'admin'
	mut tenant := '*'
	mut i := 0
	for i < args.len {
		a := args[i]
		if a.starts_with('--id=') {
			id = a['--id='.len..]
			i++
			continue
		}
		if a == '--id' && i + 1 < args.len {
			id = args[i + 1]
			i += 2
			continue
		}
		if a.starts_with('--roles=') {
			roles = a['--roles='.len..]
			i++
			continue
		}
		if a == '--roles' && i + 1 < args.len {
			roles = args[i + 1]
			i += 2
			continue
		}
		if a.starts_with('--tenant=') {
			tenant = a['--tenant='.len..]
			i++
			continue
		}
		if a == '--tenant' && i + 1 < args.len {
			tenant = args[i + 1]
			i += 2
			continue
		}
		eprintln('cx store-token: unknown arg "${a}"')
		eprintln('usage: cx store-token --id <name> [--roles admin] [--tenant "*"]')
		exit(2)
	}
	if id == '' {
		eprintln('cx store-token: --id <name> is required')
		eprintln('usage: cx store-token --id <name> [--roles admin] [--tenant "*"]')
		exit(2)
	}
	// The daemon validates roles at config parse; validating here too keeps the
	// generated stanza guaranteed-loadable (fail at generation, not at reload).
	for r in roles.split(',') {
		if r.trim_space() !in ['reader', 'writer', 'admin', 'metrics'] {
			eprintln('cx store-token: unknown role "${r.trim_space()}" (roles: reader, writer, admin, metrics)')
			exit(2)
		}
	}
	// 32 CSPRNG bytes → 64-hex secret: enough entropy that the sha256 at rest
	// is not meaningfully attackable, URL/header-safe, no escaping concerns.
	octets := rand.read(32) or {
		eprintln('cx store-token: CSPRNG unavailable: ${err.msg()}')
		exit(1)
	}
	secret := octets.hex()
	hash := sha256.sum256(secret.bytes()).hex()
	norm_roles := roles.split(',').map(it.trim_space()).join(',')
	println('[static [token id="${id}" secret-hash="sha256:${hash}" roles="${norm_roles}" tenant="${tenant}"]]')
	eprintln('cx store-token: secret for "${id}" (shown ONCE, not stored — the config carries only the hash):')
	eprintln(secret)
	eprintln('cx store-token: paste the stanza into the [auth …] section, then `kill -HUP <pid>` or the config-reload admin op (first token on an open daemon: restart).')
}
