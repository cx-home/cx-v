module main

import code
import platform
import cx
import os

// `cx store-mint-principal --id NAME --seed-file PATH --caps "read write"
// [--for grant|identity] [--force]` — the OFFLINE XSP-AUTH principal mint
// (#969, RULED: CO-5; hardened by #985, RULED: CO-10).
//
// A daemon with a non-empty `[xsp [grants …]]` table is deny-by-default: it
// admits exactly the DIDs the operator wrote into its config. Nothing shipped
// could produce such a DID, so a clean-state deployment had no first
// principal — the "provisioned out of band" gap the #968 corrections recorded
// after `cx store-token` retired with the bearer plane.
//
// This verb closes it WITHOUT reopening the plane that was retired. It mints
// an identity and prints two texts; it grants nothing. Config remains the
// SOLE authority — the minted principal is inert until an operator splices
// the printed `[grant …]` row into the daemon config and the daemon reads it.
// Nothing transits a wire, no store is opened, there is no
// trust-on-first-use registration, and no bearer is minted (G1a–G3a stand).
//
// Output contract (deterministic, so docs and tests can pin it):
//   stdout — ONE `[xsp-principal …]` element in canonical text, carrying the
//            verbatim `[config-stanza [xsp …]]` for the daemon and the
//            verbatim `[client-opts [map xsp-did=… xsp-seed-env=…]]` for the
//            client. Parseable as CX by construction; the two children are
//            copy-paste sources. `for=` on the report names WHICH daemon row
//            the stanza carries, so a machine consumer never has to sniff the
//            children to find out.
//   stderr — the operator's next steps in prose (the store-rotate-kek idiom:
//            the machine-readable report is stdout, the guidance is stderr).
// The SEED is written only to --seed-file, mode 0600, and never printed on
// either stream.
//
// The three #985 hardenings (RULED: CO-10):
//
// (i)  `--id` must be the CANONICAL spelling of its derived seed env var.
//      `CX_XSP_SEED_<NAME>` upper-cases the id and folds `-` to `_`, so the
//      derivation is many-to-one: `fleet-ops`, `fleet_ops`, `Fleet-Ops` and
//      `FLEET_OPS` all derive CX_XSP_SEED_FLEET_OPS. Two principals minted
//      under two of those spellings would silently share ONE env var — the
//      second seed exported wins and the first principal's client presents a
//      seed that does not derive its DID. The verb holds no state (it writes
//      one seed file and exits; there is no mint registry to consult), so it
//      cannot detect "an id that collides with one minted earlier". It does
//      something stronger and stateless instead: it accepts only the one
//      canonical spelling per env var (lowercase, `-`), which makes the
//      derivation INJECTIVE over the accepted ids — no two accepted ids can
//      ever collide, on this machine or any other, this year or next. A
//      registry would only have covered mints recorded in one file on one
//      host; canonicality covers all of them, with nothing to keep.
// (ii) `--for identity` emits the daemon's OWN responder row,
//      `[xsp [identity did= seed-env=]]`, built by
//      platform.svc_xsp_identity_attrs from the same xsp_identity_attrs list
//      svc_parse_xsp validates it against — mint and parser cannot drift.
// (iii) `--caps` is REQUIRED for a grant row: authority is an explicit
//      operator choice at mint time, never a default that a hurried
//      bootstrap inherits. It is REFUSED with `--for identity`, whose row
//      has no `caps` attribute — silently dropping a stated authority is
//      exactly the class of bug (i) and (iii) close.

fn run_store_mint_principal(args []string) {
	mut id := ''
	mut seed_file := ''
	// No default: --caps is a REQUIRED authority choice for a grant row
	// (#985 (iii)). `caps_given` is tracked separately from the string so an
	// explicitly EMPTY --caps ("") is a stated-but-invalid list (caught by
	// svc_check_grant_caps) rather than an omission.
	mut caps_str := ''
	mut caps_given := false
	mut for_row := 'grant'
	mut force := false
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
		if a.starts_with('--seed-file=') {
			seed_file = a['--seed-file='.len..]
			i++
			continue
		}
		if a == '--seed-file' && i + 1 < args.len {
			seed_file = args[i + 1]
			i += 2
			continue
		}
		if a.starts_with('--caps=') {
			caps_str = a['--caps='.len..]
			caps_given = true
			i++
			continue
		}
		if a == '--caps' && i + 1 < args.len {
			caps_str = args[i + 1]
			caps_given = true
			i += 2
			continue
		}
		if a.starts_with('--for=') {
			for_row = a['--for='.len..]
			i++
			continue
		}
		if a == '--for' && i + 1 < args.len {
			for_row = args[i + 1]
			i += 2
			continue
		}
		if a == '--force' {
			force = true
			i++
			continue
		}
		eprintln('cx store-mint-principal: unknown arg "${a}"')
		eprintln(smp_usage)
		exit(2)
	}
	if for_row != 'grant' && for_row != 'identity' {
		eprintln('cx store-mint-principal: --for "${for_row}" is not a row this verb emits (grant|identity: `grant` = a [xsp [grants [grant …]]] row for a client principal, `identity` = the daemon\'s own [xsp [identity …]] responder row)')
		eprintln(smp_usage)
		exit(2)
	}
	if id == '' || seed_file == '' {
		eprintln('cx store-mint-principal: --id and --seed-file are both required')
		eprintln(smp_usage)
		exit(2)
	}
	// The id names the principal in the operator's own vocabulary AND derives
	// the env var the client presents it through, so it must be a legal shell
	// identifier fragment. Refuse rather than silently mangle.
	if !smp_id_ok(id) {
		eprintln('cx store-mint-principal: --id "${id}" must be a non-empty [a-z0-9-] word (it names the principal and derives its seed env var)')
		exit(2)
	}
	// #985 (i): the seed-env derivation is many-to-one, so only the CANONICAL
	// spelling is accepted — that makes it injective, and two accepted ids can
	// never name one env var. The refusal names BOTH ids and the env var they
	// would have shared, because the operator's real question is "what should I
	// have typed", and the failure this prevents (a second seed silently
	// overwriting the first in one variable) is otherwise invisible.
	canon := smp_canonical_id(id)
	if id != canon {
		eprintln('cx store-mint-principal: --id "${id}" is not the canonical spelling of its seed env var — "${id}" and "${canon}" both derive ${smp_seed_env(id)}, so principals minted under both spellings would silently share ONE seed variable and only the last one exported would work.')
		eprintln('cx store-mint-principal: mint it as --id "${canon}" (the canonical spelling: lowercase, `-` for word breaks). CX_XSP_SEED_<NAME> upper-cases and folds `-` to `_`, so accepting only canonical ids is what makes the derivation collision-free.')
		exit(2)
	}
	// #985 (iii): --caps is a REQUIRED authority choice for a grant row, and is
	// REFUSED for an identity row, which has no caps attribute to carry it —
	// the daemon's own identity is the root of its authority, not a grantee.
	if for_row == 'identity' {
		if caps_given {
			eprintln('cx store-mint-principal: --caps does not apply to --for identity — the [xsp [identity …]] row carries only did= and seed-env=, and the daemon\'s own identity is the ROOT of its authority rather than a grantee. Drop --caps, or mint a grant row (--for grant) for a principal that needs capabilities.')
			exit(2)
		}
	} else if !caps_given {
		eprintln('cx store-mint-principal: --caps is required — the authority a grant carries is an explicit choice at mint time, never a default (RULED: CO-10, #985).')
		eprintln('cx store-mint-principal: pass a space-separated list from the v1 grammar: ${platform.xsp_grant_caps.join(' ')} (least privilege first, e.g. --caps "read write").')
		exit(2)
	}
	caps := caps_str.split(' ').filter(it != '')
	if for_row == 'grant' {
		platform.svc_check_grant_caps(caps) or {
			eprintln('cx store-mint-principal: --caps ${err.msg()}')
			exit(2)
		}
	}
	// Refuse-before-generate: an existing seed file is a LIVE principal whose
	// grant may already be in a daemon config. Overwriting it silently would
	// orphan that grant and lock the principal out. --force is the explicit
	// opt-in (rotation), and even then the old seed is gone for good.
	if os.exists(seed_file) && !force {
		eprintln('cx store-mint-principal: ${seed_file} already exists — refusing to overwrite a live principal seed (pass --force to replace it, which invalidates the existing DID)')
		exit(1)
	}
	minted := platform.svc_mint_xsp_principal() or {
		eprintln('cx store-mint-principal: ${err.msg()}')
		exit(1)
	}
	seed_env := smp_seed_env(id)
	// Write through a sibling temp file and RENAME into place. Two reasons,
	// both load-bearing for a verb whose output is a secret:
	//  * the file is chmod-ed 0600 while still EMPTY, so the seed is never on
	//    disk at the default umask, not even for an instant;
	//  * under --force the existing seed survives until the replacement is
	//    fully written — an interrupted rotation leaves the old principal
	//    intact rather than destroying both.
	tmp_seed := seed_file + '.mint-tmp'
	os.rm(tmp_seed) or {}
	os.write_file(tmp_seed, '') or {
		eprintln('cx store-mint-principal: cannot create ${tmp_seed}: ${err.msg()}')
		exit(1)
	}
	os.chmod(tmp_seed, 0o600) or {
		os.rm(tmp_seed) or {}
		eprintln('cx store-mint-principal: cannot restrict ${tmp_seed} to 0600: ${err.msg()}')
		exit(1)
	}
	// Trailing newline: a POSIX text file, and `$(cat PATH)` — the documented
	// way to load it — strips it, so the env var still holds bare hex.
	os.write_file(tmp_seed, minted.seed_hex + '\n') or {
		os.rm(tmp_seed) or {}
		eprintln('cx store-mint-principal: cannot write ${tmp_seed}: ${err.msg()}')
		exit(1)
	}
	os.mv(tmp_seed, seed_file) or {
		os.rm(tmp_seed) or {}
		eprintln('cx store-mint-principal: cannot place ${seed_file}: ${err.msg()}')
		exit(1)
	}
	// The report is assembled from the minted values rather than rendered from
	// a text template, so the printed stanza can never drift from the seed
	// that was actually written.
	//
	// The [xsp …] child differs by --for: a GRANT row authorizes a client
	// principal, an IDENTITY row is the daemon's own responder identity. The
	// identity row's attributes come from platform.svc_xsp_identity_attrs —
	// the parser's own list — so this verb spells them exactly once, there.
	mut xsp_row := smp_el('grants', [], [
		cx.Node(smp_el('grant', [smp_attr('did', minted.did), smp_attr('caps', caps.join(' '))],
			[])),
	])
	if for_row == 'identity' {
		ident_attrs := platform.svc_xsp_identity_attrs(minted.did, seed_env) or {
			eprintln('cx store-mint-principal: ${err.msg()}')
			exit(1)
		}
		xsp_row = smp_el('identity', ident_attrs, [])
	}
	report := smp_el('xsp-principal', [
		smp_attr('id', id),
		smp_attr('for', for_row),
		smp_attr('did', minted.did),
		smp_attr('seed-file', seed_file),
		smp_attr('seed-env', seed_env),
	], [
		cx.Node(smp_el('config-stanza', [], [
			cx.Node(smp_el('xsp', [], [cx.Node(xsp_row)])),
		])),
		cx.Node(smp_el('client-opts', [], [
			cx.Node(smp_el('map', [
				smp_attr('xsp-did', minted.did),
				smp_attr('xsp-seed-env', seed_env),
			], [])),
		])),
	])
	println(code.render_canonical(report))
	eprintln('')
	eprintln('cx store-mint-principal: minted `${id}` — the seed is in ${seed_file} (0600); it was NOT printed.')
	eprintln('')
	if for_row == 'identity' {
		eprintln('1. Daemon — splice [config-stanza]\'s [identity …] row into the service')
		eprintln('   config\'s [xsp …] section (the fabric daemon takes the same row at its')
		eprintln('   own top level). This is the daemon\'s RESPONDER identity: attach is')
		eprintln('   XSP-AUTH and there is no anonymous responder.')
		eprintln('2. Daemon — export the seed BEFORE store-serve reads the config; the')
		eprintln('   daemon resolves seed-env at parse time and refuses to boot without it:')
		eprintln('     export ${seed_env}="$(cat ${seed_file})"')
	} else {
		eprintln('1. Daemon — splice [config-stanza]\'s [grant …] row into the service config\'s')
		eprintln('   [xsp [grants …]] table. Grants present ⇒ deny-by-default: every other')
		eprintln('   principal is refused. The config is the ONLY grant table; minting alone')
		eprintln('   authorizes nothing.')
		eprintln('2. Client — export the seed, then present the identity through open-opts:')
		eprintln('     export ${seed_env}="$(cat ${seed_file})"')
		eprintln('     [\$store:open-opts "cx-store+xsp://HOST:PORT/STORE/" [map xsp-did="${minted.did}" xsp-seed-env="${seed_env}"]]')
	}
	eprintln('')
	eprintln('Back up ${seed_file}: the seed is the ONLY way to prove this DID, and it')
	eprintln('exists nowhere else — a lost seed means re-minting and re-granting.')
}

const smp_usage = 'usage: cx store-mint-principal --id <name> --seed-file <path> --caps "read write" [--for grant|identity] [--force]'

fn smp_el(name string, attrs []cx.Attribute, items []cx.Node) cx.Element {
	return cx.Element{
		name:  name
		attrs: attrs
		items: items
	}
}

fn smp_attr(name string, val string) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(val)
	}
}

// smp_id_ok — the principal id must be a plain word: it appears in the report,
// names the seed file's owner in operator vocabulary, and derives the env var.
// The alphabet still admits `A-Z` and `_` so that a spelling which merely
// ALIASES another gets the canonical-form refusal below (which names the id it
// collides with) rather than this generic one.
fn smp_id_ok(id string) bool {
	if id == '' {
		return false
	}
	for c in id {
		ok := (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`)
			|| c == `_` || c == `-`
		if !ok {
			return false
		}
	}
	return true
}

// smp_canonical_id — the ONE id spelling per derived env var (#985 (i),
// RULED: CO-10). smp_seed_env upper-cases and folds `-` to `_`, so its
// inverse image is a whole family of spellings; lowercase-with-`-` is the
// representative the verb accepts, matching CX's own kebab house spelling
// (`seed-env`, `xsp-did`) and keeping the id in operator vocabulary rather
// than in env-var vocabulary. Over ids restricted to [a-z0-9-], the
// derivation is injective — no two accepted ids can share a seed variable,
// which is a stronger guarantee than any registry of past mints could give
// (a registry knows only its own host's file; this holds everywhere).
fn smp_canonical_id(id string) string {
	return id.to_lower().replace('_', '-')
}

// smp_seed_env derives the client's xsp-seed-env name from the id —
// DERIVED, never a second flag to keep in sync (the CX_STORE_KEK_<id> idiom
// store-rotate-kek already uses).
fn smp_seed_env(id string) string {
	return 'CX_XSP_SEED_' + id.to_upper().replace('-', '_')
}
