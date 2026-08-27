module main

// platform_verbs_d_cx_platform.v — the PLATFORM-profile verb surface (I4,
// #651/#516, spec §4): the store/fabric daemon + operator verbs, compiled
// ONLY into the platform-profile cx (-d cx_platform). The blank-alias
// platform import ALSO lives here: importing the Ring-2 module runs its
// init(), registering every Ring-2 pack into the Ring-1 registries — so
// a cx built WITHOUT -d cx_platform has no Ring-2 code in the artifact
// and every ring-2 name refuses as an undefined callable (the §4
// profile-by-construction rule). The daemon implementations live in the
// sibling *_d_cx_platform.v files.
import platform as _

// platform_subcommands returns the platform-only SubcommandSpec entries,
// appended to the shared registry by build_subcommands (cmd/main.v).
fn platform_subcommands() []SubcommandSpec {
	return [
		SubcommandSpec{
			name:    'store-serve'
			summary: 'Run the CX store service daemon from a config.'
			help:    [
				'Usage: cx store-serve --config PATH [--allow-net[=host:port]] [--allow-*]',
				'',
				'Runs the single-node CX store service daemon: loads + validates the',
				'cxstore.service.cx config, opens the store mount, and serves until',
				'SIGTERM/SIGINT, then drains gracefully.',
			]
			run:     run_store_serve
		},
		SubcommandSpec{
			name:    'fabric-serve'
			summary: 'Run the CX fabric eventing daemon from a config.'
			help:    [
				'Usage: cx fabric-serve --config PATH [--allow-net[=host:port]] [--allow-*]',
				'',
				'Runs the single-node cx-fabric served tier: loads + validates the',
				'fabric.service.cx config, mounts the configured fabrics (journal-backed',
				'durable streams + transient channels), and serves XSP-AUTH-attached',
				'clients over raw XSP frames until SIGTERM/SIGINT, then drains.',
				'Health/ready probes ride the optional [health addr=…] listener',
				'(compatible with `cx store-health --url`).',
			]
			run:     run_fabric_serve
		},
		SubcommandSpec{
			name:    'store-health'
			summary: 'Store readiness probe (exit 0 iff accepting).'
			help:    [
				'Usage: cx store-health --url READY_URL',
				'',
				'Readiness probe for the store daemon (Docker HEALTHCHECK / systemd / LB):',
				'exit 0 iff the daemon at READY_URL reports accepting, else non-zero.',
			]
			run:     run_store_health
		},
		SubcommandSpec{
			name:    'store-rotate-kek'
			summary: 'Rotate a store key-encryption key (re-wrap envelopes).'
			help:    [
				'Usage: cx store-rotate-kek --url STORE_URL --encrypt-key-id OLD --new-key-id NEW',
				'',
				"Re-wraps every at-rest envelope's data key under the new tenant KEK",
				'(payloads and content addresses untouched; atomic per object, resumable,',
				'fail-closed) and prints the [rotation-report ...].',
				'Requires env CX_STORE_KEK_<OLD> and CX_STORE_KEK_<NEW> (64 hex chars each).',
			]
			run:     run_store_rotate_kek
		},
		SubcommandSpec{
			name:    'store-mint-principal'
			summary: 'Mint an XSP-AUTH principal offline (seed file + [grant …] stanza).'
			help:    [
				'Usage: cx store-mint-principal --id NAME --seed-file PATH --caps "read write"',
				'                               [--for grant|identity] [--force]',
				'',
				'Mints one XSP-AUTH principal entirely OFFLINE — the clean-state bootstrap',
				'for a deny-by-default daemon. Generates an Ed25519 seed, derives its',
				'did:key, writes the seed to PATH (mode 0600; never printed), and prints',
				'the daemon-config row for the service config\'s [xsp ...] section plus',
				'the client\'s xsp-did / xsp-seed-env open-opts.',
				'',
				'Nothing transits a wire and no store is opened. Config remains the SOLE',
				'authority: the minted principal is inert until an operator splices the',
				'printed grant into the daemon config.',
				'  --id NAME         principal name; derives the seed env var CX_XSP_SEED_<NAME>',
				'  --seed-file PATH  where the 32-byte seed lands, as hex, mode 0600',
				'  --caps CLASSES    REQUIRED for --for grant: space-separated capabilities',
				'                    for the printed row (read write delete admin peer).',
				'                    There is no default — the authority a grant carries is',
				'                    an explicit choice at mint time. Refused with',
				'                    --for identity, whose row carries no caps.',
				'  --for ROW         which daemon row to print: `grant` (default) = the',
				'                    [xsp [grants [grant ...]]] row authorizing this',
				'                    principal; `identity` = the daemon\'s OWN',
				'                    [xsp [identity did= seed-env=]] responder row',
				'  --force           replace an existing seed file (invalidates its DID)',
				'',
				'--id must be the CANONICAL spelling of its env var: lowercase, `-` for',
				'word breaks. CX_XSP_SEED_<NAME> upper-cases the id and folds `-` to `_`,',
				'so `fleet-ops`, `fleet_ops`, `Fleet-Ops` and `FLEET_OPS` would all derive',
				'CX_XSP_SEED_FLEET_OPS — two principals minted under two of those spellings',
				'would silently share ONE seed variable, and only the last one exported',
				'would work. Accepting the canonical spelling alone makes the derivation',
				'collision-free by construction; the others are refused, naming both the',
				'canonical id and the env var they would have shared.',
			]
			run:     run_store_mint_principal
		},
	]
}
