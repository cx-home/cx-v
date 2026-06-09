module main

import cx
import code
import os

// Phase 2.17 — `cx-stdlib` bundled skeleton tests.
//
// Asserts every frozen sub-package per spec/stdlib.md §3:
//   - is enumerated in `code.bundled_stdlib_names()`,
//   - exposes a non-empty source via `code.bundled_stdlib_source(name)`,
//   - parses cleanly through the existing scan + parse_def pipeline,
//   - exposes ≥ 1 `scope=public` [?def] (signature surface).
//
// Phase 2.17 ships signature-only; bodies are `null` placeholders and
// full implementations land per the Phase 3.x companion-spec rollout
// (spec/stdlib_strings.md, spec/stdlib_json.md, etc.).
//
// Cross-references:
// (bundling rule)
//   - spec/stdlib.md §3 (frozen sub-package surface).

// ── §3 surface — bundled sub-packages enumerated ─────────────────────────────
// Count tracks the bundled surface as module implementations land (16→17 when
// store landed; 17→19 when csv + url landed; 19→23 when crypto + geo + mime +
// validate landed; 23→24 email; 24→25 html; 25→26 i18n; 26→27 locale; 27→28 ft
// in the v0.8.0 std-lib impl phase; 28→32 when prof + process + fp + http
// joined the bundle — net was already enumerated). http is a count
// RECONCILIATION, not a +1: it was bundled as a signature stub from the impl
// phase (the README §3 row is the lone graduation edit, stdlib_http.md §12),
// so authoring http's spec/fixtures does NOT move this canary.

fn test_stdlib_surface_enumerates_bundled_subpackages() {
	names := code.bundled_stdlib_names()
	assert names.len == 37, 'expected 37 cx-stdlib sub-packages, got ${names.len}: ${names}'
	expected := [
		'cx-stdlib/strings',
		'cx-stdlib/json',
		'cx-stdlib/http',
		'cx-stdlib/re',
		'cx-stdlib/time',
		'cx-stdlib/math',
		'cx-stdlib/io',
		'cx-stdlib/net',
		'cx-stdlib/bytes',
		'cx-stdlib/format',
		'cx-stdlib/path',
		'cx-stdlib/log',
		'cx-stdlib/hash',
		'cx-stdlib/env',
		'cx-stdlib/test',
		'cx-stdlib/random',
		'cx-stdlib/uuid',
		'cx-stdlib/store',
		'cx-stdlib/csv',
		'cx-stdlib/url',
		'cx-stdlib/crypto',
		'cx-stdlib/geo',
		'cx-stdlib/mime',
		'cx-stdlib/validate',
		'cx-stdlib/email',
		'cx-stdlib/html',
		'cx-stdlib/i18n',
		'cx-stdlib/locale',
		'cx-stdlib/ft',
		'cx-stdlib/prof',
		'cx-stdlib/process',
		'cx-stdlib/fp',
		'cx-stdlib/bus',
		'cx-stdlib/journal',
		'cx-stdlib/session',
		'cx-stdlib/authz',
		'cx-stdlib/sched',
	]
	for n in expected {
		assert n in names, 'expected ${n} in bundled_stdlib_names(), got ${names}'
	}
}

// ── Every sub-package source is non-empty ────────────────────────────────────

fn test_stdlib_every_subpackage_has_source_bytes() {
	for name in code.bundled_stdlib_names() {
		src := code.bundled_stdlib_source(name) or {
			assert false, 'no source for ${name}'
			return
		}
		assert src.len > 0, 'empty source for ${name}'
		assert src.contains('[?def'), 'no [?def] declarations in ${name}: ${src}'
	}
}

// ── Each sub-package parses through the loader's scan + parse_def ────────────

fn test_stdlib_every_subpackage_parses_and_exposes_public_def() {
	for name in code.bundled_stdlib_names() {
		src := code.bundled_stdlib_source(name) or {
			assert false, 'no source for ${name}'
			return
		}
		mut table := code.new_module_table()
		mod := code.load_module(src, name, mut table) or {
			assert false, 'load_module failed for ${name}: ${err}'
			return
		}
		assert mod.defs.len > 0, '${name} exposes no [?def]'
		// At least one def is :scope public — every sub-package commits
		// to surface-via-public per spec/stdlib.md §3.
		mut any_public := false
		for _, def in mod.defs {
			if scope := def.scope {
				if scope == 'public' {
					any_public = true
					break
				}
			}
		}
		assert any_public, '${name} has no scope=public [?def]'
	}
}

// ── register_bundled_stdlib populates every name into a ModuleTable ──────────

fn test_stdlib_register_bundled_stdlib_populates_table() {
	mut table := code.new_module_table()
	code.register_bundled_stdlib(mut table)
	for name in code.bundled_stdlib_names() {
		assert name in table.registered_sources, 'expected ${name} in registered_sources'
	}
}

// ── bundled-stdlib version tag matches the binary version ────────────────────

fn test_stdlib_version_tag_matches_binary() {
	// spec/stdlib.md §2: bundled stdlib version follows the CX binary.
	// The constant in stdlib_bundle.v carries the canonical value used
	// by the cx-lock writer when emitting :resolved "bundled:<v>".
	assert code.cx_bundled_stdlib_version == '0.8.0',
		'expected cx_bundled_stdlib_version == 0.8.0, got ${code.cx_bundled_stdlib_version}'
}

// ── A program importing cx-stdlib/strings resolves with the loader ───────────

fn test_stdlib_lib_import_resolves_via_bundle() {
	// Synthetic consumer program imports cx-stdlib/strings — after
	// `register_bundled_stdlib(mut table)` it should resolve as a
	// registered-name resolver without filesystem or network access.
	mut table := code.new_module_table()
	code.register_bundled_stdlib(mut table)
	consumer_src := '[?lib "cx-stdlib/strings"]
[?def use-trim scope=public pure [returns string] ($s::string) [trim s]]'
	mod := code.load_module(consumer_src, 'consumer', mut table) or {
		assert false, 'consumer load failed: ${err}'
		return
	}
	assert mod.libs.len == 1
	assert mod.libs[0].resolver_source == 'cx-stdlib/strings'
	assert 'cx-stdlib/strings' in table.modules, 'expected stdlib strings module loaded'
}

// ── Spot-check: strings exposes the spec/stdlib.md §3 surface ────────────────

fn test_stdlib_strings_exposes_documented_surface() {
	// spec/stdlib.md §3 lists `upper`, `lower`, `trim`, `split`, `join`,
	// `replace` (etc.) for cx-stdlib/strings — assert each is present.
	src := code.bundled_stdlib_source('cx-stdlib/strings') or {
		assert false, 'no strings source'
		return
	}
	mut table := code.new_module_table()
	mod := code.load_module(src, 'cx-stdlib/strings', mut table) or {
		assert false, 'strings load failed: ${err}'
		return
	}
	for n in ['upper', 'lower', 'trim', 'split', 'join', 'replace'] {
		assert n in mod.defs, '${n} missing from cx-stdlib/strings'
	}
}

// ── On-disk skeleton files exist for inspection (advisory) ──────────────────

fn test_stdlib_on_disk_files_match_bundle_bytes() {
	// Both forms exist — the inline string consts (loader-facing) and
	// the on-disk `/stdlib/<name>.cx` files (human inspection). They
	// should be byte-identical so the bundle never silently drifts.
	import_os := os_module_for_disk_check()
	if !import_os {
		// Skip when running in an environment without filesystem access
		// (defensive — `os` is always available in this test harness).
		return
	}
	// One canonical check — strings.cx — keeps the test fast; if a
	// future regenerator gets wired up, all 14 can be validated.
	disk := read_stdlib_file('strings.cx') or {
		// Allow the test to pass when running outside the repo (the
		// bundle stays the source of truth in that case).
		return
	}
	bundle := code.bundled_stdlib_source('cx-stdlib/strings') or {
		assert false, 'no strings source'
		return
	}
	// Allow trailing-newline-difference; normalise via trim_space.
	assert disk.trim_space() == bundle.trim_space(),
		'cx-stdlib/strings: disk file diverges from bundle bytes'
}

// keep these compile-out helpers inline so the test file remains
// self-contained and the cx.LibNode + cx.DefNode types remain
// the only cross-module structural touchpoints we depend on.

fn os_module_for_disk_check() bool {
	return true
}

fn read_stdlib_file(name string) ?string {
	// Resolve against the repo root via the V `@VMODROOT` (= vcx/) —
	// stdlib/ sits one directory above.
	candidates := [
		os.join_path(@VMODROOT, '..', 'stdlib', name),
		os.join_path('stdlib', name),
	]
	for c in candidates {
		if os.exists(c) {
			s := os.read_file(c) or { continue }
			return s
		}
	}
	return none
}

// Touch every cx symbol the file uses so the V compiler keeps the
// `cx` import even when the disk-check helper above is conditionally
// disabled. cx.LibNode is the only first-class type the on-disk
// fixtures interrogate via `mod.libs`.
const _stdlib_skeleton_cx_keep_alive = cx.ResolverKind.registered_name
