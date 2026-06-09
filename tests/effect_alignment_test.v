module main

import code

// effect_alignment_test.v — the §6.5.1 capability-alignment gate
// (spec/core/code.md §6.5.1; SAP §4.1 ALIGNMENT; D010).
//
// Enforces BOTH directions of the ONE-WAY invariant + drift canaries:
//
//   (1) gated ⇒ impure : every capability_gated_prims() key is classified
//       impure by the closed §6.5.x purity table.
//   (2) closed exception table : every impure entry of the purity table is
//       EITHER capability-gated OR in the closed exception buckets.
//   (3) drift canaries : the gated map agrees with the LIVE dispatcher lists
//       (process- prefix, env- minus env_pure_prims, io read+write+open),
//       so the table cannot silently drift from the guards it mirrors.
//
// The maps are owned by effect_alignment.v (one source of truth shared by
// the checker fold and this gate).

// ── (1) gated ⇒ impure ─────────────────────────────────────────────────────────

fn test_every_gated_prim_is_impure() {
	gated := code.capability_gated_prims()
	assert gated.len > 0, 'capability_gated_prims() is empty — the gate has nothing to enforce'
	mut violations := []string{}
	for prim, cap in gated {
		if !code.builtin_is_impure(prim) {
			violations << '${prim} (gated under `${cap}`) is NOT classified impure'
		}
	}
	assert violations.len == 0, 'direction-1 (gated ⇒ impure) violations:\n  ' +
		violations.join('\n  ')
}

// ── (2) every impure entry is gated OR in the closed exception table ───────────

fn test_every_impure_is_gated_or_excepted() {
	gated := code.capability_gated_prims()
	exceptions := code.impure_without_capability_exceptions()
	impure := code.impure_builtin_names()
	assert impure.len > 0, 'no impure builtins — the purity table is empty'
	mut orphans := []string{}
	for prim in impure {
		if prim in gated {
			continue
		}
		if prim in exceptions {
			continue
		}
		orphans << prim
	}
	assert orphans.len == 0,
		'direction-2 violation — impure-without-capability builtins missing from the closed exception table:\n  ' +
		orphans.join('\n  ') +
		'\n(either gate them with cap_guard, or add an exception row in effect_alignment.v)'
}

// The exception table must be CLOSED: no entry that is also gated (an entry
// cannot be both), and no entry that is not actually impure.
fn test_exception_table_is_closed_and_consistent() {
	gated := code.capability_gated_prims()
	exceptions := code.impure_without_capability_exceptions()
	for prim, _ in exceptions {
		assert prim !in gated,
			'`${prim}` is in BOTH the gated map and the exception table — it cannot be both'
		assert code.builtin_is_impure(prim),
			'`${prim}` is in the impure-without-capability exception table but is NOT classified impure'
	}
}

// ── (3) drift canaries ─────────────────────────────────────────────────────────

// Every gated `process-` prim is the whole process- prefix (the dispatcher
// gates the prefix), and every purity-table `process-` name is gated.
fn test_process_prefix_fully_gated() {
	gated := code.capability_gated_prims()
	for prim in code.impure_builtin_names() {
		if prim.starts_with('process-') {
			assert prim in gated,
				'`${prim}` starts with `process-` but is not in the gated map (process- is prefix-gated)'
			assert gated[prim] == 'subprocess',
				'`${prim}` should be gated under `subprocess`, got `${gated[prim]}`'
		}
	}
}

// Every gated `env-` prim is an env- name NOT in env_uncapped_prims, charged
// under `env` (environment/identity) or `read` (cwd / executable-path
// filesystem-layout disclosure, env.md §7); and no uncapped name is gated.
fn test_env_gating_excludes_pure_prims() {
	gated := code.capability_gated_prims()
	pure_prims := code.alignment_env_pure_prims()
	read_prims := ['env-cwd', 'env-executable-path']
	for prim, cap in gated {
		if prim.starts_with('env-') {
			assert prim !in pure_prims,
				'`${prim}` is in the gated map but is a capability-free env name (env_uncapped_prims)'
			expected_cap := if prim in read_prims { 'read' } else { 'env' }
			assert cap == expected_cap,
				'`${prim}` should be gated under `${expected_cap}`, got `${cap}`'
		}
	}
	for pure_prim in pure_prims {
		assert pure_prim !in gated,
			'uncapped env name `${pure_prim}` must NOT be capability-gated'
	}
}

// The gated io surface == io_read_caps ∪ io_write_caps ∪ {io-open}.
fn test_io_gated_set_matches_dispatcher_lists() {
	gated := code.capability_gated_prims()
	mut expected := map[string]bool{}
	for n in code.alignment_io_read_caps() {
		expected[n] = true
	}
	for n in code.alignment_io_write_caps() {
		expected[n] = true
	}
	expected['io-open'] = true

	// Every expected io prim is gated.
	for prim, _ in expected {
		assert prim in gated, 'io prim `${prim}` (dispatcher list) is not in the gated map'
	}
	// Every gated io- prim is expected (no extras, no drift).
	for prim, _ in gated {
		if prim.starts_with('io-') {
			assert prim in expected,
				'gated io prim `${prim}` is not in io_read_caps ∪ io_write_caps ∪ {io-open}'
		}
	}
}

// Sanity: the four cap-gated path/store/i18n/testkit singletons are present
// and impure (these are the C2 additions that previously defaulted pure).
fn test_c2_newly_classified_singletons() {
	for prim in ['path-absolute', 'path-canonical', 'i18n-load-catalog',
		'test-fixture-load', 'store-open', 'store-open-opts'] {
		assert code.builtin_is_impure(prim),
			'`${prim}` must be classified impure (it is capability-gated)'
		assert prim in code.capability_gated_prims(), '`${prim}` must be in the gated map'
	}
	// `test-fixture` (the in-memory, ungated sibling) must NOT be gated.
	assert 'test-fixture' !in code.capability_gated_prims(),
		'`test-fixture` builds an in-memory sequence with no cap_guard — it must not be gated'
}
