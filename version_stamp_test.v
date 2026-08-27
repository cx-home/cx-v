module cx

// version_stamp_test.v — the Ring-0 half of the #979/CO-4 provenance rule,
// the half the C ABI reports (#984).
//
// `cx_version()` used to answer the unstamped compile-time fallback in EVERY
// libcx, release artifacts included: vcx/Makefile's lib recipes passed no
// version defines at all, and check_version_consistency proved only that
// cabi.v DERIVES from the define, never that the define was PASSED. The
// library now carries version + release state, composed through the one
// function below — the same one cli.version_headline composes through, so the
// library and the cx binary cannot disagree about whether a build is the
// release its VERSION names.
//
// The `+<commit>` build metadata is deliberately NOT part of this rule; it
// belongs to `cx --version`, which has a provenance section. See the doc
// comment on version_stamp in cabi.v for why the library must not carry it.
//
// Pinning the ARTIFACT (that the defines actually reach a built libcx) is
// tests/abi/c_abi_test.c's test_version_stamp, driven by `make abi-c-test`.

fn test_version_stamp_renders_both_release_states() {
	// The two ruled shapes.
	assert version_stamp('0.17.0', 'release') == '0.17.0'
	assert version_stamp('0.17.0', 'dev') == '0.17.0-dev'
	// The version number itself is never touched — it is the VERSION file,
	// pre-release identifiers and all.
	assert version_stamp('1.2.3-rc1', 'release') == '1.2.3-rc1'
}

fn test_only_the_exact_release_state_claims_a_release() {
	// An unstamped build (the `dev` default), a typo, a case variant, or some
	// future state falls to the honest pre-release shape. The safe direction
	// is the default one.
	for state in ['', 'dev', 'Release', 'RELEASE', 'released', 'true', '1'] {
		assert version_stamp('0.17.0', state) == '0.17.0-dev',
			'state ${state} must not claim a release'
		assert !is_release_build(state), 'state ${state} must not read as a release'
	}
	assert is_release_build(release_state_release)
	assert release_state_release == 'release'
}

fn test_the_library_reports_the_composed_stamp() {
	// Whatever this build was stamped with, the exported surface reports the
	// COMPOSITION of the two defines — not the bare version, which is what
	// made every libcx claim a release it had not earned.
	assert cx_version_stamped == version_stamp(cx_version_str, cx_release_str)
	// A non-release build must carry the pre-release marker. `v test` passes
	// no defines, so this build is `dev` by the honest default.
	if !is_release_build(cx_release_str) {
		assert cx_version_stamped.ends_with('-dev'),
			'a non-release library must carry the -dev marker: ${cx_version_stamped}'
	}
}
