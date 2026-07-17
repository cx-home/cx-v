module main

import code

// TDD for cx-xap Tier-2 coordination channel (#25; spec/02-working/
// xap_feature_augmentation.md §3.2). The coordination channel carries ephemeral
// interaction state (viewport/selection) between features. It is TRANSIENT
// (latest-wins, not appended like the journal) and lives SEPARATELY from rt.log
// — off the PEP-gated cascade, out of audit by design.

// Latest-wins: a second publish replaces the first (transient, not appended).
fn test_xap_coord_latest_wins() {
	prog := "[?lib 'cx-xap' :as xap]
[?let [= \$rt [\$xap:run {tenant: \"helm\"}]]
[= \$a [\$xap:coord-publish \$rt \"chart/viewport\" [viewport zoom=12]]]
[= \$b [\$xap:coord-publish \$rt \"chart/viewport\" [viewport zoom=13]]]
  [\$xap:coord-read \$rt \"chart/viewport\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('zoom=13'), 'expected latest viewport (zoom=13), got: ${out}'
	assert !out.contains('zoom=12'), 'coordination must be latest-wins, not appended: ${out}'
}

// An unpublished channel reads empty (no frame yet).
fn test_xap_coord_empty_channel() {
	prog := "[?lib 'cx-xap' :as xap]
[?let [= \$rt [\$xap:run {tenant: \"helm\"}]]
  [\$xap:coord-read \$rt \"chart/viewport\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert !out.contains('viewport'), 'unpublished channel should be empty, got: ${out}'
}

// Coordination frames do NOT land in the journal/state (the partition between
// transient coordination and the durable cascade).
fn test_xap_coord_not_journaled() {
	prog := "[?lib 'cx-xap' :as xap]
[?let [= \$rt [\$xap:run {tenant: \"helm\"}]]
[= \$a [\$xap:coord-publish \$rt \"chart/viewport\" [viewport zoom=12]]]
  [\$xap:state \$rt \"/chart/viewport\"]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert !out.contains('zoom'), 'coordination must not appear in journal-backed state: ${out}'
}
