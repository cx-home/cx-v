module main

import code

// Behavioral TDD for the bundled cx-xap PEP (cx-private #7,
// spec/03-approved/xap/xap.md). The PEP is the cascade's step 1 (§2.2):
// principals have inherent authority; an agent must hold a dial-issued delegation;
// an un-granted intent is denied (CXER4850) and appends NOTHING; why-allowed is
// computed from the store (revoke flips it). These assert BEHAVIOR, not names.

const guestbook_setup = "[?lib 'cx-xap' :as xap]
[\$xap:component guestbook
  {bind: \"/guestbook\"
   emits: ([do :sign [name :string]])
   view: [?fn (\$gs) [panel [list]]]
   working-panel: :none}]
"

// An agent intent with NO dial is DENIED (CXER4850) — no covering delegation.
fn test_agent_denied_without_dial() {
	prog := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
  [\$xap:emit \$rt [do :sign [name \"Lin\"]] {actor: \"agent:greeter-1\"}]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4850'), 'agent emit without a dial must be denied (CXER4850), got: ${out}'
	assert !out.contains('Lin'), 'a denied intent must append nothing, got: ${out}'
}

// The denied agent intent left the journal/state EMPTY (append nothing on deny).
fn test_deny_appends_nothing() {
	prog := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
[?let [= \$x [\$xap:emit \$rt [do :sign [name \"Lin\"]] {actor: \"agent:greeter-1\"}]]
  [\$xap:state \$rt \"/guestbook\"]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert !out.contains('Lin'), 'denied emit must not be in state, got: ${out}'
}

// After the dial issues the covering delegation, the SAME agent intent is admitted
// and folds into state.
fn test_agent_admitted_after_dial() {
	prog := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
[?let [= \$d [\$xap:dial \$rt [from id=\"principal:dana\"] [to id=\"agent:greeter-1\"] [scope :guestbook] [setting :semi-auto]]]
[?let [= \$b [\$xap:emit \$rt [do :sign [name \"Lin\"]] {actor: \"agent:greeter-1\"}]]
  [\$xap:state \$rt \"/guestbook\"]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('Lin'), 'agent emit AFTER the dial must be admitted + folded, got: ${out}'
	assert !out.contains('CXER4850'), 'admitted emit must not be denied, got: ${out}'
}

// A principal actor has inherent authority — admitted with no dial at all.
fn test_principal_inherent_authority() {
	prog := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
[?let [= \$h [\$xap:emit \$rt [do :sign [name \"Ada\"]] {actor: \"principal:dana\"}]]
  [\$xap:state \$rt \"/guestbook\"]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('Ada'), 'principal emit must be admitted (inherent authority), got: ${out}'
	assert !out.contains('CXER4850'), 'principal must not be denied, got: ${out}'
}

// why-allowed is COMPUTED: true after the dial, then REVOKE flips it to false.
fn test_why_allowed_revoke_flips() {
	prog_allowed := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
[?let [= \$d [\$xap:dial \$rt [from id=\"principal:dana\"] [to id=\"agent:greeter-1\"] [scope :guestbook] [setting :semi-auto]]]
  [\$xap:why-allowed \$rt [do :sign [name \"Lin\"]] {actor: \"agent:greeter-1\"}]]]"
	out_allowed := code.eval_code('', prog_allowed, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out_allowed.contains("allowed='true'"), 'after dial, why-allowed must be true, got: ${out_allowed}'

	prog_revoked := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
[?let [= \$d [\$xap:dial \$rt [from id=\"principal:dana\"] [to id=\"agent:greeter-1\"] [scope :guestbook] [setting :semi-auto]]]
[?let [= \$r [\$xap:revoke \$rt \"d-dial-guestbook\"]]
  [\$xap:why-allowed \$rt [do :sign [name \"Lin\"]] {actor: \"agent:greeter-1\"}]]]]"
	out_revoked := code.eval_code('', prog_revoked, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out_revoked.contains("allowed='false'"), 'after revoke, why-allowed must flip to false, got: ${out_revoked}'
}

// After revoke, the agent's emit is again DENIED (the gate re-closes).
fn test_emit_denied_after_revoke() {
	prog := guestbook_setup +
		"[?let [= \$rt [\$xap:run {tenant: \"demo\" components: (guestbook)}]]
[?let [= \$d [\$xap:dial \$rt [from id=\"principal:dana\"] [to id=\"agent:greeter-1\"] [scope :guestbook] [setting :semi-auto]]]
[?let [= \$r [\$xap:revoke \$rt \"d-dial-guestbook\"]]
  [\$xap:emit \$rt [do :sign [name \"Lin\"]] {actor: \"agent:greeter-1\"}]]]]"
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out.contains('CXER4850'), 'after revoke the agent emit must be denied again, got: ${out}'
}
