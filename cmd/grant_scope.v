module main

// Grant-suffix discipline for the CLI capability flags (#1059).
//
// `--allow-<cap>=RESOURCE` is the scope spelling. Exactly ONE capability
// enforces it today: `net`, whose host[:port] scope narrows the dialable
// set and is checked at the effect point. `read` and `write` carried the
// same spelling and DROPPED it on the floor — `cx --allow-read=/tmp p.cx`
// parsed to the bare `read` grant and the program could read `/etc/hosts`,
// silently, exit 0. The suffix looked like a boundary and was not one.
//
// That is the #713 / #880 fail-open-silence class, in the one direction a
// deny-by-default capability system must never be silent in: OVER-grant. A
// caller who types the narrower spelling gets the WIDER authority than the
// one they asked for, with nothing on stderr to say so.
//
// Until real path scoping lands (cx-home/cx-private#1061 — prefix
// semantics, canonicalization, symlink policy), the suffix REFUSES at
// startup: a usage error (exit 2) before any program evaluation, naming
// the flag, the suffix it would have ignored, the authority it would have
// granted instead, the accepted bare spelling, and the tracking issue.
// Fail closed and loud, never open and quiet.
//
// The bare grants are untouched: `--allow-read` / `--allow-write` still
// grant exactly what they always granted. `--allow-net`'s scoping is
// untouched. No new semantics are invented here — the refusal says the
// scoping does not exist yet, which is the true statement.

// scope_unenforced_caps names the capabilities whose `=RESOURCE` suffix the
// engine does not enforce and which therefore REFUSE the suffix rather than
// accept it as a no-op.
//
// It is deliberately NOT `capability_names() minus net`. These three are the
// ones whose suffix reads as a real boundary and was PROBED fail-open at
// v0.16.0 (version-literal-ok): `--allow-read=/nonexistent` read `/etc/hosts`,
// `--allow-write=/nonexistent` wrote `/tmp/probe.txt`, `--allow-env=HOME`
// read `$SHELL`. All three spellings appear in documentation as the normal
// invocation, which is what makes the silence expensive.
//
// The remaining non-net capabilities (`clock`, `random`, `subprocess`,
// `eval`, `secret-reveal`) still accept-and-ignore a suffix. `subprocess`
// is the one that matters there — security.md §2 specifies an allowed-
// executables constraint the guard does not enforce (see the C12 note in
// diagram.v) — and it is recorded on #1061 §6 for a decision rather than
// swept in here. Adding a name to this list is all it takes to close one.
fn scope_unenforced_caps() []string {
	return ['read', 'write', 'env']
}

// grant_scope_refusal returns the usage diagnostic for an unenforceable
// `--allow-<cap>=RESOURCE`, or an empty slice when the argument is fine.
//
// `cmd` is the command word for the diagnostic prefix ('cx',
// 'cx eval', 'cx diagram', …), `arg` the flag as typed, `cap_name` the
// capability parsed out of it, and `rest` everything after `--allow-`
// (i.e. `cap` or `cap=resource`).
fn grant_scope_refusal(cmd string, arg string, cap_name string, rest string) []string {
	if !rest.contains('=') || cap_name !in scope_unenforced_caps() {
		return []string{}
	}
	suffix := rest.all_after('=')
	shown := if suffix == '' { '(empty)' } else { suffix }
	// read/write scope a path; env scopes a variable name. Say which.
	kind := if cap_name == 'env' { 'per-name' } else { 'per-path' }
	breadth := if cap_name == 'env' { 'every variable' } else { 'the whole filesystem' }
	return [
		'${cmd}: ${arg}: ${cap_name} scoping is NOT IMPLEMENTED — the resource `${shown}` would be IGNORED and the grant would be BLANKET ${cap_name} authority over ${breadth}, not the narrowing this spells (cx-home/cx-private#1059)',
		'  the accepted spelling is the bare grant:  --allow-${cap_name}',
		'  it grants ${cap_name} over ${breadth} — which is what the suffixed form has always done — so say it explicitly instead of appearing to narrow it',
		'  real ${kind} ${cap_name} scoping is tracked at cx-home/cx-private#1061',
		'  `--allow-net=host[:port]` is the one grant whose scope IS enforced today',
	]
}

// refuse_unenforced_grant_scope prints the refusal and exits 2 (the usage
// band) when `arg` carries an unenforceable scope suffix. No-op otherwise.
// Called from every CLI grant parse site, BEFORE any program is read or
// evaluated, so the refusal can never race an effect.
fn refuse_unenforced_grant_scope(cmd string, arg string, cap_name string, rest string) {
	lines := grant_scope_refusal(cmd, arg, cap_name, rest)
	if lines.len == 0 {
		return
	}
	for line in lines {
		eprintln(line)
	}
	exit(2)
}
