module main

import os
import code

// `cx xap check-surface [DIR]` — the SURFACE DERIVATION CHECK, graduated out
// of the reference app (#846; it began life as reference/shop/check-surface.cx
// under #726, where it was that app's only implementation).
//
// surface.cxs says a surface "is DERIVED from the xap + feature specs: it
// BINDS already-declared verbs/views to MEDIA — it does NOT redeclare
// intents." That is a checkable claim about ANY surface, and the schema
// cannot check it: `cx validate` sees one document's SHAPE and knows nothing
// about the features. So a surface that names an intent no feature declares,
// instances a feature the xap never enabled, or shows a field that does not
// exist all validate cleanly. Nor would a web client catch them — a client
// tests RENDERING; these are errors of MEANING, decidable statically against
// the composed grammar and the enabled feature set.
//
// The check itself stays a CX program (language policy: tooling is CX first)
// — this command discovers the project's authored layers, splices their
// paths into the program, and evaluates it in-process. The report is the
// compose gate's tooling face: `ok=` plus EVERY problem, never just the
// first. The process exit is the gate face: any problem ⇒ exit 1, so a make
// target or CI can stand on it.

@[noreturn]
fn xap_check_surface_die(msg string) {
	eprintln('cx xap check-surface: ${msg}')
	eprintln('Usage: cx xap check-surface [DIR]')
	eprintln('')
	eprintln('DIR (default .) must hold the authored layers of one XAP project:')
	eprintln('  *.feature.cxd  (one or more)')
	eprintln('  *.xap.cxd      (exactly one)')
	eprintln('  *.surface.cxd  (one or more; each surface is checked)')
	exit(2)
}

fn run_xap_check_surface(args []string) {
	if args.len > 0 && args[0] in ['-h', '--help'] {
		println('Usage: cx xap check-surface [DIR]')
		println('')
		println('Checks that every *.surface.cxd in DIR is a faithful DERIVATION of')
		println('the xap + feature specs beside it — three classes the shape schema')
		println('cannot see:')
		println('  :unenabled-feature  a panel instances a feature the xap never enables')
		println('  :unknown-intent     a control names an intent no feature declares')
		println('  :unknown-field      a shown noun.field does not exist on the feature')
		println('')
		println('Reports like the compose gate\'s tooling face — ok= plus EVERY problem.')
		println('Exit: 0 clean, 1 any problem, 2 usage / not a XAP project directory.')
		exit(0)
	}
	if args.len > 1 {
		xap_check_surface_die('expected at most one DIR, got ${args.len} arguments')
	}
	dir := if args.len == 1 { args[0] } else { '.' }
	if !os.is_dir(dir) {
		xap_check_surface_die('${dir} is not a directory')
	}
	entries := os.ls(dir) or { xap_check_surface_die('cannot list ${dir}: ${err}') }
	mut features := []string{}
	mut xaps := []string{}
	mut surfaces := []string{}
	for e in entries {
		if e.ends_with('.feature.cxd') {
			features << os.join_path(dir, e)
		} else if e.ends_with('.xap.cxd') {
			xaps << os.join_path(dir, e)
		} else if e.ends_with('.surface.cxd') {
			surfaces << os.join_path(dir, e)
		}
	}
	features.sort()
	surfaces.sort()
	if xaps.len != 1 {
		xap_check_surface_die('${dir} holds ${xaps.len} *.xap.cxd files — a XAP project has exactly one')
	}
	if features.len == 0 {
		xap_check_surface_die('${dir} holds no *.feature.cxd — nothing to derive a surface from')
	}
	if surfaces.len == 0 {
		xap_check_surface_die('${dir} holds no *.surface.cxd — nothing to check')
	}
	for p in features {
		xap_check_surface_path_ok(p)
	}
	xap_check_surface_path_ok(xaps[0])

	// One evaluation per surface: the program is regenerated with that
	// surface's path spliced in, so each report stands alone.
	code.caps_set_list(['read']) or {
		eprintln('cx xap check-surface: ${err.msg()}')
		exit(2)
	}
	mut any_problem := false
	for sp in surfaces {
		xap_check_surface_path_ok(sp)
		prog := xap_check_surface_program(xaps[0], sp, features)
		out := code.eval_code('', prog, 'cx') or {
			// the `!`-guarded reads name the failing FILE; a project whose
			// inputs do not resolve must FAIL, never report over nothing
			eprintln('cx xap check-surface: ${err.msg()}')
			exit(1)
		}
		println(out.trim_space())
		if out.contains('ok=false') {
			any_problem = true
		}
	}
	if any_problem {
		exit(1)
	}
}

// The generated program embeds paths in single-quoted CX strings; a quote in
// a path would change the program, so it is refused rather than escaped.
fn xap_check_surface_path_ok(p string) {
	if p.contains("'") || p.contains('\\') {
		xap_check_surface_die('path ${p} contains a quote or backslash — move the project or pass a plain path')
	}
}

// xap_check_surface_program renders the check for ONE surface against the
// xap document and every feature document. It is the graduated form of
// reference/shop/check-surface.cx (#726), generalized: file paths are
// spliced by the CLI instead of hard-coded, and the feature count is
// whatever the project holds.
fn xap_check_surface_program(xap_path string, surface_path string, feature_paths []string) string {
	mut b := []string{}
	b << "[?lib 'cx-xap' :as xap]"
	b << "[?lib 'cx-stdlib/io' :as io]"
	b << "[?lib 'cx-stdlib/cx' :as cx]"
	b << "[?lib 'cx-stdlib/strings' :as strings]"
	b << ''
	b << '[; a shown token is `noun.field`; it is known when that field exists on'
	b << '   that noun of that feature. The composed grammar projects noun NAMES but'
	b << '   not their fields, so this reads the feature document. ]'
	b << '[?def shown-field-known scope=public (\$feat \$tok)'
	b << "  [?let [= \$parts [\$strings:split \$tok '.']]"
	b << '    [?if [= [\$count \$parts] 2]'
	b << '      [then [?let [= \$n [\$first \$parts]] [= \$f [\$last \$parts]]'
	b << '              [> [\$count \$feat//noun[= \$_@name \$n]//field[= \$_@name \$f]] 0]]]'
	b << '      [else false]]]]'
	b << ''
	b << '[; `!` guards each BINDING: navigating an err yields the EMPTY node-set'
	b << '   (code.md §6.2), and this check exists precisely to never say ok=true'
	b << '   over nothing — so a missing file names itself and aborts. ]'
	mut binds := []string{}
	binds << "[= \$xd  [\$cx:parse [\$io:read-file '${xap_path}']!]]"
	binds << "[= \$sfd [\$cx:parse [\$io:read-file '${surface_path}']!]]"
	for i, fp in feature_paths {
		binds << "[= \$fd${i} [\$cx:parse [\$io:read-file '${fp}']!]]"
	}
	joined_binds := binds.join('\n      ')
	b << '[?let ${joined_binds}'
	b << '  [?let [= \$xap     [\$first [?for [in \$n \$xd//xap] [yield \$n]]]]'
	b << '        [= \$surface [\$first [?for [in \$n \$sfd//surface] [yield \$n]]]]'
	mut fvars := []string{}
	for i, _ in feature_paths {
		b << '        [= \$f${i} [\$first [?for [in \$n \$fd${i}//feature] [yield \$n]]]]'
		fvars << '\$f${i}'
	}
	compose_args := fvars.join(' ')
	feats_seq := fvars.join(', ')
	b << '    [?let [= \$g [\$xap:compose ${compose_args}]]'
	b << '          [= \$feats (${feats_seq})]'
	b << ''
	b << '      [?let'
	b << '        [; 1 — a panel may only instance a feature the xap ENABLES. ]'
	b << '        [= \$bad-panels'
	b << '          [?for [in \$p \$surface//panel]'
	b << '            [where [= [\$count \$xap//features/feature[= \$_@name \$p@feature]] 0]]'
	b << '            [yield [problem kind=:unenabled-feature panel=\$p@name feature=\$p@feature]]]]'
	b << ''
	b << '        [; 2 — a control BINDS an already-declared intent; [?else] IS the'
	b << '           err channel\'s coalesce (§8.13), so resolving to the sentinel'
	b << '           means rho refused — ambiguous or unknown, both surface bugs. ]'
	b << '        [= \$bad-controls'
	b << '          [?for [in \$c \$surface//control]'
	b << '            [where [= [?else [\$xap:resolve \$g \$c@intent] :unresolved] :unresolved]]'
	b << '            [yield [problem kind=:unknown-intent intent=\$c@intent]]]]'
	b << ''
	b << '        [; 3 — every shown `noun.field` must exist on the panel\'s feature. ]'
	b << '        [= \$bad-shows'
	b << '          [?for [in \$p \$surface//panel]'
	b << "                [in \$tok [\$strings:split-whitespace [\$concat '' \$p/shows]]]"
	b << '            [where [not [\$shown-field-known'
	b << '                          [\$first [?for [in \$f \$feats] [where [= \$f@name \$p@feature]] [yield \$f]]]'
	b << '                          \$tok]]]'
	b << '            [yield [problem kind=:unknown-field panel=\$p@name shows=\$tok]]]]'
	b << ''
	b << '        [?let [= \$problems [?for [in \$s (\$bad-panels, \$bad-controls, \$bad-shows)]'
	b << '                                 [in \$p \$s] [yield \$p]]]'
	// R-A1 (2026-08-25): the problem rows splice as direct children.
	b << '          [surface-check surface=\$surface@name xap=\$surface@xap'
	b << '                         ok=[= [\$count \$problems] 0]'
	b << '            [?splice \$problems]]]]]]]'
	return b.join('\n')
}
