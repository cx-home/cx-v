module cx

// cx lint — style + correctness warnings.
//
// Per internal design record
//
// Public V API:
// cx_text_lint(input, opts) -> []Finding — run all enabled checks
// lint_render_text(findings) -> string — gcc-style "path:line:col: ..."
// lint_render_json(findings) -> string — JSON array
// lint_render_summary(findings) -> string — counts per severity
//
// Five initial check IDs:
// CX-L001 — comment-style consistency (severity: info)
// CX-L002 — REMOVED (was long/short type-annotation mixing)
// CX-L003 — unused anchor (severity: warn)
// CX-L004 — dangling alias / merge (severity: error)
// CX-L005 — v3.4 deprecated patterns (severity: warn)
//
// v0 limitations (documented; future enhancement):
// - CX-L005 implementation covers leading-zero round-trip warning;
// the sized-type-needed and explicit-bool-attr checks are
// stubs.

pub enum Severity {
	info
	warn
	error_severity
}

fn severity_str(s Severity) string {
	return match s {
		.info { 'info' }
		.warn { 'warn' }
		.error_severity { 'error' }
	}
}

// severity_str_pub exposes severity_str for external test runners.
pub fn severity_str_pub(s Severity) string {
	return severity_str(s)
}

// Finding is one lint result. `path` uses CXPath syntax; `line` and
// `col` point at the offending token in the source. `suggestion` is
// optional (set per-check, omitted when no actionable fix exists).
pub struct Finding {
pub:
	check string // 'CX-L001' etc.
	severity Severity
	message string
	path string // CXPath expression
	line int // 1-based
	col int // 1-based
	suggestion string // empty when no specific fix recommended
}

pub struct LintOptions {
pub:
	disabled []string // e.g. ['CX-L003'] disables that check
	only string // e.g. 'CX-L004' runs only that one check ('' = all)
	severity_override map[string]Severity // CX-L00X → effective severity (config-driven)
}

pub fn cx_text_lint(input string, opts LintOptions) ![]Finding {
	doc := parse(input)!
	mut findings := []Finding{}

	if check_enabled('CX-L001', opts) {
		check_l001_comment_style(input, doc, mut findings)
	}
	// CX-L002 (long/short type-annotation mixing) deleted by 
	// short aliases (`:i`/`:s`/…) are removed, so there is no long/short
	// mixing left to police.
	if check_enabled('CX-L003', opts) {
		check_l003_unused_anchors(doc, mut findings)
	}
	if check_enabled('CX-L004', opts) {
		check_l004_dangling_aliases(doc, mut findings)
	}
	if check_enabled('CX-L005', opts) {
		check_l005_deprecated_patterns(input, doc, mut findings)
	}

	// Apply [?cx lint-disable=...] / lint-enable=... directive scopes.
	// The directives are scanned in document order; any finding whose
	// `path` is in scope of an active disable for that finding's check
	// is suppressed before return.
	suppressed_at_path := build_lint_suppression_map(doc)
	if suppressed_at_path.len > 0 {
		findings = filter_suppressed(findings, suppressed_at_path)
	}

	return findings
}

fn check_enabled(check string, opts LintOptions) bool {
	if opts.only != '' && opts.only != check {
		return false
	}
	for d in opts.disabled {
		if d == check { return false }
	}
	return true
}

// ── CX-L001 — comment-style consistency ──────────────────────────────────────

// Detect single-line [- block ] comments alongside # line comments
// in the same document. The v3.4 line-comment form (`# ...`) is
// canonical for one-liners; the [- block ] form is reserved for
// multi-line. A document mixing both for single lines indicates
// style drift the user can clean up by switching the single-line
// blocks to `#` form.
//
// Implementation note: the parser strips `#` line comments at parse
// time, so they are not visible in the AST. Detection scans the
// source text directly (mirroring CX-L005's source-text approach)
// for `# ...EOL` patterns and `[- ... ]` patterns, classifying each
// block comment as single-line or multi-line by whether its body
// contains a newline. If a document has at least one line comment
// AND at least one single-line block comment, every single-line
// block comment is flagged.
fn check_l001_comment_style(input string, doc Document, mut findings []Finding) {
	mut has_line_comment := false
	mut single_line_blocks := [][3]int{} // [start_byte, line, col]

	mut i := 0
	mut line := 1
	mut col := 1
	for i < input.len {
		c := input[i]
		if c == `\n` {
			line++
			col = 1
			i++
			continue
		}
		// Skip quoted strings to avoid false positives.
		if c == `'` || c == `"` {
			quote := c
			i++
			col++
			for i < input.len && input[i] != quote {
				if input[i] == `\n` { line++; col = 1 } else { col++ }
				i++
			}
			if i < input.len { i++; col++ }
			continue
		}
		// Skip raw-text blocks [# ... #] — content is not comment text.
		if c == `[` && i + 1 < input.len && input[i + 1] == `#` {
			i += 2; col += 2
			for i + 1 < input.len && !(input[i] == `#` && input[i + 1] == `]`) {
				if input[i] == `\n` { line++; col = 1 } else { col++ }
				i++
			}
			if i + 1 < input.len { i += 2; col += 2 }
			continue
		}
		// Line comment: # to end of line.
		if c == `#` {
			has_line_comment = true
			for i < input.len && input[i] != `\n` { i++; col++ }
			continue
		}
		// Block comment: [- ... ]. Multi-line if body contains a newline.
		if c == `[` && i + 1 < input.len && input[i + 1] == `-` {
			start_line := line
			start_col := col
			start_byte := i
			i += 2; col += 2
			mut multiline := false
			for i < input.len && input[i] != `]` {
				if input[i] == `\n` { multiline = true; line++; col = 1 } else { col++ }
				i++
			}
			if i < input.len { i++; col++ }
			if !multiline {
				single_line_blocks << [start_byte, start_line, start_col]!
			}
			continue
		}
		i++
		col++
	}

	if has_line_comment && single_line_blocks.len > 0 {
		for blk in single_line_blocks {
			findings << Finding{
				check: 'CX-L001'
				severity: .info
				message: "single-line block comment '[- ... ]' alongside # line comments — pick one style"
				path: ''
				line: blk[1]
				col: blk[2]
				suggestion: 'rewrite as # line comment for consistency, or move to multi-line block form'
			}
		}
	}
	_ = doc
}

// CX-L002 (long/short type-annotation mixing) removed by short
// aliases (`:i`/`:s`/…) are gone, so there is no mixing to police and the
// check, its source-scan helper, and the long/short alias tables are deleted.

// ── CX-L003 — unused anchor ──────────────────────────────────────────────────

// Walk the document collecting anchor declarations and alias/merge
// references. Emit a Finding for each anchor never referenced.
fn check_l003_unused_anchors(doc Document, mut findings []Finding) {
	mut anchors := map[string]string{} // anchor name -> CXPath
	mut refs := map[string]bool{}
	walk_collect_anchors_refs('', doc.elements, mut anchors, mut refs)
	for name, path in anchors {
		if name !in refs {
			findings << Finding{
				check: 'CX-L003'
				severity: .warn
				message: "anchor '${name}' declared but never referenced"
				path: path
				line: 0 // unknown without parser positions
				col: 0
				suggestion: "remove the anchor declaration, or add a *${name} reference"
			}
		}
	}
}

fn walk_collect_anchors_refs(parent string, nodes []Node, mut anchors map[string]string,
 mut refs map[string]bool) {
	mut name_count := map[string]int{}
	for n in nodes {
		if n is Element {
			el := n as Element
			idx := name_count[el.name]
			name_count[el.name] = idx + 1
			path := if parent == '' { '/' + el.name } else { parent + '/' + el.name }
			if name := el.anchor() {
				anchors[name] = path
			}
			if name := el.merge() {
				refs[name] = true
			}
			walk_collect_anchors_refs(path, el.items, mut anchors, mut refs)
		} else if n is AliasNode {
			refs[n.name] = true
		}
	}
}

// ── CX-L004 — dangling alias / merge ─────────────────────────────────────────

// Walk the document collecting all anchor names, then walk again
// looking for alias/merge references whose target wasn't declared.
fn check_l004_dangling_aliases(doc Document, mut findings []Finding) {
	mut anchors := map[string]string{}
	mut tmp_refs := map[string]bool{}
	walk_collect_anchors_refs('', doc.elements, mut anchors, mut tmp_refs)
	walk_check_dangling('', doc.elements, anchors, mut findings)
}

fn walk_check_dangling(parent string, nodes []Node, anchors map[string]string,
 mut findings []Finding) {
	mut name_count := map[string]int{}
	for n in nodes {
		if n is Element {
			el := n as Element
			idx := name_count[el.name]
			name_count[el.name] = idx + 1
			path := if parent == '' { '/' + el.name } else { parent + '/' + el.name }
			if name := el.merge() {
				if name !in anchors {
					findings << Finding{
						check: 'CX-L004'
						severity: .error_severity
						message: "merge reference '*${name}' has no matching '&${name}' anchor"
						path: path
						line: 0
						col: 0
						suggestion: "declare '&${name}' on a sibling element, or remove the merge reference"
					}
				}
			}
			walk_check_dangling(path, el.items, anchors, mut findings)
		} else if n is AliasNode {
			if n.name !in anchors {
				findings << Finding{
					check: 'CX-L004'
					severity: .error_severity
					message: "alias '*${n.name}' has no matching '&${n.name}' anchor"
					path: parent
					line: 0
					col: 0
					suggestion: "declare '&${n.name}' on a sibling element, or remove the alias"
				}
			}
		}
	}
}

// ── CX-L005 — v3.4 deprecated patterns ───────────────────────────────────────

// Source-text-level checks for patterns that round-trip differently
// between v3.3 and v3.4. The leading-zero check is implemented;
// sized-type-needed and explicit-bool-attr are stubs.
fn check_l005_deprecated_patterns(input string, _ Document, mut findings []Finding) {
	check_l005_leading_zero(input, mut findings)
}

// check_l005_leading_zero scans the source text for tokens that
// look like leading-zero numerics (e.g. `02134`). In v3.3 these
// auto-typed to int (after dropping leading zeros); in v3.4 they
// stay strings. Warn if the token appears unquoted; the user may
// be expecting v3.3 semantics.
fn check_l005_leading_zero(input string, mut findings []Finding) {
	mut line := 1
	mut col := 1
	mut i := 0
	for i < input.len {
		c := input[i]
		if c == `\n` {
			line++
			col = 1
			i++
			continue
		}
		// Skip strings/quoted tokens to avoid false positives.
		if c == `'` || c == `"` {
			quote := c
			i++
			col++
			for i < input.len && input[i] != quote {
				if input[i] == `\n` { line++; col = 1 } else { col++ }
				i++
			}
			if i < input.len { i++; col++ }
			continue
		}
		// Skip line comments (#...EOL) and block comments [-...].
		if c == `#` {
			for i < input.len && input[i] != `\n` { i++; col++ }
			continue
		}
		// Look for leading-zero numerics: at-word-boundary `0` followed by
		// 1+ ASCII digits. Avoids `0`, `0.5`, `0x...`, `0b...`, `0o...`.
		if c == `0` && (i == 0 || !is_word_char(input[i-1])) && i + 1 < input.len {
			next := input[i+1]
			if next >= `1` && next <= `9` {
				// Found `0` followed by a digit 1-9. Read the full token.
				start_col := col
				start := i
				mut end := i + 1
				for end < input.len && ((input[end] >= `0` && input[end] <= `9`) || input[end] == `_`) {
					end++
				}
				// Only flag pure integers (no `.`, no `e`).
				if end == input.len || (input[end] != `.` && input[end] != `e` && input[end] != `E`) {
					token := input[start..end]
					findings << Finding{
						check: 'CX-L005'
						severity: .warn
						message: "leading-zero numeric '${token}' is now a string in v3.4 (was int in v3.3)"
						path: '' // tracked by line:col, no AST path
						line: line
						col: start_col
						suggestion: "if you want it as a string keep as-is; if you wanted the numeric, drop the leading zero"
					}
				}
				col += (end - i)
				i = end
				continue
			}
		}
		i++
		col++
	}
}

fn is_word_char(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`)
		|| (b >= `0` && b <= `9`) || b == `_` || b == `.`
}

// ── Suppression: [?cx lint-disable=...] / lint-enable=... ────────────────────
//
// Per D7. Directives are CXDirective nodes whose attrs
// contain `lint-disable=CHECK,CHECK,...` or `lint-enable=...`. Scope
// is "from the directive onward in document order until the
// enclosing element ends or a counter-directive". `lint-disable=all`
// suppresses every check.
//
// build_lint_suppression_map walks the document with a scope stack
// and records, for every Element, the set of check IDs disabled at
// that element's path. filter_suppressed drops any finding whose
// path falls within the disabled scope of a check.

fn build_lint_suppression_map(doc Document) map[string]map[string]bool {
	mut current := map[string]bool{}
	mut by_path := map[string]map[string]bool{}
	// Walk prolog + top-level elements as one stream — top-level
	// directives govern everything that follows in the document, not
	// just the sub-list they happen to live in. There is no
	// "enclosing element" at the document scope, so no save/restore
	// boundary applies here.
	for n in doc.prolog {
		process_lint_node(n, '', mut current, mut by_path)
	}
	for n in doc.elements {
		process_lint_node(n, '', mut current, mut by_path)
	}
	return by_path
}

fn process_lint_node(n Node, parent string, mut current map[string]bool, mut by_path map[string]map[string]bool) {
	match n {
		CXDirectiveNode {
			for a in n.attrs {
				val := scalar_value_str(a.value)
				if a.name == 'lint-disable' {
					for c in split_check_list(val) {
						current[c] = true
					}
				} else if a.name == 'lint-enable' {
					for c in split_check_list(val) {
						current.delete(c)
					}
				}
			}
		}
		Element {
			path := if parent == '' { '/' + n.name } else { parent + '/' + n.name }
			by_path[path] = current.clone()
			// Recurse into element body with restore-on-exit so the
			// directive's scope ends with the enclosing element per
			// D7.
			saved := current.clone()
			for child in n.items {
				process_lint_node(child, path, mut current, mut by_path)
			}
			current.clear()
			for k, v in saved {
				current[k] = v
			}
		}
		else {}
	}
}

fn split_check_list(val string) []string {
	mut out := []string{}
	for part in val.split(',') {
		t := part.trim_space()
		if t.len > 0 { out << t }
	}
	return out
}

// finding_check_disabled returns true when the finding's path falls
// within an element scope where the finding's check is disabled, OR
// when 'all' was disabled. Findings with empty path (source-text-
// positioned, like CX-L001 / CX-L005) are matched against the
// document-root scope only — finer-grained line-based suppression
// is a future enhancement.
fn finding_check_disabled(f Finding, by_path map[string]map[string]bool) bool {
	if f.path == '' {
		// Source-text-positioned findings consult the empty-path
		// (document-root) scope. The walk records by_path['/<root>']
		// for every top-level Element; we use the first one as the
		// root-scope proxy. If no scope was recorded at all, no
		// suppression applies.
		if by_path.len == 0 { return false }
		for _, scope in by_path {
			if 'all' in scope || f.check in scope {
				return true
			}
			break
		}
		return false
	}
	// Walk path prefixes from full path up to /. Finding is suppressed
	// if any prefix has the check (or 'all') disabled.
	mut p := f.path
	for {
		if scope := by_path[p] {
			if 'all' in scope || f.check in scope {
				return true
			}
		}
		idx := p.last_index('/') or { return false }
		if idx == 0 {
			break
		}
		p = p[..idx]
	}
	return false
}

fn filter_suppressed(findings []Finding, by_path map[string]map[string]bool) []Finding {
	mut out := []Finding{cap: findings.len}
	for f in findings {
		if !finding_check_disabled(f, by_path) {
			out << f
		}
	}
	return out
}

// ── .cxlint.cx config-file support ───────────────────────────────────────────
//
// Per D7 second mechanism. A `.cxlint.cx` file (CX-formatted)
// at the working directory or any ancestor provides default
// suppressions. Recognized children of the [lint] root element:
//
// [disable check=CX-L003] # disable a check globally
// [severity check=CX-L005 level=info] # override severity
//
// `path=...` glob filters and `--config=...` explicit paths are
// future enhancements; v0 supports the no-glob "disable everywhere"
// and "severity override" cases since those cover most adoption
// patterns. Missing config file is not an error.

pub struct LintConfig {
pub mut:
	disabled []string // check IDs disabled by config
	severity_override map[string]Severity // check ID → effective severity
}

// load_lint_config_from parses a .cxlint.cx file content into a
// LintConfig. Empty content / missing top-level [lint] element
// returns the empty config.
pub fn load_lint_config_from(content string) !LintConfig {
	mut cfg := LintConfig{
		disabled: []string{}
		severity_override: map[string]Severity{}
	}
	if content.trim_space() == '' { return cfg }
	doc := parse(content)!
	for n in doc.elements {
		if n is Element {
			if n.name != 'lint' { continue }
			for child in n.items {
				if child is Element {
					match child.name {
						'disable' {
							if v := element_attr_string(child, 'check') {
								cfg.disabled << v
							}
						}
						'severity' {
							if check := element_attr_string(child, 'check') {
								if level := element_attr_string(child, 'level') {
									if sev := parse_severity_level(level) {
										cfg.severity_override[check] = sev
									}
								}
							}
						}
						else {}
					}
				}
			}
		}
	}
	return cfg
}

fn element_attr_string(e Element, name string) ?string {
	for a in e.attrs {
		if a.name == name {
			return scalar_value_str(a.value)
		}
	}
	return none
}

fn parse_severity_level(s string) ?Severity {
	return match s {
		'info' { ?Severity(.info) }
		'warn' { ?Severity(.warn) }
		'error' { ?Severity(.error_severity) }
		else { none }
	}
}

// merge_config_into_options applies a LintConfig to a LintOptions:
// the config's disabled list extends the options' disabled list (de-
// duplicated). Severity overrides are stored in the LintOptions for
// the post-pass renderer to apply.
pub fn merge_config_into_options(cfg LintConfig, opts LintOptions) LintOptions {
	mut combined := opts.disabled.clone()
	for d in cfg.disabled {
		if d !in combined { combined << d }
	}
	return LintOptions{
		disabled: combined
		only: opts.only
		severity_override: cfg.severity_override.clone()
	}
}

// apply_severity_overrides rewrites Finding.severity per the config's
// severity_override map. Used after cx_text_lint when overrides are
// present.
pub fn apply_severity_overrides(findings []Finding, overrides map[string]Severity) []Finding {
	if overrides.len == 0 { return findings }
	mut out := []Finding{cap: findings.len}
	for f in findings {
		if sev := overrides[f.check] {
			out << Finding{
				check: f.check
				severity: sev
				message: f.message
				path: f.path
				line: f.line
				col: f.col
				suggestion: f.suggestion
			}
		} else {
			out << f
		}
	}
	return out
}

// ── Renderers ────────────────────────────────────────────────────────────────

// lint_render_text produces gcc-style "path:line: SEVERITY [CHECK-ID] message".
pub fn lint_render_text(findings []Finding) string {
	if findings.len == 0 { return '' }
	mut out := []string{cap: findings.len}
	for f in findings {
		loc := if f.line > 0 { '${f.line}:${f.col}: ' } else { '' }
		ctx := if f.path != '' { ' [${f.path}]' } else { '' }
		mut line := '${loc}${severity_str(f.severity)} ${f.check}: ${f.message}${ctx}'
		if f.suggestion != '' {
			line += '\n suggestion: ${f.suggestion}'
		}
		out << line
	}
	return out.join('\n')
}

// lint_render_json produces an array of finding records.
pub fn lint_render_json(findings []Finding) string {
	if findings.len == 0 { return '[]' }
	mut out := []string{cap: findings.len + 2}
	out << '['
	for i, f in findings {
		mut fields := []string{}
		fields << '"check": ${json_quote(f.check)}'
		fields << '"severity": ${json_quote(severity_str(f.severity))}'
		fields << '"message": ${json_quote(f.message)}'
		if f.path != '' {
			fields << '"path": ${json_quote(f.path)}'
		}
		if f.line > 0 {
			fields << '"line": ${f.line}'
			fields << '"col": ${f.col}'
		}
		if f.suggestion != '' {
			fields << '"suggestion": ${json_quote(f.suggestion)}'
		}
		comma := if i < findings.len - 1 { ',' } else { '' }
		out << ' { ' + fields.join(', ') + ' }' + comma
	}
	out << ']'
	return out.join('\n')
}

// lint_render_summary produces a one-line summary: counts per severity
// and per check ID.
pub fn lint_render_summary(findings []Finding) string {
	if findings.len == 0 { return 'no findings' }
	mut info_count := 0
	mut warn_count := 0
	mut err_count := 0
	for f in findings {
		match f.severity {
			.info { info_count++ }
			.warn { warn_count++ }
			.error_severity { err_count++ }
		}
	}
	return '${findings.len} finding(s): ${err_count} error, ${warn_count} warn, ${info_count} info'
}

// ── fail-on threshold ────────────────────────────────────────────────────────

// findings_at_or_above_threshold returns true if any finding has
// severity >= threshold. Used by the CLI to decide exit code.
pub fn findings_at_or_above_threshold(findings []Finding, threshold Severity) bool {
	for f in findings {
		if severity_rank(f.severity) >= severity_rank(threshold) {
			return true
		}
	}
	return false
}

fn severity_rank(s Severity) int {
	return match s {
		.info { 0 }
		.warn { 1 }
		.error_severity { 2 }
	}
}
