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
	doc := parse(input) or {
		// #921: the reader dispatch must agree with fmt/run (#391) — a
		// call-shaped PROGRAM document (`[$xap:component …]`) is not a
		// lint parse failure just because the DATA reading refuses it.
		// When the program reading accepts the source there is no data
		// tree for the doc-shaped checks: return no findings rather than
		// a false refusal. A document BOTH readings refuse keeps
		// reporting the data diagnostic, exactly like cx_text_fmt's
		// arbitration.
		data_err := err
		parse_program(input) or { return data_err }
		return []Finding{}
	}
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
	if check_enabled('CX-L006', opts) {
		check_l006_let_staircase(input, mut findings)
	}
	if check_enabled('CX-L008', opts) {
		check_l008_pipe_stage_flow(input, mut findings)
	}
	if check_enabled('CX-L007', opts) {
		check_l007_field_read_aggregation(input, mut findings)
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

// ── CX-L006 — flatten nested single-binding [?let] staircases (#65) ───────────
//
// A deep chain of nested single-binding [?let] forms — each [?let] whose only
// `[= …]` binding precedes a body that is exactly the next [?let], terminating
// in one expression — is a `let*` written the verbose way. [?let] already takes
// multiple `[= …]` clauses before its body, so the staircase collapses to one
// flat [?let]. This is an advisory (info), DETECT-ONLY hint: it flags the
// OUTERMOST [?let] of a pure staircase of depth >= let_staircase_min and
// suggests the flat form; it does NOT rewrite (autofix is a separate, larger
// surface). Non-pure nestings (a [?let] with >1 binding, the legacy
// bind/value/body slot form, or a body that is an [?if]/[?match]/[?for]/other
// expression) are left untouched — only the exact chain shape matches.

const let_staircase_min = 3

// is_let_binding_clause reports whether `n` is a `[= $x V]` binding clause —
// the exact shape eval_let's binding_clause accepts.
fn is_let_binding_clause(n ProgramNode) bool {
	if n is ProgramLiteral {
		if n.kind == .cx_element && n.name == '=' && n.items.len == 2 {
			head := n.items[0]
			if head is ProgramBinding {
				return head.path.len == 0
			}
		}
	}
	return false
}

// pure_single_binding_let returns the body of `d` IFF `d` is the pure
// single-binding positional [?let] form: exactly one `[= …]` binding then one
// body, no labeled (legacy bind/value/body) slots. Else none.
fn pure_single_binding_let(d ProgramDirective) ?ProgramNode {
	mut positionals := []ProgramNode{}
	for s in d.slots {
		if s.kind == .labeled {
			return none
		}
		positionals << s.value
	}
	if positionals.len != 2 {
		return none
	}
	if !is_let_binding_clause(positionals[0]) {
		return none
	}
	return positionals[1]
}

// let_staircase_depth counts consecutive pure single-binding [?let] forms from
// `d` and returns (depth, terminal_body) — terminal_body is the first body that
// is not itself such a [?let].
fn let_staircase_depth(d ProgramDirective) (int, ProgramNode) {
	mut depth := 0
	mut cur := ProgramNode(d)
	for {
		if cur is ProgramDirective {
			if cur.name == 'let' {
				if body := pure_single_binding_let(cur) {
					depth++
					cur = body
					continue
				}
			}
		}
		break
	}
	return depth, cur
}

fn check_l006_let_staircase(input string, mut findings []Finding) {
	// Parse the PROGRAM reading; a pure-data resource (no [?let] program form)
	// simply doesn't parse here and is skipped.
	prog := parse_program(input) or { return }
	walk_let_staircase(prog.body, mut findings)
}

fn walk_let_staircase(node ProgramNode, mut findings []Finding) {
	if node is ProgramDirective {
		if node.name == 'let' {
			depth, terminal := let_staircase_depth(node)
			if depth >= let_staircase_min {
				findings << Finding{
					check:      'CX-L006'
					severity:   .info
					message:    'nested single-binding [?let] staircase (${depth} levels) — [?let] accepts multiple [= …] clauses; collapse to one flat [?let] (let*)'
					line:       node.pos.line
					col:        node.pos.col
					suggestion: 'rewrite as a single [?let] with the ${depth} bindings in order followed by the body'
				}
				// Do not descend INTO the flagged chain (avoid re-flagging the
				// inner lets); continue scanning from its terminal body.
				walk_let_staircase(terminal, mut findings)
				return
			}
		}
	}
	walk_let_staircase_children(node, mut findings)
}

fn walk_let_staircase_children(node ProgramNode, mut findings []Finding) {
	match node {
		ProgramDirective {
			for s in node.slots {
				walk_let_staircase(s.value, mut findings)
			}
		}
		ProgramLiteral {
			if ne := node.name_expr {
				walk_let_staircase(ne, mut findings)
			}
			for it in node.items {
				walk_let_staircase(it, mut findings)
			}
			for a in node.attrs {
				walk_let_staircase(a.value, mut findings)
			}
		}
		ProgramCall {
			for a in node.args {
				walk_let_staircase(a, mut findings)
			}
		}
		ProgramForComp {
			// L100: THE ONE traversal (program_for_walk.v).
			for item in for_comp_children(node) {
				walk_let_staircase(item.node, mut findings)
			}
		}
		Program {
			walk_let_staircase(node.body, mut findings)
		}
		else {}
	}
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
// ── CX-L007 — aggregation over a simple field accessor (#610) ────────────────
//
// `[$count $x/field]` (and $empty / $exists) over a PURE child chain is a
// FIELD READ: per code.md §6.2 it aggregates the field's CONTENT — for a
// field holding one element, the inner element's own arity — never "how
// many children matched". The trap was ruled by-design in #584 (the
// field-read algebra is load-bearing platform-wide); at scale the guard is
// this lint, not folklore. Warning severity: the composition is legal and
// sometimes intended (`[$count $x/list]` over a multi-item field is
// idiomatic), so the finding teaches the sanctioned match-counting idioms
// rather than forbidding the read.
fn check_l007_field_read_aggregation(input string, mut findings []Finding) {
	prog := parse_program(input) or { return } // not program source → not this rule's domain
	l007_walk(prog.body, mut findings)
}

fn l007_flag(call ProgramCall, b ProgramBinding, mut findings []Finding) {
	mut chain := '\$${b.name}'
	for st in b.path {
		chain += '/${st.name}'
	}
	findings << Finding{
		check:    'CX-L007'
		severity: .warn
		message:  '[\$${call.name} ${chain}] aggregates the FIELD\'s content (code.md §6.2: a one-element field reports the inner element\'s arity), not how many `${b.path.last().name}` children matched'
		path:     chain
		line:     call.pos.line
		col:      call.pos.col
		suggestion: 'for match-counting use [\$${call.name} ${chain.all_before_last('/')}//${b.path.last().name}], [\$count ${chain.all_before_last('/')}/*], or a predicate step; keep the field read only if you mean the content'
	}
}

fn l007_walk(n ProgramNode, mut findings []Finding) {
	match n {
		Program {
			l007_walk(n.body, mut findings)
		}
		ProgramCall {
			if n.name in ['count', 'empty', 'exists'] && n.args.len == 1 {
				a := n.args[0]
				if a is ProgramBinding {
					if a.path.len > 0 {
						mut pure_chain := true
						for st in a.path {
							if st.kind != .child || st.predicates.len > 0 {
								pure_chain = false
								break
							}
						}
						if pure_chain {
							l007_flag(n, a, mut findings)
						}
					}
				}
			}
			for a in n.args {
				l007_walk(a, mut findings)
			}
		}
		ProgramDirective {
			for s in n.slots {
				l007_walk(s.value, mut findings)
			}
		}
		ProgramForComp {
			// L100: THE ONE traversal (program_for_walk.v).
			for item in for_comp_children(n) {
				l007_walk(item.node, mut findings)
			}
		}
		ProgramLiteral {
			for it in n.items {
				l007_walk(it, mut findings)
			}
			for at in n.attrs {
				l007_walk(at.value, mut findings)
			}
			for s in n.slots {
				l007_walk(s.value, mut findings)
			}
			if ne := n.name_expr {
				l007_walk(ne, mut findings)
			}
		}
		else {}
	}
}

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
		// Block comment: [; ... ]. The body runs to the matching `]`, balancing
		// nested `[`…`]` (a comment may contain bracketed prose), mirroring the
		// reader's read_until_close. Multi-line if the body contains a newline.
		// (`[-` is the subtraction operator post the [; …] migration, never a
		// comment — so this rule no longer keys on it.)
		if c == `[` && i + 1 < input.len && input[i + 1] == `;` {
			start_line := line
			start_col := col
			start_byte := i
			i += 2; col += 2
			mut multiline := false
			mut depth := 0
			for i < input.len {
				ch := input[i]
				if ch == `[` {
					depth++
				} else if ch == `]` {
					if depth == 0 {
						break
					}
					depth--
				}
				if ch == `\n` { multiline = true; line++; col = 1 } else { col++ }
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
				message: "single-line block comment '[; ... ]' alongside # line comments — pick one style"
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
					// attr-EXACT (#203.2 discipline, via #880): an attribute no
					// clause grants is a loud config error, never silently
					// ignored — `[disable check=CX-L003 path='legacy/**']` used
					// to disable the rule REPO-WIDE while reading as scoped.
					match child.name {
						'disable' {
							for a in child.attrs {
								if a.name != 'check' {
									return error('.cxlint.cx: [disable] admits only check= — unknown attribute `${a.name}` (per-path scoping is not implemented; scope by directory-level config files instead)')
								}
							}
							if v := element_attr_string(child, 'check') {
								cfg.disabled << v
							}
						}
						'severity' {
							for a in child.attrs {
								if a.name !in ['check', 'level'] {
									return error('.cxlint.cx: [severity] admits only check= and level= — unknown attribute `${a.name}`')
								}
							}
							if check := element_attr_string(child, 'check') {
								if level := element_attr_string(child, 'level') {
									if sev := parse_severity_level(level) {
										cfg.severity_override[check] = sev
									}
								}
							}
						}
						else {
							return error('.cxlint.cx: unknown [lint] clause `${child.name}` — the config admits [disable] and [severity]')
						}
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

// ── CX-L008 — declared shape flow across [?pipe] stages ──────────────────────
//
// The Layer-B advisory at the lint dial (shape_inference.md §2/§4,
// stream 16 W5): for each adjacent pair of no-hole simple-call [?pipe]
// stages whose heads are [?def]s DECLARED IN THIS FILE, compare stage
// i's declared [returns T] with the receiving parameter's ::T on stage
// i+1 (the no-hole form appends the piped value as the last positional
// argument → last declared non-rest param). Both boundaries must be
// declared to participate; compatibility is conservative (equal text,
// `any`, or int flowing into the float/number family). Warn severity —
// the runtime refusal is `--strict`'s job; this is the adoption dial.

struct L008Sig {
	returns_type string
	last_param   string
}

fn check_l008_pipe_stage_flow(input string, mut findings []Finding) {
	prog := parse_program(input) or { return }
	mut sigs := map[string]L008Sig{}
	l008_collect_defs(prog.body, mut sigs)
	l008_walk(prog.body, sigs, mut findings)
}

fn l008_collect_defs(node ProgramNode, mut sigs map[string]L008Sig) {
	if node is ProgramDirective {
		if node.name == 'def' {
			for sl in node.slots {
				if sl.label == 'raw-source' {
					v := sl.value
					if v is ProgramLiteral && v.kind == .string_lit {
						if def := parse_def(v.str_val) {
							mut last := ''
							for j := def.params.len - 1; j >= 0; j-- {
								if !def.params[j].is_rest {
									last = def.params[j].type_expr_source or { '' }
									break
								}
							}
							sigs[def.name] = L008Sig{
								returns_type: def.returns_type_source or { '' }
								last_param:   last
							}
						}
					}
				}
			}
		}
	}
	match node {
		ProgramDirective {
			for s in node.slots {
				l008_collect_defs(s.value, mut sigs)
			}
		}
		ProgramLiteral {
			// A multi-statement program parses as one block literal —
			// the statements are its items.
			for it in node.items {
				l008_collect_defs(it, mut sigs)
			}
		}
		Program {
			l008_collect_defs(node.body, mut sigs)
		}
		else {}
	}
}

fn l008_walk(node ProgramNode, sigs map[string]L008Sig, mut findings []Finding) {
	if node is ProgramDirective {
		if node.name == 'pipe' && node.slots.len >= 3 {
			mut prev_ret := ''
			mut prev_name := ''
			for i in 1 .. node.slots.len {
				stage := node.slots[i].value
				mut cur := L008Sig{}
				mut cur_name := ''
				mut participates := false
				if stage is ProgramCall {
					mut nholes := 0
					for a in stage.args {
						if a is ProgramCall && a.name == program_hole_name {
							nholes++
						}
					}
					if nholes == 0 {
						if sig := sigs[stage.name] {
							cur = sig
							cur_name = stage.name
							participates = true
						}
					}
				}
				if participates && prev_ret != '' && cur.last_param != '' {
					if !l008_compose(prev_ret, cur.last_param) {
						findings << Finding{
							check:      'CX-L008'
							severity:   .warn
							message:    '[?pipe] stage flow: `${prev_name}` declares [returns ${prev_ret}] but `${cur_name}` receives `::${cur.last_param}`'
							line:       node.pos.line
							col:        node.pos.col
							suggestion: 'align the declared boundary types, or run under --strict for the pre-execution refusal'
						}
					}
				}
				if participates {
					prev_ret = cur.returns_type
					prev_name = cur_name
				} else {
					prev_ret = ''
					prev_name = ''
				}
			}
		}
	}
	match node {
		ProgramDirective {
			for s in node.slots {
				l008_walk(s.value, sigs, mut findings)
			}
		}
		ProgramLiteral {
			if ne := node.name_expr {
				l008_walk(ne, sigs, mut findings)
			}
			for it in node.items {
				l008_walk(it, sigs, mut findings)
			}
			for a in node.attrs {
				l008_walk(a.value, sigs, mut findings)
			}
		}
		ProgramCall {
			for a in node.args {
				l008_walk(a, sigs, mut findings)
			}
		}
		ProgramForComp {
			for item in for_comp_children(node) {
				l008_walk(item.node, sigs, mut findings)
			}
		}
		Program {
			l008_walk(node.body, sigs, mut findings)
		}
		else {}
	}
}

fn l008_compose(produced string, consumed string) bool {
	p := produced.trim_space()
	c := consumed.trim_space()
	if p == '' || c == '' || p == 'any' || c == 'any' || p == c {
		return true
	}
	_ = parse_type_expr(p) or { return true }
	_ = parse_type_expr(c) or { return true }
	if p == 'int' && (c == 'float' || c == 'number') {
		return true
	}
	if (p == 'int' || p == 'float' || p == 'decimal' || p == 'bigint') && c == 'number' {
		return true
	}
	return false
}
