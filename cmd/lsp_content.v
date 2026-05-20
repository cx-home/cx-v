// Q5 v0.7.0: `cx lsp` — content helpers.
//
// Word extraction, hover documentation, completion lists, and semantic
// token computation. These are deliberately lightweight at v0.7.0: the
// LSP server uses libcx for parse/format/lint, but the contextual lookups
// (what is the word under the cursor? what does this directive do?) are
// answered from local string scanning + static doc tables. A future
// v0.7.x iteration can replace the static tables with introspection
// against the canonical directive registry.

module main

// word_at_position returns the identifier-like token spanning (line, col)
// inside source. Identifiers extend across letters/digits/_-.:?@#&* so
// that `?fn`, `:where`, `@id`, `#anchor`, `*merge`, `cx:eval` all read
// as single tokens for hover/definition lookup.
fn word_at_position(source string, line int, col int) string {
	lines := source.split('\n')
	if line < 0 || line >= lines.len { return '' }
	row := lines[line]
	if col < 0 || col > row.len { return '' }
	// Walk left to start.
	mut start := col
	for start > 0 && is_lsp_word_char(row[start - 1]) {
		start--
	}
	// Walk right to end.
	mut end := col
	for end < row.len && is_lsp_word_char(row[end]) {
		end++
	}
	if start == end { return '' }
	return row[start..end]
}

fn is_lsp_word_char(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		|| (c >= `0` && c <= `9`) || c == `_` || c == `-` || c == `.`
		|| c == `:` || c == `?` || c == `@` || c == `#` || c == `&` || c == `*`
}

// hover_docs_for returns markdown-formatted documentation for a CX
// identifier (directive, module function, slot label). Returns '' for
// unknown words — the LSP server then sends a null hover response so
// editors don't pop up an empty tooltip.
fn hover_docs_for(word string) string {
	// Strip the directive `?` prefix for table lookup.
	key := if word.starts_with('?') { word[1..] } else { word }
	if doc := directive_docs[key] { return doc }
	if doc := module_fn_docs[word] { return doc }
	if doc := slot_label_docs[word] { return doc }
	return ''
}

// completion_directive_names returns the canonical v0.7.0 directive
// allowlist with short descriptions. Keep in sync with parser.v
// directive allowlist and spec/eval.md §3.
fn completion_directive_names() map[string]string {
	return {
		'?if':        'Conditional. `[?if cond :then ... :else ...]`'
		'?for':       'FLWOR iteration. `[?for x in coll :let ... :where ... :return ...]`'
		'?let':       'Lexical binding. `[?let :x 1 :y 2 :in [+ x y]]`'
		'?fn':        'First-class function. `[?fn :params [x y] :body [+ x y]]`'
		'?match':     'Pattern matching. `[?match v :case ... :case ...]`'
		'?try':       'Error handling. `[?try ... :catch err-tag binding ...]`'
		'?def':       'Top-level definition. `[?def name [?fn :params ... :body ...]]`'
		'?include':   '?include path (sandboxed, lexical collapse). See spec/include.md.'
		'?eval':      'Sandboxed nested evaluation. `[?eval cx-source]`'
		'?cx':        'Self-host directive — operate on CX AST values.'
		'?xpath':     'Embedded XPath 4.0 query expression.'
		'?xquery':    'Embedded XQuery 4.0 expression.'
		'?cxpath':    'Native CXPath query expression.'
	}
}

// completion_module_fns returns commonly-used module-prefixed names
// (cx:, fn:, log:, map:, array:, math:). Editors render this as a
// flat completion list; LSP clients sort by label.
fn completion_module_fns() map[string]string {
	return {
		// cx: self-host module (ADR 0023)
		'cx:parse':              'Parse CX source text into an AST value.'
		'cx:render':             'Render an AST value back to CX source.'
		'cx:hash':               'SHA-256 of canonical bytes.'
		'cx:diff':               'Three-policy semantic diff.'
		'cx:patch':              'Apply a diff to an AST.'
		'cx:schema-of':          'Infer a cxs schema from instance data.'
		'cx:resolve-includes':   'Resolve ?include directives into a single AST.'
		'cx:eval':               'Sandboxed nested evaluation (M1-M5 gated).'
		// log: structured logging
		'log:trace':             'Log at trace level.'
		'log:debug':             'Log at debug level.'
		'log:info':              'Log at info level.'
		'log:warn':              'Log at warn level.'
		'log:error':             'Log at error level.'
		'log:with-context':      'Bind ambient context for nested log calls.'
		// fn: namespace highlights (full ~180 in spec/eval.md)
		'fn:count':              'Cardinality of a sequence.'
		'fn:sum':                'Numeric sum.'
		'fn:avg':                'Numeric average.'
		'fn:min':                'Minimum value.'
		'fn:max':                'Maximum value.'
		'fn:string-join':        'Concatenate strings with a separator.'
		'fn:format-number':      'Locale-aware number formatting.'
		'fn:format-date':        'Locale-aware date formatting.'
		'fn:slice':              'Sub-sequence by start/length.'
		'fn:replicate':          'Repeat a value N times.'
		'fn:characters':         'String → character sequence.'
		'fn:all-different':      'True iff all values are distinct.'
		'fn:partition':          'Group a sequence by a key function.'
		'fn:json-to-xml':        'Convert JSON value to XML.'
		'fn:xml-to-json':        'Convert XML value to JSON.'
		'fn:json-doc':           'Load a JSON document by URI.'
		'fn:normalize-unicode':  'Apply Unicode normalization (NFC/NFD/NFKC/NFKD).'
		'fn:safe-url':           'Reject dangerous URL schemes (javascript:, data:, …).'
		'fn:node-name':          'Element name of a node.'
		'fn:base-uri':           'Base URI of a node.'
		'fn:document-uri':       'Document URI of a node.'
		'fn:lang':               'Inherited cx:lang of a node.'
		'fn:innermost':          'Deepest matching nodes in a set.'
		'fn:outermost':          'Top-most matching nodes in a set.'
		// map:, array: module surface
		'map:get':               'Lookup a key in a map.'
		'map:put':               'Insert/replace a key in a map.'
		'map:keys':              'Sequence of keys.'
		'map:size':              'Number of entries.'
		'array:get':             'Index into an array (1-based).'
		'array:size':            'Length of an array.'
		'array:head':            'First element.'
		'array:tail':            'All but first element.'
	}
}

// completion_snippet_for returns an LSP-snippet template for a
// directive name. Tab-stops use `${N:placeholder}` syntax (LSP
// snippet format) — editors land the cursor at $1, then $2 on Tab,
// then $0 (the final exit position) when the user is done.
fn completion_snippet_for(name string) ?string {
	key := if name.starts_with('?') { name[1..] } else { name }
	snippets := {
		'if':       '[?if \${1:cond} :then \${2:then-expr} :else \${3:else-expr}]\$0'
		'for':      '[?for \${1:x} in \${2:coll} :return \${3:body}]\$0'
		'let':      '[?let :\${1:name} \${2:value} :in \${3:body}]\$0'
		'fn':       '[?fn :params [\${1:x}] :body \${2:body}]\$0'
		'match':    '[?match \${1:value} :case \${2:pattern} \${3:result} :else \${4:default}]\$0'
		'try':      '[?try \${1:body} :catch \${2:err-name} \${3:handler}]\$0'
		'def':      '[?def \${1:name} \${2:value}]\$0'
		'include':  '[?include "\${1:path.cx}"]\$0'
		'eval':     '[?eval \${1:cx-source}]\$0'
		'cx':       '[?cx \${1:directive}]\$0'
		'xpath':    '[?xpath \${1:expression}]\$0'
		'xquery':   '[?xquery \${1:expression}]\$0'
		'cxpath':   '[?cxpath \${1:expression}]\$0'
	}
	if s := snippets[key] { return s }
	return none
}

// ── Static doc tables ───────────────────────────────────────────────

const directive_docs = {
	'if':       '**?if** — Conditional.\n\n`[?if cond :then expr :else expr]`'
	'for':      '**?for** — FLWOR iteration.\n\nSlots: `:let`, `:where`, `:order-by`, `:group-by`, `:count`, `:while`, `:return`. Tumbling + sliding windows via `:tumbling-window` / `:sliding-window`.'
	'let':      '**?let** — Lexical binding.\n\n`[?let :name value :other-name value :in body]`'
	'fn':       '**?fn** — First-class function.\n\n`[?fn :params [x y] :body expr]`\n\nSupports partial application via `[?partial f arg]` and arrow-lambda `-> (x) { body }` surface (B10).'
	'match':    '**?match** — Pattern matching.\n\n`[?match value :case pattern result :case ... :else default]`'
	'try':      '**?try** — Error handling.\n\n`[?try body :catch err-name binding handler ...]`. Multi-catch via repeated `:catch` slots.'
	'def':      '**?def** — Top-level definition.\n\nBinds a name in the current evaluation environment.'
	'include':  '**?include** — Lexical inclusion.\n\nSandboxed by spec/include.md §6 (path-traversal denied, depth-limit enforced). Errors: E901–E911.'
	'eval':     '**?eval** — Sandboxed nested evaluation.\n\nGated by M1–M5 caps (max_depth, max_steps, max_alloc, max_time, syscall_deny).'
	'cx':       '**?cx** — Self-host directive (ADR 0023).\n\nAccess to `cx:parse`, `cx:render`, `cx:hash`, `cx:diff`, `cx:patch`, `cx:schema-of`, `cx:resolve-includes`, `cx:eval`.'
}

const module_fn_docs = {
	'cx:parse':            '**cx:parse(source)** — Parse a CX source string into an AST value. Lossless round-trip with `cx:render`.'
	'cx:render':           '**cx:render(ast)** — Render an AST value back to canonical CX source.'
	'cx:hash':             '**cx:hash(value)** — SHA-256 hex of the strict canonical bytes for `value`.'
	'cx:diff':             '**cx:diff(a, b, :policy ?)** — Three-policy semantic diff: `:structure`, `:identity`, `:value`. Returns a patch.'
	'cx:patch':            '**cx:patch(doc, patch)** — Apply a `cx:diff` patch to an AST. Order-sensitive against the source it was diffed from.'
	'cx:schema-of':        '**cx:schema-of(value)** — Infer a `cxs` schema from instance data. Returns the canonical schema AST.'
	'cx:resolve-includes': '**cx:resolve-includes(doc, :base ?)** — Walk `?include` directives, sandbox-resolve, splice in. See spec/include.md.'
	'cx:eval':             '**cx:eval(source, :caps ?)** — Sandboxed nested evaluation. Caps default to M1-M5 limits.'
	'log:trace':           '**log:trace(msg, fields…)** — Trace-level log. Filtered by `:level` ambient context.'
	'log:debug':           '**log:debug(msg, fields…)** — Debug-level log.'
	'log:info':            '**log:info(msg, fields…)** — Info-level log.'
	'log:warn':            '**log:warn(msg, fields…)** — Warn-level log.'
	'log:error':           '**log:error(msg, fields…)** — Error-level log.'
	'log:with-context':    '**log:with-context(fields, body)** — Bind ambient log context for the dynamic extent of `body`.'
	'fn:format-number':    '**fn:format-number(value, picture, :locale ?)** — Locale-aware number formatting. v0.7.0: en/de/fr. Full CLDR/ICU at v0.7.x.'
	'fn:safe-url':         '**fn:safe-url(url)** — Returns `url` if the scheme is allowlisted; raises CXER0014 for javascript:, data:, vbscript:, file:.'
}

const slot_label_docs = {
	':let':       'FLWOR `:let` — let-binding inside `?for`. Multiple allowed.'
	':where':     'FLWOR `:where` — filter predicate.'
	':order-by':  'FLWOR `:order-by` — sort the iteration.'
	':group-by':  'FLWOR `:group-by` — group by a key expression.'
	':count':     'FLWOR `:count` — bind position counter.'
	':while':     'FLWOR `:while` — early-exit condition.'
	':return':    'FLWOR `:return` — per-tuple result expression.'
	':case':      'Pattern-match arm (`?match`).'
	':catch':     '`?try` catch arm. Multiple `:catch` slots supported.'
	':params':    '`?fn` parameter list.'
	':body':      '`?fn` body expression.'
	':then':      '`?if` then-branch.'
	':else':      '`?if` / `?match` default branch.'
	':in':        '`?let` body expression.'
}

// ── Semantic tokens ─────────────────────────────────────────────────
//
// LSP semantic tokens are delta-encoded as a flat int array, 5 values
// per token: [deltaLine, deltaStart, length, tokenType, tokenModifiers].
// deltaLine is relative to the previous token's line; deltaStart is
// relative to the previous token's start column when on the same line,
// or absolute when on a new line.

const tt_namespace = 0
const tt_keyword = 1
const tt_variable = 2
const tt_parameter = 3
const tt_property = 4
const tt_string = 5
const tt_number = 6
const tt_comment = 7
const tt_operator = 8
const tt_decorator = 9

struct SemToken {
	line     int
	col      int
	length   int
	tt       int
	tm       int
}

fn compute_semantic_tokens(source string) []int {
	mut tokens := []SemToken{}
	mut line := 0
	mut col := 0
	mut i := 0
	for i < source.len {
		c := source[i]
		// Newline.
		if c == `\n` {
			line++
			col = 0
			i++
			continue
		}
		// Whitespace.
		if c == ` ` || c == `\t` || c == `\r` {
			col++
			i++
			continue
		}
		// Line comment `#` — but only when not part of `#id` decorator
		// (which we treat below). A bare `#` followed by a space is a
		// comment; `#` followed by an identifier char is a decorator.
		if c == `#` && i + 1 < source.len && !is_lsp_word_char(source[i + 1]) {
			// Skip to EOL.
			start := col
			mut j := i
			for j < source.len && source[j] != `\n` {
				j++
			}
			tokens << SemToken{line: line, col: start, length: j - i, tt: tt_comment, tm: 0}
			col += j - i
			i = j
			continue
		}
		// String literal — `"…"` with escapes.
		if c == `"` {
			start := col
			start_line := line
			mut j := i + 1
			for j < source.len && source[j] != `"` {
				if source[j] == `\\` && j + 1 < source.len { j += 2 } else { j++ }
				if source[j - 1] == `\n` { /* span breaks anyway */ break }
			}
			if j < source.len { j++ }
			length := j - i
			tokens << SemToken{line: start_line, col: start, length: length, tt: tt_string, tm: 0}
			col += length
			i = j
			continue
		}
		// Number — leading digit or `-` then digit.
		if (c >= `0` && c <= `9`)
			|| (c == `-` && i + 1 < source.len && source[i + 1] >= `0` && source[i + 1] <= `9`) {
			start := col
			mut j := i
			if source[j] == `-` { j++ }
			for j < source.len && ((source[j] >= `0` && source[j] <= `9`) || source[j] == `.` || source[j] == `e` || source[j] == `E` || source[j] == `+` || source[j] == `-`) {
				j++
			}
			length := j - i
			tokens << SemToken{line: line, col: start, length: length, tt: tt_number, tm: 0}
			col += length
			i = j
			continue
		}
		// `?directive` — keyword.
		if c == `?` && i + 1 < source.len && is_lsp_word_char(source[i + 1]) {
			start := col
			mut j := i + 1
			for j < source.len && is_lsp_word_char(source[j]) { j++ }
			length := j - i
			tokens << SemToken{line: line, col: start, length: length, tt: tt_keyword, tm: 0}
			col += length
			i = j
			continue
		}
		// `:slot` — parameter.
		if c == `:` && i + 1 < source.len && is_lsp_word_char(source[i + 1]) {
			start := col
			mut j := i + 1
			for j < source.len && is_lsp_word_char(source[j]) { j++ }
			length := j - i
			tokens << SemToken{line: line, col: start, length: length, tt: tt_parameter, tm: 0}
			col += length
			i = j
			continue
		}
		// `@id` / `#anchor` / `*merge` — decorators.
		if c == `@` || c == `#` || c == `*` {
			if i + 1 < source.len && is_lsp_word_char(source[i + 1]) {
				start := col
				mut j := i + 1
				for j < source.len && is_lsp_word_char(source[j]) { j++ }
				length := j - i
				tokens << SemToken{line: line, col: start, length: length, tt: tt_decorator, tm: 0}
				col += length
				i = j
				continue
			}
		}
		// `module:name` — namespace + word. Detect the `:` boundary.
		if is_ident_start(c) {
			start := col
			mut j := i
			for j < source.len && is_lsp_word_char(source[j]) && source[j] != `:` { j++ }
			// `module:name` form?
			if j < source.len && source[j] == `:` && j + 1 < source.len && is_lsp_word_char(source[j + 1]) {
				ns_len := j - i
				tokens << SemToken{line: line, col: start, length: ns_len, tt: tt_namespace, tm: 0}
				j++
				name_start := j
				for j < source.len && is_lsp_word_char(source[j]) && source[j] != `:` { j++ }
				tokens << SemToken{line: line, col: start + ns_len + 1, length: j - name_start, tt: tt_variable, tm: 0}
				length := j - i
				col += length
				i = j
				continue
			}
			length := j - i
			if length > 0 {
				tokens << SemToken{line: line, col: start, length: length, tt: tt_variable, tm: 0}
				col += length
				i = j
				continue
			}
		}
		// Operators `|>`, `=>`, `||`, `->`, `!`, `to`.
		if c == `|` || c == `=` || c == `-` || c == `!` {
			if (c == `|` && i + 1 < source.len && (source[i + 1] == `>` || source[i + 1] == `|`))
				|| (c == `=` && i + 1 < source.len && source[i + 1] == `>`)
				|| (c == `-` && i + 1 < source.len && source[i + 1] == `>`) {
				tokens << SemToken{line: line, col: col, length: 2, tt: tt_operator, tm: 0}
				col += 2
				i += 2
				continue
			}
			if c == `!` {
				tokens << SemToken{line: line, col: col, length: 1, tt: tt_operator, tm: 0}
				col++
				i++
				continue
			}
		}
		// Default: skip.
		col++
		i++
	}
	return delta_encode(tokens)
}

fn is_ident_start(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || c == `_`
}

fn delta_encode(tokens []SemToken) []int {
	mut out := []int{}
	mut prev_line := 0
	mut prev_col := 0
	for tok in tokens {
		delta_line := tok.line - prev_line
		delta_start := if delta_line == 0 { tok.col - prev_col } else { tok.col }
		out << delta_line
		out << delta_start
		out << tok.length
		out << tok.tt
		out << tok.tm
		prev_line = tok.line
		prev_col = tok.col
	}
	return out
}
