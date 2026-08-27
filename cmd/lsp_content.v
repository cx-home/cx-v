// Q5: `cx lsp` — content helpers.
//
// Word extraction, hover documentation, completion lists, and semantic
// token computation. These are deliberately lightweight: the
// LSP server uses libcx for parse/format/lint, but the contextual lookups
// (what is the word under the cursor? what does this directive do?) are
// answered from local string scanning + static doc tables. A future
// iteration can replace the static tables with introspection
// against the canonical directive registry.

module main
import cx

import code

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

// completion_directive_names returns the directive completion set,
// DERIVED from the one canonical registry (cx.directive_names) rather
// than hand-maintained beside it.
//
// #705: the hand-kept list had drifted into a different language. It
// advertised four heads that DO NOT EXIST at either layer (`?xpath`,
// `?xquery`, `?cxpath` — pure LSP invention — and `?include`, which is a
// DATA-document assembly directive, not an eval-time head), documented
// the abolished `:then` / `:else` slot syntax, and cited a spec file that
// no longer exists. governance.md §10.2 requires an LSP update on every
// grammar change; nothing enforced it, so the surface rotted quietly.
//
// Offering a head no parser knows is the same defect class the
// shell-completion drift gate exists to prevent. Deriving the SET closes
// it by construction: a directive cannot be advertised unless the
// registry has it, and cannot be missed once the registry gains it.
//
// Descriptions stay hand-written, because prose is the one part a
// registry cannot supply. `directive_help` carries them for the heads
// that have earned one; everything else gets a plain, honest fallback
// rather than an invented explanation.
fn completion_directive_names() map[string]string {
	help := directive_help()
	mut out := map[string]string{}
	for name in cx.directive_names {
		key := '?' + name
		out[key] = help[key] or { 'Directive `[${key} …]` — see code.md §4.1.' }
	}
	return out
}

// directive_help is the curated hover prose. Every key MUST be a real
// registry name — the lsp-registry-parity gate fails on a key that is
// not, which is exactly how the four phantom heads would be caught now.
fn directive_help() map[string]string {
	return {
		'?if':         'Conditional. `[?if COND [then …] [else …]]`'
		'?for':        'Comprehension. `[?for [in $x COLL] [where P] [yield E]]`'
		'?let':        'Lexical binding. `[?let [= $x 1] [= $y 2] [+ $x $y]]`'
		'?fn':         'First-class function. `[?fn ($x $y) [+ $x $y]]`'
		'?match':      'Pattern matching. `[?match V [case P R] [when PRED R] [else R]]`'
		'?def':        'Module-level function. `[?def NAME ($params) BODY]`'
		'?const':      'Module-level constant. `[?const NAME VALUE]`'
		'?lib':        'Import a module. `[?lib \'cx-stdlib/strings\']`'
		'?eval':       'Sandboxed nested evaluation. `[?eval TREE [context MAP]]`'
		'?cx':         'Self-host directive. `[?cx include "path.cx"]`, `[?cx cx:hash VALUE]`, …'
		'?modify':     'Structural edit over a CXPath focus. `[?modify $doc //user [set-attr k v]]`'
		'?pipe':       'Left-to-right stage composition. `[?pipe V [$f] [$g]]`'
		'?map':        'Map over a collection. `[?map XS [using $f]]`'
		'?reduce':     'Fold a collection. `[?reduce XS [using $f] [from INIT]]`'
		'?with-open':  'Scoped resource: opens, binds, and closes on exit.'
		'?with-scope': 'Dynamic-scoped context fields for the body.'
		'?with-caps':  'Narrow authority for the body. `[?with-caps [deny net] BODY]` (narrow-only).'
		'?send':       'Send a value to a channel. `[?send V to=$ch]`'
		'?receive':    'Receive from a channel. `[?receive from=$ch]`'
		'?try-send':   'Non-blocking send; `timeout=` waits up to a deadline.'
		'?try-receive': 'Non-blocking receive; `timeout=` waits up to a deadline.'
		'?worker':     'Spawn a named worker.'
		'?async':      'Evaluate eagerly in an asynchronous context; returns a future.'
		'?await':      'Await a future.'
		'?retry':      'Re-run on failure with a bounded attempt count.'
		'?timeout':    'Bound an evaluation by a duration.'
		'?secret':     'Wrap a value as a secret (redacted on emit).'
		'?reveal':     'Reveal a secret — capability-gated (`secret-reveal`).'
		'?element':    'Computed-name element construction.'
		'?quote':      'Quote a tree without evaluating it.'
	}
}


// completion_module_fns returns commonly-used module-prefixed names
// (cx:, fn:, log:, map:, array:, math:). Editors render this as a
// flat completion list; LSP clients sort by label.
fn completion_module_fns() map[string]string {
	return {
		// cx: self-host module
		'cx:parse':              'Parse CX source text into an AST value.'
		'cx:render':             'Evaluate a template source string and serialize the result (sugar over cx:eval).'
		'cx:ast':                'Declaration-AST JSON projection of module source (libs/consts/defs).'
		'cx:hash':               'SHA-256 of canonical bytes.'
		'cx:diff':               'Three-policy semantic diff.'
		'cx:patch':              'Apply a diff to an AST.'
		'cx:schema-of':          'Infer a cxs schema from instance data.'
		'cx:resolve-includes':   'Resolve ?include directives into a single AST.'
		'cx:eval':               'Evaluate a CX source string in the context-only sandbox (eval capability).'
		// log: structured logging
		'log:trace':             'Log at trace level.'
		'log:debug':             'Log at debug level.'
		'log:info':              'Log at info level.'
		'log:warn':              'Log at warn level.'
		'log:error':             'Log at error level.'
		'log:with-context':      'Bind ambient context for nested log calls.'
		// fn: namespace highlights (full ~180 in code.md)
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
		'fn:node-name':          'Element name of a node.'
		'fn:base-uri':           'Base URI of a node.'
		'fn:document-uri':       'Document URI of a node.'
		'fn:lang':               'Inherited cx:lang of a node.'
		'fn:innermost':          'Deepest matching nodes in a set.'
		'fn:outermost':          'Top-most matching nodes in a set.'
		// map:, array: module surface (#925, RULED: PYE-1 — the full
		// spec/std-lib/map.md + array.md rosters; every name is backed by
		// stdlib/map.cx / stdlib/array.cx)
		'map:get':               'Lookup a key in a map — key identity is (kind, image); absent → empty sequence.'
		'map:put':               'New map with the key bound (replace in place, or append last).'
		'map:keys':              'Sequence of keys in insertion order, each carrying its kind.'
		'map:size':              'Number of entries (declarations included).'
		'map:contains':          'Whether the key is bound, under (kind, image) identity.'
		'map:entry':             'The single-entry map {k: v}.'
		'map:merge':             'Fold a sequence of maps left-to-right; later bindings win.'
		'map:remove':            'New map without the key; a miss is the identity.'
		'map:for-each':          'Apply fn(key, value) per entry; the sequence of results.'
		'array:get':             'Index into an array (1-based; out of range refuses).'
		'array:size':            'Length of an array.'
		'array:head':            'First item; empty array → empty sequence.'
		'array:tail':            'All but the first item; empty array → [].'
		'array:append':          'New array with the value as the last item.'
		'array:reverse':         'Items in reverse order.'
		'array:subarray':        'len items from 1-based start, clamped to the end.'
		'array:put':             'New array with 1-based position replaced.'
		'array:remove':          'New array without the 1-based position.'
		'array:insert-before':   'New array with the value inserted before the position (size+1 appends).'
		'array:flatten':         'Sequence of leaf items, nested arrays and boxed sequences expanded.'
		'array:join':            'Concatenate a sequence of arrays into one array.'
		'array:sort':            'Ascending by the [$sort] arrangement, boxed back into an array.'
		'array:filter':          'Items for which the predicate answers true.'
		'array:for-each':        'New array of fn applied per item.'
		'array:fold-left':       'fn(fn(init, a1), a2)… — fn takes (accumulator, item).'
		'array:fold-right':      'fn(a1, fn(a2, … init)) — fn takes (item, accumulator).'
	}
}

// completion_stdlib_fns enumerates EVERY public `[?def]` across the bundled
// stdlib modules (code.bundled_stdlib_*), keyed `module:name` (the canonical
// `[$prefix:local …]` call surface), with a signature detail
// (`($a::T $b::U) → R`). Built from the compiled-in bundle — the single source
// of truth — so it never drifts from the shipped stdlib. Unlike the curated
// `completion_module_fns` (core cx:/fn:/map:/array: namespaces), this covers
// the full module surface: json, crypto, time, http, csv, re, store, … (~800
// functions across ~30 modules). Callers should cache the result
// (see LspState.get_stdlib_completion) — it parses every module.
fn completion_stdlib_fns() map[string]string {
	mut out := map[string]string{}
	mut table := code.new_module_table()
	for full in code.bundled_stdlib_names() {
		src := code.bundled_stdlib_source(full) or { continue }
		// A module that fails to load standalone (e.g. unresolved cross-module
		// import in isolation) is skipped — its functions just won't appear.
		m := code.load_module(src, full, mut table) or { continue }
		prefix := full.all_after_last('/')
		for name in m.public_def_names() {
			def := m.defs[name] or { continue }
			out['${prefix}:${name}'] = stdlib_def_detail(def)
		}
	}
	return out
}

// stdlib_def_detail renders a `[?def]`'s parameter list + return type as a
// one-line completion detail, e.g. `($s::string $opts::map) → any`.
fn stdlib_def_detail(def cx.DefNode) string {
	mut parts := []string{}
	for p in def.params {
		t := p.type_expr_source or { 'any' }
		mut pre := '\$'
		if p.is_rest {
			pre = '\$:rest '
		} else if p.is_named {
			pre = ':'
		}
		parts << '${pre}${p.name}::${t}'
	}
	sig := '(' + parts.join(' ') + ')'
	ret := def.returns_type_source or { 'any' }
	return '${sig} → ${ret}'
}

// completion_snippet_for returns an LSP-snippet template for a
// directive name. Tab-stops use `${N:placeholder}` syntax (LSP
// snippet format) — editors land the cursor at $1, then $2 on Tab,
// then $0 (the final exit position) when the user is done.
fn completion_snippet_for(name string) ?string {
	key := if name.starts_with('?') { name[1..] } else { name }
	snippets := {
		// Clause-child forms (spec/code.md §7.2, §8.2, §8.4, §8.5, §8.7).
		// The retired colon-slot spellings these replace were REJECTED by
		// the parser — `[?let :x 1 :in body]` raises CXER0100 — so the
		// completion inserted syntax that could not compile (#711 item 5).
		// `\\\$` is an LSP-snippet-escaped literal `$` (the CX sigil).
		'if':       '[?if \${1:cond} [then \${2:then-expr}] [else \${3:else-expr}]]\$0'
		'for':      '[?for [in \\\$\${1:x} \${2:coll}] [yield \${3:body}]]\$0'
		'let':      '[?let [= \\\$\${1:name} \${2:value}] \${3:body}]\$0'
		'fn':       '[?fn (\\\$\${1:x}) \${2:body}]\$0'
		'match':    '[?match \${1:value} [case \${2:pattern} \${3:result}] [else \${4:default}]]\$0'
		'def':      '[?def \${1:name} (\\\$\${2:param}) \${3:body}]\$0'
		'eval':     '[?eval \${1:tree}]\$0'
		'cx':       '[?cx include "\${1:path.cx}"]\$0'
		'include':  '[?include [\'\${1:path.cx}\']]\$0'
		// `xpath` / `xquery` / `cxpath` snippets RETIRED with their
		// completion entries above — no parser knows those heads.
	}
	if s := snippets[key] { return s }
	return none
}

// ── Static doc tables ───────────────────────────────────────────────

const directive_docs = {
	'if':       '**?if** — Conditional.\n\n`[?if cond [then expr] [else expr]]`'
	'for':      '**?for** — Comprehension (spec/code.md §7.2).\n\n`[?for [in \$x coll] [where P] [yield E]]`\n\nClause children: `[in \$x SRC]`, `[= \$y E]`, `[where P]`, `[order-by E asc|desc]`, `[group-by E]`, `[limit N]`, `[take N]`, `[drop N]`, `[take-while P]`, `[drop-while P]`, `[par]` / `[par N]`, `[lazy]`, `[ordered]`, `[fail-fast]`.\n\nOuter-container variants `[?for-array]` / `[?for-map]` pair with the `[yield-array E]` / `[yield-map K V]` yield clauses.'
	'let':      '**?let** — Lexical binding.\n\n`[?let [= \$x 1] [= \$y 2] body]`\n\nFlat multi-binding only — bindings are `[= \$name value]` clause children before the body; nested single-binding staircases are a lint finding (L003).'
	'fn':       '**?fn** — First-class function.\n\n`[?fn (\$x \$y) body]`\n\nSupports partial application via `[?partial f arg]` and arrow-lambda `-> (x) { body }` surface (B10).'
	'match':    '**?match** — Pattern matching.\n\n`[?match value [case P R] [case P [where G] R] [when PRED R] [else R]]`\n\n`[case …]` matches a PATTERN; `[when …]` is a boolean GUARD arm.'
	'def':      '**?def** — Module-level function (§8.7).\n\n`[?def name (\$params) body]`'
	'include':  '**?include** — PARSE/ASSEMBLY-time inclusion in a DATA document (code.md §13).\n\n`[?include [\'path.cx\']]`\n\nSandboxed by spec/include.md §6 (path-traversal denied, depth-limit enforced). Errors: E901–E911.\n\nNOT an eval-time code head — in a CODE program the spelling is `[?cx include "path.cx"]`.'
	'eval':     '**?eval** — Sandboxed nested evaluation (§6.4.4).\n\n`[?eval TREE]` / `[?eval TREE [context MAP]]` / `[?eval TREE [context MAP] [opts {"max-depth": 16}]]`\n\nGated by the `eval` capability (deny-by-default → CXER0271) and the M1–M5 caps.'
	'cx':       '**?cx** — Self-host directive.\n\n`[?cx include "path.cx"]` — lexical inclusion, sandboxed by spec/include.md §6 (path-traversal denied, depth-limit enforced; errors E901–E911). There is no bare `[?include …]` head.\n\nAlso `cx:parse`, `cx:render`, `cx:hash`, `cx:diff`, `cx:patch`, `cx:schema-of`, `cx:resolve-includes`, `cx:eval`.'
}

const module_fn_docs = {
	'cx:parse':            '**cx:parse(source)** — Parse a CX source string into an AST value. Lossless round-trip with `cx:render`.'
	'cx:render':           '**cx:render(template, context)** — `cx:serialize(cx:eval(template, context))`: evaluate a template source string in the cx:eval sandbox and serialize the result. Impure (`eval` capability), and it shares cx:eval\'s recursion budget.'
	'cx:hash':             '**cx:hash(value)** — SHA-256 hex of the strict canonical bytes for `value`.'
	'cx:diff':             '**cx:diff(a, b, :policy ?)** — Three-policy semantic diff: `:structure`, `:identity`, `:value`. Returns a patch.'
	'cx:patch':            '**cx:patch(doc, patch)** — Apply a `cx:diff` patch to an AST. Order-sensitive against the source it was diffed from.'
	'cx:schema-of':        '**cx:schema-of(value)** — Infer a `cxs` schema from instance data. Returns the canonical schema AST.'
	'cx:resolve-includes': '**cx:resolve-includes(value, root)** — Run the `[?cx include]` resolution algorithm against an EXPLICIT root. Impure (`read` capability). See spec/core/code.md §13.'
	'cx:eval':             '**cx:eval(source, context, opts?)** — Evaluate a CX source string against `context`, in the context-only sandbox: no ambient capture, `[?lib]` may narrow but not widen (CXER4113), recursion depth 8 (`opts.max-depth`, CXER4114). Impure (`eval` capability). See spec/modules/cx.md §3.'
	'log:trace':           '**log:trace(msg, fields…)** — Trace-level log. Filtered by `:level` ambient context.'
	'log:debug':           '**log:debug(msg, fields…)** — Debug-level log.'
	'log:info':            '**log:info(msg, fields…)** — Info-level log.'
	'log:warn':            '**log:warn(msg, fields…)** — Warn-level log.'
	'log:error':           '**log:error(msg, fields…)** — Error-level log.'
	'log:with-context':    '**log:with-context(fields, body)** — Bind ambient log context for the dynamic extent of `body`.'
	'fn:format-number':    '**fn:format-number(value, picture, :locale ?)** — Locale-aware number formatting. Currently en/de/fr; full CLDR/ICU is a follow-up.'
}

// slot_label_docs documents the CLAUSE-CHILD heads of the directive
// forms — `[where P]`, `[yield E]`, `[then E]`, … — keyed WITHOUT a
// colon, because the colon-slot spellings this table used to carry
// (`:where`, `:return`, `:then`, `:params`, …) are not the shipped
// surface and are rejected by the parser (#711 item 5, stream-2 W2).
const slot_label_docs = {
	// `[?for]` clause children (spec/code.md §7.2)
	'in':          '`[?for]` generator — `[in \$x SRC]` binds each item of SRC.'
	'where':       '`[?for]` / `[?match]` filter predicate — `[where P]`. PREFIX form.'
	'order-by':    '`[?for]` ordering barrier — `[order-by E]` / `[order-by E desc]`.'
	'group-by':    '`[?for]` grouping barrier — `[group-by E]`. Binds `\$key` and `\$group` (hash-partition; first-key-appearance order).'
	'limit':       '`[?for]` result limit — `[limit N]`.'
	'take':        '`[?for]` short-circuit after N yields — `[take N]`.'
	'drop':        '`[?for]` skip the first N candidates — `[drop N]`.'
	'take-while':  '`[?for]` yield until the predicate first fails — `[take-while P]`.'
	'drop-while':  '`[?for]` skip while the predicate holds — `[drop-while P]`.'
	'par':         '`[?for]` parallel outermost generator — `[par]` (W = min(4, ncpu)), `[par N]`, `[par max]` (§7.3).'
	'lazy':        '`[?for]` lazy evaluation — yield each item as ready (§7.4; renamed from `[stream]` by U1.1a).'
	'ordered':     '`[?for]` preserve input order under `[par]` (§7.3).'
	'fail-fast':   '`[?for]` under `[par]`: short-circuit on the FIRST observed `[err]` (drain queued work, discard in-flight). A no-op without `[par]`.'
	'yield':       '`[?for]` / `[?match]` result clause — `[yield E]`.'
	'yield-array': '`[?for-array]` result clause — `[yield-array E]`.'
	'yield-map':   '`[?for-map]` result clause — `[yield-map K V]` (key and value expressions).'
	// branch / arm clause children
	'then':        '`[?if]` then-branch — `[then E]`.'
	'else':        '`[?if]` / `[?match]` default branch — `[else E]`.'
	'case':        '`[?match]` PATTERN arm — `[case P R]` or `[case P [where G] R]`.'
	'when':        '`[?match]` GUARD arm — `[when PRED R]`; fires when PRED is truthy.'
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
// tt_atom — atom literal `:NAME`. Distinct from tt_parameter
// (slot label `:label`) — the two lex identically but parse differently.
// Position index 10 in the semanticTokens legend (`enumMember`).
const tt_atom = 10
// tt_function — an element / call HEAD name (the `name` in `[name …]` or an
// explicit `name(args)` call). Position index 11 in the legend (`function`).
const tt_function = 11

// program_clause_keywords are bareword HEADS that read as control/clause
// keywords rather than element constructors in the program surface: the
// bracket-clause arms of `[?if]`/`[?match]`/for-comprehensions. The program
// parser sees them as ordinary `cx_element` heads (positional clause children),
// so this name set is what distinguishes `[then …]` (keyword) from `[article …]`
// (element → function). Kept SMALL to avoid mis-coloring a data element that
// happens to share the name.
const program_clause_keywords = {
	'then':  true
	'else':  true
	'case':  true
	'when':  true
	'where': true
	'yield': true
}

struct SemToken {
	line     int
	col      int
	length   int
	tt       int
	tm       int
}

// program_token_overlay walks a parsed program AST and returns a map keyed by
// 0-based byte OFFSET (the same coordinate as compute_semantic_tokens' cursor
// `i`, and as cx.Position.offset) → token type, for the ONE thing the flat
// lexer cannot decide from position alone: an atom literal `:NAME` → tt_atom
// vs a `:label` slot prefix (they lex identically; only the parser tells them
// apart). Element / call HEADS are typed structurally by the lexer's head-
// position rule instead (see compute_semantic_tokens), which needs no successful
// parse and avoids the head-offset mismatch the AST positions caused.
//
// On a buffer that does not parse (normal mid-edit), parse_program errors and
// the overlay is empty — `:ident` tokens then fall back to tt_parameter.
fn program_token_overlay(source string) map[int]int {
	prog := cx.parse_program(source) or { return {} }
	mut out := map[int]int{}
	collect_token_roles(prog.body, source, mut out)
	return out
}

// collect_token_roles recursively walks a ProgramNode subtree and records the
// byte offset → tt_atom of every atom literal.
fn collect_token_roles(node cx.ProgramNode, source string, mut out map[int]int) {
	match node {
		cx.ProgramLiteral {
			if node.kind == .atom_lit {
				out[node.pos.offset] = tt_atom
			}
			// Element / call HEADS are NOT recorded here. cx_element pos points
			// at the `[` (not the name) and the program parser models the `[= …]`
			// bind form and `[$call …]` dispatch as elements whose "name" is `=`
			// / a `$`-glued head — so head offsets land on `=`/`[`/`$`, which the
			// flat lexer's bareword lookup never hits (verified: 1/40 emitted).
			// Heads are instead typed STRUCTURALLY by the lexer's head-position
			// rule (a token immediately after `[`), which is parse-error-robust
			// and correctly colors `$`-call heads as functions. This overlay now
			// carries ONLY the one thing position alone cannot decide: an atom
			// literal `:NAME` vs a `:label` slot prefix.
			for child in node.items {
				collect_token_roles(child, source, mut out)
			}
			for slot in node.slots {
				collect_token_roles(slot.value, source, mut out)
			}
			for attr in node.attrs {
				collect_token_roles(attr.value, source, mut out)
			}
		}
		cx.Program {
			collect_token_roles(node.body, source, mut out)
		}
		cx.ProgramBinding {
			// name + path — no child ProgramNode; the `$name` span is typed by
			// the lexer's `$` arm.
		}
		cx.ProgramCall {
			for arg in node.args {
				collect_token_roles(arg, source, mut out)
			}
		}
		cx.ProgramDirective {
			for slot in node.slots {
				collect_token_roles(slot.value, source, mut out)
			}
		}
		cx.ProgramForComp {
			// L100: THE ONE traversal. The hand-rolled walk this replaces
			// stopped at `yield`, so tokens inside the `[yield-map K V]`
			// VALUE expression got NO semantic-token roles at all.
			for item in cx.for_comp_children(node) {
				collect_token_roles(item.node, source, mut out)
			}
		}
		cx.ProgramPattern {
			for attr in node.attrs {
				if val := attr.value {
					collect_token_roles(val, source, mut out)
				}
			}
			for child in node.body {
				collect_token_roles(child, source, mut out)
			}
		}
		cx.ProgramPathExpr {
			// No literal children in path expressions.
		}
		cx.ProgramSliceAccess {
			collect_token_roles(node.binding, source, mut out)
			for ax in node.axes {
				if v := ax.start { collect_token_roles(v, source, mut out) }
				if v := ax.stop  { collect_token_roles(v, source, mut out) }
				if v := ax.step  { collect_token_roles(v, source, mut out) }
			}
		}
		cx.ProgramSliceLiteral {
			for ax in node.axes {
				if v := ax.start { collect_token_roles(v, source, mut out) }
				if v := ax.stop  { collect_token_roles(v, source, mut out) }
				if v := ax.step  { collect_token_roles(v, source, mut out) }
			}
		}
		cx.ProgramWildcard {
			// No children.
		}
	}
}

fn compute_semantic_tokens(source string) []int {
	// Parser-driven overlay: byte offset → token type for the spans only the
	// parser can classify — atom literals (`:NAME` vs `:label`) and element /
	// call HEADS (`[name …]`, `name(args)`). The lexer below tokenizes spans
	// (strings, numbers, `$bindings`, `?directives`, operators — all context-
	// free) and consults the overlay to type heads / atoms correctly without
	// re-introducing the old blanket-`variable` masking. On a buffer that does
	// not parse (mid-edit), the overlay is empty and heads degrade to no token.
	overlay := program_token_overlay(source)

	mut tokens := []SemToken{}
	mut line := 0
	mut col := 0
	mut i := 0
	// expect_head tracks HEAD position: the first token after a `[` (modulo
	// whitespace) is an element / call / clause head. This structural rule —
	// not a parse — is what colors `[name …]` element heads and `[$call …]`
	// call heads as functions (distinct from `$binding` references, which sit
	// elsewhere and stay variables). It is robust to parse errors and to the
	// program parser's `[= …]` / `[$…]` head-offset conventions.
	mut expect_head := false
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
		// Block comment `[; … ]` — emit a comment token for the WHOLE span so it
		// DIMS like the line comment. Without this the tokenizer descended into the
		// body and emitted code tokens (atoms / types / directives / bindings) that
		// OVERRIDE the editor's tmLanguage + tree-sitter comment highlighting (the
		// reported "interior not dimmed"). Balance nested `[ ]` to the matching `]`
		// (mirrors the parser's read_until_close), treating `[#…#]` / `[|…|]` as
		// atomic so their inner `]` does not miscount. LSP tokens cannot span lines,
		// so emit ONE comment token per line the comment covers (as the string arm
		// does); skip zero-length segments.
		if c == `[` && i + 1 < source.len && source[i + 1] == `;` {
			mut j := i
			mut depth := 0
			mut seg_col := col
			mut cur_line := line
			mut cur_col := col
			for j < source.len {
				ch := source[j]
				if ch == `\n` {
					if cur_col > seg_col {
						tokens << SemToken{line: cur_line, col: seg_col, length: cur_col - seg_col, tt: tt_comment, tm: 0}
					}
					cur_line++
					cur_col = 0
					seg_col = 0
					j++
					continue
				}
				// Atomic raw/block span: skip to #] / |] so its inner ] is not counted.
				if ch == `[` && j + 1 < source.len && (source[j + 1] == `#` || source[j + 1] == `|`) {
					cf := source[j + 1]
					cur_col += 2
					j += 2
					for j < source.len {
						if source[j] == cf && j + 1 < source.len && source[j + 1] == `]` {
							cur_col += 2
							j += 2
							break
						}
						if source[j] == `\n` {
							if cur_col > seg_col {
								tokens << SemToken{line: cur_line, col: seg_col, length: cur_col - seg_col, tt: tt_comment, tm: 0}
							}
							cur_line++
							cur_col = 0
							seg_col = 0
						} else {
							cur_col++
						}
						j++
					}
					continue
				}
				if ch == `[` {
					depth++
				} else if ch == `]` {
					depth--
					cur_col++
					j++
					if depth == 0 {
						break
					}
					continue
				}
				cur_col++
				j++
			}
			if cur_col > seg_col {
				tokens << SemToken{line: cur_line, col: seg_col, length: cur_col - seg_col, tt: tt_comment, tm: 0}
			}
			line = cur_line
			col = cur_col
			i = j
			expect_head = false
			continue
		}
		// Raw text `[# … #]` and block content `[| … |]` are OPAQUE regions:
		// skip them entirely (emit no tokens). Their interior is CDATA / an
		// embedded language — tree-sitter colors raw text and injects the inner
		// language; tokenizing the interior as cx produced garbage (`(`, JS
		// fragments → spurious function/keyword tokens). Scan to the matching
		// `#]` / `|]`, tracking line/col so later tokens stay aligned.
		if c == `[` && i + 1 < source.len && (source[i + 1] == `#` || source[i + 1] == `|`) {
			cf := source[i + 1]
			col += 2
			mut j := i + 2
			for j < source.len {
				if source[j] == cf && j + 1 < source.len && source[j + 1] == `]` {
					col += 2
					j += 2
					break
				}
				if source[j] == `\n` {
					line++
					col = 0
				} else {
					col++
				}
				j++
			}
			i = j
			expect_head = false
			continue
		}
		// `[` opens a form — the next non-whitespace token is its HEAD.
		// (Whitespace/newlines above preserve expect_head; every other token
		// branch below consumes the head slot via the `is_head` capture.)
		if c == `[` {
			expect_head = true
			col++
			i++
			continue
		}
		// Capture-and-consume the head slot for this token. Any non-`[`,
		// non-whitespace byte (`]`, `{`, `(`, `,`, a scalar, a sigil, …) ends
		// the head expectation; only the `$` and bareword arms act on is_head.
		is_head := expect_head
		expect_head = false
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
		// String literal — `"…"` with `\\` escapes. May span MULTIPLE lines
		// (cx admits multi-line double-quoted strings; real code embeds whole
		// JS/CSS bodies as `[?const APPJS "…"]`). Two things this must get right:
		// (1) scan across newlines to the closing `"` — the old code broke at the
		// first `\n`, so a multi-line string's body was then tokenized as cx code
		// → mass garbage; (2) LSP semantic tokens cannot span lines, so emit ONE
		// string token PER LINE the string covers.
		if c == `"` {
			mut j := i + 1
			mut seg_col := col          // start col of the current line's segment
			mut cur_line := line
			mut cur_col := col + 1      // col just past the opening `"`
			for j < source.len && source[j] != `"` {
				if source[j] == `\n` {
					tokens << SemToken{line: cur_line, col: seg_col, length: cur_col - seg_col, tt: tt_string, tm: 0}
					cur_line++
					cur_col = 0
					seg_col = 0
					j++
					continue
				}
				if source[j] == `\\` && j + 1 < source.len && source[j + 1] != `\n` {
					cur_col += 2
					j += 2
					continue
				}
				cur_col++
				j++
			}
			if j < source.len {
				// closing quote
				cur_col++
				j++
			}
			tokens << SemToken{line: cur_line, col: seg_col, length: cur_col - seg_col, tt: tt_string, tm: 0}
			line = cur_line
			col = cur_col
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
		// `:slot` or `:atom` — classified via the parser overlay.
		//
		// Both atom literals and labeled-slot prefixes start with `:ident`
		// at the lexer level. The overlay map (built by program_token_overlay
		// above, keyed by byte offset) records every position where the parser
		// confirms an atom literal; those get tt_atom. All other `:ident`
		// tokens remain tt_parameter (slot label).
		if c == `:` && i + 1 < source.len && is_lsp_word_char(source[i + 1]) {
			start := col
			mut j := i + 1
			for j < source.len && is_lsp_word_char(source[j]) { j++ }
			length := j - i
			tt := if i in overlay { overlay[i] } else { tt_parameter }
			tokens << SemToken{line: line, col: start, length: length, tt: tt, tm: 0}
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
		// `$binding` / `$module:name`. In HEAD position (`[$call …]`) the `$`
		// head is a CALL — the name is tt_function so calls stand out from the
		// `$binding` REFERENCES that fill argument position (tt_variable). The
		// leading `$` is PART of the token (so the sigil and name render as one,
		// not a two-tone split).
		if c == `$` && i + 1 < source.len && is_lsp_word_char(source[i + 1]) {
			start := col
			name_tt := if is_head { tt_function } else { tt_variable }
			mut j := i + 1
			for j < source.len && is_lsp_word_char(source[j]) && source[j] != `:` { j++ }
			// `$module:name` → namespace (incl. `$`) + name (function head / variable).
			if j < source.len && source[j] == `:` && j + 1 < source.len && is_lsp_word_char(source[j + 1]) {
				ns_len := j - i // includes the leading `$`
				tokens << SemToken{line: line, col: start, length: ns_len, tt: tt_namespace, tm: 0}
				j++
				name_start := j
				for j < source.len && is_lsp_word_char(source[j]) && source[j] != `:` { j++ }
				tokens << SemToken{line: line, col: start + ns_len + 1, length: j - name_start, tt: name_tt, tm: 0}
				col += j - i
				i = j
				continue
			}
			length := j - i // includes the leading `$`
			tokens << SemToken{line: line, col: start, length: length, tt: name_tt, tm: 0}
			col += length
			i = j
			continue
		}
		// Bareword (optionally namespaced `module:name`): in HEAD position it is
		// an element / call head → tt_function, or a clause keyword (`then` /
		// `else` / `case` / …) → tt_keyword. ANYWHERE ELSE it is prose / a value
		// reference / an attribute name — emit NOTHING and defer to the grammar
		// layer (emitting a blanket `variable` here is what masked the grammar
		// before). The whole word, INCLUDING any `module:name` continuation, is
		// consumed so the trailing `:name` is not re-lexed as a `:slot`/`:atom`.
		if is_ident_start(c) {
			mut j := i
			for j < source.len && is_lsp_word_char(source[j]) && source[j] != `:` { j++ }
			word := source[i..j]
			// Consume a `:name` namespace continuation as part of the word.
			if j < source.len && source[j] == `:` && j + 1 < source.len && is_lsp_word_char(source[j + 1]) {
				j++
				for j < source.len && is_lsp_word_char(source[j]) && source[j] != `:` { j++ }
			}
			length := j - i
			if length > 0 {
				if is_head {
					tt := if word in program_clause_keywords { tt_keyword } else { tt_function }
					tokens << SemToken{line: line, col: col, length: length, tt: tt, tm: 0}
				}
				col += length
				i = j
				continue
			}
		}
		// Operators `|>`, `=>`, `||`, `->`, `!`, and the bare `=` head (the
		// `[= …]` bind form and `name=value` attribute separator).
		if c == `|` || c == `=` || c == `-` || c == `!` {
			if (c == `|` && i + 1 < source.len && (source[i + 1] == `>` || source[i + 1] == `|`))
				|| (c == `=` && i + 1 < source.len && source[i + 1] == `>`)
				|| (c == `-` && i + 1 < source.len && source[i + 1] == `>`) {
				tokens << SemToken{line: line, col: col, length: 2, tt: tt_operator, tm: 0}
				col += 2
				i += 2
				continue
			}
			if c == `!` || c == `=` {
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
