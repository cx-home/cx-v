module cx

// ── CX code token model ──────────────────────────────────────────────────────────
//
// ProgramToken kinds, positions, and the directive-name closed set, locked to
// spec/code.md §3 (lexical structure) and §4.1 (directive registry).
//
// Grammar reference: spec/grammar.ebnf productions [120]–[129]. The
// ProgramDirName closed set in [127e] mirrors `directive_names` below — gate 3
// of the §11.6 release gates verifies set-equality across this module,
// the §4.1 registry, the EBNF, spec/ast.md, and spec/eval.md §12.
//
// Co-evolves with the spec. Adding a directive requires a spec
// change per spec/governance.md §10 and updates in all five sites.

// ProgramTokenKind enumerates every terminal the program lexer emits.
pub enum ProgramTokenKind {
	// Structural sigils
	lbrack            // '['
	rbrack            // ']'
	ldirective        // '[?'
	lparen            // '('
	rparen            // ')'
	lbrace            // '{'
	rbrace            // '}'
	comma             // ','
	// Pattern / binding / path sigils
	dollar            // '$'
	at                // '@'
	at_bang           // '@!'
	colon             // ':' (slot label prefix — parser confirms label)
	double_colon      // '::' — CXPath axis separator
	slash             // '/'
	double_slash      // '//' — CXPath descendant-or-self axis
	dot               // '.'
	star              // '*'
	double_star       // '**'
	pipe              // '|'
	plus              // '+'
	minus             // '-' (standalone; '-DIGIT' is a number literal)
	// Comparison operators (used in pattern @attr predicates and exprs)
	eq                // '='
	neq               // '!='
	lt                // '<'
	le                // '<='
	gt                // '>'
	ge                // '>='
	tilde             // '~' — graded-similarity operator head (similar.md §3.1)
	// Postfix call markers
	bang              // '!' postfix-or-standalone (parser disambiguates)
	qmark             // '?' postfix-or-standalone (parser disambiguates)
	// Literals
	ident             // [A-Za-z_][A-Za-z0-9_-]*
	directive_name    // 'match' | 'for' | 'modify' | ... (one of directive_names)
	string_lit        // '...' or "..."
	number_lit        // 123, -1.5, 1.5e10, etc.
	bool_lit          // 'true' | 'false'
	duration_lit      // 100ms, 5s, 1h30m, 2w (lexicon [L25] — exact span)
	period_lit        // 3mo, 1y, 1y6mo (lexicon [L26] — calendar span)
	date_lit          // 2024-01-15 (lexicon §9 [L23] — ONE token)
	datetime_lit      // 2024-01-15T10:30:00Z (lexicon §9 [L24] — ONE token)
	// DATA↔PROGRAM seam: a pure-DATA construct embedded verbatim in program
	// source — raw text `[#…#]`, an entity / char reference `&…;` / `&#…;`, or a
	// declaration `[!…]` (DTD decls + `[!DOCTYPE …]`). `text` carries the WHOLE
	// span (delimiters included); the parser delegates to `cx.parse_data_node`.
	data_span
	// End of input
	eof
}

// Position carries 1-based line / column plus the absolute byte offset.
// Lexer errors and parser errors both cite Position so diagnostics can
// be rendered uniformly.
pub struct Position {
pub:
	offset int // 0-based byte offset into source
	line   int // 1-based
	col    int // 1-based
}

// ProgramToken is the lexer's output unit. `text` carries the source slice
// verbatim (for literals, identifiers, durations); structural tokens set
// `text` to the canonical sigil string.
pub struct ProgramToken {
pub:
	kind ProgramTokenKind
	text string
	pos  Position
}

// LexError is the structured error a lexer produces. `code` is always
// `cx-err:CXER0100` (PARSE_ERROR) per spec/code.md §3.1; `message` carries
// the human-readable explanation and `pos` locates the offending byte.
pub struct LexError {
	Error
pub:
	code    string   = 'cx-err:CXER0100'
	message string
	pos     Position
}

pub fn (e LexError) msg() string {
	return '${e.code}: ${e.message} at line ${e.pos.line}:${e.pos.col}'
}

// directive_names is the closed set of directive names per
// spec/code.md §3.5 and §4.1 registry. Order is documentation-only;
// membership is what the lexer checks.
//
// This list MUST agree with spec/grammar.ebnf [127e] ProgramDirName and
// spec/eval.md §12.1–12.6 row count. Gate 3 verifies the equality.
//
// Changes: 'find' removed (retired); 'modify' added;
// 'par-map' / 'par-reduce' renamed to 'map' / 'reduce';
// Iterator combinator stdlib added (W3c): filter,
// take, drop, zip, enumerate, chunks, concat, chain, cycle, scan,
// flatten, partition, group-by; force-materialisation directives per
// to-sequence, to-array, to-map.
pub const directive_names = [
	'match', 'for', 'for-array', 'for-map',
	// 'try' RETIRED (SAP C3c, code.md §8.8 tombstone): handling unifies on
	// match + else/fallback + with-error-hook + '!'; a '[?try …]' head is an
	// unknown directive → CXER0100.
	'let', 'fn', 'def', 'if', 'else', 'pipe', 'modify',
	'map', 'reduce',
	// Core block-scoping directives with a guaranteed exit edge:
	// [?with-open] (scoped-resource RAII) + [?with-scope]
	// (dynamic-scoped context). See spec/code.md §8.10.7 / §8.10.8.
	'with-open', 'with-scope',
	// Module system directives (spec/code.md §12): [?lib]
	// import + [?const] module-level constant. Parsed at program level by
	// capturing raw source and delegating to parse_lib / parse_const.
	'lib', 'const',
	// Iterator combinator stdlib (W3c)
	'filter', 'take', 'drop', 'zip', 'enumerate', 'chunks',
	'concat', 'chain', 'cycle', 'scan', 'flatten',
	'partition', 'group-by',
	// explicit force-materialisation
	'to-sequence', 'to-array', 'to-map',
	// view opt-in (zero-copy slice intent)
	'view', 'views',
	'retry', 'timeout', 'circuit-breaker', 'fallback', 'rate-limit',
	'bulkhead',
	'http-service', 'service-handle', 'http-client',
	'worker', 'worker-handle',
	'channel', 'send', 'receive', 'try-send', 'try-receive', 'close',
	'select',
	'stop', 'wait-for',
	'async', 'await', 'await-all', 'await-any', 'await-race',
	'cancel', 'check-cancel', 'sleep',
	// Error-hook / capability / secret directives (spec/code.md §9.6,
	// security.md §3, cxdm.md §12). Mirrors grammar.ebnf [127e].
	'with-error-hook', 'with-caps', 'secret', 'reveal',
	// Compile-time string interpolation (spec/code.md §8.12;
	// grammar.ebnf [127r] StrDirective).
	'str',
	// Homoiconic dynamic construction (spec/code.md §6.4.2-§6.4.4;
	// grammar.ebnf [127s]-[127z]): computed names + quasiquote + tree-eval.
	'element', 'attr', 'entry', 'name',
	'quote', 'unquote', 'splice', 'eval',
	// Inert value annotations (spec/code.md §4.1 / §4.2 — D5):
	// `[?meta {…} FORM]` attaches a side-band metadata map to FORM's value;
	// read back via the `meta-of` builtin.
	'meta',
]

// is_directive_name reports whether `name` is a registered directive
// per the locked §4.1 registry.
pub fn is_directive_name(name string) bool {
	for d in directive_names {
		if d == name {
			return true
		}
	}
	return false
}
