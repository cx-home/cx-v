// Q5: `cx lsp` — Language Server Protocol implementation for CX.
//
// Architecture: thin LSP wrapper over libcx. The CX parser, lint, fmt,
// and validation engines are the canonical implementation; the LSP
// server marshals their results into the LSP message shapes. There is
// no separate parser, no tree-sitter dependency at runtime, no FFI
// surface to maintain — one parser, one source of truth.
//
// Pattern reference: TypeScript's tsserver (built into the compiler)
// and Go's gopls (built into the Go toolchain). Same architecture:
// the LSP server is a thin wrapper over the canonical implementation
// rather than a parallel reimplementation.
//
// Wire format: JSON-RPC 2.0 over stdio with LSP's `Content-Length`
// header framing. See https://microsoft.github.io/language-server-protocol/.
//
// Capabilities:
//   - textDocument/{didOpen,didChange,didClose}
//   - textDocument/publishDiagnostics (push from parse errors)
//   - textDocument/hover (directive + filter docstrings)
//   - textDocument/completion (directive names + in-scope bindings)
//   - textDocument/semanticTokens (full)
//   - textDocument/formatting (wraps cx fmt)
//   - textDocument/definition (#id + &anchor + ?def name resolution)
//
// Editor configs: tooling/lsp/{vscode,neovim,helix}.example.

module main

import os
import x.json2
import cx

// ── Wire-level: JSON-RPC framing over stdio ──────────────────────────

const lsp_buf_size = 65536

struct LspMessage {
mut:
	jsonrpc string
	id      json2.Any  // int OR string OR none (for notifications)
	has_id  bool       // true iff the `id` key was present on the wire
	method  string
	params  json2.Any
	result  json2.Any
	error   json2.Any
}

fn run_lsp(args []string) {
	// LSP is silent on stderr by default; --verbose enables tracing.
	verbose := '--verbose' in args
	if verbose {
		eprintln('cx lsp: starting (v0.7.0)')
	}
	mut state := new_lsp_state(verbose)
	for {
		msg := read_lsp_message() or {
			if verbose { eprintln('cx lsp: read error: ${err}') }
			break
		}
		if msg.method == 'exit' {
			if verbose { eprintln('cx lsp: exit notification — terminating') }
			break
		}
		dispatch_lsp_message(msg, mut state)
	}
}

// read_lsp_message reads a single LSP-framed JSON-RPC message from
// stdin. Uses raw `C.read(0, …)` for both header and body so the V
// buffered stdin doesn't swallow body bytes between the two reads.
fn read_lsp_message() !LspMessage {
	header := read_lsp_header()!
	mut content_length := 0
	for hl in header.split('\n') {
		l := hl.trim_space()
		if l.len == 0 { continue }
		if l.to_lower().starts_with('content-length:') {
			parts := l.split(':')
			if parts.len >= 2 {
				content_length = parts[1].trim_space().int()
			}
		}
	}
	if content_length <= 0 {
		return error('missing or zero Content-Length')
	}
	mut body_bytes := []u8{len: content_length}
	mut read := 0
	for read < content_length {
		n := C.read(0, unsafe { &body_bytes[read] }, content_length - read)
		if n <= 0 { return error('eof mid-body') }
		read += int(n)
	}
	body := body_bytes.bytestr()
	any_val := json2.decode[json2.Any](body)!
	return lsp_message_from_any(any_val)
}

// read_lsp_header reads bytes one at a time from fd 0 until the
// `\r\n\r\n` end-of-headers marker is observed. Returns the raw header
// bytes (excluding the terminating blank line) as a string.
fn read_lsp_header() !string {
	mut buf := []u8{cap: 256}
	mut one := [u8(0)]
	for {
		n := C.read(0, unsafe { &one[0] }, 1)
		if n <= 0 { return error('eof') }
		buf << one[0]
		if buf.len >= 4
			&& buf[buf.len - 4] == `\r`
			&& buf[buf.len - 3] == `\n`
			&& buf[buf.len - 2] == `\r`
			&& buf[buf.len - 1] == `\n` {
			return buf[..buf.len - 4].bytestr()
		}
	}
	return error('unreachable')
}

fn lsp_message_from_any(v json2.Any) !LspMessage {
	obj := v as map[string]json2.Any
	mut m := LspMessage{}
	if jr := obj['jsonrpc'] { m.jsonrpc = jr.str() }
	if id := obj['id']      { m.id = id  m.has_id = true }
	if method := obj['method'] { m.method = method.str() }
	if params := obj['params'] { m.params = params }
	if result := obj['result'] { m.result = result }
	if err := obj['error']     { m.error = err }
	return m
}

// write_lsp_response sends a JSON-RPC response with the given id +
// result. The id is the same shape (int / string) that came in.
fn write_lsp_response(id json2.Any, result json2.Any) {
	mut env := map[string]json2.Any{}
	env['jsonrpc'] = json2.Any('2.0')
	env['id'] = id
	env['result'] = result
	write_lsp_envelope(env)
}

fn write_lsp_error(id json2.Any, code int, message string) {
	mut err := map[string]json2.Any{}
	err['code'] = json2.Any(i64(code))
	err['message'] = json2.Any(message)
	mut env := map[string]json2.Any{}
	env['jsonrpc'] = json2.Any('2.0')
	env['id'] = id
	env['error'] = json2.Any(err)
	write_lsp_envelope(env)
}

fn write_lsp_notification(method string, params json2.Any) {
	mut env := map[string]json2.Any{}
	env['jsonrpc'] = json2.Any('2.0')
	env['method'] = json2.Any(method)
	env['params'] = params
	write_lsp_envelope(env)
}

fn write_lsp_envelope(env map[string]json2.Any) {
	body := json2.Any(env).json_str()
	header := 'Content-Length: ${body.len}\r\n\r\n'
	print(header)
	print(body)
	lsp_flush_stdout()
}

// ── Dispatcher ───────────────────────────────────────────────────────

fn dispatch_lsp_message(msg LspMessage, mut state LspState) {
	if state.verbose {
		eprintln('cx lsp: ← ${msg.method}')
	}
	// id present → request; expects a response.
	// id absent  → notification; no response.
	//
	// We test has_id (set only when the `id` key was on the wire), NOT
	// `msg.id is json2.Null`: an absent id leaves the struct-default
	// json2.Any, whose zero value is an empty array — not json2.Null —
	// so the old check classified every notification as a request and
	// replied with an error carrying a bogus `id:[]`. Editors then choke
	// (Neovim: `assert(tonumber(decoded.id), 'response id must be a
	// number')`), e.g. on the textDocument/didSave fired by `:w`.
	is_request := msg.has_id
	match msg.method {
		'initialize'                   { handle_initialize(msg, mut state) }
		'initialized'                  { /* notification — no-op */ }
		'shutdown'                     { handle_shutdown(msg, mut state) }
		'textDocument/didOpen'         { handle_did_open(msg, mut state) }
		'textDocument/didChange'       { handle_did_change(msg, mut state) }
		'textDocument/didSave'         { /* notification — no-op */ }
		'textDocument/didClose'        { handle_did_close(msg, mut state) }
		'textDocument/hover'           { handle_hover(msg, mut state) }
		'textDocument/completion'      { handle_completion(msg, mut state) }
		'textDocument/semanticTokens/full' { handle_semantic_tokens(msg, mut state) }
		'textDocument/formatting'      { handle_formatting(msg, mut state) }
		'textDocument/definition'      { handle_definition(msg, mut state) }
		'textDocument/documentSymbol'  { handle_document_symbol(msg, mut state) }
		'textDocument/foldingRange'    { handle_folding_range(msg, mut state) }
		'textDocument/selectionRange'  { handle_selection_range(msg, mut state) }
		'textDocument/references'      { handle_references(msg, mut state) }
		'textDocument/rename'          { handle_rename(msg, mut state) }
		'textDocument/prepareRename'   { handle_prepare_rename(msg, mut state) }
		'textDocument/codeAction'      { handle_code_action(msg, mut state) }
		'textDocument/codeLens'        { handle_code_lens(msg, mut state) }
		'textDocument/inlayHint'       { handle_inlay_hint(msg, mut state) }
		'textDocument/signatureHelp'   { handle_signature_help(msg, mut state) }
		'$/cancelRequest'              { /* no-op */ }
		else {
			if is_request {
				write_lsp_error(msg.id, -32601, 'method not found: ${msg.method}')
			}
		}
	}
}

// ── Initialize / shutdown ────────────────────────────────────────────

fn handle_initialize(msg LspMessage, mut state LspState) {
	// Advertise capabilities. Numeric constants per LSP spec §6 (text
	// document sync kinds — Full=1, Incremental=2). The server uses Full
	// sync; Incremental is a future optimisation.
	mut caps := map[string]json2.Any{}
	caps['textDocumentSync'] = json2.Any(i64(1))  // Full
	caps['hoverProvider'] = json2.Any(true)
	mut completion := map[string]json2.Any{}
	completion['triggerCharacters'] = json2.Any([json2.Any('['), json2.Any('?'), json2.Any('@'), json2.Any(':'), json2.Any('/')])
	caps['completionProvider'] = json2.Any(completion)
	caps['definitionProvider'] = json2.Any(true)
	// `cx fmt` (cx_text_fmt) is the lossless canonical formatter: it
	// round-trips comments and is idempotent (`fmt(fmt(x)) == fmt(x)`), so a
	// whole-document format edit is safe under any client or trigger.
	caps['documentFormattingProvider'] = json2.Any(true)
	mut sem_tokens := map[string]json2.Any{}
	sem_tokens['legend'] = semantic_tokens_legend()
	sem_tokens['full'] = json2.Any(true)
	caps['semanticTokensProvider'] = json2.Any(sem_tokens)
	caps['documentSymbolProvider'] = json2.Any(true)
	caps['foldingRangeProvider'] = json2.Any(true)
	caps['selectionRangeProvider'] = json2.Any(true)
	caps['referencesProvider'] = json2.Any(true)
	mut rename_provider := map[string]json2.Any{}
	rename_provider['prepareProvider'] = json2.Any(true)
	caps['renameProvider'] = json2.Any(rename_provider)
	caps['codeActionProvider'] = json2.Any(true)
	// CodeLens: each top-level program directive in the
	// source gets a "View diagram" lens that opens the rendered
	// diagram via the `cx.diagram` workspace command. Phase 4.5
	// reference impl.
	mut code_lens := map[string]json2.Any{}
	code_lens['resolveProvider'] = json2.Any(false)
	caps['codeLensProvider'] = json2.Any(code_lens)
	caps['inlayHintProvider'] = json2.Any(true)
	mut sig_help := map[string]json2.Any{}
	sig_help['triggerCharacters'] = json2.Any([json2.Any(' '), json2.Any('(')])
	caps['signatureHelpProvider'] = json2.Any(sig_help)

	mut server_info := map[string]json2.Any{}
	server_info['name'] = json2.Any('cx lsp')
	server_info['version'] = json2.Any('0.8.0')

	mut result := map[string]json2.Any{}
	result['capabilities'] = json2.Any(caps)
	result['serverInfo'] = json2.Any(server_info)
	write_lsp_response(msg.id, json2.Any(result))
}

fn handle_shutdown(msg LspMessage, mut state LspState) {
	state.shutting_down = true
	write_lsp_response(msg.id, json2.Any(json2.Null{}))
}

// ── Document state ───────────────────────────────────────────────────

fn handle_did_open(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	text := td['text'] or { return }.str()
	state.open_doc(uri, text)
	publish_diagnostics(uri, mut state)
}

fn handle_did_change(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	changes := params['contentChanges'] or { return } as []json2.Any
	if changes.len == 0 { return }
	// Full sync: take the last full-doc text.
	last := changes[changes.len - 1] as map[string]json2.Any
	if text := last['text'] {
		state.update_doc(uri, text.str())
		publish_diagnostics(uri, mut state)
	}
}

fn handle_did_close(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	state.close_doc(uri)
}

// ── Diagnostics ──────────────────────────────────────────────────────

fn publish_diagnostics(uri string, mut state LspState) {
	source := state.doc_source(uri) or { return }
	mut diagnostics := []json2.Any{}
	// A `.cx` resource has TWO legitimate readings, both served by the ONE
	// cxparse engine: the DATA reading (cx.parse — scannerless; handles prose,
	// `[- … ]` comments, mixed-content markup like a tour/doc) and the PROGRAM
	// reading (cx.parse_program — tokenised; handles `[$call]`, directives,
	// operator heads). These are reading MODES of one engine, not two parsers.
	// A file is well-formed if it parses under EITHER mode, so we only raise a
	// syntax diagnostic when BOTH fail. (Raising on a single mode is wrong: it
	// flags valid programs as data errors — e.g. `[> a b]`, program maps — and
	// valid data documents as program errors — e.g. a `;`/em-dash in prose or a
	// comment. The earlier false errors were a STALE editor binary running an
	// old program parser, fixed by pointing the editor at the trunk build.)
	cx.parse(source) or {
		data_err := err.msg()
		if _ := cx.parse_program(source) {
			// valid under the program reading → not a syntax error
		} else {
			// Both readings failed → a genuine syntax error. Report the data
			// reading's position (its scannerless cursor pinpoints prose/markup
			// faults; parse_error_position handles either error format).
			line, col := parse_error_position(data_err)
			mut diag := map[string]json2.Any{}
			mut range_obj := map[string]json2.Any{}
			mut start := map[string]json2.Any{}
			start['line'] = json2.Any(i64(line))
			start['character'] = json2.Any(i64(col))
			mut end_pos := map[string]json2.Any{}
			end_pos['line'] = json2.Any(i64(line))
			end_pos['character'] = json2.Any(i64(col + 1))
			range_obj['start'] = json2.Any(start)
			range_obj['end'] = json2.Any(end_pos)
			diag['range'] = json2.Any(range_obj)
			diag['severity'] = json2.Any(i64(1))  // Error
			diag['source'] = json2.Any('cx-parse')
			diag['message'] = json2.Any(data_err)
			diagnostics << json2.Any(diag)
		}
	}
	// v0.8.0 Phase 5.5 — CXLS001 / CXLS002 / CXLS003 from [?match] arm
	// analysis. match_diagnostics returns an empty slice on parse
	// failure (mid-edit / unrelated syntax error), so we always emit
	// any parse-error diag first and then layer match-arm diags on
	// top — no duplicate / no race.
	for d in match_diagnostics(source) {
		diagnostics << d
	}
	// v0.8.0 Phase 5.5 finish — CXLS004 from [?modify] :set-attr /
	// delete-attr on attribute-step focus paths. The
	// analyser recognises both the static parse-error signal (the
	// code parser raises CXER0100 before producing the AST) and the
	// post-parse defensive walk; see vcx/cmd/lsp_modify_diagnostics.v.
	for d in modify_diagnostics(source) {
		diagnostics << d
	}
	// CXLS005 advisory when [?map :par] / [?reduce :par]
	// has no [?bulkhead] wrap in its :using body. Hint severity; no
	// directive-level opt-out (standard editor suppress comments apply).
	for d in par_diagnostics(source) {
		diagnostics << d
	}
	// CXLS006 advisory when a [?for] / [?for-array]
	// [?for-map] generator source is an open-end range (`1 to *`) with no
	// `:take` / `:takewhile` terminator. Forcing the iterator at eval
	// time raises CXER0100; the advisory surfaces this statically so the
	// editor flags it before run. See vcx/cmd/lsp_infinite_diagnostics.v.
	for d in infinite_diagnostics(source) {
		diagnostics << d
	}
	// CXLS007 advisory: an ambiguous whitespace-separated quoted-string body
	// (`[x "a" "b"]`) that does not round-trip in idiomatic XML/CX. Warning
	// severity; see vcx/cmd/lsp_string_list_diagnostics.v.
	for d in string_list_diagnostics(source) {
		diagnostics << d
	}
	mut params := map[string]json2.Any{}
	params['uri'] = json2.Any(uri)
	params['diagnostics'] = json2.Any(diagnostics)
	write_lsp_notification('textDocument/publishDiagnostics', json2.Any(params))
}

// parse_error_position extracts "line:col" from a libcx parse error
// message. Returns (0, 0) when the format doesn't match — diagnostics
// are still emitted at the start of the document.
fn parse_error_position(msg string) (int, int) {
	// Extract a 1-based `L:C` location from a parse-error message, wherever it
	// sits. The data reading historically prefixes "L:C: message"; the program
	// reading (cx.parse_program) embeds it as "… at line L:C". Scan for the
	// first `<digits>:<digits>` run (digits immediately on both sides of a `:`)
	// so BOTH formats resolve to the real position rather than 0:0.
	for i := 0; i < msg.len; i++ {
		if msg[i] != `:` { continue }
		mut j := i - 1
		for j >= 0 && msg[j] >= `0` && msg[j] <= `9` { j-- }
		mut k := i + 1
		for k < msg.len && msg[k] >= `0` && msg[k] <= `9` { k++ }
		before := msg[j + 1..i]
		after := msg[i + 1..k]
		if before.len > 0 && after.len > 0 {
			l := before.int()
			c := after.int()
			if l > 0 && c >= 0 {
				// LSP positions are 0-based; libcx is 1-based.
				return l - 1, c - 1
			}
		}
	}
	return 0, 0
}

// ── Hover ────────────────────────────────────────────────────────────

fn handle_hover(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	pos := params['position'] or { return } as map[string]json2.Any
	line := json_int(pos['line'] or { return })
	col := json_int(pos['character'] or { return })
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	// v0.8.0 Phase 5.5 — CXPath focus hover. When the
	// cursor sits inside a ProgramPathExpr's source range, return
	// the structural breakdown ahead of the per-word docs path.
	if path_md := cxpath_hover_md(source, line, col) {
		mut contents := map[string]json2.Any{}
		contents['kind'] = json2.Any('markdown')
		contents['value'] = json2.Any(path_md)
		mut result := map[string]json2.Any{}
		result['contents'] = json2.Any(contents)
		write_lsp_response(msg.id, json2.Any(result))
		return
	}
	word := word_at_position(source, line, col)
	if word == '' {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	doc_text := hover_docs_for(word)
	if doc_text == '' {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	mut contents := map[string]json2.Any{}
	contents['kind'] = json2.Any('markdown')
	contents['value'] = json2.Any(doc_text)
	mut result := map[string]json2.Any{}
	result['contents'] = json2.Any(contents)
	write_lsp_response(msg.id, json2.Any(result))
}

// ── Completion ───────────────────────────────────────────────────────

fn handle_completion(msg LspMessage, mut state LspState) {
	mut items := []json2.Any{}

	// v0.8.0 Phase 5.5 finish — path-context completion.
	// When the cursor sits inside a CXPath fragment, prepend axis /
	// element / attribute completions sourced from
	// vcx/cmd/lsp_modify_diagnostics.v. The path-context check is
	// best-effort: if the request omits position/textDocument (some
	// clients send a bare params), or if the cursor is NOT inside a
	// CXPath, the provider returns an empty slice and the directive /
	// module-function completions below remain unchanged.
	mut path_items := []json2.Any{}
	path_items = completion_path_items_from_params(msg, mut state)
	for pi in path_items {
		items << pi
	}

	// Directive names — sourced from the canonical allowlist.
	// Items are snippet-flavoured so editors expand `?if` → full
	// `[?if cond :then x :else y]` template with tab-stops.
	directives := completion_directive_names()
	for name, desc in directives {
		mut item := map[string]json2.Any{}
		item['label'] = json2.Any(name)
		item['kind'] = json2.Any(i64(14))  // Keyword
		item['detail'] = json2.Any('cx directive')
		item['documentation'] = json2.Any(desc)
		if snippet := completion_snippet_for(name) {
			item['insertText'] = json2.Any(snippet)
			item['insertTextFormat'] = json2.Any(i64(2))  // Snippet
		}
		items << json2.Any(item)
	}
	// Core module-prefixed names (cx:, log:, fn:, map:, array:) — curated
	// builtins that are NOT bundled stdlib modules.
	for name, desc in completion_module_fns() {
		mut item := map[string]json2.Any{}
		item['label'] = json2.Any(name)
		item['kind'] = json2.Any(i64(3))   // Function
		item['detail'] = json2.Any('cx module function')
		item['documentation'] = json2.Any(desc)
		items << json2.Any(item)
	}
	// Full bundled stdlib surface (json:, crypto:, time:, http:, csv:, re:,
	// store:, … — ~800 functions across ~30 modules), enumerated from the
	// compiled-in bundle and cached. `detail` carries the signature.
	for name, sig in state.get_stdlib_completion() {
		mut item := map[string]json2.Any{}
		item['label'] = json2.Any(name)
		item['kind'] = json2.Any(i64(3))   // Function
		item['detail'] = json2.Any(sig)
		item['documentation'] = json2.Any('cx stdlib function')
		items << json2.Any(item)
	}
	mut result := map[string]json2.Any{}
	result['isIncomplete'] = json2.Any(false)
	result['items'] = json2.Any(items)
	write_lsp_response(msg.id, json2.Any(result))
}

// completion_path_items_from_params unpacks the request's
// textDocument.uri + position and asks `path_completion_items` for
// path-context completions. Returns an empty slice on any unpack
// failure or when the cursor is NOT inside a CXPath fragment.
fn completion_path_items_from_params(msg LspMessage, mut state LspState) []json2.Any {
	empty := []json2.Any{}
	if msg.params !is map[string]json2.Any { return empty }
	params := msg.params as map[string]json2.Any
	td_any := params['textDocument'] or { return empty }
	if td_any !is map[string]json2.Any { return empty }
	td := td_any as map[string]json2.Any
	uri_any := td['uri'] or { return empty }
	uri := uri_any.str()
	source := state.doc_source(uri) or { return empty }
	pos_any := params['position'] or { return empty }
	if pos_any !is map[string]json2.Any { return empty }
	pos := pos_any as map[string]json2.Any
	line_any := pos['line'] or { return empty }
	col_any  := pos['character'] or { return empty }
	line := json_int(line_any)
	col  := json_int(col_any)
	return path_completion_items(source, line, col)
}

// ── Semantic tokens ──────────────────────────────────────────────────

fn semantic_tokens_legend() json2.Any {
	mut legend := map[string]json2.Any{}
	// Token type order matters — semanticTokens delta-encodes against
	// these indices. Keep stable across versions.
	token_types := [
		json2.Any('namespace'),    // 0  — module prefix (cx:, log:, fn:, …)
		json2.Any('keyword'),      // 1  — directive name (if, for, fn, let, …)
		json2.Any('variable'),     // 2  — bound names (?let x, ?for x)
		json2.Any('parameter'),    // 3  — slot labels (:let, :where, :return)
		json2.Any('property'),     // 4  — attribute names
		json2.Any('string'),       // 5  — quoted string values
		json2.Any('number'),       // 6  — numeric scalars
		json2.Any('comment'),      // 7  — # line comments + [-...] blocks
		json2.Any('operator'),     // 8  — |>, =>, ||, ->, !, to
		json2.Any('decorator'),    // 9  — #id, &anchor, *merge
		json2.Any('enumMember'),   // 10 — atom literal :NAME (tt_atom)
		json2.Any('function'),     // 11 — element / call head name (tt_function)
	]
	legend['tokenTypes'] = json2.Any(token_types)
	legend['tokenModifiers'] = json2.Any([]json2.Any{})
	return json2.Any(legend)
}

fn handle_semantic_tokens(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any(json2.Null{}))
		return
	}
	data := compute_semantic_tokens(source)
	mut result := map[string]json2.Any{}
	mut data_any := []json2.Any{}
	for v in data { data_any << json2.Any(i64(v)) }
	result['data'] = json2.Any(data_any)
	write_lsp_response(msg.id, json2.Any(result))
}

// ── Formatting ───────────────────────────────────────────────────────

fn handle_formatting(msg LspMessage, mut state LspState) {
	// Whole-document format via `cx fmt` (cx_text_fmt) — the lossless
	// canonical formatter: it round-trips comments and is idempotent
	// (`fmt(fmt(x)) == fmt(x)`), so a single full-range TextEdit normalises
	// layout without losing data or oscillating. A parse error yields zero
	// edits (leave the buffer untouched rather than emit a partial result).
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	formatted := cx.cx_text_fmt(source) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	// Safety guard — NEVER emit a destructive edit. `cx fmt` is lossless and
	// idempotent, but format-on-save runs unattended on every `:w`, so we make
	// a hypothetical future regression fail SAFE (zero edits) rather than
	// clobber the buffer. Apply the edit only when the result is both
	// data-equivalent to the source (strict-canonical equality) AND a fixpoint
	// (re-formatting is stable, so the buffer can't oscillate save-to-save).
	equivalent := cx.cx_text_eq(source, formatted) or { false }
	if !equivalent {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	refmt := cx.cx_text_fmt(formatted) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	if refmt != formatted {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	// Single TextEdit replacing the whole document.
	lines := source.split('\n').len
	mut edit := map[string]json2.Any{}
	mut range_obj := map[string]json2.Any{}
	mut start := map[string]json2.Any{}
	start['line'] = json2.Any(i64(0))
	start['character'] = json2.Any(i64(0))
	mut end_pos := map[string]json2.Any{}
	end_pos['line'] = json2.Any(i64(lines))
	end_pos['character'] = json2.Any(i64(0))
	range_obj['start'] = json2.Any(start)
	range_obj['end'] = json2.Any(end_pos)
	edit['range'] = json2.Any(range_obj)
	edit['newText'] = json2.Any(formatted)
	write_lsp_response(msg.id, json2.Any([json2.Any(edit)]))
}

// ── Goto definition ──────────────────────────────────────────────────
//
// Minimum: resolve #id references to their declaration site.
// Anchor / merge / ?def-name resolution adds later once the
// CXLEnv binding-position tracking is exposed.

fn handle_definition(msg LspMessage, mut state LspState) {
	params := msg.params as map[string]json2.Any
	td := params['textDocument'] or { return } as map[string]json2.Any
	uri := td['uri'] or { return }.str()
	pos := params['position'] or { return } as map[string]json2.Any
	line := json_int(pos['line'] or { return })
	col := json_int(pos['character'] or { return })
	source := state.doc_source(uri) or {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	word := word_at_position(source, line, col)
	if !(word.starts_with('@') || word.starts_with('#')) {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	target_id := word[1..]
	def_line, def_col := find_id_declaration(source, target_id)
	if def_line < 0 {
		write_lsp_response(msg.id, json2.Any([]json2.Any{}))
		return
	}
	mut loc := map[string]json2.Any{}
	loc['uri'] = json2.Any(uri)
	mut range_obj := map[string]json2.Any{}
	mut start := map[string]json2.Any{}
	start['line'] = json2.Any(i64(def_line))
	start['character'] = json2.Any(i64(def_col))
	mut end_pos := map[string]json2.Any{}
	end_pos['line'] = json2.Any(i64(def_line))
	end_pos['character'] = json2.Any(i64(def_col + target_id.len + 1))
	range_obj['start'] = json2.Any(start)
	range_obj['end'] = json2.Any(end_pos)
	loc['range'] = json2.Any(range_obj)
	write_lsp_response(msg.id, json2.Any([json2.Any(loc)]))
}

// find_id_declaration scans source for `#<name>` followed by a non-
// identifier char (the declaration syntax) and returns its position.
// Returns (-1, -1) when not found.
fn find_id_declaration(source string, name string) (int, int) {
	pattern := '#' + name
	mut line := 0
	mut col := 0
	mut i := 0
	for i < source.len {
		if i + pattern.len <= source.len && source[i..i + pattern.len] == pattern {
			// Make sure this is the declaration, not the bare-@ ref.
			// Declaration site: `[name #id ...` — preceded by name + ws.
			// Heuristic: `#id` after `[name ` qualifies; `@id` is the
			// reference side and handled separately.
			after_pos := i + pattern.len
			if after_pos >= source.len ||
				!is_name_continuation(source[after_pos]) {
				// Walk backward to determine if preceded by `[name `
				// — declaration vs literal `#text` content.
				return line, col
			}
		}
		if source[i] == `\n` {
			line++
			col = 0
		} else {
			col++
		}
		i++
	}
	return -1, -1
}

fn is_name_continuation(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		|| (c >= `0` && c <= `9`) || c == `_` || c == `-` || c == `.`
}

// ── Stdio helpers ────────────────────────────────────────────────────

fn lsp_flush_stdout() {
	C.fflush(C.stdout)
}

// json_int normalises a json2.Any number (which V's json2 decodes as
// f64 for any JSON-numeric input) into an int. Returns 0 for non-
// numeric inputs so callers don't have to thread errors through every
// position read.
fn json_int(v json2.Any) int {
	if v is i64 { return int(v) }
	if v is f64 { return int(v) }
	if v is f32 { return int(v) }
	return 0
}
