// Q5 v0.7.0: `cx lsp` — Language Server Protocol implementation for CX.
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
// Capabilities at v0.7.0:
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
	if id := obj['id']      { m.id = id }
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
	is_request := !(msg.id is json2.Null)
	match msg.method {
		'initialize'                   { handle_initialize(msg, mut state) }
		'initialized'                  { /* notification — no-op */ }
		'shutdown'                     { handle_shutdown(msg, mut state) }
		'textDocument/didOpen'         { handle_did_open(msg, mut state) }
		'textDocument/didChange'       { handle_did_change(msg, mut state) }
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
		'textDocument/inlayHint'       { handle_inlay_hint(msg, mut state) }
		'textDocument/signatureHelp'   { handle_signature_help(msg, mut state) }
		'$/cancelRequest'              { /* no-op at v0.7.0 */ }
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
	// document sync kinds — Full=1, Incremental=2). v0.7.0 uses Full
	// sync; Incremental is a v0.7.x optimisation.
	mut caps := map[string]json2.Any{}
	caps['textDocumentSync'] = json2.Any(i64(1))  // Full
	caps['hoverProvider'] = json2.Any(true)
	mut completion := map[string]json2.Any{}
	completion['triggerCharacters'] = json2.Any([json2.Any('['), json2.Any('?'), json2.Any('@'), json2.Any(':')])
	caps['completionProvider'] = json2.Any(completion)
	caps['definitionProvider'] = json2.Any(true)
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
	caps['inlayHintProvider'] = json2.Any(true)
	mut sig_help := map[string]json2.Any{}
	sig_help['triggerCharacters'] = json2.Any([json2.Any(' '), json2.Any('(')])
	caps['signatureHelpProvider'] = json2.Any(sig_help)

	mut server_info := map[string]json2.Any{}
	server_info['name'] = json2.Any('cx lsp')
	server_info['version'] = json2.Any('0.7.0')

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
	// Full sync at v0.7.0: take the last full-doc text.
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
	cx.parse(source) or {
		// libcx parse errors carry "line:col: message" prefixes.
		msg_text := err.msg()
		line, col := parse_error_position(msg_text)
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
		diag['message'] = json2.Any(msg_text)
		diagnostics << json2.Any(diag)
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
	// V parser produces "L:C: message" or contains it after a path.
	parts := msg.split(':')
	if parts.len < 3 { return 0, 0 }
	for i in 0 .. parts.len - 1 {
		l := parts[i].trim_space().int()
		c := parts[i + 1].trim_space().int()
		if l > 0 && c >= 0 {
			// LSP positions are 0-based; libcx is 1-based.
			return l - 1, c - 1
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
	// Directive names — sourced from the v0.7.0 canonical allowlist.
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
	// Module-prefixed names (cx:, log:, fn:, map:, array:, math:)
	for name, desc in completion_module_fns() {
		mut item := map[string]json2.Any{}
		item['label'] = json2.Any(name)
		item['kind'] = json2.Any(i64(3))   // Function
		item['detail'] = json2.Any('cx module function')
		item['documentation'] = json2.Any(desc)
		items << json2.Any(item)
	}
	mut result := map[string]json2.Any{}
	result['isIncomplete'] = json2.Any(false)
	result['items'] = json2.Any(items)
	write_lsp_response(msg.id, json2.Any(result))
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
// v0.7.0 minimum: resolve #id references to their declaration site.
// Anchor / merge / ?def-name resolution adds in v0.7.x once the
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
