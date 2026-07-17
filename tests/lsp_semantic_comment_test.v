module main

import os
import testenv

// lsp_semantic_comment_test.v — regression guard for `[; … ]` block-comment
// dimming (cx-private). The LSP semantic-token tokenizer must emit COMMENT
// tokens for the whole `[; … ]` span, not descend into it and emit code tokens
// (atoms / types / directives / bindings). Those code tokens override the
// editor's tmLanguage (VS Code) and tree-sitter (Neovim) comment highlighting —
// which are themselves correct — so the comment interior showed UN-dimmed (the
// repeatedly-reported bug). This drives the real `cx lsp` over JSON-RPC and
// asserts the semantic-token TYPE ids.
//
// tt_comment is index 7 in the semanticTokens legend (vcx/cmd/lsp_content.v).
const tt_comment = 7

fn cx_bin() string {
	return testenv.cx_bin()
}

// frame wraps a JSON-RPC body in an LSP `Content-Length` header.
fn frame(body string) string {
	return 'Content-Length: ${body.len}\r\n\r\n${body}'
}

fn json_escape(s string) string {
	return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r',
		'\\r').replace('\t', '\\t')
}

// semantic_token_types drives `cx lsp` on `program` and returns the flat list of
// semantic-token TYPE ids (one per token). A full session is piped on stdin
// (initialize → didOpen → semanticTokens/full → shutdown → exit) so the server
// terminates and os.execute returns.
fn semantic_token_types(program string) []int {
	esc := json_escape(program)
	reqs := frame('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}') +
		frame('{"jsonrpc":"2.0","method":"initialized","params":{}}') +
		frame('{"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":"file:///t.cx","languageId":"cx","version":1,"text":"${esc}"}}}') +
		frame('{"jsonrpc":"2.0","id":2,"method":"textDocument/semanticTokens/full","params":{"textDocument":{"uri":"file:///t.cx"}}}') +
		frame('{"jsonrpc":"2.0","id":3,"method":"shutdown","params":{}}') +
		frame('{"jsonrpc":"2.0","method":"exit","params":{}}')
	reqfile := os.join_path(os.temp_dir(), 'cx_lsp_sem_req.txt')
	os.write_file(reqfile, reqs) or { panic('write ${reqfile}: ${err}') }
	r := os.execute('${cx_bin()} lsp < ${reqfile}')
	out := r.output
	// Only the semanticTokens response carries a "data" array.
	marker := '"data":['
	idx := out.index(marker) or { panic('no semanticTokens data in LSP output:\n${out}') }
	rest := out[idx + marker.len..]
	endi := rest.index(']') or { panic('unterminated data array in:\n${out}') }
	mut data := []int{}
	for n in rest[..endi].split(',') {
		t := n.trim_space()
		if t != '' {
			data << t.int()
		}
	}
	// Each token is 5 ints: [deltaLine, deltaStart, length, TYPE, modifiers].
	mut types := []int{}
	mut k := 3
	for k < data.len {
		types << data[k]
		k += 5
	}
	return types
}

// A `[; … ]` comment — multi-line, with a nested bracket, an atom, a binding,
// and a directive head — each of which WOULD get a code token if the tokenizer
// descended into the comment. The whole span must be comment.
fn test_block_comment_interior_is_all_comment() {
	prog := '[; header [tbl col:int]\n   :atom \$bind and ?key here ]'
	types := semantic_token_types(prog)
	assert types.len > 0, 'expected >=1 semantic token for the [; … ] comment (got none)'
	for t in types {
		assert t == tt_comment, 'a token inside [; … ] is type ${t}, not comment (${tt_comment}) — interior leaked as code: ${types}'
	}
}

// Guard against over-dimming: real code around a `[; … ]` comment must keep its
// (non-comment) tokens; only the comment dims.
fn test_code_around_block_comment_keeps_code_tokens() {
	prog := '[greet name=x]\n[; just :atom \$b ]\n[other]'
	types := semantic_token_types(prog)
	assert tt_comment in types, 'expected the [; … ] line to emit a comment token: ${types}'
	mut has_code := false
	for t in types {
		if t != tt_comment {
			has_code = true
		}
	}
	assert has_code, 'expected code tokens for the [greet]/[other] lines — over-dimmed: ${types}'
}
