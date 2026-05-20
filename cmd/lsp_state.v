// Q5 v0.7.0: `cx lsp` — document state (open buffer cache).
//
// LSP servers are stateful per client: they hold the in-memory text of
// every open document so subsequent didChange / hover / completion /
// definition requests can resolve positions without re-reading disk.
// At v0.7.0 we use full-document sync (LSP TextDocumentSyncKind=1), so
// each didChange replaces the entire buffer text — no incremental
// rope / piece-table machinery yet.

module main

struct LspState {
mut:
	verbose       bool
	shutting_down bool
	docs          map[string]string  // uri → current source text
}

fn new_lsp_state(verbose bool) LspState {
	return LspState{
		verbose: verbose
		shutting_down: false
		docs: map[string]string{}
	}
}

fn (mut s LspState) open_doc(uri string, text string) {
	s.docs[uri] = text
	if s.verbose {
		eprintln('cx lsp: opened ${uri} (${text.len} bytes)')
	}
}

fn (mut s LspState) update_doc(uri string, text string) {
	s.docs[uri] = text
	if s.verbose {
		eprintln('cx lsp: updated ${uri} (${text.len} bytes)')
	}
}

fn (mut s LspState) close_doc(uri string) {
	s.docs.delete(uri)
	if s.verbose {
		eprintln('cx lsp: closed ${uri}')
	}
}

fn (s LspState) doc_source(uri string) ?string {
	if src := s.docs[uri] {
		return src
	}
	return none
}
