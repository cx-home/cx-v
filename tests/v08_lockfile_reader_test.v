module main

import cx
import os

// Tests for the Phase 2.12 Part 3 cx.lock parse-only reader
// (spec/lockfile.md).
//
// Covers the minimal lockfile shape (schema version + `[modules]`
// + `[module]` entries), the optional `[transitive-graph]` /
// `[edge]` block, and the CXLOCK_PARSE / CXLOCK_UNSUPPORTED_VERSION
// error surfaces.
//
// Out of scope at Phase 2.12 Part 3:
//   - SRI verification of HTTPS-fetched bytes (Phase 2.14).
//   - HTTPS fetch + cache (Phase 2.14).
//   - Transitive-graph closure check (Phase 2.14).
//   - `:resolved` shape validation (Phase 2.14).

// ── Minimal fixture ──────────────────────────────────────────────────────────

// Note on attribute syntax: spec/lockfile.md §3 says the lockfile is a
// CX-data document parsed via the existing data grammar — no new parser
// support is required. The lockfile spec examples render attributes
// in a `:name VALUE` editorial notation, but the wire surface uses the
// canonical CX-data attribute form `name="VALUE"`. These fixtures use
// the wire form.

const minimal_lockfile_src = '[cx.lock version="1"
  [modules
    [module
      name="cx-stdlib"
      resolved="bundled:0.8.0"]]]'

fn test_lockfile_reader_minimal_parses() {
	lf := cx.parse_lockfile_text(minimal_lockfile_src) or {
		panic('expected parse success, got: ${err}')
	}
	assert lf.schema_version == '1'
	assert lf.modules.len == 1
	assert lf.modules[0].name == 'cx-stdlib'
	assert lf.modules[0].resolved == 'bundled:0.8.0'
	assert lf.modules[0].version == none
	assert lf.modules[0].integrity == none
	assert lf.transitive_graph.len == 0
}

// ── Multi-module fixture with HTTPS + SRI ────────────────────────────────────

const multi_module_lockfile_src = '[cx.lock version="1"
  [modules
    [module
      name="cx-stdlib"
      resolved="bundled:0.8.0"]
    [module
      name="cx-stdlib/strings"
      resolved="bundled:0.8.0"]
    [module
      name="github.com/example/regex-helpers"
      resolved="https://cdn.example.com/regex-helpers-1.2.3.zip"
      version="1.2.3"
      sri="sha384-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
    [module
      name="./local-helpers.cx"
      resolved="./local-helpers.cx"]]]'

fn test_lockfile_reader_multi_module_parses() {
	lf := cx.parse_lockfile_text(multi_module_lockfile_src) or {
		panic('expected parse success, got: ${err}')
	}
	assert lf.schema_version == '1'
	assert lf.modules.len == 4

	assert lf.modules[0].name == 'cx-stdlib'
	assert lf.modules[0].resolved == 'bundled:0.8.0'

	assert lf.modules[1].name == 'cx-stdlib/strings'
	assert lf.modules[1].resolved == 'bundled:0.8.0'

	assert lf.modules[2].name == 'github.com/example/regex-helpers'
	assert lf.modules[2].resolved == 'https://cdn.example.com/regex-helpers-1.2.3.zip'
	v := lf.modules[2].version or { '' }
	assert v == '1.2.3'
	sri := lf.modules[2].integrity or { '' }
	assert sri == 'sha384-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

	assert lf.modules[3].name == './local-helpers.cx'
	assert lf.modules[3].resolved == './local-helpers.cx'
}

// ── Transitive-graph fixture ─────────────────────────────────────────────────

const transitive_graph_lockfile_src = '[cx.lock version="1"
  [modules
    [module
      name="cx-stdlib/strings"
      resolved="bundled:0.8.0"]
    [module
      name="github.com/example/regex-helpers"
      resolved="https://cdn.example.com/regex-helpers-1.2.3.zip"
      sri="sha384-XYZ"]]
  [transitive-graph
    [edge from="github.com/example/regex-helpers" to="cx-stdlib/strings"]]]'

fn test_lockfile_reader_transitive_graph_parses() {
	lf := cx.parse_lockfile_text(transitive_graph_lockfile_src) or {
		panic('expected parse success, got: ${err}')
	}
	assert lf.transitive_graph.len == 1
	assert lf.transitive_graph[0].from == 'github.com/example/regex-helpers'
	assert lf.transitive_graph[0].to == 'cx-stdlib/strings'
}

// ── Filesystem entry point ────────────────────────────────────────────────────

fn test_lockfile_reader_reads_from_disk() {
	tmp := os.temp_dir()
	path := os.join_path(tmp, 'v08_lockfile_reader_disk_test.cx.lock')
	os.write_file(path, minimal_lockfile_src) or {
		panic('failed to write fixture: ${err}')
	}
	defer {
		os.rm(path) or {}
	}
	lf := cx.read_lockfile(path) or {
		panic('expected read success, got: ${err}')
	}
	assert lf.schema_version == '1'
	assert lf.modules.len == 1
	assert lf.modules[0].name == 'cx-stdlib'
}

fn test_lockfile_reader_missing_file_fails() {
	cx.read_lockfile('/nonexistent/path/to/cx.lock') or {
		assert err.msg().starts_with('CXLOCK_PARSE'), 'got: ${err}'
		return
	}
	assert false, 'expected error for nonexistent file'
}

// ── Error coverage — schema / shape ───────────────────────────────────────────

fn test_lockfile_reader_unknown_version_fails() {
	src := '[cx.lock version="99"
  [modules
    [module name="foo" resolved="bundled:0.8.0"]]]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().starts_with('CXLOCK_UNSUPPORTED_VERSION'), 'got: ${err}'
		return
	}
	assert false, 'expected CXLOCK_UNSUPPORTED_VERSION'
}

fn test_lockfile_reader_missing_version_fails() {
	src := '[cx.lock
  [modules
    [module name="foo" resolved="bundled:0.8.0"]]]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().contains('missing :version'), 'got: ${err}'
		return
	}
	assert false, 'expected missing :version error'
}

fn test_lockfile_reader_wrong_root_element_fails() {
	src := '[not.cx.lock version="1"
  [modules
    [module name="foo" resolved="bundled:0.8.0"]]]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().contains('root element must be named'), 'got: ${err}'
		return
	}
	assert false, 'expected wrong-root error'
}

fn test_lockfile_reader_module_missing_name_fails() {
	src := '[cx.lock version="1"
  [modules
    [module resolved="bundled:0.8.0"]]]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().contains('missing :name'), 'got: ${err}'
		return
	}
	assert false, 'expected missing-name error'
}

fn test_lockfile_reader_module_missing_resolved_fails() {
	src := '[cx.lock version="1"
  [modules
    [module name="foo"]]]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().contains('missing :resolved'), 'got: ${err}'
		return
	}
	assert false, 'expected missing-resolved error'
}

fn test_lockfile_reader_no_modules_block_fails() {
	src := '[cx.lock version="1"]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().contains('no [module] entries'), 'got: ${err}'
		return
	}
	assert false, 'expected no-modules error'
}

fn test_lockfile_reader_unexpected_child_of_modules_fails() {
	src := '[cx.lock version="1"
  [modules
    [notamodule name="foo" resolved="bundled:0.8.0"]]]'
	cx.parse_lockfile_text(src) or {
		assert err.msg().contains('unexpected child of [modules]'), 'got: ${err}'
		return
	}
	assert false, 'expected unexpected-child error'
}
