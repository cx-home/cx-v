module main

import cx
import os

// Tests for the v0.7.0 ?include resolution engine (spec/include.md,
// GG1 row at v0_7_0_status.md). Covers the §1–§8 contract: splice
// semantics, path resolution, traversal reject, URL reject, cycle
// detection, depth limit, error mapping E901-E911.

fn tmp_dir(label string) string {
	dir := os.join_path(os.temp_dir(), 'cx_include_${label}_${os.getpid()}')
	os.rmdir_all(dir) or {}
	os.mkdir_all(dir) or { panic('mkdir ${dir}: ${err}') }
	return dir
}

fn write_file(dir string, name string, content string) string {
	full := os.join_path(dir, name)
	os.mkdir_all(os.dir(full)) or {}
	os.write_file(full, content) or { panic('write ${full}: ${err}') }
	return full
}

// ── Splice semantics ────────────────────────────────────────────────────

fn test_include_splices_top_level_elements() {
	root := tmp_dir('splice_basic')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'defaults.cx', '[server host=localhost]\n[server host=backup]')
	main := '[config\n  [?cx include=defaults.cx]\n  [client retries=3]\n]'
	doc := cx.parse_with_include_root(main, root) or {
		panic('parse_with_include_root: ${err}')
	}
	assert doc.elements.len == 1, 'expected 1 root, got ${doc.elements.len}'
	config := doc.elements[0] as cx.Element
	// After splice: 3 children — two servers + the trailing client.
	assert config.items.len == 3, 'expected 3 items after splice, got ${config.items.len}'
}

fn test_include_no_root_preserves_directive() {
	// Empty root → no resolution; directive remains in AST as prolog
	// node (top-level [?cx ...] parses into doc.prolog per
	// is_prolog_node_type, parser.v:544).
	root := tmp_dir('no_root')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'a.cx', '[a]')
	doc := cx.parse_with_include_root('[?cx include=a.cx]', '') or {
		panic('parse: ${err}')
	}
	assert doc.prolog.len == 1, 'expected directive in prolog, got ${doc.prolog.len}'
	first := doc.prolog[0]
	assert first is cx.CXDirectiveNode, 'expected CXDirectiveNode, got: ${first.type_name()}'
}

fn test_include_nested_resolution() {
	root := tmp_dir('nested')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'leaf.cx', '[leaf v=1]')
	write_file(root, 'mid.cx', '[mid\n  [?cx include=leaf.cx]\n]')
	doc := cx.parse_with_include_root('[?cx include=mid.cx]', root) or {
		panic('${err}')
	}
	assert doc.elements.len == 1
	mid := doc.elements[0] as cx.Element
	assert mid.name == 'mid'
	assert mid.items.len == 1
	leaf := mid.items[0] as cx.Element
	assert leaf.name == 'leaf'
}

// ── Path resolution + reject paths ──────────────────────────────────────

fn test_include_e901_absolute_path_rejected() {
	root := tmp_dir('e901')
	defer { os.rmdir_all(root) or {} }
	cx.parse_with_include_root('[?cx include=/etc/passwd]', root) or {
		assert err.msg().contains('E901'), 'expected E901, got: ${err.msg()}'
		return
	}
	assert false, 'expected E901 reject'
}

fn test_include_e902_traversal_rejected() {
	root := tmp_dir('e902')
	defer { os.rmdir_all(root) or {} }
	// Try to reach a sibling-of-root file via `../`. Resolved path
	// escapes root → E902.
	cx.parse_with_include_root('[?cx include=../sibling.cx]', root) or {
		assert err.msg().contains('E902'), 'expected E902, got: ${err.msg()}'
		return
	}
	assert false, 'expected E902 reject'
}

fn test_include_e903_url_scheme_rejected() {
	root := tmp_dir('e903')
	defer { os.rmdir_all(root) or {} }
	cases := ["[?cx include='http://evil.com/a.cx']", "[?cx include='file:///etc/passwd']"]
	for src in cases {
		cx.parse_with_include_root(src, root) or {
			assert err.msg().contains('E903'), 'expected E903 for ${src}, got: ${err.msg()}'
			continue
		}
		assert false, 'expected E903 reject for ${src}'
	}
}

fn test_include_e904_cycle_detected() {
	root := tmp_dir('e904')
	defer { os.rmdir_all(root) or {} }
	// Self-include cycle.
	write_file(root, 'loop.cx', '[?cx include=loop.cx]')
	cx.parse_with_include_root('[?cx include=loop.cx]', root) or {
		assert err.msg().contains('E904'), 'expected E904, got: ${err.msg()}'
		return
	}
	assert false, 'expected E904 cycle'
}

fn test_include_e905_max_depth_exceeded() {
	root := tmp_dir('e905')
	defer { os.rmdir_all(root) or {} }
	// Chain a-1.cx → a-2.cx → ... → a-10.cx; max depth 8 should fire.
	for i in 1 .. 10 {
		next := 'a-${i + 1}.cx'
		write_file(root, 'a-${i}.cx', '[?cx include=${next}]')
	}
	write_file(root, 'a-10.cx', '[leaf]')
	cx.parse_with_include_root('[?cx include=a-1.cx]', root) or {
		assert err.msg().contains('E905'), 'expected E905, got: ${err.msg()}'
		return
	}
	assert false, 'expected E905 depth limit'
}

fn test_include_e906_not_found() {
	root := tmp_dir('e906')
	defer { os.rmdir_all(root) or {} }
	cx.parse_with_include_root('[?cx include=nonexistent.cx]', root) or {
		assert err.msg().contains('E906'), 'expected E906, got: ${err.msg()}'
		return
	}
	assert false, 'expected E906 not-found'
}

fn test_include_e908_directory_rejected() {
	root := tmp_dir('e908')
	defer { os.rmdir_all(root) or {} }
	os.mkdir_all(os.join_path(root, 'subdir')) or {}
	cx.parse_with_include_root('[?cx include=subdir]', root) or {
		assert err.msg().contains('E908'), 'expected E908, got: ${err.msg()}'
		return
	}
	assert false, 'expected E908 directory reject'
}

fn test_include_e911_inner_parse_fail() {
	root := tmp_dir('e911')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'broken.cx', '[unterminated')
	cx.parse_with_include_root('[?cx include=broken.cx]', root) or {
		assert err.msg().contains('E911'), 'expected E911, got: ${err.msg()}'
		return
	}
	assert false, 'expected E911 inner parse fail'
}

// ── Diamond include (legal per spec §6) ─────────────────────────────────

fn test_include_diamond_legal() {
	root := tmp_dir('diamond')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'leaf.cx', '[leaf v=42]')
	write_file(root, 'b.cx', '[b [?cx include=leaf.cx]]')
	write_file(root, 'c.cx', '[c [?cx include=leaf.cx]]')
	main := '[doc\n  [?cx include=b.cx]\n  [?cx include=c.cx]\n]'
	doc := cx.parse_with_include_root(main, root) or {
		panic('diamond failed: ${err}')
	}
	root_doc := doc.elements[0] as cx.Element
	assert root_doc.items.len == 2
	b := root_doc.items[0] as cx.Element
	c := root_doc.items[1] as cx.Element
	assert b.name == 'b'
	assert c.name == 'c'
	assert b.items.len == 1
	assert c.items.len == 1
}

// ── Splice rules: discard XMLDecl / CXDirective at included top level ───

fn test_include_discards_xmldecl_at_top_level() {
	root := tmp_dir('xmldecl')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'inc.cx', "[?xml version='1.0']\n[real-element]")
	main := '[?cx include=inc.cx]'
	doc := cx.parse_with_include_root(main, root) or { panic('${err}') }
	// Only the real element is spliced; the XMLDecl is discarded.
	assert doc.elements.len == 1
	real := doc.elements[0] as cx.Element
	assert real.name == 'real-element'
}

// U7 — real-sandbox regression. Per spec/v0_7_0_status.md U7 + GG1:
// the ?include resolver MUST reject paths that escape the include
// root even when the target file exists on disk. Creates the
// sibling file explicitly so the failure-mode is "traversal
// rejected by sandbox" rather than "E906 file-not-found".

fn test_u7_real_sandbox_rejects_existing_sibling_via_traversal() {
	parent := os.join_path(os.temp_dir(), 'cx_u7_real_${os.getpid()}')
	os.rmdir_all(parent) or {}
	os.mkdir_all(parent) or { panic(err) }
	defer { os.rmdir_all(parent) or {} }
	// Create a "secret" file as a SIBLING of the include root.
	os.write_file(os.join_path(parent, 'secret.cx'), '[secret content]') or { panic(err) }
	// The include root is a subdir of parent; ../secret.cx escapes
	// the root and must be rejected as E902 even though the target
	// file exists.
	root := os.join_path(parent, 'allowed')
	os.mkdir_all(root) or { panic(err) }
	cx.parse_with_include_root('[?cx include=../secret.cx]', root) or {
		assert err.msg().contains('E902'),
			'U7 sandbox breach: expected E902 traversal-rejected, got: ${err.msg()}'
		return
	}
	assert false, 'U7 sandbox breach: ?include of ../secret.cx succeeded'
}

fn test_u7_real_sandbox_admits_in_tree_include() {
	// Companion to the negative case: a legitimate in-tree include
	// works. Confirms the sandbox isn't refusing everything.
	root := tmp_dir('u7_admits')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'allowed.cx', '[allowed flag=ok]')
	doc := cx.parse_with_include_root('[?cx include=allowed.cx]', root) or {
		panic('legitimate in-tree include should resolve: ${err}')
	}
	assert doc.elements.len == 1
	el := doc.elements[0] as cx.Element
	assert el.name == 'allowed'
}

// ── [?include] CXL directive (eval-time include) ─────────────────────
//
// Per ADR 0017 §D8: `[?include path]` is the eval-time CXL directive
// counterpart to the parse-time `[?cx include=path]` resolver. Reads
// the file under env.include_root, parses it (resolving any nested
// `[?cx include=…]` via the GG1 resolver), and evaluates the result
// inline at the directive site. Same security model: lexical
// containment, cycle detection, depth limit.

fn test_cxl_include_splices_eval_time() {
	root := tmp_dir('cxl_inc_basic')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'partial.cxl', "[mid from partial]")
	prog := "[doc [pre 'before'] [?include 'partial.cxl'] [post 'after']]"
	out := cx.eval_cxl_with_include_root('', prog, 'text', root) or {
		panic('eval failed: ${err}')
	}
	assert out.contains("[mid from partial]"), 'partial not spliced: ${out}'
	assert out.contains('[pre before]') && out.contains('[post after]'),
		'surrounding nodes lost: ${out}'
}

fn test_cxl_include_requires_root() {
	prog := "[?include 'anything.cxl']"
	cx.eval_cxl_with_include_root('', prog, 'text', '') or {
		assert err.msg().contains('CXER0014'),
			'expected CXER0014 without include_root, got: ${err.msg()}'
		return
	}
	assert false, '[?include] should error when no include_root supplied'
}

fn test_cxl_include_rejects_traversal() {
	parent := os.join_path(os.temp_dir(), 'cx_cxl_inc_traversal_${os.getpid()}')
	os.rmdir_all(parent) or {}
	os.mkdir_all(parent) or { panic(err) }
	defer { os.rmdir_all(parent) or {} }
	os.write_file(os.join_path(parent, 'secret.cxl'), '[secret value=leaked]') or { panic(err) }
	root := os.join_path(parent, 'allowed')
	os.mkdir_all(root) or { panic(err) }
	prog := "[?include '../secret.cxl']"
	cx.eval_cxl_with_include_root('', prog, 'text', root) or {
		assert err.msg().contains('E902'),
			'expected E902 traversal-rejected, got: ${err.msg()}'
		return
	}
	assert false, '[?include] traversal escape should be rejected'
}

fn test_cxl_include_detects_cycle() {
	root := tmp_dir('cxl_inc_cycle')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'a.cxl', "[?include 'b.cxl']")
	write_file(root, 'b.cxl', "[?include 'a.cxl']")
	prog := "[?include 'a.cxl']"
	cx.eval_cxl_with_include_root('', prog, 'text', root) or {
		assert err.msg().contains('E904'),
			'expected E904 cycle, got: ${err.msg()}'
		return
	}
	assert false, '[?include] cycle should be detected'
}

fn test_cxl_include_resolves_nested_cx_include() {
	// CXL [?include] reads a file and parses it via the GG1
	// parse-time resolver — so a partial can itself use [?cx include]
	// for static includes-within-includes.
	root := tmp_dir('cxl_inc_nested')
	defer { os.rmdir_all(root) or {} }
	write_file(root, 'inner.cx', "[inner 'leaf']")
	write_file(root, 'outer.cxl', "[outer-wrap [?cx include=inner.cx]]")
	prog := "[?include 'outer.cxl']"
	out := cx.eval_cxl_with_include_root('', prog, 'text', root) or {
		panic('nested include failed: ${err}')
	}
	assert out.contains("[inner leaf]"), 'inner.cx not transitively spliced: ${out}'
}
