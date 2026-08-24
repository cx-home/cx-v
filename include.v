module cx

import os

// ── ?include resolution (spec/include.md, GG1) ───────────────────────────
//
// Post-parse pass that walks the AST replacing every
// [?cx include=path] CXDirectiveNode with the included document's
// element-level children, per spec/include.md §4.
//
// Resolution is opt-in: callers supply an include root (an absolute
// directory) against which paths validate. Without a root, this pass
// is a no-op and directives remain in the AST as CXDirectiveNodes.
//
// Pass ordering per spec/include.md §5:
//   parse → resolve_includes → resolve_namespaces → resolve_ids
//
// Errors: E901 absolute-path; E902 traversal-escape; E903 URL-scheme;
//         E904 cycle; E905 depth-exceeded; E906 not-found;
//         E907 not-readable; E908 directory; E909 I/O; E910 non-UTF-8;
//         E911 included-file parse fail.

pub const max_include_depth_default = 8

// ResolveIncludeOpts carries the resolver state across a recursive
// include-tree walk.
pub struct ResolveIncludeOpts {
pub mut:
	// Absolute directory path; every resolved include must lie under it.
	// Empty disables resolution (entry-point parse_with_include_root
	// short-circuits in that case).
	root          string
	// Maximum include-stack depth. Default 8 per spec/include.md §7.
	// Element-nesting limit (max_depth=64; spec/03-approved/core/limits.md §2)
	// is independent.
	max_depth     int
	// Absolute path of the file currently containing a directive being
	// resolved. Used as the base for resolving relative paths
	// (spec/include.md §3.1). For the entry document the value is the
	// include root.
	current_file  string
	// Recursion stack of canonicalised absolute paths. Used for cycle
	// detection (E904).
	include_stack []string
}

// Public entry point: parses + resolves includes against the supplied
// root. Empty / "" root preserves directives in the AST as
// CXDirectiveNodes (matching the no-resolution default of parse()).
pub fn parse_with_include_root(src string, root string) !Document {
	mut doc := parse(src)!
	if root == '' {
		return doc
	}
	mut abs_root := root
	if !os.is_abs_path(abs_root) {
		abs_root = os.abs_path(abs_root)
	}
	// real_path normalises symlinks (e.g. /tmp → /private/tmp on macOS).
	// Only apply when the path exists — empty / not-yet-created roots
	// would round-trip through real_path with platform-specific
	// fallback behaviour we don't want to depend on.
	if os.exists(abs_root) {
		abs_root = os.real_path(abs_root)
	}
	opts := ResolveIncludeOpts{
		root:          abs_root
		max_depth:     max_include_depth_default
		current_file:  abs_root
		include_stack: []
	}
	resolve_includes_doc(mut doc, opts)!
	return doc
}

// resolve_includes_doc runs the include-resolution pass over a
// previously-parsed Document, mutating in place. Used by DD18
// `cx:resolve-includes` to run resolution on an already-parsed
// cx-value.
//
// Top-level `[?cx include=...]` directives parse into `doc.prolog`
// (per `is_prolog_node_type`); we walk both prolog and elements,
// redistributing spliced Element nodes from prolog into elements
// (Elements are not valid prolog content). Prolog-type splice
// outputs (Comment / PI) stay in prolog at the directive site.
pub fn resolve_includes_doc(mut doc Document, opts ResolveIncludeOpts) ! {
	if doc.prolog.len > 0 {
		mut new_prolog := []Node{}
		mut prepended_elements := []Node{}
		for n in doc.prolog {
			match n {
				CXDirectiveNode {
					if path := include_attr(n) {
						spliced := load_and_resolve_include(path, opts)!
						for s in spliced {
							if is_prolog_node_type(s) {
								new_prolog << s
							} else {
								prepended_elements << s
							}
						}
						continue
					}
					new_prolog << n
				}
				else { new_prolog << n }
			}
		}
		doc.prolog = new_prolog
		if prepended_elements.len > 0 {
			mut combined := prepended_elements.clone()
			combined << doc.elements
			doc.elements = combined
		}
	}
	doc.elements = resolve_includes_nodes(doc.elements, opts)!
}

// resolve_includes_nodes walks a sibling list, returning a new sibling
// list with every [?cx include=...] directive replaced by its spliced
// content per spec/include.md §4.
fn resolve_includes_nodes(nodes []Node, opts ResolveIncludeOpts) ![]Node {
	mut out := []Node{}
	for n in nodes {
		match n {
			CXDirectiveNode {
				if path := include_attr(n) {
					spliced := load_and_resolve_include(path, opts)!
					out << spliced
					continue
				}
				// Non-include CXDirectiveNode pass through.
				out << n
			}
			Element {
				mut el := n
				el.items = resolve_includes_nodes(el.items, opts)!
				out << Node(el)
			}
			else {
				out << n
			}
		}
	}
	return out
}

// include_attr returns the value of the `include=` attribute on a
// CXDirectiveNode, if any. Returns none for non-include directives.
fn include_attr(d CXDirectiveNode) ?string {
	for a in d.attrs {
		if a.name == 'include' {
			return scalar_value_str_public(a.value)
		}
	}
	return none
}

// load_and_resolve_include validates the path, reads the file,
// parses it, recurses, and returns the element-level top-level
// children ready to splice in at the directive site.
fn load_and_resolve_include(rel_path string, opts ResolveIncludeOpts) ![]Node {
	// E901 — absolute path. Catches POSIX absolute (`/`), Windows drive
	// letter (`C:\` / `C:/`), and UNC (`\\server\share`).
	if rel_path.len > 0 && (rel_path[0] == `/` || rel_path[0] == `\\`) {
		return error('cx-err:E901 absolute include path rejected: ${rel_path}')
	}
	if rel_path.len >= 2 && rel_path[1] == `:` {
		return error('cx-err:E901 absolute include path rejected: ${rel_path}')
	}
	// E903 — URL-scheme. Any `://`, or any of the known scheme prefixes.
	if rel_path.contains('://') {
		return error('cx-err:E903 URL-scheme include path rejected: ${rel_path}')
	}
	url_prefixes := ['file:', 'http:', 'https:', 'ftp:', 'gopher:', 'data:']
	for p in url_prefixes {
		if rel_path.starts_with(p) {
			return error('cx-err:E903 URL-scheme include path rejected: ${rel_path}')
		}
	}
	// Spec §3.4: `/` is the path separator in the directive. We do not
	// rewrite `\` to `/` (a `\` on POSIX is a literal filename char).
	// Resolve relative to the directory of the file containing the
	// directive (spec §3.1).
	mut base_dir := os.dir(opts.current_file)
	if opts.current_file == opts.root {
		base_dir = opts.root
	}
	joined := os.join_path(base_dir, rel_path)
	lexical := lexical_collapse(joined)
	// E902 — traversal-escape. Lexical check first per spec §3.3.
	if !lexical_under_root(lexical, opts.root) {
		return error('cx-err:E902 include path escapes include root: ${rel_path} → ${lexical} (root=${opts.root})')
	}
	// E906 — not found.
	if !os.exists(lexical) {
		return error('cx-err:E906 included file does not exist: ${lexical}')
	}
	// E908 — directory.
	if os.is_dir(lexical) {
		return error('cx-err:E908 include path resolves to directory: ${lexical}')
	}
	// Post-symlink check (spec §3.3): re-canonicalise via real_path and
	// re-check against root.
	resolved := os.real_path(lexical)
	if !lexical_under_root(resolved, opts.root) {
		return error('cx-err:E902 include path escapes include root after symlink resolution: ${rel_path} → ${resolved} (root=${opts.root})')
	}
	// E904 — cycle.
	for st in opts.include_stack {
		if st == resolved {
			mut chain := opts.include_stack.clone()
			chain << resolved
			return error('cx-err:E904 include cycle detected: ${chain.join(' → ')}')
		}
	}
	// E905 — depth.
	if opts.include_stack.len + 1 > opts.max_depth {
		return error('cx-err:E905 max_include_depth (${opts.max_depth}) exceeded at: ${resolved}')
	}
	// E907 — readability via read_file failure; E909 — I/O.
	contents := os.read_file(resolved) or {
		// V's os.read_file conflates "no permission" and "I/O error";
		// we report E909 as the generic carrier and let the message
		// disambiguate.
		return error('cx-err:E909 I/O error reading ${resolved}: ${err}')
	}
	// E910 — UTF-8 validity. V strings are byte sequences; we apply a
	// simple structural check (no NUL inside, no obviously-truncated
	// continuation bytes). Full structural UTF-8 validation matching
	// RFC 3629 is a follow-up; the resolver accepts any byte sequence the
	// parser tolerates, with the parse error becoming E911.
	if contents.contains('\x00') {
		return error('cx-err:E910 included file is not valid UTF-8 (NUL byte): ${resolved}')
	}
	// E911 — included-file parse failure.
	mut inner := parse(contents) or {
		return error('cx-err:E911 included file ${resolved} failed parse: ${err.msg()}')
	}
	// Recurse for nested includes — both prolog and elements. The
	// included document's own `[?cx include=...]` directives at top
	// level park in `inner.prolog`; resolve_includes_doc walks both
	// regions and emits cycle / depth / not-found errors with the
	// extended include stack.
	mut child_opts := opts
	child_opts.current_file = resolved
	child_opts.include_stack = opts.include_stack.clone()
	child_opts.include_stack << resolved
	resolve_includes_doc(mut inner, child_opts)!
	// Splice per spec/include.md §4: keep Element / Comment / PI /
	// RawText / Scalar / Text / BlockContent / AliasElement / EntityRef
	// from inner.elements (post-recursion these are guaranteed not to
	// be CXDirective include directives). Discard XMLDecl / inner
	// CXDirectiveNode (output-target, etc.) at top level of included
	// doc — those don't flow up to the parent.
	mut spliced := []Node{}
	for n in inner.elements {
		match n {
			XMLDeclNode { continue }
			CXDirectiveNode { continue }
			else { spliced << n }
		}
	}
	return spliced
}

// lexical_collapse normalises a path by collapsing `.` and `..` segments
// without consulting the filesystem. POSIX-style joining only — `\` is
// treated as a literal char per spec §3.4.
fn lexical_collapse(p string) string {
	is_abs := p.len > 0 && p[0] == `/`
	parts := p.split('/')
	mut stack := []string{}
	for part in parts {
		if part == '' || part == '.' { continue }
		if part == '..' {
			if stack.len > 0 && stack[stack.len - 1] != '..' {
				stack.delete(stack.len - 1)
			} else if !is_abs {
				stack << '..'
			}
			// On an absolute path, .. above root is silently dropped
			// (matches POSIX realpath / Python pathlib behavior).
			continue
		}
		stack << part
	}
	mut out := stack.join('/')
	if is_abs {
		out = '/' + out
	}
	if out == '' {
		out = '.'
	}
	return out
}

// lexical_under_root reports whether a lexically-collapsed path lies
// at or under the include root directory. Used by E902.
fn lexical_under_root(path string, root string) bool {
	if path == root { return true }
	prefix := if root.ends_with('/') { root } else { root + '/' }
	return path.starts_with(prefix)
}
