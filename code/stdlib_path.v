module code

import cx
import os

// stdlib_path.v — native primitives backing the `cx-stdlib/path` module
// (spec/stdlib_path.md). Path logic is mostly inexpressible in pure CX
// `[?def]` bodies (segment walking, glob matching, normalization,
// containment), so the bundle bodies bottom out in the primitives
// dispatched here. See stdlib_dispatch.v for the registration line.
//
// Every primitive is purely syntactic except `path-absolute` (reads
// cwd) and `path-canonical` (touches the filesystem to resolve
// symlinks). POSIX (`/foo/bar`) and Windows (`C:\foo`, `\\srv\share`)
// inputs are auto-detected by leading character per §2; output is
// platform-agnostic forward-slash form unless a Windows path is
// detected, in which case the original separators are preserved on
// passthrough operations.
//
// Error values are returned as `[err :code cx-err:CXERxxxx :message …]`
// element nodes (the renderer surfaces the code string, which the
// conformance harness matches against `--- out_err`).

// ── scalar / sequence / error builders ──────────────────────────────

fn path_str(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.string_type }
}

fn path_bool(b bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(b), data_type: cx.ScalarType.bool_type }
}

fn path_seq(parts []string) cx.Node {
	mut items := []cx.Node{cap: parts.len}
	for p in parts {
		items << path_str(p)
	}
	return cx.Element{ name: '__cx_seq__', items: items }
}

// path_err builds a failure outcome draft-3 `[result
// status=err code=… message=…]` (scalars → attributes).
fn path_err(err_code string, msg string) cx.Node {
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{ name: 'status', value: cx.ScalarValue('err') },
			cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
			cx.Attribute{ name: 'message', value: cx.ScalarValue(msg) },
		]
	}
}

// path_arg_str reads a string-valued scalar argument; none for any
// other node shape.
fn path_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// ── style detection (§2) ────────────────────────────────────────────

// is_windows_path detects a Windows-style path by leading drive letter
// (`C:`) or UNC prefix (`\\server\share`). Mixed separators with a
// leading `/` are POSIX.
fn is_windows_path(p string) bool {
	if p.starts_with('\\\\') {
		return true
	}
	if p.len >= 2 && p[1] == `:` {
		c := p[0]
		if (c >= `A` && c <= `Z`) || (c >= `a` && c <= `z`) {
			return true
		}
	}
	return false
}

// path_sep returns the separator a given path uses. Windows paths use
// `\`; everything else uses `/`.
fn path_sep_for(p string) string {
	return if is_windows_path(p) { '\\' } else { '/' }
}

// split_segs splits a path into (root, segments) where root is the
// leading absolute prefix ("" for relative paths) and segments are the
// non-empty path components. Both `/` and `\` are accepted as
// separators on input per §2.
fn split_segs(p string) (string, []string) {
	mut root := ''
	mut rest := p
	if is_windows_path(p) {
		if p.starts_with('\\\\') {
			// UNC: \\server\share — root is \\server\share
			body := p[2..]
			norm := body.replace('\\', '/')
			parts := norm.split('/')
			if parts.len >= 2 {
				root = '\\\\' + parts[0] + '\\' + parts[1]
				rest = parts[2..].join('/')
			} else {
				root = p
				rest = ''
			}
		} else {
			// drive: C: or C:\
			root = p[..2]
			rest = p[2..]
			if rest.starts_with('\\') || rest.starts_with('/') {
				root += '\\'
				rest = rest[1..]
			}
		}
	} else if p.starts_with('/') {
		root = '/'
		rest = p[1..]
	}
	norm := rest.replace('\\', '/')
	mut segs := []string{}
	for s in norm.split('/') {
		if s != '' {
			segs << s
		}
	}
	return root, segs
}

// join_with_root rebuilds a path string from a root + segments using
// the given separator.
fn join_with_root(root string, segs []string, sep string) string {
	body := segs.join(sep)
	if root == '' {
		return body
	}
	if root == '/' {
		return '/' + body
	}
	// drive root "C:\" or "C:" / UNC "\\srv\share"
	if root.ends_with('\\') || root.ends_with('/') {
		return root + body
	}
	if body == '' {
		return root
	}
	return root + sep + body
}

// ── component extraction (§3.1) ──────────────────────────────────────

fn path_dirname(p string) string {
	if p == '' {
		return ''
	}
	sep := path_sep_for(p)
	root, segs := split_segs(p)
	if segs.len == 0 {
		// only a root (or empty) — root is its own parent (§4.3)
		return if root == '' { '' } else { root }
	}
	if segs.len == 1 {
		return if root == '' { '' } else { trim_root_sep(root) }
	}
	return join_with_root(root, segs[..segs.len - 1], sep)
}

// trim_root_sep collapses "C:\" → "C:" and keeps "/" as "/".
fn trim_root_sep(root string) string {
	if root == '/' {
		return '/'
	}
	return root
}

fn path_basename(p string) string {
	if p == '' {
		return ''
	}
	_, segs := split_segs(p)
	if segs.len == 0 {
		return ''
	}
	return segs[segs.len - 1]
}

fn path_extension(p string) string {
	base := path_basename(p)
	dot := base.last_index('.') or { return '' }
	// a leading dot (dotfile, e.g. ".bashrc") is not an extension
	if dot == 0 {
		return ''
	}
	return base[dot..]
}

fn path_stem(p string) string {
	base := path_basename(p)
	ext := path_extension(p)
	if ext == '' {
		return base
	}
	return base[..base.len - ext.len]
}

fn path_parts(p string) []string {
	_, segs := split_segs(p)
	return segs
}

// ── composition (§3.2) ──────────────────────────────────────────────

// path_join collapses redundant separators across the supplied parts.
// Parts are joined with `/`; leading/trailing separators on individual
// parts are absorbed. An absolute first part keeps its leading root.
fn path_join(parts []string) string {
	mut nonempty := []string{}
	for p in parts {
		if p != '' {
			nonempty << p
		}
	}
	if nonempty.len == 0 {
		return ''
	}
	first := nonempty[0]
	sep := path_sep_for(first)
	mut leading := ''
	if first.starts_with('/') {
		leading = '/'
	}
	mut segs := []string{}
	for p in nonempty {
		norm := p.replace('\\', '/')
		for s in norm.split('/') {
			if s != '' {
				segs << s
			}
		}
	}
	body := segs.join(sep)
	return leading + body
}

// ── normalization (§3.3) ─────────────────────────────────────────────

// path_normalize collapses `.` and `..` segments syntactically and
// removes redundant separators. No filesystem access.
fn path_normalize(p string) string {
	if p == '' {
		return ''
	}
	sep := path_sep_for(p)
	root, segs := split_segs(p)
	is_abs := root != ''
	mut out := []string{}
	for s in segs {
		if s == '.' {
			continue
		}
		if s == '..' {
			if out.len > 0 && out[out.len - 1] != '..' {
				out.delete_last()
			} else if !is_abs {
				out << '..'
			}
			// absolute: `..` above root is dropped
			continue
		}
		out << s
	}
	if is_abs {
		return join_with_root(root, out, sep)
	}
	if out.len == 0 {
		return '.'
	}
	return out.join(sep)
}

// path_absolute prefixes cwd if the path is relative. Impure.
fn path_absolute(p string) string {
	if path_is_absolute(p) {
		return path_normalize(p)
	}
	cwd := os.getwd()
	return path_normalize(path_join([cwd, p]))
}

// path_relative computes the relative path from `from` to `to`. Pure.
fn path_relative(from string, to string) string {
	sep := path_sep_for(to)
	_, fsegs := split_segs(path_normalize(from))
	_, tsegs := split_segs(path_normalize(to))
	mut i := 0
	for i < fsegs.len && i < tsegs.len && fsegs[i] == tsegs[i] {
		i++
	}
	mut out := []string{}
	for _ in i .. fsegs.len {
		out << '..'
	}
	for j in i .. tsegs.len {
		out << tsegs[j]
	}
	if out.len == 0 {
		return '.'
	}
	return out.join(sep)
}

// path_canonical resolves symlinks + normalizes. Impure. Raises
// CXER2600 when an intermediate component is missing.
fn path_canonical(p string) cx.Node {
	abs := if path_is_absolute(p) { p } else { path_join([os.getwd(), p]) }
	if !os.exists(abs) {
		return path_err('cx-err:CXER2600', 'E_PATH_NOT_FOUND: ${p}')
	}
	real := os.real_path(abs)
	return path_str(path_normalize(real))
}

// ── predicates (§3.4) ────────────────────────────────────────────────

fn path_is_absolute(p string) bool {
	if p.starts_with('/') {
		return true
	}
	if is_windows_path(p) {
		if p.starts_with('\\\\') {
			return true
		}
		// drive path is absolute only when followed by a separator
		if p.len >= 3 && (p[2] == `\\` || p[2] == `/`) {
			return true
		}
	}
	return false
}

fn path_is_relative(p string) bool {
	return !path_is_absolute(p)
}

fn path_is_posix_style(p string) bool {
	return !is_windows_path(p)
}

fn path_is_windows_style(p string) bool {
	return is_windows_path(p)
}

fn path_has_extension(p string) bool {
	return path_extension(p) != ''
}

// ── manipulation (§3.5) ──────────────────────────────────────────────

fn path_with_extension(p string, ext string) string {
	stem_part := path_stem(p)
	dir := path_dirname(p)
	mut e := ext
	if e != '' && !e.starts_with('.') {
		e = '.' + e
	}
	name := stem_part + e
	return rejoin_dir(dir, name, p)
}

fn path_with_stem(p string, stem string) string {
	ext := path_extension(p)
	dir := path_dirname(p)
	return rejoin_dir(dir, stem + ext, p)
}

fn path_with_name(p string, name string) string {
	dir := path_dirname(p)
	return rejoin_dir(dir, name, p)
}

// rejoin_dir attaches a new basename to the dirname of the original
// path, preserving the original separator style. An empty dir (the
// path had no directory component) yields the bare name.
fn rejoin_dir(dir string, name string, original string) string {
	if dir == '' {
		return name
	}
	sep := path_sep_for(original)
	if dir == '/' {
		return '/' + name
	}
	if dir.ends_with('\\') || dir.ends_with('/') {
		return dir + name
	}
	return dir + sep + name
}

fn path_append(p string, suffix string) string {
	return path_join([p, suffix])
}

// ── globbing (§3.6) ──────────────────────────────────────────────────

// path_match_glob matches a candidate path against a glob pattern over
// `/`-split segments. `*`/`?`/`[...]` operate within a single segment;
// `**` matches zero or more whole segments. Returns an err-value
// (CXER2602) on a malformed pattern (unterminated `[`).
fn path_match_glob(pattern string, candidate string) cx.Node {
	if !glob_pattern_valid(pattern) {
		return path_err('cx-err:CXER2602', 'E_PATH_INVALID_PATTERN: ${pattern}')
	}
	_, psegs := split_segs(pattern.replace('\\', '/'))
	_, csegs := split_segs(candidate.replace('\\', '/'))
	return path_bool(match_segs(psegs, 0, csegs, 0))
}

// glob_pattern_valid rejects patterns with an unterminated `[` class.
fn glob_pattern_valid(pattern string) bool {
	mut i := 0
	for i < pattern.len {
		if pattern[i] == `[` {
			mut j := i + 1
			mut closed := false
			for j < pattern.len {
				if pattern[j] == `]` {
					closed = true
					break
				}
				j++
			}
			if !closed {
				return false
			}
			i = j + 1
			continue
		}
		i++
	}
	return true
}

// match_segs matches pattern segments against candidate segments with
// `**` as a multi-segment (zero-or-more) wildcard.
fn match_segs(pat []string, pi int, cand []string, ci int) bool {
	if pi == pat.len {
		return ci == cand.len
	}
	if pat[pi] == '**' {
		// `**` matches zero or more whole segments
		mut k := ci
		for {
			if match_segs(pat, pi + 1, cand, k) {
				return true
			}
			if k >= cand.len {
				break
			}
			k++
		}
		return false
	}
	if ci >= cand.len {
		return false
	}
	if !match_one_seg(pat[pi], cand[ci]) {
		return false
	}
	return match_segs(pat, pi + 1, cand, ci + 1)
}

// match_one_seg matches a single segment against a single-segment glob
// (supporting `*`, `?`, `[...]`).
fn match_one_seg(pat string, s string) bool {
	return match_glob_chars(pat, 0, s, 0)
}

fn match_glob_chars(pat string, pi int, s string, si int) bool {
	if pi == pat.len {
		return si == s.len
	}
	c := pat[pi]
	match c {
		`*` {
			// zero or more chars within the segment
			mut k := si
			for {
				if match_glob_chars(pat, pi + 1, s, k) {
					return true
				}
				if k >= s.len {
					break
				}
				k++
			}
			return false
		}
		`?` {
			if si >= s.len {
				return false
			}
			return match_glob_chars(pat, pi + 1, s, si + 1)
		}
		`[` {
			close := index_of_byte(pat, `]`, pi + 1)
			if close < 0 {
				return false
			}
			class := pat[pi + 1..close]
			if si >= s.len {
				return false
			}
			if char_in_class(class, s[si]) {
				return match_glob_chars(pat, close + 1, s, si + 1)
			}
			return false
		}
		else {
			if si >= s.len || pat[pi] != s[si] {
				return false
			}
			return match_glob_chars(pat, pi + 1, s, si + 1)
		}
	}
}

fn index_of_byte(s string, b u8, from int) int {
	mut i := from
	for i < s.len {
		if s[i] == b {
			return i
		}
		i++
	}
	return -1
}

// char_in_class tests a byte against a `[...]` class body, supporting
// ranges (`a-z`).
fn char_in_class(class string, ch u8) bool {
	mut i := 0
	for i < class.len {
		if i + 2 < class.len && class[i + 1] == `-` {
			if ch >= class[i] && ch <= class[i + 2] {
				return true
			}
			i += 3
			continue
		}
		if class[i] == ch {
			return true
		}
		i++
	}
	return false
}

// ── cross-platform separators (§3.7) ─────────────────────────────────

fn path_separator() string {
	return if os.user_os() == 'windows' { '\\' } else { '/' }
}

fn path_list_separator() string {
	return if os.user_os() == 'windows' { ';' } else { ':' }
}

// ── path-safety (§3.8) ───────────────────────────────────────────────

// path_is_within decides containment after normalization. A directory
// is within itself.
fn path_is_within(dir string, candidate string) bool {
	ndir := path_normalize(dir)
	ncand := path_normalize(candidate)
	if ncand == ndir {
		return true
	}
	// candidate must be ndir + a separator + more
	prefix := if ndir.ends_with('/') { ndir } else { ndir + '/' }
	return ncand.starts_with(prefix)
}

// path_safe_join joins base + untrusted, normalizes, and raises
// CXER2603 if the result escapes base. Empty untrusted yields base.
fn path_safe_join(base string, untrusted string) cx.Node {
	joined := path_join([base, untrusted])
	norm := path_normalize(joined)
	nbase := path_normalize(base)
	if norm == nbase {
		return path_str(norm)
	}
	prefix := if nbase.ends_with('/') { nbase } else { nbase + '/' }
	if !norm.starts_with(prefix) {
		return path_err('cx-err:CXER2603', 'E_PATH_ESCAPES_BASE: ${untrusted}')
	}
	return path_str(norm)
}

// path_equals_case_insensitive compares two paths ignoring case (§4.5).
fn path_equals_ci(a string, b string) bool {
	return a.to_lower() == b.to_lower()
}

// ── dispatch table ───────────────────────────────────────────────────

fn path_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'path-dirname' {
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_dirname(p))
		}
		'path-basename' {
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_basename(p))
		}
		'path-extension' {
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_extension(p))
		}
		'path-stem' {
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_stem(p))
		}
		'path-parent' {
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_dirname(p))
		}
		'path-parts' {
			p := path_arg_str(args[0]) or { return none }
			return path_seq(path_parts(p))
		}
		'path-join' {
			// The bundle declares `join` variadic (`:rest parts`), so the
			// evaluator collects the call args into a single `__cx_seq__`
			// envelope bound to `parts`. Accept that envelope (expand it),
			// a bare sequence arg, or raw positional string args.
			mut parts := []string{}
			for a in args {
				if a is cx.Element {
					el := a as cx.Element
					if el.name == '__cx_seq__' {
						for it in el.items {
							parts << path_arg_str(it) or { return none }
						}
						continue
					}
				}
				parts << path_arg_str(a) or { return none }
			}
			return path_str(path_join(parts))
		}
		'path-join-seq' {
			if args[0] is cx.Element {
				el := args[0] as cx.Element
				mut parts := []string{cap: el.items.len}
				for it in el.items {
					parts << path_arg_str(it) or { return none }
				}
				return path_str(path_join(parts))
			}
			return none
		}
		'path-normalize' {
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_normalize(p))
		}
		'path-absolute' {
			// §6.5.1 / security.md §4: resolves against the real cwd → gated
			// under `read` (deny-by-default; SAP C2 / D010). Fail-closed
			// BEFORE the effect.
			if d := cap_guard('read', name) {
				return d
			}
			p := path_arg_str(args[0]) or { return none }
			return path_str(path_absolute(p))
		}
		'path-relative' {
			from := path_arg_str(args[0]) or { return none }
			to := path_arg_str(args[1]) or { return none }
			return path_str(path_relative(from, to))
		}
		'path-canonical' {
			// §6.5.1 / security.md §4: touches the filesystem to resolve
			// symlinks → gated under `read` (deny-by-default; SAP C2 / D010).
			// Fail-closed BEFORE the effect.
			if d := cap_guard('read', name) {
				return d
			}
			p := path_arg_str(args[0]) or { return none }
			return path_canonical(p)
		}
		'path-is-absolute' {
			p := path_arg_str(args[0]) or { return none }
			return path_bool(path_is_absolute(p))
		}
		'path-is-relative' {
			p := path_arg_str(args[0]) or { return none }
			return path_bool(path_is_relative(p))
		}
		'path-is-posix-style' {
			p := path_arg_str(args[0]) or { return none }
			return path_bool(path_is_posix_style(p))
		}
		'path-is-windows-style' {
			p := path_arg_str(args[0]) or { return none }
			return path_bool(path_is_windows_style(p))
		}
		'path-has-extension' {
			p := path_arg_str(args[0]) or { return none }
			return path_bool(path_has_extension(p))
		}
		'path-with-extension' {
			p := path_arg_str(args[0]) or { return none }
			ext := path_arg_str(args[1]) or { return none }
			return path_str(path_with_extension(p, ext))
		}
		'path-with-stem' {
			p := path_arg_str(args[0]) or { return none }
			stem := path_arg_str(args[1]) or { return none }
			return path_str(path_with_stem(p, stem))
		}
		'path-with-name' {
			p := path_arg_str(args[0]) or { return none }
			nm := path_arg_str(args[1]) or { return none }
			return path_str(path_with_name(p, nm))
		}
		'path-append' {
			p := path_arg_str(args[0]) or { return none }
			suffix := path_arg_str(args[1]) or { return none }
			return path_str(path_append(p, suffix))
		}
		'path-match-glob' {
			pattern := path_arg_str(args[0]) or { return none }
			p := path_arg_str(args[1]) or { return none }
			return path_match_glob(pattern, p)
		}
		'path-separator' {
			return path_str(path_separator())
		}
		'path-list-separator' {
			return path_str(path_list_separator())
		}
		'path-is-within' {
			dir := path_arg_str(args[0]) or { return none }
			cand := path_arg_str(args[1]) or { return none }
			return path_bool(path_is_within(dir, cand))
		}
		'path-safe-join' {
			base := path_arg_str(args[0]) or { return none }
			untrusted := path_arg_str(args[1]) or { return none }
			return path_safe_join(base, untrusted)
		}
		'path-equals-ci' {
			a := path_arg_str(args[0]) or { return none }
			b := path_arg_str(args[1]) or { return none }
			return path_bool(path_equals_ci(a, b))
		}
		else {
			return none
		}
	}
}
