module code

import cx

// stdlib_re.v — native primitives backing the `cx-stdlib/re` module
// (spec/std-lib/re.md). Regex matching is RE2-backed (spec §1) via the
// libcx RE2 shim (vcx/cx/regex_re2.v + vcx/deps/re2_shim/); it is not
// expressible as a pure CX `[?def]` body, so the bundle bodies forward to
// the `re-*` primitives dispatched here (see stdlib_dispatch.v).
//
// ── value model ──────────────────────────────────────────────────────
//   compiled pattern → [regex pattern=$str ci=.. ml=.. ds=.. uni=.. lit=..
//                       mmb=..] (an opaque element, spec §3; carries the
//                       source pattern + effective flags so every op
//                       recompiles — spec §3 mandates no compile cache).
//   match            → [match start=$int end=$int <pattern+flag attrs>
//                       [g start=$int end=$int]...] (group 0 first; an
//                       unset group has start=-1). The subject string is
//                       carried as the `subject` attr so group-i text is
//                       a span slice. find returns this; no-match returns
//                       the [no-match] sentinel (spec §4.2).
//   sequence         → [__cx_seq__ ...] (renders `(a, b, c)`).
//   map              → [__cx_map__ [key value]...] (renders `{k: v}`).
//
// Errors are VALUE nodes (mk_err, eval.v): the spec §6 codes
// CXER3200..CXER3203. The conformance runner matches the bare code in
// `out-err`.

// ── flag / arg helpers ───────────────────────────────────────────────

fn re_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn re_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn re_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn re_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn re_no_match() cx.Node {
	return cx.Element{
		name: 'no-match'
	}
}

// re_items extracts the materialized item list of any sequence-shaped
// node: a __cx_seq__ / __cx_arr__ element, or an (eager) IteratorNode
// whose memo carries the items (core [$map] returns the latter).
fn re_items(n cx.Node) []cx.Node {
	match n {
		cx.Element {
			if n.name == '__cx_seq__' || n.name == '__cx_arr__' {
				return n.items
			}
		}
		cx.IteratorNode {
			return n.memo
		}
		else {}
	}
	return []cx.Node{}
}

fn re_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('re', 're-', 'string', n)
	return none
}

fn re_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return v }
			f64 { return i64(v) }
			else {}
		}
	}
	note_operand_fault('re', 're-', 'int', n)
	return none
}

// re_scalar_bool reads a bool/int/string flag value from a map entry.
fn re_scalar_bool(n cx.Node) bool {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			bool { return v }
			string { return v == 'true' }
			i64 { return v != 0 }
			else {}
		}
	}
	return false
}

// re_read_flags parses a `__cx_map__` flags argument into Re2Flags,
// applying the spec §4.1 defaults (unicode=true, the rest false; mmb=0).
fn re_read_flags(n cx.Node) cx.Re2Flags {
	mut f := cx.Re2Flags{
		unicode: true
	}
	if n is cx.Element && n.name == '__cx_map__' {
		for entry in n.items {
			if entry is cx.Element && entry.items.len > 0 {
				val := entry.items[0]
				match entry.name {
					'case-insensitive' { f.case_insensitive = re_scalar_bool(val) }
					'multiline' { f.multiline = re_scalar_bool(val) }
					'dotall' { f.dotall = re_scalar_bool(val) }
					'unicode' { f.unicode = re_scalar_bool(val) }
					'literal' { f.literal = re_scalar_bool(val) }
					'max-match-bytes' {
						if mb := re_arg_int(val) {
							f.max_match_bytes = mb
						}
					}
					else {}
				}
			}
		}
	}
	return f
}

// ── compiled-pattern element <-> (pattern, flags) ─────────────────────

fn re_bool_attr(name string, b bool) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(b)
	}
}

fn re_compiled_element(pattern string, f cx.Re2Flags) cx.Node {
	return cx.Element{
		name:  'regex'
		attrs: [
			cx.Attribute{
				name:  'pattern'
				value: cx.ScalarValue(pattern)
			},
			re_bool_attr('ci', f.case_insensitive),
			re_bool_attr('ml', f.multiline),
			re_bool_attr('ds', f.dotall),
			re_bool_attr('uni', f.unicode),
			re_bool_attr('lit', f.literal),
			cx.Attribute{
				name:  'mmb'
				value: cx.ScalarValue(f.max_match_bytes)
			},
		]
	}
}

fn re_attr_bool(el cx.Element, name string) bool {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value) == 'true'
		}
	}
	return false
}

fn re_attr_str(el cx.Element, name string) string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

fn re_attr_int(el cx.Element, name string) i64 {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value).i64()
		}
	}
	return 0
}

// re_unpack_compiled reads (pattern, flags) off a [regex …] element.
fn re_unpack_compiled(n cx.Node) ?(string, cx.Re2Flags) {
	if n is cx.Element && n.name == 'regex' {
		f := cx.Re2Flags{
			case_insensitive: re_attr_bool(n, 'ci')
			multiline:        re_attr_bool(n, 'ml')
			dotall:           re_attr_bool(n, 'ds')
			unicode:          re_attr_bool(n, 'uni')
			literal:          re_attr_bool(n, 'lit')
			max_match_bytes:  re_attr_int(n, 'mmb')
		}
		return re_attr_str(n, 'pattern'), f
	}
	return none
}

// ── compile-time error mapping ────────────────────────────────────────
//
// re2_compile_checked surfaces an err whose message starts CXER3200
// (unsupported PCRE feature) or CXER3201 (syntax error). Map onto the
// spec §6 value nodes.
fn re_compile_err(msg string) cx.Node {
	if msg.starts_with('CXER3200') {
		return mk_err('cx-err:CXER3200', 'E_RE_FEATURE_UNSUPPORTED: ${msg}')
	}
	return mk_err('cx-err:CXER3201', 'E_RE_PATTERN_INVALID: ${msg}')
}

// ── match element <-> spans ───────────────────────────────────────────

fn re_match_element(pattern string, f cx.Re2Flags, subject string, spans []cx.Re2Span) cx.Node {
	mut group_children := []cx.Node{cap: spans.len}
	for sp in spans {
		group_children << cx.Element{
			name:  'g'
			attrs: [
				cx.Attribute{
					name:  'start'
					value: cx.ScalarValue(sp.start)
				},
				cx.Attribute{
					name:  'end'
					value: cx.ScalarValue(sp.end)
				},
			]
		}
	}
	full := spans[0]
	return cx.Element{
		name:  'match'
		attrs: [
			cx.Attribute{
				name:  'start'
				value: cx.ScalarValue(full.start)
			},
			cx.Attribute{
				name:  'end'
				value: cx.ScalarValue(full.end)
			},
			cx.Attribute{
				name:  'subject'
				value: cx.ScalarValue(subject)
			},
			cx.Attribute{
				name:  'pattern'
				value: cx.ScalarValue(pattern)
			},
			re_bool_attr('ci', f.case_insensitive),
			re_bool_attr('ml', f.multiline),
			re_bool_attr('ds', f.dotall),
			re_bool_attr('uni', f.unicode),
			re_bool_attr('lit', f.literal),
		]
		items: [cx.Node(cx.Element{
			name:  'groups'
			items: group_children
		})]
	}
}

// re_match_flags reads the flags carried on a [match …] element.
fn re_match_flags(el cx.Element) cx.Re2Flags {
	return cx.Re2Flags{
		case_insensitive: re_attr_bool(el, 'ci')
		multiline:        re_attr_bool(el, 'ml')
		dotall:           re_attr_bool(el, 'ds')
		unicode:          re_attr_bool(el, 'uni')
		literal:          re_attr_bool(el, 'lit')
	}
}

// re_match_spans returns the per-group [start,end) spans of a [match …]
// element (index 0 = full match).
fn re_match_spans(el cx.Element) []cx.Re2Span {
	mut spans := []cx.Re2Span{}
	for it in el.items {
		if it is cx.Element && it.name == 'groups' {
			for g in it.items {
				if g is cx.Element && g.name == 'g' {
					spans << cx.Re2Span{
						start: re_attr_int(g, 'start')
						end:   re_attr_int(g, 'end')
					}
				}
			}
		}
	}
	return spans
}

// re_group_text returns the subject slice for group `i`, or none when the
// index is out of range or the group is unset.
fn re_group_text(el cx.Element, i int) ?string {
	spans := re_match_spans(el)
	if i < 0 || i >= spans.len {
		return none
	}
	sp := spans[i]
	if sp.start < 0 || sp.end < 0 {
		return none
	}
	subject := re_attr_str(el, 'subject')
	if sp.start > subject.len || sp.end > subject.len {
		return none
	}
	return subject[int(sp.start)..int(sp.end)]
}

// ── find-all iteration (zero-width codepoint advance, spec §4.2/§5) ─────
//
// Returns the list of per-match span sets. `from` is the starting byte
// offset (find-from). On a max-match-bytes overrun, returns an err node
// via the (ok=false, err) channel.
fn re_collect_matches(pattern string, f cx.Re2Flags, subject string, from int) ([]([]cx.Re2Span), ?cx.Node) {
	mut out := [][]cx.Re2Span{}
	mut pos := from
	if pos < 0 {
		pos = 0
	}
	for pos <= subject.len {
		spans := cx.re2_match_at(pattern, f, subject, pos) or {
			return out, re_compile_err(err.msg())
		}
		if spans.len == 0 {
			break
		}
		full := spans[0]
		if f.max_match_bytes > 0 && (full.end - full.start) > f.max_match_bytes {
			return out, mk_err('cx-err:CXER3203',
				'E_RE_MATCH_BYTES_EXCEEDED: match of ${full.end - full.start} bytes exceeds budget ${f.max_match_bytes}')
		}
		out << spans
		if full.end == full.start {
			// Zero-width match — advance one codepoint to guarantee
			// forward progress (spec §4.2 / §5).
			pos = int(full.start) + cx.re2_utf8_advance(subject, int(full.start))
		} else {
			pos = int(full.end)
		}
	}
	return out, none
}

// ── replace template substitution (spec §4.4 token table) ─────────────
//
// $0 = full match; $1.. = numbered group; ${name} = named group; $$ =
// literal $. The Perl/JS $& alias is NOT supported (spec §4.4) — a bare
// `$&` is emitted verbatim ($ then &).
fn re_apply_template(template string, el cx.Element, named map[string]int) string {
	mut out := []u8{cap: template.len}
	mut i := 0
	for i < template.len {
		c := template[i]
		if c != `$` {
			out << c
			i++
			continue
		}
		// c == '$'
		if i + 1 >= template.len {
			out << c
			i++
			continue
		}
		nxt := template[i + 1]
		if nxt == `$` {
			out << `$`
			i += 2
			continue
		}
		if nxt == `{` {
			// ${name}
			mut j := i + 2
			for j < template.len && template[j] != `}` {
				j++
			}
			if j < template.len {
				name := template[i + 2..j]
				if idx := named[name] {
					if t := re_group_text(el, idx) {
						out << t.bytes()
					}
				}
				i = j + 1
				continue
			}
			// no closing brace — emit literally
			out << c
			i++
			continue
		}
		if nxt >= `0` && nxt <= `9` {
			// $N — greedily consume digits (spec uses $1.., $0)
			mut j := i + 1
			for j < template.len && template[j] >= `0` && template[j] <= `9` {
				j++
			}
			num := template[i + 1..j].int()
			if t := re_group_text(el, num) {
				out << t.bytes()
			}
			i = j
			continue
		}
		// $ followed by anything else ($& etc.) — emit the $ verbatim.
		out << c
		i++
	}
	return out.bytestr()
}

// re_named_map recompiles the pattern to recover the name→index mapping.
fn re_named_map(pattern string, f cx.Re2Flags) map[string]int {
	mut m := map[string]int{}
	names := cx.re2_group_names(pattern, f) or { return m }
	for name in names {
		idx := cx.re2_named_index(pattern, f, name) or { continue }
		m[name] = idx
	}
	return m
}

// ── dispatch ───────────────────────────────────────────────────────────

fn re_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// ── §4.1 compilation ────────────────────────────────────────
		're-compile' {
			pattern := re_arg_str(args[0]) or { return none }
			f := cx.Re2Flags{
				unicode: true
			}
			cx.re2_validate(pattern, f) or { return re_compile_err(err.msg()) }
			return re_compiled_element(pattern, f)
		}
		're-compile-with-flags' {
			pattern := re_arg_str(args[0]) or { return none }
			f := re_read_flags(args[1])
			cx.re2_validate(pattern, f) or { return re_compile_err(err.msg()) }
			return re_compiled_element(pattern, f)
		}

		// ── §4.2 matching ───────────────────────────────────────────
		're-matches' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			r := cx.re2_full_match_flags(pattern, f, s) or { return re_compile_err(err.msg()) }
			return re_bool(r)
		}
		're-find' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			return re_find_impl(pattern, f, s, 0)
		}
		're-find-from' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			from := re_arg_int(args[2]) or { return none }
			return re_find_impl(pattern, f, s, int(from))
		}
		're-find-all', 're-find-iter' {
			// find-iter yields lazily; mem-bounded conformance materializes
			// to the same span set, so both share the eager collector.
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			matches, errn := re_collect_matches(pattern, f, s, 0)
			if e := errn {
				return e
			}
			mut items := []cx.Node{cap: matches.len}
			for spans in matches {
				items << re_match_element(pattern, f, s, spans)
			}
			return re_seq(items)
		}

		// ── §4.3 groups ─────────────────────────────────────────────
		're-group' {
			el := re_match_arg(args[0]) or { return none }
			i := re_arg_int(args[1]) or { return none }
			t := re_group_text(el, int(i)) or {
				return mk_err('cx-err:CXER3202', 'E_RE_GROUP_NOT_FOUND: group ${i}')
			}
			return re_str(t)
		}
		're-group-named' {
			el := re_match_arg(args[0]) or { return none }
			gname := re_arg_str(args[1]) or { return none }
			f := re_match_flags(el)
			pattern := re_attr_str(el, 'pattern')
			named := re_named_map(pattern, f)
			idx := named[gname] or {
				return mk_err('cx-err:CXER3202', 'E_RE_GROUP_NOT_FOUND: name "${gname}"')
			}
			t := re_group_text(el, idx) or {
				return mk_err('cx-err:CXER3202', 'E_RE_GROUP_NOT_FOUND: name "${gname}"')
			}
			return re_str(t)
		}
		're-groups-all' {
			el := re_match_arg(args[0]) or { return none }
			spans := re_match_spans(el)
			mut items := []cx.Node{cap: spans.len}
			for i in 0 .. spans.len {
				if t := re_group_text(el, i) {
					items << re_str(t)
				} else {
					items << re_str('')
				}
			}
			return re_seq(items)
		}
		're-groups-map' {
			el := re_match_arg(args[0]) or { return none }
			f := re_match_flags(el)
			pattern := re_attr_str(el, 'pattern')
			named := re_named_map(pattern, f)
			mut keys := named.keys()
			keys.sort_with_compare(fn [named] (a &string, b &string) int {
				return named[*a] - named[*b]
			})
			mut entries := []cx.Node{}
			for k in keys {
				idx := named[k]
				val := re_group_text(el, idx) or { '' }
				entries << cx.Element{
					name:  k
					items: [re_str(val)]
				}
			}
			return cx.Element{
				name:  '__cx_map__'
				items: entries
			}
		}

		// ── §4.4 replace ────────────────────────────────────────────
		're-replace' {
			return re_replace_impl(args, false)
		}
		're-replace-first' {
			return re_replace_impl(args, true)
		}
		// replace-fn is composed in pure CX (the bundle body maps the
		// callable over find-all then splices) — re-replace-splice does the
		// byte-offset splice with the precomputed per-match replacements.
		're-replace-splice' {
			return re_replace_splice(args)
		}
		're-match-spans' {
			// Helper for replace-fn: the per-match full-match [start,end)
			// spans of (re, s) as a sequence of [span start end] elements,
			// so the CX splice aligns 1:1 with find-all's match order.
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			matches, errn := re_collect_matches(pattern, f, s, 0)
			if e := errn {
				return e
			}
			mut items := []cx.Node{cap: matches.len}
			for spans in matches {
				full := spans[0]
				items << cx.Element{
					name:  'span'
					attrs: [
						cx.Attribute{
							name:  'start'
							value: cx.ScalarValue(full.start)
						},
						cx.Attribute{
							name:  'end'
							value: cx.ScalarValue(full.end)
						},
					]
				}
			}
			return re_seq(items)
		}

		// ── §4.5 split ──────────────────────────────────────────────
		're-split' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			return re_split_impl(pattern, f, s, -1)
		}
		're-split-limit' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			s := re_arg_str(args[1]) or { return none }
			max := re_arg_int(args[2]) or { return none }
			return re_split_impl(pattern, f, s, int(max))
		}

		// ── §4.6 inspection ─────────────────────────────────────────
		're-group-count' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			n := cx.re2_num_groups(pattern, f) or { return re_compile_err(err.msg()) }
			return re_int(i64(n))
		}
		're-group-names' {
			pattern, f := re_unpack_compiled(args[0]) or { return none }
			names := cx.re2_group_names(pattern, f) or { return re_compile_err(err.msg()) }
			mut items := []cx.Node{cap: names.len}
			for nm in names {
				items << re_str(nm)
			}
			return re_seq(items)
		}
		're-pattern-text' {
			pattern, _ := re_unpack_compiled(args[0]) or { return none }
			return re_str(pattern)
		}
		're-pattern-flags' {
			_, f := re_unpack_compiled(args[0]) or { return none }
			entries := [
				cx.Node(cx.Element{
					name:  'case-insensitive'
					items: [re_bool(f.case_insensitive)]
				}),
				cx.Node(cx.Element{
					name:  'multiline'
					items: [re_bool(f.multiline)]
				}),
				cx.Node(cx.Element{
					name:  'dotall'
					items: [re_bool(f.dotall)]
				}),
				cx.Node(cx.Element{
					name:  'unicode'
					items: [re_bool(f.unicode)]
				}),
				cx.Node(cx.Element{
					name:  'literal'
					items: [re_bool(f.literal)]
				}),
				cx.Node(cx.Element{
					name:  'max-match-bytes'
					items: [re_int(f.max_match_bytes)]
				}),
			]
			return cx.Element{
				name:  '__cx_map__'
				items: entries
			}
		}
		're-escape' {
			s := re_arg_str(args[0]) or { return none }
			return re_str(cx.re2_escape(s))
		}

		// ── generic map accessor (shared with other stdlib modules) ──
		// `map-get` is referenced by the re + ft conformance fixtures but
		// is not a language-core builtin; it has no core name clash. Reached
		// here only when otherwise unresolved (the stdlib chain runs after
		// the core builtin set). See SPEC-FINDINGS §H.
		'map-get' {
			if args.len < 2 {
				return none
			}
			m := args[0]
			key := re_arg_str(args[1]) or { return none }
			if m is cx.Element && m.name == '__cx_map__' {
				for entry in m.items {
					if entry is cx.Element && entry.name == key && entry.items.len > 0 {
						return entry.items[0]
					}
				}
			}
			return none
		}
		else {
			return none
		}
	}
}

// re_match_arg resolves a [match …] element argument; the [no-match]
// sentinel and other shapes yield none.
fn re_match_arg(n cx.Node) ?cx.Element {
	if n is cx.Element && n.name == 'match' {
		return n
	}
	return none
}

// re_find_impl runs `find` / `find-from`: first match at or after byte
// `from`. Honours max-match-bytes (spec §4.1/§7).
fn re_find_impl(pattern string, f cx.Re2Flags, s string, from int) cx.Node {
	mut start := from
	if start < 0 {
		start = 0
	}
	spans := cx.re2_match_at(pattern, f, s, start) or { return re_compile_err(err.msg()) }
	if spans.len == 0 {
		return re_no_match()
	}
	full := spans[0]
	if f.max_match_bytes > 0 && (full.end - full.start) > f.max_match_bytes {
		return mk_err('cx-err:CXER3203',
			'E_RE_MATCH_BYTES_EXCEEDED: match of ${full.end - full.start} bytes exceeds budget ${f.max_match_bytes}')
	}
	return re_match_element(pattern, f, s, spans)
}

// re_replace_impl backs replace / replace-first via per-match template
// substitution over the find-all span sets.
fn re_replace_impl(args []cx.Node, first_only bool) ?cx.Node {
	pattern, f := re_unpack_compiled(args[0]) or { return none }
	s := re_arg_str(args[1]) or { return none }
	template := re_arg_str(args[2]) or { return none }
	matches, errn := re_collect_matches(pattern, f, s, 0)
	if e := errn {
		return e
	}
	named := re_named_map(pattern, f)
	mut out := []u8{cap: s.len}
	mut cursor := 0
	for mi, spans in matches {
		if first_only && mi > 0 {
			break
		}
		full := spans[0]
		st := int(full.start)
		en := int(full.end)
		if st > cursor {
			out << s[cursor..st].bytes()
		}
		// Build a transient match element so the template can read groups.
		mel := re_match_element(pattern, f, s, spans) as cx.Element
		out << re_apply_template(template, mel, named).bytes()
		cursor = en
	}
	if cursor < s.len {
		out << s[cursor..].bytes()
	}
	return re_str(out.bytestr())
}

// re_replace_splice backs replace-fn: given (subject, spans-seq,
// replacements-seq), splices the original subject by byte offset,
// substituting each match span with the aligned replacement string.
fn re_replace_splice(args []cx.Node) ?cx.Node {
	s := re_arg_str(args[0]) or { return none }
	mut spans := []cx.Re2Span{}
	for it in re_items(args[1]) {
		if it is cx.Element && it.name == 'span' {
			spans << cx.Re2Span{
				start: re_attr_int(it, 'start')
				end:   re_attr_int(it, 'end')
			}
		}
	}
	mut repls := []string{}
	for it in re_items(args[2]) {
		repls << re_arg_str(it) or { '' }
	}
	mut out := []u8{cap: s.len}
	mut cursor := 0
	for i, sp in spans {
		st := int(sp.start)
		en := int(sp.end)
		if st > cursor {
			out << s[cursor..st].bytes()
		}
		if i < repls.len {
			out << repls[i].bytes()
		}
		cursor = en
	}
	if cursor < s.len {
		out << s[cursor..].bytes()
	}
	return re_str(out.bytestr())
}

// re_split_impl backs split / split-limit. `max < 0` = unlimited;
// split-limit yields at most max+1 segments (spec §4.5). Empty (zero-
// width) separator matches are skipped for splitting so `\s+`-style splits
// behave intuitively; the remainder after the limit is kept intact.
fn re_split_impl(pattern string, f cx.Re2Flags, s string, max int) cx.Node {
	matches, errn := re_collect_matches(pattern, f, s, 0)
	if e := errn {
		return e
	}
	mut parts := []cx.Node{}
	mut cursor := 0
	mut taken := 0
	for spans in matches {
		full := spans[0]
		st := int(full.start)
		en := int(full.end)
		if en == st {
			// zero-width separator — does not split (spec §4.5 intent).
			continue
		}
		if max >= 0 && taken >= max {
			break
		}
		parts << re_str(s[cursor..st])
		cursor = en
		taken++
	}
	parts << re_str(s[cursor..])
	return re_seq(parts)
}
