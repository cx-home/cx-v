module code

import cx

// stdlib_html.v — native primitives backing `cx-stdlib/html`
// (spec/std-lib/html.md). Lenient WHATWG-style HTML parse into a CXDM
// element tree, HTML5 / XHTML serialization, safe-default + policy-driven
// sanitization, and tag-stripping text extraction. The module's [?def]
// bodies (stdlib_src_html, stdlib_bundle.v) forward here via
// stdlib_dispatch.v::stdlib_builtin.
//
// ── CX value model ──────────────────────────────────────────────────
//   parse returns a single document-root `[html-document …]` element
//   wrapping the recovered top-level element tree; HTML elements become
//   CXDM elements (name = lowercased tag), attributes become CXDM
//   attributes, character data become TextNodes. parse-fragment returns a
//   `name=''` sequence wrapper of the fragment's top-level nodes (no
//   document wrapper). serialize / serialize-xhtml / sanitize* (string
//   variants) / extract-text return a string scalar. sanitize-tree* return
//   an element tree.
//
// Errors are VALUES (mk_err, eval.v): CXER3900 E_HTML_PARSE_FAILED,
// CXER3901 E_HTML_POLICY_INVALID, CXER3902 E_HTML_SERIALIZE_FAILED (§5).
//
// html is pure — no process-global state, no `@[has_globals]`.

// ── value builders ───────────────────────────────────────────────────

fn html_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn html_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn html_err_parse(msg string) cx.Node {
	return mk_err('cx-err:CXER3900', 'E_HTML_PARSE_FAILED: ${msg}')
}

fn html_err_policy(msg string) cx.Node {
	return mk_err('cx-err:CXER3901', 'E_HTML_POLICY_INVALID: ${msg}')
}

fn html_err_serialize(msg string) cx.Node {
	return mk_err('cx-err:CXER3902', 'E_HTML_SERIALIZE_FAILED: ${msg}')
}

// document-root wrapper name. parse returns this so CXPath '//a' on the
// parse result reaches the recovered elements (descendant-or-self of the
// root). The sanitizer / serializer treat it as a transparent container.
const html_doc_root = 'html-document'

// ── HTML structural tables ───────────────────────────────────────────

// void elements emit no end tag and have no children (WHATWG §13.1.2).
const html_void_tags = {
	'area':   true
	'base':   true
	'br':     true
	'col':    true
	'embed':  true
	'hr':     true
	'img':    true
	'input':  true
	'link':   true
	'meta':   true
	'param':  true
	'source': true
	'track':  true
	'wbr':    true
}

// raw-text elements: content up to the matching end tag is literal text
// (no nested markup). script/style additionally are dropped wholesale by
// the sanitizer + extract-text.
const html_rawtext_tags = {
	'script':   true
	'style':    true
	'textarea': true
	'title':    true
}

fn html_is_void(tag string) bool {
	return tag in html_void_tags
}

// ── tokenizer ────────────────────────────────────────────────────────

enum HtmlTokKind {
	text
	start_tag
	end_tag
	comment
	doctype
}

struct HtmlAttr {
	name  string
	value string
}

struct HtmlToken {
	kind         HtmlTokKind
	name         string // tag name (lowercased) or text content
	attrs        []HtmlAttr
	self_closing bool
}

fn html_is_space(c u8) bool {
	return c == ` ` || c == `\t` || c == `\n` || c == `\r` || c == `\f`
}

fn html_is_tagname_char(c u8) bool {
	return (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
		|| (c >= `0` && c <= `9`) || c == `-` || c == `_` || c == `:`
}

// html_tokenize scans the input into a flat token stream. Lenient: a
// stray `<` not beginning a tag is emitted as text; unterminated tags are
// recovered at end of input. Raw-text elements consume their content as a
// single text token up to the matching end tag.
fn html_tokenize(input string) []HtmlToken {
	mut toks := []HtmlToken{}
	mut i := 0
	n := input.len
	for i < n {
		c := input[i]
		if c == `<` {
			// Comment / doctype / bogus comment.
			if i + 3 < n && input[i + 1] == `!` && input[i + 2] == `-` && input[i + 3] == `-` {
				// comment: up to '-->'
				mut j := i + 4
				for j + 2 < n && !(input[j] == `-` && input[j + 1] == `-` && input[j + 2] == `>`) {
					j++
				}
				end := if j + 2 < n { j + 3 } else { n }
				toks << HtmlToken{ kind: .comment }
				i = end
				continue
			}
			if i + 1 < n && input[i + 1] == `!` {
				// doctype / bogus declaration: up to '>'
				mut j := i + 2
				for j < n && input[j] != `>` {
					j++
				}
				toks << HtmlToken{ kind: .doctype }
				i = if j < n { j + 1 } else { n }
				continue
			}
			// End tag </name ...>
			if i + 1 < n && input[i + 1] == `/` {
				mut j := i + 2
				start := j
				for j < n && html_is_tagname_char(input[j]) {
					j++
				}
				name := input[start..j].to_lower()
				// skip to '>'
				for j < n && input[j] != `>` {
					j++
				}
				i = if j < n { j + 1 } else { n }
				if name != '' {
					toks << HtmlToken{ kind: .end_tag, name: name }
				}
				continue
			}
			// Start tag <name attrs ...>
			if i + 1 < n && ((input[i + 1] >= `a` && input[i + 1] <= `z`)
				|| (input[i + 1] >= `A` && input[i + 1] <= `Z`)) {
				mut j := i + 1
				start := j
				for j < n && html_is_tagname_char(input[j]) {
					j++
				}
				tag := input[start..j].to_lower()
				mut attrs := []HtmlAttr{}
				mut self_closing := false
				// parse attributes
				for j < n {
					// skip whitespace
					for j < n && html_is_space(input[j]) {
						j++
					}
					if j >= n {
						break
					}
					if input[j] == `>` {
						j++
						break
					}
					if input[j] == `/` {
						// self-closing marker (or stray slash)
						if j + 1 < n && input[j + 1] == `>` {
							self_closing = true
							j += 2
							break
						}
						j++
						continue
					}
					// attribute name
					astart := j
					for j < n && !html_is_space(input[j]) && input[j] != `=`
						&& input[j] != `>` && input[j] != `/` {
						j++
					}
					aname := input[astart..j].to_lower()
					mut aval := ''
					// skip whitespace before '='
					mut k := j
					for k < n && html_is_space(input[k]) {
						k++
					}
					if k < n && input[k] == `=` {
						k++
						for k < n && html_is_space(input[k]) {
							k++
						}
						if k < n && (input[k] == `"` || input[k] == `'`) {
							q := input[k]
							k++
							vstart := k
							for k < n && input[k] != q {
								k++
							}
							aval = input[vstart..k]
							if k < n {
								k++
							}
						} else {
							vstart := k
							for k < n && !html_is_space(input[k]) && input[k] != `>` {
								k++
							}
							aval = input[vstart..k]
						}
						j = k
					}
					if aname != '' {
						attrs << HtmlAttr{ name: aname, value: html_decode_entities(aval) }
					}
				}
				// raw-text element: consume content as a single text token
				if tag in html_rawtext_tags && !self_closing {
					close := '</' + tag
					mut e := j
					mut found := -1
					for e + close.len <= n {
						if input[e..e + close.len].to_lower() == close {
							found = e
							break
						}
						e++
					}
					content_end := if found >= 0 { found } else { n }
					raw := input[j..content_end]
					toks << HtmlToken{ kind: .start_tag, name: tag, attrs: attrs }
					if raw.len > 0 {
						toks << HtmlToken{ kind: .text, name: raw }
					}
					if found >= 0 {
						// advance past the end tag '>'
						mut m := found + close.len
						for m < n && input[m] != `>` {
							m++
						}
						i = if m < n { m + 1 } else { n }
						toks << HtmlToken{ kind: .end_tag, name: tag }
					} else {
						i = n
						toks << HtmlToken{ kind: .end_tag, name: tag }
					}
					continue
				}
				toks << HtmlToken{ kind: .start_tag, name: tag, attrs: attrs, self_closing: self_closing }
				i = j
				continue
			}
			// stray '<' — literal text
			toks << HtmlToken{ kind: .text, name: '<' }
			i++
			continue
		}
		// text run up to next '<'
		start := i
		for i < n && input[i] != `<` {
			i++
		}
		raw := input[start..i]
		toks << HtmlToken{ kind: .text, name: html_decode_entities(raw) }
	}
	return toks
}

// ── tree builder (lenient recovery) ──────────────────────────────────
//
// A pragmatic subset of the WHATWG tree-construction algorithm covering
// the recovery the conformance corpus exercises: implied close of
// auto-closing block elements (<p>, <li>), unclosed-tag closing at EOF,
// and ignoring stray end tags. Implied <html>/<head>/<body> are NOT
// materialised as wrapper nodes — the spec's observable contracts are
// expressed via the recovered element tree and text, and the document
// root wrapper ([html-document]) stands in as the single queryable root.

// tags whose open instance is implicitly closed by a sibling start tag.
fn html_implies_close(open string, next string) bool {
	if open == 'p' {
		// a <p> is closed by a following block-level start tag
		return next in ['p', 'div', 'ul', 'ol', 'li', 'table', 'blockquote',
			'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'figure',
			'dl', 'address', 'section', 'article', 'header', 'footer']
	}
	if open == 'li' {
		return next == 'li'
	}
	if open == 'dt' || open == 'dd' {
		return next == 'dt' || next == 'dd'
	}
	if open in ['td', 'th'] {
		return next in ['td', 'th', 'tr']
	}
	if open == 'tr' {
		return next == 'tr'
	}
	if open in ['thead', 'tbody', 'tfoot'] {
		return next in ['thead', 'tbody', 'tfoot']
	}
	if open == 'option' {
		return next == 'option'
	}
	return false
}

struct HtmlBuildFrame {
mut:
	name  string
	attrs []cx.Attribute
	items []cx.Node
}

// html_build_tree turns the token stream into top-level CXDM nodes.
fn html_build_tree(toks []HtmlToken) []cx.Node {
	mut roots := []cx.Node{}
	mut stack := []HtmlBuildFrame{}

	close_top := fn (mut stack []HtmlBuildFrame, mut roots []cx.Node) {
		if stack.len == 0 {
			return
		}
		top := stack.pop()
		el := cx.Element{
			name:  top.name
			attrs: top.attrs
			items: top.items
		}
		if stack.len > 0 {
			stack[stack.len - 1].items << cx.Node(el)
		} else {
			roots << cx.Node(el)
		}
	}

	push_node := fn (mut stack []HtmlBuildFrame, mut roots []cx.Node, node cx.Node) {
		if stack.len > 0 {
			stack[stack.len - 1].items << node
		} else {
			roots << node
		}
	}

	for tok in toks {
		match tok.kind {
			.text {
				if tok.name.len > 0 {
					push_node(mut stack, mut roots, cx.Node(cx.TextNode{ value: tok.name }))
				}
			}
			.comment, .doctype {
				// dropped — not represented in the CXDM tree
			}
			.start_tag {
				// implied-close of auto-closing open elements
				for stack.len > 0 && html_implies_close(stack[stack.len - 1].name, tok.name) {
					close_top(mut stack, mut roots)
				}
				mut cattrs := []cx.Attribute{}
				for a in tok.attrs {
					cattrs << cx.Attribute{
						name:  a.name
						value: cx.ScalarValue(a.value)
					}
				}
				if html_is_void(tok.name) || tok.self_closing {
					el := cx.Element{
						name:  tok.name
						attrs: cattrs
					}
					push_node(mut stack, mut roots, cx.Node(el))
				} else {
					stack << HtmlBuildFrame{
						name:  tok.name
						attrs: cattrs
					}
				}
			}
			.end_tag {
				// find the nearest matching open element; close down to it.
				mut found := -1
				for k := stack.len - 1; k >= 0; k-- {
					if stack[k].name == tok.name {
						found = k
						break
					}
				}
				if found >= 0 {
					for stack.len > found {
						close_top(mut stack, mut roots)
					}
				}
				// stray end tag with no matching open → ignored
			}
		}
	}
	// close any still-open elements at EOF
	for stack.len > 0 {
		close_top(mut stack, mut roots)
	}
	return roots
}

// html_parse_roots tokenizes + builds the recovered top-level node list.
fn html_parse_roots(input string) []cx.Node {
	return html_build_tree(html_tokenize(input))
}

// ── entity decode ────────────────────────────────────────────────────

const html_named_entities = {
	'amp':    '&'
	'lt':     '<'
	'gt':     '>'
	'quot':   '"'
	'apos':   "'"
	'nbsp':   ' '
	'copy':   '©'
	'reg':    '®'
	'trade':  '™'
	'hellip': '…'
	'mdash':  '—'
	'ndash':  '–'
	'lsquo':  '‘'
	'rsquo':  '’'
	'ldquo':  '“'
	'rdquo':  '”'
	'laquo':  '«'
	'raquo':  '»'
	'times':  '×'
	'divide': '÷'
	'deg':    '°'
	'pound':  '£'
	'euro':   '€'
	'cent':   '¢'
	'yen':    '¥'
	'sect':   '§'
	'para':   '¶'
	'middot': '·'
	'bull':   '•'
	'dagger': '†'
	'permil': '‰'
	'micro':  'µ'
	'frac12': '½'
	'frac14': '¼'
	'frac34': '¾'
	'sup2':   '²'
	'sup3':   '³'
	'plusmn': '±'
}

fn html_codepoint_to_utf8(cp int) string {
	if cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) {
		return '�'
	}
	return utf32_to_str(u32(cp))
}

// html_decode_entities resolves named (&amp;) and numeric (&#65; / &#x41;)
// references. An unrecognized or malformed reference is left verbatim
// (browsers preserve a bare '&').
fn html_decode_entities(s string) string {
	if !s.contains('&') {
		return s
	}
	mut out := []u8{}
	mut i := 0
	n := s.len
	for i < n {
		if s[i] != `&` {
			out << s[i]
			i++
			continue
		}
		// find ';' within a bounded window
		mut semi := -1
		mut j := i + 1
		for j < n && j < i + 32 {
			if s[j] == `;` {
				semi = j
				break
			}
			j++
		}
		if semi < 0 {
			out << s[i]
			i++
			continue
		}
		body := s[i + 1..semi]
		if body.len == 0 {
			out << s[i]
			i++
			continue
		}
		if body[0] == `#` {
			mut cp := 0
			mut ok := false
			if body.len > 1 && (body[1] == `x` || body[1] == `X`) {
				hex := body[2..]
				if hex.len > 0 {
					ok = true
					for hc in hex {
						d := html_hex_digit(hc) or {
							ok = false
							break
						}
						cp = cp * 16 + d
					}
				}
			} else {
				dec := body[1..]
				if dec.len > 0 {
					ok = true
					for dc in dec {
						if dc < `0` || dc > `9` {
							ok = false
							break
						}
						cp = cp * 10 + int(dc - `0`)
					}
				}
			}
			if ok {
				out << html_codepoint_to_utf8(cp).bytes()
				i = semi + 1
				continue
			}
		} else if rep := html_named_entities[body] {
			out << rep.bytes()
			i = semi + 1
			continue
		}
		// unrecognized — keep the '&' literally and continue from next char
		out << s[i]
		i++
	}
	return out.bytestr()
}

fn html_hex_digit(c u8) ?int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a` + 10)
	}
	if c >= `A` && c <= `F` {
		return int(c - `A` + 10)
	}
	return none
}

// ── serialization ────────────────────────────────────────────────────

// html_escape_text escapes text-node content for HTML output (&, <, >).
fn html_escape_text(s string) string {
	mut out := s.replace('&', '&amp;')
	out = out.replace('<', '&lt;')
	out = out.replace('>', '&gt;')
	return out
}

// html_escape_attr escapes an attribute value for double-quoted output.
fn html_escape_attr(s string) string {
	mut out := s.replace('&', '&amp;')
	out = out.replace('"', '&quot;')
	return out
}

// html_serialize_node serializes one CXDM node to HTML. xhtml=true emits
// XML-well-formed output (void elements self-close).
fn html_serialize_node(n cx.Node, xhtml bool) string {
	match n {
		cx.TextNode {
			return html_escape_text(n.value)
		}
		cx.ScalarNode {
			return html_escape_text(cx.scalar_value_str_public(n.value))
		}
		cx.Element {
			// transparent document-root / sequence wrappers: serialize
			// children only.
			if n.name == html_doc_root || n.name == '' || n.name == '__cx_seq__' {
				mut inner := ''
				for it in n.items {
					inner += html_serialize_node(it, xhtml)
				}
				return inner
			}
			tag := n.name
			mut s := '<' + tag
			for a in n.attrs {
				v := cx.scalar_value_str_public(a.value)
				s += ' ' + a.name + '="' + html_escape_attr(v) + '"'
			}
			if html_is_void(tag) {
				if xhtml {
					s += '/>'
				} else {
					s += '>'
				}
				return s
			}
			s += '>'
			for it in n.items {
				s += html_serialize_node(it, xhtml)
			}
			s += '</' + tag + '>'
			return s
		}
		else {
			return ''
		}
	}
}

// html_serialize is the entry for serialize / serialize-xhtml. The arg
// must be a CXDM element tree (the parse / sanitize-tree shape).
fn html_serialize(arg cx.Node, xhtml bool) cx.Node {
	// D7 — a transparent DocumentNode (e.g. from [$cx:parse]) serializes its
	// top-level children. Non-element prolog nodes (comments/PIs) drop out via
	// html_serialize_node's `else` arm, matching HTML's comment handling.
	if arg is cx.DocumentNode {
		mut out := ''
		for c in arg.prolog {
			out += html_serialize_node(c, xhtml)
		}
		for c in arg.elements {
			out += html_serialize_node(c, xhtml)
		}
		return html_str(out)
	}
	if arg !is cx.Element {
		return html_err_serialize('argument is not a CXDM element tree')
	}
	return html_str(html_serialize_node(arg, xhtml))
}

// ── extract-text ─────────────────────────────────────────────────────

fn html_extract_collect(n cx.Node, mut parts []string) {
	match n {
		cx.TextNode {
			t := n.value.trim_space()
			if t != '' {
				parts << t
			}
		}
		cx.Element {
			if n.name == 'script' || n.name == 'style' {
				return
			}
			for it in n.items {
				html_extract_collect(it, mut parts)
			}
		}
		else {}
	}
}

fn html_extract_text(input string) cx.Node {
	roots := html_parse_roots(input)
	mut parts := []string{}
	for r in roots {
		html_extract_collect(r, mut parts)
	}
	return html_str(parts.join(' '))
}

// ── sanitizer policy ─────────────────────────────────────────────────

const html_default_allowed_tags = {
	'a':          true
	'abbr':       true
	'address':    true
	'b':          true
	'blockquote': true
	'br':         true
	'caption':    true
	'cite':       true
	'code':       true
	'col':        true
	'colgroup':   true
	'dd':         true
	'del':        true
	'dfn':        true
	'div':        true
	'dl':         true
	'dt':         true
	'em':         true
	'figcaption': true
	'figure':     true
	'h1':         true
	'h2':         true
	'h3':         true
	'h4':         true
	'h5':         true
	'h6':         true
	'hr':         true
	'i':          true
	'img':        true
	'ins':        true
	'kbd':        true
	'li':         true
	'mark':       true
	'ol':         true
	'p':          true
	'pre':        true
	'q':          true
	's':          true
	'samp':       true
	'small':      true
	'span':       true
	'strong':     true
	'sub':        true
	'sup':        true
	'table':      true
	'tbody':      true
	'td':         true
	'tfoot':      true
	'th':         true
	'thead':      true
	'time':       true
	'tr':         true
	'u':          true
	'ul':         true
	'var':        true
	'wbr':        true
}

// global attributes allowed on any element.
const html_global_attrs = {
	'class': true
	'id':    true
	'lang':  true
	'dir':   true
}

// per-tag attribute allowlist (beyond globals).
fn html_tag_allows_attr(tag string, attr string) bool {
	if attr in html_global_attrs {
		return true
	}
	match tag {
		'a' { return attr == 'href' || attr == 'title' }
		'img' { return attr in ['src', 'alt', 'width', 'height'] }
		'td', 'th' { return attr == 'colspan' || attr == 'rowspan' }
		'blockquote', 'q', 'del', 'ins' {
			if attr == 'cite' {
				return true
			}
			if (tag == 'del' || tag == 'ins') && attr == 'datetime' {
				return true
			}
			return false
		}
		'time' { return attr == 'datetime' }
		else { return false }
	}
}

// URL-bearing attributes whose value must pass scheme validation.
fn html_is_url_attr(attr string) bool {
	return attr == 'href' || attr == 'src' || attr == 'cite'
}

struct HtmlPolicy {
mut:
	allow_tags     map[string]bool // additive over default
	deny_tags      map[string]bool
	allow_attrs    map[string]bool // additive global attrs
	deny_attrs     map[string]bool
	url_schemes    map[string]bool // allowed URL schemes (replaces default if set_schemes)
	set_schemes    bool
	data_mimes     map[string]bool
	data_mimes_set bool // allow-data-mime clause present (even if empty → deny all)
	allow_css      bool
}

fn html_default_policy() HtmlPolicy {
	return HtmlPolicy{
		allow_css: true
	}
}

const html_default_url_schemes = {
	'http':   true
	'https':  true
	'mailto': true
}

const html_default_data_mimes = {
	'image/png':  true
	'image/jpeg': true
	'image/gif':  true
	'image/webp': true
}

// html_read_policy parses an `[html-policy …]` element into an HtmlPolicy,
// validating it. Returns an error VALUE (CXER3901) on a forbidden /
// malformed clause.
fn html_read_policy(n cx.Node) (HtmlPolicy, cx.Node, bool) {
	mut pol := html_default_policy()
	if n !is cx.Element {
		return pol, html_err_policy('policy is not an [html-policy …] element'), true
	}
	el := n as cx.Element
	if el.name != 'html-policy' {
		return pol, html_err_policy('expected [html-policy …], got [${el.name}]'), true
	}
	for clause in el.items {
		if clause !is cx.Element {
			continue
		}
		ce := clause as cx.Element
		toks := html_clause_tokens(ce)
		match ce.name {
			'allow-tags' {
				for t in toks {
					lt := t.to_lower()
					if lt == 'script' || lt == 'style' {
						return pol, html_err_policy('cannot re-allow forbidden tag <${lt}>'), true
					}
					pol.allow_tags[lt] = true
				}
			}
			'deny-tags' {
				for t in toks {
					pol.deny_tags[t.to_lower()] = true
				}
			}
			'allow-attributes' {
				for t in toks {
					lt := t.to_lower()
					if lt.starts_with('on') {
						return pol, html_err_policy('cannot re-allow event-handler attribute ${lt}'), true
					}
					pol.allow_attrs[lt] = true
				}
			}
			'deny-attributes' {
				for t in toks {
					pol.deny_attrs[t.to_lower()] = true
				}
			}
			'allow-url-schemes' {
				pol.set_schemes = true
				for t in toks {
					pol.url_schemes[t.to_lower()] = true
				}
			}
			'allow-data-mime' {
				pol.data_mimes_set = true
				for t in toks {
					lt := t.to_lower()
					if lt == 'text/html' || lt == 'image/svg+xml' {
						return pol, html_err_policy('data: MIME ${lt} can never be allowed'), true
					}
					pol.data_mimes[lt] = true
				}
			}
			'allow-css' {
				if toks.len > 0 {
					pol.allow_css = toks[0].to_lower() == 'true'
				}
			}
			else {
				return pol, html_err_policy('unknown policy clause [${ce.name}]'), true
			}
		}
	}
	return pol, cx.Node(cx.Element{}), false
}

// html_clause_tokens reads the bare-word / scalar tokens of a policy
// clause body (e.g. `[allow-tags table tr td]` → ['table','tr','td']).
fn html_clause_tokens(ce cx.Element) []string {
	mut out := []string{}
	for it in ce.items {
		match it {
			cx.TextNode {
				for w in it.value.fields() {
					out << w
				}
			}
			cx.ScalarNode {
				out << cx.scalar_value_str_public(it.value)
			}
			cx.Element {
				// a bareword arg parses as a childless element [table]
				if it.items.len == 0 && it.attrs.len == 0 {
					out << it.name
				}
			}
			else {}
		}
	}
	return out
}

fn html_policy_allows_tag(pol HtmlPolicy, tag string) bool {
	if tag in pol.deny_tags {
		return false
	}
	if tag in html_default_allowed_tags {
		return true
	}
	return tag in pol.allow_tags
}

fn html_policy_allows_attr(pol HtmlPolicy, tag string, attr string) bool {
	if attr in pol.deny_attrs {
		return false
	}
	// on* handlers are never allowed.
	if attr.starts_with('on') {
		return false
	}
	if html_tag_allows_attr(tag, attr) {
		return true
	}
	return attr in pol.allow_attrs
}

// html_url_scheme extracts the lowercased scheme of a URL value, or '' for
// a scheme-relative / relative URL.
fn html_url_scheme(url string) string {
	mut i := 0
	for i < url.len {
		c := url[i]
		if c == `:` {
			return url[..i].to_lower()
		}
		if (c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`)
			|| (c >= `0` && c <= `9`) || c == `+` || c == `-` || c == `.` {
			i++
			continue
		}
		// no scheme (e.g. '/', '#', '?', or path char before ':')
		return ''
	}
	return ''
}

// html_url_allowed validates a URL-bearing attribute value against the
// policy's scheme + data: MIME rules.
fn html_url_allowed(pol HtmlPolicy, url string) bool {
	trimmed := url.trim_space()
	scheme := html_url_scheme(trimmed)
	if scheme == '' {
		// scheme-relative ('//host') or relative/anchor URL → allowed.
		return true
	}
	if scheme == 'data' {
		return html_data_url_allowed(pol, trimmed)
	}
	if scheme == 'javascript' {
		return false
	}
	schemes := if pol.set_schemes {
		// additive over default
		mut m := map[string]bool{}
		for k, _ in html_default_url_schemes {
			m[k] = true
		}
		for k, _ in pol.url_schemes {
			m[k] = true
		}
		m
	} else {
		html_default_url_schemes.clone()
	}
	return scheme in schemes
}

// html_data_url_allowed checks a data: URL against the data: MIME
// allowlist. text/html and image/svg+xml are always denied.
fn html_data_url_allowed(pol HtmlPolicy, url string) bool {
	// data:<mime>[;...],<payload>
	rest := url[5..] // after 'data:'
	mut mime := rest
	if ci := rest.index(',') {
		mime = rest[..ci]
	}
	if sc := mime.index(';') {
		mime = mime[..sc]
	}
	mime = mime.trim_space().to_lower()
	if mime == 'text/html' || mime == 'image/svg+xml' {
		return false
	}
	mimes := if pol.data_mimes_set {
		pol.data_mimes.clone()
	} else {
		html_default_data_mimes.clone()
	}
	return mime in mimes
}

// ── inline-CSS sanitization ──────────────────────────────────────────

const html_css_allowed_props = {
	'color':                true
	'background-color':     true
	'font-family':          true
	'font-size':            true
	'font-weight':          true
	'font-style':           true
	'font-variant':         true
	'text-align':           true
	'text-decoration':      true
	'line-height':          true
	'letter-spacing':       true
	'white-space':          true
	'margin':               true
	'margin-top':           true
	'margin-right':         true
	'margin-bottom':        true
	'margin-left':          true
	'padding':              true
	'padding-top':          true
	'padding-right':        true
	'padding-bottom':       true
	'padding-left':         true
	'border':               true
	'border-top':           true
	'border-right':         true
	'border-bottom':        true
	'border-left':          true
	'border-color':         true
	'border-width':         true
	'border-style':         true
	'border-radius':        true
	'width':                true
	'height':               true
	'max-width':            true
	'max-height':           true
	'display':              true
	'vertical-align':       true
	'list-style':           true
	'list-style-type':      true
	'list-style-position':  true
}

// html_sanitize_css filters a `style` declaration list to the property
// allowlist + value validation, re-serializing in canonical form
// (`prop:value;prop:value`, lowercased property, no trailing `;`).
fn html_sanitize_css(style string) string {
	mut kept := []string{}
	for decl in style.split(';') {
		d := decl.trim_space()
		if d == '' {
			continue
		}
		ci := d.index(':') or { continue }
		prop := d[..ci].trim_space().to_lower()
		val := d[ci + 1..].trim_space()
		if prop !in html_css_allowed_props {
			continue
		}
		if !html_css_value_ok(prop, val) {
			continue
		}
		kept << prop + ':' + val
	}
	return kept.join(';')
}

fn html_css_value_ok(prop string, val string) bool {
	lv := val.to_lower()
	if lv.contains('expression(') {
		return false
	}
	if lv.contains('behavior') || lv.contains('-moz-binding') {
		return false
	}
	if val.contains('<') {
		return false
	}
	if prop == 'position' && (lv.contains('fixed') || lv.contains('sticky')) {
		return false
	}
	if lv.contains('url(') {
		// url() target must use a safe scheme
		idx := lv.index('url(') or { return true }
		mut inner := lv[idx + 4..]
		if cp := inner.index(')') {
			inner = inner[..cp]
		}
		inner = inner.trim(' \t\'"')
		sch := html_url_scheme(inner)
		if sch == 'javascript' || sch == 'data' {
			return false
		}
	}
	return true
}

// ── tree sanitization ────────────────────────────────────────────────

// html_sanitize_nodes filters a node list per policy, returning the kept
// (possibly rewritten) nodes. Disallowed elements are dropped WITH their
// content for script/style/svg/math; other disallowed elements are
// dropped but — per a conservative reading we drop the whole subtree for
// non-allowlisted tags (the spec lists svg/math content-drop; an
// unrecognized tag is dropped, and the corpus only asserts content-drop
// for script/style/svg). To stay faithful to the fixtures (svg dropped
// with content), non-allowlisted elements are dropped entirely.
fn html_sanitize_nodes(nodes []cx.Node, pol HtmlPolicy) []cx.Node {
	mut out := []cx.Node{}
	for n in nodes {
		match n {
			cx.TextNode {
				out << n
			}
			cx.ScalarNode {
				out << n
			}
			cx.Element {
				if n.name == html_doc_root || n.name == '' {
					// transparent wrapper: recurse, keep wrapper
					inner := html_sanitize_nodes(n.items, pol)
					out << cx.Node(cx.Element{
						name:  n.name
						items: inner
					})
					continue
				}
				if !html_policy_allows_tag(pol, n.name) {
					// dropped entirely (with content) — script/style/svg/math
					// and any unrecognized tag.
					continue
				}
				mut kept_attrs := []cx.Attribute{}
				for a in n.attrs {
					aval := cx.scalar_value_str_public(a.value)
					// `style` is governed by the inline-CSS policy, not the
					// element attribute allowlist.
					if a.name == 'style' {
						// on* check still applies via the generic guard below;
						// style itself is never an on* handler.
						if a.name in pol.deny_attrs {
							continue
						}
						if !pol.allow_css {
							continue
						}
						cleaned := html_sanitize_css(aval)
						if cleaned == '' {
							continue
						}
						kept_attrs << cx.Attribute{
							name:  'style'
							value: cx.ScalarValue(cleaned)
						}
						continue
					}
					if !html_policy_allows_attr(pol, n.name, a.name) {
						continue
					}
					if html_is_url_attr(a.name) {
						if !html_url_allowed(pol, aval) {
							continue
						}
					}
					kept_attrs << cx.Attribute{
						name:  a.name
						value: cx.ScalarValue(aval)
					}
				}
				inner := html_sanitize_nodes(n.items, pol)
				out << cx.Node(cx.Element{
					name:  n.name
					attrs: kept_attrs
					items: inner
				})
			}
			else {}
		}
	}
	return out
}

// html_sanitize_tree applies a policy to a parsed tree, returning a new
// tree. The root wrapper is preserved.
fn html_sanitize_tree(tree cx.Node, pol HtmlPolicy) cx.Node {
	res := html_sanitize_nodes([tree], pol)
	if res.len == 1 {
		return res[0]
	}
	// wrapper was dropped (shouldn't happen for a real root) → re-wrap
	return cx.Element{
		name:  html_doc_root
		items: res
	}
}

// ── public dispatch ──────────────────────────────────────────────────

fn html_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'html-parse' {
			s := html_arg_str(args[0]) or { return html_err_parse('non-string input') }
			roots := html_parse_roots(s)
			return cx.Element{
				name:  html_doc_root
				items: roots
			}
		}
		'html-parse-fragment' {
			s := html_arg_str(args[0]) or { return html_err_parse('non-string input') }
			roots := html_parse_roots(s)
			return cx.Element{
				name:  ''
				items: roots
			}
		}
		'html-serialize' {
			return html_serialize(args[0], false)
		}
		'html-serialize-xhtml' {
			return html_serialize(args[0], true)
		}
		'html-extract-text' {
			// Accepts either a raw HTML string (parse, then strip) or an
			// already-parsed CXDM element tree (the parse / serialize-round-
			// trip composition the conformance corpus exercises, §6).
			a0 := args[0]
			if a0 is cx.Element {
				mut parts := []string{}
				html_extract_collect(a0, mut parts)
				return html_str(parts.join(' '))
			}
			s := html_arg_str(a0) or { return html_err_parse('non-string input') }
			return html_extract_text(s)
		}
		'html-sanitize' {
			s := html_arg_str(args[0]) or { return html_err_parse('non-string input') }
			roots := html_parse_roots(s)
			tree := cx.Element{
				name:  html_doc_root
				items: roots
			}
			cleaned := html_sanitize_tree(tree, html_default_policy())
			return html_str(html_serialize_node(cleaned, false))
		}
		'html-sanitize-with-policy' {
			s := html_arg_str(args[0]) or { return html_err_parse('non-string input') }
			pol, errnode, is_err := html_read_policy(args[1])
			if is_err {
				return errnode
			}
			roots := html_parse_roots(s)
			tree := cx.Element{
				name:  html_doc_root
				items: roots
			}
			cleaned := html_sanitize_tree(tree, pol)
			return html_str(html_serialize_node(cleaned, false))
		}
		'html-sanitize-tree' {
			if args[0] !is cx.Element {
				return html_err_serialize('argument is not a CXDM element tree')
			}
			return html_sanitize_tree(args[0], html_default_policy())
		}
		'html-sanitize-tree-with-policy' {
			if args[0] !is cx.Element {
				return html_err_serialize('argument is not a CXDM element tree')
			}
			pol, errnode, is_err := html_read_policy(args[1])
			if is_err {
				return errnode
			}
			return html_sanitize_tree(args[0], pol)
		}
		else {
			return none
		}
	}
}

// ── bundled module source ────────────────────────────────────────────
//
// stdlib_src_html is the `cx-stdlib/html` [?def] surface (spec §3). Every
// body forwards to a native `html-`-prefixed primitive
// (html_stdlib_builtin, above); WHATWG parse / serialize / sanitize are
// not expressible in pure CX. All nine functions are pure (§2.4).
//
// NOTE: this const is $embed_file-d from stdlib/html.cx — edit that file.
const stdlib_src_html = $embed_file('../stdlib/html.cx').to_string()
