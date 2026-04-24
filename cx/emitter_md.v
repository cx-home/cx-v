module cx

// ── Markdown Emitter ──────────────────────────────────────────────────────────
//
// CX AST → Markdown output.
// Entry points: emit_md(doc Document) string
//               emit_md_docs(docs []Document) string

pub fn emit_md(doc Document) string {
	mut out := []string{}
	for n in doc.prolog {
		if n is CommentNode { continue }
	}
	for n in doc.elements {
		emit_md_top(n, mut out)
	}
	result := out.join('')
	return result.trim_right('\n')
}

pub fn emit_md_docs(docs []Document) string {
	parts := docs.map(emit_md(it))
	return parts.join('\n---\n')
}

fn emit_md_top(n Node, mut out []string) {
	match n {
		Element {
			e := n as Element
			if e.name == 'doc' || e.name == 'article' {
				if e.attrs.len > 0 {
					emit_md_yaml_frontmatter(e.attrs, mut out)
				}
				for child in e.items {
					emit_md_block(child, mut out)
				}
			} else {
				emit_md_block(n, mut out)
			}
		}
		else {
			emit_md_block(n, mut out)
		}
	}
}

fn emit_md_block(n Node, mut out []string) {
	match n {
		Element {
			e := n as Element
			match e.name {
				'h1' { out << '# ${emit_md_children_inline(e.items)}\n\n' }
				'h2' { out << '## ${emit_md_children_inline(e.items)}\n\n' }
				'h3' { out << '### ${emit_md_children_inline(e.items)}\n\n' }
				'h4' { out << '#### ${emit_md_children_inline(e.items)}\n\n' }
				'h5' { out << '##### ${emit_md_children_inline(e.items)}\n\n' }
				'h6' { out << '###### ${emit_md_children_inline(e.items)}\n\n' }
				'p'  { out << '${emit_md_children_inline(e.items)}\n\n' }
				'blockquote' { out << '> ${emit_md_children_inline(e.items)}\n\n' }
				'hr' { out << '---\n\n' }
				'br' { out << '\n' }
				'ul' {
					for child in e.items {
						if child is Element {
							ce := child as Element
							if ce.name == 'li' {
								out << '- ${emit_md_children_inline(ce.items)}\n'
							}
						}
					}
					out << '\n'
				}
				'ol' {
					mut num := 1
					for child in e.items {
						if child is Element {
							ce := child as Element
							if ce.name == 'li' {
								out << '${num}. ${emit_md_children_inline(ce.items)}\n'
								num++
							}
						}
					}
					out << '\n'
				}
				'code' {
					has_block := e.items.any(it is BlockContentNode || it is RawTextNode)
					if has_block {
						lang := find_attr_value(e.attrs, 'lang') or { '' }
						for item in e.items {
							if item is BlockContentNode {
								bc := item as BlockContentNode
								raw := md_block_content_text(bc)
								out << '\`\`\`${lang}\n${raw}\n\`\`\`\n\n'
							} else if item is RawTextNode {
								rt := item as RawTextNode
								out << '\`\`\`${lang}\n${rt.value}\n\`\`\`\n\n'
							}
						}
					} else {
						out << '\`${emit_md_children_inline(e.items)}\`\n\n'
					}
				}
				'a' {
					href := find_attr_value(e.attrs, 'href') or { '' }
					text := emit_md_children_inline(e.items)
					out << '[${text}](${href})\n\n'
				}
				'img' {
					src := find_attr_value(e.attrs, 'src') or { '' }
					alt := find_attr_value(e.attrs, 'alt') or { '' }
					out << '![${alt}](${src})\n\n'
				}
				'table' {
					for item in e.items {
						if item is BlockContentNode {
							bc := item as BlockContentNode
							raw := md_block_content_text(bc)
							out << '${raw}\n'
						} else if item is RawTextNode {
							rt := item as RawTextNode
							out << '${rt.value}\n'
						}
					}
					out << '\n'
				}
				'doc', 'article' {
					if e.attrs.len > 0 {
						emit_md_yaml_frontmatter(e.attrs, mut out)
					}
					for child in e.items {
						emit_md_block(child, mut out)
					}
				}
				'strong', 'b', 'em', 'i', 'del', 's', 'c',
				'sub', 'sup', 'u' {
					out << '${emit_md_inline(n)}\n\n'
				}
				else {
					out << '<!-- [${emit_md_unknown_element(e)}] -->\n\n'
				}
			}
		}
		TextNode {
			t := n as TextNode
			v := t.value.trim_space()
			if v.len > 0 {
				out << '${v}\n\n'
			}
		}
		CommentNode {
			c := n as CommentNode
			out << '<!--${c.value}-->\n\n'
		}
		else {}
	}
}

fn emit_md_children_inline(items []Node) string {
	mut parts := []string{}
	for item in items {
		parts << emit_md_inline(item)
	}
	return parts.join('')
}

fn emit_md_inline(n Node) string {
	match n {
		TextNode {
			return md_escape_text((n as TextNode).value)
		}
		Element {
			e := n as Element
			match e.name {
				'strong', 'b' { return '**${emit_md_children_inline(e.items)}**' }
				'em', 'i'     { return '*${emit_md_children_inline(e.items)}*' }
				'del', 's'    { return '~~${emit_md_children_inline(e.items)}~~' }
				'sub'         { return '~${emit_md_children_inline(e.items)}~' }
				'sup'         { return '^${emit_md_children_inline(e.items)}^' }
				'u'           { return '<u>${emit_md_children_inline(e.items)}</u>' }
				'code', 'c'   { return '\`${emit_md_children_inline(e.items)}\`' }
				'a' {
					href := find_attr_value(e.attrs, 'href') or { '' }
					text := emit_md_children_inline(e.items)
					return '[${text}](${href})'
				}
				'img' {
					src := find_attr_value(e.attrs, 'src') or { '' }
					alt := find_attr_value(e.attrs, 'alt') or { '' }
					return '![${alt}](${src})'
				}
				else {
					return '<!-- [${emit_md_unknown_element(e)}] -->'
				}
			}
		}
		ScalarNode {
			s := n as ScalarNode
			return match s.value {
				i64       { s.value.str() }
				f64       { format_float(s.value as f64) }
				bool      { if s.value as bool { 'true' } else { 'false' } }
				NullValue { 'null' }
				string    { s.value as string }
			}
		}
		else {
			return ''
		}
	}
}

fn emit_md_unknown_element(e Element) string {
	mut s := e.name
	if a := e.anchor { s += ' &${a}' }
	if m := e.merge  { s += ' *${m}' }
	for attr in e.attrs {
		s += ' ${attr.name}:${cx_quote_attr_if_needed(attr.str_value())}'
	}
	if e.items.len > 0 {
		s += ' ${emit_md_children_inline(e.items)}'
	}
	return s
}

fn md_block_content_text(bc BlockContentNode) string {
	mut parts := []string{}
	for item in bc.items {
		match item {
			TextNode     { parts << (item as TextNode).value }
			RawTextNode  { parts << '[#${(item as RawTextNode).value}#]' }
			Element {
				mut tmp := []string{}
				cx_emit_element(item as Element, 0, false, mut tmp)
				parts << tmp.join('').trim_right('\n')
			}
			else {}
		}
	}
	return parts.join('')
}

fn md_escape_text(s string) string {
	mut result := ''
	for ch in s.bytes() {
		result += match ch {
			`\\` { '\\\\' }
			else  { ch.ascii_str() }
		}
	}
	return result
}

fn emit_md_yaml_frontmatter(attrs []Attribute, mut out []string) {
	out << '---\n'
	for a in attrs {
		out << '${a.name}: ${a.str_value()}\n'
	}
	out << '---\n\n'
}
