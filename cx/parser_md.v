module cx

// ── Markdown → CX AST parser ──────────────────────────────────────────────────
//
// Entry point: pub fn parse_md_cx(src string) !ParseResult
//
// Block parsing is line-by-line state machine. Inline parsing uses a recursive
// marker-based approach. The result is wrapped in a doc element.

pub fn parse_md_cx(src string) !ParseResult {
	doc := parse_md_document(src)!
	return ParseResult{ single: doc, is_multi: false }
}

fn parse_md_document(src string) !Document {
	lines := src.split('\n')
	mut idx := 0

	// YAML frontmatter — only when a closing '---' or '...' exists after line 0
	mut fm_attrs := []Attribute{}
	has_fm_close := lines[1..].any(it.trim_space() == '---' || it.trim_space() == '...')
	if lines.len > 0 && lines[0].trim_space() == '---' && has_fm_close {
		idx = 1
		mut fm_lines := []string{}
		for idx < lines.len {
			line := lines[idx]
			idx++
			if line.trim_space() == '---' || line.trim_space() == '...' {
				break
			}
			fm_lines << line
		}
		fm_attrs = parse_yaml_frontmatter(fm_lines)
	}

	// Parse block elements
	mut block_nodes := []Node{}
	for idx < lines.len {
		node, new_idx := parse_md_block(lines, idx)
		idx = new_idx
		if node_val := node {
			block_nodes << node_val
		}
	}

	doc_elem := Element{
		name:  'doc'
		attrs: fm_attrs
		items: block_nodes
	}

	return Document{ elements: [Node(doc_elem)] }
}

fn parse_yaml_frontmatter(lines []string) []Attribute {
	mut attrs := []Attribute{}
	for line in lines {
		colon_idx := line.index(':') or { continue }
		key := line[..colon_idx].trim_space()
		val := line[colon_idx + 1..].trim_space()
		if key.len > 0 {
			attrs << Attribute{ name: key, value: ScalarValue(val), data_type: none }
		}
	}
	return attrs
}

// parse_md_block parses one block element starting at lines[idx].
// Returns (optional node, new_idx). new_idx is the next line to process.
fn parse_md_block(lines []string, idx int) (?Node, int) {
	if idx >= lines.len {
		return none, idx
	}
	line := lines[idx]
	trimmed := line.trim_space()

	// Blank line — skip
	if trimmed.len == 0 {
		return none, idx + 1
	}

	// ATX headings: # ## ### #### ##### ######
	if trimmed.starts_with('#') {
		mut level := 0
		for level < trimmed.len && trimmed[level] == `#` {
			level++
		}
		if level <= 6 && level < trimmed.len && trimmed[level] == ` ` {
			text := trimmed[level + 1..]
			elem_name := 'h${level}'
			inline_nodes := parse_md_inline(text)
			elem := Element{ name: elem_name, items: inline_nodes }
			return Node(elem), idx + 1
		}
	}

	// Fenced code block: ```lang
	if trimmed.starts_with('```') {
		lang := trimmed[3..].trim_space()
		mut code_lines := []string{}
		mut new_idx := idx + 1
		for new_idx < lines.len {
			l := lines[new_idx]
			new_idx++
			if l.trim_space().starts_with('```') {
				break
			}
			code_lines << l
		}
		code_text := code_lines.join('\n')
		mut attrs := []Attribute{}
		if lang.len > 0 {
			attrs << Attribute{ name: 'lang', value: ScalarValue(lang), data_type: none }
		}
		// Use RawTextNode ([#..#]) unless content contains #] which would
		// prematurely terminate it. In that case use BlockContentNode ([|..|])
		// which re-parses inner [..] as CX — correct for lang=cx blocks.
		code_item := if code_text.contains('#]') {
			Node(BlockContentNode{ items: [Node(TextNode{ value: code_text })] })
		} else {
			Node(RawTextNode{ value: code_text })
		}
		elem := Element{ name: 'code', attrs: attrs, items: [code_item] }
		return Node(elem), new_idx
	}

	// Horizontal rule: --- or *** or ___ (3+ chars, all same)
	if is_md_hr(trimmed) {
		elem := Element{ name: 'hr' }
		return Node(elem), idx + 1
	}

	// Blockquote: > text
	if trimmed.starts_with('> ') {
		text := trimmed[2..]
		inline_nodes := parse_md_inline(text)
		elem := Element{ name: 'blockquote', items: inline_nodes }
		return Node(elem), idx + 1
	}
	if trimmed == '>' {
		elem := Element{ name: 'blockquote', items: [] }
		return Node(elem), idx + 1
	}

	// Unordered list: collect consecutive - / * / + items
	if trimmed.len >= 2 && (trimmed[0] == `-` || trimmed[0] == `*` || trimmed[0] == `+`) && trimmed[1] == ` ` {
		mut li_nodes := []Node{}
		mut new_idx := idx
		for new_idx < lines.len {
			l := lines[new_idx].trim_space()
			if l.len >= 2 && (l[0] == `-` || l[0] == `*` || l[0] == `+`) && l[1] == ` ` {
				item_text := l[2..]
				inline_nodes := parse_md_inline(item_text)
				li_elem := Element{ name: 'li', items: inline_nodes }
				li_nodes << Node(li_elem)
				new_idx++
			} else if l.trim_space().len == 0 {
				new_idx++
				break
			} else {
				break
			}
		}
		ul_elem := Element{ name: 'ul', items: li_nodes }
		return Node(ul_elem), new_idx
	}

	// Ordered list: N. text
	if is_md_ol_item(trimmed) {
		mut li_nodes := []Node{}
		mut new_idx := idx
		for new_idx < lines.len {
			l := lines[new_idx].trim_space()
			if is_md_ol_item(l) {
				dot_idx := l.index('. ') or { break }
				item_text := l[dot_idx + 2..]
				inline_nodes := parse_md_inline(item_text)
				li_elem := Element{ name: 'li', items: inline_nodes }
				li_nodes << Node(li_elem)
				new_idx++
			} else if l.trim_space().len == 0 {
				new_idx++
				break
			} else {
				break
			}
		}
		ol_elem := Element{ name: 'ol', items: li_nodes }
		return Node(ol_elem), new_idx
	}

	// Pipe table: lines starting with |
	if trimmed.starts_with('|') {
		mut table_lines := []string{}
		mut new_idx := idx
		for new_idx < lines.len {
			l := lines[new_idx].trim_space()
			if l.starts_with('|') {
				table_lines << lines[new_idx]
				new_idx++
			} else if l.len == 0 {
				new_idx++
				break
			} else {
				break
			}
		}
		raw_content := table_lines.join('\n')
		table_elem := Element{ name: 'table', items: [Node(RawTextNode{ value: raw_content })] }
		return Node(table_elem), new_idx
	}

	// HTML comment: <!-- ... --> — possibly CX element
	if trimmed.starts_with('<!--') && trimmed.ends_with('-->') {
		inner := trimmed[4..trimmed.len - 3].trim_space()
		if inner.starts_with('[') {
			// Try to parse as CX
			if cx_result := parse_cx(inner) {
				if cx_doc := cx_result.single {
					if cx_doc.elements.len > 0 {
						return cx_doc.elements[0], idx + 1
					}
				}
			}
		}
		// Keep as comment
		comment_val := trimmed[4..trimmed.len - 3]
		return Node(CommentNode{ value: comment_val }), idx + 1
	}

	// Paragraph: collect consecutive non-blank non-special lines
	mut para_lines := []string{}
	mut new_idx := idx
	for new_idx < lines.len {
		l := lines[new_idx]
		lt := l.trim_space()
		if lt.len == 0 {
			new_idx++
			break
		}
		// Stop if the next line starts a new block type
		if lt.starts_with('#') || lt.starts_with('```') || lt.starts_with('>') ||
		   is_md_hr(lt) || is_md_list_item(lt) || lt.starts_with('|') ||
		   (lt.starts_with('<!--') && lt.ends_with('-->')) {
			break
		}
		para_lines << lt
		new_idx++
	}
	if para_lines.len == 0 {
		return none, idx + 1
	}
	full_text := para_lines.join(' ')
	inline_nodes := parse_md_inline(full_text)
	p_elem := Element{ name: 'p', items: inline_nodes }
	return Node(p_elem), new_idx
}

fn is_md_hr(s string) bool {
	if s.len < 3 { return false }
	ch := s[0]
	if ch != `-` && ch != `*` && ch != `_` { return false }
	for b in s.bytes() {
		if b != ch && b != ` ` { return false }
	}
	mut count := 0
	for b in s.bytes() {
		if b == ch { count++ }
	}
	return count >= 3
}

fn is_md_ol_item(s string) bool {
	if s.len < 3 { return false }
	mut i := 0
	for i < s.len && s[i] >= `0` && s[i] <= `9` {
		i++
	}
	if i == 0 { return false }
	if i >= s.len { return false }
	if s[i] != `.` { return false }
	if i + 1 >= s.len { return false }
	return s[i + 1] == ` `
}

fn is_md_list_item(s string) bool {
	if s.len >= 2 && (s[0] == `-` || s[0] == `*` || s[0] == `+`) && s[1] == ` ` {
		return true
	}
	return is_md_ol_item(s)
}

// ── Inline parser ─────────────────────────────────────────────────────────────

fn parse_md_inline(src string) []Node {
	nodes, _ := parse_md_inline_inner(src, 0, '')
	return nodes
}

// parse_md_inline_inner parses inline content from src[start..], stopping when
// the closing marker is found (or end of string). Returns (nodes, end_pos).
fn parse_md_inline_inner(src string, start int, stop_marker string) ([]Node, int) {
	mut nodes := []Node{}
	mut text_buf := ''
	mut i := start

	for i < src.len {
		// Check stop marker
		if stop_marker.len > 0 && i + stop_marker.len <= src.len &&
		   src[i..i + stop_marker.len] == stop_marker {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			return nodes, i + stop_marker.len
		}

		b := src[i]

		// *** bold+italic
		if b == `*` && i + 2 < src.len && src[i + 1] == `*` && src[i + 2] == `*` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 3, '***')
			if end > i + 3 {
				em_elem := Element{ name: 'em', items: inner_nodes }
				strong_elem := Element{ name: 'strong', items: [Node(em_elem)] }
				nodes << strong_elem
				i = end
				continue
			}
			text_buf += '***'
			i += 3
			continue
		}

		// ** bold
		if b == `*` && i + 1 < src.len && src[i + 1] == `*` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 2, '**')
			if end > i + 2 {
				strong_elem := Element{ name: 'strong', items: inner_nodes }
				nodes << strong_elem
				i = end
				continue
			}
			text_buf += '**'
			i += 2
			continue
		}

		// * italic
		if b == `*` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 1, '*')
			if end > i + 1 {
				em_elem := Element{ name: 'em', items: inner_nodes }
				nodes << em_elem
				i = end
				continue
			}
			text_buf += '*'
			i++
			continue
		}

		// ~~ strikethrough
		if b == `~` && i + 1 < src.len && src[i + 1] == `~` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 2, '~~')
			if end > i + 2 {
				del_elem := Element{ name: 'del', items: inner_nodes }
				nodes << del_elem
				i = end
				continue
			}
			text_buf += '~~'
			i += 2
			continue
		}

		// ~ subscript
		if b == `~` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 1, '~')
			if end > i + 1 {
				sub_elem := Element{ name: 'sub', items: inner_nodes }
				nodes << sub_elem
				i = end
				continue
			}
			text_buf += '~'
			i++
			continue
		}

		// ^ superscript
		if b == `^` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 1, '^')
			if end > i + 1 {
				sup_elem := Element{ name: 'sup', items: inner_nodes }
				nodes << sup_elem
				i = end
				continue
			}
			text_buf += '^'
			i++
			continue
		}

		// __ underline (note: in standard MD __ is bold, but we map it to u per design)
		if b == `_` && i + 1 < src.len && src[i + 1] == `_` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			inner_nodes, end := parse_md_inline_inner(src, i + 2, '__')
			if end > i + 2 {
				u_elem := Element{ name: 'u', items: inner_nodes }
				nodes << u_elem
				i = end
				continue
			}
			text_buf += '__'
			i += 2
			continue
		}

		// ` inline code
		if b == `\`` {
			if text_buf.len > 0 {
				nodes << TextNode{ value: text_buf }
				text_buf = ''
			}
			mut j := i + 1
			mut code_text := ''
			for j < src.len && src[j] != `\`` {
				code_text += src[j..j + 1]
				j++
			}
			if j < src.len {
				code_elem := Element{ name: 'code', items: [Node(TextNode{ value: code_text })] }
				nodes << code_elem
				i = j + 1
			} else {
				text_buf += '\`'
				i++
			}
			continue
		}

		// ![alt](url) image
		if b == `!` && i + 1 < src.len && src[i + 1] == `[` {
			// find matching ]
			mut j := i + 2
			mut alt := ''
			for j < src.len && src[j] != `]` {
				alt += src[j..j + 1]
				j++
			}
			if j < src.len && j + 1 < src.len && src[j + 1] == `(` {
				// find closing )
				mut k := j + 2
				mut url := ''
				for k < src.len && src[k] != `)` {
					url += src[k..k + 1]
					k++
				}
				if k < src.len {
					if text_buf.len > 0 {
						nodes << TextNode{ value: text_buf }
						text_buf = ''
					}
					img_attrs := [
						Attribute{ name: 'src', value: ScalarValue(url), data_type: none },
						Attribute{ name: 'alt', value: ScalarValue(alt), data_type: none },
					]
					img_elem := Element{ name: 'img', attrs: img_attrs }
					nodes << img_elem
					i = k + 1
					continue
				}
			}
		}

		// [text](url) link
		if b == `[` {
			mut j := i + 1
			mut link_text := ''
			mut depth := 1
			for j < src.len && depth > 0 {
				if src[j] == `[` { depth++ }
				if src[j] == `]` { depth-- }
				if depth > 0 { link_text += src[j..j + 1] }
				j++
			}
			if j < src.len && src[j] == `(` {
				mut k := j + 1
				mut url := ''
				for k < src.len && src[k] != `)` {
					url += src[k..k + 1]
					k++
				}
				if k < src.len {
					if text_buf.len > 0 {
						nodes << TextNode{ value: text_buf }
						text_buf = ''
					}
					link_inner := parse_md_inline(link_text)
					a_attrs := [Attribute{ name: 'href', value: ScalarValue(url), data_type: none }]
					a_elem := Element{ name: 'a', attrs: a_attrs, items: link_inner }
					nodes << a_elem
					i = k + 1
					continue
				}
			}
		}

		// regular character
		text_buf += src[i..i + 1]
		i++
	}

	if text_buf.len > 0 {
		nodes << TextNode{ value: text_buf }
	}
	return nodes, i
}
