module cx

// ── ScalarValue string conversion ──────────────────────────────────────────────

// str returns the CX string representation of a ScalarValue.
pub fn (v ScalarValue) str() string {
	return scalar_value_str(v)
}

// ── Element navigation ─────────────────────────────────────────────────────────

// get returns the first direct child Element with the given name.
pub fn (e Element) get(name string) ?Element {
	for item in e.items {
		if item is Element && item.name == name {
			return item
		}
	}
	return none
}

// get_all returns all direct child Elements with the given name.
pub fn (e Element) get_all(name string) []Element {
	mut result := []Element{}
	for item in e.items {
		if item is Element && item.name == name {
			result << item
		}
	}
	return result
}

// attr returns the string value of the named attribute, or '' if absent.
pub fn (e Element) attr(name string) string {
	for a in e.attrs {
		if a.name == name {
			return scalar_value_str(a.value)
		}
	}
	return ''
}

// has_attr returns true if the element has an attribute with the given name.
pub fn (e Element) has_attr(name string) bool {
	for a in e.attrs {
		if a.name == name {
			return true
		}
	}
	return false
}

// attr_val returns the typed value of the named attribute, or none if absent.
fn (e Element) attr_val(name string) ?ScalarValue {
	for a in e.attrs {
		if a.name == name {
			return a.value
		}
	}
	return none
}

// text returns the concatenated text and scalar child content.
pub fn (e Element) text() string {
	mut parts := []string{}
	for item in e.items {
		match item {
			TextNode   { parts << item.value }
			ScalarNode { parts << scalar_value_str(item.value) }
			else       {}
		}
	}
	return parts.join(' ')
}

// scalar returns the value of the first ScalarNode child, or none.
pub fn (e Element) scalar() ?ScalarValue {
	for item in e.items {
		if item is ScalarNode {
			return item.value
		}
	}
	return none
}

// children returns all direct child Elements (excludes text, scalar, and other nodes).
pub fn (e Element) children() []Element {
	mut result := []Element{}
	for item in e.items {
		if item is Element {
			result << item
		}
	}
	return result
}

// find_all returns all descendant Elements with the given name (depth-first).
pub fn (e Element) find_all(name string) []Element {
	mut result := []Element{}
	for item in e.items {
		if item is Element {
			if item.name == name {
				result << item
			}
			result << item.find_all(name)
		}
	}
	return result
}

// find_first returns the first descendant Element with the given name.
pub fn (e Element) find_first(name string) ?Element {
	for item in e.items {
		if item is Element {
			if item.name == name {
				return item
			}
			if found := item.find_first(name) {
				return found
			}
		}
	}
	return none
}

// at navigates by slash-separated path from this element: el.at('server/host').
pub fn (e Element) at(path string) ?Element {
	parts := path.split('/').filter(it.len > 0)
	if parts.len == 0 {
		return none
	}
	mut cur := e.get(parts[0]) or { return none }
	for part in parts[1..] {
		cur = cur.get(part) or { return none }
	}
	return cur
}

// set_attr upserts an attribute value.
pub fn (mut e Element) set_attr(name string, value ScalarValue) {
	for i, a in e.attrs {
		if a.name == name {
			e.attrs[i].value = value
			return
		}
	}
	e.attrs << Attribute{ name: name, value: value }
}

// remove_attr removes an attribute by name.
pub fn (mut e Element) remove_attr(name string) {
	e.attrs = e.attrs.filter(it.name != name)
}

// append adds a child node at the end.
pub fn (mut e Element) append(node Node) {
	e.items << node
}

// prepend inserts a child node at position 0.
pub fn (mut e Element) prepend(node Node) {
	e.items.insert(0, node)
}

// insert inserts a child node at the given index.
pub fn (mut e Element) insert(index int, node Node) {
	if index >= e.items.len {
		e.items << node
	} else {
		e.items.insert(index, node)
	}
}

// remove_at removes the child node at the given index.
pub fn (mut e Element) remove_at(index int) {
	if index < 0 || index >= e.items.len {
		return
	}
	e.items.delete(index)
}

// remove_child removes all direct child Elements with the given name.
pub fn (mut e Element) remove_child(name string) {
	mut new_items := []Node{}
	for item in e.items {
		if item is Element && item.name == name {
			continue
		}
		new_items << item
	}
	e.items = new_items
}

// ── Document navigation ───────────────────────────────────────────────────────

// root returns the first top-level Element.
pub fn (d Document) root() ?Element {
	for e in d.elements {
		if e is Element {
			return e
		}
	}
	return none
}

// get returns the first top-level Element with the given name.
pub fn (d Document) get(name string) ?Element {
	for e in d.elements {
		if e is Element && e.name == name {
			return e
		}
	}
	return none
}

// at navigates by slash-separated path from the first matching top-level element.
pub fn (d Document) at(path string) ?Element {
	parts := path.split('/').filter(it.len > 0)
	if parts.len == 0 {
		return d.root()
	}
	mut cur := d.get(parts[0]) or { return none }
	for part in parts[1..] {
		cur = cur.get(part) or { return none }
	}
	return cur
}

// find_first returns the first descendant Element with the given name.
pub fn (d Document) find_first(name string) ?Element {
	for e in d.elements {
		if e is Element {
			if e.name == name {
				return e
			}
			if found := e.find_first(name) {
				return found
			}
		}
	}
	return none
}

// find_all returns all descendant Elements with the given name.
pub fn (d Document) find_all(name string) []Element {
	mut result := []Element{}
	for e in d.elements {
		if e is Element {
			if e.name == name {
				result << e
			}
			result << e.find_all(name)
		}
	}
	return result
}

// append adds a top-level node.
pub fn (mut d Document) append(node Node) {
	d.elements << node
}

// prepend inserts a top-level node at position 0.
pub fn (mut d Document) prepend(node Node) {
	d.elements.insert(0, node)
}

// to_cx serializes the document to canonical CX.
pub fn (d Document) to_cx() string {
	return emit_cx(d)
}

// to_xml serializes the document to XML.
pub fn (d Document) to_xml() !string {
	return emit_xml(d)
}

// to_json serializes the document to JSON.
pub fn (d Document) to_json() !string {
	return emit_semantic_json(d)
}

// to_yaml serializes the document to YAML.
pub fn (d Document) to_yaml() !string {
	return emit_yaml(d)
}

// to_toml serializes the document to TOML.
pub fn (d Document) to_toml() !string {
	return emit_toml(d)
}

// to_md serializes the document to Markdown.
pub fn (d Document) to_md() !string {
	return emit_md(d)
}

// ── Stream convenience ────────────────────────────────────────────────────────

// stream parses CX source and returns all events.
pub fn stream(src string) ![]StreamEvent {
	mut s := new_stream(src)!
	return s.collect()
}
