module cx

// transform returns a new Document with the element at path replaced by f(original).
// If the path does not exist, returns the original document unchanged.
pub fn (d Document) transform(path string, f fn (Element) Element) Document {
	parts := path.split('/').filter(it.len > 0)
	if parts.len == 0 {
		return d
	}
	for i, node in d.elements {
		if node is Element && node.name == parts[0] {
			if parts.len == 1 {
				return transform_doc_replace_at(d, i, f(transform_elem_detached(node)))
			}
			if updated := transform_path_copy(node, parts[1..], f) {
				return transform_doc_replace_at(d, i, updated)
			}
			return d
		}
	}
	return d
}

// transform_all applies f to every element matching the CXPath expression and
// returns a new Document. Invalid expressions panic.
pub fn (d Document) transform_all(expr string, f fn (Element) Element) Document {
	cx_expr := cxpath_parse(expr)
	mut new_elements := []Node{cap: d.elements.len}
	for node in d.elements {
		new_elements << transform_rebuild_node(node, cx_expr, f)
	}
	return Document{
		prolog:   d.prolog
		doctype:  d.doctype
		elements: new_elements
	}
}

fn transform_elem_detached(e Element) Element {
	return Element{
		name:      e.name
		anchor:    e.anchor
		merge:     e.merge
		data_type: e.data_type
		attrs:     e.attrs.clone()
		items:     e.items
	}
}

fn transform_doc_replace_at(d Document, idx int, el Element) Document {
	mut new_elements := []Node{cap: d.elements.len}
	for i, n in d.elements {
		if i == idx {
			new_elements << Node(el)
		} else {
			new_elements << n
		}
	}
	return Document{
		prolog:   d.prolog
		doctype:  d.doctype
		elements: new_elements
	}
}

fn transform_path_copy(e Element, parts []string, f fn (Element) Element) ?Element {
	for i, item in e.items {
		if item is Element && item.name == parts[0] {
			if parts.len == 1 {
				return transform_elem_replace_at(e, i, f(transform_elem_detached(item)))
			}
			if updated := transform_path_copy(item, parts[1..], f) {
				return transform_elem_replace_at(e, i, updated)
			}
			return none
		}
	}
	return none
}

fn transform_elem_replace_at(e Element, idx int, child Element) Element {
	mut new_items := []Node{cap: e.items.len}
	for i, n in e.items {
		if i == idx {
			new_items << Node(child)
		} else {
			new_items << n
		}
	}
	return Element{
		name:      e.name
		anchor:    e.anchor
		merge:     e.merge
		data_type: e.data_type
		attrs:     e.attrs
		items:     new_items
	}
}

fn transform_rebuild_node(node Node, expr CXPathExpr, f fn (Element) Element) Node {
	if node !is Element {
		return node
	}
	el := node as Element
	mut new_items := []Node{cap: el.items.len}
	for item in el.items {
		new_items << transform_rebuild_node(item, expr, f)
	}
	new_el := Element{
		name:      el.name
		anchor:    el.anchor
		merge:     el.merge
		data_type: el.data_type
		attrs:     el.attrs
		items:     new_items
	}
	if cxpath_elem_matches(new_el, expr) {
		return Node(f(transform_elem_detached(new_el)))
	}
	return Node(new_el)
}
