module cx

// ── Streaming event types ─────────────────────────────────────────────────────

pub type StreamEvent = StreamStartDoc
	| StreamEndDoc
	| StreamStartElement
	| StreamEndElement
	| StreamText
	| StreamScalar
	| StreamComment
	| StreamPI
	| StreamEntityRef
	| StreamRawText
	| StreamAlias

pub struct StreamStartDoc {}
pub struct StreamEndDoc {}

pub struct StreamStartElement {
pub:
	name      string
	attrs     []Attribute
	data_type ?string
	anchor    ?string
	merge     ?string
}

pub struct StreamEndElement {
pub:
	name string
}

pub struct StreamText {
pub:
	value string
}

pub struct StreamScalar {
pub:
	data_type string
	value     ScalarValue
}

pub struct StreamComment {
pub:
	value string
}

pub struct StreamPI {
pub:
	target string
	data   ?string
}

pub struct StreamEntityRef {
pub:
	name string
}

pub struct StreamRawText {
pub:
	value string
}

pub struct StreamAlias {
pub:
	name string
}

// ── Stream — pull-model event stream ─────────────────────────────────────────

pub struct Stream {
mut:
	events []StreamEvent
	pos    int
}

// new_stream parses CX input and returns a Stream ready for next() calls.
pub fn new_stream(input string) !Stream {
	doc := parse(input)!
	return new_stream_from_doc(doc)
}

// new_stream_from_doc creates a Stream from a pre-parsed Document.
pub fn new_stream_from_doc(doc Document) Stream {
	mut events := []StreamEvent{}
	events << StreamStartDoc{}
	for n in doc.prolog {
		collect_node_events(n, mut events)
	}
	for n in doc.elements {
		collect_node_events(n, mut events)
	}
	events << StreamEndDoc{}
	return Stream{ events: events, pos: 0 }
}

// next returns the next event, or none when exhausted.
pub fn (mut s Stream) next() ?StreamEvent {
	if s.pos >= s.events.len {
		return none
	}
	e := s.events[s.pos]
	s.pos++
	return e
}

// collect drains all remaining events into a slice.
pub fn (mut s Stream) collect() []StreamEvent {
	result := s.events[s.pos..]
	s.pos = s.events.len
	return result
}

// ── DOM walker ────────────────────────────────────────────────────────────────

fn collect_node_events(n Node, mut events []StreamEvent) {
	match n {
		Element {
			events << StreamStartElement{
				name:      n.name
				attrs:     n.attrs
				data_type: n.data_type
				anchor:    n.anchor
				merge:     n.merge
			}
			for child in n.items {
				collect_node_events(child, mut events)
			}
			events << StreamEndElement{ name: n.name }
		}
		TextNode {
			events << StreamText{ value: n.value }
		}
		ScalarNode {
			events << StreamScalar{
				data_type: scalar_type_name(n.data_type)
				value:     n.value
			}
		}
		CommentNode {
			events << StreamComment{ value: n.value }
		}
		PINode {
			events << StreamPI{ target: n.target, data: n.data }
		}
		EntityRefNode {
			events << StreamEntityRef{ name: n.name }
		}
		RawTextNode {
			events << StreamRawText{ value: n.value }
		}
		AliasNode {
			events << StreamAlias{ name: n.name }
		}
		BlockContentNode {
			for item in n.items {
				collect_node_events(item, mut events)
			}
		}
		// XMLDeclNode, CXDirectiveNode, DTD nodes — skip
		else {}
	}
}

// ── JSON serialisation for C ABI ──────────────────────────────────────────────

pub fn event_to_json(e StreamEvent) string {
	return match e {
		StreamStartDoc {
			'{"type":"StartDoc"}'
		}
		StreamEndDoc {
			'{"type":"EndDoc"}'
		}
		StreamStartElement {
			mut pairs := []string{}
			pairs << '"type":"StartElement"'
			pairs << '"name":${json_str(e.name)}'
			pairs << '"attrs":${json_attrs(e.attrs)}'
			if dt := e.data_type { pairs << '"dataType":${json_str(dt)}' }
			if a  := e.anchor    { pairs << '"anchor":${json_str(a)}' }
			if m  := e.merge     { pairs << '"merge":${json_str(m)}' }
			'{${pairs.join(',')}}'
		}
		StreamEndElement {
			'{"type":"EndElement","name":${json_str(e.name)}}'
		}
		StreamText {
			'{"type":"Text","value":${json_str(e.value)}}'
		}
		StreamScalar {
			v := json_scalar_value(e.value)
			'{"type":"Scalar","dataType":${json_str(e.data_type)},"value":${v}}'
		}
		StreamComment {
			'{"type":"Comment","value":${json_str(e.value)}}'
		}
		StreamPI {
			mut pairs := []string{}
			pairs << '"type":"PI"'
			pairs << '"target":${json_str(e.target)}'
			if d := e.data { pairs << '"data":${json_str(d)}' }
			'{${pairs.join(',')}}'
		}
		StreamEntityRef {
			'{"type":"EntityRef","name":${json_str(e.name)}}'
		}
		StreamRawText {
			'{"type":"RawText","value":${json_str(e.value)}}'
		}
		StreamAlias {
			'{"type":"Alias","name":${json_str(e.name)}}'
		}
	}
}
