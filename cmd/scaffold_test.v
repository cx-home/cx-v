module main

import cx

// Round-trip guard for the `cx scaffold` templates (#306, #448): every kind
// must parse as current CX, carry NO retired surface forms, and yield the
// INTENDED typed values. The retired `:table[…]` form parsed as a raw-text
// blob (zero tables, #306), and the retired single-colon type annotations
// (`port:u16=8080`, `[date :date …]`) parse as namespace-qualified names on
// the current surface (lexicon.ebnf [L50]/[L51]) — `cx --json` showed a
// `"port:u16"` KEY instead of a u16-typed `port` (#448). These tests pin the
// scaffold to live syntax at the AST level; vcx/tests/scaffold_cli_test.v
// drives the built binary over the same templates.

fn scaffold_kinds() map[string]string {
	return {
		'config': scaffold_config
		'data':   scaffold_data
		'doc':    scaffold_doc
		'log':    scaffold_log
		'table':  scaffold_table
	}
}

// Scalar type names that the RETIRED single-colon annotation could glue.
// On the current surface a type is glued with a DOUBLE colon (`::u16`); a
// single glued colon is the namespace qualifier.
const retired_glued_types = ['u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'f16', 'f32',
	'f64', 'int', 'float', 'bool', 'decimal', 'bigint', 'date', 'datetime', 'time', 'atom',
	'bytes', 'string', 'null']

// first_single_colon_type returns the first retired single-colon type
// annotation (`name:type=…`, `[name :type …]`) found in src, or none.
// A `::` (current surface) never matches: the first colon is skipped because
// the NEXT char is a colon, the second because the PREVIOUS char is one.
fn first_single_colon_type(src string) ?string {
	for i := 0; i < src.len; i++ {
		if src[i] != `:` {
			continue
		}
		if i > 0 && src[i - 1] == `:` {
			continue
		}
		if i + 1 < src.len && src[i + 1] == `:` {
			continue
		}
		rest := src[i + 1..]
		for t in retired_glued_types {
			if !rest.starts_with(t) {
				continue
			}
			j := i + 1 + t.len
			if j >= src.len {
				return src[i..]
			}
			nc := src[j]
			// token must END after the type name to read as an annotation
			if nc == `=` || nc == ` ` || nc == `]` || nc == `[` || nc == `\n` {
				return src[i..j]
			}
		}
	}
	return none
}

// root_element finds the first root element named `name` (documents may
// carry top-level comments alongside the element roots).
fn root_element(doc cx.Document, name string) ?cx.Element {
	for n in doc.elements {
		if n is cx.Element {
			if n.name == name {
				return n
			}
		}
	}
	return none
}

fn attr_of(e cx.Element, name string) ?cx.Attribute {
	for a in e.attrs {
		if a.name == name {
			return a
		}
	}
	return none
}

fn test_scaffold_templates_parse() {
	for kind, tpl in scaffold_kinds() {
		cx.parse(tpl) or {
			assert false, 'scaffold ${kind} template no longer parses: ${err.msg()}'
		}
	}
}

fn test_scaffold_templates_carry_no_retired_surface() {
	for kind, tpl in scaffold_kinds() {
		assert !tpl.contains(':table['), 'scaffold ${kind} carries the retired :table[ block form'
		if hit := first_single_colon_type(tpl) {
			assert false, 'scaffold ${kind} carries a retired single-colon type annotation: `${hit}` (current surface glues types with `::`)'
		}
	}
}

fn test_scaffold_config_typed_attrs() {
	doc := cx.parse(scaffold_config) or {
		assert false, 'scaffold config no longer parses: ${err.msg()}'
		return
	}
	cfg := root_element(doc, 'config') or {
		assert false, 'scaffold config has no [config] root'
		return
	}
	assert cfg.attr('env') == 'dev', 'env must parse as an ATTRIBUTE of [config], got "${cfg.attr('env')}"'
	srv := cfg.get('server') or {
		assert false, 'scaffold config has no [server] child'
		return
	}
	port := attr_of(srv, 'port') or {
		assert false, 'server carries no `port` attribute — a retired single-colon annotation parses as a `port:u16` namespace-qualified name'
		return
	}
	assert port.data_type() or { '' } == 'u16', 'port must be ::u16 typed'
	assert srv.attr('port') == '8080'
	assert !srv.has_attr('port:u16')
	db := cfg.get('database') or {
		assert false, 'scaffold config has no [database] child'
		return
	}
	pool := attr_of(db, 'pool_size') or {
		assert false, 'database carries no `pool_size` attribute'
		return
	}
	assert pool.data_type() or { '' } == 'u8', 'pool_size must be ::u8 typed'
	timeout := attr_of(db, 'connect_timeout_ms') or {
		assert false, 'database carries no `connect_timeout_ms` attribute'
		return
	}
	assert timeout.data_type() or { '' } == 'u32', 'connect_timeout_ms must be ::u32 typed'
}

fn test_scaffold_data_typed_prices() {
	doc := cx.parse(scaffold_data) or {
		assert false, 'scaffold data no longer parses: ${err.msg()}'
		return
	}
	catalog := root_element(doc, 'catalog') or {
		assert false, 'scaffold data has no [catalog] root'
		return
	}
	products := catalog.get_all('product')
	assert products.len == 3
	for p in products {
		price := attr_of(p, 'price') or {
			assert false, 'product carries no `price` attribute — a retired single-colon annotation parses as a `price:decimal` namespace-qualified name'
			return
		}
		assert price.data_type() or { '' } == 'decimal', 'price must be ::decimal typed'
		assert !p.has_attr('price:decimal')
	}
}

fn test_scaffold_doc_typed_date() {
	doc := cx.parse(scaffold_doc) or {
		assert false, 'scaffold doc no longer parses: ${err.msg()}'
		return
	}
	article := root_element(doc, 'article') or {
		assert false, 'scaffold doc has no [article] root'
		return
	}
	date_el := article.get('date') or {
		assert false, 'scaffold doc has no [date] child'
		return
	}
	assert date_el.data_type() or { '' } == 'date', 'date element must be ::date typed — the retired `[date :date …]` form parses `:date` as a child token'
}

fn test_scaffold_log_events() {
	doc := cx.parse(scaffold_log) or {
		assert false, 'scaffold log no longer parses: ${err.msg()}'
		return
	}
	mut events := []cx.Element{}
	for n in doc.elements {
		if n is cx.Element {
			events << n
		}
	}
	assert events.len == 3, 'scaffold log must parse as three logfmt event roots'
	assert events[0].attr('level') == 'info'
	assert events[1].attr('slow') == 'true'
	assert events[2].attr('err') == 'connection refused'
}

fn test_scaffold_table_round_trips_through_table_api() {
	tables := cx.tables_from_cx(scaffold_table) or {
		assert false, 'tables_from_cx on scaffold table: ${err.msg()}'
		return
	}
	assert tables.len == 1
	assert tables[0].row_count() == 3
	assert tables[0].col_count() == 5
	assert tables[0].cols() == ['id', 'name', 'age', 'city', 'email']
	types := tables[0].types()
	assert types[0] == 'int'
	assert types[2] == 'int'
}

fn test_scaffold_doc_embedded_table_round_trips() {
	tables := cx.tables_from_cx(scaffold_doc) or {
		assert false, 'tables_from_cx on scaffold doc: ${err.msg()}'
		return
	}
	assert tables.len == 1
	assert tables[0].row_count() == 3
	assert tables[0].cols() == ['metric', 'value']
}
