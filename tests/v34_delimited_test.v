module main

import cx

// Phase 7.67 — delimited V core smoke tests. The fuller
// conformance fixtures live in conformance/delimited.txt; these tests
// exercise the V-internal API directly to catch regressions early.

fn test_emit_table_basic() {
	src := '[users [table[name::string age::int active::bool]]
  alice 30 true
  bob 25 false
]'
	out := cx.to_csv(src) or { panic(err) }
	expected := 'name,age,active\r\nalice,30,true\r\nbob,25,false\r\n'
	assert out == expected
}

fn test_emit_repeated_row() {
	src := '[users
  [user id=1 name=alice admin=true]
  [user id=2 name=bob]
  [user id=3 name=carol admin=true]
]'
	out := cx.to_csv(src) or { panic(err) }
	expected := 'id,name,admin\r\n1,alice,true\r\n2,bob,\r\n3,carol,true\r\n'
	assert out == expected
}

fn test_emit_dotted_path() {
	src := '[config
  [server host=localhost port=8080 tls=true]
  [logging level=info format=json]
]'
	out := cx.to_csv(src) or { panic(err) }
	expected := 'server.host,server.port,server.tls,logging.level,logging.format\r\nlocalhost,8080,true,info,json\r\n'
	assert out == expected
}

fn test_emit_quote_when_needed() {
	src := "[t [table[name::string note::string]]
  alice 'hello, world'
  bob ok
]"
	out := cx.to_csv(src) or { panic(err) }
	expected := 'name,note\r\nalice,"hello, world"\r\nbob,ok\r\n'
	assert out == expected
}

fn test_emit_doublequote_doubling() {
	src := "[t [table[name::string note::string]]
  alice 'she said \"hi\"'
]"
	out := cx.to_csv(src) or { panic(err) }
	// Embedded `\"` is doubled; the whole field is quoted because it
	// contains `\"`.
	expected := 'name,note\r\nalice,"she said ""hi"""\r\n'
	assert out == expected
}

fn test_emit_tsv() {
	src := '[t [table[a b c]]
  x y z
]'
	out := cx.to_tsv(src) or { panic(err) }
	expected := 'a\tb\tc\r\nx\ty\tz\r\n'
	assert out == expected
}

fn test_parse_csv_basic() {
	csv_in := 'name,age,active\nalice,30,true\nbob,25,false\n'
	out := cx.from_csv(csv_in) or { panic(err) }
	// Auto-typing should narrow age → :int and active → :bool.
	expected := '[table [table[name age::int active::bool]]
  alice 30 true
  bob 25 false
]'
	assert out == expected
}

fn test_parse_csv_quoted_string_stays_string() {
	// Quoted "30" should NOT auto-type to int — quoting is the
	// explicit "this is a string" signal.
	csv_in := 'name,age\nalice,"30"\nbob,"25"\n'
	out := cx.from_csv(csv_in) or { panic(err) }
	expected := '[table [table[name age]]
  alice 30
  bob 25
]'
	assert out == expected
}

fn test_parse_csv_singlequote() {
	csv_in := "name,note\nalice,'hello, world'\n"
	out := cx.from_csv(csv_in) or { panic(err) }
	// Single-quoted field with embedded delimiter; emitted as a
	// quoted CX string because it contains comma + space.
	expected := "[table [table[name note]]
  alice 'hello, world'
]"
	assert out == expected
}

fn test_parse_csv_doublequote_doubling() {
	csv_in := 'name,note\nalice,"she said ""hi"""\n'
	out := cx.from_csv(csv_in) or { panic(err) }
	expected := "[table [table[name note]]
  alice 'she said \"hi\"'
]"
	assert out == expected
}

fn test_parse_csv_empty_cell_is_null() {
	csv_in := 'name,age\nalice,30\nbob,\n'
	out := cx.from_csv(csv_in) or { panic(err) }
	// age narrows to :int (null doesn't constrain the column type).
	expected := '[table [table[name age::int]]
  alice 30
  bob null
]'
	assert out == expected
}

fn test_parse_csv_crlf() {
	csv_in := 'a,b\r\n1,2\r\n3,4\r\n'
	out := cx.from_csv(csv_in) or { panic(err) }
	expected := '[table [table[a::int b::int]]
  1 2
  3 4
]'
	assert out == expected
}

fn test_roundtrip_table() {
	src := '[users [table[name::string age::int active::bool]]
  alice 30 true
  bob 25 false
]'
	csv_out := cx.to_csv(src) or { panic(err) }
	cx_back := cx.from_csv(csv_out) or { panic(err) }
	// Element name defaults to `table` on parse — original `users`
	// is not recoverable from CSV. Type narrowing
	// recovers the int/bool types.
	expected := '[table [table[name age::int active::bool]]
  alice 30 true
  bob 25 false
]'
	assert cx_back == expected
}

fn test_invalid_delimiter_errors() {
	if _ := cx.to_delimited('[t [table[a]]\n  x\n]', `"`) {
		assert false, 'expected error for double-quote delimiter'
	} else {
		assert true
	}
}

fn test_emit_psv() {
	src := '[t [table[a b]]
  x y
]'
	out := cx.to_psv(src) or { panic(err) }
	expected := 'a|b\r\nx|y\r\n'
	assert out == expected
}
