module main

import cx

// Tests for the Phase 2.12 Part 3 `[?lib]` parser.
//
// Covers the three resolver-kind shapes (file / registered / HTTPS),
// the `:as ALIAS` and `:only (NAMES…)` modifiers, and the parse-time
// validations enumerated in lib_parser.v (CXLIB_PARSE /
// CXLIB_UNKNOWN_MODIFIER / CXLIB_INSECURE_TRANSPORT).

// ── Positive coverage — resolver kinds ────────────────────────────────────────

fn test_parse_lib_file_path_dot_slash() {
	n := cx.parse_lib("[?lib './local-helpers.cx']") or {
		panic('expected parse success, got: ${err}')
	}
	assert n.resolver_kind == cx.ResolverKind.file_path
	assert n.resolver_source == './local-helpers.cx'
	assert n.alias == none
	assert n.only_imports == none
}

fn test_parse_lib_file_path_dot_dot_slash() {
	n := cx.parse_lib("[?lib '../shared/utils.cx']")!
	assert n.resolver_kind == cx.ResolverKind.file_path
	assert n.resolver_source == '../shared/utils.cx'
}

fn test_parse_lib_file_path_absolute() {
	n := cx.parse_lib("[?lib '/usr/local/share/cx/foo.cx']")!
	assert n.resolver_kind == cx.ResolverKind.file_path
	assert n.resolver_source == '/usr/local/share/cx/foo.cx'
}

fn test_parse_lib_registered_name_stdlib() {
	n := cx.parse_lib("[?lib 'cx-stdlib/strings']")!
	assert n.resolver_kind == cx.ResolverKind.registered_name
	assert n.resolver_source == 'cx-stdlib/strings'
}

fn test_parse_lib_registered_name_github() {
	n := cx.parse_lib("[?lib 'github.com/example/regex-helpers']")!
	assert n.resolver_kind == cx.ResolverKind.registered_name
	assert n.resolver_source == 'github.com/example/regex-helpers'
}

fn test_parse_lib_https_url() {
	n := cx.parse_lib("[?lib 'https://cdn.example.com/regex-1.2.3.zip']")!
	assert n.resolver_kind == cx.ResolverKind.https_url
	assert n.resolver_source == 'https://cdn.example.com/regex-1.2.3.zip'
}

fn test_parse_lib_double_quoted() {
	n := cx.parse_lib('[?lib "cx-stdlib/json"]')!
	assert n.resolver_kind == cx.ResolverKind.registered_name
	assert n.resolver_source == 'cx-stdlib/json'
}

// ── Positive coverage — :as modifier ──────────────────────────────────────────

fn test_parse_lib_with_as() {
	n := cx.parse_lib("[?lib 'github.com/example/regex-helpers' :as regex]")!
	assert n.resolver_kind == cx.ResolverKind.registered_name
	assert n.resolver_source == 'github.com/example/regex-helpers'
	got_alias := n.alias or { '' }
	assert got_alias == 'regex'
	assert n.only_imports == none
}

fn test_parse_lib_with_as_on_file_path() {
	n := cx.parse_lib("[?lib './helpers.cx' :as h]")!
	assert n.resolver_kind == cx.ResolverKind.file_path
	got_alias := n.alias or { '' }
	assert got_alias == 'h'
}

// ── Positive coverage — :only modifier ────────────────────────────────────────

fn test_parse_lib_with_only_single() {
	n := cx.parse_lib("[?lib 'cx-stdlib/strings' :only (trim)]")!
	assert n.resolver_kind == cx.ResolverKind.registered_name
	got_only := n.only_imports or { panic('expected only_imports set') }
	assert got_only == ['trim']
}

fn test_parse_lib_with_only_multiple() {
	n := cx.parse_lib("[?lib 'cx-stdlib/strings' :only (trim split join)]")!
	got_only := n.only_imports or { panic('expected only_imports set') }
	assert got_only == ['trim', 'split', 'join']
}

fn test_parse_lib_with_only_extra_whitespace() {
	n := cx.parse_lib("[?lib 'cx-stdlib/strings' :only (  trim  split  )]")!
	got_only := n.only_imports or { panic('expected only_imports set') }
	assert got_only == ['trim', 'split']
}

// ── Positive coverage — :as + :only together ─────────────────────────────────

fn test_parse_lib_with_as_and_only() {
	n := cx.parse_lib("[?lib 'cx-stdlib/strings' :as strs :only (trim split)]")!
	got_alias := n.alias or { '' }
	assert got_alias == 'strs'
	got_only := n.only_imports or { panic('expected only_imports set') }
	assert got_only == ['trim', 'split']
}

fn test_parse_lib_with_only_then_as() {
	// Order-independence between :as and :only modifiers.
	n := cx.parse_lib("[?lib 'cx-stdlib/strings' :only (trim split) :as strs]")!
	got_alias := n.alias or { '' }
	assert got_alias == 'strs'
	got_only := n.only_imports or { panic('expected only_imports set') }
	assert got_only == ['trim', 'split']
}

// ── Source + loc preservation ────────────────────────────────────────────────

fn test_parse_lib_source_and_loc_preserved() {
	src := "[?lib 'cx-stdlib/json']"
	n := cx.parse_lib(src)!
	got_src := n.source or { '' }
	assert got_src == src
	got_loc := n.loc or { cx.LibLoc{} }
	assert got_loc.start == 0
	assert got_loc.end == src.len
}

// ── Error coverage — missing / malformed shape ───────────────────────────────

fn test_parse_lib_missing_prefix_fails() {
	cx.parse_lib("'cx-stdlib/json'") or {
		assert err.msg().starts_with('CXLIB_PARSE'), 'got: ${err}'
		return
	}
	assert false, 'expected error for missing prefix'
}

fn test_parse_lib_wrong_directive_fails() {
	cx.parse_lib("[?libx 'cx-stdlib/json']") or {
		assert err.msg().starts_with('CXLIB_PARSE'), 'got: ${err}'
		return
	}
	assert false, 'expected error for [?libx …]'
}

fn test_parse_lib_missing_resolver_fails() {
	cx.parse_lib('[?lib]') or {
		assert err.msg().contains('missing resolver'), 'got: ${err}'
		return
	}
	assert false, 'expected error for missing resolver'
}

fn test_parse_lib_empty_resolver_fails() {
	cx.parse_lib("[?lib '']") or {
		assert err.msg().contains('empty resolver'), 'got: ${err}'
		return
	}
	assert false, 'expected error for empty resolver'
}

fn test_parse_lib_unquoted_resolver_fails() {
	cx.parse_lib('[?lib cx-stdlib/json]') or {
		assert err.msg().contains('quoted'), 'got: ${err}'
		return
	}
	assert false, 'expected error for unquoted resolver'
}

fn test_parse_lib_unterminated_resolver_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/json") or {
		assert err.msg().contains('unterminated'), 'got: ${err}'
		return
	}
	assert false, 'expected error for unterminated resolver'
}

fn test_parse_lib_missing_closing_bracket_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/json'") or {
		assert err.msg().starts_with('CXLIB_PARSE'), 'got: ${err}'
		return
	}
	assert false, 'expected error for missing closing ]'
}

// ── Error coverage — insecure transport ──────────────────────────────────────

fn test_parse_lib_http_refused() {
	cx.parse_lib("[?lib 'http://insecure.example.com/foo.cx']") or {
		assert err.msg().starts_with('CXLIB_INSECURE_TRANSPORT'), 'got: ${err}'
		return
	}
	assert false, 'expected error for http:// resolver'
}

// ── Error coverage — modifiers ───────────────────────────────────────────────

fn test_parse_lib_unknown_modifier_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/json' :foo bar]") or {
		assert err.msg().starts_with('CXLIB_UNKNOWN_MODIFIER'), 'got: ${err}'
		return
	}
	assert false, 'expected CXLIB_UNKNOWN_MODIFIER'
}

fn test_parse_lib_in_memory_modifier_unknown_at_v0_8_0() {
	// reserves the slot but Phase 2.12 Part 3 surfaces it
	// as CXLIB_UNKNOWN_MODIFIER per file-level comment in lib_parser.v.
	cx.parse_lib("[?lib 'cx-stdlib/json' :in-memory]") or {
		assert err.msg().starts_with('CXLIB_UNKNOWN_MODIFIER'), 'got: ${err}'
		return
	}
	assert false, 'expected CXLIB_UNKNOWN_MODIFIER for :in-memory'
}

fn test_parse_lib_duplicate_as_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/json' :as j1 :as j2]") or {
		assert err.msg().contains('duplicate :as'), 'got: ${err}'
		return
	}
	assert false, 'expected duplicate :as error'
}

fn test_parse_lib_duplicate_only_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/strings' :only (trim) :only (split)]") or {
		assert err.msg().contains('duplicate :only'), 'got: ${err}'
		return
	}
	assert false, 'expected duplicate :only error'
}

fn test_parse_lib_as_missing_name_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/json' :as]") or {
		assert err.msg().contains(':as missing alias'), 'got: ${err}'
		return
	}
	assert false, 'expected :as missing alias error'
}

fn test_parse_lib_only_missing_paren_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/strings' :only trim split]") or {
		assert err.msg().contains(':only missing opening'), 'got: ${err}'
		return
	}
	assert false, 'expected :only missing opening paren error'
}

fn test_parse_lib_only_empty_list_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/strings' :only ()]") or {
		assert err.msg().contains(':only requires at least one name'), 'got: ${err}'
		return
	}
	assert false, 'expected :only empty list error'
}

fn test_parse_lib_only_unclosed_paren_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/strings' :only (trim split]") or {
		assert err.msg().starts_with('CXLIB_PARSE'), 'got: ${err}'
		return
	}
	assert false, 'expected unterminated :only list error'
}

// ── Trailing-input rejection ─────────────────────────────────────────────────

fn test_parse_lib_trailing_input_fails() {
	cx.parse_lib("[?lib 'cx-stdlib/json'] junk") or {
		assert err.msg().contains('unexpected trailing input'), 'got: ${err}'
		return
	}
	assert false, 'expected trailing input error'
}
