module code

import os
import cx

// ── The schema registry re-ruled: hint-bindings over content identity
// (shape_inference.md §3, L63; validate.md §3.2/§7 discharged;
// stream 16 W4) ───────────────────────────────────────────────────────
//
// Names are HINTS, hashes are IDENTITY (the stream-19 address posture).
// `register-schema` / `[?schema-register]` put the schema's canonical
// text into the content registry and bind the local name to its
// content-hash. `validate-against` resolves name → hash → content,
// fail-closed at every hop (the 0x12 rule generalized): an unknown
// name, an unpinned hash, or store content that fails hash
// self-verification all raise CXER1600 — a poisoned store NEVER
// resolves. Resolution order: in-process bindings, then the module's
// cx.lock `[schemas]` pins. Content order: the in-process registry,
// then `CX_SCHEMA_STORE` (a content-addressed directory of .cxs
// files, sharded `<hex[..2]>/<hex>.cxs`; reads self-verify, writes
// are cache-writes — a failed write is a lost optimization only, the
// module-cache posture).

// schema_hash_hex computes the E2 schema content identity — sha-256
// over the STRICT-CANONICAL bytes (the same bytes cx_text_hash
// covers). The identity is canonical; the stored/registered CONTENT is
// the VERBATIM text — canonical data emission quote-protects ::T
// annotated tokens ([attr sku::string] → [attr 'sku::string ']),
// which is identity-preserving but not schema-semantics-preserving
// (#791), so canonical bytes are a hash basis, never a content
// carrier here.
fn schema_hash_hex(text string) !string {
	h := cx.schema_content_hash(text)!
	return h.hex()
}

fn schema_store_dir() string {
	return os.getenv('CX_SCHEMA_STORE')
}

fn schema_store_path(dir string, hash_hex string) string {
	return os.join_path(dir, hash_hex[..2], hash_hex + '.cxs')
}

// schema_store_write persists VERBATIM schema text under its
// canonical-bytes hash. Silent-degrade: the registry binding is the
// act; the store write is a shared-cache optimization
// (module_cache_store precedent).
fn schema_store_write(hash_hex string, text string) {
	dir := schema_store_dir()
	if dir == '' {
		return
	}
	path := schema_store_path(dir, hash_hex)
	if os.exists(path) {
		return
	}
	os.mkdir_all(os.dir(path)) or { return }
	os.write_file(path, text) or { return }
}

// schema_store_read fetches content by hash from CX_SCHEMA_STORE and
// SELF-VERIFIES it (recomputes the canonical-bytes hash over what was
// read — formatting-invariant, so any byte layout of the SAME
// canonical identity verifies) — content that fails verification is
// treated as absent, fail-closed.
fn schema_store_read(hash_hex string) ?string {
	dir := schema_store_dir()
	if dir == '' {
		return none
	}
	path := schema_store_path(dir, hash_hex)
	text := os.read_file(path) or { return none }
	actual := schema_hash_hex(text) or { return none }
	if actual != hash_hex {
		return none
	}
	return text
}

// schema_registry_register binds `name` to the schema's content-hash
// and retains the canonical text. Rebinding a name is allowed (a
// hint-binding, not an identity); the content entry is append-only by
// construction (keyed by its own hash). Returns the hash hex — the
// registration receipt.
fn schema_registry_register(mut env MatchEnv, name string, schema_text string) !string {
	hash_hex := schema_hash_hex(schema_text)!
	env.state.schema_bindings[name] = hash_hex
	env.state.schema_contents[hash_hex] = schema_text
	schema_store_write(hash_hex, schema_text)
	return hash_hex
}

// schema_registry_resolve_name resolves a name hint to a content-hash:
// in-process bindings first, then the module cx.lock `[schemas]` pins.
fn schema_registry_resolve_name(mut env MatchEnv, name string) ?string {
	if h := env.state.schema_bindings[name] {
		return h
	}
	module_lock_load(mut env.state.module_table) or { return none }
	if lf := env.state.module_table.lockfile {
		for p in lf.schemas {
			if p.name == name {
				return p.hash
			}
		}
	}
	return none
}

// schema_registry_resolve_content resolves a content-hash to schema
// text (verbatim): the in-process registry, then the self-verifying
// store.
fn schema_registry_resolve_content(mut env MatchEnv, hash_hex string) ?string {
	if t := env.state.schema_contents[hash_hex] {
		return t
	}
	return schema_store_read(hash_hex)
}

// eval_register_schema is the env-aware `register-schema` verb
// ($name::string $schema::any): the schema arg is a schema ELEMENT
// value (its canonical text is registered) or a STRING of schema text.
fn eval_register_schema(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: register-schema takes ($name::string $schema)')
	}
	name := val_arg_str(args[0]) or {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: register-schema $name must be a string')
	}
	text := schema_arg_text(args[1]) or {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: register-schema $schema must be a schema element or schema text')
	}
	hash_hex := schema_registry_register(mut env, name, text) or {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: register-schema: ${err.msg()}')
	}
	return cx.ScalarNode{
		value:     cx.ScalarValue(hash_hex)
		data_type: cx.ScalarType.string_type
	}
}

// schema_arg_text renders a schema argument to text: an element value
// emits as a one-element document; a string scalar is taken verbatim.
fn schema_arg_text(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
		return none
	}
	if n is cx.Element {
		return cx.emit_cx(cx.Document{ elements: [cx.Node(n)] })
	}
	return none
}

// eval_validate_against is the env-aware `validate-against`
// ($value::any $schema-ref::string): name → hash → content, then the
// content's OWN language decides the engine — a `[schema …]` root
// takes the validate.md inline-schema path (custom validators
// included); anything else is a `.cxs` data schema (schema.md) and
// takes cx.validate, its diagnostics mapped onto the §3.3 result
// vocabulary. Every resolution failure is CXER1600, with the failing
// hop named.
fn eval_validate_against(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER1600',
			'E_VALIDATE_SCHEMA_NOT_FOUND: validate-against takes ($value $schema-ref::string)')
	}
	name := val_arg_str(args[1]) or {
		return mk_err('cx-err:CXER1600',
			'E_VALIDATE_SCHEMA_NOT_FOUND: $schema-ref must be a string name')
	}
	hash_hex := schema_registry_resolve_name(mut env, name) or {
		return mk_err('cx-err:CXER1600',
			'E_VALIDATE_SCHEMA_NOT_FOUND: no schema registered or pinned under `${name}`')
	}
	text := schema_registry_resolve_content(mut env, hash_hex) or {
		return mk_err('cx-err:CXER1600',
			'E_VALIDATE_SCHEMA_NOT_FOUND: `${name}` resolves to ${hash_hex} but no content with that hash is available (registry, then CX_SCHEMA_STORE; store reads self-verify — mismatching content never resolves)')
	}
	return schema_validate_value_text(args[0], name, text, mut env)
}

// schema_validate_value_text validates a value against resolved schema
// content — the language dispatch shared by validate-against and the
// strict-mode E2 element-name enforcement (W5). The content's OWN root
// decides the engine; the result is the ONE [ok]/[invalid] vocabulary.
fn schema_validate_value_text(value cx.Node, name string, text string, mut env MatchEnv) cx.Node {
	doc := cx.parse(text) or {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: registered content under `${name}` does not parse: ${err.msg()}')
	}
	mut root := cx.Element{}
	mut found := false
	for n in doc.elements {
		if n is cx.Element {
			root = n
			found = true
			break
		}
	}
	if !found {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: registered content under `${name}` has no root element')
	}
	// Language dispatch: a .cxs HEADER is also spelled [schema …] but
	// REQUIRES of= (schema.md §2); the validate.md inline schema never
	// carries of=. The of= attribute is the discriminator.
	mut has_of := false
	for a in root.attrs {
		if a.name == 'of' {
			has_of = true
		}
	}
	if root.name == 'schema' && !has_of {
		// validate.md inline-schema language — the validate-shape path,
		// custom validators applied with env in scope.
		return validate_shape_with_env(value, root, mut env)
	}
	// .cxs data-schema language (schema.md): the value validates as a
	// one-element document. The value is round-tripped through its
	// canonical text first — runtime values carry evaluator-internal
	// node shapes (e.g. the __cx_seq__ marker) that the parse-level
	// validator does not read; text → parse restores the data shapes.
	vtext := render_canonical(value)
	vdoc := cx.parse(vtext) or {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: value does not round-trip as data for .cxs validation: ${err.msg()}')
	}
	rep := cx.validate(vdoc, text) or {
		return mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: registered .cxs under `${name}`: ${err.msg()}')
	}
	mut viols := []cx.Node{}
	for d in rep.diagnostics {
		viols << val_violation(d.code, '', '', '', d.message)
	}
	return val_result(viols, value)
}

// value_matches_type_env is the STRICT-mode type check with the env in
// scope (W5, L64): a top-level ELEMENT-NAME type whose name has a
// registered/pinned schema enforces by SCHEMA VALIDATION (the schema's
// own of= root subsumes the head match — the worked-example Order ↔
// [schema of=order] case); an unpinned element-name keeps W1's
// head-match; every other type shape takes the env-free structural
// walker. A pinned name whose CONTENT is unavailable fails CLOSED —
// under strict, a declared-and-pinned contract that cannot be checked
// is a mismatch, never a pass.
fn value_matches_type_env(n cx.Node, typ string, mut env MatchEnv) bool {
	t := typ.trim_space()
	if t == '' || t == 'any' {
		return true
	}
	te := cx.parse_type_expr(t) or { return true }
	if te.kind == .element_name {
		tname := te.name or { '' }
		if hash_hex := schema_registry_resolve_name(mut env, tname) {
			text := schema_registry_resolve_content(mut env, hash_hex) or { return false }
			r := schema_validate_value_text(n, tname, text, mut env)
			if r is cx.Element {
				return r.name == 'ok'
			}
			return false
		}
	}
	return value_matches_type_expr(n, te)
}

// The `[?schema-register]` DIRECTIVE spelling named by validate.md §7's
// deferral is retired-before-birth: the closed §4.1 registry (grammar
// [127e]) is one-form-per-act (the 'chain'-alias retirement precedent),
// and registration is a stdlib act, not a language form — the
// `register-schema` verb is THE spelling. W7's validate.md §7 sweep
// states the discharge.
