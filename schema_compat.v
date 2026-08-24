module cx

// cx schema compat — the L149 three-valued compatibility predicate as a
// shipped Ring-0 verb (spec/03-approved/core/schema.md §16.5, RULED: SEA-1;
// spec/03-approved/core/schema_event_evolution.md §5).
//
// schema_compat classifies EVERY field-level change between two schema
// declaration forms into the closed §16.5.1 class set, derives the
// translator (the Lane-2 [schema-lineage] claim carrying its [derived …]
// rules as data — §16.5.2) for the mechanically-derivable classes, and
// refuses — with a specific prompt naming the missing rule per change —
// for the reinterpreting classes.
//
// Sound-refusal-first riders (the SEA-1 ledger):
//   SEA-1a — a rename is DECLARED (opts.renames), never guessed; the
//            undeclared candidate pair is named in the refusal prompt.
//   SEA-1b — the derived rules rewrite exactly the entries declaring
//            schema= OLD; pass NEW and schema-less entries; REFUSE any
//            address unknown to the chain. Lossless by construction:
//            the seam applies field-level surgery natively — never
//            enumerate-and-rebuild.
//   SEA-1c — removal refuses by default; opts.allow_remove acknowledges a
//            field-level drop (payload rewriting, never a shred).
//   SEA-1g — the translator is DATA ([?modify] is ruled impure, so a
//            generated pure def cannot spell a lossless rewrite); the
//            journal seam applies [derived] rules natively (journal.md
//            §3.9, the derived-chain form).
//
// Ring 0: no evaluator — pure functions over parse_schema's SchemaModel.
// Determinism: sorted iteration everywhere; the same schema pair plus the
// same declarations yields a byte-identical translator document.

pub struct SchemaCompatOpts {
pub:
	renames      map[string]string // 'TYPE/OLD' -> 'NEW' (attrs and elems)
	allow_remove []string          // 'TYPE/FIELD' acknowledged drops
}

pub struct SchemaChange {
pub:
	class     string // additive-optional | additive-default | default-changed | rename | widen | narrow | remove | reinterpret
	type_name string
	field     string // attr/elem name ('' for type-level / header changes)
	detail    string // human-readable sentence (what changed)
	prompt    string // refusal classes only: the specific missing rule
	// derivation payload (derivable classes only):
	action   string // '' | rename-attr | rename-elem | set-default | drop-attr | drop-elem
	old_name string
	new_name string
	value    string // raw literal to materialize (set-default)
	vtype    string // the declared type of `value` (set-default)
}

pub struct SchemaCompatReport {
pub mut:
	from_addr     string // sha2-256:<hex> of the old schema
	to_addr       string
	root          string // the NEW schema's root element name (of=)
	verdict       string // identical | derivable | refused
	changes       []SchemaChange
	upcaster_name string
	translator    string // the derived upcaster document text ('' unless derivable with rewrites, or identical)
}

// is_refusal_class reports whether a class stops the change.
fn is_refusal_class(class string) bool {
	return class in ['narrow', 'remove', 'reinterpret']
}

// schema_compat is the entry point: classify old→new, derive or refuse.
pub fn schema_compat(old_text string, new_text string, opts SchemaCompatOpts) !SchemaCompatReport {
	old_sm := parse_schema(old_text)!
	new_sm := parse_schema(new_text)!
	old_hash := schema_content_hash(old_text)!
	new_hash := schema_content_hash(new_text)!
	mut rep := SchemaCompatReport{
		from_addr: 'sha2-256:' + old_hash.hex()
		to_addr:   'sha2-256:' + new_hash.hex()
		root:      new_sm.root
	}
	if rep.from_addr == rep.to_addr {
		rep.verdict = 'identical'
		return rep
	}
	mut changes := []SchemaChange{}
	// header-level: root + mode.
	if old_sm.root != new_sm.root {
		changes << SchemaChange{
			class:     'reinterpret'
			type_name: old_sm.root
			detail:    "root element changed: of=${old_sm.root} -> of=${new_sm.root}"
			prompt:    "the root element changed from '${old_sm.root}' to '${new_sm.root}' — a different document species is a different meaning; author a [schema-lineage] claim with a hand-written upcaster (relation :split or :merge) if old data is to be carried"
		}
	}
	if old_sm.mode != new_sm.mode {
		om := int(old_sm.mode)
		nm := int(new_sm.mode)
		if nm < om {
			changes << SchemaChange{
				class:     'widen'
				type_name: new_sm.root
				field:     'mode'
				detail:    'mode loosened: ${old_sm.mode} -> ${new_sm.mode}'
			}
		} else {
			changes << SchemaChange{
				class:     'narrow'
				type_name: new_sm.root
				field:     'mode'
				detail:    'mode tightened: ${old_sm.mode} -> ${new_sm.mode}'
				prompt:    "mode tightened from ${old_sm.mode} to ${new_sm.mode} — previously-tolerated undeclared content becomes a diagnostic; declare the undeclared vocabulary in the new schema, or author a claim acknowledging the tightening"
			}
		}
	}
	// type-level walk, sorted for determinism.
	mut tnames := []string{}
	for k, _ in old_sm.types {
		tnames << k
	}
	for k, _ in new_sm.types {
		if k !in old_sm.types {
			tnames << k
		}
	}
	tnames.sort()
	for tn in tnames {
		in_old := tn in old_sm.types
		in_new := tn in new_sm.types
		if in_new && !in_old {
			changes << SchemaChange{
				class:     'additive-optional'
				type_name: tn
				detail:    'new type declaration [${tn}] — existing documents never reference it'
			}
			continue
		}
		if in_old && !in_new {
			changes << SchemaChange{
				class:     'remove'
				type_name: tn
				detail:    'type declaration [${tn}] removed'
				prompt:    "type '${tn}' was removed — data of this type loses its vocabulary; author a [schema-lineage] claim with a hand-written upcaster carrying (or lawfully retiring) it (type removal has no --allow-remove acknowledgment)"
			}
			continue
		}
		ot := old_sm.types[tn] or { SchemaType{} }
		nt := new_sm.types[tn] or { SchemaType{} }
		compat_type(tn, ot, nt, opts, mut changes)
	}
	// verdict + derivation.
	mut refused := false
	for c in changes {
		if is_refusal_class(c.class) && c.prompt != '' {
			refused = true
		}
	}
	rep.changes = changes
	if refused {
		rep.verdict = 'refused'
		return rep
	}
	rep.verdict = 'derivable'
	rep.upcaster_name = 'upcast-${old_hash.hex()[..8]}-to-${new_hash.hex()[..8]}'
	rep.translator = derive_translator(rep, new_sm)
	return rep
}

// compat_type classifies one shared type declaration's field-level deltas.
fn compat_type(tn string, ot SchemaType, nt SchemaType, opts SchemaCompatOpts, mut changes []SchemaChange) {
	// declared renames landing in this type: OLD -> NEW.
	mut renamed_from := map[string]string{} // old name -> new name
	mut renamed_to := map[string]bool{}     // new names that are rename targets
	for k, v in opts.renames {
		if k.contains('/') && k.all_before('/') == tn {
			renamed_from[k.all_after('/')] = v
			renamed_to[v] = true
		}
	}
	allow := fn [opts] (tn string, f string) bool {
		return '${tn}/${f}' in opts.allow_remove
	}
	// ── attributes ──────────────────────────────────────────────────────────
	mut anames := sorted_key_union_attr(ot.attrs, nt.attrs)
	for an in anames {
		in_old := an in ot.attrs
		in_new := an in nt.attrs
		oa := ot.attrs[an] or { AttrRule{} }
		if in_old && !in_new {
			if nn := renamed_from[an] {
				if nn in nt.attrs {
					na := nt.attrs[nn] or { AttrRule{} }
					changes << SchemaChange{
						class:     'rename'
						type_name: tn
						field:     an
						detail:    "attribute '${an}' renamed to '${nn}' (declared)"
						action:    'rename-attr'
						old_name:  an
						new_name:  nn
					}
					// the renamed pair still compares rule-vs-rule.
					compat_attr_rules(tn, nn, oa, na, mut changes)
				} else {
					changes << SchemaChange{
						class:     'reinterpret'
						type_name: tn
						field:     an
						detail:    "declared rename target '${nn}' does not exist on [${tn}]"
						prompt:    "--rename ${tn}/${an}=${nn} names a target the new schema does not declare — fix the declaration"
					}
				}
				continue
			}
			if allow(tn, an) {
				changes << SchemaChange{
					class:     'remove'
					type_name: tn
					field:     an
					detail:    "attribute '${an}' removed (acknowledged via --allow-remove)"
					action:    'drop-attr'
					old_name:  an
				}
				continue
			}
			// name the rename candidate when exactly one same-shaped attr was added.
			mut cand := ''
			mut cand_n := 0
			for nn2, na2 in nt.attrs {
				if nn2 !in ot.attrs && nn2 !in renamed_to && attr_rule_shape_eq(oa, na2) {
					cand = nn2
					cand_n++
				}
			}
			mut prompt := "attribute '${an}' on [${tn}] was removed — dropping a field loses data; acknowledge with --allow-remove ${tn}/${an}, or author a [schema-lineage] claim with a hand-written upcaster"
			if cand_n == 1 {
				prompt = "attribute '${an}' on [${tn}] was removed and '${cand}' (same declared shape) was added — if this is a rename, declare --rename ${tn}/${an}=${cand}; if a genuine remove+add, acknowledge with --allow-remove ${tn}/${an}"
			}
			changes << SchemaChange{
				class:     'remove'
				type_name: tn
				field:     an
				detail:    "attribute '${an}' removed"
				prompt:    prompt
			}
			continue
		}
		if in_new && !in_old {
			if an in renamed_to {
				continue // handled with its rename source
			}
			na := nt.attrs[an] or { AttrRule{} }
			if na.has_def {
				changes << SchemaChange{
					class:     'additive-default'
					type_name: tn
					field:     an
					detail:    "new attribute '${an}' with [default ${na.def_value}]"
					action:    'set-default'
					new_name:  an
					value:     na.def_value
					vtype:     na.type_name
				}
			} else if !na.required {
				changes << SchemaChange{
					class:     'additive-optional'
					type_name: tn
					field:     an
					detail:    "new optional attribute '${an}'"
				}
			} else {
				changes << SchemaChange{
					class:     'narrow'
					type_name: tn
					field:     an
					detail:    "new required attribute '${an}' (no default)"
					prompt:    "new required attribute '${an}' on [${tn}] has no derivation from old data — [req] addition is breaking even in open mode (L149); add a [default …], make it [opt], or author a [schema-lineage] claim with a hand-written upcaster that computes it"
				}
			}
			continue
		}
		// present in both — rule-vs-rule.
		na := nt.attrs[an] or { AttrRule{} }
		compat_attr_rules(tn, an, oa, na, mut changes)
	}
	// ── child elements ──────────────────────────────────────────────────────
	mut enames := sorted_key_union_elem(ot.elems, nt.elems)
	for en in enames {
		in_old := en in ot.elems
		in_new := en in nt.elems
		oe := ot.elems[en] or { ElemRule{} }
		if in_old && !in_new {
			if nn := renamed_from[en] {
				if nn in nt.elems {
					changes << SchemaChange{
						class:     'rename'
						type_name: tn
						field:     en
						detail:    "child element '${en}' renamed to '${nn}' (declared)"
						action:    'rename-elem'
						old_name:  en
						new_name:  nn
					}
					ne := nt.elems[nn] or { ElemRule{} }
					compat_elem_rules(tn, nn, oe, ne, mut changes)
				} else {
					changes << SchemaChange{
						class:     'reinterpret'
						type_name: tn
						field:     en
						detail:    "declared rename target '${nn}' does not exist on [${tn}]"
						prompt:    "--rename ${tn}/${en}=${nn} names a child the new schema does not declare — fix the declaration"
					}
				}
				continue
			}
			if allow(tn, en) {
				changes << SchemaChange{
					class:     'remove'
					type_name: tn
					field:     en
					detail:    "child element '${en}' removed (acknowledged via --allow-remove)"
					action:    'drop-elem'
					old_name:  en
				}
				continue
			}
			changes << SchemaChange{
				class:     'remove'
				type_name: tn
				field:     en
				detail:    "child element '${en}' removed"
				prompt:    "child element '${en}' on [${tn}] was removed — dropping a child loses data; acknowledge with --allow-remove ${tn}/${en}, or author a [schema-lineage] claim with a hand-written upcaster"
			}
			continue
		}
		if in_new && !in_old {
			if en in renamed_to {
				continue
			}
			ne := nt.elems[en] or { ElemRule{} }
			if ne.min == 0 {
				changes << SchemaChange{
					class:     'additive-optional'
					type_name: tn
					field:     en
					detail:    "new optional child element '${en}'"
				}
			} else {
				changes << SchemaChange{
					class:     'narrow'
					type_name: tn
					field:     en
					detail:    "new required child element '${en}' (min ${ne.min})"
					prompt:    "new required child element '${en}' on [${tn}] has no derivation from old data — give it [card \"0..N\"], or author a [schema-lineage] claim with a hand-written upcaster that synthesizes it"
				}
			}
			continue
		}
		ne := nt.elems[en] or { ElemRule{} }
		compat_elem_rules(tn, en, oe, ne, mut changes)
	}
	// ── body shape ──────────────────────────────────────────────────────────
	compat_body_rules(tn, ot.body, nt.body, mut changes)
	// ── ordering constraint ─────────────────────────────────────────────────
	if ot.child_order_strict != nt.child_order_strict {
		if nt.child_order_strict {
			changes << SchemaChange{
				class:     'narrow'
				type_name: tn
				field:     'ordering'
				detail:    '[check ordering=strict] added'
				prompt:    "[${tn}] gained [check ordering=strict] — previously-valid child orders become diagnostics; drop the constraint or author a claim acknowledging the tightening"
			}
		} else {
			changes << SchemaChange{
				class:     'widen'
				type_name: tn
				field:     'ordering'
				detail:    '[check ordering=strict] removed'
			}
		}
	}
}

// attr_rule_shape_eq: same declared shape (used only for rename-candidate naming).
fn attr_rule_shape_eq(a AttrRule, b AttrRule) bool {
	return a.type_name == b.type_name && a.required == b.required && a.pat == b.pat
		&& a.enum_vals == b.enum_vals && a.range_min == b.range_min && a.range_max == b.range_max
		&& a.len_min == b.len_min && a.len_max == b.len_max && a.members == b.members
}

// compat_attr_rules compares one attribute's old rule against its new rule.
fn compat_attr_rules(tn string, an string, oa AttrRule, na AttrRule, mut changes []SchemaChange) {
	// declared type.
	if oa.type_name != na.type_name || oa.members != na.members {
		if type_widens(oa.type_name, oa.members, na.type_name, na.members) {
			changes << SchemaChange{
				class:     'widen'
				type_name: tn
				field:     an
				detail:    "type widened: ${type_text(oa)} -> ${type_text(na)}"
			}
		} else {
			changes << SchemaChange{
				class:     'reinterpret'
				type_name: tn
				field:     an
				detail:    "type changed: ${type_text(oa)} -> ${type_text(na)}"
				prompt:    "attribute '${an}' on [${tn}] changed type ${type_text(oa)} -> ${type_text(na)} — outside the join lattice this is a different value model; author a [schema-lineage] claim with a hand-written upcaster that converts the values"
			}
		}
	}
	// requiredness.
	if oa.required && !na.required {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     an
			detail:    "'${an}' [req] -> [opt]"
		}
	} else if !oa.required && na.required {
		changes << SchemaChange{
			class:     'narrow'
			type_name: tn
			field:     an
			detail:    "'${an}' [opt] -> [req]"
			prompt:    "attribute '${an}' on [${tn}] became required — [req] addition is breaking even in open mode (L149): old data may omit it; add a [default …] instead, or author a claim with an upcaster that computes it"
		}
	}
	// defaults.
	if oa.has_def && na.has_def && oa.def_value != na.def_value {
		changes << SchemaChange{
			class:     'default-changed'
			type_name: tn
			field:     an
			detail:    "default changed: ${oa.def_value} -> ${na.def_value} (old default materialized on old data)"
			action:    'set-default'
			new_name:  an
			value:     oa.def_value
			vtype:     oa.type_name
		}
	} else if oa.has_def && !na.has_def {
		if na.required {
			changes << SchemaChange{
				class:     'narrow'
				type_name: tn
				field:     an
				detail:    "default removed and '${an}' became required"
				prompt:    "attribute '${an}' on [${tn}] lost its default and became required — old data relying on the materialized default now refuses; keep a [default …] or author a claim with an upcaster"
			}
		} else {
			changes << SchemaChange{
				class:     'default-changed'
				type_name: tn
				field:     an
				detail:    "default removed (old default materialized on old data so its meaning survives)"
				action:    'set-default'
				new_name:  an
				value:     oa.def_value
			vtype:     oa.type_name
			}
		}
	} else if !oa.has_def && na.has_def {
		changes << SchemaChange{
			class:     'reinterpret'
			type_name: tn
			field:     an
			detail:    "a default was added to existing attribute '${an}'"
			prompt:    "attribute '${an}' on [${tn}] gained [default ${na.def_value}] — old data's ABSENT values now materialize to ${na.def_value}, a new meaning no translator can preserve (absence cannot be materialized); if the re-meaning is intended, author a [schema-lineage] claim saying so"
		}
	}
	// enum.
	compat_enum(tn, an, oa.enum_vals, na.enum_vals, mut changes)
	// range / length.
	compat_bounds(tn, an, 'range', oa.range_min, oa.range_max, na.range_min, na.range_max, mut changes)
	compat_bounds(tn, an, 'len', oa.len_min, oa.len_max, na.len_min, na.len_max, mut changes)
	// pattern.
	compat_pattern(tn, an, oa.pat, na.pat, mut changes)
}

fn compat_elem_rules(tn string, en string, oe ElemRule, ne ElemRule, mut changes []SchemaChange) {
	if oe.type_name != ne.type_name {
		changes << SchemaChange{
			class:     'reinterpret'
			type_name: tn
			field:     en
			detail:    "child element '${en}' retargeted: ::${oe.type_name} -> ::${ne.type_name}"
			prompt:    "child element '${en}' on [${tn}] now names a different type declaration — a different shape for the same name is a different meaning; author a claim with a hand-written upcaster"
		}
		return
	}
	old_max_txt := if oe.max_unbounded { '*' } else { oe.max.str() }
	new_max_txt := if ne.max_unbounded { '*' } else { ne.max.str() }
	widened := ne.min <= oe.min && (ne.max_unbounded || (!oe.max_unbounded && ne.max >= oe.max))
	narrowed := ne.min > oe.min || (!ne.max_unbounded && (oe.max_unbounded || ne.max < oe.max))
	if oe.min == ne.min && oe.max_unbounded == ne.max_unbounded && oe.max == ne.max {
		return
	}
	if widened && !narrowed {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     en
			detail:    "cardinality widened: ${oe.min}..${old_max_txt} -> ${ne.min}..${new_max_txt}"
		}
	} else {
		changes << SchemaChange{
			class:     'narrow'
			type_name: tn
			field:     en
			detail:    "cardinality narrowed: ${oe.min}..${old_max_txt} -> ${ne.min}..${new_max_txt}"
			prompt:    "child element '${en}' on [${tn}] narrowed its cardinality ${oe.min}..${old_max_txt} -> ${ne.min}..${new_max_txt} — old data may violate it; widen the card, or author a claim with an upcaster that reshapes the children"
		}
	}
}

fn compat_body_rules(tn string, ob BodyRule, nb BodyRule, mut changes []SchemaChange) {
	if ob.kind != nb.kind || ob.item_kind != nb.item_kind || ob.key_kind != nb.key_kind {
		if body_widens(ob, nb) {
			changes << SchemaChange{
				class:     'widen'
				type_name: tn
				field:     'body'
				detail:    'body widened: ${body_text(ob)} -> ${body_text(nb)}'
			}
		} else {
			changes << SchemaChange{
				class:     'reinterpret'
				type_name: tn
				field:     'body'
				detail:    'body changed: ${body_text(ob)} -> ${body_text(nb)}'
				prompt:    "[${tn}]'s body shape changed ${body_text(ob)} -> ${body_text(nb)} — outside the join lattice this is a different value model; author a [schema-lineage] claim with a hand-written upcaster"
			}
		}
		return
	}
	if !ob.required && nb.required {
		changes << SchemaChange{
			class:     'narrow'
			type_name: tn
			field:     'body'
			detail:    'body became required'
			prompt:    "[${tn}]'s body became required — old data may omit it; drop [req] or author a claim with an upcaster that synthesizes the body"
		}
	} else if ob.required && !nb.required {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     'body'
			detail:    'body [req] dropped'
		}
	}
	compat_enum(tn, 'body', ob.enum_vals, nb.enum_vals, mut changes)
	compat_bounds(tn, 'body', 'range', ob.range_min, ob.range_max, nb.range_min, nb.range_max, mut changes)
	compat_bounds(tn, 'body', 'len', ob.len_min, ob.len_max, nb.len_min, nb.len_max, mut changes)
	compat_pattern(tn, 'body', ob.pat, nb.pat, mut changes)
}

fn compat_enum(tn string, f string, old_vals []string, new_vals []string, mut changes []SchemaChange) {
	if old_vals == new_vals {
		return
	}
	if old_vals.len > 0 && new_vals.len == 0 {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     f
			detail:    '[enum …] removed'
		}
		return
	}
	if old_vals.len == 0 && new_vals.len > 0 {
		changes << SchemaChange{
			class:     'narrow'
			type_name: tn
			field:     f
			detail:    '[enum ${new_vals.join(' ')}] added'
			prompt:    "'${f}' on [${tn}] gained an enum — old values outside {${new_vals.join(', ')}} refuse; widen the enum, or author a claim with an upcaster mapping the out-of-enum values"
		}
		return
	}
	mut dropped := []string{}
	for v in old_vals {
		if v !in new_vals {
			dropped << v
		}
	}
	if dropped.len == 0 {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     f
			detail:    'enum widened (superset)'
		}
	} else {
		changes << SchemaChange{
			class:     'narrow'
			type_name: tn
			field:     f
			detail:    'enum narrowed: {${dropped.join(', ')}} dropped'
			prompt:    "'${f}' on [${tn}] dropped enum value(s) {${dropped.join(', ')}} — old data carrying them refuses; keep them, or author a claim with an upcaster mapping each dropped value"
		}
	}
}

fn compat_bounds(tn string, f string, kind string, omin string, omax string, nmin string, nmax string, mut changes []SchemaChange) {
	if omin == nmin && omax == nmax {
		return
	}
	// '' = unbounded on that side.
	min_widened := nmin == '' || (omin != '' && nmin.f64() <= omin.f64())
	max_widened := nmax == '' || (omax != '' && nmax.f64() >= omax.f64())
	if min_widened && max_widened {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     f
			detail:    '${kind} widened: [${bound_text(omin, omax)}] -> [${bound_text(nmin, nmax)}]'
		}
	} else {
		changes << SchemaChange{
			class:     'narrow'
			type_name: tn
			field:     f
			detail:    '${kind} narrowed: [${bound_text(omin, omax)}] -> [${bound_text(nmin, nmax)}]'
			prompt:    "'${f}' on [${tn}] narrowed its ${kind} [${bound_text(omin, omax)}] -> [${bound_text(nmin, nmax)}] — old values may fall outside; widen it, or author a claim with an upcaster mapping the out-of-${kind} values"
		}
	}
}

fn bound_text(min string, max string) string {
	l := if min == '' { '-inf' } else { min }
	r := if max == '' { '+inf' } else { max }
	return '${l}..${r}'
}

fn compat_pattern(tn string, f string, opat string, npat string, mut changes []SchemaChange) {
	if opat == npat {
		return
	}
	if opat != '' && npat == '' {
		changes << SchemaChange{
			class:     'widen'
			type_name: tn
			field:     f
			detail:    '[pattern …] removed'
		}
		return
	}
	verb := if opat == '' { 'added' } else { 'changed' }
	changes << SchemaChange{
		class:     'narrow'
		type_name: tn
		field:     f
		detail:    '[pattern …] ${verb}'
		prompt:    "'${f}' on [${tn}] ${verb} its [pattern] — regex containment is not mechanically provable, so this is treated as a tightening; keep the old pattern, or author a claim with an upcaster normalizing the values"
	}
}

// ── the widening (join) lattice ──────────────────────────────────────────────

fn int_rank(t string) int {
	return match t {
		'i8' { 8 }
		'i16' { 16 }
		'i32' { 32 }
		'int', 'i64' { 64 }
		else { 0 }
	}
}

fn uint_rank(t string) int {
	return match t {
		'u8' { 8 }
		'u16' { 16 }
		'u32' { 32 }
		'u64' { 64 }
		else { 0 }
	}
}

fn float_rank(t string) int {
	return match t {
		'f16' { 16 }
		'f32' { 32 }
		'float', 'f64' { 64 }
		else { 0 }
	}
}

// scalar_widens: every value admitted by `old` is admitted by `new`.
fn scalar_widens(old string, new string) bool {
	if old == new {
		return true
	}
	if new == 'any' || new == 'scalar' {
		return true
	}
	oi := int_rank(old)
	ou := uint_rank(old)
	of_ := float_rank(old)
	ni := int_rank(new)
	nu := uint_rank(new)
	nf := float_rank(new)
	if oi > 0 && ni > 0 {
		return ni >= oi
	}
	if ou > 0 && nu > 0 {
		return nu >= ou
	}
	if ou > 0 && ni > 0 {
		return ni > ou // u8 fits i16+, u32 fits i64
	}
	// int ⊔ float -> float (the ONE collapsing join, schema.md §16); the
	// validator already admits int where float is declared.
	if (oi > 0 || ou > 0) && nf > 0 {
		return true
	}
	if of_ > 0 && nf > 0 {
		return nf >= of_
	}
	if (oi > 0 || ou > 0) && new == 'bigint' {
		return true
	}
	// decimal joins only decimal (the no-mixing rule); everything else: no.
	return false
}

// type_widens handles the scalar-or-union attr type forms.
fn type_widens(old_t string, old_members []string, new_t string, new_members []string) bool {
	mut olds := []string{}
	if old_members.len > 0 {
		olds = old_members.clone()
	} else if old_t != '' {
		olds = [old_t]
	}
	mut news := []string{}
	if new_members.len > 0 {
		news = new_members.clone()
	} else if new_t != '' {
		news = [new_t]
	}
	if olds.len == 0 || news.len == 0 {
		return false
	}
	for o in olds {
		mut covered := false
		for n in news {
			if scalar_widens(o, n) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

fn body_widens(ob BodyRule, nb BodyRule) bool {
	if nb.kind == 'any' {
		return true
	}
	if ob.kind == nb.kind && ob.kind in ['arr', 'seq', 'list'] {
		return ob.item_kind == nb.item_kind || scalar_widens(ob.item_kind, nb.item_kind)
	}
	if ob.kind == nb.kind && ob.kind == 'map' {
		return ob.key_kind == nb.key_kind
			&& (ob.item_kind == nb.item_kind || scalar_widens(ob.item_kind, nb.item_kind))
	}
	if ob.item_kind == '' && nb.item_kind == '' {
		return scalar_widens(ob.kind, nb.kind)
	}
	return false
}

fn type_text(a AttrRule) string {
	if a.members.len > 0 {
		return '[or ${a.members.join(' ')}]'
	}
	if a.type_name == '' {
		return '(untyped)'
	}
	return a.type_name
}

fn body_text(b BodyRule) string {
	if !b.declared && b.kind == '' {
		return '(undeclared)'
	}
	if b.kind in ['arr', 'seq', 'list'] {
		return '[list ${b.item_kind}]'
	}
	if b.kind == 'map' {
		return '[map ${b.key_kind} ${b.item_kind}]'
	}
	if b.kind == '' {
		return '(untyped)'
	}
	return b.kind
}

// ── the derived translator (the upcaster document) ───────────────────────────

// derive_translator emits the SEA-1g upcaster document: the Lane-2
// [schema-lineage] claim carrying the derived rules AS DATA ([derived …],
// schema.md §16.5.2). The journal seam applies the rules natively —
// lossless field-level surgery; undeclared/open-mode content rides through
// untouched (SEA-1b).
fn derive_translator(rep SchemaCompatReport, new_sm SchemaModel) string {
	root := new_sm.root
	name := rep.upcaster_name
	mut rules := []string{} // one closed-vocabulary rule element per derivation action
	for c in rep.changes {
		match c.action {
			'rename-attr' {
				rules << '[rename-attr from=${c.old_name} to=${c.new_name}]'
			}
			'rename-elem' {
				rules << '[rename-elem from=${c.old_name} to=${c.new_name}]'
			}
			'set-default' {
				vt := if c.vtype == '' { 'string' } else { c.vtype }
				rules << '[set-default attr=${c.new_name} value=${compat_q(c.value)} vtype=${vt}]'
			}
			'drop-attr' {
				rules << '[drop-attr attr=${c.old_name}]'
			}
			'drop-elem' {
				rules << '[drop-elem elem=${c.old_name}]'
			}
			else {}
		}
	}
	mut b := []string{}
	b << '[# Derived translator (cx schema compat, RULED: SEA-1).'
	b << '   from ${rep.from_addr}'
	b << '   to   ${rep.to_addr}'
	b << '   root [${root}]. Applied natively at the journal seam (§3.9, the'
	b << '   derived-chain form): rewrites entries declaring the OLD address,'
	b << '   passes the NEW address and schema-less entries, refuses any address'
	b << '   unknown to the chain (SEA-1b/SEA-1g). #]'
	b << ''
	b << '[schema-lineage'
	b << "  [from '${rep.from_addr}']"
	b << "  [to '${rep.to_addr}']"
	b << '  [relation :additive]'
	b << '  [upcaster ${name}]'
	if rules.len == 0 {
		b << '  [derived root=${root}]]'
	} else {
		b << '  [derived root=${root}'
		for i, r in rules {
			suffix := if i == rules.len - 1 { ']]' } else { '' }
			b << '    ${r}${suffix}'
		}
	}
	return b.join('\n') + '\n'
}

// ── report rendering (CLI face) ──────────────────────────────────────────────

fn compat_q(s string) string {
	return "'" + s.replace('\\', '\\\\').replace("'", "\\'") + "'"
}

// schema_compat_report_text renders the §16.5.3 report element.
pub fn schema_compat_report_text(rep SchemaCompatReport) string {
	mut b := []string{}
	b << "[schema-compat from='${rep.from_addr}' to='${rep.to_addr}' verdict=${rep.verdict}"
	for c in rep.changes {
		fattr := if c.field != '' { " field='${c.field}'" } else { '' }
		if is_refusal_class(c.class) && c.prompt != '' {
			b << '  [missing-rule class=${c.class} type=${c.type_name}${fattr} prompt=${compat_q(c.prompt)}]'
		} else {
			b << '  [change class=${c.class} type=${c.type_name}${fattr} detail=${compat_q(c.detail)}]'
		}
	}
	if rep.verdict == 'derivable' && rep.upcaster_name != '' {
		b << '  [upcaster ${rep.upcaster_name}]'
	}
	return b.join('\n') + ']\n'
}

// ── small helpers ────────────────────────────────────────────────────────────

fn sorted_key_union_attr(a map[string]AttrRule, b map[string]AttrRule) []string {
	mut out := []string{}
	for k, _ in a {
		out << k
	}
	for k, _ in b {
		if k !in a {
			out << k
		}
	}
	out.sort()
	return out
}

fn sorted_key_union_elem(a map[string]ElemRule, b map[string]ElemRule) []string {
	mut out := []string{}
	for k, _ in a {
		out << k
	}
	for k, _ in b {
		if k !in a {
			out << k
		}
	}
	out.sort()
	return out
}
