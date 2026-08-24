module cx

// canonical_float.v — §1.3 enforcement for non-finite floats (I1 identity
// epoch, stream 12, W-3): NaN and ±Inf have NO canonical form — `[a 1e400]`
// used to canonicalize to `[a +inf.0]`, bytes that cannot re-parse. The
// canonical/hash lane now REFUSES such a document instead of emitting it;
// display rendering (the program result lane) may still spell non-finite
// values, but they can never acquire a Tier-1 address.

// reject_nonfinite_floats errors if any float scalar in the document —
// element bodies, attribute values, collection items, map keys/values,
// table cells — is NaN or ±Inf.
fn reject_nonfinite_floats(doc Document) ! {
	reject_nonfinite_nodes(doc.prolog)!
	reject_nonfinite_nodes(doc.elements)!
}

fn reject_nonfinite_nodes(nodes []Node) ! {
	for n in nodes {
		match n {
			Element {
				for a in n.attrs {
					v := a.value
					if v is f64 {
						if !cx_f64_is_finite(v) {
							return nonfinite_err(n.name, a.name)
						}
					}
				}
				reject_nonfinite_nodes(n.items)!
				if td := n.table_opt() {
					for row in td.rows {
						for cell in row {
							if cell is f64 {
								if !cx_f64_is_finite(cell) {
									return nonfinite_err(n.name, '')
								}
							}
						}
					}
				}
			}
			ScalarNode {
				if n.data_type == .float_type {
					v := n.value
					if v is f64 {
						if !cx_f64_is_finite(v) {
							return nonfinite_err('', '')
						}
					}
				}
			}
			SequenceNode {
				reject_nonfinite_nodes(n.items)!
			}
			ArrayNode {
				reject_nonfinite_nodes(n.items)!
			}
			MapNode {
				for entry in n.entries {
					kv := entry.key_value
					if kv is f64 {
						if !cx_f64_is_finite(kv) {
							return nonfinite_err('', '')
						}
					}
					reject_nonfinite_nodes([entry.value])!
				}
			}
			else {}
		}
	}
	return
}

fn nonfinite_err(elem string, attr string) IError {
	mut loc := ''
	if elem.len > 0 && attr.len > 0 {
		loc = ' (element `${elem}`, attribute `${attr}`)'
	} else if elem.len > 0 {
		loc = ' (element `${elem}`)'
	}
	return error('non-finite float (NaN/±Inf) has no canonical form — canonical.md §1.3/§2.5${loc} (cx-err:CXER0109)')
}
