module cx

// numeric_exact.v — exact-family numeric comparison (I1 stream 11,
// L40/L42): int, bigint, and decimal compare MATHEMATICALLY across kinds
// (`bigint 99 = int 99`; `1.10::decimal = 1.1::decimal` — scale is
// identity, value is equality). The comparison is pure digit arithmetic
// over the base-10 fixed-point images — no f64 round-trip, so bigint
// ordering is exact beyond 2^53 and decimal never loses scale digits.

// cx_exact_num_image returns the base-10 fixed-point image of an
// exact-family scalar (int / bigint / decimal), or none for every other
// kind — float is deliberately NOT in the family (L44: `[cast]` is the
// only decimal↔float bridge).
pub fn cx_exact_num_image(sn ScalarNode) ?string {
	match sn.data_type {
		.int_type {
			v := sn.value
			if v is i64 {
				return v.str()
			}
			return none
		}
		.bigint_type, .decimal_type {
			v := sn.value
			if v is string {
				return v
			}
			return none
		}
		else {
			return none
		}
	}
}

// cx_exact_num_cmp compares two base-10 fixed-point images
// mathematically: -1, 0, +1. Lenient on non-canonical spellings
// (leading `+`, redundant zeros) — runtime-built values may not have
// passed the coercion normalizer.
pub fn cx_exact_num_cmp(a string, b string) int {
	a_neg, a_int, a_frac := exact_split(a)
	b_neg, b_int, b_frac := exact_split(b)
	a_zero := a_int == '0' && a_frac.len == 0
	b_zero := b_int == '0' && b_frac.len == 0
	if a_zero && b_zero {
		return 0
	}
	an := a_neg && !a_zero
	bn := b_neg && !b_zero
	if an != bn {
		return if an { -1 } else { 1 }
	}
	mag := exact_mag_cmp(a_int, a_frac, b_int, b_frac)
	return if an { -mag } else { mag }
}

// exact_split normalizes one image into (negative, integer digits without
// leading zeros, fraction digits without trailing zeros).
fn exact_split(s_in string) (bool, string, string) {
	mut s := s_in
	mut neg := false
	if s.starts_with('+') {
		s = s[1..]
	} else if s.starts_with('-') {
		neg = true
		s = s[1..]
	}
	mut int_part := s
	mut frac := ''
	if idx := s.index('.') {
		int_part = s[..idx]
		frac = s[idx + 1..]
	}
	mut ip := int_part.trim_left('0')
	if ip.len == 0 {
		ip = '0'
	}
	fr := frac.trim_right('0')
	return neg, ip, fr
}

fn exact_mag_cmp(a_int string, a_frac string, b_int string, b_frac string) int {
	if a_int.len != b_int.len {
		return if a_int.len < b_int.len { -1 } else { 1 }
	}
	if a_int != b_int {
		return if a_int < b_int { -1 } else { 1 }
	}
	// Equal integer parts: compare fractions digit-by-digit with implicit
	// trailing zeros (already stripped, so a longer fraction that matches
	// the shorter as a prefix is strictly larger).
	min := if a_frac.len < b_frac.len { a_frac.len } else { b_frac.len }
	for i in 0 .. min {
		if a_frac[i] != b_frac[i] {
			return if a_frac[i] < b_frac[i] { -1 } else { 1 }
		}
	}
	if a_frac.len == b_frac.len {
		return 0
	}
	return if a_frac.len < b_frac.len { -1 } else { 1 }
}
// ── Exact arithmetic (I1 stream 11, L44) ─────────────────────────────────────
//
// Schoolbook digit-string arithmetic over the same base-10 fixed-point
// images the comparator uses. Scale rules per L44: max(s₁,s₂) for +/−,
// s₁+s₂ for ×; ÷ computes the exact quotient when it terminates and
// errors otherwise (CXER3002 family — the caller maps the message).

struct CxExact {
mut:
	neg    bool
	digits string // magnitude, no sign/dot, no leading zeros ('0' for zero)
	scale  int    // value = (-1)^neg × digits × 10^-scale
}

fn cx_exact_parse(img string) CxExact {
	neg0, ip, _ := exact_split(img)
	// exact_split trims TRAILING fraction zeros (comparison form) — for
	// arithmetic the authored scale matters, so re-derive it here.
	mut frac := ''
	if idx := img.index('.') {
		frac = img[idx + 1..]
	}
	mut digits := ip + frac
	digits = digits.trim_left('0')
	if digits.len == 0 {
		digits = '0'
	}
	return CxExact{
		neg:    neg0 && digits != '0'
		digits: digits
		scale:  frac.len
	}
}

fn (e CxExact) render() string {
	mut d := e.digits
	if e.scale == 0 {
		return if e.neg { '-' + d } else { d }
	}
	for d.len <= e.scale {
		d = '0' + d
	}
	cut := d.len - e.scale
	out := d[..cut] + '.' + d[cut..]
	return if e.neg { '-' + out } else { out }
}

fn dg_trim(s string) string {
	t := s.trim_left('0')
	return if t.len == 0 { '0' } else { t }
}

fn dg_cmp(a string, b string) int {
	if a.len != b.len {
		return if a.len < b.len { -1 } else { 1 }
	}
	if a == b {
		return 0
	}
	return if a < b { -1 } else { 1 }
}

fn dg_add(a string, b string) string {
	mut out := []u8{cap: a.len + 1}
	mut i := a.len - 1
	mut j := b.len - 1
	mut carry := 0
	for i >= 0 || j >= 0 || carry > 0 {
		mut sum := carry
		if i >= 0 {
			sum += int(a[i] - `0`)
			i--
		}
		if j >= 0 {
			sum += int(b[j] - `0`)
			j--
		}
		out << u8(`0` + (sum % 10))
		carry = sum / 10
	}
	out.reverse_in_place()
	return out.bytestr()
}

// dg_sub computes a − b for a ≥ b (caller compares first).
fn dg_sub(a string, b string) string {
	mut out := []u8{cap: a.len}
	mut i := a.len - 1
	mut j := b.len - 1
	mut borrow := 0
	for i >= 0 {
		mut d := int(a[i] - `0`) - borrow
		if j >= 0 {
			d -= int(b[j] - `0`)
			j--
		}
		if d < 0 {
			d += 10
			borrow = 1
		} else {
			borrow = 0
		}
		out << u8(`0` + d)
		i--
	}
	out.reverse_in_place()
	return dg_trim(out.bytestr())
}

fn dg_mul(a string, b string) string {
	if a == '0' || b == '0' {
		return '0'
	}
	mut acc := []int{len: a.len + b.len}
	for i := a.len - 1; i >= 0; i-- {
		for j := b.len - 1; j >= 0; j-- {
			acc[i + j + 1] += int(a[i] - `0`) * int(b[j] - `0`)
		}
	}
	for k := acc.len - 1; k > 0; k-- {
		acc[k - 1] += acc[k] / 10
		acc[k] %= 10
	}
	mut out := []u8{cap: acc.len}
	for d in acc {
		out << u8(`0` + d)
	}
	return dg_trim(out.bytestr())
}

// dg_divmod_small divides by a small positive constant, returning the
// quotient digits and the remainder.
fn dg_divmod_small(a string, m int) (string, int) {
	mut out := []u8{cap: a.len}
	mut rem := 0
	for i in 0 .. a.len {
		cur := rem * 10 + int(a[i] - `0`)
		out << u8(`0` + (cur / m))
		rem = cur % m
	}
	return dg_trim(out.bytestr()), rem
}

// dg_divmod is schoolbook long division a ÷ b (b ≠ '0'), returning
// (quotient, remainder) digit strings.
fn dg_divmod(a string, b string) (string, string) {
	if dg_cmp(a, b) < 0 {
		return '0', a
	}
	mut q := []u8{cap: a.len}
	mut rem := ''
	for i in 0 .. a.len {
		rem = dg_trim(rem + a[i..i + 1])
		mut d := 0
		for d < 9 {
			trial := dg_mul(b, (d + 1).str())
			if dg_cmp(trial, rem) > 0 {
				break
			}
			d++
		}
		q << u8(`0` + d)
		if d > 0 {
			rem = dg_sub(rem, dg_mul(b, d.str()))
		}
	}
	return dg_trim(q.bytestr()), rem
}

fn cx_exact_add_signed(a CxExact, b CxExact) CxExact {
	// Align scales.
	mut ad := a.digits
	mut bd := b.digits
	mut sc := a.scale
	if a.scale < b.scale {
		for _ in 0 .. b.scale - a.scale {
			ad += '0'
		}
		sc = b.scale
	} else if b.scale < a.scale {
		for _ in 0 .. a.scale - b.scale {
			bd += '0'
		}
	}
	ad = dg_trim(ad)
	bd = dg_trim(bd)
	if a.neg == b.neg {
		return CxExact{ neg: a.neg, digits: dg_add(ad, bd), scale: sc }
	}
	c := dg_cmp(ad, bd)
	if c == 0 {
		return CxExact{ neg: false, digits: '0', scale: sc }
	}
	if c > 0 {
		return CxExact{ neg: a.neg, digits: dg_sub(ad, bd), scale: sc }
	}
	return CxExact{ neg: b.neg, digits: dg_sub(bd, ad), scale: sc }
}

// cx_exact_add / cx_exact_sub / cx_exact_mul: image-level entry points.
pub fn cx_exact_add(a string, b string) string {
	return cx_exact_add_signed(cx_exact_parse(a), cx_exact_parse(b)).render()
}

pub fn cx_exact_sub(a string, b string) string {
	mut bb := cx_exact_parse(b)
	if bb.digits != '0' {
		bb.neg = !bb.neg
	}
	return cx_exact_add_signed(cx_exact_parse(a), bb).render()
}

pub fn cx_exact_mul(a string, b string) string {
	aa := cx_exact_parse(a)
	bb := cx_exact_parse(b)
	return CxExact{
		neg:    aa.neg != bb.neg && aa.digits != '0' && bb.digits != '0'
		digits: dg_mul(aa.digits, bb.digits)
		scale:  aa.scale + bb.scale
	}.render()
}

// cx_exact_div computes the EXACT quotient of two decimal images. Errors
// when the quotient does not terminate (the reduced denominator carries a
// prime factor other than 2 or 5) — the L44 rounding-context rule: without
// an explicit context, a non-terminating division is CXER3002.
pub fn cx_exact_div(a string, b string) !string {
	aa := cx_exact_parse(a)
	bb := cx_exact_parse(b)
	if bb.digits == '0' {
		return error('division by zero')
	}
	if aa.digits == '0' {
		return '0'
	}
	// value = (aa/bb) × 10^(bb.scale − aa.scale). Strip 2s and 5s from the
	// denominator; whatever remains must divide the numerator exactly.
	mut den := bb.digits
	mut twos := 0
	mut fives := 0
	for {
		q, r := dg_divmod_small(den, 2)
		if r != 0 {
			break
		}
		den = q
		twos++
	}
	for {
		q, r := dg_divmod_small(den, 5)
		if r != 0 {
			break
		}
		den = q
		fives++
	}
	mut num := aa.digits
	if den != '1' {
		q, r := dg_divmod(num, den)
		if r != '0' {
			return error('non-terminating decimal division — supply a rounding context (cx-err:CXER3002)')
		}
		num = q
	}
	// Divide by the remaining 2^twos·5^fives by multiplying into powers of
	// ten: ÷2 = ×5/10, ÷5 = ×2/10.
	for _ in 0 .. twos {
		num = dg_mul(num, '5')
	}
	for _ in 0 .. fives {
		num = dg_mul(num, '2')
	}
	mut res := CxExact{
		neg:    aa.neg != bb.neg
		digits: dg_trim(num)
		scale:  twos + fives + aa.scale - bb.scale
	}
	if res.scale < 0 {
		for _ in 0 .. -res.scale {
			res.digits += '0'
		}
		res.scale = 0
	}
	if res.digits == '0' {
		res.neg = false
	}
	return res.render()
}

// cx_exact_div_ctx — decimal division under an explicit rounding context
// (stream 11 §5, L44: "÷ requires an explicit rounding context (precision
// + mode)"): the exact quotient rounded to `scale` fractional digits per
// `mode` (:half-up | :half-even | :down | :up). This is the ONLY way to
// divide a non-terminating quotient; cx_exact_div stays the exact form.
pub fn cx_exact_div_ctx(a string, b string, scale int, mode string) !string {
	if scale < 0 {
		return error('rounding context: precision must be >= 0')
	}
	aa := cx_exact_parse(a)
	bb := cx_exact_parse(b)
	if bb.digits == '0' {
		return error('division by zero')
	}
	if aa.digits == '0' {
		mut z := CxExact{
			neg:    false
			digits: '0'
			scale:  scale
		}
		if scale > 0 {
			z.digits = '0'
		}
		return z.render()
	}
	// |a/b| × 10^(scale+1) = (aa.digits × 10^bb.scale) / (bb.digits ×
	// 10^aa.scale) × 10^(scale+1) — pad both sides non-negatively.
	mut num := aa.digits
	for _ in 0 .. bb.scale + scale + 1 {
		num += '0'
	}
	mut den := bb.digits
	for _ in 0 .. aa.scale {
		den += '0'
	}
	q, r := dg_divmod(num, den)
	// split off the rounding digit (the scale+1-th fractional digit).
	mut body := '0'
	mut rd := 0
	if q.len > 1 {
		body = q[..q.len - 1]
	}
	rd = int(q[q.len - 1] - `0`)
	rest_nonzero := r != '0'
	mut round_up := false
	match mode {
		':down', 'down' {
			round_up = false
		}
		':up', 'up' {
			round_up = rd > 0 || rest_nonzero
		}
		':half-up', 'half-up' {
			round_up = rd >= 5
		}
		':half-even', 'half-even' {
			if rd > 5 || (rd == 5 && rest_nonzero) {
				round_up = true
			} else if rd == 5 && !rest_nonzero {
				last := body[body.len - 1]
				round_up = (last - `0`) % 2 == 1
			}
		}
		else {
			return error('rounding context: unknown mode `${mode}` (:half-up | :half-even | :down | :up)')
		}
	}
	if round_up {
		body = dg_add(body, '1')
	}
	res := CxExact{
		neg:    aa.neg != bb.neg && dg_trim(body) != '0'
		digits: dg_trim(body)
		scale:  scale
	}
	return res.render()
}

// cx_exact_int_divmod: truncated integer division over integer images
// (bigint ⊕ int lanes). Signs follow truncation-toward-zero.
pub fn cx_exact_int_divmod(a string, b string) !(string, string) {
	aa := cx_exact_parse(a)
	bb := cx_exact_parse(b)
	if bb.digits == '0' {
		return error('division by zero')
	}
	if aa.scale != 0 || bb.scale != 0 {
		return error('integer division over non-integer images')
	}
	q, r := dg_divmod(aa.digits, bb.digits)
	qs := if (aa.neg != bb.neg) && q != '0' { '-' + q } else { q }
	rs := if aa.neg && r != '0' { '-' + r } else { r }
	return qs, rs
}

// cx_exact_mod computes the EXACT remainder `a − b × trunc(a/b)` over two
// decimal/bigint images, with the SIGN OF THE DIVIDEND (XPath 3.1 §3.5, the
// same rule the int and float lanes already follow) and scale max(s₁,s₂).
//
// The scale is not a free choice — L44 forces it by composition. The
// remainder IS a subtraction (`a − b×q`), `q` is integral so `b×q` carries
// scale s₂ (L44's `×` rule: s₁+s₂ with s(q)=0), and L44's `−` rule is
// max(s₁,s₂). Hence max(s₁,s₂), which is exactly the common scale the two
// operands align to below.
//
// Unlike `÷`, this ALWAYS terminates and is ALWAYS exact — the quotient is
// truncated to an integer, so no rounding context is ever needed and
// CXER3002 cannot arise. Aligning both operands to the common scale makes
// their digit strings integers, so one integer divmod yields the remainder.
pub fn cx_exact_mod(a string, b string) !string {
	aa := cx_exact_parse(a)
	bb := cx_exact_parse(b)
	if bb.digits == '0' {
		return error('division by zero')
	}
	sc := if aa.scale > bb.scale { aa.scale } else { bb.scale }
	mut ad := aa.digits
	mut bd := bb.digits
	for _ in 0 .. sc - aa.scale {
		ad += '0'
	}
	for _ in 0 .. sc - bb.scale {
		bd += '0'
	}
	_, r := dg_divmod(dg_trim(ad), dg_trim(bd))
	return CxExact{
		neg:    aa.neg && r != '0'
		digits: r
		scale:  sc
	}.render()
}

// cx_exact_idiv computes the EXACT integral quotient `trunc(a/b)` over two
// decimal/bigint images — `[$idiv]`'s exact-family lane (#1044) and the
// complement of cx_exact_mod above: `a = b × idiv(a,b) + mod(a,b)` holds by
// construction, both truncating toward zero (code.md §6.5 / XPath 3.1 §3.5).
//
// Like `%` and UNLIKE `÷`, this ALWAYS terminates and is ALWAYS exact, so no
// rounding context is ever needed and CXER3002 cannot arise here: `idiv` does
// not ASK for the quotient's fractional part, and truncation toward zero is
// §6.5's own already-normative rounding, not an invented one. L44 leaves the
// scale/mode question open only for `÷`, which is a different question.
//
// Aligning both operands to the common scale makes their digit strings
// integers whose shared 10^k factor cancels in the quotient, so a single
// integer divmod yields it — and the quotient is integral, hence scale 0.
pub fn cx_exact_idiv(a string, b string) !string {
	aa := cx_exact_parse(a)
	bb := cx_exact_parse(b)
	if bb.digits == '0' {
		return error('division by zero')
	}
	sc := if aa.scale > bb.scale { aa.scale } else { bb.scale }
	mut ad := aa.digits
	mut bd := bb.digits
	for _ in 0 .. sc - aa.scale {
		ad += '0'
	}
	for _ in 0 .. sc - bb.scale {
		bd += '0'
	}
	q, _ := dg_divmod(dg_trim(ad), dg_trim(bd))
	return CxExact{
		neg:    aa.neg != bb.neg && q != '0'
		digits: q
		scale:  0
	}.render()
}

// cx_decimal_image_from_float renders a finite double as a FIXED-POINT
// decimal image (L44 float→decimal cast: shortest-round-trip digits per
// Ryū/L18, expanded — the decimal surface has no exponent form). none for
// NaN/±Inf.
pub fn cx_decimal_image_from_float(v f64) ?string {
	if !cx_f64_is_finite(v) {
		return none
	}
	img := cx_format_float(v)
	eidx := img.index('e') or { return img }
	mant := img[..eidx]
	exp := img[eidx + 1..].int()
	neg := mant.starts_with('-')
	m := if neg { mant[1..] } else { mant }
	dot := m.index('.') or { m.len }
	digits := m.replace('.', '')
	frac_len := digits.len - dot
	mut e := CxExact{
		neg:    neg
		digits: dg_trim(digits)
		scale:  frac_len - exp
	}
	if e.scale < 0 {
		for _ in 0 .. -e.scale {
			e.digits += '0'
		}
		e.scale = 0
	}
	if e.digits == '0' {
		e.neg = false
	}
	return e.render()
}

// ── Exact unary math (I1 stream 11 — math.md §4.4 non-transcendentals) ──────

pub fn cx_exact_abs(img string) string {
	e := cx_exact_parse(img)
	return CxExact{ neg: false, digits: e.digits, scale: e.scale }.render()
}

// cx_exact_floor / cx_exact_ceiling / cx_exact_round_half_away return the
// INTEGRAL digit image (no fraction) of the rounded value.
pub fn cx_exact_floor(img string) string {
	e := cx_exact_parse(img)
	ip, frac_nonzero := exact_int_part(e)
	if !e.neg || !frac_nonzero {
		return if e.neg && ip != '0' { '-' + ip } else { ip }
	}
	bumped := dg_add(ip, '1')
	return '-' + bumped
}

pub fn cx_exact_ceiling(img string) string {
	e := cx_exact_parse(img)
	ip, frac_nonzero := exact_int_part(e)
	if e.neg || !frac_nonzero {
		return if e.neg && ip != '0' { '-' + ip } else { ip }
	}
	return dg_add(ip, '1')
}

// Half-away-from-zero (XPath fn:round).
pub fn cx_exact_round_half_away(img string) string {
	e := cx_exact_parse(img)
	ip, _ := exact_int_part(e)
	mut out := ip
	if first_frac_digit(e) >= 5 {
		out = dg_add(ip, '1')
	}
	if e.neg && out != '0' {
		return '-' + out
	}
	return out
}

// exact_int_part returns (integer digit image, fraction-nonzero?).
fn exact_int_part(e CxExact) (string, bool) {
	mut d := e.digits
	if e.scale == 0 {
		return d, false
	}
	for d.len <= e.scale {
		d = '0' + d
	}
	cut := d.len - e.scale
	frac := d[cut..]
	mut nonzero := false
	for c in frac {
		if c != `0` {
			nonzero = true
			break
		}
	}
	return dg_trim(d[..cut]), nonzero
}

fn first_frac_digit(e CxExact) int {
	if e.scale == 0 {
		return 0
	}
	mut d := e.digits
	for d.len <= e.scale {
		d = '0' + d
	}
	return int(d[d.len - e.scale] - `0`)
}

// cx_decimal_image_from_json_number renders a JSON number literal
// (mantissa [.frac] [e exp]) as an EXACT fixed-point decimal image — JSON
// decimal text is always exactly representable in fixed point, so the
// documented `all-decimal` mode can be genuinely exact (I1 stream 11,
// defect D). none for malformed input.
pub fn cx_decimal_image_from_json_number(raw string) ?string {
	mut s := raw
	mut neg := false
	if s.starts_with('-') {
		neg = true
		s = s[1..]
	} else if s.starts_with('+') {
		s = s[1..]
	}
	mut exp := 0
	eidx := s.index_any('eE')
	if eidx >= 0 {
		exp = s[eidx + 1..].int()
		s = s[..eidx]
	}
	mut int_part := s
	mut frac := ''
	if idx := s.index('.') {
		int_part = s[..idx]
		frac = s[idx + 1..]
	}
	if int_part.len == 0 && frac.len == 0 {
		return none
	}
	if (int_part.len > 0 && !is_all_digits(int_part)) || (frac.len > 0 && !is_all_digits(frac)) {
		return none
	}
	mut e := CxExact{
		neg:    neg
		digits: dg_trim(int_part + frac)
		scale:  frac.len - exp
	}
	if e.scale < 0 {
		for _ in 0 .. -e.scale {
			e.digits += '0'
		}
		e.scale = 0
	}
	if e.digits == '0' {
		e.neg = false
	}
	return e.render()
}
