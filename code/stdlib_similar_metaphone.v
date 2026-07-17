module code

// stdlib_similar_metaphone.v — Double Metaphone phonetic keys for the
// cx-stdlib `similar` module's `metaphone` scorer (spec/stdlib_similar.md).
//
// Faithful port of Lawrence Philips' Double Metaphone (C/C++ Users Journal,
// June 2000). Produces a (primary, alternate) key pair per input, each capped
// at the classic default of 4 characters. Input is case-folded to uppercase
// and common Latin-1 diacritics are folded to their base letters before the
// rule engine runs; `Ç` and `Ñ` keep their reference-algorithm treatment
// (Ç → S, Ñ → N) via dedicated markers so they never collide with the C/N
// rule families.
//
// The rule engine operates on the whole (possibly multi-word) string so the
// reference's context rules that look across spaces — 'VAN ', 'VON ',
// 'SAN ', 'MAC C' — behave exactly as published. The scorer entry point
// `similar_metaphone_score` instead keys word-by-word and joins, per the
// similar-module contract.

const dm_key_limit = 4

// marker bytes for the two diacritics the reference algorithm treats
// specially (Latin-1 code points, safely outside the A–Z rule space).
const dm_c_cedilla = u8(0xc7)
const dm_n_tilde = u8(0xd1)

struct DmState {
	work     string // uppercase folded input + 5 spaces of padding
	length   int    // length of the folded input (without padding)
	last     int    // length - 1
	slavo    bool   // Slavo-Germanic hint: W, K, CZ or WITZ present
	germanic bool   // Germanic hint: VAN / VON / SCH prefix
mut:
	primary   string
	secondary string
	current   int
}

fn (st &DmState) at(pos int) u8 {
	if pos < 0 || pos >= st.work.len {
		return 0
	}
	return st.work[pos]
}

fn (st &DmState) vowel_at(pos int) bool {
	c := st.at(pos)
	return c == `A` || c == `E` || c == `I` || c == `O` || c == `U` || c == `Y`
}

// has reports whether the padded working string carries any of `list`
// starting at `start` (each candidate must be exactly `n` bytes long).
fn (st &DmState) has(start int, n int, list []string) bool {
	if start < 0 || start + n > st.work.len {
		return false
	}
	sub := st.work[start..start + n]
	for cand in list {
		if sub == cand {
			return true
		}
	}
	return false
}

fn (mut st DmState) add(s string) {
	st.primary += s
	st.secondary += s
}

fn (mut st DmState) add2(p string, s string) {
	st.primary += p
	st.secondary += s
}

// dm_fold uppercases and folds common Latin-1 diacritics to the working
// alphabet the reference algorithm expects. Ç/Ñ become dedicated marker
// bytes (they carry their own rules); unknown non-ASCII runes become a
// position-holding `?` that the engine skips, mirroring the reference's
// default-case behavior for unrecognized characters.
fn dm_fold(word string) string {
	mut out := []u8{cap: word.len}
	for r in word.runes() {
		c := u32(r)
		if c >= u32(`a`) && c <= u32(`z`) {
			out << u8(c - 32)
		} else if c < 128 {
			out << u8(c) // A–Z kept; digits/punct/space skipped by the engine
		} else {
			match c {
				0xc0...0xc5, 0xe0...0xe5 { // À-Å à-å
					out << u8(`A`)
				}
				0xc6, 0xe6 { // Æ æ
					out << u8(`A`)
					out << u8(`E`)
				}
				0xc7, 0xe7 { // Ç ç — sounds as S per the reference
					out << dm_c_cedilla
				}
				0xc8...0xcb, 0xe8...0xeb { // È-Ë è-ë
					out << u8(`E`)
				}
				0xcc...0xcf, 0xec...0xef { // Ì-Ï ì-ï
					out << u8(`I`)
				}
				0xd0, 0xf0 { // Ð ð
					out << u8(`D`)
				}
				0xd1, 0xf1 { // Ñ ñ
					out << dm_n_tilde
				}
				0xd2...0xd6, 0xd8, 0xf2...0xf6, 0xf8 { // Ò-Ö Ø ò-ö ø
					out << u8(`O`)
				}
				0xd9...0xdc, 0xf9...0xfc { // Ù-Ü ù-ü
					out << u8(`U`)
				}
				0xdd, 0xfd, 0xff { // Ý ý ÿ
					out << u8(`Y`)
				}
				0xde, 0xfe { // Þ þ
					out << u8(`T`)
					out << u8(`H`)
				}
				0xdf { // ß
					out << u8(`S`)
					out << u8(`S`)
				}
				else {
					out << u8(`?`)
				}
			}
		}
	}
	return out.bytestr()
}

// similar_double_metaphone returns the (primary, alternate) Double Metaphone
// keys for `word`, each at most 4 characters. Empty or letterless input
// yields two empty keys.
fn similar_double_metaphone(word string) (string, string) {
	base := dm_fold(word)
	if base.len == 0 {
		return '', ''
	}
	mut st := DmState{
		work:     base + '     '
		length:   base.len
		last:     base.len - 1
		slavo:    base.contains('W') || base.contains('K') || base.contains('CZ')
			|| base.contains('WITZ')
		germanic: base.starts_with('VAN ') || base.starts_with('VON ') || base.starts_with('SCH')
	}
	// skip these silent letters when at the start of the word
	if st.has(0, 2, ['GN', 'KN', 'PN', 'WR', 'PS']) {
		st.current++
	}
	// initial 'X' is pronounced 'Z' e.g. 'Xavier' — mapped to 'S'
	if st.at(0) == `X` {
		st.add('S')
		st.current++
	}
	for st.primary.len < dm_key_limit || st.secondary.len < dm_key_limit {
		if st.current >= st.length {
			break
		}
		ch := st.at(st.current)
		match ch {
			`A`, `E`, `I`, `O`, `U`, `Y` {
				if st.current == 0 {
					st.add('A') // all initial vowels map to 'A'
				}
				st.current++
			}
			`B` {
				// '-mb' as in 'dumb' is handled at 'M'
				st.add('P')
				st.skip_double(`B`)
			}
			dm_c_cedilla {
				st.add('S')
				st.current++
			}
			`C` {
				st.dm_c()
			}
			`D` {
				st.dm_d()
			}
			`F` {
				st.skip_double(`F`)
				st.add('F')
			}
			`G` {
				st.dm_g()
			}
			`H` {
				// keep only if first & before vowel, or between two vowels
				if (st.current == 0 || st.vowel_at(st.current - 1)) && st.vowel_at(st.current + 1) {
					st.add('H')
					st.current += 2
				} else {
					st.current++
				}
			}
			`J` {
				st.dm_j()
			}
			`K` {
				st.skip_double(`K`)
				st.add('K')
			}
			`L` {
				st.dm_l()
			}
			`M` {
				st.dm_m()
			}
			`N` {
				st.skip_double(`N`)
				st.add('N')
			}
			dm_n_tilde {
				st.current++
				st.add('N')
			}
			`P` {
				st.dm_p()
			}
			`Q` {
				st.skip_double(`Q`)
				st.add('K')
			}
			`R` {
				st.dm_r()
			}
			`S` {
				st.dm_s()
			}
			`T` {
				st.dm_t()
			}
			`V` {
				st.skip_double(`V`)
				st.add('F')
			}
			`W` {
				st.dm_w()
			}
			`X` {
				st.dm_x()
			}
			`Z` {
				st.dm_z()
			}
			else {
				st.current++
			}
		}
	}
	mut p := st.primary
	mut s := st.secondary
	if p.len > dm_key_limit {
		p = p[..dm_key_limit]
	}
	if s.len > dm_key_limit {
		s = s[..dm_key_limit]
	}
	return p, s
}

fn (mut st DmState) skip_double(c u8) {
	if st.at(st.current + 1) == c {
		st.current += 2
	} else {
		st.current++
	}
}

fn (mut st DmState) dm_c() {
	cur := st.current
	// various germanic, e.g. 'wachtler' but not 'reichenbacher'
	if cur > 1 && !st.vowel_at(cur - 2) && st.has(cur - 1, 3, ['ACH']) && st.at(cur + 2) != `I`
		&& (st.at(cur + 2) != `E` || st.has(cur - 2, 6, ['BACHER', 'MACHER'])) {
		st.add('K')
		st.current += 2
		return
	}
	// special case 'caesar'
	if cur == 0 && st.has(cur, 6, ['CAESAR']) {
		st.add('S')
		st.current += 2
		return
	}
	// italian 'chianti'
	if st.has(cur, 4, ['CHIA']) {
		st.add('K')
		st.current += 2
		return
	}
	if st.has(cur, 2, ['CH']) {
		// find 'michael'
		if cur > 0 && st.has(cur, 4, ['CHAE']) {
			st.add2('K', 'X')
			st.current += 2
			return
		}
		// greek roots e.g. 'chemistry', 'chorus'
		if cur == 0 && (st.has(cur + 1, 5, ['HARAC', 'HARIS'])
			|| st.has(cur + 1, 3, ['HOR', 'HYM', 'HIA', 'HEM'])) && !st.has(0, 5, ['CHORE']) {
			st.add('K')
			st.current += 2
			return
		}
		// germanic, greek, or otherwise 'ch' for 'kh' sound;
		// 'architect' but not 'arch', 'orchestra' and 'orchid' stay hard;
		// trailing set covers e.g. 'wachtler', 'wechsler', but not 'tichner'
		if st.germanic || st.has(cur - 2, 6, ['ORCHES', 'ARCHIT', 'ORCHID'])
			|| st.has(cur + 2, 1, ['T', 'S'])
			|| ((st.has(cur - 1, 1, ['A', 'O', 'U', 'E']) || cur == 0)
			&& st.has(cur + 2, 1, ['L', 'R', 'N', 'M', 'B', 'H', 'F', 'V', 'W', ' '])) {
			st.add('K')
		} else if cur > 0 {
			if st.has(0, 2, ['MC']) {
				st.add('K') // e.g. 'McHugh'
			} else {
				st.add2('X', 'K')
			}
		} else {
			st.add('X')
		}
		st.current += 2
		return
	}
	// e.g. 'czerny'
	if st.has(cur, 2, ['CZ']) && !st.has(cur - 2, 4, ['WICZ']) {
		st.add2('S', 'X')
		st.current += 2
		return
	}
	// e.g. 'focaccia'
	if st.has(cur + 1, 3, ['CIA']) {
		st.add('X')
		st.current += 3
		return
	}
	// double 'C', but not if e.g. 'McClellan'
	if st.has(cur, 2, ['CC']) && !(cur == 1 && st.at(0) == `M`) {
		// 'bellocchio' but not 'bacchus'
		if st.has(cur + 2, 1, ['I', 'E', 'H']) && !st.has(cur + 2, 2, ['HU']) {
			// 'accident', 'accede', 'succeed'
			if (cur == 1 && st.at(cur - 1) == `A`) || st.has(cur - 1, 5, ['UCCEE', 'UCCES']) {
				st.add('KS')
			} else {
				// 'bacci', 'bertucci', other italian
				st.add('X')
			}
			st.current += 3
			return
		}
		// Pierce's rule
		st.add('K')
		st.current += 2
		return
	}
	if st.has(cur, 2, ['CK', 'CG', 'CQ']) {
		st.add('K')
		st.current += 2
		return
	}
	if st.has(cur, 2, ['CI', 'CE', 'CY']) {
		// italian vs. english
		if st.has(cur, 3, ['CIO', 'CIE', 'CIA']) {
			st.add2('S', 'X')
		} else {
			st.add('S')
		}
		st.current += 2
		return
	}
	st.add('K')
	// name sent in 'mac caffrey', 'mac gregor'
	if st.has(cur + 1, 2, [' C', ' Q', ' G']) {
		st.current += 3
	} else if st.has(cur + 1, 1, ['C', 'K', 'Q']) && !st.has(cur + 1, 2, ['CE', 'CI']) {
		st.current += 2
	} else {
		st.current++
	}
}

fn (mut st DmState) dm_d() {
	cur := st.current
	if st.has(cur, 2, ['DG']) {
		if st.has(cur + 2, 1, ['I', 'E', 'Y']) {
			// e.g. 'edge'
			st.add('J')
			st.current += 3
			return
		}
		// e.g. 'edgar'
		st.add('TK')
		st.current += 2
		return
	}
	if st.has(cur, 2, ['DT', 'DD']) {
		st.add('T')
		st.current += 2
		return
	}
	st.add('T')
	st.current++
}

fn (mut st DmState) dm_g() {
	cur := st.current
	if st.at(cur + 1) == `H` {
		if cur > 0 && !st.vowel_at(cur - 1) {
			st.add('K')
			st.current += 2
			return
		}
		// 'ghislane', 'ghiradelli'
		if cur == 0 {
			if st.at(cur + 2) == `I` {
				st.add('J')
			} else {
				st.add('K')
			}
			st.current += 2
			return
		}
		// Parker's rule (with some further refinements) —
		// e.g. 'hugh', 'bough', 'broughton'
		if (cur > 1 && st.has(cur - 2, 1, ['B', 'H', 'D']))
			|| (cur > 2 && st.has(cur - 3, 1, ['B', 'H', 'D']))
			|| (cur > 3 && st.has(cur - 4, 1, ['B', 'H'])) {
			st.current += 2
			return
		}
		// e.g. 'laugh', 'McLaughlin', 'cough', 'gough', 'rough', 'tough'
		if cur > 2 && st.at(cur - 1) == `U` && st.has(cur - 3, 1, ['C', 'G', 'L', 'R', 'T']) {
			st.add('F')
		} else if cur > 0 && st.at(cur - 1) != `I` {
			st.add('K')
		}
		st.current += 2
		return
	}
	if st.at(cur + 1) == `N` {
		if cur == 1 && st.vowel_at(0) && !st.slavo {
			st.add2('KN', 'N')
		} else if !st.has(cur + 2, 2, ['EY']) && st.at(cur + 1) != `Y` && !st.slavo {
			// not e.g. 'cagney'
			st.add2('N', 'KN')
		} else {
			st.add('KN')
		}
		st.current += 2
		return
	}
	// 'tagliaro'
	if st.has(cur + 1, 2, ['LI']) && !st.slavo {
		st.add2('KL', 'L')
		st.current += 2
		return
	}
	// -ges-, -gep-, -gel-, -gie- at beginning
	if cur == 0 && (st.at(cur + 1) == `Y`
		|| st.has(cur + 1, 2, ['ES', 'EP', 'EB', 'EL', 'EY', 'IB', 'IL', 'IN', 'IE', 'EI', 'ER'])) {
		st.add2('K', 'J')
		st.current += 2
		return
	}
	// -ger-, -gy-
	if (st.has(cur + 1, 2, ['ER']) || st.at(cur + 1) == `Y`)
		&& !st.has(0, 6, ['DANGER', 'RANGER', 'MANGER']) && !st.has(cur - 1, 1, ['E', 'I'])
		&& !st.has(cur - 1, 3, ['RGY', 'OGY']) {
		st.add2('K', 'J')
		st.current += 2
		return
	}
	// italian e.g. 'biaggi'
	if st.has(cur + 1, 1, ['E', 'I', 'Y']) || st.has(cur - 1, 4, ['AGGI', 'OGGI']) {
		// obvious germanic
		if st.germanic || st.has(cur + 1, 2, ['ET']) {
			st.add('K')
		} else if st.has(cur + 1, 4, ['IER ']) {
			// always soft if french ending
			st.add('J')
		} else {
			st.add2('J', 'K')
		}
		st.current += 2
		return
	}
	st.skip_double(`G`)
	st.add('K')
}

fn (mut st DmState) dm_j() {
	cur := st.current
	// obvious spanish, 'jose', 'san jacinto'
	if st.has(cur, 4, ['JOSE']) || st.has(0, 4, ['SAN ']) {
		if (cur == 0 && st.at(cur + 4) == ` `) || st.has(0, 4, ['SAN ']) {
			st.add('H')
		} else {
			st.add2('J', 'H')
		}
		st.current++
		return
	}
	if cur == 0 {
		// Yankelovich / Jankelowicz
		st.add2('J', 'A')
	} else if st.vowel_at(cur - 1) && !st.slavo && (st.at(cur + 1) == `A` || st.at(cur + 1) == `O`) {
		// spanish pronunciation of e.g. 'bajador'
		st.add2('J', 'H')
	} else if cur == st.last {
		st.add2('J', '')
	} else if !st.has(cur + 1, 1, ['L', 'T', 'K', 'S', 'N', 'M', 'B', 'Z'])
		&& !st.has(cur - 1, 1, ['S', 'K', 'L']) {
		st.add('J')
	}
	st.skip_double(`J`) // it could happen
}

fn (mut st DmState) dm_l() {
	cur := st.current
	if st.at(cur + 1) == `L` {
		// spanish e.g. 'cabrillo', 'gallegos'
		if (cur == st.length - 3 && st.has(cur - 1, 4, ['ILLO', 'ILLA', 'ALLE']))
			|| ((st.has(st.last - 1, 2, ['AS', 'OS'])
			|| st.has(st.last, 1, ['A', 'O'])) && st.has(cur - 1, 4, ['ALLE'])) {
			st.add2('L', '')
			st.current += 2
			return
		}
		st.current += 2
	} else {
		st.current++
	}
	st.add('L')
}

fn (mut st DmState) dm_m() {
	cur := st.current
	// 'dumb', 'thumb'
	if (st.has(cur - 1, 3, ['UMB']) && (cur + 1 == st.last || st.has(cur + 2, 2, ['ER'])))
		|| st.at(cur + 1) == `M` {
		st.current += 2
	} else {
		st.current++
	}
	st.add('M')
}

fn (mut st DmState) dm_p() {
	if st.at(st.current + 1) == `H` {
		st.add('F')
		st.current += 2
		return
	}
	// also account for 'campbell', 'raspberry'
	if st.has(st.current + 1, 1, ['P', 'B']) {
		st.current += 2
	} else {
		st.current++
	}
	st.add('P')
}

fn (mut st DmState) dm_r() {
	cur := st.current
	// french e.g. 'rogier', but exclude 'hochmeier'
	if cur == st.last && !st.slavo && st.has(cur - 2, 2, ['IE'])
		&& !st.has(cur - 4, 2, ['ME', 'MA']) {
		st.add2('', 'R')
	} else {
		st.add('R')
	}
	st.skip_double(`R`)
}

fn (mut st DmState) dm_s() {
	cur := st.current
	// special cases 'island', 'isle', 'carlisle', 'carlysle'
	if st.has(cur - 1, 3, ['ISL', 'YSL']) {
		st.current++
		return
	}
	// special case 'sugar-'
	if cur == 0 && st.has(cur, 5, ['SUGAR']) {
		st.add2('X', 'S')
		st.current++
		return
	}
	if st.has(cur, 2, ['SH']) {
		// germanic
		if st.has(cur + 1, 4, ['HEIM', 'HOEK', 'HOLM', 'HOLZ']) {
			st.add('S')
		} else {
			st.add('X')
		}
		st.current += 2
		return
	}
	// italian & armenian
	if st.has(cur, 3, ['SIO', 'SIA']) || st.has(cur, 4, ['SIAN']) {
		if !st.slavo {
			st.add2('S', 'X')
		} else {
			st.add('S')
		}
		st.current += 3
		return
	}
	// german & anglicisations, e.g. 'smith' matches 'schmidt',
	// 'snider' matches 'schneider'; also -sz- in slavic languages
	if (cur == 0 && st.has(cur + 1, 1, ['M', 'N', 'L', 'W'])) || st.has(cur + 1, 1, ['Z']) {
		st.add2('S', 'X')
		if st.has(cur + 1, 1, ['Z']) {
			st.current += 2
		} else {
			st.current++
		}
		return
	}
	if st.has(cur, 2, ['SC']) {
		// Schlesinger's rule
		if st.at(cur + 2) == `H` {
			// dutch origin, e.g. 'school', 'schooner'
			if st.has(cur + 3, 2, ['OO', 'ER', 'EN', 'UY', 'ED', 'EM']) {
				// 'schermerhorn', 'schenker'
				if st.has(cur + 3, 2, ['ER', 'EN']) {
					st.add2('X', 'SK')
				} else {
					st.add('SK')
				}
				st.current += 3
				return
			}
			if cur == 0 && !st.vowel_at(3) && st.at(3) != `W` {
				st.add2('X', 'S')
			} else {
				st.add('X')
			}
			st.current += 3
			return
		}
		if st.has(cur + 2, 1, ['I', 'E', 'Y']) {
			st.add('S')
			st.current += 3
			return
		}
		st.add('SK')
		st.current += 3
		return
	}
	// french e.g. 'resnais', 'artois'
	if cur == st.last && st.has(cur - 2, 2, ['AI', 'OI']) {
		st.add2('', 'S')
	} else {
		st.add('S')
	}
	if st.has(cur + 1, 1, ['S', 'Z']) {
		st.current += 2
	} else {
		st.current++
	}
}

fn (mut st DmState) dm_t() {
	cur := st.current
	if st.has(cur, 4, ['TION']) {
		st.add('X')
		st.current += 3
		return
	}
	if st.has(cur, 3, ['TIA', 'TCH']) {
		st.add('X')
		st.current += 3
		return
	}
	if st.has(cur, 2, ['TH']) || st.has(cur, 3, ['TTH']) {
		// special case 'thomas', 'thames' or germanic
		if st.has(cur + 2, 2, ['OM', 'AM']) || st.germanic {
			st.add('T')
		} else {
			st.add2('0', 'T')
		}
		st.current += 2
		return
	}
	if st.has(cur + 1, 1, ['T', 'D']) {
		st.current += 2
	} else {
		st.current++
	}
	st.add('T')
}

fn (mut st DmState) dm_w() {
	cur := st.current
	// can also be in middle of word
	if st.has(cur, 2, ['WR']) {
		st.add('R')
		st.current += 2
		return
	}
	if cur == 0 && (st.vowel_at(cur + 1) || st.has(cur, 2, ['WH'])) {
		if st.vowel_at(cur + 1) {
			// Wasserman should match Vasserman
			st.add2('A', 'F')
		} else {
			// need Uomo to match Womo
			st.add('A')
		}
	}
	// Arnow should match Arnoff
	if (cur == st.last && st.vowel_at(cur - 1))
		|| st.has(cur - 1, 5, ['EWSKI', 'EWSKY', 'OWSKI', 'OWSKY'])
		|| st.has(0, 3, ['SCH']) {
		st.add2('', 'F')
		st.current++
		return
	}
	// polish e.g. 'filipowicz'
	if st.has(cur, 4, ['WICZ', 'WITZ']) {
		st.add2('TS', 'FX')
		st.current += 4
		return
	}
	// else skip it
	st.current++
}

fn (mut st DmState) dm_x() {
	cur := st.current
	// french e.g. 'breaux'
	if !(cur == st.last && (st.has(cur - 3, 3, ['IAU', 'EAU']) || st.has(cur - 2, 2, ['AU', 'OU']))) {
		st.add('KS')
	}
	if st.has(cur + 1, 1, ['C', 'X']) {
		st.current += 2
	} else {
		st.current++
	}
}

fn (mut st DmState) dm_z() {
	cur := st.current
	// chinese pinyin e.g. 'zhao'
	if st.at(cur + 1) == `H` {
		st.add('J')
		st.current += 2
		return
	}
	if st.has(cur + 1, 2, ['ZO', 'ZI', 'ZA']) || (st.slavo && cur > 0 && st.at(cur - 1) != `T`) {
		st.add2('S', 'TS')
	} else {
		st.add('S')
	}
	st.skip_double(`Z`)
}

// dm_keys_joined keys each whitespace-separated word independently and joins
// the per-word keys with a single space (the similar-module multi-word
// contract).
fn dm_keys_joined(s string) (string, string) {
	words := s.fields()
	mut prims := []string{cap: words.len}
	mut alts := []string{cap: words.len}
	for w in words {
		p, a := similar_double_metaphone(w)
		prims << p
		alts << a
	}
	return prims.join(' '), alts.join(' ')
}

// similar_metaphone_score scores two strings by Double Metaphone key
// agreement: 1.0 for equal strings (case-insensitive) or matching primary
// keys, 0.8 for a primary/alternate or alternate/alternate match, 0.0
// otherwise. Inputs that produce no phonetic key (digits, punctuation)
// score 0.0 unless the strings themselves are equal.
fn similar_metaphone_score(a string, b string) f64 {
	if a.to_lower() == b.to_lower() {
		return 1.0
	}
	pa, sa := dm_keys_joined(a)
	pb, sb := dm_keys_joined(b)
	if pa.trim_space() == '' || pb.trim_space() == '' {
		return 0.0
	}
	if pa == pb {
		return 1.0
	}
	if pa == sb || sa == pb {
		return 0.8
	}
	if sa.trim_space() != '' && sa == sb {
		return 0.8
	}
	return 0.0
}
