module code

// stdlib_similar_metaphone_test.v — reference vectors for the Double
// Metaphone port in stdlib_similar_metaphone.v. Expected keys follow
// Lawrence Philips' reference implementation (CUJ, June 2000), truncated
// to the classic 4-character limit.

struct DmVector {
	word    string
	primary string
	alt     string
}

fn dm_check_vectors(vectors []DmVector) {
	mut fails := []string{}
	for v in vectors {
		p, a := similar_double_metaphone(v.word)
		if p != v.primary || a != v.alt {
			fails << '${v.word}: got (${p}, ${a}) want (${v.primary}, ${v.alt})'
		}
	}
	for f in fails {
		eprintln('double metaphone mismatch: ${f}')
	}
	assert fails.len == 0
}

fn test_dm_common_surnames() {
	dm_check_vectors([
		DmVector{'SMITH', 'SM0', 'XMT'},
		DmVector{'SCHMIDT', 'XMT', 'SMT'},
		DmVector{'JOHNSON', 'JNSN', 'ANSN'},
		DmVector{'WILLIAMS', 'ALMS', 'FLMS'},
		DmVector{'JONES', 'JNS', 'ANS'},
		DmVector{'BROWN', 'PRN', 'PRN'},
		DmVector{'DAVIS', 'TFS', 'TFS'},
		DmVector{'MILLER', 'MLR', 'MLR'},
		DmVector{'WILSON', 'ALSN', 'FLSN'},
		DmVector{'MOORE', 'MR', 'MR'},
		DmVector{'TAYLOR', 'TLR', 'TLR'},
		DmVector{'ANDERSON', 'ANTR', 'ANTR'},
		DmVector{'THOMAS', 'TMS', 'TMS'},
		DmVector{'JACKSON', 'JKSN', 'AKSN'},
		DmVector{'WHITE', 'AT', 'AT'},
		DmVector{'HARRIS', 'HRS', 'HRS'},
		DmVector{'MARTIN', 'MRTN', 'MRTN'},
		DmVector{'THOMPSON', 'TMPS', 'TMPS'},
		DmVector{'GARCIA', 'KRS', 'KRX'},
		DmVector{'MARTINEZ', 'MRTN', 'MRTN'},
		DmVector{'ROBINSON', 'RPNS', 'RPNS'},
		DmVector{'CLARK', 'KLRK', 'KLRK'},
		DmVector{'RODRIGUEZ', 'RTRK', 'RTRK'},
		DmVector{'LEWIS', 'LS', 'LS'},
		DmVector{'LEE', 'L', 'L'},
		DmVector{'WALKER', 'ALKR', 'FLKR'},
		DmVector{'HALL', 'HL', 'HL'},
		DmVector{'ALLEN', 'ALN', 'ALN'},
		DmVector{'YOUNG', 'ANK', 'ANK'},
		DmVector{'HERNANDEZ', 'HRNN', 'HRNN'},
		DmVector{'KING', 'KNK', 'KNK'},
		DmVector{'WRIGHT', 'RT', 'RT'},
		DmVector{'LOPEZ', 'LPS', 'LPS'},
		DmVector{'HILL', 'HL', 'HL'},
		DmVector{'SCOTT', 'SKT', 'SKT'},
		DmVector{'GREEN', 'KRN', 'KRN'},
		DmVector{'ADAMS', 'ATMS', 'ATMS'},
		DmVector{'BAKER', 'PKR', 'PKR'},
		DmVector{'GONZALEZ', 'KNSL', 'KNSL'},
		DmVector{'NELSON', 'NLSN', 'NLSN'},
	])
}

fn test_dm_initial_letter_exceptions() {
	dm_check_vectors([
		DmVector{'XAVIER', 'SF', 'SFR'},
		DmVector{'KNIGHT', 'NT', 'NT'},
		DmVector{'GNOME', 'NM', 'NM'},
		DmVector{'PNEUMONIA', 'NMN', 'NMN'},
		DmVector{'PSYCHO', 'SX', 'SK'},
		DmVector{'WRESTLE', 'RSTL', 'RSTL'},
		DmVector{'AEGIS', 'AJS', 'AKS'},
	])
}

fn test_dm_c_family() {
	dm_check_vectors([
		DmVector{'CZERNY', 'SRN', 'XRN'},
		DmVector{'FOCACCIA', 'FKX', 'FKX'},
		DmVector{'BELLOCCHIO', 'PLX', 'PLX'},
		DmVector{'BACCHUS', 'PKS', 'PKS'},
		DmVector{'ACCIDENT', 'AKST', 'AKST'},
		DmVector{'ACCEDE', 'AKST', 'AKST'},
		DmVector{'ARCH', 'ARX', 'ARK'},
		DmVector{'ARCHITECT', 'ARKT', 'ARKT'},
		DmVector{'ORCHESTRA', 'ARKS', 'ARKS'},
		DmVector{'ORCHID', 'ARKT', 'ARKT'},
		DmVector{'WACHTLER', 'AKTL', 'FKTL'},
		DmVector{'MICHAEL', 'MKL', 'MXL'},
		DmVector{'CAESAR', 'SSR', 'SSR'},
		DmVector{'CHIANTI', 'KNT', 'KNT'},
		DmVector{'MCHUGH', 'MK', 'MK'},
	])
}

fn test_dm_dg_families() {
	dm_check_vectors([
		DmVector{'DUMB', 'TM', 'TM'},
		DmVector{'THUMB', '0M', 'TM'},
		DmVector{'EDGE', 'AJ', 'AJ'},
		DmVector{'EDGAR', 'ATKR', 'ATKR'},
		DmVector{'GHOST', 'KST', 'KST'},
		DmVector{'GHISLANE', 'JLN', 'JLN'},
		DmVector{'AGHAST', 'AKST', 'AKST'},
		DmVector{'LAUGH', 'LF', 'LF'},
		DmVector{'COUGH', 'KF', 'KF'},
		DmVector{'ROUGH', 'RF', 'RF'},
		DmVector{'CAUGHT', 'KFT', 'KFT'},
		DmVector{'TAGLIARO', 'TKLR', 'TLR'},
		DmVector{'AGNES', 'AKNS', 'ANS'},
		DmVector{'WAGNER', 'AKNR', 'FKNR'},
	])
}

fn test_dm_s_family() {
	dm_check_vectors([
		DmVector{'ISLAND', 'ALNT', 'ALNT'},
		DmVector{'ISLE', 'AL', 'AL'},
		DmVector{'SUGAR', 'XKR', 'SKR'},
		DmVector{'SHOE', 'X', 'X'},
		DmVector{'SCHOOL', 'SKL', 'SKL'},
		DmVector{'SCHERMERHORN', 'XRMR', 'SKRM'},
		DmVector{'RESNAIS', 'RSN', 'RSNS'},
	])
}

fn test_dm_jt_families() {
	dm_check_vectors([
		DmVector{'JOSE', 'HS', 'HS'},
		DmVector{'SAN JACINTO', 'SNHS', 'SNHS'},
		DmVector{'YANKELOVICH', 'ANKL', 'ANKL'},
		DmVector{'JANKELOWICZ', 'JNKL', 'ANKL'},
		DmVector{'NATION', 'NXN', 'NXN'},
		DmVector{'WATCH', 'AX', 'FX'},
		DmVector{'THAMES', 'TMS', 'TMS'},
		DmVector{'MATTHEW', 'M0', 'MTF'},
		DmVector{'VON SCHMIDT', 'FNXM', 'FNXM'},
	])
}

fn test_dm_wxz_families() {
	dm_check_vectors([
		DmVector{'ARNOW', 'ARN', 'ARNF'},
		DmVector{'FILIPOWICZ', 'FLPT', 'FLPF'},
		DmVector{'BREAUX', 'PR', 'PR'},
		DmVector{'ZHAO', 'J', 'J'},
		DmVector{'PIZZA', 'PS', 'PTS'},
		DmVector{'ROGIER', 'RJ', 'RJR'},
		DmVector{'CABRILLO', 'KPRL', 'KPR'},
		DmVector{'CAMPBELL', 'KMPL', 'KMPL'},
		DmVector{'PHONE', 'FN', 'FN'},
	])
}

fn test_dm_diacritics_fold() {
	p1, a1 := similar_double_metaphone('José')
	assert p1 == 'HS'
	assert a1 == 'HS'
	p2, a2 := similar_double_metaphone('Muñoz')
	assert p2 == 'MNS'
	assert a2 == 'MNS'
	// folded input must key identically to its plain-ASCII spelling
	p3, a3 := similar_double_metaphone('café')
	p4, a4 := similar_double_metaphone('cafe')
	assert p3 == p4
	assert a3 == a4
	p5, _ := similar_double_metaphone('François')
	assert p5 == 'FRNS'
}

fn test_dm_empty_and_nonletter() {
	p1, a1 := similar_double_metaphone('')
	assert p1 == ''
	assert a1 == ''
	p2, a2 := similar_double_metaphone('123')
	assert p2 == ''
	assert a2 == ''
}

fn test_metaphone_score_exact_and_primary() {
	// case-insensitive equality wins outright
	assert similar_metaphone_score('Smith', 'smith') == 1.0
	// primary/primary key match
	assert similar_metaphone_score('SMITH', 'SMYTHE') == 1.0
	assert similar_metaphone_score('Katherine', 'Catherine') == 1.0
	assert similar_metaphone_score('nation', 'nashun') == 1.0
}

fn test_metaphone_score_alternate() {
	// SMITH (SM0/XMT) vs SCHMIDT (XMT/SMT): primary meets alternate
	assert similar_metaphone_score('SMITH', 'SCHMIDT') == 0.8
	// YANKELOVICH (ANKL/ANKL) vs JANKELOWICZ (JNKL/ANKL)
	assert similar_metaphone_score('YANKELOVICH', 'JANKELOWICZ') == 0.8
}

fn test_metaphone_score_mismatch_and_edges() {
	assert similar_metaphone_score('SMITH', 'JONES') == 0.0
	// empty inputs: equal strings still score 1.0
	assert similar_metaphone_score('', '') == 1.0
	assert similar_metaphone_score('abc', '') == 0.0
	// keyless inputs (digits) only match by literal equality
	assert similar_metaphone_score('123', '123') == 1.0
	assert similar_metaphone_score('123', '456') == 0.0
	// diacritics fold before keying
	assert similar_metaphone_score('José', 'Jose') == 1.0
}

fn test_metaphone_score_multiword() {
	// per-word keys joined with ' ' — both sides key to 'JN SM0'
	assert similar_metaphone_score('JOHN SMITH', 'JON SMYTH') == 1.0
	assert similar_metaphone_score('JOHN SMITH', 'JANE DOE') == 0.0
}
