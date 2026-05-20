module main

import cx

// Z3 — Locale-sensitive fn library per spec/i18n.md §1.
// v0.7.0 ships format-number with locale-aware separators driven
// by the input document's cx:lang. Other locale-sensitive fns
// (format-date, compare with collation) maintain the v0.6.0
// surface; full ICU/CLDR-grade locale support is filed as v0.7.x
// pending V's ICU integration story.

fn test_z3_format_number_en_default() {
	out := cx.eval_cxl('[doc cx:lang=en]',
		"[?=[?format-number [1234567.89, '#,##0.00']]]", '') or { panic('${err}') }
	assert out == '1,234,567.89', 'en: expected 1,234,567.89, got: "${out}"'
}

fn test_z3_format_number_de_locale() {
	out := cx.eval_cxl('[doc cx:lang=de]',
		"[?=[?format-number [1234567.89, '#,##0.00']]]", '') or { panic('${err}') }
	assert out == '1.234.567,89', 'de: expected 1.234.567,89, got: "${out}"'
}

fn test_z3_format_number_fr_locale() {
	out := cx.eval_cxl('[doc cx:lang=fr]',
		"[?=[?format-number [1234567.89, '#,##0.00']]]", '') or { panic('${err}') }
	assert out == '1 234 567,89', 'fr: expected 1 234 567,89, got: "${out}"'
}

fn test_z3_format_number_explicit_lang_arg_overrides_doc_lang() {
	// 3rd arg supplies explicit lang; overrides doc-level cx:lang.
	out := cx.eval_cxl('[doc cx:lang=en]',
		"[?=[?format-number [1234.5, '#,##0.0', 'de']]]", '') or { panic('${err}') }
	assert out == '1.234,5', 'expected de output, got: "${out}"'
}

fn test_z3_format_number_unknown_lang_falls_back_to_en() {
	out := cx.eval_cxl('[doc cx:lang=zh-Hans]',
		"[?=[?format-number [1000, '#,##0']]]", '') or { panic('${err}') }
	assert out == '1,000', 'expected en fallback, got: "${out}"'
}

fn test_z3_format_number_negative() {
	out := cx.eval_cxl('[doc cx:lang=en]',
		"[?=[?format-number [-1234.5, '#,##0.00']]]", '') or { panic('${err}') }
	assert out == '-1,234.50', 'expected -1,234.50, got: "${out}"'
}

fn test_z3_format_number_no_group_picture() {
	out := cx.eval_cxl('[doc cx:lang=en]',
		"[?=[?format-number [12345.678, '0.000']]]", '') or { panic('${err}') }
	assert out == '12345.678', 'no group; expected 12345.678, got: "${out}"'
}
