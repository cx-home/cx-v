/* libcx RE2 shim — C-callable wrapper around C++ re2::RE2.
 *
 * Phase 7.74c-schema-validator-v-core (+ spec/schema.md §7).
 * Used by the V core schema validator's S008 pattern check; bindings
 * never call this header directly — they go through cx_validate /
 * cx_validate_apply_defaults via the C ABI, so RE2's regex semantics
 * are centralised at the libcx boundary and identical across all
 * language bindings (per the locked decision in spec/abi.md §3 and
 * spec/schema.md §7).
 *
 * Linkage: depends on system RE2 (Homebrew `re2` on macOS /
 * `libre2-dev` on Debian/Ubuntu); vendored-submodule path
 * is queued post-tag for full source-pin determinism. The C++
 * exception machinery is suppressed at this boundary: every entry
 * point either succeeds or returns a NULL/ZERO sentinel.
 */

#ifndef CX_RE2_SHIM_H
#define CX_RE2_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. */
typedef struct cx_re2 cx_re2;

/* Compile `pattern` as an RE2 anchored-or-unanchored regex. Returns
 * NULL on parse / unsupported-feature failure. The caller releases
 * the handle with cx_re2_destroy. */
cx_re2 *cx_re2_compile(const char *pattern);

/* Return 1 when `text` (length `text_len`) fully matches the pattern;
 * 0 otherwise. Full-match semantics align with spec/schema.md §7
 * `:pat='...'` ("must match the regex" — the schema author writes
 * `^...$` for partial matches, but the validator treats `:pat` as a
 * full-match by default since that's the common-case schema
 * authoring pattern). Returns 0 when `re == NULL`.
 *
 * The text-length variant avoids a NUL-scan on long inputs. */
int cx_re2_full_match(cx_re2 *re, const char *text, unsigned long text_len);

/* Return 1 when the regex matches anywhere in `text`; 0 otherwise.
 * Backs XPath 4.0 fn:matches — the schema validator uses the full-
 * match variant above; fn:matches uses partial semantics so an
 * unanchored pattern like `[0-9]+` matches any input that contains
 * a digit run. C5 (regex family). */
int cx_re2_partial_match(cx_re2 *re, const char *text, unsigned long text_len);

/* Find the next match starting at `start_offset` in `text`. On match,
 * writes the match start/end byte offsets to *out_start / *out_end
 * and returns 1. On no-match, returns 0 and leaves the out params
 * unchanged. Used by V-side tokenize / split implementations that
 * iterate matches without allocating intermediate arrays at the
 * shim boundary. C5 (regex family). */
int cx_re2_find(cx_re2 *re, const char *text, unsigned long text_len,
                unsigned long start_offset,
                unsigned long *out_start, unsigned long *out_end);

/* Replace every non-overlapping match of the pattern in `text` with
 * `replacement` (RE2 replacement syntax: `\1`..`\9` back-refs etc.).
 * Returns a malloc'd NUL-terminated buffer that the caller frees via
 * cx_re2_free_string, or NULL on internal failure (out-of-memory).
 * C5 (regex family). */
char *cx_re2_replace_all(cx_re2 *re, const char *text, unsigned long text_len,
                         const char *replacement, unsigned long replacement_len);

/* Release a string returned by cx_re2_replace_all. Safe on NULL. */
void cx_re2_free_string(char *s);

/* ── cx-stdlib/re full surface (spec/std-lib/re.md) ──────────────────────
 *
 * The functions below back the cx-stdlib/re module's capture-group,
 * flag, inspection and escape surface. They compose with the
 * schema-validator surface above (same engine, same handle type).
 *
 * Flag handling: `case_insensitive` / `multiline` / `dotall` map to RE2
 * inline-flag semantics ((?i)/(?m)/(?s)); `literal` uses RE2's literal
 * Options. Unicode class rewriting (\d→\p{Nd}, etc. for unicode=true) is
 * performed on the V side before the pattern reaches this layer, so the
 * shim is encoding-agnostic. */

/* Compile with flags. Returns NULL on parse / unsupported-feature
 * failure (caller distinguishes CXER3200 vs CXER3201 by pre-scan). */
cx_re2 *cx_re2_compile_opts(const char *pattern, int case_insensitive,
                            int multiline, int dotall, int literal);

/* Number of capturing groups (group 0 / the full match excluded), i.e.
 * RE2::NumberOfCapturingGroups(). Returns -1 when re == NULL. */
int cx_re2_num_groups(cx_re2 *re);

/* Returns a malloc'd, NUL-terminated buffer listing the named capturing
 * groups, one per line as "name\tindex\n" (index is the 1-based group
 * number). Empty string when there are no named groups. NULL on OOM.
 * Caller frees with cx_re2_free_string. The order is the RE2 map order
 * (ascending group index is NOT guaranteed; the V side sorts by index). */
char *cx_re2_group_names(cx_re2 *re);

/* Match the regex against text starting the search at `startpos` (the
 * full buffer is passed so ^ / \b / multiline anchors see real context).
 * On match, writes byte [start,end) for groups 0..max_groups-1 into
 * out_starts / out_ends and returns 1; an unset group writes -1/-1.
 * Returns 0 on no-match. The search is UNANCHORED (group 0 is the first
 * match at or after startpos). max_groups should be num_groups + 1. */
int cx_re2_match_at(cx_re2 *re, const char *text, unsigned long text_len,
                    unsigned long startpos, long *out_starts,
                    long *out_ends, int max_groups);

/* RE2::QuoteMeta — canonical escape of `s` so it matches literally.
 * Returns a malloc'd NUL-terminated buffer; caller frees with
 * cx_re2_free_string. NULL on OOM. */
char *cx_re2_quote_meta(const char *s, unsigned long s_len);

/* Release the handle. Safe on NULL. */
void cx_re2_destroy(cx_re2 *re);

/* Library version string ("re2 0.YYYY.MM.DD" or similar) for
 * diagnostic purposes. */
const char *cx_re2_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CX_RE2_SHIM_H */
