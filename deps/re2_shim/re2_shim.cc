// libcx RE2 shim — C-callable wrapper around C++ re2::RE2.
// See re2_shim.h for the contract.

#include "re2_shim.h"
#include <re2/re2.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <map>
#include <vector>

extern "C" {

struct cx_re2 {
    re2::RE2 *re;
};

cx_re2 *cx_re2_compile(const char *pattern) {
    if (!pattern) return nullptr;
    re2::RE2::Options opts;
    opts.set_log_errors(false);
    re2::RE2 *re = new re2::RE2(pattern, opts);
    if (!re->ok()) {
        delete re;
        return nullptr;
    }
    cx_re2 *h = new cx_re2;
    h->re = re;
    return h;
}

int cx_re2_full_match(cx_re2 *re, const char *text, unsigned long text_len) {
    if (!re || !re->re || !text) return 0;
    re2::StringPiece sp(text, static_cast<size_t>(text_len));
    return re2::RE2::FullMatch(sp, *re->re) ? 1 : 0;
}

int cx_re2_partial_match(cx_re2 *re, const char *text, unsigned long text_len) {
    if (!re || !re->re || !text) return 0;
    re2::StringPiece sp(text, static_cast<size_t>(text_len));
    return re2::RE2::PartialMatch(sp, *re->re) ? 1 : 0;
}

int cx_re2_find(cx_re2 *re, const char *text, unsigned long text_len,
                unsigned long start_offset,
                unsigned long *out_start, unsigned long *out_end) {
    if (!re || !re->re || !text || !out_start || !out_end) return 0;
    if (start_offset > text_len) return 0;
    re2::StringPiece sp(text + start_offset,
                        static_cast<size_t>(text_len - start_offset));
    re2::StringPiece match;
    if (!re->re->Match(sp, 0, sp.size(), re2::RE2::UNANCHORED, &match, 1)) {
        return 0;
    }
    *out_start = start_offset + (match.data() - sp.data());
    *out_end = *out_start + match.size();
    return 1;
}

char *cx_re2_replace_all(cx_re2 *re, const char *text, unsigned long text_len,
                         const char *replacement, unsigned long replacement_len) {
    if (!re || !re->re || !text || !replacement) return nullptr;
    std::string out(text, static_cast<size_t>(text_len));
    re2::StringPiece rep(replacement, static_cast<size_t>(replacement_len));
    re2::RE2::GlobalReplace(&out, *re->re, rep);
    char *buf = static_cast<char *>(std::malloc(out.size() + 1));
    if (!buf) return nullptr;
    std::memcpy(buf, out.data(), out.size());
    buf[out.size()] = '\0';
    return buf;
}

void cx_re2_free_string(char *s) {
    if (s) std::free(s);
}

// ── cx-stdlib/re full surface ────────────────────────────────────────────

cx_re2 *cx_re2_compile_opts(const char *pattern, int case_insensitive,
                            int multiline, int dotall, int literal) {
    if (!pattern) return nullptr;
    re2::RE2::Options opts;
    opts.set_log_errors(false);
    if (case_insensitive) opts.set_case_sensitive(false);
    if (dotall) opts.set_dot_nl(true);
    if (literal) opts.set_literal(true);
    // RE2's `^`/`$` are text anchors by default; multiline makes them
    // match at internal line boundaries. The Options have no direct
    // multiline knob — set_one_line(false) is the default and (?m) is the
    // portable enable — so for multiline we set never-capture off and rely
    // on the V layer prepending (?m). When literal is set, anchors are not
    // metacharacters, so multiline is a no-op there.
    (void)multiline;
    re2::RE2 *re = new re2::RE2(pattern, opts);
    if (!re->ok()) {
        delete re;
        return nullptr;
    }
    cx_re2 *h = new cx_re2;
    h->re = re;
    return h;
}

int cx_re2_num_groups(cx_re2 *re) {
    if (!re || !re->re) return -1;
    return re->re->NumberOfCapturingGroups();
}

char *cx_re2_group_names(cx_re2 *re) {
    std::string out;
    if (re && re->re) {
        const std::map<std::string, int> &named =
            re->re->NamedCapturingGroups();
        for (const auto &kv : named) {
            out += kv.first;
            out += '\t';
            out += std::to_string(kv.second);
            out += '\n';
        }
    }
    char *buf = static_cast<char *>(std::malloc(out.size() + 1));
    if (!buf) return nullptr;
    std::memcpy(buf, out.data(), out.size());
    buf[out.size()] = '\0';
    return buf;
}

int cx_re2_match_at(cx_re2 *re, const char *text, unsigned long text_len,
                    unsigned long startpos, long *out_starts,
                    long *out_ends, int max_groups) {
    if (!re || !re->re || !text || !out_starts || !out_ends ||
        max_groups <= 0) {
        return 0;
    }
    if (startpos > text_len) return 0;
    re2::StringPiece full(text, static_cast<size_t>(text_len));
    // RE2::Match writes one StringPiece per group (0 = whole match).
    std::vector<re2::StringPiece> subs(static_cast<size_t>(max_groups));
    bool ok = re->re->Match(full, static_cast<size_t>(startpos),
                            static_cast<size_t>(text_len),
                            re2::RE2::UNANCHORED, subs.data(), max_groups);
    if (!ok) return 0;
    for (int i = 0; i < max_groups; i++) {
        if (subs[i].data() == nullptr) {
            out_starts[i] = -1;
            out_ends[i] = -1;
        } else {
            long st = static_cast<long>(subs[i].data() - full.data());
            out_starts[i] = st;
            out_ends[i] = st + static_cast<long>(subs[i].size());
        }
    }
    return 1;
}

char *cx_re2_quote_meta(const char *s, unsigned long s_len) {
    std::string in(s ? s : "", static_cast<size_t>(s ? s_len : 0));
    std::string quoted = re2::RE2::QuoteMeta(in);
    char *buf = static_cast<char *>(std::malloc(quoted.size() + 1));
    if (!buf) return nullptr;
    std::memcpy(buf, quoted.data(), quoted.size());
    buf[quoted.size()] = '\0';
    return buf;
}

void cx_re2_destroy(cx_re2 *re) {
    if (!re) return;
    delete re->re;
    delete re;
}

const char *cx_re2_version(void) {
    // RE2 doesn't ship a version macro; the package version is the
    // Homebrew/apt label. Diagnostic-only — bindings call this at
    // load time for the trace log.
    return "re2-system";
}

} // extern "C"
