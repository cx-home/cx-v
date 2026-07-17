module code

import cx
import cxstore
import os

// Stored full-text index for cxstore documents (issue #86 — upgrade ft from
// per-call to stored). Reuses the stdlib_ft tokenizer (segment → case-fold →
// stopword removal → Porter2 stem) so a stored index matches per-call ft
// semantics. The index maps token → store keys (an inverted index); it is a
// derived accelerator — rebuildable by walking the repo's documents, persisted
// as a sidecar TSV for warm start. Lives in module `code` to reuse the private
// tokenizer; operates over a cxstore.Repo.

struct StoredFtIndex {
mut:
	postings map[string][]string // token → store keys (insertion order, unique)
}

// store_ft_pipeline is the default tokenization pipeline (English, case-folded,
// stopworded, Porter2-stemmed) — the ft default surface.
fn store_ft_pipeline() FtPipeline {
	return FtPipeline{
		language:       'en'
		case_sensitive: false
		stem_lang:      'en'
		stopwords_mode: 'default'
		stopwords_set:  map[string]bool{}
		min_token_len:  1
	}
}

// store_ft_collect gathers the searchable text of a node — attribute values and
// scalar/text leaf values (not structural element names).
fn store_ft_collect(n cx.Node, mut out []string) {
	match n {
		cx.Element {
			for a in n.attrs {
				out << cx.scalar_value_str_public(a.value)
			}
			for c in n.items {
				store_ft_collect(c, mut out)
			}
		}
		cx.ScalarNode {
			out << render_scalar(n)
		}
		cx.TextNode {
			out << n.value
		}
		else {}
	}
}

// build_store_ft (re)builds the inverted index by walking every stored document.
fn build_store_ft(repo &cxstore.Repo) StoredFtIndex {
	mut ix := StoredFtIndex{}
	p := store_ft_pipeline()
	for key in repo.list() {
		doc := repo.get_doc(key) or { continue }
		mut parts := []string{}
		for el in doc.elements {
			store_ft_collect(el, mut parts)
		}
		tokens := ft_tokenize_full(parts.join(' '), p)
		mut seen := map[string]bool{}
		for t in tokens {
			if t in seen {
				continue
			}
			seen[t] = true
			if t !in ix.postings {
				ix.postings[t] = []string{}
			}
			ix.postings[t] << key
		}
	}
	return ix
}

// search returns the store keys of documents matching ALL query terms (AND),
// tokenizing the query with the same pipeline used to build the index.
fn (ix &StoredFtIndex) search(query string) []string {
	qtokens := ft_tokenize_full(query, store_ft_pipeline())
	if qtokens.len == 0 {
		return []string{}
	}
	first := ix.postings[qtokens[0]] or { return []string{} }
	mut result := first.clone()
	for i := 1; i < qtokens.len; i++ {
		postings := ix.postings[qtokens[i]] or { return []string{} }
		mut next := []string{}
		for k in result {
			if k in postings {
				next << k
			}
		}
		result = next.clone()
	}
	return result
}

fn (ix &StoredFtIndex) save(path string) ! {
	mut lines := []string{}
	for tok, keys in ix.postings {
		for k in keys {
			lines << '${tok}\t${k}'
		}
	}
	os.write_file(path, lines.join('\n') + '\n')!
}

fn load_store_ft(path string) !StoredFtIndex {
	mut ix := StoredFtIndex{}
	content := os.read_file(path)!
	for line in content.split_into_lines() {
		if line.trim_space() == '' {
			continue
		}
		parts := line.split('\t')
		if parts.len != 2 {
			continue
		}
		if parts[0] !in ix.postings {
			ix.postings[parts[0]] = []string{}
		}
		ix.postings[parts[0]] << parts[1]
	}
	return ix
}
