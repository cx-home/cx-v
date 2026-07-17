module code

import cxstore
import os

fn test_store_ft_search_and_stemming() {
	dir := os.join_path(os.temp_dir(), 'cxstore_ft_rt')
	os.rmdir_all(dir) or {}
	mut repo := cxstore.open_repo(dir) or {
		assert false, 'open: ${err}'
		return
	}
	ka := repo.put_text('[doc [title "the quick brown fox"] [body "it jumps over"]]') or {
		assert false, 'putA: ${err}'
		return
	}
	kb := repo.put_text('[doc [title "a lazy sleeping dog"]]') or {
		assert false, 'putB: ${err}'
		return
	}

	ix := build_store_ft(repo)

	// term hits the right doc
	assert ix.search('quick') == [ka]
	assert ix.search('dog') == [kb]
	// Porter2 stemming: query 'jumping' stems to 'jump', matches 'jumps'
	assert ix.search('jumping') == [ka]
	// stopword-only query yields nothing
	assert ix.search('the') == []
	// absent term
	assert ix.search('zebra') == []
	// AND semantics: both terms in the same doc
	assert ix.search('quick fox') == [ka]
	assert ix.search('quick dog') == [] // not in the same doc

	os.rmdir_all(dir) or {}
}

fn test_store_ft_multi_doc_and_sidecar() {
	dir := os.join_path(os.temp_dir(), 'cxstore_ft_multi')
	os.rmdir_all(dir) or {}
	mut repo := cxstore.open_repo(dir) or {
		assert false, 'open: ${err}'
		return
	}
	k1 := repo.put_text('[log [entry "database error occurred"]]') or {
		assert false, 'put1: ${err}'
		return
	}
	k2 := repo.put_text('[log [entry "database connection restored"]]') or {
		assert false, 'put2: ${err}'
		return
	}
	ix := build_store_ft(repo)
	dbhits := ix.search('database')
	assert dbhits.len == 2
	assert k1 in dbhits && k2 in dbhits
	assert ix.search('error') == [k1]

	// sidecar round-trips
	sc := os.join_path(dir, 'ft.tsv')
	ix.save(sc) or {
		assert false, 'save: ${err}'
		return
	}
	ix2 := load_store_ft(sc) or {
		assert false, 'load: ${err}'
		return
	}
	assert ix2.search('database').len == 2
	assert ix2.search('error') == [k1]

	os.rmdir_all(dir) or {}
}
