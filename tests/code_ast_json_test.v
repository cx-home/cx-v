module main
import code

fn test_program_ast_json_simple_find() {
	json := code.program_ast_json('[?for [pizza [name $n] [price $p]] [yield [hit :name $n :price $p]]]') or { panic(err) }
	assert json.contains('"?for"')
	assert json.contains('"pizza"')
	assert json.contains('"$n"')
	assert json.contains('":yield"')
}

fn test_program_ast_json_empty() {
	json := code.program_ast_json('') or { panic(err) }
	assert json == '{}'
}

fn test_program_ast_json_let_arith() {
	json := code.program_ast_json('[?let [= \$a 10] [?let [= \$b 32] [+ \$a \$b]]]') or { panic(err) }
	assert json.contains('"?let"')
	assert json.contains('":in"') || json.contains('"\$a"')
}
