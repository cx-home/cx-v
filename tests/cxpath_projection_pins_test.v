// cxpath_projection_pins_test.v — pins two CXPath/projection behaviors that
// were BROKEN on earlier builds and healed since; both cost real workaround
// code in shipped tools (xap-marine, xap-store-console stage1-check), so they
// are load-bearing properties now, not incidental ones:
//
//   1. `//` descends the anonymous for-comprehension envelope exactly as it
//      descends literal sequences — including mixed children and empty ()
//      yields (the shape stage1-check's violation bags use).
//   2. [$count] over a path projection returns the projection's cardinality
//      (one-level, two-level, and `//`), agreeing with the for-comp count.
//
// Runs the real binary end-to-end (the behaviors live in the eval path-walk).
module main

import os
import testenv

fn cpp_cx_binary() string {
	return testenv.cx_bin()
}

fn cpp_run(name string, prog string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, prog) or { panic('write ${p}: ${err}') }
	r := os.execute('${cpp_cx_binary()} ${p}')
	assert r.exit_code == 0, '${name} failed: ${r.output}'
	return r.output
}

fn test_descend_forcomp_envelope_with_empty_yields() {
	prog := "[?lib 'cx-stdlib/strings' :as s]\n" +
		'[?let [= \$rows [?for [in \$i ("a", "b", "c")]\n' +
		'                 [yield [?if [= \$i "b"] [then [?element "violation" [?attr "n" \$i]]] [else ()]]]]]\n' +
		' [?let [= \$more [?for [in \$i ("d")] [yield ()]]]\n' +
		'  [?let [= \$one [?if true [then ([?element "violation" [?attr "n" "z"]])] [else ()]]]\n' +
		'   [?let [= \$bag [?element "bag" \$rows \$more \$one]]\n' +
		'    ([\$count [?for [in \$x \$bag//violation] [yield \$x]]], [\$s:count [\$cx:emit \$bag] "[violation"])]]]]\n'
	out := cpp_run('cx_cpp_env.cx', prog)
	assert out.contains('(2, 2)'), 'envelope descent broke: ${out}'
}

fn test_count_over_path_projection_cardinality() {
	prog := '[?let [= \$m [?element "package" [?element "exports" [?element "def" [?attr "name" "a"]] [?element "def" [?attr "name" "b"]]]]]\n' +
		' [?let [= \$exl [\$first [?for [in \$e \$m/exports] [yield \$e]]]]\n' +
		'  ([\$count \$exl/def], [\$count [?for [in \$d \$exl/def] [yield \$d]]], [\$count \$m/exports/def], [\$count \$m//def])]]\n'
	out := cpp_run('cx_cpp_count.cx', prog)
	assert out.contains('(2, 2, 2, 2)'), 'projection count broke: ${out}'
}
