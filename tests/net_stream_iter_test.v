module main

import os
import testenv
import time
import net

// net_stream_iter_test.v — BEHAVIORAL conformance for §3.4 stream iterators:
// line-iter yields CRLF/LF-stripped lines off a socket until EOF; chunk-iter
// yields fixed-size byte chunks. A V server pushes a few lines then closes; a cx
// client dials, walks the iterator with [?for], and collects the lines.

fn cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint PID + nanosecond-salted band (26800-26899) so the concurrent
// `v test vcx/tests/` gate processes don't collide on a port.
fn pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26800 + int(salt)
}

fn write_tmp(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn test_net_line_iter() {
	port := pick_port()
	mut l := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind ${port}: ${err}')
		return
	}
	l.set_accept_timeout(5 * time.second)
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		c.write_string('alpha\nbravo\ncharlie\n') or {}
		c.close() or {} // EOF terminates the iterator
		l.close() or {}
	}(mut l)

	// cx client: dial, walk line-iter, yield each line joined.
	prog := write_tmp('cx_lineiter.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?let [= \$s [\$net:dial-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [?for [in \$ln [\$net:line-iter \$s]]\n' +
		'    [yield \$ln]]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output
	assert out.contains('alpha'), 'line-iter missed alpha; got: ${out}'
	assert out.contains('bravo'), 'line-iter missed bravo; got: ${out}'
	assert out.contains('charlie'), 'line-iter missed charlie; got: ${out}'
}

fn test_net_chunk_iter() {
	port := pick_port() + 30
	mut l := net.listen_tcp(.ip, '127.0.0.1:${port}') or {
		eprintln('SKIP: cannot bind ${port}: ${err}')
		return
	}
	l.set_accept_timeout(5 * time.second)
	srv := spawn fn (mut l net.TcpListener) {
		mut c := l.accept() or {
			l.close() or {}
			return
		}
		c.write_string('0123456789ABCDE') or {} // 15 bytes → chunks of 4 + a tail
		c.close() or {}
		l.close() or {}
	}(mut l)

	// walk chunk-iter (size 4) and count the chunks: ceil(15/4) = 4.
	prog := write_tmp('cx_chunkiter.cx', '[?lib \'cx-stdlib/net\' :as net]\n' +
		'[?lib \'cx-stdlib/bytes\' :as bytes]\n' +
		'[?let [= \$s [\$net:dial-tcp "tcp://127.0.0.1:${port}" {}]]\n' +
		'  [\$count [?for [in \$ck [\$net:chunk-iter \$s 4]]\n' +
		'    [yield [\$bytes:to-string-latin1 \$ck]]]]]\n')
	res := os.execute('${cx_binary()} --allow-net=127.0.0.1:${port} ${prog}')
	srv.wait()
	out := res.output.trim_space()
	assert out == '4', 'chunk-iter did not yield 4 chunks for 15 bytes @ size 4; got: ${out}'
}
