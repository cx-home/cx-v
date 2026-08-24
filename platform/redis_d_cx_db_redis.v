@[has_globals]
module platform
import code {
	cap_guard,
	mk_err,
}

import cx
import db.redis
import math.big

// redis engine for the database-access layer (#75) — gated `-d cx_db_redis`, so
// the default/wasm build never compiles it. redis is NOT SQL and NOT cxstore: it
// exposes its own native power. The V client is pure-V (RESP over TCP, no C dep).
//
// One generic command verb exposes EVERY redis command — the whole native
// surface, not a fixed subset:
//
//   [$redis-open URL]            -> [redis-db handle=N url=…]   (url: redis://[:pw@]host[:port])
//   [$redis-cmd HANDLE WORD+]    -> RESP reply mapped to CX data
//   [$redis-close HANDLE]        -> null
//
// RESP→CX: simple/bulk string, integer, double, bool, bignum → scalar; null →
// CX null; array → [list …]; set → [set …]; push → [push …]; map → [map [k v] …].
// Networked, so redis-open cap-guards `net`.

@[heap]
struct RedisRegistry {
mut:
	conns   map[int]&redis.DB
	next_id int
}

__global (
	g_redis_reg voidptr
)

fn redis_reg() &RedisRegistry {
	if g_redis_reg == unsafe { nil } {
		r := &RedisRegistry{
			conns: map[int]&redis.DB{}
		}
		g_redis_reg = voidptr(r)
	}
	return unsafe { &RedisRegistry(g_redis_reg) }
}

// redis_url_parse extracts host, port and optional password from
// redis://[user:password@]host[:port][/db]; db index is ignored (use SELECT).
fn redis_url_parse(url string) (string, u16, string) {
	mut s := url
	if s.starts_with('redis://') {
		s = s['redis://'.len..]
	} else if s.starts_with('rediss://') {
		s = s['rediss://'.len..]
	}
	mut password := ''
	if s.contains('@') {
		cred := s.all_before('@')
		s = s.all_after('@')
		password = if cred.contains(':') { cred.all_after_last(':') } else { cred }
	}
	if s.contains('/') {
		s = s.all_before('/')
	}
	mut host := s
	mut port := u16(6379)
	if s.contains(':') {
		host = s.all_before_last(':')
		port = s.all_after_last(':').u16()
	}
	if host == '' {
		host = '127.0.0.1'
	}
	return host, port, password
}

fn redis_handle_of(n cx.Node) ?int {
	if n is cx.Element && n.name == 'redis-db' {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}

pub fn redis_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'redis-open' { return redis_open_impl(args) }
		'redis-cmd' { return redis_cmd_impl(args) }
		'redis-close' { return redis_close_impl(args) }
		else { return none }
	}
}

fn redis_open_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: redis-open expects ($url)')
	}
	url := store_arg_str(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: redis-open expects a url string')
	}
	if d := cap_guard('net', 'redis open ${url}') {
		return d
	}
	host, port, password := redis_url_parse(url)
	db := redis.connect(redis.Config{
		host:     host
		port:     port
		password: password
	}) or {
		return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${err.msg()}')
	}
	mut reg := redis_reg()
	id := reg.next_id
	reg.next_id++
	reg.conns[id] = &db
	return cx.Element{
		name:  'redis-db'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'url'
				value: cx.ScalarValue(url)
			},
		]
	}
}

fn redis_cmd_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: redis-cmd expects ($db, $word, $words…)')
	}
	id := redis_handle_of(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: redis-cmd expects a [redis-db] handle')
	}
	mut parts := []string{cap: args.len}
	for i, a in args[1..] {
		// §8 (#524, same tightening as the §7.1 bind params): a non-string
		// command word REFUSES named — never the silent ''-degrade.
		parts << store_arg_str(a) or {
			return mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: redis-cmd word ${i + 1} is not a string scalar — command words are string scalars only (db_access.md §8); convert explicitly (e.g. [\$concat \'\' \$v])')
		}
	}
	if parts.len == 0 {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: redis-cmd needs at least a command word')
	}
	mut reg := redis_reg()
	mut db := reg.conns[id] or {
		return mk_err('cx-err:CXER1120', 'E_REDIS: unknown redis handle ${id}')
	}
	rv := db.cmd(...parts) or {
		return mk_err('cx-err:CXER1120', 'E_REDIS: ${err.msg()}')
	}
	return redis_val_to_cx(rv)
}

fn redis_close_impl(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0108', 'E_ARG: redis-close expects ($db)')
	}
	id := redis_handle_of(args[0]) or {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: redis-close expects a [redis-db] handle')
	}
	mut reg := redis_reg()
	mut db := reg.conns[id] or { return store_null() }
	db.close() or {}
	reg.conns.delete(id)
	return store_null()
}

fn redis_scalar_key(v redis.RedisValue) string {
	return match v {
		[]u8 { v.bytestr() }
		string { v }
		i64 { v.str() }
		else { 'key' }
	}
}

fn redis_val_to_cx(v redis.RedisValue) cx.Node {
	match v {
		bool {
			return store_str(v.str())
		}
		i64 {
			return store_str(v.str())
		}
		f32 {
			return store_str(v.str())
		}
		f64 {
			return store_str(v.str())
		}
		big.Integer {
			return store_str(v.str())
		}
		string {
			return store_str(v)
		}
		[]u8 {
			return store_str(v.bytestr())
		}
		redis.RedisNull {
			return store_null()
		}
		redis.RedisVerbatim {
			return store_str(v.data.bytestr())
		}
		redis.RedisBlobError {
			return mk_err('cx-err:CXER1120', 'E_REDIS: ${v.data.bytestr()}')
		}
		[]redis.RedisValue {
			mut items := []cx.Node{cap: v.len}
			for e in v {
				items << redis_val_to_cx(e)
			}
			return cx.Element{
				name:  'list'
				items: items
			}
		}
		redis.RedisSet {
			mut items := []cx.Node{cap: v.elements.len}
			for e in v.elements {
				items << redis_val_to_cx(e)
			}
			return cx.Element{
				name:  'set'
				items: items
			}
		}
		redis.RedisPush {
			mut items := []cx.Node{cap: v.elements.len}
			for e in v.elements {
				items << redis_val_to_cx(e)
			}
			return cx.Element{
				name:  'push'
				items: items
			}
		}
		map[string]redis.RedisValue {
			mut items := []cx.Node{cap: v.len}
			for k, val in v {
				items << cx.Element{
					name:  k
					items: [redis_val_to_cx(val)]
				}
			}
			return cx.Element{
				name:  'map'
				items: items
			}
		}
		redis.RedisMap {
			mut items := []cx.Node{cap: v.pairs.len / 2}
			mut i := 0
			for i + 1 < v.pairs.len {
				key := redis_scalar_key(v.pairs[i])
				items << cx.Element{
					name:  key
					items: [redis_val_to_cx(v.pairs[i + 1])]
				}
				i += 2
			}
			return cx.Element{
				name:  'map'
				items: items
			}
		}
	}
}
