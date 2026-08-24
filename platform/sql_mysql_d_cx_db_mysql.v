module platform

import db.mysql

// mysql engine for the SQL surface (sql.v) — gated `-d cx_db_mysql`, so the
// default/wasm build never links libmysqlclient. Implements the SqlConn trait.
// URL: mysql://[user[:password]@]host[:port]/dbname ; open cap-guards `net`.
//
// Params: the simple libmysqlclient query() path has no placeholder binding, so
// `?` holes are filled with `escape_string`-quoted values (injection-safe; all
// params arrive as strings). Typed prepared-statement binding is a follow-up.

struct MysqlConn {
mut:
	db mysql.DB
}

fn mysql_url_parse(url string) (string, u32, string, string, string) {
	mut s := url
	if s.starts_with('mysql://') {
		s = s['mysql://'.len..]
	}
	mut user := 'root'
	mut password := ''
	if s.contains('@') {
		cred := s.all_before('@')
		s = s.all_after('@')
		if cred.contains(':') {
			user = cred.all_before(':')
			password = cred.all_after(':')
		} else {
			user = cred
		}
	}
	mut dbname := ''
	if s.contains('/') {
		dbname = s.all_after('/')
		s = s.all_before('/')
	}
	mut host := s
	mut port := u32(3306)
	if s.contains(':') {
		host = s.all_before_last(':')
		port = s.all_after_last(':').u32()
	}
	if host == '' {
		host = '127.0.0.1'
	}
	return host, port, user, password, dbname
}

fn new_mysql_conn(url string) !SqlConn {
	host, port, user, password, dbname := mysql_url_parse(url)
	db := mysql.connect(mysql.Config{
		host:     host
		port:     port
		user:     user
		password: password
		dbname:   dbname
	})!
	return &MysqlConn{
		db: db
	}
}

fn mysql_bind(db &mysql.DB, stmt string, params []string) string {
	if params.len == 0 {
		return stmt
	}
	parts := stmt.split('?')
	mut out := ''
	for i, part in parts {
		out += part
		if i < parts.len - 1 {
			out += if i < params.len {
				"'" + db.escape_string(params[i]) + "'"
			} else {
				'?'
			}
		}
	}
	return out
}

fn (mut c MysqlConn) run(stmt string, params []string) !SqlResult {
	q := mysql_bind(&c.db, stmt, params)
	res := c.db.query(q)!
	mut cols := []string{}
	mut data := [][]string{}
	// Non-SELECT statements (DDL/INSERT/UPDATE) produce no result set: store_result
	// returns a nil pointer, and rows()/maps() would deref it. Only read rows when
	// a result set exists. Field.name is module-private, so columns come from maps()
	// (keyed by column name; V maps preserve insertion order = column order).
	if res.result != unsafe { nil } {
		rows_maps := res.maps()
		for i, m in rows_maps {
			mut rowvals := []string{cap: m.len}
			for k, v in m {
				if i == 0 {
					cols << k
				}
				rowvals << v
			}
			data << rowvals
		}
		res.free()
	}
	return SqlResult{
		cols:       cols
		rows:       data
		changes:    int(c.db.affected_rows())
		last_rowid: i64(c.db.last_id())
	}
}

fn (mut c MysqlConn) shutdown() {
	c.db.close() or {}
}
