/*
	Coypright 2017 Daniel Nichter
	Copyright 2014-2016 Percona LLC and/or its affiliates
*/

package query_test

import (
	"testing"

	"github.com/go-mysql/query"
)

// Uncomment to check for 100% test coverage:
//query.Debug = true

func TestFingerprintBasic(t *testing.T) {
	var q string
	var f string

	// A most basic case.
	q = "SELECT c FROM t WHERE id=1"
	f = "select c from t where id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// The values looks like one line -- comments, but they're not.
	q = `UPDATE groups_search SET  charter = '   -------3\'\' XXXXXXXXX.\n    \n    -----------------------------------------------------', show_in_list = 'Y' WHERE group_id='aaaaaaaa'`
	f = "update groups_search set charter = ?, show_in_list = ? where group_id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// PT treats this as "mysqldump", but we don't do any special fingerprints.
	q = "SELECT /*!40001 SQL_NO_CACHE */ * FROM `film`"
	f = "select /*!40001 sql_no_cache */ * from `film`"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Fingerprints stored procedure calls specially
	q = "CALL foo(1, 2, 3)"
	f = "call foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Fingerprints admin commands as themselves
	q = "administrator command: Init DB"
	f = "administrator command: Init DB"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Removes identifier from USE
	q = "use `foo`"
	f = "use ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Handles bug from perlmonks thread 728718
	q = "select null, 5.001, 5001. from foo"
	f = "select ?, ?, ? from foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Handles quoted strings
	q = "select 'hello', '\nhello\n', \"hello\", '\\'' from foo"
	f = "select ?, ?, ?, ? from foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Handles trailing newline
	q = "select 'hello'\n"
	f = "select ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "select '\\\\' from foo"
	f = "select ? from foo" // +1
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Collapses whitespace
	q = "select   foo"
	f = "select foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Lowercases, replaces integer
	q = "SELECT * from foo where a = 5"
	f = "select * from foo where a = ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Floats
	q = "select 0e0, +6e-30, -6.00 from foo where a = 5.5 or b=0.5 or c=.5"
	f = "select ?, ?, ? from foo where a = ? or b=? or c=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Hex/bit
	q = "select 0x0, x'123', 0b1010, b'10101' from foo"
	f = "select ?, ?, ?, ? from foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Collapses whitespace
	q = " select  * from\nfoo where a = 5"
	f = "select * from foo where a = ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// IN lists
	q = "select * from foo where a in (5) and b in (5, 8,9 ,9 , 10)"
	f = "select * from foo where a in(?+) and b in(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Numeric table names.  By default, PT will return foo_n, etc. because
	// match_embedded_numbers is false by default for speed.
	q = "select foo_1 from foo_2_3"
	f = "select foo_1 from foo_2_3"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Numeric table name prefixes
	q = "select 123foo from 123foo"
	f = "select 123foo from 123foo" // +1
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Numeric table name prefixes with underscores
	q = "select 123_foo from 123_foo"
	f = "select 123_foo from 123_foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// A string that needs no changes
	q = "insert into abtemp.coxed select foo.bar from foo"
	f = "insert into abtemp.coxed select foo.bar from foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// limit alone
	q = "select * from foo limit 5"
	f = "select * from foo limit ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// limit with comma-offset
	q = "select * from foo limit 5, 10"
	f = "select * from foo limit ?, ?" // +1
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// limit with offset
	q = "select * from foo limit 5 offset 10"
	f = "select * from foo limit ? offset ?" // +1
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Fingerprint LOAD DATA INFILE
	q = "LOAD DATA INFILE '/tmp/foo.txt' INTO db.tbl"
	f = "load data infile ? into db.tbl"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Fingerprint db.tbl<number>name (preserve number)
	q = "SELECT * FROM prices.rt_5min where id=1"
	f = "select * from prices.rt_5min where id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Fingerprint /* -- comment */ SELECT (bug 1174956)
	q = "/* -- S++ SU ABORTABLE -- spd_user: rspadim */SELECT SQL_SMALL_RESULT SQL_CACHE DISTINCT centro_atividade FROM est_dia WHERE unidade_id=1001 AND item_id=67 AND item_id_red=573"
	f = "select sql_small_result sql_cache distinct centro_atividade from est_dia where unidade_id=? and item_id=? and item_id_red=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "INSERT INTO t (ts) VALUES (NOW())"
	f = "insert into t (ts) values(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "INSERT INTO t (ts) VALUES ('()', '\\(', '\\)')"
	f = "insert into t (ts) values(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "select `col` from `table-1` where `id` = 5"
	f = "select `col` from `table-1` where `id` = ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintValueList(t *testing.T) {
	var q string
	var f string

	// VALUES lists
	q = "insert into foo(a, b, c) values(2, 4, 5)"
	f = "insert into foo(a, b, c) values(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// VALUES lists with multiple ()
	q = "insert into foo(a, b, c) values(2, 4, 5) , (2,4,5)"
	f = "insert into foo(a, b, c) values(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// VALUES lists with VALUE()
	q = "insert into foo(a, b, c) value(2, 4, 5)"
	f = "insert into foo(a, b, c) value(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "insert into foo values (1, '(2)', 'This is a trick: ). More values.', 4)"
	f = "insert into foo values(?+)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintInList(t *testing.T) {
	var q string
	var f string

	q = "select * from t where (base.nid IN  ('1412', '1410', '1411'))"
	f = "select * from t where (base.nid in(?+))"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT ID, name, parent, type FROM posts WHERE _name IN ('perf','caching') AND (type = 'page' OR type = 'attachment')"
	f = "select id, name, parent, type from posts where _name in(?+) and (type = ? or type = ?)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT t FROM field WHERE  (entity_type = 'node') AND (entity_id IN  ('609')) AND (language IN  ('und')) AND (deleted = '0') ORDER BY delta ASC"
	f = "select t from field where (entity_type = ?) and (entity_id in(?+)) and (language in(?+)) and (deleted = ?) order by delta"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintOrderBy(t *testing.T) {
	var q string
	var f string

	// Remove ASC from ORDER BY
	// Issue 1030: Fingerprint can remove ORDER BY ASC
	q = "select c from t where i=1 order by c asc"
	f = "select c from t where i=? order by c"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Remove only ASC from ORDER BY
	q = "select * from t where i=1 order by a, b ASC, d DESC, e asc"
	f = "select * from t where i=? order by a, b, d desc, e"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Remove ASC from spacey ORDER BY
	q = `select * from t where i=1      order            by
			  a,  b          ASC, d    DESC,

									 e asc`
	f = "select * from t where i=? order by a, b, d desc, e"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintOneLineComments(t *testing.T) {
	var q string
	var f string

	// Removes one-line comments in fingerprints
	q = "select \n-- bar\n foo"
	f = "select foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Removes one-line comments in fingerprint without mushing things together
	q = "select foo-- bar\n,foo"
	f = "select foo,foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Removes one-line EOL comments in fingerprints
	q = "select foo -- bar\n"
	f = "select foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Removes one-line # hash comments
	q = "### Channels ###\n\u0009\u0009\u0009\u0009\u0009SELECT sourcetable, IF(f.lastcontent = 0, f.lastupdate, f.lastcontent) AS lastactivity,\n\u0009\u0009\u0009\u0009\u0009f.totalcount AS activity, type.class AS type,\n\u0009\u0009\u0009\u0009\u0009(f.nodeoptions \u0026 512) AS noUnsubscribe\n\u0009\u0009\u0009\u0009\u0009FROM node AS f\n\u0009\u0009\u0009\u0009\u0009INNER JOIN contenttype AS type ON type.contenttypeid = f.contenttypeid \n\n\u0009\u0009\u0009\u0009\u0009INNER JOIN subscribed AS sd ON sd.did = f.nodeid AND sd.userid = 15965\n UNION  ALL \n\n\u0009\u0009\u0009\u0009\u0009### Users ###\n\u0009\u0009\u0009\u0009\u0009SELECT f.name AS title, f.userid AS keyval, 'user' AS sourcetable, IFNULL(f.lastpost, f.joindate) AS lastactivity,\n\u0009\u0009\u0009\u0009\u0009f.posts as activity, 'Member' AS type,\n\u0009\u0009\u0009\u0009\u00090 AS noUnsubscribe\n\u0009\u0009\u0009\u0009\u0009FROM user AS f\n\u0009\u0009\u0009\u0009\u0009INNER JOIN userlist AS ul ON ul.relationid = f.userid AND ul.userid = 15965\n\u0009\u0009\u0009\u0009\u0009WHERE ul.type = 'f' AND ul.aq = 'yes'\n ORDER BY title ASC LIMIT 100"
	f = "select sourcetable, if(f.lastcontent = ?, f.lastupdate, f.lastcontent) as lastactivity, f.totalcount as activity, type.class as type, (f.nodeoptions & ?) as nounsubscribe from node as f inner join contenttype as type on type.contenttypeid = f.contenttypeid inner join subscribed as sd on sd.did = f.nodeid and sd.userid = ? union all select f.name as title, f.userid as keyval, ? as sourcetable, ifnull(f.lastpost, f.joindate) as lastactivity, f.posts as activity, ? as type, ? as nounsubscribe from user as f inner join userlist as ul on ul.relationid = f.userid and ul.userid = ? where ul.type = ? and ul.aq = ? order by title limit ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintTricky(t *testing.T) {
	var q string
	var f string

	// Full hex can look like an ident if not for the leading 0x.
	q = "SELECT c FROM t WHERE id=0xdeadbeaf"
	f = "select c from t where id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Caused a crash.
	q = "SELECT *    FROM t WHERE 1=1 AND id=1"
	f = "select * from t where ?=? and id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Caused a crash.
	q = "SELECT `db`.*, (CASE WHEN (`date_start` <=  '2014-09-10 09:17:59' AND `date_end` >=  '2014-09-10 09:17:59') THEN 'open' WHEN (`date_start` >  '2014-09-10 09:17:59' AND `date_end` >  '2014-09-10 09:17:59') THEN 'tbd' ELSE 'none' END) AS `status` FROM `foo` AS `db` WHERE (a_b in ('1', '10101'))"
	f = "select `db`.*, (case when (`date_start` <= ? and `date_end` >= ?) then ? when (`date_start` > ? and `date_end` > ?) then ? else ? end) as `status` from `foo` as `db` where (a_b in(?+))"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// VALUES() after ON DUPE KEY is not the same as VALUES() for INSERT.
	q = "insert into t values (1) on duplicate key update query_count=COALESCE(query_count, 0) + VALUES(query_count)"
	f = "insert into t values(?+) on duplicate key update query_count=coalesce(query_count, ?) + values(query_count)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
	q = "insert into t values (1), (2), (3)\n\n\ton duplicate key update query_count=1"
	f = "insert into t values(?+) on duplicate key update query_count=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "select  t.table_schema,t.table_name,engine  from information_schema.tables t  inner join information_schema.columns c  on t.table_schema=c.table_schema and t.table_name=c.table_name group by t.table_schema,t.table_name having  sum(if(column_key in ('PRI','UNI'),1,0))=0"
	f = "select t.table_schema,t.table_name,engine from information_schema.tables t inner join information_schema.columns c on t.table_schema=c.table_schema and t.table_name=c.table_name group by t.table_schema,t.table_name having sum(if(column_key in(?+),?,?))=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Empty value list is valid SQL.
	q = "INSERT INTO t () VALUES ()"
	f = "insert into t () values()"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestNumbersInFunctions(t *testing.T) {
	var q string
	var f string

	// Full hex can look like an ident if not for the leading 0x.
	q = "select sleep(2) from test.n"
	f = "select sleep(?) from test.n"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestId(t *testing.T) {
	var f string
	var id string

	f = "hello world"
	id = "93CB22BB8F5ACDC3"
	if got := query.Id(f); got != id {
		t.Error("got %s \nexpected %d", got, id)
	}

	f = "select sourcetable, if(f.lastcontent = ?, f.lastupdate, f.lastcontent) as lastactivity, f.totalcount as activity, type.class as type, (f.nodeoptions & ?) as nounsubscribe from node as f inner join contenttype as type on type.contenttypeid = f.contenttypeid inner join subscribed as sd on sd.did = f.nodeid and sd.userid = ? union all select f.name as title, f.userid as keyval, ? as sourcetable, ifnull(f.lastpost, f.joindate) as lastactivity, f.posts as activity, ? as type, ? as nounsubscribe from user as f inner join userlist as ul on ul.relationid = f.userid and ul.userid = ? where ul.type = ? and ul.aq = ? order by title limit ?"
	id = "DB9EF18846547B8C"
	if got := query.Id(f); got != id {
		t.Error("got %s \nexpected %d", got, id)
	}

	f = "select sleep(?) from n"
	id = "7F7D57ACDD8A346E"
	if got := query.Id(f); got != id {
		t.Error("got %s \nexpected %d", got, id)
	}
}

func TestFingerprintPanicChallenge1(t *testing.T) {
	var q string
	var f string

	q = "SELECT '' '' ''"
	f = "select ? ? ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT '' '' '' FROM kamil"
	f = "select ? ? ? from kamil"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT 'a' 'b' 'c' 'd'"
	f = "select ? ? ? ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT 'a' 'b' 'c' 'd' FROM kamil"
	f = "select ? ? ? ? from kamil"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintDashesInNames(t *testing.T) {
	var q string
	var f string

	q = "select field from `master-db-1`.`table-1` order by id, ?;"
	f = "select field from `master-db-1`.`table-1` order by id, ?;"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "select field from `-master-db-1`.`-table-1-` order by id, ?;"
	f = "select field from `-master-db-1`.`-table-1-` order by id, ?;"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT BENCHMARK(100000000, pow(rand(), rand())), 1 FROM `-hj-7d6-shdj5-7jd-kf-g988h-`.`-aaahj-7d6-shdj5-7&^%$jd-kf-g988h-9+4-5*6ab-`"
	f = "select benchmark(?, pow(rand(), rand())), ? from `-hj-7d6-shdj5-7jd-kf-g988h-`.`-aaahj-7d6-shdj5-7&^%$jd-kf-g988h-9+4-5*6ab-`"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT BENCHMARK(100000000, pow(rand(), rand())), name from `-hj-7d6-shdj5-7jd-kf-g988h-`.`-aaahj-7d6-shdj5-7jd-kf-g988h-`"
	f = "select benchmark(?, pow(rand(), rand())), name from `-hj-7d6-shdj5-7jd-kf-g988h-`.`-aaahj-7d6-shdj5-7jd-kf-g988h-`"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintKeywords(t *testing.T) {
	var q string
	var f string

	// values is a keyword but value is not. :-\
	q = "SELECT name, value FROM variable"
	f = "select name, value from variable"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintUseIndex(t *testing.T) {
	var q string
	var f string

	q = `SELECT 	1 AS one FROM calls USE INDEX(index_name)`
	f = "select ? as one from calls use index(index_name)"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestFingerprintWithNumberInDbName(t *testing.T) {
	var q string
	var f string

	defaultReplaceNumbersInWords := query.ReplaceNumbersInWords
	query.ReplaceNumbersInWords = true
	defer func() {
		// Restore default value for other tests
		query.ReplaceNumbersInWords = defaultReplaceNumbersInWords
	}()

	q = "SELECT c FROM org235.t WHERE id=0xdeadbeaf"
	f = "select c from org?.t where id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "CREATE DATABASE org235_percona345 COLLATE 'utf8_general_ci'"
	f = "create database org?_percona? collate ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "select foo_1 from foo_2_3"
	f = "select foo_? from foo_?_?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	q = "SELECT * FROM prices.rt_5min where id=1"
	f = "select * from prices.rt_?min where id=?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}

	// Prefixes are not supported, requires more hacks
	q = "select 123foo from 123foo"
	f = "select 123foo from 123foo"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}

func TestBackticks(t *testing.T) {
	var q string
	var f string

	q = "select `tbl_ids`.`tbl_col`, `tbl_ids`.`id_col`, `tbl_ids`.`updated_at`, `tbl_ids`.`nickname`, `users`.`id_active`, `alias_35017380`.`usr_id` from `tbl_ids` join `users` on `tbl_ids`.`id_col` = `users`.`col` left outer join (select `usr`.`usr_id` as `usr_id` from `usr` where `usr`.`deleted_at` is null) as `alias_35017380` on `alias_35017380`.`usr_id` = `users`.`id` where `tbl_ids`.`tbl_col` = 123"
	f = "select `tbl_ids`.`tbl_col`, `tbl_ids`.`id_col`, `tbl_ids`.`updated_at`, `tbl_ids`.`nickname`, `users`.`id_active`, `alias_35017380`.`usr_id` from `tbl_ids` join `users` on `tbl_ids`.`id_col` = `users`.`col` left outer join (select `usr`.`usr_id` as `usr_id` from `usr` where `usr`.`deleted_at` is null) as `alias_35017380` on `alias_35017380`.`usr_id` = `users`.`id` where `tbl_ids`.`tbl_col` = ?"
	if got := query.Fingerprint(q); got != f {
		t.Errorf("got:\n%s\nexpected:\n%s\n", got, f)
	}
}
