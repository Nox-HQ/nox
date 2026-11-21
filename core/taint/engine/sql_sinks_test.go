package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// SQL APIs the RealVuln benchmark labels that the catalog did not name, each
// reached by a request value: Prisma's unsafe raw queries (9 labels), Drizzle's
// sql.raw (6), TypeORM's DataSource/EntityManager.query (6), pg-promise (5),
// JPA's createNativeQuery (9), R2DBC's DatabaseClient.sql (3), and Spring's
// JdbcTemplate.query. Each has its parameterized form beside it, which must
// stay unreported.
func TestSQLSinksTheCatalogDidNotName(t *testing.T) {
	js := func(call string) string {
		return "function h(req) {\n  const id = req.query.id;\n  return " + call + ";\n}\n"
	}
	java := func(stmt string) string {
		return "package a;\n\npublic class C {\n    public Object h(HttpServletRequest request) {\n        String id = request.getParameter(\"id\");\n        return " + stmt + ";\n    }\n}\n"
	}
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		src  string
		want bool
	}{
		{"prisma $queryRawUnsafe", lexctx.LangJavaScript, js("prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = '${id}'`)"), true},
		{"prisma $queryRawUnsafe bound", lexctx.LangJavaScript, js("prisma.$queryRawUnsafe(\"SELECT * FROM t WHERE id = $1\", id)"), false},
		{"prisma $executeRawUnsafe", lexctx.LangJavaScript, js("this.prisma.$executeRawUnsafe(\"DELETE FROM t WHERE id = \" + id)"), true},
		{"drizzle sql.raw", lexctx.LangJavaScript, js("db.execute(sql.raw(`select * from t where id = '${id}'`))"), true},
		{"drizzle sql.raw on its own", lexctx.LangJavaScript, js("sql.raw(\"order by \" + id)"), true},
		{"typeorm AppDataSource.query", lexctx.LangJavaScript, js("AppDataSource.query(`SELECT * FROM t WHERE id = '${id}'`)"), true},
		{"typeorm dataSource.query bound", lexctx.LangJavaScript, js("dataSource.query(\"SELECT * FROM t WHERE id = $1\", [id])"), false},
		{"typeorm manager.query", lexctx.LangJavaScript, js("this.documents.manager.query(\"SELECT * FROM t WHERE id = '\" + id + \"'\")"), true},
		{"pg-promise db.one", lexctx.LangJavaScript, js("db.one(\"SELECT * FROM t WHERE id = '\" + id + \"'\")"), true},
		{"pg-promise db.many bound", lexctx.LangJavaScript, js("db.many(\"SELECT * FROM t WHERE id = $1\", [id])"), false},
		{"jpa createNativeQuery", lexctx.LangJava, java("em.createNativeQuery(\"SELECT * FROM t WHERE id = '\" + id + \"'\", T.class)"), true},
		{"jpa createNativeQuery bound", lexctx.LangJava, java("em.createNativeQuery(\"SELECT * FROM t WHERE id = ?1\", T.class).setParameter(1, id)"), false},
		{"r2dbc databaseClient.sql", lexctx.LangJava, java("databaseClient.sql(\"SELECT * FROM t WHERE id = '\" + id + \"'\")"), true},
		{"spring jdbcTemplate.query", lexctx.LangJava, java("jdbcTemplate.query(\"SELECT * FROM t WHERE id = '\" + id + \"'\", mapper)"), true},
		{"spring jdbcTemplate.query bound", lexctx.LangJava, java("jdbcTemplate.query(\"SELECT * FROM t WHERE id = ?\", mapper, id)"), false},
	} {
		got := slices.Contains(analyzeRuleIDs(t, "t"+extFor(c.lang), c.lang, c.src), "TAINT-001")
		if got != c.want {
			t.Errorf("%s: TAINT-001 reported = %v, want %v", c.name, got, c.want)
		}
	}
}
