package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestRubyActiveRecordAndPG(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"delete_by interpolated", "class C < ApplicationController\n  def destroy\n    User.delete_by(\"id = '#{params[:id]}'\")\n  end\nend\n", []string{"TAINT-001"}},
		{"delete_by with a placeholder", "class C < ApplicationController\n  def destroy\n    User.delete_by(\"id = ?\", params[:id])\n  end\nend\n", nil},
		{"maximum of a request column", "class C < ApplicationController\n  def stats\n    User.maximum(params[:column])\n  end\nend\n", []string{"TAINT-001"}},
		{"pg exec", "class C < ApplicationController\n  def q\n    conn = PG.connect(dbname: 'x')\n    qry = \"SELECT * FROM u WHERE n = '#{params[:n]}'\"\n    conn.exec(qry)\n  end\nend\n", []string{"TAINT-001"}},
		{"pg exec_params binds", "class C < ApplicationController\n  def q\n    conn = PG.connect(dbname: 'x')\n    conn.exec_params('SELECT * FROM u WHERE n = $1', [params[:n]])\n  end\nend\n", nil},
		{"another object's exec", "class C < ApplicationController\n  def q\n    runner = Runner.new\n    runner.exec(params[:n])\n  end\nend\n", nil},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("c.rb", lexctx.LangRuby, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
