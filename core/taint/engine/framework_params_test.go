package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Handler parameters a framework binds from the request are request values,
// whatever they are named. Each case beside its counterpart, a parameter the
// same framework fills with something the client does not choose.
func TestFrameworkBoundParametersAreRequestValues(t *testing.T) {
	nest := func(params, use string) string {
		return "import { Controller, Post, Body, Query, Param, Req } from '@nestjs/common';\nimport { execSync } from 'child_process';\n" +
			"@Controller('x')\nexport class X {\n  @Post()\n  run(" + params + ") {\n    return execSync('ls ' + " + use + ");\n  }\n}\n"
	}
	fastapi := func(decorator, params, use string) string {
		return "import subprocess\nfrom fastapi import FastAPI, Depends, Request\napp = FastAPI()\n\n" + decorator +
			"\ndef handler(" + params + "):\n    subprocess.run('ls ' + " + use + ", shell=True)\n"
	}
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		file string
		src  string
		want bool
	}{
		// NestJS parameter decorators.
		{"nest @Body", lexctx.LangJavaScript, "x.controller.ts", nest(`@Body('cmd') cmd: string`, "cmd"), true},
		{"nest @Body() dto", lexctx.LangJavaScript, "x.controller.ts", nest(`@Body() dto: RunDto`, "dto.dir"), true},
		{"nest @Query", lexctx.LangJavaScript, "x.controller.ts", nest(`@Query('dir') dir?: string`, "dir"), true},
		{"nest @Param", lexctx.LangJavaScript, "x.controller.ts", nest(`@Param('id') id: string`, "id"), true},
		{"nest multi-line params", lexctx.LangJavaScript, "x.controller.ts", nest("\n    @Req() req: any,\n    @Body('cmd') cmd: string,\n  ", "cmd"), true},
		{"nest undecorated param", lexctx.LangJavaScript, "x.controller.ts", nest(`cmd: string`, "cmd"), false},
		{"nest injected service field", lexctx.LangJavaScript, "x.controller.ts", nest(`@Body('cmd') cmd: string`, "this.root"), false},

		// Python route functions: FastAPI and Flask.
		{"fastapi query param", lexctx.LangPython, "main.py", fastapi(`@app.get("/x")`, "dir: str", "dir"), true},
		{"fastapi body model", lexctx.LangPython, "main.py", fastapi(`@router.post("/x")`, "body: RunIn", "body.dir"), true},
		{"fastapi async route", lexctx.LangPython, "main.py",
			"import subprocess\nfrom fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/x')\nasync def handler(dir: str = 'tmp'):\n    subprocess.run('ls ' + dir, shell=True)\n", true},
		{"flask route variable", lexctx.LangPython, "app.py",
			"import subprocess\nfrom flask import Flask\napp = Flask(__name__)\n\n@app.route('/ls/<path:d>')\ndef handler(d):\n    subprocess.run('ls ' + d, shell=True)\n    return 'ok'\n", true},
		{"fastapi Depends", lexctx.LangPython, "main.py", fastapi(`@app.get("/x")`, "root: str = Depends(get_root)", "root"), false},
		{"fastapi Annotated Depends", lexctx.LangPython, "main.py", fastapi(`@app.get("/x")`, "root: Annotated[str, Depends(get_root)]", "root"), false},
		{"fastapi Request object", lexctx.LangPython, "main.py", fastapi(`@app.get("/x")`, "request: Request", "request.app.state.root"), false},
		{"not a route", lexctx.LangPython, "main.py", fastapi(`@functools.lru_cache()`, "dir: str", "dir"), false},
		{"undecorated function", lexctx.LangPython, "main.py",
			"import subprocess\n\ndef handler(dir):\n    subprocess.run('ls ' + dir, shell=True)\n", false},

		// Next.js server actions.
		{"use server file", lexctx.LangJavaScript, "actions.ts",
			"'use server';\nimport { execSync } from 'child_process';\nexport async function run(formData: FormData) {\n  execSync('ls ' + formData.get('dir'));\n}\n", true},
		{"use server in the function", lexctx.LangJavaScript, "page.tsx",
			"import { execSync } from 'child_process';\nexport default function Page() {\n  async function run(dir: string) {\n    'use server';\n    execSync('ls ' + dir);\n  }\n  return null;\n}\n", true},
		{"no directive", lexctx.LangJavaScript, "lib.ts",
			"import { execSync } from 'child_process';\nexport async function run(dir: string) {\n  execSync('ls ' + dir);\n}\n", false},
		{"use server file, unexported helper", lexctx.LangJavaScript, "actions.ts",
			"'use server';\nimport { execSync } from 'child_process';\nasync function helper(dir: string) {\n  execSync('ls ' + dir);\n}\nexport async function run() {\n  await helper('tmp');\n}\n", false},
	} {
		got := slices.Contains(analyzeRuleIDs(t, c.file, c.lang, c.src), "TAINT-002")
		if got != c.want {
			t.Errorf("%s: TAINT-002 reported = %v, want %v", c.name, got, c.want)
		}
	}
}

// MyBatis's @Param names a mapper argument in Java; it is not request data,
// and the NestJS decorator table must not reach the JVM extractors.
func TestJavaParamAnnotationIsNotARequestBinding(t *testing.T) {
	src := "package a;\n\npublic class Dao {\n    public void run(@Param(\"dir\") String dir) throws Exception {\n        Runtime.getRuntime().exec(\"ls \" + dir);\n    }\n}\n"
	if slices.Contains(analyzeRuleIDs(t, "Dao.java", lexctx.LangJava, src), "TAINT-002") {
		t.Error("a MyBatis @Param argument was treated as a request value")
	}
}
