package errleak

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func lines(path string, lang lexctx.Lang, src string) []int {
	var out []int
	for _, f := range ScanFile(path, lang, []byte(src)) {
		out = append(out, f.Location.StartLine)
	}
	return out
}

type tc struct {
	name, src string
	want      []int
}

func run(t *testing.T, path string, lang lexctx.Lang, cases []tc) {
	t.Helper()
	for _, c := range cases {
		if got := lines(path, lang, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}

func TestJavaScript(t *testing.T) {
	run(t, "src/routes.ts", lexctx.LangJavaScript, []tc{
		{"stack in a 500", "try { run(); } catch (err) {\n  res.status(500).json({ error: err.message, stack: err.stack });\n}\n", []int{2}},
		{"the whole error object", "try { await user.save(); } catch (e) {\n  res.status(400).send(e);\n}\n", []int{2}},
		{"message of an untyped error in a 500", "try { await repo.find(); } catch (error: any) {\n  res.status(500).json({ error: error.message });\n}\n", []int{2}},
		{"promise catch", "db.query(sql).then(r => res.json(r)).catch(err =>\n  res.status(500).json({ error: err.message }));\n", []int{2}},
		{"node-style callback", "db.all(sql, function (err, rows) {\n  if (err) return res.send(err);\n  res.json(rows);\n});\n", []int{2}},
		{"express error middleware", "app.use((err, req, res, next) => {\n  res.status(500).send(err.stack);\n});\n", []int{2}},
		{"TypeScript cast in place", "try { run(); } catch (err) {\n  res.status(500).json({ stack: (err as Error).stack });\n}\n", []int{2}},
		{"rebound under a cast", "try { run(); } catch (error) {\n  const err = error as Error;\n  response.status(500).json({ error: err.message, stack: err.stack });\n}\n", []int{3}},
		{"message through an alias", "try { run(); } catch (err) {\n  const msg = err.message;\n  res.status(500).send(msg);\n}\n", []int{3}},
		{"Koa body", "try { await next(); } catch (err) {\n  ctx.body = err.stack;\n}\n", []int{2}},
		{"NestJS exception message", "import { Controller } from '@nestjs/common';\ntry { run(); } catch (e) {\n  throw new InternalServerErrorException(e.message);\n}\n", []int{3}},
		// Not reported.
		{"a message sent as a client error is chosen", "try { validate(body); } catch (err) {\n  res.status(400).json({ error: err.message });\n}\n", nil},
		{"the handler tells error kinds apart", "try { run(); } catch (err) {\n  if (err instanceof AppError) return res.status(500).json({ error: err.message });\n  res.status(500).json({ error: 'Internal error' });\n}\n", nil},
		{"logged, and a fixed message sent", "try { run(); } catch (err) {\n  console.error(err);\n  res.status(500).json({ error: 'Internal error' });\n}\n", nil},
		{"an error property that is not detail", "try { run(); } catch (err) {\n  res.status(500).json({ code: err.code });\n}\n", nil},
		{"a message alias stays a message", "try { validate(body); } catch (err) {\n  const m = err.message;\n  res.status(422).send(m);\n}\n", nil},
		{"concatenation gives only the message", "try { validate(body); } catch (err) {\n  res.status(400).send('failed: ' + err);\n}\n", nil},
		{"outside any handler", "res.status(500).json({ stack: err.stack });\n", nil},
	})
}

func TestPython(t *testing.T) {
	run(t, "app/views.py", lexctx.LangPython, []tc{
		{"generic exception message from a route", "@app.route('/q')\ndef q():\n    try:\n        run()\n    except Exception as e:\n        return jsonify(error=str(e)), 500\n", []int{6}},
		{"traceback in a response", "def view(request):\n    try:\n        run()\n    except ValueError:\n        return HttpResponse(traceback.format_exc())\n", []int{5}},
		{"database error message in an f-string", "def view(request):\n    try:\n        run()\n    except sqlite3.OperationalError as e:\n        return HttpResponse(f'failed: {e}')\n", []int{5}},
		{"error handler", "@app.errorhandler(Exception)\ndef handle(e):\n    return str(e), 500\n", []int{3}},
		{"alias rendered after the block", "@app.route('/run', methods=['POST'])\ndef run_q():\n    error = None\n    try:\n        run()\n    except Exception as e:\n        error = f'Database error: {str(e)}'\n    return render_template('q.html', error=error)\n", []int{8}},
		{"FastAPI HTTPException", "@router.post('/x')\nasync def x():\n    try:\n        run()\n    except Exception as exc:\n        raise HTTPException(status_code=500, detail=str(exc))\n", []int{6}},
		// Not reported.
		{"a value error's message is chosen", "@app.route('/q')\ndef q():\n    try:\n        run()\n    except ValueError as e:\n        return jsonify(error=str(e)), 400\n", nil},
		{"a handler for the application's own error", "@app.errorhandler(ValidationError)\ndef handle(e):\n    return str(e), 400\n", nil},
		{"a helper's return is not the response", "def helper():\n    try:\n        run()\n    except Exception as e:\n        return str(e)\n", nil},
		{"logged only", "@app.route('/q')\ndef q():\n    try:\n        run()\n    except Exception as e:\n        log.exception(e)\n        return jsonify(error='Internal error'), 500\n", nil},
		{"the name after the block is not the exception", "@app.route('/q')\ndef q():\n    try:\n        run()\n    except Exception as e:\n        detail = str(e)\n        log.warning(detail)\n    e = 'ok'\n    return jsonify(status=e)\n", nil},
	})
}

func TestJava(t *testing.T) {
	const ctl = "@RestController\nclass C {\n"
	run(t, "src/main/java/app/C.java", lexctx.LangJava, []tc{
		{"generic exception message in a body", ctl + "  ResponseEntity<?> a() {\n    try { run(); } catch (Exception e) {\n      return ResponseEntity.status(500).body(e.getMessage());\n    }\n  }\n}\n", []int{5}},
		{"servlet writer", "class S extends HttpServlet {\n  void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {\n    try { run(); } catch (SQLException e) {\n      resp.getWriter().write(e.toString());\n    }\n  }\n}\n", []int{4}},
		{"stack trace of a specific exception", ctl + "  Object a() {\n    try { run(); } catch (IllegalArgumentException e) {\n      return failed().feedback(ExceptionUtils.getStackTrace(e)).build();\n    }\n  }\n}\n", []int{5}},
		{"generic exception handler", "@RestControllerAdvice\nclass H {\n  @ExceptionHandler(Exception.class)\n  public Result handle(Exception e) {\n    return Result.error(e.getMessage());\n  }\n}\n", []int{5}},
		{"Struts action error", "class A extends ActionSupport {\n  String run() {\n    try { load(); } catch (Exception e) {\n      addActionError(\"Error Occurred: \" + e.getMessage());\n    }\n    return INPUT;\n  }\n}\n", []int{4}},
		{"the exception object serialised", ctl + "  ResponseEntity<?> a() {\n    try { run(); } catch (RuntimeException e) {\n      return ResponseEntity.internalServerError().body(e);\n    }\n  }\n}\n", []int{5}},
		// Not reported.
		{"a not-found message is chosen", ctl + "  ResponseEntity<?> a() {\n    try { run(); } catch (NotFoundException e) {\n      return ResponseEntity.status(404).body(e.getMessage());\n    }\n  }\n}\n", nil},
		{"a handler for the application's own exception", "@RestControllerAdvice\nclass H {\n  @ExceptionHandler(BusinessException.class)\n  public Result handle(BusinessException e) {\n    return Result.error(e.getMessage());\n  }\n}\n", nil},
		{"logged, and a fixed message sent", ctl + "  ResponseEntity<?> a() {\n    try { run(); } catch (Exception e) {\n      log.error(\"failed\", e);\n      return ResponseEntity.status(500).body(\"Internal error\");\n    }\n  }\n}\n", nil},
		{"a return outside a web class", "class Repo {\n  String a() {\n    try { run(); } catch (Exception e) {\n      return e.getMessage();\n    }\n  }\n}\n", nil},
	})
}
