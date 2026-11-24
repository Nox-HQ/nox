package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Mass assignment (CWE-915) is the WHOLE request object written onto a stored
// record: every field the client sends lands, including the ones the form
// never showed (role, ownerId, isAdmin). A field read from the request and
// written by name is the application choosing the field, and is not.
func TestMassAssignmentJavaScript(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            bool
	}{
		{"Object.assign of the body", "routes/u.js",
			"app.put('/u', async (req, res) => {\n  const user = await User.findById(req.params.id);\n  Object.assign(user, req.body);\n  await user.save();\n});\n", true},
		{"a copy of the body", "routes/u.js",
			"app.put('/u', async (req, res) => {\n  const patch = req.body;\n  Object.assign(deal, patch);\n});\n", true},
		{"a spread copy of the body", "routes/u.js",
			"app.put('/u', async (req, res) => {\n  const patch = { ...req.body };\n  Object.assign(deal, patch);\n});\n", true},
		{"Mongoose create from the body", "routes/u.js",
			"app.post('/u', async (req, res) => {\n  const u = await User.create(req.body);\n});\n", true},
		{"Mongoose update by id from the body", "routes/u.js",
			"app.put('/u/:id', async (req, res) => {\n  await User.findByIdAndUpdate(req.params.id, req.body);\n});\n", true},
		{"NestJS whole DTO saved", "src/deals.controller.ts",
			"class C {\n  @Put(':id')\n  update(@Param('id') id: string, @Body() dto: UpdateDealDto) {\n    return this.repo.save({ ...existing, ...dto });\n  }\n}\n", true},
		{"through a service helper", "src/deals.service.ts",
			"class S {\n  apply(deal, patch) {\n    Object.assign(deal, patch);\n  }\n  @Put(':id')\n  update(@Body() dto: UpdateDealDto) {\n    this.apply(found, dto);\n  }\n}\n", true},
		{"Prisma create with the DTO as data", "src/u.service.ts",
			"class C {\n  @Post()\n  add(@Body() dto: CreateUserDto) {\n    return this.prisma.user.create({ data: dto });\n  }\n}\n", true},
		{"TypeORM repository save", "src/u.service.ts",
			"class C {\n  @Post()\n  add(@Body() dto: CreateUserDto) {\n    return this.usersRepository.save(dto);\n  }\n}\n", true},
		// Not mass assignment.
		{"Prisma create from chosen DTO fields", "src/u.service.ts",
			"class C {\n  @Post()\n  add(@Body() dto: CreateUserDto) {\n    return this.prisma.user.create({ data: { name: dto.name, email: dto.email } });\n  }\n}\n", false},
		{"the DTO handed to the app's own service", "src/deals.controller.ts",
			"class C {\n  @Put(':id')\n  update(@Param('id') id: string, @Body() dto: UpdateDealDto) {\n    return this.dealsService.update(id, dto);\n  }\n}\n", false},
		{"a field written by name", "routes/u.js",
			"app.put('/u', async (req, res) => {\n  Object.assign(user, { name: req.body.name });\n});\n", false},
		{"a field read first", "routes/u.js",
			"app.put('/u', async (req, res) => {\n  const name = req.body.name;\n  Object.assign(user, { name });\n});\n", false},
		{"create from chosen fields", "routes/u.js",
			"app.post('/u', async (req, res) => {\n  await User.create({ name: req.body.name, email: req.body.email });\n});\n", false},
		{"defaults merged into the body", "routes/u.js",
			"app.post('/u', async (req, res) => {\n  Object.assign(req.body, defaults);\n});\n", false},
		{"the body narrowed to chosen fields", "routes/u.js",
			"app.put('/u', async (req, res) => {\n  const patch = req.body;\n  const allowed = pick(patch, ['name', 'email']);\n  Object.assign(user, allowed);\n});\n", false},
		{"fields destructured from the body", "routes/w.js",
			"app.post('/w', async (req, res) => {\n  const { url, event } = req.body;\n  await prisma.webhook.create({ data: { url, event } });\n});\n", false},
		{"fields destructured from a whole DTO", "src/w.service.ts",
			"class C {\n  @Post()\n  add(@Body() dto: Dto) {\n    const { url } = dto;\n    return this.repo.save(url);\n  }\n}\n", false},
		{"a field passed to the same helper", "src/deals.service.ts",
			"class S {\n  apply(deal, patch) {\n    Object.assign(deal, patch);\n  }\n  @Put(':id')\n  rename(@Body('name') name: string) {\n    this.apply(found, { name });\n  }\n}\n", false},
		{"NestJS single field", "src/deals.controller.ts",
			"class C {\n  @Put(':id')\n  rename(@Body('name') name: string) {\n    return this.repo.save({ ...existing, name });\n  }\n}\n", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, c.path, lexctx.LangJavaScript, c.src), "TAINT-014"); got != c.want {
			t.Errorf("%s: TAINT-014 reported=%v, want %v", c.name, got, c.want)
		}
	}
}

// A spread operand is a read: `...dto` was skipped as the attribute after a
// dot, so a tainted value spread into an object or an argument list reached
// no sink in any taint class.
func TestSpreadOperandIsRead(t *testing.T) {
	if got := freeIdentifiers(langJavaScript, "{ ...existing, ...dto }"); !slices.Equal(got, []string{"existing", "dto"}) {
		t.Errorf("object spread: %v", got)
	}
	if got := freeIdentifiers(langJavaScript, "...args"); !slices.Equal(got, []string{"args"}) {
		t.Errorf("argument spread: %v", got)
	}
	if got := freeIdentifiers(langJavaScript, "a.b"); !slices.Equal(got, []string{"a"}) {
		t.Errorf("attribute: %v", got)
	}
	src := "const cp = require('child_process');\napp.get('/x', (req, res) => {\n  cp.execFile('sh', ['-c', ...req.query.args]);\n  cp.exec(...[req.query.cmd]);\n});\n"
	if !slices.Contains(analyzeRuleIDs(t, "r.js", lexctx.LangJavaScript, src), "TAINT-002") {
		t.Errorf("a spread request value reached no command sink")
	}
}
