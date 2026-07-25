package main

// Seed lists of genuinely popular, real packages. These are the anchors the
// hallucination generator perturbs and extends. Every name here is a real,
// widely-installed package; the generator NEVER asserts anything about these
// real packages — they are used only as stems/neighbours for candidate names,
// and a generated candidate that collides with a real seed is dropped.
//
// Ported from the research prototype (scratchpad/research/slopsquat/seeds.py),
// kept deliberately small (~40 per ecosystem) and hardcoded for determinism.

// pypiSeeds are popular PyPI packages (real).
var pypiSeeds = []string{
	"requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic",
	"sqlalchemy", "boto3", "aiohttp", "httpx", "pytest", "click", "rich",
	"scipy", "scikit-learn", "matplotlib", "pillow", "beautifulsoup4",
	"selenium", "celery", "redis", "pymongo", "psycopg2", "cryptography",
	"pyyaml", "jinja2", "tenacity", "openai", "anthropic", "langchain",
	"tiktoken", "transformers", "torch", "tensorflow", "uvicorn", "starlette",
	"typer", "loguru", "python-dateutil",
}

// npmSeeds are popular npm packages (real).
var npmSeeds = []string{
	"react", "express", "lodash", "axios", "chalk", "commander", "moment",
	"dayjs", "webpack", "vite", "eslint", "prettier", "typescript", "jest",
	"vitest", "next", "vue", "svelte", "zod", "yup", "dotenv", "cors",
	"mongoose", "sequelize", "prisma", "nodemon", "socket.io", "uuid",
	"bcrypt", "jsonwebtoken", "passport", "redux", "tailwindcss", "rxjs",
	"puppeteer", "playwright", "cheerio", "nanoid", "pino", "winston",
}

// prefixes and suffixes are the domain/task words an LLM commonly welds onto a
// stem when it invents a helper package that "should" exist.
var prefixes = []string{
	"fast", "py", "node", "ai", "async", "auto", "smart", "easy", "simple",
	"super", "pro",
}

var suffixes = []string{
	"utils", "async", "sdk", "client", "toolkit", "helpers", "core", "tools",
	"kit", "api", "cli", "plus", "x", "js", "py",
}

// obviousName is a fully-formed name an LLM confidently invents for a common
// task, tagged with the ecosystem (nox canonical: "pypi" | "npm").
type obviousName struct {
	name string
	eco  string
}

// obviousNames are curated by hand from the patterns in the slopsquatting
// literature (Spracklen et al. 2024) and everyday LLM output.
var obviousNames = []obviousName{
	{"openai-helpers", "pypi"},
	{"openai-utils", "pypi"},
	{"openai-async", "pypi"},
	{"requests-cache-async", "pypi"},
	{"requests-async", "pypi"},
	{"flask-jwt-auth", "pypi"},
	{"flask-auth", "pypi"},
	{"django-rest-auth-jwt", "pypi"},
	{"fastapi-jwt-auth", "pypi"},
	{"fastapi-auth", "pypi"},
	{"langchain-utils", "pypi"},
	{"langchain-helpers", "pypi"},
	{"anthropic-async", "pypi"},
	{"anthropic-helpers", "pypi"},
	{"pandas-utils", "pypi"},
	{"pandas-helpers", "pypi"},
	{"numpy-utils", "pypi"},
	{"boto3-helpers", "pypi"},
	{"sqlalchemy-utils-async", "pypi"},
	{"pydantic-utils", "pypi"},
	{"openai-client", "npm"},
	{"openai-sdk", "npm"},
	{"express-jwt-auth", "npm"},
	{"express-auth", "npm"},
	{"react-use-fetch", "npm"},
	{"react-hooks-utils", "npm"},
	{"axios-retry-async", "npm"},
	{"axios-cache", "npm"},
	{"lodash-async", "npm"},
	{"zod-utils", "npm"},
	{"prisma-utils", "npm"},
	{"jwt-auth-express", "npm"},
	{"node-fetch-retry", "npm"},
	{"vite-plugin-env", "npm"},
	{"next-auth-jwt", "npm"},
}
