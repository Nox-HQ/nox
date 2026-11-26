// Package treesitter parses source with the official tree-sitter runtime and
// pinned upstream grammars, compiled to WebAssembly and run by wazero
// (ADR 0006). The modules are built by scripts/treesitter/build.sh from
// scripts/treesitter/pins.json and embedded here with their SHA-256 sums.
//
// A parse crosses the WebAssembly boundary once: the guest writes the whole
// tree as a flat record array (scripts/treesitter/nox_ts.c), and the host
// reads it back. Every parse runs in a fresh module instance, so no state
// survives from one file to the next, under a memory limit, and stops when
// its context is done. The guest is granted no clock, file or network: the
// WASI functions the runtime and the grammars link against are stubs that
// fail, or end the guest.
package treesitter

import (
	"context"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed wasm/*.wasm wasm/SHA256SUMS
var embedded embed.FS

// moduleOf names the embedded module that holds each language.
var moduleOf = map[string]string{
	"python":     "python",
	"javascript": "javascript",
	"typescript": "typescript",
	"tsx":        "typescript",
	"java":       "java",
	"csharp":     "csharp",
	"php":        "php",
	"ruby":       "ruby",
	"kotlin":     "kotlin",
	"scala":      "scala",
	"swift":      "swift",
	"rust":       "rust",
	"cpp":        "cpp",
}

// Languages are the languages the embedded modules parse.
func Languages() []string {
	return []string{"cpp", "csharp", "java", "javascript", "kotlin", "php", "python", "ruby", "rust", "scala", "swift", "tsx", "typescript"}
}

// Node is one node of a parse tree. Nodes are in pre-order: a node's
// children follow it in source order, and Parent is always an earlier index
// (-1 for the root).
type Node struct {
	Kind     string // the grammar's name for the node, e.g. "function_definition"
	Field    string // the field it fills in its parent, e.g. "name"; "" for none
	Start    uint32 // first byte in the source
	End      uint32 // one past the last byte
	Parent   int32
	Named    bool // a named node, not punctuation or a keyword
	Missing  bool // inserted by error recovery; covers no bytes
	Extra    bool // a node the grammar allows anywhere, e.g. a comment
	Error    bool // an ERROR node
	HasError bool // this node or a descendant is an ERROR or MISSING node
}

// Tree is a parse of one source.
type Tree struct {
	Language string
	Nodes    []Node
	// Checks is the work the parse took: tree-sitter's progress checks, one
	// per 100 parser operations. It depends only on the grammar and the
	// source, never on the machine.
	Checks uint32
}

// HasError reports whether the parse needed error recovery anywhere.
func (t *Tree) HasError() bool { return len(t.Nodes) > 0 && t.Nodes[0].HasError }

// Errors a parse returns.
var (
	ErrLanguage = errors.New("treesitter: language not available")
	ErrParse    = errors.New("treesitter: the parser returned no tree")
	ErrMemory   = errors.New("treesitter: the guest ran out of memory")
	ErrBudget   = errors.New("treesitter: the parse used up its operation budget")
	// ErrRecovery is a parse stopped because it could no longer avoid an
	// error tree (ParseFile's early stop).
	ErrRecovery = errors.New("treesitter: every parse version entered error recovery")
)

// memoryLimitPages caps a guest's linear memory: 4096 pages of 64 KiB, 256 MiB.
const memoryLimitPages = 4096

// recordWords is NOX_RECORD_WORDS in nox_ts.c; the guest reports its own and a
// mismatch is an error, not a misread tree.
const recordWords = 6

const (
	flagNamed    = 1
	flagMissing  = 2
	flagExtra    = 4
	flagError    = 8
	flagHasError = 16
)

// Parser parses with the embedded modules. It is safe for concurrent use.
type Parser struct {
	rt wazero.Runtime

	mu       sync.Mutex
	compiled map[string]wazero.CompiledModule
	names    map[string]*names      // per language
	idle     map[string][]*instance // per module, ready for reuse

	// onDeadlineStart, when set, is called as a parse's deadline starts; a
	// test uses it to see what was already done by then.
	onDeadlineStart func(module string)
}

// names are a language's symbol and field names, read once from the guest.
type names struct {
	index   uint32
	symbols []string
	fields  []string // fields[0] is ""
}

// NewParser returns a parser. Close releases it.
func NewParser(ctx context.Context) (*Parser, error) {
	return newParserWithLimit(ctx, memoryLimitPages)
}

func newParserWithLimit(ctx context.Context, limitPages uint32) (*Parser, error) {
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(limitPages).
		WithCloseOnContextDone(true))
	if err := instantiateWASIStubs(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	return &Parser{rt: rt, compiled: map[string]wazero.CompiledModule{}, names: map[string]*names{}, idle: map[string][]*instance{}}, nil
}

// Close releases the runtime and every compiled module.
func (p *Parser) Close(ctx context.Context) error { return p.rt.Close(ctx) }

// errnoNotSupported is WASI's ENOSYS.
const errnoNotSupported = 52

// instantiateWASIStubs grants the guest the five WASI functions the runtime
// and the grammars link against. Four fail with ENOSYS; proc_exit, which the
// Swift scanner reaches through abort, ends the guest. tree-sitter reaches the clock only
// when a parse timeout is set and the descriptors only to print a debug graph
// or an assertion; nox sets neither, and a guest that tried gets an error,
// not the host's clock or files.
func instantiateWASIStubs(ctx context.Context, rt wazero.Runtime) error {
	fail := func(_ context.Context, _ api.Module, stack []uint64) { stack[0] = errnoNotSupported }
	b := rt.NewHostModuleBuilder("wasi_snapshot_preview1")
	for name, params := range map[string][]api.ValueType{
		"fd_write":       {api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		"fd_seek":        {api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		"fd_close":       {api.ValueTypeI32},
		"clock_time_get": {api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32},
	} {
		b.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(fail), params, []api.ValueType{api.ValueTypeI32}).
			Export(name)
	}
	// proc_exit does not return: it closes the guest, so the call that reached
	// it fails and the file falls back like any other trap. It is the only
	// stub that is not ENOSYS, and it gives the guest nothing from the host.
	b.NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			_ = m.CloseWithExitCode(ctx, uint32(stack[0]))
		}), []api.ValueType{api.ValueTypeI32}, nil).
		Export("proc_exit")
	_, err := b.Instantiate(ctx)
	return err
}

func (p *Parser) compiledModule(ctx context.Context, module string) (wazero.CompiledModule, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.compiled[module]; ok {
		return c, nil
	}
	b, err := embedded.ReadFile("wasm/" + module + ".wasm")
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrLanguage, module)
	}
	c, err := p.rt.CompileModule(ctx, b)
	if err != nil {
		return nil, fmt.Errorf("treesitter: compile %s: %w", module, err)
	}
	p.compiled[module] = c
	return c, nil
}

// Parse parses src as lang, one of Languages().
//
// The parse runs on a pooled instance of lang's module. A failure on a
// reused instance is tried again on a fresh one, and only the fresh
// instance's answer is returned: a failure can then never depend on which
// files an instance parsed before (see pool.go).
func (p *Parser) Parse(ctx context.Context, lang string, src []byte) (*Tree, error) {
	return p.parse(ctx, lang, src, bounds{})
}

// bounds are what stops a parse early: more than maxChecks progress checks
// (0 for no bound), and, with stopAtError, the point where every parse
// version is recovering from an error.
type bounds struct {
	maxChecks   uint32
	stopAtError bool
}

// parse is Parse within b.
func (p *Parser) parse(ctx context.Context, lang string, src []byte, b bounds) (*Tree, error) {
	module, ok := moduleOf[lang]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrLanguage, lang)
	}
	inst, err := p.acquire(ctx, module, false)
	if err != nil {
		return nil, err
	}
	tree, err := p.parseOn(ctx, inst.m, module, lang, src, b)
	p.release(ctx, inst, err == nil)
	// A spent budget or an early stop is the file's, not the instance's: a
	// fresh instance stops at the same point.
	if err == nil || inst.fresh || ctx.Err() != nil || errors.Is(err, ErrBudget) || errors.Is(err, ErrRecovery) {
		return tree, err
	}
	if inst, err = p.acquire(ctx, module, true); err != nil {
		return nil, err
	}
	tree, err = p.parseOn(ctx, inst.m, module, lang, src, b)
	p.release(ctx, inst, err == nil)
	return tree, err
}

// parseOn runs one parse on the instance m of module.
func (p *Parser) parseOn(ctx context.Context, m api.Module, module, lang string, src []byte, b bounds) (*Tree, error) {
	g := guest{ctx: ctx, m: m}
	if words := g.call("nox_record_words"); g.err == nil && words != recordWords {
		return nil, fmt.Errorf("treesitter: %s writes %d-word records, host reads %d", module, words, recordWords)
	}
	n, err := p.languageNames(&g, lang)
	if err != nil {
		return nil, err
	}

	srcPtr := uint32(g.call("nox_alloc", uint64(max(len(src), 1))))
	if g.err == nil && srcPtr == 0 {
		return nil, ErrMemory
	}
	if g.err == nil && !m.Memory().Write(srcPtr, src) {
		return nil, ErrMemory
	}
	count := int32(uint32(g.call("nox_parse", uint64(n.index), uint64(srcPtr), uint64(len(src)), uint64(b.maxChecks), boolWord(b.stopAtError))))
	checks := uint32(g.call("nox_checks"))
	resPtr := uint32(g.call("nox_result"))
	if g.err != nil {
		return nil, g.err
	}
	switch {
	case count == -1:
		return nil, fmt.Errorf("%w: %s (the runtime rejected the grammar)", ErrLanguage, lang)
	case count == -2:
		return nil, ErrParse
	case count == -3:
		return nil, ErrMemory
	case count == -4:
		return nil, fmt.Errorf("%w: more than %d checks", ErrBudget, b.maxChecks)
	case count == -5:
		return nil, fmt.Errorf("%w: after %d checks", ErrRecovery, checks)
	case count < 0:
		return nil, fmt.Errorf("treesitter: nox_parse returned %d", count)
	}
	raw, ok := m.Memory().Read(resPtr, uint32(count)*recordWords*4)
	if !ok {
		return nil, fmt.Errorf("treesitter: %d records at %#x are outside guest memory", count, resPtr)
	}
	tree, err := decode(lang, n, raw, int(count))
	if tree != nil {
		tree.Checks = checks
	}
	return tree, err
}

// guest calls exports and keeps the first error, so a sequence of calls reads
// straight through and is checked once.
type guest struct {
	ctx context.Context
	m   api.Module
	err error
}

func (g *guest) call(name string, args ...uint64) uint64 {
	if g.err != nil {
		return 0
	}
	f := g.m.ExportedFunction(name)
	if f == nil {
		g.err = fmt.Errorf("treesitter: the module exports no %s", name)
		return 0
	}
	res, err := f.Call(g.ctx, args...)
	if err != nil {
		g.err = fmt.Errorf("treesitter: %s: %w", name, err)
		return 0
	}
	if len(res) == 0 {
		return 0
	}
	return res[0]
}

// cstring reads a NUL-terminated string at ptr.
func (g *guest) cstring(ptr uint32) string {
	if g.err != nil || ptr == 0 {
		return ""
	}
	mem := g.m.Memory()
	var out []byte
	for {
		b, ok := mem.ReadByte(ptr)
		if !ok {
			g.err = fmt.Errorf("treesitter: string at %#x runs outside guest memory", ptr)
			return ""
		}
		if b == 0 {
			return string(out)
		}
		out = append(out, b)
		ptr++
	}
}

// languageNames reads lang's symbol and field names from the guest once.
func (p *Parser) languageNames(g *guest, lang string) (*names, error) {
	p.mu.Lock()
	n, ok := p.names[lang]
	p.mu.Unlock()
	if ok {
		return n, nil
	}
	n = &names{index: ^uint32(0)}
	langs := uint32(g.call("nox_lang_count"))
	for i := uint32(0); i < langs && g.err == nil; i++ {
		if g.cstring(uint32(g.call("nox_lang_name", uint64(i)))) == lang {
			n.index = i
		}
	}
	if g.err != nil {
		return nil, g.err
	}
	if n.index == ^uint32(0) {
		return nil, fmt.Errorf("%w: %s is not in its module", ErrLanguage, lang)
	}
	symbols := uint32(g.call("nox_symbol_count", uint64(n.index)))
	for s := uint32(0); s < symbols && g.err == nil; s++ {
		n.symbols = append(n.symbols, g.cstring(uint32(g.call("nox_symbol_name", uint64(n.index), uint64(s)))))
	}
	fields := uint32(g.call("nox_field_count", uint64(n.index)))
	n.fields = append(n.fields, "")
	for f := uint32(1); f <= fields && g.err == nil; f++ {
		n.fields = append(n.fields, g.cstring(uint32(g.call("nox_field_name", uint64(n.index), uint64(f)))))
	}
	if g.err != nil {
		return nil, g.err
	}
	p.mu.Lock()
	p.names[lang] = n
	p.mu.Unlock()
	return n, nil
}

// builtinSymbols are tree-sitter's own symbols, outside every language's
// table: ts_builtin_sym_error and ts_builtin_sym_error_repeat.
var builtinSymbols = map[uint32]string{0xFFFF: "ERROR", 0xFFFE: "_ERROR"}

// decode turns the guest's records into Nodes, checking every index and name
// against what the guest declared rather than trusting the array.
func decode(lang string, n *names, raw []byte, count int) (*Tree, error) {
	t := &Tree{Language: lang, Nodes: make([]Node, count)}
	word := func(i, w int) uint32 { return binary.LittleEndian.Uint32(raw[(i*recordWords+w)*4:]) }
	for i := range count {
		sym, field, parent, flags := word(i, 0), word(i, 1), word(i, 4), word(i, 5)
		kind, ok := builtinSymbols[sym]
		if !ok && int(sym) < len(n.symbols) {
			kind, ok = n.symbols[sym], true
		}
		if !ok || int(field) >= len(n.fields) {
			return nil, fmt.Errorf("treesitter: record %d names symbol %d / field %d, outside the language", i, sym, field)
		}
		p := int32(-1)
		if parent != ^uint32(0) {
			if int(parent) >= i {
				return nil, fmt.Errorf("treesitter: record %d has parent %d, not an earlier record", i, parent)
			}
			p = int32(parent)
		} else if i != 0 {
			return nil, fmt.Errorf("treesitter: record %d has no parent and is not the root", i)
		}
		t.Nodes[i] = Node{
			Kind: kind, Field: n.fields[field],
			Start: word(i, 2), End: word(i, 3), Parent: p,
			Named: flags&flagNamed != 0, Missing: flags&flagMissing != 0, Extra: flags&flagExtra != 0,
			Error: flags&flagError != 0, HasError: flags&flagHasError != 0,
		}
	}
	return t, nil
}

func boolWord(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
