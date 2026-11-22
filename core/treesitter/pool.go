package treesitter

import (
	"context"
	"fmt"
	"runtime"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Instantiating a module copies its grammar tables into a new linear memory:
// about 0.3 ms for Java, 4 ms for Python and 24 ms for TypeScript, which has
// two grammars. On a small file that is most of the parse, so instances are
// reused. Reuse keeps no state a tree can depend on (each nox_parse builds a
// new parser and tree), but a heap that grew on one file stays grown for the
// next, and a failure such as running out of memory could then depend on the
// order files were parsed in. Two rules keep the answer a function of the
// file alone:
//
//   - an instance that failed, or whose memory grew past retireBytes, is
//     closed rather than reused;
//   - Parse tries a failure on a reused instance again on a fresh one, and
//     returns the fresh instance's answer.

// retireBytes is the linear-memory size past which an instance is closed
// instead of pooled: 64 MiB, a quarter of the limit.
const retireBytes = 64 << 20

// instance is one instantiated module.
type instance struct {
	m      api.Module
	module string
	fresh  bool // instantiated for this parse, not taken from the pool
}

// maxIdle bounds the idle instances kept per module: one per CPU, the most
// parses that run at once.
func maxIdle() int { return runtime.GOMAXPROCS(0) }

// acquire returns an idle instance of module, or a new one when there is none
// or fresh is set.
func (p *Parser) acquire(ctx context.Context, module string, fresh bool) (*instance, error) {
	if !fresh {
		p.mu.Lock()
		idle := p.idle[module]
		if n := len(idle); n > 0 {
			inst := idle[n-1]
			p.idle[module] = idle[:n-1]
			p.mu.Unlock()
			inst.fresh = false
			return inst, nil
		}
		p.mu.Unlock()
	}
	c, err := p.compiledModule(ctx, module)
	if err != nil {
		return nil, err
	}
	m, err := p.rt.InstantiateModule(ctx, c, wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
	if err != nil {
		return nil, fmt.Errorf("treesitter: instantiate %s: %w", module, err)
	}
	return &instance{m: m, module: module, fresh: true}, nil
}

// release returns a healthy instance to the pool and closes any other.
func (p *Parser) release(ctx context.Context, inst *instance, healthy bool) {
	if healthy && !inst.m.IsClosed() && inst.m.Memory().Size() <= retireBytes {
		p.mu.Lock()
		if len(p.idle[inst.module]) < maxIdle() {
			p.idle[inst.module] = append(p.idle[inst.module], inst)
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
	}
	_ = inst.m.Close(ctx)
}
