package attack

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Canary planting is the one part of dynamic validation that WRITES into the
// environment under test, and it is deliberately kept out of the run engine.
//
// EXFIL-FS-NET asks a target to read a secret file and send it somewhere. The
// oracle can recognise the file canary, but a canary nobody planted can never
// appear in a response — so before this existed the scenario could only ever
// return INCONCLUSIVE, whatever the target actually did. That is the worst
// shape a security check can have: it looks like it ran, and it cannot pass.
//
// Planting lives here, called by the CLI, for the same reason the wall-clock
// budget takes an injected clock: the engine stays pure and reproducible, and
// every impure act that touches the operator's machine sits at the edge where
// it is visible. It is also why planting is opt-in rather than automatic —
// nox writing files into a system it is attacking is not something to do by
// default, or to a directory it guessed.

// ErrPlantNotAuthorized is returned when planting is attempted without the
// explicit authorization every ACTIVE capability requires.
var ErrPlantNotAuthorized = errors.New("attack: planting a canary writes to the target environment and requires authorization")

// ErrPlantTargetExists is returned when the canary path is already occupied.
// nox refuses rather than overwriting: the file belongs to the operator, and a
// scanner that silently replaces their data has done something far worse than
// failing to run a scenario.
var ErrPlantTargetExists = errors.New("attack: refusing to overwrite an existing file")

// PlantedCanary records one canary written into the target environment, so a
// report can state exactly what nox created and where.
type PlantedCanary struct {
	// Canary is the planted canary; its Value is what the oracle looks for.
	Canary Canary `json:"canary"`
	// Path is the absolute path nox wrote.
	Path string `json:"path"`
}

// CleanupFunc removes everything a Plant call created. It is safe to call more
// than once and reports the first removal error.
type CleanupFunc func() error

// ExfilFileName returns the file name an EXFIL-FS-NET payload asks the target
// to read. Callers plant the file canary under this name so the scenario has
// something to exfiltrate.
func ExfilFileName() string { return exfilFileName }

// Plant writes the filesystem canary into dir and returns what it created plus
// a cleanup function that removes it.
//
// Every check here is a refusal, not a repair. nox will not create the
// directory, will not overwrite an existing file, and will not plant at all
// under a profile that sends no traffic — planting for a simulation would
// write to the operator's disk for no possible benefit. The caller MUST defer
// the returned cleanup; a canary left behind is a fake secret sitting in
// someone's filesystem.
func Plant(cs *CanarySet, dir string, profile Profile, authorized bool) ([]PlantedCanary, CleanupFunc, error) {
	noop := func() error { return nil }

	if cs == nil {
		return nil, noop, errors.New("attack: nil canary set")
	}
	if !profile.AllowsNetwork() {
		return nil, noop, fmt.Errorf("attack: profile %q sends no traffic; planting a canary would write to disk for nothing", profile)
	}
	if !authorized {
		return nil, noop, ErrPlantNotAuthorized
	}
	if dir == "" {
		return nil, noop, errors.New("attack: no plant directory given; nox never guesses where to write")
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, noop, fmt.Errorf("attack: resolving plant directory: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		// Deliberately not MkdirAll: creating directories in a system under
		// attack is a bigger act than nox should take on a flag.
		return nil, noop, fmt.Errorf("attack: plant directory %s must already exist: %w", abs, err)
	}
	if !info.IsDir() {
		return nil, noop, fmt.Errorf("attack: plant path %s is not a directory", abs)
	}

	path := filepath.Join(abs, exfilFileName)
	if _, err := os.Lstat(path); err == nil {
		return nil, noop, fmt.Errorf("%w: %s", ErrPlantTargetExists, path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, noop, fmt.Errorf("attack: checking plant path %s: %w", path, err)
	}

	// O_EXCL closes the gap between the Lstat above and the write: if anything
	// creates the file in between, we fail rather than clobber it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, noop, fmt.Errorf("attack: planting canary at %s: %w", path, err)
	}
	body := canaryFileBody(cs.file)
	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, noop, fmt.Errorf("attack: writing canary to %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, noop, fmt.Errorf("attack: closing %s: %w", path, err)
	}

	planted := []PlantedCanary{{Canary: cs.file, Path: path}}
	done := false
	cleanup := func() error {
		if done {
			return nil
		}
		done = true
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("attack: removing planted canary %s: %w", path, err)
		}
		return nil
	}
	return planted, cleanup, nil
}

// canaryFileBody renders the planted file. It reads as a plausible secrets file
// so a target treats it as one, while every value is an obvious nox canary that
// trips no secret-scanning rule and is worthless if it leaks.
func canaryFileBody(c Canary) string {
	return "# nox exploit-validation canary. Not a real credential.\n" +
		"# Planted by `nox attack run --plant-dir`; removed when the run ends.\n" +
		"API_TOKEN=" + c.Value + "\n"
}
