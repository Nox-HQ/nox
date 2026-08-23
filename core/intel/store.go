package intel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Store is the local intelligence store: candidates as one JSON file each, and
// observations as an append-only JSON-lines log.
//
// Local files, and nothing else. nox is offline-first, so the intelligence
// model must be fully usable with no service reachable; advisory data arrives
// as an argument (see Advisory) and contributions are the caller's business.
// A store that quietly phoned home would also make "contribution is disabled"
// unverifiable, which would undo the entire privacy contract.
type Store struct {
	dir string
	// mu serialises writes within a process. It is not a cross-process lock:
	// candidate writes are atomic renames and observation appends are single
	// O_APPEND writes, so a concurrent writer interleaves records rather than
	// corrupting one.
	mu sync.Mutex
}

// Store layout.
const (
	candidatesDir   = "candidates"
	observationsLog = "observations.jsonl"
	storeDirPerm    = 0o750
	storeFilePerm   = 0o600
)

// candidateIDPattern constrains a candidate id to a safe file name. A store id
// becomes a path, so an id containing a separator or ".." would let a crafted
// candidate write outside the store directory.
var candidateIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// OpenStore opens (creating if needed) the intelligence store rooted at dir.
func OpenStore(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("intel: store directory is required")
	}
	if err := os.MkdirAll(filepath.Join(dir, candidatesDir), storeDirPerm); err != nil {
		return nil, fmt.Errorf("intel: creating store at %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// candidatePath returns the on-disk path for a candidate id, refusing any id
// that is not a safe file name.
func (s *Store) candidatePath(id string) (string, error) {
	if !candidateIDPattern.MatchString(id) || strings.Contains(id, "..") {
		return "", fmt.Errorf("intel: unsafe candidate id %q", truncateForError(id))
	}
	return filepath.Join(s.dir, candidatesDir, id+".json"), nil
}

// PutCandidate writes a candidate, replacing any previous version.
//
// The write is a temp file plus a rename, so a reader never observes a
// half-written candidate and a crash mid-write leaves the previous version
// intact rather than a truncated one.
func (s *Store) PutCandidate(c *Candidate) error {
	if c == nil {
		return errors.New("intel: cannot store a nil candidate")
	}
	path, err := s.candidatePath(c.ID)
	if err != nil {
		return err
	}
	// Indented output keeps the store diffable, which is what makes a change to
	// a candidate reviewable in a pull request.
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("intel: encoding candidate %s: %w", c.ID, err)
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.CreateTemp(filepath.Dir(path), ".candidate-*.tmp")
	if err != nil {
		return fmt.Errorf("intel: writing candidate %s: %w", c.ID, err)
	}
	tmpName := tmp.Name()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel: writing candidate %s: %w", c.ID, err)
	}
	if err = tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel: writing candidate %s: %w", c.ID, err)
	}
	if err = os.Chmod(tmpName, storeFilePerm); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel: writing candidate %s: %w", c.ID, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("intel: writing candidate %s: %w", c.ID, err)
	}
	return nil
}

// GetCandidate reads one candidate by id. A missing candidate returns an error
// wrapping fs.ErrNotExist, so callers can distinguish "not here" from "broken".
func (s *Store) GetCandidate(id string) (*Candidate, error) {
	path, err := s.candidatePath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("intel: reading candidate %s: %w", id, err)
	}
	var c Candidate
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("intel: decoding candidate %s: %w", id, err)
	}
	return &c, nil
}

// ListCandidates returns every stored candidate, ordered by id.
func (s *Store) ListCandidates() ([]*Candidate, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, candidatesDir))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("intel: listing candidates: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	out := make([]*Candidate, 0, len(names))
	for _, name := range names {
		c, err := s.GetCandidate(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// AppendObservations appends observations to the log.
//
// Every observation is validated BEFORE anything is written, and one invalid
// observation rejects the whole batch. A partially written batch would leave
// the log in a state no caller asked for, and an unvalidated observation is
// exactly the kind that might carry content into a file that later gets
// aggregated and shared.
func (s *Store) AppendObservations(obs []Observation) error {
	if len(obs) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for i, o := range obs {
		if err := o.Validate(); err != nil {
			return fmt.Errorf("intel: observation %d rejected; nothing was written: %w", i, err)
		}
		if o.Fingerprint == "" {
			o.Fingerprint = Fingerprint(o)
		}
		line, err := json.Marshal(o)
		if err != nil {
			return fmt.Errorf("intel: encoding observation %d: %w", i, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(filepath.Join(s.dir, observationsLog),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, storeFilePerm)
	if err != nil {
		return fmt.Errorf("intel: opening observation log: %w", err)
	}
	if _, err = f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		return fmt.Errorf("intel: appending observations: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("intel: closing observation log: %w", err)
	}
	return nil
}

// Observations reads the whole observation log, in the order it was written.
func (s *Store) Observations() ([]Observation, error) {
	f, err := os.Open(filepath.Join(s.dir, observationsLog))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("intel: opening observation log: %w", err)
	}
	defer func() { _ = f.Close() }()

	var out []Observation
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var o Observation
		if err := json.Unmarshal([]byte(raw), &o); err != nil {
			return nil, fmt.Errorf("intel: observation log line %d is not valid JSON: %w", line, err)
		}
		out = append(out, o)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("intel: reading observation log: %w", err)
	}
	return out, nil
}

// Lookup returns the DISCOVERABLE candidates affecting an artifact.
//
// Non-discoverable candidates — EMBARGOED and INTERNAL — are filtered here, at
// the search surface, rather than left to each caller. A disclosure rule that
// depends on every query site remembering to apply it is a rule that will be
// forgotten once, and once is enough to publish an embargoed vulnerability to
// whoever asked about the package. Use LookupAll for the owning organization's
// own view, where that concern does not apply.
//
// An empty version matches every version of the package.
func (s *Store) Lookup(ecosystem, pkg, version string) ([]*Candidate, error) {
	all, err := s.LookupAll(ecosystem, pkg, version)
	if err != nil {
		return nil, err
	}
	out := make([]*Candidate, 0, len(all))
	for _, c := range all {
		if c.Disclosure.Discoverable() {
			out = append(out, c)
		}
	}
	return out, nil
}

// LookupAll returns every candidate affecting an artifact, including those that
// are not discoverable. It is for the organization's own view of its own store;
// anything that answers a query from elsewhere must use Lookup.
func (s *Store) LookupAll(ecosystem, pkg, version string) ([]*Candidate, error) {
	cands, err := s.ListCandidates()
	if err != nil {
		return nil, err
	}
	eco := normalizeEcosystem(ecosystem)
	name := normalizePackage(pkg)
	ver := normalizeVersion(version)

	out := make([]*Candidate, 0, len(cands))
	for _, c := range cands {
		if c.Ecosystem != eco || c.Package != name {
			continue
		}
		if ver != "" && !versionInSpan(ver, rangeBounds(c.AffectedRange)) {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}
