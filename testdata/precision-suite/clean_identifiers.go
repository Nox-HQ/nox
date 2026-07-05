// Secret-looking-but-not identifiers: UUIDs, hex color codes, a git commit SHA,
// content hashes, and struct tags. None are credentials; zero findings expected.
package meta

// Build metadata — a git SHA and a semver, not secrets.
const (
	commitSHA = "9f2c1a4b7e3d6058a1c2b3d4e5f60718293a4b5c"
	version   = "v2.14.0"
)

// requestID is a canonical UUIDv4 example, an identifier not a secret.
const requestID = "123e4567-e89b-12d3-a456-426614174000"

// Palette holds hex color codes.
var Palette = map[string]string{
	"primary":    "#1a2b3c",
	"secondary":  "#ff6600",
	"background": "#0d0d0d",
}

// Asset carries a subresource-integrity hash (sha384), a public integrity value.
type Asset struct {
	Path      string `json:"path"`
	Integrity string `json:"integrity"` // e.g. sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w
}
