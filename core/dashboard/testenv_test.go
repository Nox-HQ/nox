package dashboard

import (
	"os"
	"testing"

	"github.com/nox-hq/nox/internal/testenv"
)

func TestMain(m *testing.M) { os.Exit(testenv.Main(m)) }
