package core

import (
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkRunScan benchmarks the full scan pipeline against a synthetic repo.
func BenchmarkRunScan(b *testing.B) {
	dir := setupBenchRepo(b)
	b.ResetTimer()
	for b.Loop() {
		_, err := RunScanWithOptions(dir, ScanOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRunScanParallel benchmarks parallel analyzer execution.
func BenchmarkRunScanParallel(b *testing.B) {
	dir := setupBenchRepo(b)
	b.ResetTimer()
	for b.Loop() {
		_, err := RunScanWithOptions(dir, ScanOptions{Sequential: false})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRunScanSequential benchmarks sequential analyzer execution.
func BenchmarkRunScanSequential(b *testing.B) {
	dir := setupBenchRepo(b)
	b.ResetTimer()
	for b.Loop() {
		_, err := RunScanWithOptions(dir, ScanOptions{Sequential: true})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRunScanEmpty benchmarks scanning an empty directory.
func BenchmarkRunScanEmpty(b *testing.B) {
	dir := b.TempDir()
	b.ResetTimer()
	for b.Loop() {
		_, err := RunScanWithOptions(dir, ScanOptions{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// setupBenchRepo creates a synthetic repository with a variety of file types
// to exercise all analyzers.
func setupBenchRepo(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()

	// nox:ignore -- benchmark fixtures contain intentional security patterns
	files := map[string]string{
		"main.go": `package main

import "fmt"

func main() {
	fmt.Println("hello world")
}
`,
		"config.yaml": `apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_url: postgres://user:pass@db:5432/app
`,
		"deploy.tf": `resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
		"requirements.txt": `flask==2.3.0
requests==2.31.0
cryptography==41.0.0
`,
		"go.mod": `module example.com/bench
go 1.21
require golang.org/x/text v0.14.0
`,
		"app.py": `import os
import flask

app = flask.Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "default-dev-key")

@app.route("/")
def index():
    return "hello"
`,
		"Dockerfile": `FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8080
USER root
CMD ["python", "app.py"]
`,
		".env.example": `DATABASE_URL=postgres://user:pass@localhost/db
API_KEY=your-api-key-here
SECRET=changeme
`,
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			b.Fatal(err)
		}
	}

	return dir
}
