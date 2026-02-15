# Feature Proposal: Advanced Exclusion Patterns for Nox

## Summary

Enhance Nox's exclusion system to support granular, conditional, and analyzer-aware path exclusions. This addresses the need to reduce false positives in large Node.js/web projects while maintaining security coverage.

## Problem Statement

### Current Limitations

1. **All-or-nothing lockfile scanning**: Can't exclude `package-lock.json` without disabling all dependency scanning
2. **No analyzer-specific exclusions**: Can't say "don't run secrets on test files" or "don't run VULN rules on node_modules"
3. **Rule disable is global**: Disabling `VULN-001` removes it for the entire project
4. **No conditional logic**: Can't express "downgrade severity for test files"

### Real-World Use Cases

1. **Node.js/web projects**: Exclude `package-lock.json` or downgrade VULN rules for production deps
2. **Large monorepos**: Exclude specific packages or paths from certain analyzers
3. **Test fixtures**: Reduce noise from test data that's intentionally insecure
4. **Third-party code**: Exclude vendored dependencies from security scanning

## Proposed Solution

### Layered Exclusion System

#### Layer 1: Path/Glob Exclusion (Existing, enhance)
```yaml
scan:
  exclude:
    - "node_modules/"
    - "dist/"
    - "**/*.test.js"
```
**Status**: Currently supported, works during discovery

#### Layer 2: Artifact Type Exclusion (NEW)
```yaml
scan:
  exclude_artifact_types:
    - lockfile    # Skip all lockfile scanning
    - container   # Skip container scanning
    - iac         # Skip IaC scanning
```
**Use case**: "I don't want any dependency scanning"

#### Layer 3: Analyzer + Path Rules (NEW)
```yaml
scan:
  analyzer_rules:
    - analyzer: deps
      rules: ["VULN-001", "VULN-002"]
      paths: ["**/node_modules/**", "**/test/fixtures/**"]
      action: disable
    
    - analyzer: secrets
      paths: ["**/*.test.js", "**/testdata/**"]
      action: skip_analyzer
```
**Use case**: "Don't run VULN rules on test fixtures"

#### Layer 4: Conditional Severity (NEW)
```yaml
scan:
  conditional_severity:
    - rules: ["SEC-005", "SEC-006"]
      paths: ["**/config/**", "**/*.config.js"]
      severity: low
    
    - rules: ["VULN-*"]
      paths: ["**/node_modules/**"]
      severity: info
```
**Use case**: "Lower severity for dependencies in node_modules"

#### Layer 5: Allowlist (NEW)
```yaml
scan:
  include:
    # Force include files that might be excluded by other rules
    - "vendor/important-security-check/"  # Scan this even if vendor/ is excluded
```
**Use case**: "Scan this vendor package despite being in vendor/"

### Alternative: .noxignore File

Support a `.noxignore` file similar to `.gitignore` but specifically for Nox:

```
# Skip all lockfiles
package-lock.json
yarn.lock
pnpm-lock.yaml

# Skip dependency scanning on test directories
test/
__tests__/
*.test.js
*.spec.js

# Skip secrets on config files (they often have placeholder values)
config/*.js
.env.example
```

Benefits:
- Familiar syntax for developers
- Can be project-specific or user-specific (~/.noxignore)
- Easier to maintain than complex YAML

## Implementation Strategy

### Phase 1: Analyzer-Aware Exclusions
- Add `analyzer` field to rule override system
- Implement path matching logic for exclusions
- Minimal YAML changes

### Phase 2: Artifact Type Exclusion
- Add `exclude_artifact_types` configuration
- Simple boolean check in discovery

### Phase 3: Conditional Severity
- Implement conditional logic engine
- Support glob patterns with rule wildcards

### Phase 4: .noxignore Support
- Parse `.noxignore` alongside `.gitignore`
- Merge patterns with `.nox.yaml` exclusions

## Configuration Examples

### Example 1: Node.js Project with Minimal Noise
```yaml
# .nox.yaml for a Node.js web project
scan:
  exclude:
    - "node_modules/"
    - "dist/"
    - ".next/"
    - "coverage/"
  
  # Disable vulnerability scanning on dependencies
  analyzer_rules:
    - analyzer: deps
      paths: ["**/node_modules/**"]
      action: skip_analyzer
  
  # Downgrade test file findings
  conditional_severity:
    - rules: ["SEC-*"]
      paths: ["**/*.test.js", "**/*.spec.js", "**/test/**"]
      severity: info
```

### Example 2: Monorepo with Selective Scanning
```yaml
scan:
  exclude:
    - "packages/*/node_modules/"
  
  analyzer_rules:
    # Only run full security on frontend package
    - analyzer: all
      paths: ["packages/frontend/**"]
      action: full_scan
    
    # Limited scanning on backend
    - analyzer: secrets
      paths: ["packages/backend/**"]
      action: disable
    
    # Skip dependencies on API packages
    - analyzer: deps
      paths: ["packages/api/**"]
      action: skip_analyzer
```

### Example 3: Reduce Lockfile Noise
```yaml
scan:
  # Option A: Skip lockfile artifact type entirely
  exclude_artifact_types:
    - lockfile
  
  # Option B: Keep lockfiles but disable specific rules
  analyzer_rules:
    - analyzer: deps
      rules: ["VULN-001", "VULN-002"]
      paths: ["**/package-lock.json"]
      action: disable
```

## Backward Compatibility

All changes are additive:
- Existing `.nox.yaml` configurations work unchanged
- New fields have sensible defaults (opt-in)
- Current `scan.exclude` behavior unchanged

## Priority

| Feature | Priority | Complexity |
|---------|----------|------------|
| Analyzer + Path rules | High | Medium |
| Artifact type exclusion | High | Low |
| Conditional severity | Medium | Medium |
| .noxignore support | Low | Low |
| Allowlist | Low | Low |

## Related Issues

- Support pnpm-lock.yaml parsing (#issue)
- Support yarn.lock parsing (#issue)
- Type squatting detection (#issue)
