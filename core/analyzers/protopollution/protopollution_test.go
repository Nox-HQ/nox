package protopollution

import "testing"

func TestUnguardedDeepMerge(t *testing.T) {
	cases := []struct {
		name, src string
		line      int // 0: no finding
	}{
		{"for-in recursion", `function mergeDeep(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      mergeDeep(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}`, 4},
		{"Object.entries recursion, typed method", `class S {
  private applyOverrides(target: Record<string, unknown>, src: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(src)) {
      if (value && typeof value === "object") {
        this.applyOverrides((target as Record<string, unknown>)[key] as Record<string, unknown>, value as Record<string, unknown>);
      } else {
        target[key] = value;
      }
    }
  }
}`, 5},
		{"arrow function, keys().forEach, assigned recursion", `export const deepMerge = (target, source) => {
  Object.keys(source).forEach((key) => {
    const existing = target[key];
    target[key] = deepMerge(existing && typeof existing === "object" ? existing : {}, source[key]);
  });
  return target;
};`, 4},
		{"recursion assigned to target[key], value from entries", `export function deepMerge(target: Tree, source: Tree): Tree {
  for (const [key, value] of Object.entries(source)) {
    const existing = target[key];
    target[key] = deepMerge(
      existing && typeof existing === "object" ? existing : {},
      value as Tree
    );
  }
  return target;
}`, 4},
		// Not reported.
		{"guarded by a __proto__ check", `function mergeDeep(target, source) {
  for (const key in source) {
    if (key === "__proto__" || key === "constructor") continue;
    if (typeof source[key] === "object") mergeDeep(target[key], source[key]);
    else target[key] = source[key];
  }
}`, 0},
		{"guarded by a forbidden-key set", `const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function mergeDeep(target, source) {
  for (const key of Object.keys(source)) {
    if (UNSAFE_KEYS.has(key)) continue;
    if (typeof source[key] === "object") mergeDeep(target[key], source[key]);
    else target[key] = source[key];
  }
}`, 0},
		{"shallow copy, no recursion", `function assign(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}`, 0},
		{"recursion not keyed by the loop", `function walk(node, visit) {
  for (const key in node.children) {
    walk(node.children[0], visit);
  }
}`, 0},
		{"deep clone into a fresh object", `function clone(obj) {
  const res = {};
  for (const key in obj) {
    res[key] = typeof obj[key] === "object" ? clone(obj[key]) : obj[key];
  }
  return res;
}`, 0},
		{"a read-only traversal", `function checkObjectProps(obj, template) {
  for (const prop in template) {
    if (typeof template[prop] === "object") checkObjectProps(obj[prop], template[prop]);
    else if (obj[prop] !== template[prop]) throw new Error(prop);
  }
}`, 0},
		{"in-place recursion over the object it iterates", `function formatRequestDate(params) {
  for (const key in params) {
    params[key] = String(params[key]).trim();
    if (typeof params[key] === "object") formatRequestDate(params[key]);
  }
}`, 0},
		{"hasOwnProperty alone is not a guard", `function mergeDeep(target, source) {
  for (const key in source) {
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    if (typeof source[key] === "object") mergeDeep(target[key], source[key]);
    else target[key] = source[key];
  }
}`, 4},
	}
	for _, c := range cases {
		got := scanFile("src/merge.ts", []byte(c.src))
		switch {
		case c.line == 0 && len(got) != 0:
			t.Errorf("%s: reported at line %d, want none", c.name, got[0].Location.StartLine)
		case c.line != 0 && len(got) != 1:
			t.Errorf("%s: %d findings, want 1 at line %d", c.name, len(got), c.line)
		case c.line != 0 && got[0].Location.StartLine != c.line:
			t.Errorf("%s: reported at line %d, want %d", c.name, got[0].Location.StartLine, c.line)
		}
	}
}
