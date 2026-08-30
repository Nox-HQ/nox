# The hard refutation corpus

Milestone B: *"the refutation corpus contains intentionally difficult cases
involving reflection, dynamic dispatch, FFI, unsupported semantics and bounded
analysis, and none can incorrectly reach PREVENTED."*

`testdata/refutation-suite` holds cases where a refutation is CORRECT and nox
must make it — a value in a comment, a documentation placeholder, a sanitizer
on the dominating path. It answers "does nox refute what it should?".

This corpus answers the opposite and more dangerous question: **does nox refuse
to refute what it cannot see?**

Every file here contains a real flow that a static analysis cannot follow. The
correct result for each is *undetermined*, with the reason named. The failure
this corpus exists to catch is an analyzer reporting "no flow found" as though
it were "no flow exists" — the difference between an existential search that
came up empty and a universal claim, which is the asymmetry `core/reach`
enforces at construction.

| case | what defeats the analysis |
|---|---|
| `h1_reflection.go` | `MethodByName` — the callee is a string at runtime |
| `h2_dynamic_dispatch.go` | the concrete type behind the interface is chosen from data |
| `h3_bounded_loop.go` | the flow only occurs after the eighth iteration |
| `h4_ffi.go` | the value leaves through a pointer the analysis cannot model |
| `h5_dynamic_loading.go` | `plugin.Open` — the callee does not exist at analysis time |

These are not scored for precision. A finding here is neither a true nor a false
positive; what is being measured is whether nox ever states a NEGATIVE it has
not earned.
