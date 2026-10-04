// A separate module on purpose. The reference predicates in this directory
// must not be derived from the detector they judge, and the cheapest way to
// guarantee that is to make importing it impossible: this module does not
// require github.com/nox-hq/nox. Real nox is reached only as a built binary
// (see replay/), the same way a user reaches it.
module github.com/nox-hq/nox/docs/research/concrete-witnesses

go 1.26
