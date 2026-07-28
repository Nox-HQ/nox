package engine

// Cross-unit SHARED STATE. The engine is intraprocedural plus same-file
// interprocedural via function summaries, which joins a value passed through a
// local helper CALL. It does not join a value laundered through state two units
// SHARE without calling each other:
//
//	def capture;  @cmd = params[:cmd];  end      # Ruby instance variable
//	def execute;  system @cmd;          end
//
//	sub stash { $PAYLOAD = $ENV{DATA} }          # Perl package global
//	sub flush { system("logger $PAYLOAD") }
//
// Both are real flows a correct scanner reports, and both were documented false
// negatives — "the boundary of the intraprocedural model".
//
// joinSharedState closes them narrowly: a binding of a SHARED name is copied
// into every other unit that READS that name, and the existing intra-unit
// propagation does the rest. Only names that are syntactically shared state
// (`@ivar`, `@@cvar`, `$global`, `our $PKG`) participate — a plain local never
// joins, which is what keeps this from turning every same-named local in a file
// into one variable.
//
// The join is flow-INSENSITIVE across units: it assumes the assigning unit may
// run before the reading one, which is the standard over-approximation for
// shared state (nothing in the file says otherwise). The copy is PREPENDED, so a
// unit that assigns the same name locally still overrides it in its own scope.
//
// The copied statement carries the binding's source evidence but an EMPTY
// sinkArgs: it is being replayed for its taint, not re-reported, so a sink that
// happened to appear in the binding expression is not reported a second time in
// every reader.
func joinSharedState(units []unitDraft, shared map[string]bool) []unitDraft {
	if len(shared) == 0 || len(units) < 2 {
		return units
	}
	type binding struct {
		unit int
		st   stmtDraft
	}
	var bindings []binding
	for i := range units {
		for _, st := range units[i].stmts {
			if st.assigns != "" && shared[st.assigns] {
				bindings = append(bindings, binding{unit: i, st: st})
			}
		}
	}
	if len(bindings) == 0 {
		return units
	}
	for i := range units {
		var prepend []stmtDraft
		for _, b := range bindings {
			if b.unit == i || !unitReadsName(units[i], b.st.assigns) {
				continue
			}
			cp := b.st
			cp.sinkArgs = map[string]sinkArgDraft{}
			prepend = append(prepend, cp)
		}
		if len(prepend) > 0 {
			units[i].stmts = append(prepend, units[i].stmts...)
		}
	}
	return units
}

// unitReadsName reports whether any statement in u reads name.
func unitReadsName(u unitDraft, name string) bool {
	for _, st := range u.stmts {
		for _, r := range st.reads {
			if r == name {
				return true
			}
		}
	}
	return false
}
