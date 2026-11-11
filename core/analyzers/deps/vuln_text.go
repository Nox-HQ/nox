package deps

// vulnText is a dependency finding's message in its two roles.
//
// shown is what a person reads, and may be reworded freely.
//
// identity is what the fingerprint is computed over. A dependency finding has
// no matched text, so since the first release its fingerprint has been the
// hash of the rule, the lockfile place and the message. Baselines, waivers and
// VEX statements are keyed on it. identity is therefore the message exactly as
// nox 1.65.0 assembled it (the unreadable parts included: a colon in front of
// an empty summary, the ladder's own identifiers), and it stays that way while
// shown improves. Before the two were separate, rewording the applicability
// sentence changed every dependency fingerprint in every project.
//
// The advisory's summary is part of identity, as it always was, so an edit to
// the advisory upstream still moves the fingerprint. Changing that is a
// fingerprint migration, not something to do in passing.
type vulnText struct {
	shown    string
	identity string
}

// add appends a note that reads the same in both roles.
func (t *vulnText) add(note string) {
	t.shown += note
	t.identity += note
}
