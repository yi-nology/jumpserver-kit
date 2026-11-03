package textx

import "testing"

// The one place the cut is made gets its own test: the guards downstream
// (the trail's character-boundary test, the column-ceiling test) exercise it
// through wrappers, and a wrapper can hide which side of a change is wrong.

func TestTruncKeepsWholeRunesAndMarksTheCut(t *testing.T) {
	// "日本語" is 9 bytes; a cut at 4 bytes must stop at 3.
	if got := Trunc("日本語のテキスト", 4, "…"); got != "日…" {
		t.Errorf("Trunc cut inside a rune: got %q", got)
	}
	if got := Trunc("日本語のテキスト", 4, ""); got != "日" {
		t.Errorf("Trunc with empty suffix: got %q", got)
	}
}

func TestTruncReturnsTheInputWhenItFits(t *testing.T) {
	if got := Trunc("short", 100, "…(clipped)"); got != "short" {
		t.Errorf("an uncut string must come back as it was, got %q", got)
	}
	if got := Trunc("12345", 5, "…"); got != "12345" {
		t.Errorf("a string of exactly n bytes is not cut, got %q", got)
	}
}
