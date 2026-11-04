package testsupport

import "testing"

// firstDiffLine is what turns "the documents differ" into "line N, and here
// is what each side says" — that is the whole point of the guard's message.
func TestFirstDiffLinePointsAtTheFirstDisagreement(t *testing.T) {
	cases := []struct {
		name     string
		a, b     string
		wantLine int
	}{
		{"一模一样", "a\nb\nc", "a\nb\nc", 0},
		{"首行即不同", "x", "y", 1},
		{"第三行起不同", "a\nb\nX", "a\nb\nY", 3},
		{"一侧多一行", "a\nb", "a\nb\nc", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line, _, _ := firstDiffLine([]byte(c.a), []byte(c.b))
			if line != c.wantLine {
				t.Fatalf("firstDiffLine(%q, %q) = %d，要 %d", c.a, c.b, line, c.wantLine)
			}
		})
	}
}
