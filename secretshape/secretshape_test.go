package secretshape

import (
	"strings"
	"testing"
)

func TestRedact_knownShapes(t *testing.T) {
	cases := []string{
		"sk-" + strings.Repeat("a", 40),
		"sk-ant-" + strings.Repeat("b", 40),
		"sk_live_" + strings.Repeat("c", 24),
		"ghp_" + strings.Repeat("d", 36),
		"github_pat_" + strings.Repeat("e", 30),
		"glpat-" + strings.Repeat("f", 20),
		"xoxb-" + strings.Repeat("1", 12),
		"AKIA" + strings.Repeat("Q", 16),
		"AIza" + strings.Repeat("g", 35),
		"ya29." + strings.Repeat("h", 30),
		"infrt-" + strings.Repeat("i", 20),
		"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
	}
	for _, v := range cases {
		out, n := Redact("before "+v+" after", "")
		if n != 1 || strings.Contains(out, v) || !strings.Contains(out, Placeholder) {
			t.Errorf("%q: got %q (%d)", v, out, n)
		}
	}
	out, n := Redact(`Authorization: Bearer `+strings.Repeat("t", 32), "")
	if n != 1 || out != "Authorization: Bearer "+Placeholder {
		t.Errorf("bearer: got %q (%d)", out, n)
	}
}

func TestRedact_ordinaryTextUntouched(t *testing.T) {
	cases := []string{
		"a normal sentence about skiing and skates",
		`{"url":"https://x.example/a.b.c?sig=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}`, // JWT-like, kept
		"ask-me-anything-" + strings.Repeat("z", 30),                                     // sk- inside a word
		`{"a":"-----BEGIN PRIVATE KEY-----","b":"-----END PRIVATE KEY-----"}`,            // a shape never spans a quote
	}
	for _, v := range cases {
		out, n := Redact(v, "")
		if n != 0 || out != v {
			t.Errorf("%q: got %q (%d)", v, out, n)
		}
	}
}

func TestRedact_customPlaceholder(t *testing.T) {
	out, _ := Redact("AKIA"+strings.Repeat("Q", 16), "***")
	if out != "***" {
		t.Errorf("got %q", out)
	}
}

// In serialized JSON or NDJSON a value after a newline is written "\ninfrt-…":
// the escape's letter is a word character, so \b alone would see no boundary.
func TestRedact_afterJSONEscape(t *testing.T) {
	tok := "infrt-" + strings.Repeat("i", 20)
	for _, esc := range []string{"\\n", "\\t", "\\r", "\\u0020"} {
		in := `{"text":"line` + esc + tok + `"}`
		out, n := Redact(in, "")
		want := `{"text":"line` + esc + Placeholder + `"}`
		if n != 1 || out != want {
			t.Errorf("%s: got %s (%d), want %s", esc, out, n, want)
		}
	}
	// An escaped backslash then the letter n is text: "\\nsk-…" decodes to
	// \nsk-…, a word, and stays.
	in := `{"a":"\\nsk-` + strings.Repeat("a", 30) + `"}`
	if out, n := Redact(in, ""); n != 0 || out != in {
		t.Errorf("escaped backslash: got %s (%d)", out, n)
	}
	in = `{"h":"x\nAuthorization: Bearer ` + strings.Repeat("t", 32) + `"}`
	if out, n := Redact(in, ""); n != 1 || out != `{"h":"x\nAuthorization: Bearer `+Placeholder+`"}` {
		t.Errorf("bearer after escape: got %s (%d)", out, n)
	}
}

// Every shape has a hint: a sample of each matches its shape and MayContain.
func TestMayContain_everyShape(t *testing.T) {
	samples := []string{
		"sk-" + strings.Repeat("a", 40),
		"sk_live_" + strings.Repeat("c", 24),
		"ghp_" + strings.Repeat("d", 36),
		"github_pat_" + strings.Repeat("e", 30),
		"glpat-" + strings.Repeat("f", 20),
		"xoxb-" + strings.Repeat("1", 12),
		"AKIA" + strings.Repeat("Q", 16),
		"AIza" + strings.Repeat("g", 35),
		"ya29." + strings.Repeat("h", 30),
		"infrt-" + strings.Repeat("i", 20),
		"-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
	}
	if len(samples) != len(Shapes) {
		t.Fatalf("%d samples for %d shapes: add a sample (and a hint) for the new shape", len(samples), len(Shapes))
	}
	for i, re := range Shapes {
		if !re.MatchString(samples[i]) {
			t.Errorf("sample %d %q does not match its shape %s", i, samples[i], re)
		}
		if !MayContain([]byte(samples[i])) {
			t.Errorf("shape %s: MayContain misses %q", re, samples[i])
		}
	}
	for _, v := range []string{"Authorization: Bearer " + strings.Repeat("t", 32), "AUTHORIZATION=token " + strings.Repeat("t", 32)} {
		if Bearer.MatchString(v) && !MayContain([]byte(v)) {
			t.Errorf("bearer: MayContain misses %q", v)
		}
	}
	if MayContain([]byte(`{"level":"info","component":"api","path":"/api/v1/tasks","status":200}`)) {
		t.Error("ordinary line hinted")
	}
}
