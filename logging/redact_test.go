package logging

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/inference-sh/goutils/secretshape"
)

func testHasher(t testing.TB) {
	SetEmailHasher(func(a string) string {
		s := sha256.Sum256([]byte(strings.ToLower(a)))
		return hex.EncodeToString(s[:])
	})
	t.Cleanup(func() { SetEmailHasher(nil) })
}

// capture is a logger built the way Init builds Root, writing to a buffer.
func capture() (*bytes.Buffer, zerolog.Logger) {
	var buf bytes.Buffer
	return &buf, zerolog.New(RedactWriter(zerolog.MultiLevelWriter(&buf)))
}

func TestRedact_emails(t *testing.T) {
	testHasher(t)
	tok := EmailToken("jane.doe+x@example.com")
	if !strings.HasPrefix(tok, "email:") || len(tok) != len("email:")+16 {
		t.Fatalf("token %q", tok)
	}
	buf, l := capture()
	nested, _ := json.Marshal(map[string]any{"user": map[string]any{"contact": "jane.doe+x@example.com"}})
	l.Warn().
		Str("note", "invite for jane.doe+x@example.com failed").
		Str("body", string(nested)).
		Str("url", "/admin/email-log?recipient=jane.doe%2Bx%40example.com").
		Str("multi", "line one\njane.doe+x@example.com").
		Interface("extra", map[string]any{"to": []string{"jane.doe+x@example.com"}}).
		Msgf("Sending team invite email to %s for team %s", "jane.doe+x@example.com", "acme")
	out := buf.String()
	if strings.Contains(out, "jane") || strings.Contains(out, "example.com") {
		t.Fatalf("address left in line: %s", out)
	}
	if n := strings.Count(out, tok); n != 6 {
		t.Errorf("want 6 tokens %s, got %d: %s", tok, n, out)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("line no longer JSON: %v: %s", err, out)
	}
}

func TestRedact_emailNamedFields(t *testing.T) {
	testHasher(t)
	buf, l := capture()
	l.Info().
		Str("email", "not-an-address").
		Str("git_user_email", "weird local@exa mple").
		Str("Email", "ü@example.de").
		Str("email_domain", "example.com").
		Str("recipient_hash", "abc123").
		Str("email_template", "welcome").
		Str("email_kept", EmailToken("a@b.co")).
		Msg("x")
	var m map[string]string
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"email":          EmailToken("not-an-address"),
		"git_user_email": EmailToken("weird local@exa mple"),
		"Email":          EmailToken("ü@example.de"),
		"email_domain":   "example.com",
		"recipient_hash": "abc123",
		"email_template": "welcome",
		"email_kept":     EmailToken("a@b.co"),
	} {
		if m[k] != want {
			t.Errorf("%s = %q, want %q", k, m[k], want)
		}
	}
}

func TestRedact_secrets(t *testing.T) {
	buf, l := capture()
	key := "sk-ant-" + strings.Repeat("k", 40)
	l.Error().Str("resp", `{"error":"bad key `+key+`"}`).Msg("Authorization: Bearer " + strings.Repeat("t", 32))
	out := buf.String()
	if strings.Contains(out, key) || strings.Contains(out, strings.Repeat("t", 32)) {
		t.Fatalf("secret left: %s", out)
	}
	if strings.Count(out, "[REDACTED]") != 2 {
		t.Errorf("want 2 placeholders: %s", out)
	}
}

func TestRedact_unkeyedAndUntouched(t *testing.T) {
	SetEmailHasher(nil)
	if got := RedactString(`{"m":"to a@b.com"}`); got != `{"m":"to email:redacted"}` {
		t.Errorf("unkeyed: %s", got)
	}
	for _, v := range []string{
		`{"level":"info","component":"api","method":"GET","path":"/api/v1/tasks","status":200}`,
		`{"image":"repo/app@sha256:abcdef","pkg":"left-pad@1.2.3"}`,
	} {
		in := []byte(v)
		if got := Redact(in); &got[0] != &in[0] || string(got) != v {
			t.Errorf("changed or copied: %s -> %s", v, got)
		}
	}
}

// The audit logger and Root that Init builds both redact.
func TestInit_redactsEveryLogger(t *testing.T) {
	testHasher(t)
	dir := t.TempDir()
	prevRoot, prevAudit := Root, auditRoot
	t.Cleanup(func() { Root, auditRoot = prevRoot, prevAudit })
	if err := Init(Config{Dir: dir, Filename: "x.txt", MaxSize: 1, Console: ConsoleQuiet, Level: zerolog.DebugLevel, Audit: true}); err != nil {
		t.Fatal(err)
	}
	Audit("user.created", "u1", "user", "u1", "success", &AuditContext{Extra: map[string]any{"email": "Jane@Example.com"}})
	Info("api").Msg("hello jane@example.com")
	for _, f := range []string{"x.txt", AuditFilename} {
		b := readFile(t, dir+"/"+f)
		if strings.Contains(strings.ToLower(b), "jane@example.com") {
			t.Errorf("%s holds the address: %s", f, b)
		}
		if !strings.Contains(b, EmailToken("jane@example.com")) {
			t.Errorf("%s lacks the token: %s", f, b)
		}
	}
}

// A typical request line (no address, no secret) and one with an address.
func BenchmarkRedact(b *testing.B) {
	SetEmailHasher(func(a string) string { s := sha256.Sum256([]byte(a)); return hex.EncodeToString(s[:]) })
	defer SetEmailHasher(nil)
	plain := []byte(`{"level":"info","component":"http","user_id":"01JD8Z3K4M5N6P7Q8R9S0T1V2W","team_id":"01JD8Z3K4M5N6P7Q8R9S0T1V2X","auth":"api_key","method":"POST","path":"/api/v1/apps/run","source":"sdk-py","status":200,"bytes":1834,"duration_ms":41.2,"ip":"203.0.113.9","time":"2026-11-04T10:00:00.123456789Z","message":"request"}` + "\n")
	withEmail := []byte(`{"level":"info","component":"audit","action":"user.created","actor_id":"u1","target_type":"user","target_id":"u1","outcome":"success","ip":"203.0.113.9","email":"jane.doe@example.com","role":"user","time":"2026-11-04T10:00:00.123456789Z","message":"user.created user:u1 actor:u1 success"}` + "\n")
	b.Run("plain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Redact(plain)
		}
	})
	b.Run("email", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Redact(withEmail)
		}
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func BenchmarkMayContain(b *testing.B) {
	plain := []byte(`{"level":"info","component":"http","user_id":"01JD8Z3K4M5N6P7Q8R9S0T1V2W","team_id":"01JD8Z3K4M5N6P7Q8R9S0T1V2X","auth":"api_key","method":"POST","path":"/api/v1/apps/run","source":"sdk-py","status":200,"bytes":1834,"duration_ms":41.2,"ip":"203.0.113.9","time":"2026-11-04T10:00:00.123456789Z","message":"request"}` + "\n")
	for i := 0; i < b.N; i++ {
		secretshape.MayContain(plain)
	}
}
