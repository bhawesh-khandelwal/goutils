package enginetoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const api = "https://api.example.test"

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, engineID string, iat time.Time) string {
	t.Helper()
	tok, err := Sign(priv, engineID, api, iat)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// signClaims signs claims as an engine would not: for the refusals.
func signClaims(t *testing.T, method jwt.SigningMethod, key any, kid string, c jwt.RegisteredClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Now()
	tok := sign(t, priv, "eng-1", now)

	if id, ok := Kid(tok); !ok || id != "eng-1" {
		t.Fatalf("Kid = (%q, %v), want eng-1", id, ok)
	}
	if err := Verify(tok, pub, "eng-1", []string{api}, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Good until exactly MaxTTL after it was issued, not a second more.
	if err := Verify(tok, pub, "eng-1", []string{api}, now.Add(MaxTTL-time.Second)); err != nil {
		t.Fatalf("Verify before expiry: %v", err)
	}
	if err := Verify(tok, pub, "eng-1", []string{api}, now.Add(MaxTTL+time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify after expiry = %v, want ErrInvalid", err)
	}
}

// Every token that is not exactly the engine's, now, is refused: no leeway
// on its times, only the engine's key, names and API, and EdDSA.
func TestVerifyRefuses(t *testing.T) {
	pub, priv := newKey(t)
	_, other := newKey(t)
	now := time.Now()
	claims := func(edit func(*jwt.RegisteredClaims)) jwt.RegisteredClaims {
		c := jwt.RegisteredClaims{
			Issuer: Subject("eng-1"), Subject: Subject("eng-1"), Audience: jwt.ClaimStrings{api},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		}
		edit(&c)
		return c
	}
	eddsa := func(edit func(*jwt.RegisteredClaims)) string {
		return signClaims(t, jwt.SigningMethodEdDSA, priv, Subject("eng-1"), claims(edit))
	}
	hmac := signClaims(t, jwt.SigningMethodHS256, []byte(pub), Subject("eng-1"), claims(func(*jwt.RegisteredClaims) {}))
	none := signClaims(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, Subject("eng-1"), claims(func(*jwt.RegisteredClaims) {}))

	for name, tok := range map[string]string{
		"signed by another key":       sign(t, other, "eng-1", now),
		"expired a second ago":        sign(t, priv, "eng-1", now.Add(-MaxTTL-time.Second)),
		"issued in the future":        sign(t, priv, "eng-1", now.Add(10*time.Second)),
		"living longer than MaxTTL":   eddsa(func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(MaxTTL + time.Second)) }),
		"no expiry":                   eddsa(func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil }),
		"no issued-at":                eddsa(func(c *jwt.RegisteredClaims) { c.IssuedAt = nil }),
		"for another API":             eddsa(func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"https://elsewhere.test"} }),
		"naming another engine":       eddsa(func(c *jwt.RegisteredClaims) { c.Subject = Subject("eng-2") }),
		"issued by another engine":    eddsa(func(c *jwt.RegisteredClaims) { c.Issuer = Subject("eng-2") }),
		"another engine's token":      sign(t, priv, "eng-2", now),
		"HMAC keyed with the pub key": hmac,
		"alg none":                    none,
	} {
		if err := Verify(tok, pub, "eng-1", []string{api}, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Verify = %v, want ErrInvalid", name, err)
		}
	}
	if err := Verify(sign(t, priv, "eng-1", now), pub, "eng-1", nil, now); !errors.Is(err, ErrInvalid) {
		t.Errorf("no audience to check: Verify = %v, want ErrInvalid", err)
	}
	if err := Verify(sign(t, priv, "eng-1", now), nil, "eng-1", []string{api}, now); !errors.Is(err, ErrInvalid) {
		t.Errorf("no key: Verify = %v, want ErrInvalid", err)
	}
}

func TestKidOnlyForEngineTokens(t *testing.T) {
	_, priv := newKey(t)
	for name, tok := range map[string]string{
		"not a JWT":     "sk_live_abc",
		"three dots":    "a.b.c",
		"another kid":   signClaims(t, jwt.SigningMethodEdDSA, priv, "user:1", jwt.RegisteredClaims{}),
		"an empty id":   signClaims(t, jwt.SigningMethodEdDSA, priv, SubjectPrefix, jwt.RegisteredClaims{}),
		"no kid at all": signClaims(t, jwt.SigningMethodHS256, []byte("k"), "", jwt.RegisteredClaims{}),
	} {
		if id, ok := Kid(tok); ok {
			t.Errorf("%s: Kid = %q, want none", name, id)
		}
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	pub, _ := newKey(t)
	got, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("ParsePublicKey(EncodePublicKey) = (%x, %v)", got, err)
	}
	for _, bad := range []string{"", "not base64!", EncodePublicKey(pub[:16]), EncodePublicKey(pub) + "=="} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("ParsePublicKey(%q) accepted", bad)
		}
	}
}

func TestOriginAndFingerprint(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.Example.test/v1/": "https://api.example.test",
		" http://localhost:8080 ":      "http://localhost:8080",
		"api.example.test":             "",
		"":                             "",
	} {
		if got := Origin(in); got != want {
			t.Errorf("Origin(%q) = %q, want %q", in, got, want)
		}
	}
	if Fingerprint("") != "" {
		t.Error("no key has no fingerprint")
	}
	if fp := Fingerprint("key"); len(fp) != 16 || fp == Fingerprint("key2") {
		t.Errorf("Fingerprint = %q: want 16 hex characters, one per key", fp)
	}
}
