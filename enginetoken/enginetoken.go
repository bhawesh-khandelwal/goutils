// Package enginetoken is what an engine and the API agree on for the
// engine's own credential: the token the engine signs for every call, and
// the names and fingerprints both sides compute from its keys.
//
// An engine enrolls an Ed25519 key once and keeps its private half on its
// host. Every call it makes carries a JWT it signed (RFC 7523 shape): header
// alg EdDSA, kid engine:<id>; claims iss = sub = engine:<id>, aud the API's
// origin, iat, and exp at most MaxTTL after iat. The API verifies it against
// the key pinned on the engine with no leeway: an expired token, one issued
// in the future and one that lives longer than MaxTTL are refused alike, and
// the engine corrects its clock from the refusal's Date header.
//
// Signer (the engine) and verifier (the API) are separate programs, so the
// format lives here, where both import its one definition.
package enginetoken

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// SubjectPrefix opens an engine token's kid, iss and sub (Subject).
	SubjectPrefix = "engine:"
	// MaxTTL caps how long after it was issued a token is good for.
	MaxTTL = 5 * time.Minute
	// KeyFingerprintHeader carries, on an engine's socket upgrade, the
	// Fingerprint of the encryption key the engine registered with: the API
	// admits the socket for that key only.
	KeyFingerprintHeader = "X-Engine-Key-Fingerprint"
)

// ErrInvalid wraps every refusal of a token.
var ErrInvalid = errors.New("invalid engine token")

// Subject is engine id's kid, iss and sub.
func Subject(engineID string) string { return SubjectPrefix + engineID }

// EngineOfSubject is the engine a Subject names.
func EngineOfSubject(subject string) (string, bool) {
	id, ok := strings.CutPrefix(subject, SubjectPrefix)
	return id, ok && id != ""
}

// Fingerprint is a short fingerprint of an engine key as it travels (a
// signing key's EncodePublicKey, an encryption key's PEM): the first eight
// bytes of its SHA-256, hex. Enough to tell one key from the next, and all
// of it a log line or a header carries. "" for no key.
func Fingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// Origin is rawURL's scheme and host, lower case: the audience a token for
// the API at rawURL names. "" when rawURL is not an absolute URL.
func Origin(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// EncodePublicKey is a signing key's public half as it is enrolled and
// pinned: base64url, no padding.
func EncodePublicKey(key ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// ParsePublicKey reads an EncodePublicKey.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not an Ed25519 public key, base64url without padding")
	}
	return ed25519.PublicKey(b), nil
}

// Sign is engineID's token for the API at audience (an Origin), issued at
// issuedAt and good for MaxTTL.
func Sign(key ed25519.PrivateKey, engineID, audience string, issuedAt time.Time) (string, error) {
	if engineID == "" || audience == "" {
		return "", errors.New("an engine token names its engine and its API")
	}
	subject := Subject(engineID)
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.RegisteredClaims{
		Issuer:    subject,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(issuedAt.Add(MaxTTL)),
	})
	t.Header["kid"] = subject
	return t.SignedString(key)
}

// Kid is the engine a token's header names (kid engine:<id>), read without
// verifying anything: what the API looks the pinned key up by. ok is false
// for anything that is not a JWT naming an engine.
func Kid(token string) (engineID string, ok bool) {
	t, _, err := jwt.NewParser().ParseUnverified(token, &jwt.RegisteredClaims{})
	if err != nil {
		return "", false
	}
	kid, _ := t.Header["kid"].(string)
	return EngineOfSubject(kid)
}

// Verify checks that token is engineID's, signed by key, for one of
// audiences, and good at now: EdDSA only, iss and sub engineID's Subject,
// iat and exp present, exp at most MaxTTL after iat, no leeway. Every
// refusal is ErrInvalid.
func Verify(token string, key ed25519.PublicKey, engineID string, audiences []string, now time.Time) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: engine %s has no usable key", ErrInvalid, engineID)
	}
	if len(audiences) == 0 {
		return fmt.Errorf("%w: no audience to check", ErrInvalid)
	}
	subject := Subject(engineID)
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(subject),
		jwt.WithSubject(subject),
		jwt.WithAudience(audiences...),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	var c jwt.RegisteredClaims
	if _, err := parser.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return key, nil }); err != nil {
		return fmt.Errorf("%w: engine %s: %v", ErrInvalid, engineID, err)
	}
	if c.IssuedAt == nil || c.ExpiresAt.Sub(c.IssuedAt.Time) > MaxTTL {
		return fmt.Errorf("%w: engine %s: a token lives at most %s", ErrInvalid, engineID, MaxTTL)
	}
	return nil
}
