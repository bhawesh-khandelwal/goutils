package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog"

	"github.com/inference-sh/goutils/secretshape"
)

// Every line a logger from this package writes (Root, the audit logger, and
// any logger built on RedactWriter) passes Redact first, so no log line
// carries an email address or a credential-shaped secret:
//
//   - an email address anywhere in the line (message, any string field, a
//     JSON document inside a string, a URL-encoded "%40" address) becomes
//     "email:<16 hex>", the first 16 hex digits of the hash SetEmailHasher's
//     function gives for it, or "email:redacted" while none is set;
//   - the string value of a field whose name ends in "email" (email,
//     user_email, git_user_email, Email) or "email_address" becomes the same
//     token even when it does not look like an address;
//   - every secretshape shape is replaced with secretshape.Placeholder.
//
// A line with no '@', "%40", email-named field or secret hint is written as
// is without a copy.

// EmailTokenPrefix starts the token an email address is replaced with.
const EmailTokenPrefix = "email:"

// emailTokenHexLen is how many hex digits of the hash the token keeps.
const emailTokenHexLen = 16

// emailTokenUnkeyed is the token while no hasher is set.
const emailTokenUnkeyed = EmailTokenPrefix + "redacted"

var emailHasher atomic.Pointer[func(string) string]

// SetEmailHasher sets the function an address's token is computed with: a
// hex digest (at least 16 digits) of the address, keyed so that only those
// holding the key can compute it for a candidate address. nil clears it.
// Safe to call at any time, from any goroutine.
func SetEmailHasher(hash func(address string) string) {
	if hash == nil {
		emailHasher.Store(nil)
		return
	}
	emailHasher.Store(&hash)
}

// EmailToken is the token Redact writes for address under the current
// hasher: what to search the logs for to find lines about it.
func EmailToken(address string) string {
	h := emailHasher.Load()
	if h == nil {
		return emailTokenUnkeyed
	}
	return EmailTokenOf((*h)(address))
}

// EmailTokenOf is the token for an address whose hash (the hasher's hex
// digest) is sum: for a caller that already holds the hash.
func EmailTokenOf(sum string) string {
	if len(sum) > emailTokenHexLen {
		sum = sum[:emailTokenHexLen]
	}
	return EmailTokenPrefix + sum
}

// Redact returns line with every email address and secret replaced (see
// above). A line with nothing to replace is returned as is.
func Redact(line []byte) []byte {
	hasAt := bytes.IndexByte(line, '@') >= 0 || bytes.Contains(line, hintPct40)
	hasKey := bytes.Contains(line, hintMail) || bytes.Contains(line, hintMailUC)
	hasSecret := secretshape.MayContain(line)
	if !hasAt && !hasKey && !hasSecret {
		return line
	}
	s := string(line)
	orig := s
	if hasSecret {
		s, _ = secretshape.Redact(s, "")
	}
	if hasKey {
		s = redactEmailFields(s)
	}
	if hasAt {
		s = redactAddresses(s)
	}
	if s == orig {
		return line
	}
	return []byte(s)
}

// RedactString is Redact for a string.
func RedactString(s string) string {
	return string(Redact([]byte(s)))
}

var (
	hintPct40  = []byte("%40")
	hintMail   = []byte("mail")
	hintMailUC = []byte("MAIL")
)

// redactAddresses replaces every address in s with its token: a local part
// of the usual characters, '@' or "%40", and a dotted domain whose last label
// is letters only. A JSON escape's letter right before the address
// ("\njane@…") is not part of it.
func redactAddresses(s string) string {
	var out strings.Builder
	last, i := 0, 0
	for i < len(s) {
		sep, sepLen := nextSeparator(s, i)
		if sep < 0 {
			break
		}
		k := sep
		for k > 0 && isLocalByte(s[k-1]) {
			k--
		}
		if k < sep && k > 0 && s[k-1] == '\\' && (k < 2 || s[k-2] != '\\') {
			switch {
			case s[k] == 'u' && sep-k > 5 && isHex4(s[k+1:k+5]):
				k += 5
			case strings.IndexByte("bfnrt", s[k]) >= 0:
				k++
			}
		}
		e := sep + sepLen
		for e < len(s) && isDomainByte(s[e]) {
			e++
		}
		for e > sep+sepLen && (s[e-1] == '.' || s[e-1] == '-') {
			e--
		}
		if k == sep || !validDomain(s[sep+sepLen:e]) {
			i = sep + sepLen
			continue
		}
		if out.Len() == 0 {
			out.Grow(len(s))
		}
		out.WriteString(s[last:k])
		out.WriteString(EmailToken(decodeAddress(s[k:e])))
		last, i = e, e
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

// nextSeparator is the index and length of the first '@' or "%40" in s at or
// after i, or -1.
func nextSeparator(s string, i int) (int, int) {
	at := strings.IndexByte(s[i:], '@')
	pct := strings.Index(s[i:], "%40")
	switch {
	case at < 0 && pct < 0:
		return -1, 0
	case pct < 0 || (at >= 0 && at < pct):
		return i + at, 1
	default:
		return i + pct, 3
	}
}

func isLocalByte(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
}

func isDomainByte(c byte) bool { return isAlnum(c) || c == '.' || c == '-' }

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func isHex4(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// validDomain reports whether d is two or more dot-separated labels, none
// empty or starting or ending with '-', the last of two or more letters.
func validDomain(d string) bool {
	dot := strings.LastIndexByte(d, '.')
	if dot <= 0 {
		return false
	}
	tld := d[dot+1:]
	if len(tld) < 2 {
		return false
	}
	for i := 0; i < len(tld); i++ {
		if c := tld[i]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
			return false
		}
	}
	for _, label := range strings.Split(d[:dot], ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// redactEmailFields replaces the value of every string field whose name ends
// in "email" or "email_address" (any case) with its token. A value that
// already is a token, or is empty, stays.
func redactEmailFields(s string) string {
	var out strings.Builder
	last, i := 0, 0
	for {
		j := strings.Index(s[i:], `":"`)
		if j < 0 {
			break
		}
		j += i
		vs := j + 3
		ve := stringEnd(s, vs)
		i = ve
		ks := strings.LastIndexByte(s[:j], '"')
		if ks < 0 || ve >= len(s) || !isEmailKey(s[ks+1:j]) {
			continue
		}
		raw := s[vs:ve]
		if raw == "" || strings.HasPrefix(raw, EmailTokenPrefix) {
			continue
		}
		var v string
		if err := json.Unmarshal([]byte(`"`+raw+`"`), &v); err != nil {
			v = raw
		}
		if out.Len() == 0 {
			out.Grow(len(s))
		}
		out.WriteString(s[last:vs])
		out.WriteString(EmailToken(v))
		last = ve
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

// stringEnd is the index of the quote closing the JSON string whose content
// starts at i (len(s) when unterminated).
func stringEnd(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
		case '"':
			return i
		default:
			i++
		}
	}
	return len(s)
}

// isEmailKey reports whether a field name ends in "email", "email_address"
// or "emailaddress", in any case, and is a plain identifier.
func isEmailKey(k string) bool {
	for i := 0; i < len(k); i++ {
		if c := k[i]; !isAlnum(c) && c != '_' {
			return false
		}
	}
	l := strings.ToLower(k)
	return strings.HasSuffix(l, "email") || strings.HasSuffix(l, "email_address") || strings.HasSuffix(l, "emailaddress")
}

// decodeAddress undoes the URL encoding of an address found as "a%40b.com".
func decodeAddress(a string) string {
	if !strings.Contains(a, "%") {
		return a
	}
	if d, err := url.QueryUnescape(a); err == nil {
		return d
	}
	return strings.ReplaceAll(a, "%40", "@")
}

// RedactWriter wraps w so that every line written passes Redact first. Init
// applies it to every writer it sets up; a logger built outside Init (a test
// capture, a custom sink) uses it to get the same guarantee.
func RedactWriter(w io.Writer) zerolog.LevelWriter {
	if rw, ok := w.(redactWriter); ok {
		return rw
	}
	lw, ok := w.(zerolog.LevelWriter)
	if !ok {
		lw = zerolog.LevelWriterAdapter{Writer: w}
	}
	return redactWriter{lw}
}

type redactWriter struct {
	w zerolog.LevelWriter
}

func (r redactWriter) Write(p []byte) (int, error) {
	if _, err := r.w.Write(Redact(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (r redactWriter) WriteLevel(l zerolog.Level, p []byte) (int, error) {
	if _, err := r.w.WriteLevel(l, Redact(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}
