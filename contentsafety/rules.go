package contentsafety

import (
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/inference-sh/goutils/internal/escmask"
)

// ScanSeverity levels.
const (
	ScanSeverityCritical = "critical"
	ScanSeverityWarning  = "warning"
	ScanSeverityClean    = "clean"
)

// ScanFinding represents a single security finding.
type ScanFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Match       string `json:"match,omitempty"`
}

// ScanResult is the aggregate result of scanning a skill version.
type ScanResult struct {
	Severity string        `json:"severity"` // highest severity found
	Findings []ScanFinding `json:"findings"`
}

// rule is a pattern-based content rule.
type rule struct {
	ID          string
	Severity    string
	Description string
	Patterns    []*regexp.Regexp

	// Sets is the bitmask of families this rule belongs to.
	Sets RuleSet
	// Verbs records which operations the rule is precise enough to drive.
	Verbs Verb
	// Placeholder replaces a match under Clean. Unused by DetectOnly rules.
	Placeholder string
}

// rules is the registry of security scan rules.
// allRules is built lazily. Compiling ~180 regexes at package init cost every
// consumer about 5 ms of startup — measurable on a CLI that agents invoke in
// loops — even when no content is ever scanned. sync.OnceValue defers that to
// the first Detect or Clean call.
var allRules = sync.OnceValue(func() []rule {
	rules := []rule{
		{
			ID:          "INF-SEC-001",
			Sets:        Exfiltration,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Credential exfiltration — secrets or tokens sent to external endpoints via network tools",
			Patterns: compilePatterns(
				`(?i)(curl|wget|fetch)\s+.*\$\{?(KEY|TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|AWS_SECRET)`,
				`(?i)cat\s+~?/?\.(aws|ssh|gnupg)/\w+\s*\|`,
				`(?i)printenv\s*\|.*\b(curl|wget|nc|ncat)\b`,
				`(?i)(os\.environ|process\.env).*\b(requests\.(get|post)|fetch|http\.(get|post|request)|urllib)\b`,
				`(?i)\$\{?(KEY|TOKEN|SECRET|PASSWORD)\}?.*\|\s*(curl|wget|nc)\b`,
			),
		},
		{
			ID:          "INF-SEC-002",
			Sets:        Destructive,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Destructive system command — recursive deletion, disk formatting, or partition overwrite",
			Patterns: compilePatterns(
				`(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+/`,
				`(?i)\brm\s+-[a-z]*f[a-z]*r[a-z]*\s+/`,
				`(?i)\bmkfs\b`,
				`(?i)\bdd\b.*\bof=/dev/`,
				`(?i)shutil\.rmtree\s*\(\s*['\"]\/`,
				`(?i)\btruncate\b.*(/etc/|/var/|/boot/)`,
			),
		},
		{
			ID:          "INF-SEC-003",
			Sets:        Destructive,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Remote code execution — downloading and piping scripts directly to a shell interpreter",
			Patterns: compilePatterns(
				`(?i)(curl|wget)\s+[^\|]*\|\s*(sh|bash|zsh|dash)\b`,
			),
		},
		{
			ID:          "INF-SEC-004",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Executable or binary reference — skill references a native binary file format",
			Patterns: compilePatterns(
				`(?i)\.(exe|dll|so|dylib|msi|bat|cmd|scr|pif)\b`,
			),
		},
		{
			ID:          "INF-SEC-005",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Password-protected archive download — potentially concealing malicious content",
			Patterns: compilePatterns(
				`(?i)(curl|wget).*\.(zip|7z|rar)\b.*(-P\s+|-p\s*\w|--password)`,
			),
		},
		{
			ID:          "INF-SEC-006",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Obfuscated code execution — decoding encoded payloads and passing to eval/exec/shell",
			Patterns: compilePatterns(
				`(?i)base64\s+-[dD]\s*\|\s*(sh|bash|eval)\b`,
				`(?i)xxd\s+-r\s*\|\s*(sh|bash|eval)\b`,
				`(?i)eval\s*\(\s*atob\s*\(`,
				`(?i)exec\s*\(\s*bytes\.fromhex\s*\(`,
				`(?i)eval\s*\(\s*['\"]?\s*\+?\s*chr\s*\(`,
				`(?i)(exec|eval)\s*\(\s*(compile|bytes\.decode|codecs\.decode)\s*\(`,
			),
		},

		// ── 007–010: launch-blocker rules ──────────────────────────────

		{
			ID:          "INF-SEC-007",
			Sets:        Injection,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Prompt injection — hidden instructions attempting to override agent behavior",
			Patterns: compilePatterns(
				// Invisible unicode direction overrides / zero-width chars used to hide text
				`[\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2060}\x{2066}-\x{2069}\x{FEFF}]`,
				// HTML comments with instruction-like content
				`(?i)<!--\s*(ignore|disregard|forget|override|system|instruction|you are|act as|pretend)`,
				// Explicit system prompt override attempts
				`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)`,
				`(?i)you\s+are\s+now\s+(a|an|in)\s+`,
				`(?i)new\s+system\s+prompt`,
				`(?i)\bsystem\s*:\s*(you are|ignore|forget|override)`,
				// ANSI escape sequences used to hide content in terminals
				`\x1b\[\d*[mKJH]`,
			),
		},
		{
			ID:          "INF-SEC-008",
			Sets:        Destructive,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Persistence mechanism — writing to startup scripts, cron, or system services",
			Patterns: compilePatterns(
				// Crontab manipulation
				`(?i)(crontab\s+-[el]|crontab\s+<|echo\s+.*>>\s*/etc/cron)`,
				`(?i)\b(echo|cat|printf)\b.*>>\s*~?/?\.(bashrc|zshrc|profile|bash_profile|bash_login)`,
				// systemd / init / launchd persistence
				`(?i)(systemctl\s+(enable|start)|update-rc\.d|chkconfig\s+--add)`,
				`(?i)/etc/(init\.d|systemd/system|rc\.local)`,
				`(?i)~/Library/LaunchAgents/`,
				// Windows persistence
				`(?i)(reg\s+add|schtasks\s+/create).*\\(Run|RunOnce|CurrentVersion)`,
				// Python/Node startup persistence
				`(?i)(sitecustomize|usercustomize)\.py`,
				`(?i)NODE_OPTIONS.*--require`,
			),
		},
		{
			ID:          "INF-SEC-009",
			Sets:        HiddenContent,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Hidden content — concealed instructions in non-visible areas of files",
			Patterns: compilePatterns(
				// SVG script injection
				`(?i)<script[\s>]`,
				`(?i)\bon(load|error|click|mouseover)\s*=`,
				// Data URIs with executable content
				`(?i)data:(text/html|application/javascript|text/javascript)[;,]`,
				// PEM private keys
				`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`,
			),
		},
		{
			ID:          "INF-SEC-010",
			Sets:        Destructive,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Reverse shell — establishing remote interactive shell access",
			Patterns: compilePatterns(
				`(?i)\bbash\s+-i\s+>&\s*/dev/tcp/`,
				`(?i)\bnc\s+(-[a-z]*e\s+|.*-e\s*)/bin/(sh|bash)\b`,
				`(?i)\bncat\b.*(-e|--exec)\s*/bin/(sh|bash)`,
				`(?i)\bsocat\b.*exec.*sh`,
				`(?i)\bpython[23]?\s+-c\s+.*socket.*connect`,
				`(?i)\bperl\s+-e\s+.*socket.*INET`,
				`(?i)\bphp\s+-r\s+.*fsockopen`,
				`(?i)\bruby\s+-r\s*socket\s+-e`,
				`(?i)mkfifo\s+/tmp/.*\|\s*/bin/(sh|bash)`,
			),
		},

		// ── 011–017: credential & privilege rules ──────────────────────

		{
			ID:          "INF-SEC-011",
			Sets:        Credentials,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Credential logging — printing secrets or tokens to stdout where agents can read them",
			Patterns: compilePatterns(
				`(?i)(print|console\.log|logger\.\w+)\s*\(.{0,80}\b(token|secret|password|api_key|apikey|credential|private_key)\b`,
				`(?i)(print|console\.log)\s*\(.{0,80}\b(bearer|authorization)\b`,
				`(?i)\becho\s+.*\$\{?(token|secret|password|api_key|apikey)\}?`,
			),
		},
		{
			ID:          "INF-SEC-012",
			Sets:        Credentials,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Hardcoded credential — password or secret assignment in source",
			Patterns: compilePatterns(
				`(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]`,
				`(?i)aws_secret_access_key\s*[:=]\s*\S{30,}`,
			),
		},
		{
			ID:          "INF-SEC-013",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Suspicious download — fetching binaries or archives from non-standard sources",
			Patterns: compilePatterns(
				// Direct binary downloads from IP addresses
				`(?i)(curl|wget)\s+.*https?://\d+\.\d+\.\d+\.\d+`,
				// Downloading and executing in one command
				`(?i)(curl|wget)\s+.*-[oO]\s+\S+\s*&&\s*(chmod\s+\+x|\./)`,
				// pip/npm install from URLs (not registry)
				`(?i)(pip|npm)\s+install\s+https?://`,
			),
		},
		{
			ID:          "INF-SEC-014",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Dependency confusion — installing from non-standard registries or scoped overrides",
			Patterns: compilePatterns(
				`(?i)pip\s+install\s+.*--index-url\s+`,
				`(?i)npm\s+(config\s+set\s+registry|install\s+.*--registry)\s+`,
				`(?i)pip\s+install\s+.*--extra-index-url`,
			),
		},
		{
			ID:          "INF-SEC-015",
			Sets:        Destructive,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Privilege escalation — attempting to gain elevated system permissions",
			Patterns: compilePatterns(
				`(?i)\bsudo\s+(chmod|chown|rm|mv|cp|ln|mount|umount|iptables)\b`,
				`(?i)\bchmod\s+[0-7]*4[0-7]{2}\b`, // setuid
				`(?i)\bchmod\s+[0-7]*2[0-7]{2}\b`, // setgid
				`(?i)echo\s+.*\|\s*sudo\s+tee\b`,
				`(?i)\bsudo\s+su\b`,
				`(?i)\bpkexec\b`,
				`(?i)\bdoas\b\s+\w`,
			),
		},
		{
			ID:          "INF-SEC-016",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Financial operation — cryptocurrency mining, wallet transfers, or payment manipulation",
			Patterns: compilePatterns(
				`(?i)(xmrig|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer)\b`,
				`(?i)stratum\+tcp://`,
				`(?i)\b(bitcoin|ethereum|monero|litecoin)\s*(address|wallet|transfer|send)\b`,
				`(?i)0x[a-fA-F0-9]{40}\b`, // Ethereum addresses
			),
		},
		{
			ID:          "INF-SEC-017",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Network reconnaissance — port scanning, host enumeration, or traffic interception",
			Patterns: compilePatterns(
				`(?i)\bnmap\b`,
				`(?i)\bmasscan\b`,
				`(?i)\btcpdump\b.*-[iw]\b`,
				`(?i)\btshark\b`,
				`(?i)\barpspoof\b`,
				`(?i)\bettercap\b`,
			),
		},

		// ── 018–021: supply chain & structural rules ───────────────────

		{
			ID:          "INF-SEC-018",
			Sets:        Malicious,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Path traversal — accessing files outside expected directories via ../ sequences",
			Patterns: compilePatterns(
				`(?i)(\.\.\/){3,}`, // 3+ levels of traversal
				`(?i)(cat|less|more|head|tail)\s+.*\.\./\.\./`,   // reading files via traversal
				`(?i)(open|fopen|readFile|read_file)\s*\(.*\.\.`, // programmatic file access
			),
		},
		{
			ID:          "INF-SEC-019",
			Sets:        HiddenContent,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Unicode abuse — homoglyph or confusable characters that disguise malicious content",
			Patterns: compilePatterns(
				// Cyrillic/Greek lookalikes mixed with Latin in identifiers
				`[\x{0400}-\x{04FF}].*[a-zA-Z]|[a-zA-Z].*[\x{0400}-\x{04FF}]`,
				// Fullwidth Latin characters (can bypass filters)
				`[\x{FF01}-\x{FF5E}]`,
			),
		},
		{
			ID:          "INF-SEC-020",
			Sets:        Destructive,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Environment manipulation — modifying PATH, LD_PRELOAD, or other critical env vars",
			Patterns: compilePatterns(
				`(?i)export\s+(PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|DYLD_INSERT_LIBRARIES)\s*=`,
			),
		},
		{
			ID:          "INF-SEC-021",
			Sets:        Exfiltration,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityWarning,
			Description: "Data exfiltration via DNS or steganography — covert channels for leaking data",
			Patterns: compilePatterns(
				`(?i)\bdig\b.*\bTXT\b.*\$`,       // DNS TXT record exfil
				`(?i)\bnslookup\b.*\$`,           // DNS lookup with variable data
				`(?i)\bhost\b\s+\$`,              // host command with variable
				`(?i)steghide\b`,                 // steganography tool
				`(?i)\bexiftool\b.*-comment.*\$`, // metadata exfil
			),
		},

		// ── 022: provider-specific credential detection ────────────────
		// Patterns sourced from gitleaks (github.com/gitleaks/gitleaks).
		// These catch hardcoded API keys by their known prefix/format.

		{
			ID:          "INF-SEC-022",
			Sets:        Credentials,
			Verbs:       DetectOnly,
			Severity:    ScanSeverityCritical,
			Description: "Hardcoded API key — provider-specific credential detected by known token format",
			Patterns: compilePatterns(
				// OpenAI
				`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{58,74}T3BlbkFJ[A-Za-z0-9_\-]+`,
				`\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`,
				// Anthropic
				`\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA\b`,
				`\bsk-ant-admin01-[a-zA-Z0-9_\-]{93}AA\b`,
				// AWS
				`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`,
				// Stripe
				`\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b`,
				// GitHub
				`\bghp_[0-9a-zA-Z]{36}\b`,
				`\bgithub_pat_\w{82}\b`,
				`\bgho_[0-9a-zA-Z]{36}\b`,
				`\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b`,
				// Google Cloud
				`\bAIza[\w\-]{35}\b`,
				// Slack
				`\bxoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*`,
				`(?i)xapp-\d-[A-Z0-9]+-\d-[a-z0-9]+`,
				`(?i)hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`,
				// Twilio
				`\bSK[0-9a-fA-F]{32}\b`,
				// SendGrid
				`\bSG\.[a-zA-Z0-9=_\-\.]{66}\b`,
				// npm
				`(?i)\bnpm_[a-z0-9]{36}\b`,
				// PyPI
				`\bpypi-AgEIcHlwaS5vcmc[\w\-]{50,}`,
				// Shopify
				`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`,
				// HuggingFace
				`(?i)\bhf_[a-z]{34}\b`,
				// Linear
				`\blin_api_[a-zA-Z0-9]{40}\b`,
				// Notion
				`\bntn_[0-9]{11}[A-Za-z0-9]{35}\b`,
				// Postman
				`(?i)\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`,
				// Cloudflare origin CA
				`\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b`,
				// Azure AD client secret
				`[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34}`,
				// Telegram bot token
				`\b[0-9]{5,16}:A[a-zA-Z0-9_\-]{34}\b`,
				// Generic high-confidence patterns
				`(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]`,
				// Connection strings with embedded credentials
				`(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@`,
			),
		},
	}
	// Registered after the behavioural corpus so Detect reports them in a
	// stable order.
	rules = append(rules, credentialRules()...)
	rules = append(rules, specialTokenRules()...)
	rules = append(rules, toolResultRules()...)
	return rules
})

func compilePatterns(patterns ...string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return compiled
}

func scanContentRules(result *ScanResult, filePath string, content string, include func(*rule) bool) {
	lines := strings.Split(content, "\n")

	// Build normalized lines to catch evasion: collapse spaces between single chars,
	// replace confusable unicode with ASCII equivalents, strip zero-width chars.
	normalizedLines := make([]string, len(lines))
	for i, line := range lines {
		normalizedLines[i] = normalizeLine(line)
	}

	seen := map[scanSeenKey]bool{}
	corpus := allRules()
	for i := range corpus {
		r := &corpus[i]
		if include != nil && !include(r) {
			continue
		}
		for _, pattern := range r.Patterns {
			scanLines(result, r, pattern, filePath, lines, seen)
			scanLines(result, r, pattern, filePath, normalizedLines, seen)
		}
	}
}

type scanSeenKey struct {
	ruleID  string
	lineNum int
}

func scanLines(result *ScanResult, r *rule, pattern *regexp.Regexp, filePath string, lines []string, seen map[scanSeenKey]bool) {
	for lineNum, line := range lines {
		key := scanSeenKey{r.ID, lineNum}
		if seen[key] {
			continue
		}
		if loc := escmask.FindIndex(pattern, line); loc != nil {
			seen[key] = true
			result.Findings = append(result.Findings, ScanFinding{
				RuleID:      r.ID,
				Severity:    r.Severity,
				Description: r.Description,
				File:        filePath,
				Line:        lineNum + 1,
				Match:       truncateMatch(line[loc[0]:loc[1]]),
			})
			if severityRank(r.Severity) > severityRank(result.Severity) {
				result.Severity = r.Severity
			}
		}
	}
}

// truncateMatch bounds a reported match so a finding cannot carry an entire
// document into a log line.
func truncateMatch(s string) string {
	if utf8.RuneCountInString(s) <= 200 {
		return s
	}
	return string([]rune(s)[:200]) + "..."
}

// redactionPatterns are credential-format regexes used to mask secrets in content
// before serving to clients or storing in agent context. Only high-confidence
// patterns that match structured token formats — not generic keyword heuristics.
// Sourced from gitleaks (github.com/gitleaks/gitleaks).
// Lazy for the same reason as allRules: 27 provider regexes are not worth
// compiling in a process that never scans anything.
var redactionPatterns = sync.OnceValue(func() []*regexp.Regexp {
	return compilePatterns(
		// Provider-specific tokens (structured prefixes)
		`\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}`,     // OpenAI
		`\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`,         // OpenAI legacy
		`\bsk-ant-(?:api03|admin01)-[a-zA-Z0-9_\-]{20,}`,      // Anthropic
		`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`, // AWS access key
		`\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b`, // Stripe
		`\bghp_[0-9a-zA-Z]{36}\b`,                             // GitHub PAT
		`\bgithub_pat_\w{82}\b`,                               // GitHub fine-grained PAT
		`\bgho_[0-9a-zA-Z]{36}\b`,                             // GitHub OAuth
		`\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b`,                     // GitHub app token
		`\bAIza[\w\-]{35}\b`,                                  // Google Cloud
		`\bxoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*`,      // Slack bot
		`(?i)xapp-\d-[A-Z0-9]+-\d-[a-z0-9]+`,                  // Slack app
		`\bSK[0-9a-fA-F]{32}\b`,                               // Twilio
		`\bSG\.[a-zA-Z0-9=_\-\.]{66}\b`,                       // SendGrid
		`(?i)\bnpm_[a-z0-9]{36}\b`,                            // npm
		`\bpypi-AgEIcHlwaS5vcmc[\w\-]{50,}`,                   // PyPI
		`\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b`,              // Shopify
		`(?i)\bhf_[a-z]{34}\b`,                                // HuggingFace
		`\blin_api_[a-zA-Z0-9]{40}\b`,                         // Linear
		`\bntn_[0-9]{11}[A-Za-z0-9]{35}\b`,                    // Notion
		`(?i)\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`,              // Postman
		`\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b`,                // Cloudflare origin CA
		`\b[0-9]{5,16}:A[a-zA-Z0-9_\-]{34}\b`,                 // Telegram bot
		// Structural patterns
		`-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END`, // PEM private keys
		`(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@\s]+@[^\s]+`,  // Connection strings
		`(?i)aws_secret_access_key\s*[:=]\s*\S{30,}`,                 // AWS secret key
	)
})

// Redact replaces all credential-format matches in content with [REDACTED].
// Uses hardcoded patterns + dynamically loaded gitleaks patterns.
func Redact(content string) string {
	for _, pattern := range LiveRedactionPatterns() {
		content = pattern.ReplaceAllString(content, "[REDACTED]")
	}
	return content
}

// Cyrillic confusables — package-level to avoid per-line allocation.
var confusableRunes = map[rune]rune{
	'а': 'a', 'А': 'A', 'В': 'B', 'с': 'c', 'С': 'C',
	'е': 'e', 'Е': 'E', 'Н': 'H', 'і': 'i', 'І': 'I',
	'К': 'K', 'М': 'M', 'о': 'o', 'О': 'O', 'р': 'p',
	'Р': 'P', 'Т': 'T', 'х': 'x', 'Х': 'X', 'у': 'y',
}

// Zero-width unicode codepoints to strip during normalization.
var zwSet = map[rune]bool{
	'\u200B': true, '\u200C': true, '\u200D': true, '\u200E': true, '\u200F': true,
	'\u202A': true, '\u202B': true, '\u202C': true, '\u202D': true, '\u202E': true,
	'\u2060': true, '\u2066': true, '\u2067': true, '\u2068': true, '\u2069': true,
	'\uFEFF': true,
}

// normalizeLine strips zero-width chars, replaces confusable unicode with ASCII,
// normalizes fullwidth chars, collapses single-char spacing, and strips trailing backslashes.
// All transformations happen in a single rune pass where possible.
func normalizeLine(line string) string {
	src := []rune(line)
	dst := make([]rune, 0, len(src))

	// Single pass: strip zero-width, replace confusables, normalize fullwidth
	for _, r := range src {
		if zwSet[r] {
			continue
		}
		if repl, ok := confusableRunes[r]; ok {
			r = repl
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFF01 + 0x0021
		}
		dst = append(dst, r)
	}

	// Collapse single-char spacing: "c u r l" → "curl"
	dst = collapseSingleCharSpacing(dst)

	// Strip trailing backslash (line continuation evasion)
	for len(dst) > 0 {
		last := dst[len(dst)-1]
		if last == ' ' || last == '\t' || last == '\\' {
			dst = dst[:len(dst)-1]
		} else {
			break
		}
	}

	return string(dst)
}

// collapseSingleCharSpacing detects runs of 3+ single alphanum chars
// separated by spaces ("c u r l") and collapses them ("curl").
func collapseSingleCharSpacing(runes []rune) []rune {
	n := len(runes)
	if n < 5 {
		return runes
	}

	result := make([]rune, 0, n)
	i := 0
	for i < n {
		// Need at least 3 single-char tokens: X ' ' Y ' ' Z
		if i+4 < n && (i == 0 || !isAlphanumOrUnderscore(runes[i-1])) &&
			isAlphanumOrUnderscore(runes[i]) && isSpace(runes[i+1]) &&
			isAlphanumOrUnderscore(runes[i+2]) && isSpace(runes[i+3]) &&
			isAlphanumOrUnderscore(runes[i+4]) {
			var run []rune
			j := i
			for j < n && isAlphanumOrUnderscore(runes[j]) {
				run = append(run, runes[j])
				if j+1 < n && isSpace(runes[j+1]) && j+2 < n && isAlphanumOrUnderscore(runes[j+2]) &&
					(j+3 >= n || isSpace(runes[j+3]) || !isAlphanumOrUnderscore(runes[j+3])) {
					j += 2
					continue
				}
				j++
				break
			}
			result = append(result, run...)
			i = j
			continue
		}
		result = append(result, runes[i])
		i++
	}
	return result
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t'
}

func isAlphanumOrUnderscore(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
}

func severityRank(s string) int {
	switch s {
	case ScanSeverityCritical:
		return 3
	case ScanSeverityWarning:
		return 2
	case ScanSeverityClean:
		return 1
	default:
		return 0
	}
}
