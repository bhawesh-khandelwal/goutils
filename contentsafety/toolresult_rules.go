package contentsafety

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Families for text an agent reads back from a tool (Check). None is in
// AllRules: the publish and store gates that scan with AllRules predate them,
// and several match ordinary content those gates must keep passing (a log
// line that starts "user:", a README with a badge image).
const (
	// TurnForgery matches text shaped like a conversation's structure: a
	// role or turn marker, a tool-result tag, or tool-call syntax, which can
	// make a model read data as its own turn or as a call it made.
	TurnForgery RuleSet = 1 << (iota + 9)

	// EncodedPayload matches long base64 runs that decode to readable text:
	// instructions hidden from a person skimming the result.
	EncodedPayload

	// Mentions matches chat mentions (<@U…>, <!channel>, @here) that notify
	// people when an agent posts the text on.
	Mentions

	// ImageExfil matches markdown and HTML images with a remote URL, which a
	// renderer fetches on its own, carrying whatever the URL encodes.
	ImageExfil

	// TagCharacters matches the Unicode tag block (U+E0000–E007F): invisible
	// characters a model reads as ASCII. The one rule here that rewrites.
	TagCharacters

	// AgentAddressed matches text that speaks to the AI reading it ("note to
	// the AI agent", "classify this as safe"). Not part of Injection: a skill
	// is written to an agent on purpose, and the skill gates scan Injection.
	AgentAddressed

	// ToolResultRules is what Check applies: the injection families of the
	// behavioural corpus plus those above.
	ToolResultRules = Injection | SpecialTokens | HiddenContent | Exfiltration |
		TurnForgery | EncodedPayload | Mentions | ImageExfil | TagCharacters |
		AgentAddressed
)

// Rule ids of the tool-result families.
const (
	RuleTagCharacters  = "INF-PI-001"
	RuleRoleMarker     = "INF-PI-002"
	RuleToolCallSyntax = "INF-PI-003"
	RuleEncodedText    = "INF-PI-004"
	RuleMention        = "INF-PI-005"
	RuleImageLink      = "INF-PI-006"
	RuleAgentAddressed = "INF-PI-007"
	RuleRoleTag        = "INF-PI-008"
	RuleFalseAuthority = "INF-PI-009"
)

func toolResultRules() []rule {
	return []rule{
		{
			ID:          RuleTagCharacters,
			Sets:        TagCharacters,
			Verbs:       DetectOnly | CleanSafe,
			Severity:    SeverityCritical,
			Description: "Unicode tag characters — invisible text a model reads as ASCII",
			// Removed outright: nothing a reader sees is lost. The one
			// legitimate use, subdivision flag emoji (England, Scotland,
			// Wales), degrades to a plain black flag.
			Placeholder: "",
			Patterns:    compilePatterns(`[\x{E0000}-\x{E007F}]+`),
		},
		{
			ID:          RuleRoleTag,
			Sets:        TurnForgery,
			Verbs:       DetectOnly,
			Severity:    SeverityCritical,
			Description: "Conversation tag — a system, tool-result or function-results tag that could forge a turn",
			Patterns: compilePatterns(
				`(?i)</?\s*(system|system_prompt|tool_result|tool_results|function_results|function_result|tool_response|assistant|user_message)\s*>`,
			),
		},
		{
			ID:          RuleRoleMarker,
			Sets:        TurnForgery,
			Verbs:       DetectOnly,
			Severity:    SeverityWarning,
			Description: "Role marker — a line opening with a conversation role, as a transcript would",
			Patterns: compilePatterns(
				// A line that opens with a role: a forged transcript turn.
				// Warning only: "user: alice" opens many a log line.
				`(?i)^\s*(system|assistant|user|human)\s*:`,
				// The Human:/Assistant: transcript form, anywhere, as written.
				`\b(Human|Assistant):\s`,
			),
		},
		{
			ID:          RuleToolCallSyntax,
			Sets:        TurnForgery,
			Verbs:       DetectOnly,
			Severity:    SeverityCritical,
			Description: "Tool-call syntax — text shaped like a call the model made",
			Patterns: compilePatterns(
				`(?i)</?\s*(antml:)?(function_calls|invoke)\b`,
				`(?i)<\s*(antml:)?parameter\s+name\s*=`,
				`"tool_calls"\s*:\s*\[`,
				`\{\s*"name"\s*:\s*"[^"]{1,80}"\s*,\s*"(arguments|parameters|input)"\s*:`,
				`(?i)\[TOOL_CALLS\]`,
			),
		},
		{
			ID:          RuleMention,
			Sets:        Mentions,
			Verbs:       DetectOnly,
			Severity:    SeverityWarning,
			Description: "Chat mention — notifies people when an agent posts the text",
			Patterns: compilePatterns(
				`<@[UWB][A-Z0-9]{6,}>`,
				`<!(channel|here|everyone)(\|[^>]*)?>`,
				`<!subteam\^[A-Z0-9]+`,
				`(^|[\s(\[])@(here|channel|everyone)\b`,
			),
		},
		{
			ID:          RuleImageLink,
			Sets:        ImageExfil,
			Verbs:       DetectOnly,
			Severity:    SeverityWarning,
			Description: "Remote image — a renderer fetches it unasked, carrying whatever its URL encodes",
			Patterns: compilePatterns(
				// Only a URL that can carry data: a query, a template, or a
				// long opaque segment. A badge's fixed URL carries nothing.
				`!\[[^\]]{0,200}\]\(\s*<?https?://[^)\s]*(\?|=|\{|%7[Bb]|[A-Za-z0-9_-]{40,})`,
				`(?i)<img\b[^>]*\bsrc\s*=\s*["']?https?://[^"'\s>]*(\?|=|\{|%7b|[a-z0-9_-]{40,})`,
			),
		},
		{
			ID:          RuleAgentAddressed,
			Sets:        AgentAddressed,
			Verbs:       DetectOnly,
			Severity:    SeverityCritical,
			Description: "Agent-addressed instruction — text speaking to the AI that reads it",
			Patterns: compilePatterns(
				// "Note to the AI agent", "instructions for LLMs".
				`(?i)\b(note|message|instructions?|attention|notice|reminder)\s+(to|for)\s+(the\s+|any\s+|all\s+)?(ai|llm|gpt|claude|agent|assistant|model|bot)s?\b`,
				// "AI agent reviewing these logs", "LLM model reading this".
				`(?i)\b(ai|llm)\s+(agent|assistant|model|bot|reviewer)s?\s+(reading|reviewing|analy[sz]ing|processing|triaging|summari[sz]ing|parsing|scanning)\b`,
				// "AI agents: …" opening an address.
				`(?i)\b(ai|llm)\s+(agents?|assistants?|models?|bots?|coding\s+assistants?)\s*:`,
				`(?i)\bif\s+you\s+are\s+(an?\s+)?(ai|llm|language\s+model|agent|assistant|automated\s+(system|agent|reviewer))\b`,
				// "classify this as safe", "mark these requests as false positives".
				`(?i)\b(classify|mark|treat|report|label|flag|consider|close)\s+(this|these|those|it|them|the)(\s+[a-z]+){0,2}\s+as\s+(an?\s+)?(safe|benign|harmless|legitimate|clean|false\s+positives?|normal|resolved|expected|authori[sz]ed|trusted)\b`,
				`(?i)\b(do\s+not|don'?t|never)\s+(report|flag|alert|escalate|mention|disclose)\s+(this|these|it|them|the|any|to)\b`,
				// "ignore your previous instructions", "forget your prior rules".
				`(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(of\s+)?(your|the|my|these)\s+(previous|prior|earlier|above|original|existing|current)\s+(instructions?|prompts?|rules?|guidelines?|directives?|guidance)\b`,
				// "The assistant must run …", "you should now post …".
				`(?i)\b(you|(the\s+)?(ai\s+)?(agent|assistant|model|bot|llm))\s+(must|should|shall|needs?\s+to|is\s+required\s+to|are\s+required\s+to)\s+(now\s+|always\s+|first\s+)?(run|execute|call|post|send|reply|respond|output|print|reveal|forward|include|mention|approve|delete|disable|restart|reset)\b`,
				// A result telling the agent what to say.
				`(?i)\b(tell|inform|assure|reassure)\s+the\s+user\s+(that\s+)?(there|it|this|everything|nothing|no)\b`,
			),
		},
		{
			ID:          RuleFalseAuthority,
			Sets:        AgentAddressed,
			Verbs:       DetectOnly,
			Severity:    SeverityCritical,
			Description: "False authority — data claiming to speak for the system, staff, the developer or the user",
			Patterns: compilePatterns(
				`(?i)\[\s*(admin|administrator|system|developer|operator|security(\s+team)?|staff)\s+(message|notice|override|instruction)s?\s*\]`,
				`(?i)\b(message|instructions?|notice)\s+from\s+(the\s+)?(developer|admin|administrator|operator|system|platform|security\s+team|staff|maintainers)\s*:`,
				`(?i)^\s*#{1,6}\s*system\s*(prompt|message)?\s*$`,
				`(?i)\byou\s+are\s+now\s+(operating|running|acting|working)\s+(with|as|in|under)\b`,
				`(?i)\byour\s+(operator|developer|owner|admin|administrator|creator)\s+(has\s+)?(approved|authori[sz]ed|granted|instructed|asked|wants|allowed)\b`,
				`(?i)\bthe\s+user\s+(has\s+)?(asked|approved|authori[sz]ed|wants|granted|instructed|told)\s+(me\s+)?(\([^)]{0,30}\)\s+)?(you|to\s+tell\s+you)\b`,
				`(?i)\b(the\s+)?(developer|operator|administrator|maintainers?)\s+(has|have)\s+(authori[sz]ed|approved|granted)\s+you\b`,
			),
		},
	}
}

// Encoded payloads.

// minEncodedRun is the shortest base64 run checked: 200 characters decode to
// 150 bytes, a sentence or two.
const minEncodedRun = 200

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{200,}={0,2}`)

const encodedTextDescription = "Encoded text — a long base64 run that decodes to readable text"

// detectEncodedText reports base64 runs that decode to text. Binary payloads
// (an image, a key, a hash) decode to bytes that are not text and are left
// alone; that is what keeps a data: URI or a JWT from tripping it. A run
// whose text itself matches an injection rule is critical.
func detectEncodedText(result *Result, content string, include func(*rule) bool) {
	if !hasBase64Run(content) {
		return
	}
	for _, loc := range base64Run.FindAllStringIndex(content, 32) {
		run := content[loc[0]:loc[1]]
		text, ok := decodeBase64Text(run)
		if !ok {
			continue
		}
		severity := SeverityWarning
		inner := Result{Severity: SeverityClean}
		scanWhole(&inner, text, func(r *rule) bool {
			return r.Sets&(Injection|AgentAddressed|TurnForgery|Exfiltration) != 0 && (include == nil || include(r))
		})
		if len(inner.Findings) > 0 {
			severity = SeverityCritical
		}
		result.Findings = append(result.Findings, Finding{
			RuleID:      RuleEncodedText,
			Severity:    severity,
			Description: encodedTextDescription,
			Match:       truncateMatch(text),
		})
		if severityRank(severity) > severityRank(result.Severity) {
			result.Severity = severity
		}
		return // one finding is enough to annotate
	}
}

// hasBase64Run reports whether s has minEncodedRun base64 characters in a
// row, which is far cheaper to rule out than the regex.
func hasBase64Run(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '_' || c == '-' {
			n++
			if n >= minEncodedRun {
				return true
			}
			continue
		}
		n = 0
	}
	return false
}

// decodeBase64Text decodes run as standard or URL-safe base64 and reports
// whether the result reads as text: valid UTF-8, at least 90% printable,
// with some letters and spaces.
func decodeBase64Text(run string) (string, bool) {
	trimmed := strings.TrimRight(run, "=")
	var raw []byte
	var err error
	if strings.ContainsAny(trimmed, "-_") {
		raw, err = base64.RawURLEncoding.DecodeString(trimmed)
	} else {
		raw, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		// A run cut mid-quantum by the regex: drop the tail and retry.
		cut := len(trimmed) - len(trimmed)%4
		if cut < minEncodedRun {
			return "", false
		}
		raw, err = base64.RawStdEncoding.DecodeString(trimmed[:cut])
		if err != nil {
			return "", false
		}
	}
	if !utf8.Valid(raw) {
		return "", false
	}
	s := string(raw)
	var total, printable, letters, spaces int
	for _, r := range s {
		total++
		switch {
		case r == ' ':
			spaces++
			printable++
		case r == '\n' || r == '\t' || r == '\r':
			printable++
		case unicode.IsLetter(r):
			letters++
			printable++
		case unicode.IsPrint(r):
			printable++
		}
	}
	if total == 0 || printable*10 < total*9 || letters*2 < total || spaces*30 < total {
		return "", false
	}
	return s, true
}
