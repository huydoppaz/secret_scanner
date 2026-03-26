// Package patterns provides pre-compiled regex patterns for secret detection.
// Optimized for speed with compiled patterns.
package patterns

import (
	"regexp"
	"sync"
)

// Severity levels for detected secrets.
type Severity string

const (
	SeverityCRITICAL Severity = "critical" // Verified secrets (AWS keys, private keys)
	SeverityHIGH     Severity = "high"     // Likely secrets (API tokens)
	SeverityMEDIUM   Severity = "medium"   // Potential secrets (passwords in comments)
	SeverityLOW      Severity = "low"      // Low confidence findings
)

// SeverityOrder maps severity to numeric level for comparison.
var SeverityOrder = map[Severity]int{
	SeverityCRITICAL: 0,
	SeverityHIGH:     1,
	SeverityMEDIUM:   2,
	SeverityLOW:      3,
}

// SecretPattern represents a secret detection pattern.
type SecretPattern struct {
	Name         string
	Pattern      *regexp.Regexp
	Severity     Severity
	Category     string
	Description  string
	EntropyCheck bool // Enable entropy analysis for this pattern
}

// PatternRegistry is a registry of all secret detection patterns.
// Patterns are pre-compiled for maximum performance.
type PatternRegistry struct {
	patterns []SecretPattern
	compiled bool
	mu       sync.RWMutex
}

var (
	// Global registry instance
	globalRegistry = &PatternRegistry{}
	initOnce       sync.Once
)

// GetRegistry returns the global pattern registry instance.
func GetRegistry() *PatternRegistry {
	initOnce.Do(func() {
		globalRegistry.compilePatterns()
	})
	return globalRegistry
}

// compilePatterns pre-compiles all regex patterns once.
func (r *PatternRegistry) compilePatterns() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.compiled {
		return
	}

	r.patterns = []SecretPattern{
		// ==================== PII - Personal Information ====================
		{
			Name:         "Email Address",
			Pattern:      regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			Severity:     SeverityMEDIUM,
			Category:     "PII",
			Description:  "Email address - personally identifiable information",
			EntropyCheck: false,
		},
		{
			Name:         "Phone Number (US)",
			Pattern:      regexp.MustCompile(`\(?\b\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b`),
			Severity:     SeverityMEDIUM,
			Category:     "PII",
			Description:  "US Phone number",
			EntropyCheck: false,
		},
		{
			Name:         "Phone Number (Vietnam)",
			Pattern:      regexp.MustCompile(`(0|\+84)(3[2-9]|5[6-9]|7[0-9]|8[0-9]|9[0-9])\d{7}\b`),
			Severity:     SeverityMEDIUM,
			Category:     "PII",
			Description:  "Vietnam phone number",
			EntropyCheck: false,
		},
		{
			Name:         "SSN (US)",
			Pattern:      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Severity:     SeverityCRITICAL,
			Category:     "PII",
			Description:  "US Social Security Number",
			EntropyCheck: false,
		},
		{
			Name:         "CMND/CCCD (Vietnam)",
			Pattern:      regexp.MustCompile(`\b(0\d{11}|\d{9})\b`),
			Severity:     SeverityCRITICAL,
			Category:     "PII",
			Description:  "Vietnam ID card number (CMND/CCCD)",
			EntropyCheck: false,
		},
		{
			Name:         "Date of Birth",
			Pattern:      regexp.MustCompile(`\b(0?[1-9]|[12]\d|3[01])[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](19|20)\d{2}\b`),
			Severity:     SeverityLOW,
			Category:     "PII",
			Description:  "Date of birth (DD/MM/YYYY format)",
			EntropyCheck: false,
		},
		{
			Name:         "IPv6 Address",
			Pattern:      regexp.MustCompile(`([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`),
			Severity:     SeverityLOW,
			Category:     "PII",
			Description:  "IPv6 address",
			EntropyCheck: false,
		},
		{
			Name:         "MAC Address",
			Pattern:      regexp.MustCompile(`\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b`),
			Severity:     SeverityLOW,
			Category:     "PII",
			Description:  "MAC address",
			EntropyCheck: false,
		},

		// ==================== Finance / Banking ====================
		{
			Name:         "Visa Credit Card",
			Pattern:      regexp.MustCompile(`4[0-9]{12}(?:[0-9]{3})?`),
			Severity:     SeverityCRITICAL,
			Category:     "Finance",
			Description:  "Visa credit card number",
			EntropyCheck: false,
		},
		{
			Name:         "Mastercard",
			Pattern:      regexp.MustCompile(`5[1-5][0-9]{14}|2[2-7][0-9]{14}`),
			Severity:     SeverityCRITICAL,
			Category:     "Finance",
			Description:  "Mastercard credit card number",
			EntropyCheck: false,
		},
		{
			Name:         "American Express",
			Pattern:      regexp.MustCompile(`3[47][0-9]{13}`),
			Severity:     SeverityCRITICAL,
			Category:     "Finance",
			Description:  "American Express credit card number",
			EntropyCheck: false,
		},
		{
			Name:         "Credit Card (Generic)",
			Pattern:      regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`),
			Severity:     SeverityHIGH,
			Category:     "Finance",
			Description:  "Generic credit card number",
			EntropyCheck: false,
		},
		{
			Name:         "IBAN",
			Pattern:      regexp.MustCompile(`[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}`),
			Severity:     SeverityHIGH,
			Category:     "Finance",
			Description:  "International Bank Account Number",
			EntropyCheck: false,
		},

		// ==================== AWS Keys ====================
		{
			Name:         "AWS Access Key ID",
			Pattern:      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "AWS Access Key ID - grants programmatic access to AWS services",
			EntropyCheck: false,
		},
		{
			Name:         "AWS Temporary Key (STS)",
			Pattern:      regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "AWS STS Temporary Access Key",
			EntropyCheck: false,
		},
		{
			Name:         "AWS Secret Access Key",
			Pattern:      regexp.MustCompile(`(?i)aws[_\-]?(?:secret[_\-]?)?access[_\-]?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "AWS Secret Access Key - associated with Access Key ID",
			EntropyCheck: false,
		},
		{
			Name:         "AWS Session Token",
			Pattern:      regexp.MustCompile(`(?i)aws[_\-]?session[_\-]?token\s*[:=]\s*["\']?[A-Za-z0-9/+=]{200,}["\']?`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "AWS Session Token - temporary credentials",
			EntropyCheck: false,
		},

		// ==================== GitHub Tokens ====================
		{
			Name:         "GitHub Personal Access Token",
			Pattern:      regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
			Severity:     SeverityCRITICAL,
			Category:     "Source Control",
			Description:  "GitHub Personal Access Token - grants repository access",
			EntropyCheck: false,
		},
		{
			Name:         "GitHub OAuth Token",
			Pattern:      regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
			Severity:     SeverityCRITICAL,
			Category:     "Source Control",
			Description:  "GitHub OAuth Token",
			EntropyCheck: false,
		},
		{
			Name:         "GitHub Fine-Grained PAT",
			Pattern:      regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,255}`),
			Severity:     SeverityCRITICAL,
			Category:     "Source Control",
			Description:  "GitHub Fine-Grained Personal Access Token",
			EntropyCheck: false,
		},
		{
			Name:         "GitHub App Token",
			Pattern:      regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
			Severity:     SeverityCRITICAL,
			Category:     "Source Control",
			Description:  "GitHub App or Installation Token",
			EntropyCheck: false,
		},

		// ==================== GitLab Tokens ====================
		{
			Name:         "GitLab Personal Access Token",
			Pattern:      regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20}`),
			Severity:     SeverityCRITICAL,
			Category:     "Source Control",
			Description:  "GitLab Personal Access Token",
			EntropyCheck: false,
		},

		// ==================== Private Keys ====================
		{
			Name:         "RSA Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN(?: RSA)? PRIVATE KEY-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "RSA Private Key - cryptographic key material",
			EntropyCheck: false,
		},
		{
			Name:         "EC Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "EC Private Key - elliptic curve key",
			EntropyCheck: false,
		},
		{
			Name:         "PGP Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "PGP Private Key",
			EntropyCheck: false,
		},
		{
			Name:         "SSH Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "SSH Private Key",
			EntropyCheck: false,
		},
		{
			Name:         "Generic Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "Generic Private Key",
			EntropyCheck: false,
		},
		{
			Name:         "DSA Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "DSA Private Key",
			EntropyCheck: false,
		},
		{
			Name:         "PKCS#8 Private Key",
			Pattern:      regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptographic Key",
			Description:  "PKCS#8 Private Key",
			EntropyCheck: false,
		},
		{
			Name:         "X.509 Certificate",
			Pattern:      regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
			Severity:     SeverityMEDIUM,
			Category:     "Cryptographic Key",
			Description:  "X.509 Certificate",
			EntropyCheck: false,
		},

		// ==================== JWT Tokens ====================
		{
			Name:         "JWT Token",
			Pattern:      regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
			Severity:     SeverityHIGH,
			Category:     "Authentication",
			Description:  "JSON Web Token - may contain sensitive claims",
			EntropyCheck: false,
		},

		// ==================== Stripe ====================
		{
			Name:         "Stripe Secret Key",
			Pattern:      regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			Severity:     SeverityCRITICAL,
			Category:     "Payment",
			Description:  "Stripe Secret Key - live mode",
			EntropyCheck: false,
		},
		{
			Name:         "Stripe Publishable Key",
			Pattern:      regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`),
			Severity:     SeverityHIGH,
			Category:     "Payment",
			Description:  "Stripe Publishable Key - less sensitive but still identifying",
			EntropyCheck: false,
		},
		{
			Name:         "Stripe Access Token",
			Pattern:      regexp.MustCompile(`sk_live_[A-Za-z0-9]{40,}`),
			Severity:     SeverityCRITICAL,
			Category:     "Payment",
			Description:  "Stripe Access Token",
			EntropyCheck: false,
		},

		// ==================== Slack ====================
		{
			Name:         "Slack Bot Token",
			Pattern:      regexp.MustCompile(`xoxb-[A-Za-z0-9]{10,48}`),
			Severity:     SeverityCRITICAL,
			Category:     "Messaging",
			Description:  "Slack Bot Token - bot user access",
			EntropyCheck: false,
		},
		{
			Name:         "Slack User Token",
			Pattern:      regexp.MustCompile(`xoxp-[A-Za-z0-9]{10,48}`),
			Severity:     SeverityCRITICAL,
			Category:     "Messaging",
			Description:  "Slack User Token - full user access",
			EntropyCheck: false,
		},
		{
			Name:         "Slack Webhook URL",
			Pattern:      regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
			Severity:     SeverityHIGH,
			Category:     "Messaging",
			Description:  "Slack Webhook URL - can post messages",
			EntropyCheck: false,
		},
		{
			Name:         "Slack Token (All Types)",
			Pattern:      regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,250}`),
			Severity:     SeverityCRITICAL,
			Category:     "Messaging",
			Description:  "Slack Token (bot/user/app/user_refresh/xoxa)",
			EntropyCheck: false,
		},

		// ==================== Twilio ====================
		{
			Name:         "Twilio Account SID",
			Pattern:      regexp.MustCompile(`AC[a-z0-9]{32}`),
			Severity:     SeverityCRITICAL,
			Category:     "Communication",
			Description:  "Twilio Account SID",
			EntropyCheck: false,
		},

		// ==================== Mailchimp ====================
		{
			Name:         "Mailchimp API Key",
			Pattern:      regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
			Severity:     SeverityCRITICAL,
			Category:     "Email",
			Description:  "Mailchimp API Key",
			EntropyCheck: false,
		},

		// ==================== DigitalOcean ====================
		{
			Name:         "DigitalOcean PAT",
			Pattern:      regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "DigitalOcean Personal Access Token",
			EntropyCheck: false,
		},

		// ==================== Database Connection Strings ====================
		{
			Name:         "MySQL Connection",
			Pattern:      regexp.MustCompile(`mysql://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_.\-:]+/\w+`),
			Severity:     SeverityCRITICAL,
			Category:     "Database",
			Description:  "MySQL connection string with credentials",
			EntropyCheck: false,
		},
		{
			Name:         "PostgreSQL Connection",
			Pattern:      regexp.MustCompile(`postgres(?:ql)?://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_.\-:]+/\w+`),
			Severity:     SeverityCRITICAL,
			Category:     "Database",
			Description:  "PostgreSQL connection string with credentials",
			EntropyCheck: false,
		},
		{
			Name:         "MongoDB Connection",
			Pattern:      regexp.MustCompile(`mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9_.\-:]+/\w*`),
			Severity:     SeverityCRITICAL,
			Category:     "Database",
			Description:  "MongoDB connection string with credentials",
			EntropyCheck: false,
		},
		{
			Name:         "Redis Connection",
			Pattern:      regexp.MustCompile(`redis://:[^@]+@[a-zA-Z0-9_.\-:]+:\d+`),
			Severity:     SeverityCRITICAL,
			Category:     "Database",
			Description:  "Redis connection string with password",
			EntropyCheck: false,
		},
		{
			Name:         "SQL Server Connection",
			Pattern:      regexp.MustCompile(`(?i)Server=[^;]+;.*(?:Password|Pwd)[^;]+=[^;]+`),
			Severity:     SeverityCRITICAL,
			Category:     "Database",
			Description:  "SQL Server connection string with password",
			EntropyCheck: false,
		},

		// ==================== Azure ====================
		{
			Name:         "Azure Storage Account Key",
			Pattern:      regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{88}==`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "Azure Storage Account Key",
			EntropyCheck: false,
		},
		{
			Name:         "Azure Client Secret",
			Pattern:      regexp.MustCompile(`(?i)client[_\-]?secret\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40,}["\']?`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "Azure AD Client Secret",
			EntropyCheck: false,
		},

		// ==================== Google Cloud ====================
		{
			Name:         "Google API Key",
			Pattern:      regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "Google API Key",
			EntropyCheck: false,
		},
		{
			Name:         "Google Service Account",
			Pattern:      regexp.MustCompile(`"type": "service_account"`),
			Severity:     SeverityHIGH,
			Category:     "Cloud Provider",
			Description:  "Google Service Account JSON file - likely contains private key",
			EntropyCheck: false,
		},

		// ==================== Generic API Keys/Tokens ====================
		{
			Name:         "Generic API Key",
			Pattern:      regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey)[_\-]?(?:name)?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?`),
			Severity:     SeverityHIGH,
			Category:     "API Key",
			Description:  "Generic API Key assignment",
			EntropyCheck: false,
		},
		{
			Name:         "Generic Secret",
			Pattern:      regexp.MustCompile(`(?i)(?:secret|private[_\-]?key)[_\-]?(?:name)?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?`),
			Severity:     SeverityHIGH,
			Category:     "Secret",
			Description:  "Generic secret assignment",
			EntropyCheck: false,
		},
		{
			Name:         "Generic Token",
			Pattern:      regexp.MustCompile(`(?i)(?:auth[_\-]?token|access[_\-]?token)[_\-]?(?:name)?\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?`),
			Severity:     SeverityHIGH,
			Category:     "Token",
			Description:  "Generic auth token",
			EntropyCheck: false,
		},

		// ==================== Password Patterns ====================
		{
			Name:         "Password Assignment",
			Pattern:      regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']`),
			Severity:     SeverityHIGH,
			Category:     "Credential",
			Description:  "Password assignment in code",
			EntropyCheck: false,
		},
		{
			Name:         "Username/Password Pair",
			Pattern:      regexp.MustCompile(`(?i)(?:username|user)[_\-]?(?:name)?\s*[:=]\s*["\'][^"\']+["\'].*?(?:password|passwd)[_\-]?\s*[:=]\s*["\'][^"\']+["\']`),
			Severity:     SeverityHIGH,
			Category:     "Credential",
			Description:  "Username and password pair in same context",
			EntropyCheck: false,
		},

		// ==================== Environment Variables ====================
		{
			Name:         "Environment Variable Export",
			Pattern:      regexp.MustCompile(`export\s+(?:AWS_|AZURE_|STRIPE_|GITHUB_|SLACK_|DATABASE_)?(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=\s*["\']?[A-Za-z0-9/+=]{20,}["\']?`),
			Severity:     SeverityHIGH,
			Category:     "Environment",
			Description:  "Export of sensitive environment variable",
			EntropyCheck: false,
		},
		{
			Name:         ".env Secret Assignment",
			Pattern:      regexp.MustCompile(`(?m)^(?:AWS_|AZURE_|STRIPE_|GITHUB_|SLACK_)?(?:SECRET|KEY|TOKEN|PASSWORD|PRIVATE)[A-Z_]*\s*=\s*["\']?[A-Za-z0-9/+=]{20,}["\']?$`),
			Severity:     SeverityHIGH,
			Category:     "Environment",
			Description:  "Sensitive .env variable assignment",
			EntropyCheck: false,
		},

		// ==================== Docker ====================
		{
			Name:         "Docker Hub Password",
			Pattern:      regexp.MustCompile(`(?i)docker[_\-]?hub[_\-]?(?:password|passwd)?\s*[:=]\s*["\']?[A-Za-z0-9_!@#$%^&*()]{8,}["\']?`),
			Severity:     SeverityHIGH,
			Category:     "Container",
			Description:  "Docker Hub credentials",
			EntropyCheck: false,
		},

		// ==================== Twilio ====================
		{
			Name:         "Twilio API Key",
			Pattern:      regexp.MustCompile(`SK[a-z0-9a-f]{32}`),
			Severity:     SeverityCRITICAL,
			Category:     "Communication",
			Description:  "Twilio API Key",
			EntropyCheck: false,
		},
		{
			Name:         "Twilio Auth Token",
			Pattern:      regexp.MustCompile(`[a-zA-Z0-9]{32}`),
			Severity:     SeverityHIGH,
			Category:     "Communication",
			Description:  "Twilio Auth Token (32 hex chars)",
			EntropyCheck: true,
		},

		// ==================== SendGrid ====================
		{
			Name:         "SendGrid API Key",
			Pattern:      regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
			Severity:     SeverityCRITICAL,
			Category:     "Email",
			Description:  "SendGrid API Key",
			EntropyCheck: false,
		},

		// ==================== Mailgun ====================
		{
			Name:         "Mailgun API Key",
			Pattern:      regexp.MustCompile(`(?i)key-[a-z0-9a-f]{32}`),
			Severity:     SeverityCRITICAL,
			Category:     "Email",
			Description:  "Mailgun API Key",
			EntropyCheck: false,
		},

		// ==================== NPM ====================
		{
			Name:         "NPM Token",
			Pattern:      regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
			Severity:     SeverityCRITICAL,
			Category:     "Package Manager",
			Description:  "NPM authentication token",
			EntropyCheck: false,
		},

		// ==================== PyPI ====================
		{
			Name:         "PyPI Token",
			Pattern:      regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`),
			Severity:     SeverityCRITICAL,
			Category:     "Package Manager",
			Description:  "PyPI trusted publisher token",
			EntropyCheck: false,
		},

		// ==================== Heroku ====================
		{
			Name:         "Heroku API Key",
			Pattern:      regexp.MustCompile(`[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`),
			Severity:     SeverityCRITICAL,
			Category:     "Cloud Provider",
			Description:  "Heroku API Key (UUID format)",
			EntropyCheck: false,
		},

		// ==================== Square ====================
		{
			Name:         "Square Access Token",
			Pattern:      regexp.MustCompile(`sq0atp-[A-Za-z0-9_-]{22}`),
			Severity:     SeverityCRITICAL,
			Category:     "Payment",
			Description:  "Square Access Token",
			EntropyCheck: false,
		},

		// ==================== PayPal ====================
		{
			Name:         "PayPal API Credentials",
			Pattern:      regexp.MustCompile(`(?i)paypal[_\-]?(?:client[_\-]?id|secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?`),
			Severity:     SeverityCRITICAL,
			Category:     "Payment",
			Description:  "PayPal API Client ID or Secret",
			EntropyCheck: false,
		},

		// ==================== Facebook ====================
		{
			Name:         "Facebook Access Token",
			Pattern:      regexp.MustCompile(`EAA[A-Za-z0-9]{50,}`),
			Severity:     SeverityCRITICAL,
			Category:     "Social",
			Description:  "Facebook Access Token",
			EntropyCheck: false,
		},

		// ==================== Twitter ====================
		{
			Name:         "Twitter API Key",
			Pattern:      regexp.MustCompile(`[A-Za-z0-9]{25}_[A-Za-z0-9]{40}`),
			Severity:     SeverityCRITICAL,
			Category:     "Social",
			Description:  "Twitter API Key and Secret",
			EntropyCheck: false,
		},

		// ==================== Discord ====================
		{
			Name:         "Discord Bot Token",
			Pattern:      regexp.MustCompile(`[A-Za-z\d]{24}\.[\w-]{6}\.[\w-]{38}`),
			Severity:     SeverityCRITICAL,
			Category:     "Messaging",
			Description:  "Discord Bot Token",
			EntropyCheck: false,
		},

		// ==================== Telegram ====================
		{
			Name:         "Telegram Bot Token",
			Pattern:      regexp.MustCompile(`\d{8,10}:[A-Za-z0-9_-]{35}`),
			Severity:     SeverityCRITICAL,
			Category:     "Messaging",
			Description:  "Telegram Bot API Token",
			EntropyCheck: false,
		},

		// ==================== OpenAI ====================
		{
			Name:         "OpenAI API Key",
			Pattern:      regexp.MustCompile(`sk-[A-Za-z0-9]{48}`),
			Severity:     SeverityCRITICAL,
			Category:     "AI/ML",
			Description:  "OpenAI API Key",
			EntropyCheck: false,
		},
		{
			Name:         "Anthropic API Key (New)",
			Pattern:      regexp.MustCompile(`sk-ant-api\d{2}-[a-zA-Z0-9\-_]{93}AA`),
			Severity:     SeverityCRITICAL,
			Category:     "AI/ML",
			Description:  "Anthropic API Key (new format)",
			EntropyCheck: false,
		},
		{
			Name:         "OpenAI API Key (New)",
			Pattern:      regexp.MustCompile(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`),
			Severity:     SeverityCRITICAL,
			Category:     "AI/ML",
			Description:  "OpenAI API Key (new format)",
			EntropyCheck: false,
		},

		// ==================== Hugging Face ====================
		{
			Name:         "Hugging Face Token",
			Pattern:      regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`),
			Severity:     SeverityCRITICAL,
			Category:     "AI/ML",
			Description:  "Hugging Face API Token",
			EntropyCheck: false,
		},

		// ==================== Google OAuth ====================
		{
			Name:         "Google OAuth2 Access Token",
			Pattern:      regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
			Severity:     SeverityCRITICAL,
			Category:     "Authentication",
			Description:  "Google OAuth2 Access Token",
			EntropyCheck: false,
		},
		{
			Name:         "Google OAuth Client ID",
			Pattern:      regexp.MustCompile(`\d{20}-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com`),
			Severity:     SeverityHIGH,
			Category:     "Authentication",
			Description:  "Google OAuth 2.0 Client ID",
			EntropyCheck: false,
		},
		{
			Name:         "Google OAuth Secret",
			Pattern:      regexp.MustCompile(`GOCSPX-[A-Za-z0-9_-]{28}`),
			Severity:     SeverityCRITICAL,
			Category:     "Authentication",
			Description:  "Google OAuth Client Secret",
			EntropyCheck: false,
		},

		// ==================== Random Secrets (Base64/ Hex) ====================
		{
			Name:         "Long Hex String (Potential Key)",
			Pattern:      regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
			Severity:     SeverityMEDIUM,
			Category:     "Potential Secret",
			Description:  "64-character hexadecimal string - could be secret key",
			EntropyCheck: true,
		},
		{
			Name:         "Long Base64 String (Potential Key)",
			Pattern:      regexp.MustCompile(`\b[A-Za-z0-9+/]{88}={0,2}\b`),
			Severity:     SeverityMEDIUM,
			Category:     "Potential Secret",
			Description:  "88+ character Base64 string - could be encoded secret",
			EntropyCheck: true,
		},

		// ==================== Hardcoded Credentials ====================
		{
			Name:         "Basic Auth Header",
			Pattern:      regexp.MustCompile(`Authorization:\s*Basic\s+[A-Za-z0-9+/]+=*`),
			Severity:     SeverityHIGH,
			Category:     "Authentication",
			Description:  "HTTP Basic Authentication header",
			EntropyCheck: false,
		},
		{
			Name:         "Basic Auth in URL",
			Pattern:      regexp.MustCompile(`https?:\/\/[^:]+:[^@]+@[^\s]+`),
			Severity:     SeverityCRITICAL,
			Category:     "Authentication",
			Description:  "Basic authentication credentials in URL",
			EntropyCheck: false,
		},
		{
			Name:         "Session Cookie",
			Pattern:      regexp.MustCompile(`(?i)(session|sess)=[A-Za-z0-9\-_\.]{20,}`),
			Severity:     SeverityMEDIUM,
			Category:     "Authentication",
			Description:  "Session cookie value",
			EntropyCheck: false,
		},
		{
			Name:         "CSRF Token",
			Pattern:      regexp.MustCompile(`(?i)csrf[_\-]?token["']?\s*[:=]\s*["']?[A-Za-z0-9\-_]{20,}`),
			Severity:     SeverityMEDIUM,
			Category:     "Authentication",
			Description:  "CSRF token",
			EntropyCheck: false,
		},
		{
			Name:         "Bearer Token",
			Pattern:      regexp.MustCompile(`(?i)Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]+`),
			Severity:     SeverityHIGH,
			Category:     "Authentication",
			Description:  "HTTP Bearer Token",
			EntropyCheck: false,
		},

		// ==================== Connection Strings ====================
		{
			Name:         "Connection String with Password",
			Pattern:      regexp.MustCompile(`(?i)(?:connection[_\-]?string|data[_\-]?source).*?(?:password|pwd)\s*[:=]\s*[^;]+`),
			Severity:     SeverityHIGH,
			Category:     "Database",
			Description:  "Connection string containing password",
			EntropyCheck: false,
		},

		// ==================== LDAP ====================
		{
			Name:         "LDAP Bind Password",
			Pattern:      regexp.MustCompile(`(?i)(?:ldap|active[_\-]?directory).*?(?:bind|admin)[_\-]?password\s*[:=]\s*[^"\']+`),
			Severity:     SeverityHIGH,
			Category:     "Authentication",
			Description:  "LDAP bind password",
			EntropyCheck: false,
		},

		// ==================== Crypto ====================
		{
			Name:         "Bitcoin/Wallet Address",
			Pattern:      regexp.MustCompile(`[13][a-km-zA-HJ-NP-Z1-9]{25,34}`),
			Severity:     SeverityHIGH,
			Category:     "Cryptocurrency",
			Description:  "Bitcoin address",
			EntropyCheck: false,
		},
		{
			Name:         "Ethereum Private Key",
			Pattern:      regexp.MustCompile(`0x[a-fA-F0-9]{64}\b`),
			Severity:     SeverityCRITICAL,
			Category:     "Cryptocurrency",
			Description:  "Ethereum private key (64 hex chars with 0x)",
			EntropyCheck: true,
		},

		// ==================== Healthcare / HIPAA ====================
		{
			Name:         "US NPI",
			Pattern:      regexp.MustCompile(`\b[0-9]{10}\b`),
			Severity:     SeverityCRITICAL,
			Category:     "Healthcare",
			Description:  "US National Provider Identifier",
			EntropyCheck: true,
		},
		{
			Name:         "DEA Number",
			Pattern:      regexp.MustCompile(`[A-Z][A-Z0-9][0-9]{7}`),
			Severity:     SeverityCRITICAL,
			Category:     "Healthcare",
			Description:  "DEA Registration Number",
			EntropyCheck: false,
		},
		{
			Name:         "ICD-10 Code",
			Pattern:      regexp.MustCompile(`[A-TV-Z][0-9][A-Z0-9](\.[A-Z0-9]{1,4})?`),
			Severity:     SeverityLOW,
			Category:     "Healthcare",
			Description:  "ICD-10 Diagnosis Code",
			EntropyCheck: false,
		},
		{
			Name:         "BHYT (Vietnam)",
			Pattern:      regexp.MustCompile(`[A-Z]{2}\d{13}`),
			Severity:     SeverityCRITICAL,
			Category:     "Healthcare",
			Description:  "Vietnam Health Insurance Number (BHYT)",
			EntropyCheck: false,
		},

		// ==================== Infrastructure / DevOps ====================
		{
			Name:         "Firebase Database URL",
			Pattern:      regexp.MustCompile(`[a-z0-9\-]+\.firebaseio\.com`),
			Severity:     SeverityMEDIUM,
			Category:     "Infrastructure",
			Description:  "Firebase Realtime Database URL",
			EntropyCheck: false,
		},
		{
			Name:         "AWS S3 Bucket URL",
			Pattern:      regexp.MustCompile(`s3\.amazonaws\.com\/[a-z0-9\-\.]+`),
			Severity:     SeverityMEDIUM,
			Category:     "Infrastructure",
			Description:  "AWS S3 Bucket URL",
			EntropyCheck: false,
		},

		// ==================== Bouncy Castle ====================
		{
			Name:         "BCrypt Hash",
			Pattern:      regexp.MustCompile(`\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}`),
			Severity:     SeverityMEDIUM,
			Category:     "Hash",
			Description:  "BCrypt password hash",
			EntropyCheck: false,
		},
		{
			Name:         "Argon2 Hash",
			Pattern:      regexp.MustCompile(`\$argon2(i|d|id)\$[mdt]=(?:iterations|memory|parallelism)\$\d+\$\d+\$[a-zA-Z0-9+/]+`),
			Severity:     SeverityMEDIUM,
			Category:     "Hash",
			Description:  "Argon2 password hash",
			EntropyCheck: false,
		},
	}

	r.compiled = true
}

// GetPatterns returns patterns at or above a severity level.
func (r *PatternRegistry) GetPatterns(minSeverity Severity) []SecretPattern {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.compiled {
		r.mu.RUnlock()
		r.compilePatterns()
		r.mu.RLock()
	}

	minLevel := SeverityOrder[minSeverity]
	var result []SecretPattern
	for _, p := range r.patterns {
		if SeverityOrder[p.Severity] <= minLevel {
			result = append(result, p)
		}
	}
	return result
}

// GetPatternsByCategory returns patterns by category.
func (r *PatternRegistry) GetPatternsByCategory(category string) []SecretPattern {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.compiled {
		r.mu.RUnlock()
		r.compilePatterns()
		r.mu.RLock()
	}

	var result []SecretPattern
	for _, p := range r.patterns {
		if p.Category == category {
			result = append(result, p)
		}
	}
	return result
}

// GetAllPatterns returns all compiled patterns.
func (r *PatternRegistry) GetAllPatterns() []SecretPattern {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.compiled {
		r.mu.RUnlock()
		r.compilePatterns()
		r.mu.RLock()
	}

	result := make([]SecretPattern, len(r.patterns))
	copy(result, r.patterns)
	return result
}

// GetCategoryCounts returns count of patterns per category.
func (r *PatternRegistry) GetCategoryCounts() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if !r.compiled {
		r.mu.RUnlock()
		r.compilePatterns()
		r.mu.RLock()
	}

	counts := make(map[string]int)
	for _, p := range r.patterns {
		counts[p.Category]++
	}
	return counts
}
