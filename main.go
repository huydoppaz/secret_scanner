// Secrets Scanner
//
// Fast regex-based secret detection in source code and config files.
// Converted from Python to Go for better performance.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"

	"secrets_scanner/detector"
	"secrets_scanner/patterns"
	"secrets_scanner/scanner"
)

func main() {
	var (
		path         = flag.String("path", ".", "Directory or file path to scan")
		minSeverity  = flag.String("severity", "HIGH", "Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)")
		workers      = flag.Int("workers", 8, "Number of worker threads")
		jsonOutput   = flag.Bool("json", false, "Output results as JSON")
		showSummary  = flag.Bool("summary", true, "Show summary statistics")
		listPatterns = flag.Bool("patterns", false, "List all detection patterns")
		includeExts  = flag.String("include-ext", "", "Comma-separated file extensions to include (e.g., '.go,.js,.py')")
		excludeExts  = flag.String("exclude-ext", "", "Comma-separated file extensions to exclude (e.g., '.log,.tmp')")
		showHelp     = flag.Bool("help", false, "Show detailed help information")
	)
	flag.Parse()

	// Show detailed help
	if *showHelp {
		printDetailedHelp()
		return
	}

	// List patterns mode
	if *listPatterns {
		printPatterns()
		return
	}

	// Validate path
	absPath, err := filepath.Abs(*path)
	if err != nil {
		color.Red("Error: Invalid path: %v", err)
		os.Exit(1)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		color.Red("Error: Path does not exist: %s", absPath)
		os.Exit(1)
	}

	// Parse severity
	severity := parseSeverity(*minSeverity)

	// Parse extensions
	extensions := buildExtensions(*includeExts, *excludeExts)

	// Print scan info
	if !*jsonOutput {
		printBanner()
		color.Cyan("📁 Scanning: %s", absPath)
		color.Cyan("🔍 Minimum severity: %s", *minSeverity)
		color.Cyan("🧵 Workers: %d", *workers)
		if *includeExts != "" {
			color.Cyan("📎 Include extensions: %s", *includeExts)
		}
		if *excludeExts != "" {
			color.Cyan("🚫 Exclude extensions: %s", *excludeExts)
		}
		fmt.Println()
	}

	// Create scanner with custom extensions
	s := scanner.NewSecretsScanner(severity, *workers, 0, extensions, nil)

	// Set up progress callback for non-JSON mode
	if !*jsonOutput {
		s.OnProgress = func(scanned, total int, currentFile string) {
			if scanned%100 == 0 || scanned == total {
				percent := float64(scanned) * 100 / float64(total)
				color.Yellow("Progress: %d/%d (%.1f%%)", scanned, total, percent)
			}
		}
	}

	// Run scan
	result := s.ScanPath(absPath)

	// Output results
	if *jsonOutput {
		outputJSON(result)
	} else {
		outputText(result, *showSummary)
	}

	// Exit with error code if secrets found
	if len(result.Findings) > 0 {
		os.Exit(1)
	}
}

func printBanner() {
	banner := `
   _____                 _                 
  / ___/____  ____ ___  (_) /_____  __  __ 
  \__ \/ __ \/ __  / / / / __/ __ \/ / / /
 ___/ / /_/ / /_/ / /_/ / /_/ /_/ / /_/ / 
/____/ .___/\__,_/\__,_/\__/\____/\__,_/  
    /_/                                    
`
	color.Green(banner)
	color.Yellow("🔐 Fast Secret Detection Scanner - Go Edition")
	fmt.Println()
}

func parseSeverity(s string) patterns.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return patterns.SeverityCRITICAL
	case "HIGH":
		return patterns.SeverityHIGH
	case "MEDIUM":
		return patterns.SeverityMEDIUM
	case "LOW":
		return patterns.SeverityLOW
	default:
		return patterns.SeverityHIGH
	}
}

func outputJSON(result *scanner.ScanResult) {
	output := map[string]interface{}{
		"status":             result.Status,
		"findings":           result.Findings,
		"files_scanned":      result.FilesScanned,
		"files_with_secrets": result.FilesWithSecrets,
		"scan_duration":      result.ScanDuration,
		"errors":             result.Errors,
		"started_at":         result.StartedAt,
		"completed_at":       result.CompletedAt,
		"summary":            result.GetSummary(),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(output)
}

func outputText(result *scanner.ScanResult, showSummary bool) {
	// Print findings
	if len(result.Findings) == 0 {
		color.Green("✅ No secrets detected!")
	} else {
		color.Red("\n🚨 Found %d potential secret(s):\n", len(result.Findings))

		for i, finding := range result.Findings {
			printFinding(i+1, finding)
		}
	}

	// Print summary
	if showSummary {
		summary := result.GetSummary()
		fmt.Println()
		color.Cyan("📊 Scan Summary:")
		color.White("  Files scanned: %d", result.FilesScanned)
		color.White("  Files with secrets: %d", result.FilesWithSecrets)
		color.White("  Duration: %.2fs", result.ScanDuration)

		if total, ok := summary["total"].(int); ok && total > 0 {
			fmt.Println()
			color.Cyan("  Findings by Severity:")
			if bySev, ok := summary["by_severity"].(map[string]int); ok {
				for sev, count := range bySev {
					if count > 0 {
						colorFunc := getSeverityColor(sev)
						colorFunc("    %s: %d", strings.ToUpper(sev), count)
					}
				}
			}

			fmt.Println()
			color.Cyan("  Findings by Category:")
			if byCat, ok := summary["by_category"].(map[string]int); ok {
				for cat, count := range byCat {
					color.White("    %s: %d", cat, count)
				}
			}
		}
	}

	// Print errors if any
	if len(result.Errors) > 0 {
		fmt.Println()
		color.Yellow("⚠️  Errors (%d):", len(result.Errors))
		for _, err := range result.Errors {
			color.Yellow("  - %s", err)
		}
	}

	fmt.Println()
}

func printFinding(index int, finding map[string]interface{}) {
	severity, _ := finding["severity"].(string)
	colorFunc := getSeverityColor(severity)

	fmt.Println(strings.Repeat("─", 70))
	colorFunc("[%d] %s", index, finding["pattern"])
	colorFunc("    Severity: %s", severity)
	color.White("    Category: %s", finding["category"])
	color.White("    File: %s:%v", finding["file"], finding["line"])
	color.White("    Description: %s", finding["description"])
	if matched, ok := finding["matched_value"].(string); ok {
		color.White("    Value: %s", matched)
	}
	if line, ok := finding["line_content"].(string); ok && line != "" {
		color.White("    Line: %s", strings.TrimSpace(line))
	}
	fmt.Println()
}

func getSeverityColor(severity string) func(format string, a ...interface{}) {
	switch strings.ToLower(severity) {
	case "critical":
		return color.Red
	case "high":
		return color.HiRed
	case "medium":
		return color.Yellow
	case "low":
		return color.Blue
	default:
		return color.White
	}
}

func printPatterns() {
	registry := patterns.GetRegistry()
	allPatterns := registry.GetAllPatterns()
	categories := registry.GetCategoryCounts()

	printBanner()
	color.Cyan("📋 Detection Patterns (%d total)\n", len(allPatterns))

	// Group by category
	byCategory := make(map[string][]patterns.SecretPattern)
	for _, p := range allPatterns {
		byCategory[p.Category] = append(byCategory[p.Category], p)
	}

	for cat, count := range categories {
		color.HiCyan("\n%s (%d patterns):", cat, count)
		for _, p := range byCategory[cat] {
			colorFunc := getSeverityColor(string(p.Severity))
			colorFunc("  • %s [%s]", p.Name, p.Severity)
			color.White("    %s", p.Description)
		}
	}
}

// Helper function for quick detection
func detectInContent(content string, filePath string) []map[string]interface{} {
	return detector.DetectSecretsFast(content, filePath, patterns.SeverityHIGH)
}

// printDetailedHelp prints comprehensive help information
func printDetailedHelp() {
	fmt.Println(`
SECRETS SCANNER - Fast Secret Detection Tool
=============================================

DESCRIPTION:
  A high-performance Go-based tool for detecting secrets, API keys, passwords,
  and sensitive data in source code and configuration files.

USAGE:
  secrets-scanner [INPUT_OPTIONS] [FILTER_OPTIONS] [OUTPUT_OPTIONS]

═══════════════════════════════════════════════════════════════════
INPUT OPTIONS
═══════════════════════════════════════════════════════════════════

  -path string
      Directory or file path to scan
      Default: "." (current directory)
      Examples:
        -path ./src
        -path /var/www/app
        -path config.yaml
        -path ./main.go

═══════════════════════════════════════════════════════════════════
FILTER OPTIONS (File Extensions)
═══════════════════════════════════════════════════════════════════

  -include-ext string
      Scan ONLY these file extensions (comma-separated)
      This OVERRIDES the default extension list
      Examples:
        -include-ext ".go"              # Scan only Go files
        -include-ext ".go,.js,.py"      # Scan Go, JS, Python files
        -include-ext ".yaml,.yml,.json" # Scan config files

  -exclude-ext string
      SKIP these file extensions (comma-separated)
      Removes from default list or from -include-ext list
      Examples:
        -exclude-ext ".log"                  # Skip log files
        -exclude-ext ".log,.tmp,.md"         # Skip logs, temp, markdown
        -exclude-ext "_test.go,.test.js"     # Skip test files

  DEFAULT EXTENSIONS (used when -include-ext not specified):
    Code:     .py, .js, .ts, .java, .go, .rs, .php, .cs, .cpp, .c
    Config:   .json, .yaml, .yml, .xml, .env, .properties
    Scripts:  .sh, .bash, .ps1, .sql
    Others:   Dockerfile, Makefile, .env

═══════════════════════════════════════════════════════════════════
SCAN OPTIONS
═══════════════════════════════════════════════════════════════════

  -severity string
      Minimum severity level to report
      Values: CRITICAL, HIGH, MEDIUM, LOW
      Default: "HIGH"
      Example: -severity CRITICAL

  -workers int
      Number of concurrent worker threads
      Default: 8
      Set to 0 for auto-detect (CPU cores)
      Example: -workers 16

  -patterns
      List all 100+ detection patterns and exit
      Example: -patterns

═══════════════════════════════════════════════════════════════════
OUTPUT OPTIONS
═══════════════════════════════════════════════════════════════════

  -json
      Output results in JSON format (default: pretty text)
      Useful for CI/CD integration and scripting
      Example: -json > secrets-report.json

  -summary
      Show summary statistics (default: true)
      Use -summary=false to disable
      Example: -summary=false

═══════════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════

CONSOLE OUTPUT includes:
  • Scan progress with file count and percentage
  • Each finding with:
      - Pattern name (e.g., "AWS Access Key ID")
      - Severity level (CRITICAL/HIGH/MEDIUM/LOW)
      - Category (Cloud Provider, API Key, etc.)
      - File path and line number
      - Description of the secret type
      - Masked value (****) for security
  • Summary statistics:
      - Total files scanned
      - Files with secrets
      - Count by severity level
      - Count by category
      - Scan duration

JSON OUTPUT STRUCTURE:
  {
    "status": "completed",
    "findings": [
      {
        "pattern": "AWS Access Key ID",
        "severity": "critical",
        "category": "Cloud Provider",
        "file": "/path/to/file.go",
        "line": 42,
        "matched_value": "AKIA****EXAMPLE",
        "description": "AWS Access Key ID"
      }
    ],
    "files_scanned": 150,
    "files_with_secrets": 5,
    "scan_duration": 2.35,
    "summary": {
      "total": 12,
      "by_severity": {
        "critical": 2,
        "high": 5,
        "medium": 3,
        "low": 2
      },
      "by_category": {
        "Cloud Provider": 3,
        "API Key": 2,
        ...
      }
    }
  }

═══════════════════════════════════════════════════════════════════
EXIT CODES
═══════════════════════════════════════════════════════════════════

  0  No secrets detected (success)
  1  Secrets detected OR error occurred

═══════════════════════════════════════════════════════════════════
EXAMPLES
═══════════════════════════════════════════════════════════════════

  Basic scan of current directory:
    ./secrets-scanner

  Scan specific directory:
    ./secrets-scanner -path ./src

  Scan only Go files:
    ./secrets-scanner -include-ext ".go"

  Scan all code except test files:
    ./secrets-scanner -exclude-ext "_test.go,.test.js,.spec.ts"

  Scan config files only:
    ./secrets-scanner -include-ext ".yaml,.yml,.json,.env"

  High severity + JSON output for CI/CD:
    ./secrets-scanner -path . -severity HIGH -json > report.json

  Maximum performance (all CPU cores):
    ./secrets-scanner -workers 0 -severity LOW

  Scan specific file:
    ./secrets-scanner -path ./config/database.yml

═══════════════════════════════════════════════════════════════════
SUPPORTED DETECTION CATEGORIES (100+ Patterns)
═══════════════════════════════════════════════════════════════════

  PII              - Email, Phone (US/VN), SSN, CMND/CCCD, MAC, IPv4/IPv6
  Finance          - Visa, Mastercard, Amex, IBAN, Bitcoin, Ethereum
  Cloud            - AWS (AKIA/ASIA), Azure, GCP, DigitalOcean, Heroku
  Source Control   - GitHub (ghp/gho/ghu/ghs), GitLab
  Cryptographic    - RSA, EC, DSA, PGP, SSH, PKCS#8, X.509 keys
  Payment          - Stripe, PayPal, Square
  Messaging        - Slack, Discord, Telegram, Twilio
  AI/ML            - OpenAI, Anthropic, Hugging Face
  Healthcare       - NPI, DEA, ICD-10, BHYT (Vietnam)
  Database         - MySQL, PostgreSQL, MongoDB, Redis, SQL Server
  Infrastructure   - Firebase, AWS S3

═══════════════════════════════════════════════════════════════════

For more information: https://github.com/yourusername/secrets-scanner
`)
}

// buildExtensions builds the extension map from include/exclude flags
func buildExtensions(include, exclude string) map[string]bool {
	// Start with default extensions
	extensions := make(map[string]bool)

	// If include is specified, use only those extensions
	if include != "" {
		for _, ext := range strings.Split(include, ",") {
			ext := strings.TrimSpace(ext)
			if ext != "" {
				// Ensure extension starts with .
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				extensions[strings.ToLower(ext)] = true
			}
		}
	} else {
		// Use default extensions
		extensions = scanner.ScannableExtensions
	}

	// Remove excluded extensions
	if exclude != "" {
		for _, ext := range strings.Split(exclude, ",") {
			ext := strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				delete(extensions, strings.ToLower(ext))
			}
		}
	}

	return extensions
}
