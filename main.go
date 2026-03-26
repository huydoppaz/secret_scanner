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
	)
	flag.Parse()

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
