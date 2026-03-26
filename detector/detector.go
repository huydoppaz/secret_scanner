// Package detector provides fast multi-pattern matching engine for secret detection.
// Optimized for speed with pre-compiled patterns.
package detector

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strings"

	"secrets_scanner/patterns"
)

// SecretFinding represents a detected secret.
type SecretFinding struct {
	PatternName   string `json:"pattern"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	Description   string `json:"description"`
	FilePath      string `json:"file"`
	LineNumber    int    `json:"line"`
	LineContent   string `json:"line_content"`
	MatchStart    int    `json:"match_start"`
	MatchEnd      int    `json:"match_end"`
	MatchedValue  string `json:"matched_value"`
	Confidence    string `json:"confidence"`
}

// MaskedValue returns the masked secret value.
func (f *SecretFinding) MaskedValue() string {
	value := f.MatchedValue
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// ToDict converts the finding to a map.
func (f *SecretFinding) ToDict() map[string]interface{} {
	return map[string]interface{}{
		"pattern":       f.PatternName,
		"severity":      f.Severity,
		"category":      f.Category,
		"description":   f.Description,
		"file":          f.FilePath,
		"line":          f.LineNumber,
		"line_content":  f.LineContent,
		"position":      f.PositionString(),
		"matched_value": f.MaskedValue(),
		"confidence":    f.Confidence,
	}
}

// PositionString returns the position as a string.
func (f *SecretFinding) PositionString() string {
	return ""
}

// SecretDetector is a fast secret detector using pre-compiled regex patterns.
//
// Optimizations:
// - Pre-compiled patterns (done once at startup)
// - Single pass through file content
// - Early termination for binary files
// - Match position tracking
type SecretDetector struct {
	minSeverity patterns.Severity
	patterns    []patterns.SecretPattern
	compiled    bool
}

// NewSecretDetector creates a new SecretDetector.
//
// Args:
//   - minSeverity: Minimum severity level to detect
func NewSecretDetector(minSeverity patterns.Severity) *SecretDetector {
	registry := patterns.GetRegistry()
	return &SecretDetector{
		minSeverity: minSeverity,
		patterns:    registry.GetPatterns(minSeverity),
		compiled:    true,
	}
}

// DetectInContent detects secrets in file content.
//
// Args:
//   - content: File content to scan
//   - filePath: Path to the file (for reporting)
//
// Returns:
//   - List of findings
func (d *SecretDetector) DetectInContent(content string, filePath string) []SecretFinding {
	var findings []SecretFinding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Skip empty lines for performance
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		// Skip common false positive patterns
		if d.isFalsePositive(line) {
			continue
		}

		// Scan line with all patterns
		for _, pattern := range d.patterns {
			matches := pattern.Pattern.FindAllStringIndex(line, -1)

			for _, match := range matches {
				matchedValue := line[match[0]:match[1]]

				// Validate match quality
				if d.validateMatch(matchedValue, pattern) {
					finding := SecretFinding{
						PatternName:  pattern.Name,
						Severity:     string(pattern.Severity),
						Category:     pattern.Category,
						Description:  pattern.Description,
						FilePath:     filePath,
						LineNumber:   lineNum + 1,
						LineContent:  strings.TrimRight(line, "\r\n"),
						MatchStart:   match[0],
						MatchEnd:     match[1],
						MatchedValue: matchedValue,
						Confidence:   d.getConfidence(pattern.Severity),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// DetectInFile detects secrets in a single file.
//
// Args:
//   - filePath: Path to file
//
// Returns:
//   - List of findings
func (d *SecretDetector) DetectInFile(filePath string) []SecretFinding {
	// Quick binary check
	if d.isBinary(filePath) {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	return d.DetectInContent(string(content), filePath)
}

// isBinary checks if file is binary (quick check).
func (d *SecretDetector) isBinary(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()

	buf := make([]byte, 8192)
	n, err := file.Read(buf)
	if err != nil {
		return true
	}

	for i := 0; i < n; i++ {
		if buf[i] == 0x00 {
			return true
		}
	}
	return false
}

// isFalsePositive checks if line is likely a false positive.
func (d *SecretDetector) isFalsePositive(line string) bool {
	// Skip comment-only lines with generic patterns
	stripped := strings.TrimSpace(line)

	// Skip if it's just an example/documentation
	falsePositiveStarts := []string{
		"example", "example.com", "localhost",
		"your_", "your-", "<", "{", "[{", "# example",
		"// TODO", "# TODO", "<!--",
	}

	for _, fp := range falsePositiveStarts {
		if strings.HasPrefix(stripped, fp) {
			return true
		}
	}

	// Skip very short lines
	if len(stripped) < 10 {
		return true
	}

	return false
}

// validateMatch validates that a match is likely a real secret.
func (d *SecretDetector) validateMatch(value string, pattern patterns.SecretPattern) bool {
	// Skip if value looks like placeholder
	placeholders := []string{"XXX", "***", "###", "...", "CHANGE_ME", "REPLACE_ME", "YOUR_"}
	upperValue := strings.ToUpper(value)
	for _, p := range placeholders {
		if strings.Contains(upperValue, p) {
			return false
		}
	}

	// Check minimum entropy for random-looking secrets
	if pattern.EntropyCheck {
		entropy := calculateEntropy(value)
		if entropy < 3.5 { // Low entropy = likely not random
			return false
		}
	}

	return true
}

// calculateEntropy calculates Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		prob := float64(count) / length
		if prob > 0 {
			entropy -= prob * math.Log2(prob)
		}
	}

	return entropy
}

// getConfidence returns confidence level based on severity.
func (d *SecretDetector) getConfidence(severity patterns.Severity) string {
	confidenceMap := map[patterns.Severity]string{
		patterns.SeverityCRITICAL: "high",
		patterns.SeverityHIGH:     "high",
		patterns.SeverityMEDIUM:   "medium",
		patterns.SeverityLOW:      "low",
	}
	if conf, ok := confidenceMap[severity]; ok {
		return conf
	}
	return "medium"
}

// DetectSecretsFast is a fast helper function for secret detection.
//
// Args:
//   - content: File content
//   - filePath: File path
//   - minSeverity: Minimum severity
//
// Returns:
//   - List of finding dicts
func DetectSecretsFast(content string, filePath string, minSeverity patterns.Severity) []map[string]interface{} {
	detector := NewSecretDetector(minSeverity)
	findings := detector.DetectInContent(content, filePath)

	result := make([]map[string]interface{}, len(findings))
	for i, f := range findings {
		result[i] = f.ToDict()
	}
	return result
}

// DetectSecretsInFile is a helper function to detect secrets in a file.
func DetectSecretsInFile(filePath string, minSeverity patterns.Severity) []map[string]interface{} {
	detector := NewSecretDetector(minSeverity)
	findings := detector.DetectInFile(filePath)

	result := make([]map[string]interface{}, len(findings))
	for i, f := range findings {
		result[i] = f.ToDict()
	}
	return result
}

// ScanFile scans a single file and returns findings.
func ScanFile(filePath string, minSeverity patterns.Severity, maxFileSize int64) []SecretFinding {
	// Check file size
	info, err := os.Stat(filePath)
	if err != nil {
		return nil
	}
	if info.Size() > maxFileSize {
		return nil
	}

	detector := NewSecretDetector(minSeverity)
	return detector.DetectInFile(filePath)
}

// IsBinaryFile checks if a file is binary.
func IsBinaryFile(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 8192), 8192)
	
	if scanner.Scan() {
		chunk := scanner.Bytes()
		for _, b := range chunk {
			if b == 0x00 {
				return true
			}
		}
	}
	return false
}

// ShouldScanFile checks if file should be scanned.
func ShouldScanFile(path string, extensions map[string]bool, excludeDirs map[string]bool) bool {
	// Check directory exclusion
	dir := filepath.Dir(path)
	for {
		if dir == "." || dir == "/" {
			break
		}
		base := filepath.Base(dir)
		if excludeDirs[base] {
			return false
		}
		dir = filepath.Dir(dir)
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(path))
	if extensions[ext] {
		return true
	}

	// Check for config files without extension
	base := filepath.Base(path)
	specialFiles := map[string]bool{
		".env":           true,
		".gitignore":     true,
		".dockerignore":  true,
		"Makefile":       true,
		"Dockerfile":     true,
		"docker-compose.yml": true,
		"docker-compose.yaml": true,
	}
	if specialFiles[base] {
		return true
	}

	return false
}
