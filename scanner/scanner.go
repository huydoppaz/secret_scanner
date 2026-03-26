// Package scanner provides multi-threaded file scanning for fast secret detection.
// Optimized for speed with parallel processing.
package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"secrets_scanner/detector"
	"secrets_scanner/patterns"
)

// ScanStatus represents the scan status.
type ScanStatus string

const (
	ScanStatusPENDING   ScanStatus = "pending"
	ScanStatusRUNNING   ScanStatus = "running"
	ScanStatusCOMPLETED ScanStatus = "completed"
	ScanStatusFAILED    ScanStatus = "failed"
)

// ScannableExtensions contains file extensions to scan.
var ScannableExtensions = map[string]bool{
	// Code files
	".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".java": true, ".go": true, ".rs": true, ".rb": true, ".php": true,
	".cs": true, ".cpp": true, ".c": true, ".h": true, ".swift": true, ".kt": true,
	// Config files
	".json": true, ".yaml": true, ".yml": true, ".xml": true, ".toml": true,
	".ini": true, ".cfg": true, ".conf": true, ".config": true,
	".properties": true, ".env": true, ".env.example": true,
	// Shell scripts
	".sh": true, ".bash": true, ".zsh": true, ".fish": true,
	".ps1": true, ".bat": true, ".cmd": true,
	// SQL
	".sql": true, ".gradle": true, ".sbt": true, ".mk": true, ".cmake": true,
}

// ExcludedDirs contains directories to skip.
var ExcludedDirs = map[string]bool{
	"node_modules": true, ".git": true, ".svn": true, ".hg": true,
	"__pycache__": true, ".pytest_cache": true, ".mypy_cache": true,
	".venv": true, "venv": true, "env": true, ".env": true,
	"dist": true, "build": true, "out": true, "target": true, "bin": true, "obj": true,
	".idea": true, ".vscode": true, ".settings": true,
	"coverage": true, ".nyc_output": true, ".grunt": true,
	"bower_components": true, "vendor": true, "packages": true,
}

// ScanResult represents the result of a secrets scan.
type ScanResult struct {
	mu                sync.RWMutex
	Status            ScanStatus               `json:"status"`
	Findings          []map[string]interface{} `json:"findings"`
	FilesScanned      int                      `json:"files_scanned"`
	FilesWithSecrets  int                      `json:"files_with_secrets"`
	ScanDuration      float64                  `json:"scan_duration"`
	Errors            []string                 `json:"errors"`
	StartedAt         string                   `json:"started_at"`
	CompletedAt       string                   `json:"completed_at"`
	filesWithSecretsMap map[string]bool
}

// NewScanResult creates a new ScanResult.
func NewScanResult() *ScanResult {
	return &ScanResult{
		Status:              ScanStatusPENDING,
		Findings:            make([]map[string]interface{}, 0),
		Errors:              make([]string, 0),
		filesWithSecretsMap: make(map[string]bool),
	}
}

// AddFinding adds a finding to the result (thread-safe).
func (r *ScanResult) AddFinding(finding map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, finding)
}

// AddError adds an error to the result (thread-safe).
func (r *ScanResult) AddError(err string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Errors = append(r.Errors, err)
}

// IncrementFilesScanned increments the files scanned count (thread-safe).
func (r *ScanResult) IncrementFilesScanned() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.FilesScanned++
}

// MarkFileWithSecrets marks a file as having secrets (thread-safe).
func (r *ScanResult) MarkFileWithSecrets(filePath string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.filesWithSecretsMap[filePath] {
		r.filesWithSecretsMap[filePath] = true
		r.FilesWithSecrets++
	}
}

// ToDict converts the result to a map.
func (r *ScanResult) ToDict() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return map[string]interface{}{
		"status":              r.Status,
		"findings":            r.Findings,
		"files_scanned":       r.FilesScanned,
		"files_with_secrets":  r.FilesWithSecrets,
		"scan_duration":       fmt.Sprintf("%.2fs", r.ScanDuration),
		"errors":              r.Errors,
		"started_at":          r.StartedAt,
		"completed_at":        r.CompletedAt,
	}
}

// GetSummary returns summary statistics.
func (r *ScanResult) GetSummary() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	bySeverity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	byCategory := make(map[string]int)

	for _, f := range r.Findings {
		if severity, ok := f["severity"].(string); ok {
			bySeverity[severity]++
		}
		if category, ok := f["category"].(string); ok {
			byCategory[category]++
		}
	}

	return map[string]interface{}{
		"total":       len(r.Findings),
		"by_severity": bySeverity,
		"by_category": byCategory,
	}
}

// SecretsScanner is a multi-threaded secrets scanner.
//
// Optimizations:
// - Worker pool for parallel file scanning
// - Early file filtering (extension, binary check)
// - Progress callbacks
// - Configurable concurrency
type SecretsScanner struct {
	minSeverity  patterns.Severity
	maxWorkers   int
	maxFileSize  int64
	extensions   map[string]bool
	excludeDirs  map[string]bool
	detector     *detector.SecretDetector

	// Callbacks
	OnProgress      func(scanned, total int, currentFile string)
	OnFileComplete  func(filePath string, findingsCount int)
}

// NewSecretsScanner creates a new SecretsScanner.
//
// Args:
//   - minSeverity: Minimum severity to detect
//   - maxWorkers: Number of worker threads (0 = auto = CPU cores)
//   - maxFileSize: Maximum file size to scan (bytes)
//   - extensions: File extensions to scan (nil = default)
//   - excludeDirs: Directories to exclude (nil = default)
func NewSecretsScanner(
	minSeverity patterns.Severity,
	maxWorkers int,
	maxFileSize int64,
	extensions map[string]bool,
	excludeDirs map[string]bool,
) *SecretsScanner {
	// Auto-detect optimal workers based on CPU cores
	if maxWorkers <= 0 {
		maxWorkers = runtime.NumCPU()
		if maxWorkers < 4 {
			maxWorkers = 4
		}
	}
	if maxFileSize <= 0 {
		maxFileSize = 10 * 1024 * 1024 // 10MB
	}
	if extensions == nil {
		extensions = ScannableExtensions
	}
	if excludeDirs == nil {
		excludeDirs = ExcludedDirs
	}

	return &SecretsScanner{
		minSeverity: minSeverity,
		maxWorkers:  maxWorkers,
		maxFileSize: maxFileSize,
		extensions:  extensions,
		excludeDirs: excludeDirs,
		detector:    detector.NewSecretDetector(minSeverity),
	}
}

// ScanPath scans a directory or file for secrets with MAX SPEED optimization.
//
// Args:
//   - path: Directory or file path to scan
//
// Returns:
//   - ScanResult with all findings
func (s *SecretsScanner) ScanPath(path string) *ScanResult {
	startTime := time.Now()

	result := NewScanResult()
	result.Status = ScanStatusRUNNING
	result.StartedAt = startTime.Format(time.RFC3339)

	// Check if path is a single file
	info, err := os.Stat(path)
	if err != nil {
		result.Status = ScanStatusFAILED
		result.AddError(err.Error())
		return result
	}

	// Handle single file case
	if !info.IsDir() {
		if s.shouldScanFile(path) {
			findings := s.scanFile(path)
			result.IncrementFilesScanned()
			if len(findings) > 0 {
				result.MarkFileWithSecrets(path)
				for _, f := range findings {
					result.AddFinding(f.ToDict())
				}
			}
		}
		result.Status = ScanStatusCOMPLETED
		result.CompletedAt = time.Now().Format(time.RFC3339)
		result.ScanDuration = time.Since(startTime).Seconds()
		return result
	}

	// MAX SPEED: Stream files concurrently while walking
	fileChan := make(chan string, s.maxWorkers*4) // Buffered channel
	doneChan := make(chan struct{})
	var totalFiles int64

	// Start file walker goroutine
	go func() {
		defer close(fileChan)
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if s.excludeDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if s.shouldScanFile(p) {
				atomic.AddInt64(&totalFiles, 1)
				fileChan <- p
			}
			return nil
		})
	}()

	// Start workers with atomic counters for max speed
	var wg sync.WaitGroup
	var scannedCount int64
	workers := s.maxWorkers

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {
				findings := s.scanFile(filePath)
				count := atomic.AddInt64(&scannedCount, 1)

				if len(findings) > 0 {
					result.MarkFileWithSecrets(filePath)
					for _, f := range findings {
						result.AddFinding(f.ToDict())
					}
				}

				// Callbacks (throttled)
				if s.OnFileComplete != nil {
					s.OnFileComplete(filePath, len(findings))
				}
				if s.OnProgress != nil && count%100 == 0 {
					total := int(atomic.LoadInt64(&totalFiles))
					s.OnProgress(int(count), total, filePath)
				}
			}
		}()
	}

	// Wait for completion
	wg.Wait()
	close(doneChan)

	// Update result
	result.Status = ScanStatusCOMPLETED
	result.CompletedAt = time.Now().Format(time.RFC3339)
	result.ScanDuration = time.Since(startTime).Seconds()

	return result
}

// collectFiles collects files to scan from path (used for pre-counting).
func (s *SecretsScanner) collectFiles(path string) ([]string, error) {
	var files []string

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if s.excludeDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if s.shouldScanFile(p) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		if s.shouldScanFile(path) {
			files = append(files, path)
		}
	}

	return files, nil
}

// shouldScanFile checks if file should be scanned.
func (s *SecretsScanner) shouldScanFile(path string) bool {
	// Check directory exclusion
	dir := filepath.Dir(path)
	for {
		if dir == "." || dir == "/" || dir == filepath.VolumeName(dir)+string(os.PathSeparator) {
			break
		}
		base := filepath.Base(dir)
		if s.excludeDirs[base] {
			return false
		}
		dir = filepath.Dir(dir)
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(path))
	if s.extensions[ext] {
		return true
	}

	// Check for config files without extension
	base := filepath.Base(path)
	specialFiles := map[string]bool{
		".env":                true,
		".gitignore":          true,
		".dockerignore":       true,
		"Makefile":            true,
		"Dockerfile":          true,
		"docker-compose.yml":  true,
		"docker-compose.yaml": true,
	}
	if specialFiles[base] {
		return true
	}

	return false
}

// scanFile scans a single file for secrets.
func (s *SecretsScanner) scanFile(filePath string) []detector.SecretFinding {
	// Size check
	info, err := os.Stat(filePath)
	if err != nil {
		return nil
	}
	if info.Size() > s.maxFileSize {
		return nil
	}

	// Quick binary check
	if s.isBinaryFile(filePath) {
		return nil
	}

	// Read content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	// Detect secrets
	findings := s.detector.DetectInContent(string(content), filePath)
	return findings
}

// isBinaryFile checks if file is binary.
func (s *SecretsScanner) isBinaryFile(path string) bool {
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

// ScanDirectory is a quick scan function for CLI use.
//
// Args:
//   - directory: Directory to scan
//   - minSeverityStr: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
//   - maxWorkers: Number of threads
//
// Returns:
//   - ScanResult
func ScanDirectory(directory string, minSeverityStr string, maxWorkers int) *ScanResult {
	severityMap := map[string]patterns.Severity{
		"CRITICAL": patterns.SeverityCRITICAL,
		"HIGH":     patterns.SeverityHIGH,
		"MEDIUM":   patterns.SeverityMEDIUM,
		"LOW":      patterns.SeverityLOW,
	}

	severity := severityMap[strings.ToUpper(minSeverityStr)]
	if severity == "" {
		severity = patterns.SeverityHIGH
	}

	scanner := NewSecretsScanner(severity, maxWorkers, 0, nil, nil)
	return scanner.ScanPath(directory)
}
