# Secrets Scanner - Go Edition

Fast regex-based secret detection in source code and config files. Converted from Python to Go for better performance and concurrency.

## Features

- 🔍 **100+ Detection Patterns** - PII, Finance, Cloud keys, API tokens, Private keys, Healthcare data, etc.
- ⚡ **MAX SPEED** - Auto-detected workers (CPU cores), streaming file discovery, lock-free counters
- 🎯 **Configurable Severity** - CRITICAL, HIGH, MEDIUM, LOW levels
- 📊 **Rich Output** - Text and JSON output formats with detailed summaries
- 🚀 **Single Binary** - Cross-platform compilation, no dependencies
- 🌍 **Vietnam Support** - CMND/CCCD, BHYT, Vietnam phone numbers

## Detection Categories

| Category | Count | Examples |
|----------|-------|----------|
| PII | 8 | Email, Phone, SSN, CMND/CCCD, MAC |
| Finance | 5 | Visa, Mastercard, IBAN, Credit Cards |
| Cloud | 10+ | AWS, Azure, GCP, DigitalOcean |
| Cryptographic | 8 | RSA, EC, DSA, PGP, SSH, PKCS#8 |
| API Keys | 20+ | GitHub, Slack, OpenAI, Stripe |
| Database | 5 | MySQL, PostgreSQL, MongoDB, Redis |
| Healthcare | 4 | NPI, DEA, ICD-10, BHYT |
| Infrastructure | 2 | Firebase, AWS S3 |

## Installation

### Prerequisites

- Go 1.21 or higher

### Build

```bash
# Clone the repository
cd secrets_scanner

# Download dependencies
go mod tidy

# Build the binary
go build -o secrets-scanner main.go

# Or build for specific platform
GOOS=linux GOARCH=amd64 go build -o secrets-scanner-linux main.go
GOOS=windows GOARCH=amd64 go build -o secrets-scanner.exe main.go
```

## Usage

### Basic Scan

```bash
# Scan current directory
./secrets-scanner

# Scan specific directory
./secrets-scanner -path /path/to/code

# Scan specific file
./secrets-scanner -path /path/to/config.yaml
```

### Advanced Options

```bash
# Set minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
./secrets-scanner -severity CRITICAL

# Use more workers for faster scanning
./secrets-scanner -workers 16

# Output as JSON
./secrets-scanner -json

# List all detection patterns
./secrets-scanner -patterns
```

### Examples

```bash
# Scan with HIGH severity and 16 workers
./secrets-scanner -path ./src -severity HIGH -workers 16

# Output JSON for CI/CD integration
./secrets-scanner -path ./src -json > results.json

# Scan only critical secrets
./secrets-scanner -path ./src -severity CRITICAL
```

## Package Structure

```
secrets_scanner/
├── main.go              # CLI entry point
├── patterns/
│   └── patterns.go      # Detection patterns registry
├── detector/
│   └── detector.go      # Secret detection engine
├── scanner/
│   └── scanner.go       # Multi-threaded file scanner
└── go.mod               # Go module definition
```

## API Usage

### Using as a Library

```go
package main

import (
    "fmt"
    "secrets_scanner/patterns"
    "secrets_scanner/scanner"
)

func main() {
    // Create scanner with HIGH severity, 8 workers
    s := scanner.NewSecretsScanner(
        patterns.SeverityHIGH,
        8,              // workers
        10*1024*1024,   // max file size (10MB)
        nil,            // use default extensions
        nil,            // use default exclude dirs
    )

    // Scan directory
    result := s.ScanPath("./my-code")

    // Process results
    fmt.Printf("Files scanned: %d\n", result.FilesScanned)
    fmt.Printf("Secrets found: %d\n", len(result.Findings))

    for _, finding := range result.Findings {
        fmt.Printf("%s: %s\n", finding["pattern"], finding["file"])
    }
}
```

### Quick Detection

```go
import (
    "secrets_scanner/detector"
    "secrets_scanner/patterns"
)

// Detect in string content
findings := detector.DetectSecretsFast(
    "api_key = 'AKIAIOSFODNN7EXAMPLE'",
    "config.txt",
    patterns.SeverityHIGH,
)
```

## Detection Patterns

The scanner detects **100+ types** of sensitive data:

| Category | Patterns |
|----------|----------|
| **PII** | Email, Phone (US/VN), SSN, CMND/CCCD, DOB, IPv4/6, MAC |
| **Finance** | Visa, Mastercard, Amex, Credit Cards, IBAN, Bitcoin, Ethereum |
| **Cloud** | AWS (AKIA/ASIA), Azure, GCP, DigitalOcean, Heroku |
| **Source Control** | GitHub (ghp/gho/ghu/ghs), GitLab |
| **Cryptographic** | RSA, EC, DSA, PGP, SSH, PKCS#8, X.509 |
| **Payment** | Stripe, PayPal, Square |
| **Messaging** | Slack, Discord, Telegram, Twilio |
| **AI/ML** | OpenAI, Anthropic, Hugging Face |
| **Healthcare** | NPI, DEA, ICD-10, BHYT (VN) |
| **Database** | MySQL, PostgreSQL, MongoDB, Redis, SQL Server |
| **Infrastructure** | Firebase, AWS S3 |

## Severity Levels

- **CRITICAL** - Verified secrets (AWS keys, private keys)
- **HIGH** - Likely secrets (API tokens, passwords)
- **MEDIUM** - Potential secrets (hashes, long hex strings)
- **LOW** - Low confidence findings

## Performance

The Go implementation offers significant performance improvements:

- **Parallel Processing** - Worker pool for concurrent file scanning
- **Pre-compiled Patterns** - All regex patterns compiled once at startup
- **Early Filtering** - Binary files and excluded directories skipped quickly
- **Memory Efficient** - Streaming file reads with size limits

## Exit Codes

- `0` - No secrets found
- `1` - Secrets detected or error occurred

## License

MIT License
