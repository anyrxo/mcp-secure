# MCP Secure

<div align="center">

```
███╗   ███╗ ██████╗██████╗     ███████╗███████╗ ██████╗
████╗ ████║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔════╝
██╔████╔██║██║     ██████╔╝    ███████╗█████╗  ██║     
██║╚██╔╝██║██║     ██╔═══╝     ╚════██║██╔══╝  ██║     
██║ ╚═╝ ██║╚██████╗██║         ███████║███████╗╚██████╗
╚═╝     ╚═╝ ╚═════╝╚═╝         ╚══════╝╚══════╝ ╚═════╝
```

**Security Scanner & Linter for Model Context Protocol Servers**

*Find vulnerabilities, enforce best practices, secure your MCPs*

[![npm version](https://img.shields.io/npm/v/mcp-secure.svg)](https://www.npmjs.com/package/mcp-secure)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)

[🚀 Quick Start](#quick-start) • [📖 Documentation](#documentation) • [🔒 Security Rules](#security-rules) • [💻 CLI](#cli-commands)

</div>

---

## 🌟 What is MCP Secure?

**MCP Secure** is a comprehensive security scanner and linter specifically designed for **Model Context Protocol (MCP)** servers. It analyzes your MCP server code to detect vulnerabilities, enforce security best practices, and ensure your integration with Claude Code is safe and secure.

### Why MCP Secure?

- **🛡️ Security First**: Detects 10+ categories of security vulnerabilities
- **⚡ Fast Scanning**: Scans entire codebases in seconds
- **🎯 MCP-Specific**: Rules tailored for MCP server patterns
- **✨ Beautiful CLI**: Clear, actionable security reports
- **🔧 CI/CD Ready**: Easy integration with pipelines
- **📊 Detailed Reports**: Know exactly what to fix and how

---

## 🚀 Quick Start

### Installation

```bash
# Install globally
npm install -g mcp-secure

# Or use via npx (no installation)
npx mcp-secure scan
```

### Basic Usage

```bash
# Scan current directory
mcp-secure scan

# Scan specific directory
mcp-secure scan ./my-mcp-server

# View all security rules
mcp-secure rules

# CI/CD mode (JSON output)
mcp-secure ci
```

---

## 🔒 Security Rules

MCP Secure checks for 10 comprehensive security issues:

### Critical Severity

| ID | Rule | Description |
|----|------|-------------|
| **MCP001** | Command Injection | Detects unsafe command execution with user input |
| **MCP002** | Path Traversal | Prevents directory traversal attacks |

### High Severity

| ID | Rule | Description |
|----|------|-------------|
| **MCP003** | Hardcoded Secrets | Finds API keys, tokens, passwords in code |
| **MCP004** | SQL Injection | Detects unsafe SQL query construction |
| **MCP009** | Unrestricted Network | Catches SSRF and unsafe HTTP requests |

### Medium Severity

| ID | Rule | Description |
|----|------|-------------|
| **MCP005** | Missing Input Validation | Ensures tool handlers validate arguments |
| **MCP006** | Insecure Deserialization | Detects unsafe JSON.parse usage |
| **MCP010** | Missing Rate Limiting | Checks for DoS protection |

### Low & Info

| ID | Rule | Description |
|----|------|-------------|
| **MCP007** | Missing Error Handling | Validates try-catch blocks |
| **MCP008** | MCP Best Practices | Encourages SDK usage and descriptions |

---

## 💻 CLI Commands

### `mcp-secure scan [path]`

Scan MCP server code for security issues.

```bash
# Basic scan
mcp-secure scan

# Scan with options
mcp-secure scan ./src --severity high --fail-on critical
```

**Options:**
- `--severity <level>` - Only show issues at or above severity (critical, high, medium, low, info)
- `--json` - Output results as JSON
- `--fail-on <severity>` - Exit with error if issues found (for CI/CD)

**Example Output:**
```
📊 Scan Results

Files scanned: 15
Total issues: 3

┌────────────────────┬──────────┐
│ Severity           │ Count    │
├────────────────────┼──────────┤
│ Critical           │ 0        │
│ High               │ 1        │
│ Medium             │ 2        │
│ Low                │ 0        │
│ Info               │ 0        │
└────────────────────┴──────────┘

🔍 Issues Found

1. [HIGH] MCP003 - Potential hardcoded API Key detected
   File: src/config.ts:12
   Code: const API_KEY = "sk-1234567890abcdef";
   Fix: Use environment variables (process.env) to store sensitive data.
```

### `mcp-secure rules`

List all security rules with descriptions.

```bash
mcp-secure rules
```

### `mcp-secure ci [path]`

Run scan optimized for CI/CD pipelines.

```bash
# In CI/CD pipeline
mcp-secure ci

# Exit code 0 = passed, 1 = failed
```

---

## 📖 Documentation

### Integrating with CI/CD

#### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npx mcp-secure ci
```

#### GitLab CI

```yaml
security_scan:
  image: node:18
  script:
    - npx mcp-secure ci
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx mcp-secure scan --fail-on high
```

---

## 🛠️ Configuration

Create `.mcpsecure.json` in your project root:

```json
{
  "ignore": [
    "**/test/**",
    "**/examples/**"
  ],
  "severity": "medium",
  "rules": {
    "MCP001": "error",
    "MCP008": "warn"
  }
}
```

---

## 🎯 Examples

### Example 1: Scan Before Deployment

```bash
#!/bin/bash
# deploy.sh

echo "Running security scan..."
if mcp-secure scan --fail-on high; then
  echo "✅ Security scan passed"
  npm run deploy
else
  echo "❌ Security issues found - deployment blocked"
  exit 1
fi
```

### Example 2: Find Only Critical Issues

```bash
mcp-secure scan --severity critical --json > security-report.json
```

### Example 3: Development Workflow

```bash
# Watch mode (scan on file change)
mcp-secure scan && echo "✅ No issues"
```

---

## 🔍 What MCP Secure Detects

### Command Injection

**Vulnerable Code:**
```typescript
const result = exec(`git clone ${userInput}`);
```

**Secure Code:**
```typescript
const result = execFile('git', ['clone', userInput]);
```

### Path Traversal

**Vulnerable Code:**
```typescript
const data = fs.readFileSync(userInput);
```

**Secure Code:**
```typescript
const safePath = path.resolve('/allowed/dir', userInput);
if (!safePath.startsWith('/allowed/dir')) throw new Error('Invalid path');
const data = fs.readFileSync(safePath);
```

### Hardcoded Secrets

**Vulnerable Code:**
```typescript
const API_KEY = "sk-1234567890";
```

**Secure Code:**
```typescript
const API_KEY = process.env.API_KEY;
```

---

## 🚧 Roadmap

- [ ] Custom rule creation
- [ ] Auto-fix capabilities
- [ ] VS Code extension
- [ ] GitHub App integration
- [ ] SARIF format output
- [ ] Dependency vulnerability scanning

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- **Anthropic** - For Claude Code and MCP
- **MCP Community** - For building awesome servers
- **Security Researchers** - For vulnerability patterns

---

<div align="center">

**Made with ❤️ for the MCP Community**

⭐ Star us on GitHub | 🐛 Report Issues | 📖 Read the Docs

</div>
