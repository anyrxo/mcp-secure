import { SecurityRule, SecurityIssue } from '../types.js';

/**
 * Security rules for MCP server scanning
 */
export const securityRules: SecurityRule[] = [
  // CRITICAL: Command Injection
  {
    id: 'MCP001',
    name: 'Command Injection',
    severity: 'critical',
    description: 'Detects potential command injection vulnerabilities',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      const dangerousPatterns = [
        /exec\s*\([^)]*\$\{/,
        /spawn\s*\([^)]*\$\{/,
        /execSync\s*\([^)]*\$\{/,
        /child_process.*\$\{/,
        /eval\s*\(/,
        /new Function\s*\(/
      ];

      lines.forEach((line, idx) => {
        dangerousPatterns.forEach(pattern => {
          if (pattern.test(line)) {
            issues.push({
              rule: 'MCP001',
              severity: 'critical',
              message: 'Potential command injection vulnerability detected',
              file,
              line: idx + 1,
              code: line.trim(),
              fix: 'Sanitize user input before executing commands. Use allowlists and avoid template literals in exec/spawn.'
            });
          }
        });
      });

      return issues;
    }
  },

  // CRITICAL: Path Traversal
  {
    id: 'MCP002',
    name: 'Path Traversal',
    severity: 'critical',
    description: 'Detects path traversal vulnerabilities',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      const patterns = [
        /readFile\s*\([^)]*\.\./,
        /writeFile\s*\([^)]*\.\./,
        /require\s*\([^)]*\.\./,
        /import\s*\([^)]*\.\./
      ];

      lines.forEach((line, idx) => {
        patterns.forEach(pattern => {
          if (pattern.test(line) && !line.includes('//')) {
            issues.push({
              rule: 'MCP002',
              severity: 'critical',
              message: 'Potential path traversal vulnerability',
              file,
              line: idx + 1,
              code: line.trim(),
              fix: 'Validate and sanitize file paths. Use path.resolve() and check against allowed directories.'
            });
          }
        });
      });

      return issues;
    }
  },

  // HIGH: Hardcoded Secrets
  {
    id: 'MCP003',
    name: 'Hardcoded Secrets',
    severity: 'high',
    description: 'Detects hardcoded API keys, tokens, and secrets',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      const secretPatterns = [
        { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"](sk-|pk_live|[A-Za-z0-9]{32,})['"]/, name: 'API Key' },
        { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/, name: 'Password' },
        { pattern: /(?:token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9]{20,}['"]/, name: 'Auth Token' },
        { pattern: /(?:secret|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9]{20,}['"]/, name: 'Secret' },
        { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key' },
        { pattern: /ghp_[A-Za-z0-9]{36}/, name: 'GitHub Token' }
      ];

      lines.forEach((line, idx) => {
        secretPatterns.forEach(({ pattern, name }) => {
          if (pattern.test(line) && !line.includes('process.env') && !line.includes('example')) {
            issues.push({
              rule: 'MCP003',
              severity: 'high',
              message: `Potential hardcoded ${name} detected`,
              file,
              line: idx + 1,
              code: line.trim().substring(0, 50) + '...',
              fix: 'Use environment variables (process.env) to store sensitive data. Never commit secrets to version control.'
            });
          }
        });
      });

      return issues;
    }
  },

  // HIGH: SQL Injection
  {
    id: 'MCP004',
    name: 'SQL Injection',
    severity: 'high',
    description: 'Detects potential SQL injection vulnerabilities',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      const patterns = [
        /query\s*\([^)]*\$\{/,
        /execute\s*\([^)]*\$\{/,
        /SELECT.*\$\{/,
        /INSERT.*\$\{/,
        /UPDATE.*\$\{/,
        /DELETE.*\$\{/
      ];

      lines.forEach((line, idx) => {
        patterns.forEach(pattern => {
          if (pattern.test(line)) {
            issues.push({
              rule: 'MCP004',
              severity: 'high',
              message: 'Potential SQL injection vulnerability',
              file,
              line: idx + 1,
              code: line.trim(),
              fix: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.'
            });
          }
        });
      });

      return issues;
    }
  },

  // MEDIUM: Missing Input Validation
  {
    id: 'MCP005',
    name: 'Missing Input Validation',
    severity: 'medium',
    description: 'Detects missing input validation in tool handlers',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      let inToolHandler = false;
      let hasValidation = false;

      lines.forEach((line, idx) => {
        if (/tools\s*:\s*\[/.test(line) || /server\.setRequestHandler/.test(line)) {
          inToolHandler = true;
          hasValidation = false;
        }

        if (inToolHandler) {
          if (/validate|check|assert|throw|if\s*\(/.test(line)) {
            hasValidation = true;
          }

          if (/\}\s*\]/.test(line) && !hasValidation) {
            issues.push({
              rule: 'MCP005',
              severity: 'medium',
              message: 'Tool handler lacks input validation',
              file,
              line: idx + 1,
              fix: 'Add input validation to verify argument types, ranges, and formats before processing.'
            });
            inToolHandler = false;
          }
        }
      });

      return issues;
    }
  },

  // MEDIUM: Insecure Deserialization
  {
    id: 'MCP006',
    name: 'Insecure Deserialization',
    severity: 'medium',
    description: 'Detects unsafe deserialization patterns',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      const patterns = [
        /JSON\.parse\s*\([^)]*\)/,
        /yaml\.load\s*\([^)]*\)/,
        /eval\s*\([^)]*JSON/
      ];

      lines.forEach((line, idx) => {
        patterns.forEach(pattern => {
          if (pattern.test(line) && !line.includes('try') && !line.includes('catch')) {
            issues.push({
              rule: 'MCP006',
              severity: 'medium',
              message: 'Unprotected deserialization detected',
              file,
              line: idx + 1,
              code: line.trim(),
              fix: 'Wrap deserialization in try-catch blocks and validate the structure after parsing.'
            });
          }
        });
      });

      return issues;
    }
  },

  // LOW: Missing Error Handling
  {
    id: 'MCP007',
    name: 'Missing Error Handling',
    severity: 'low',
    description: 'Detects async operations without error handling',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      let inAsyncFunction = false;
      let hasTryCatch = false;

      lines.forEach((line, idx) => {
        if (/async\s+function|async\s+\(/.test(line)) {
          inAsyncFunction = true;
          hasTryCatch = false;
        }

        if (inAsyncFunction && /try\s*\{/.test(line)) {
          hasTryCatch = true;
        }

        if (inAsyncFunction && /\}\s*$/.test(line) && !hasTryCatch && /await/.test(content.substring(0, content.indexOf(line)))) {
          issues.push({
            rule: 'MCP007',
            severity: 'low',
            message: 'Async function missing try-catch error handling',
            file,
            line: idx + 1,
            fix: 'Wrap async operations in try-catch blocks to handle errors gracefully.'
          });
          inAsyncFunction = false;
        }
      });

      return issues;
    }
  },

  // INFO: Best Practices
  {
    id: 'MCP008',
    name: 'MCP Best Practices',
    severity: 'info',
    description: 'Checks MCP-specific best practices',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];

      // Check for MCP SDK usage
      if (!content.includes('@modelcontextprotocol/sdk')) {
        issues.push({
          rule: 'MCP008',
          severity: 'info',
          message: 'Consider using the official MCP SDK (@modelcontextprotocol/sdk)',
          file,
          fix: 'Using the official SDK ensures compatibility and follows best practices.'
        });
      }

      // Check for tool descriptions
      if (content.includes('tools:') && !content.includes('description:')) {
        issues.push({
          rule: 'MCP008',
          severity: 'info',
          message: 'Tools should include descriptions for better discoverability',
          file,
          fix: 'Add description fields to all tools to help users understand their purpose.'
        });
      }

      return issues;
    }
  },

  // HIGH: Unrestricted Network Access
  {
    id: 'MCP009',
    name: 'Unrestricted Network Access',
    severity: 'high',
    description: 'Detects unrestricted network requests',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];
      const lines = content.split('\n');

      const patterns = [
        /fetch\s*\([^)]*\$\{/,
        /axios\s*\([^)]*\$\{/,
        /request\s*\([^)]*\$\{/,
        /http\.get\s*\([^)]*\$\{/
      ];

      lines.forEach((line, idx) => {
        patterns.forEach(pattern => {
          if (pattern.test(line)) {
            issues.push({
              rule: 'MCP009',
              severity: 'high',
              message: 'Unrestricted network request with user-controlled URL',
              file,
              line: idx + 1,
              code: line.trim(),
              fix: 'Validate URLs against an allowlist. Prevent SSRF by restricting to known-safe domains.'
            });
          }
        });
      });

      return issues;
    }
  },

  // MEDIUM: Insufficient Rate Limiting
  {
    id: 'MCP010',
    name: 'Missing Rate Limiting',
    severity: 'medium',
    description: 'Detects lack of rate limiting on tools',
    check: (content: string, file: string): SecurityIssue[] => {
      const issues: SecurityIssue[] = [];

      if (content.includes('server.setRequestHandler') &&
          !content.includes('rateLimit') &&
          !content.includes('throttle')) {
        issues.push({
          rule: 'MCP010',
          severity: 'medium',
          message: 'No rate limiting detected in MCP server',
          file,
          fix: 'Implement rate limiting to prevent abuse and DoS attacks.'
        });
      }

      return issues;
    }
  }
];
