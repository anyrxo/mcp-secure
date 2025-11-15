import fs from 'fs/promises';
import path from 'path';
import { glob } from 'glob';
import { SecurityIssue, ScanResult } from '../types.js';
import { securityRules } from '../rules/index.js';

export class SecurityScanner {
  private basePath: string;

  constructor(basePath: string = process.cwd()) {
    this.basePath = basePath;
  }

  /**
   * Scan a directory for security issues
   */
  async scan(targetPath?: string): Promise<ScanResult> {
    const scanPath = targetPath || this.basePath;
    const allIssues: SecurityIssue[] = [];

    // Find all TypeScript and JavaScript files
    const patterns = [
      '**/*.ts',
      '**/*.js',
      '**/*.mjs',
      '**/*.cjs'
    ];

    const ignorePatterns = [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/*.test.*',
      '**/*.spec.*'
    ];

    let fileCount = 0;

    for (const pattern of patterns) {
      const files = await glob(pattern, {
        cwd: scanPath,
        ignore: ignorePatterns,
        absolute: true
      });

      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf-8');
          const relativeFile = path.relative(scanPath, file);

          // Run all security rules
          for (const rule of securityRules) {
            const issues = rule.check(content, relativeFile);
            allIssues.push(...issues);
          }

          fileCount++;
        } catch (error) {
          // Skip files that can't be read
          console.warn(`Warning: Could not read ${file}`);
        }
      }
    }

    // Count issues by severity
    const critical = allIssues.filter(i => i.severity === 'critical').length;
    const high = allIssues.filter(i => i.severity === 'high').length;
    const medium = allIssues.filter(i => i.severity === 'medium').length;
    const low = allIssues.filter(i => i.severity === 'low').length;
    const info = allIssues.filter(i => i.severity === 'info').length;

    // Sort issues by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    allIssues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return {
      files: fileCount,
      issues: allIssues,
      critical,
      high,
      medium,
      low,
      info,
      passed: critical === 0 && high === 0
    };
  }

  /**
   * Scan a single file
   */
  async scanFile(filePath: string): Promise<SecurityIssue[]> {
    const content = await fs.readFile(filePath, 'utf-8');
    const issues: SecurityIssue[] = [];

    for (const rule of securityRules) {
      const ruleIssues = rule.check(content, filePath);
      issues.push(...ruleIssues);
    }

    return issues;
  }

  /**
   * Get list of all security rules
   */
  getRules() {
    return securityRules.map(rule => ({
      id: rule.id,
      name: rule.name,
      severity: rule.severity,
      description: rule.description
    }));
  }
}
