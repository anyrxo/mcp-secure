#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import Table from 'cli-table3';
import { SecurityScanner } from './scanner/index.js';
import { securityRules } from './rules/index.js';

const program = new Command();

// Banner
const banner = `
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ${chalk.cyan('███╗   ███╗ ██████╗██████╗     ███████╗███████╗ ██████╗')}   ║
║   ${chalk.cyan('████╗ ████║██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔════╝')}   ║
║   ${chalk.cyan('██╔████╔██║██║     ██████╔╝    ███████╗█████╗  ██║     ')}   ║
║   ${chalk.cyan('██║╚██╔╝██║██║     ██╔═══╝     ╚════██║██╔══╝  ██║     ')}   ║
║   ${chalk.cyan('██║ ╚═╝ ██║╚██████╗██║         ███████║███████╗╚██████╗')}   ║
║   ${chalk.cyan('╚═╝     ╚═╝ ╚═════╝╚═╝         ╚══════╝╚══════╝ ╚═════╝')}   ║
║                                                           ║
║   ${chalk.white('Security Scanner for Model Context Protocol')}          ║
║   ${chalk.gray('Find vulnerabilities, enforce best practices')}         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
`;

program
  .name('mcp-secure')
  .description('Security scanner and linter for MCP servers')
  .version('1.0.0');

// Scan command
program
  .command('scan [path]')
  .description('Scan MCP server code for security vulnerabilities')
  .option('--severity <level>', 'Only show issues of this severity or higher (critical, high, medium, low, info)')
  .option('--json', 'Output results as JSON')
  .option('--fail-on <severity>', 'Exit with error code if issues found at or above severity (critical, high, medium)')
  .action(async (targetPath, options) => {
    console.log(banner);

    const spinner = ora('Scanning for security issues...').start();

    try {
      const scanner = new SecurityScanner();
      const scanPath = targetPath || process.cwd();

      // Check if path is a file or directory
      const fs = await import('fs/promises');
      const stats = await fs.stat(scanPath);

      let result;
      if (stats.isFile()) {
        // Scan single file
        const issues = await scanner.scanFile(scanPath);
        result = {
          files: 1,
          issues,
          critical: issues.filter(i => i.severity === 'critical').length,
          high: issues.filter(i => i.severity === 'high').length,
          medium: issues.filter(i => i.severity === 'medium').length,
          low: issues.filter(i => i.severity === 'low').length,
          info: issues.filter(i => i.severity === 'info').length,
          passed: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0
        };
      } else {
        // Scan directory
        result = await scanner.scan(scanPath);
      }

      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      // Display results
      console.log(chalk.cyan('\n📊 Scan Results\n'));
      console.log(chalk.gray(`Files scanned: ${result.files}`));
      console.log(chalk.gray(`Total issues: ${result.issues.length}\n`));

      // Summary table
      const summaryTable = new Table({
        head: ['Severity', 'Count'],
        colWidths: [20, 10]
      });

      summaryTable.push(
        [chalk.red.bold('Critical'), result.critical > 0 ? chalk.red(result.critical) : chalk.green('0')],
        [chalk.magenta.bold('High'), result.high > 0 ? chalk.magenta(result.high) : chalk.green('0')],
        [chalk.yellow.bold('Medium'), result.medium > 0 ? chalk.yellow(result.medium) : chalk.green('0')],
        [chalk.blue.bold('Low'), result.low > 0 ? chalk.blue(result.low) : chalk.green('0')],
        [chalk.gray.bold('Info'), result.info > 0 ? chalk.gray(result.info) : chalk.green('0')]
      );

      console.log(summaryTable.toString());

      // Filter by severity if requested
      let displayIssues = result.issues;
      if (options.severity) {
        const severityLevels = ['info', 'low', 'medium', 'high', 'critical'];
        const minLevel = severityLevels.indexOf(options.severity.toLowerCase());
        displayIssues = result.issues.filter(issue =>
          severityLevels.indexOf(issue.severity) >= minLevel
        );
      }

      // Display issues
      if (displayIssues.length > 0) {
        console.log(chalk.cyan('\n\n🔍 Issues Found\n'));

        displayIssues.forEach((issue, idx) => {
          const severityColor = {
            critical: chalk.red.bold,
            high: chalk.magenta.bold,
            medium: chalk.yellow.bold,
            low: chalk.blue.bold,
            info: chalk.gray.bold
          }[issue.severity];

          console.log(`${idx + 1}. ${severityColor(`[${issue.severity.toUpperCase()}]`)} ${chalk.white.bold(issue.rule)} - ${issue.message}`);
          console.log(`   ${chalk.gray('File:')} ${issue.file}${issue.line ? `:${issue.line}` : ''}`);
          if (issue.code) {
            console.log(`   ${chalk.gray('Code:')} ${chalk.dim(issue.code)}`);
          }
          if (issue.fix) {
            console.log(`   ${chalk.green('Fix:')} ${issue.fix}`);
          }
          console.log('');
        });
      } else {
        console.log(chalk.green('\n\n✅ No security issues found! Your MCP server looks great.\n'));
      }

      // Overall result
      if (result.passed) {
        console.log(chalk.green.bold('✓ PASSED') + chalk.gray(' - No critical or high severity issues'));
      } else {
        console.log(chalk.red.bold('✗ FAILED') + chalk.gray(` - Found ${result.critical + result.high} critical/high severity issues`));
      }

      console.log('');

      // Check fail-on option
      if (options.failOn) {
        const severityMap: Record<string, number> = {
          critical: result.critical,
          high: result.high,
          medium: result.medium
        };

        if (severityMap[options.failOn.toLowerCase()] > 0) {
          process.exit(1);
        }
      } else if (!result.passed) {
        process.exit(1);
      }

    } catch (error) {
      spinner.fail(chalk.red('Scan failed'));
      console.error(chalk.red((error as Error).message));
      process.exit(1);
    }
  });

// List rules command
program
  .command('rules')
  .description('List all security rules')
  .action(() => {
    console.log(banner);
    console.log(chalk.cyan('\n📋 Security Rules\n'));

    const table = new Table({
      head: ['ID', 'Severity', 'Name', 'Description'],
      colWidths: [10, 12, 30, 50],
      wordWrap: true
    });

    securityRules.forEach(rule => {
      const severityColor = {
        critical: chalk.red,
        high: chalk.magenta,
        medium: chalk.yellow,
        low: chalk.blue,
        info: chalk.gray
      }[rule.severity];

      table.push([
        chalk.white(rule.id),
        severityColor(rule.severity),
        chalk.white.bold(rule.name),
        chalk.gray(rule.description)
      ]);
    });

    console.log(table.toString());
    console.log(chalk.gray(`\nTotal rules: ${securityRules.length}\n`));
  });

// CI command (for continuous integration)
program
  .command('ci [path]')
  .description('Run scan optimized for CI/CD (JSON output, exit codes)')
  .action(async (targetPath) => {
    try {
      const scanner = new SecurityScanner();
      const result = await scanner.scan(targetPath || process.cwd());

      console.log(JSON.stringify({
        passed: result.passed,
        files: result.files,
        summary: {
          critical: result.critical,
          high: result.high,
          medium: result.medium,
          low: result.low,
          info: result.info
        },
        issues: result.issues
      }, null, 2));

      process.exit(result.passed ? 0 : 1);
    } catch (error) {
      console.error(JSON.stringify({ error: (error as Error).message }));
      process.exit(1);
    }
  });

program.parse();
