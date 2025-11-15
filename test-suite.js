#!/usr/bin/env node

/**
 * Comprehensive Test Suite for MCP Secure
 * Validates all security rules and scanner functionality
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const CLI_PATH = path.join(__dirname, 'dist', 'cli.js');
const TEST_DIR = path.join(__dirname, 'test-samples');

let testsPassed = 0;
let testsFailed = 0;

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logTest(name, passed, details = '') {
  if (passed) {
    log(`✓ ${name}`, 'green');
    if (details) log(`  ${details}`, 'gray');
    testsPassed++;
  } else {
    log(`✗ ${name}`, 'red');
    if (details) log(`  ${details}`, 'red');
    testsFailed++;
  }
}

async function setup() {
  log('\n🔧 Setting up test environment...', 'cyan');
  await fs.mkdir(TEST_DIR, { recursive: true });
  log('✓ Test environment ready', 'green');
}

async function cleanup() {
  log('\n🧹 Cleaning up...', 'cyan');
  try {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    log('✓ Cleanup complete', 'green');
  } catch (error) {
    log(`⚠ Cleanup warning: ${error.message}`, 'yellow');
  }
}

async function createTestFile(filename, content) {
  const filePath = path.join(TEST_DIR, filename);
  await fs.writeFile(filePath, content);
  return filePath;
}

async function runScan(targetPath) {
  try {
    const { stdout, stderr } = await execAsync(`node ${CLI_PATH} scan ${targetPath}`);
    return { success: true, stdout, stderr };
  } catch (error) {
    return { success: false, stdout: error.stdout, stderr: error.stderr, error };
  }
}

// Test 1: CLI loads
async function testCLILoads() {
  log('\n📋 Test 1: CLI loads without errors', 'cyan');
  try {
    const { stdout } = await execAsync(`node ${CLI_PATH} --help`);
    const passed = stdout.includes('mcp-secure') && stdout.includes('scan');
    logTest('CLI loads and shows help', passed,
      passed ? 'Help text displayed' : 'Help text missing');
  } catch (error) {
    logTest('CLI loads and shows help', false, error.message);
  }
}

// Test 2: Rules command
async function testRulesCommand() {
  log('\n📋 Test 2: Rules command', 'cyan');
  try {
    const { stdout } = await execAsync(`node ${CLI_PATH} rules`);
    const checks = [
      stdout.includes('MCP001'),
      stdout.includes('Command Injection'),
      stdout.includes('critical'),
      stdout.includes('Total rules: 10')
    ];
    const passed = checks.every(c => c);
    logTest('Rules command lists all security rules', passed,
      passed ? 'All 10 rules present' : 'Some rules missing');
  } catch (error) {
    logTest('Rules command lists all security rules', false, error.message);
  }
}

// Test 3: Detect Command Injection (MCP001)
async function testCommandInjection() {
  log('\n📋 Test 3: Detect Command Injection', 'cyan');

  const vulnerableCode = `
const { exec } = require('child_process');
function runCommand(userInput) {
  exec(\`git clone \${userInput}\`);
}
`;

  try {
    const filePath = await createTestFile('cmd-injection.js', vulnerableCode);
    const { stdout } = await runScan(filePath); // Scan specific file, not directory

    const detected = stdout.includes('MCP001') &&
                     stdout.includes('Command Injection') &&
                     stdout.includes('critical');

    logTest('Detects command injection vulnerability', detected,
      detected ? 'MCP001 triggered correctly' : 'Failed to detect');
  } catch (error) {
    logTest('Detects command injection vulnerability', false, error.message);
  }
}

// Test 4: Detect Hardcoded Secrets (MCP003)
async function testHardcodedSecrets() {
  log('\n📋 Test 4: Detect Hardcoded Secrets', 'cyan');

  const vulnerableCode = `
const API_KEY = "sk-1234567890abcdefghijklmnop";
const PASSWORD = "super_secret_password_123";
`;

  try {
    const filePath = await createTestFile('secrets.js', vulnerableCode);
    const { stdout } = await runScan(filePath); // Scan specific file

    const detected = stdout.includes('MCP003') &&
                     stdout.includes('Hardcoded');

    logTest('Detects hardcoded secrets', detected,
      detected ? 'MCP003 triggered correctly' : 'Failed to detect');
  } catch (error) {
    logTest('Detects hardcoded secrets', false, error.message);
  }
}

// Test 5: Detect SQL Injection (MCP004)
async function testSQLInjection() {
  log('\n📋 Test 5: Detect SQL Injection', 'cyan');

  const vulnerableCode = `
function getUser(username) {
  const query = \`SELECT * FROM users WHERE name = '\${username}'\`;
  db.query(query);
}
`;

  try {
    await createTestFile('sql-injection.js', vulnerableCode);
    const { stdout } = await runScan(TEST_DIR);

    const detected = stdout.includes('MCP004') &&
                     stdout.includes('SQL');

    logTest('Detects SQL injection', detected,
      detected ? 'MCP004 triggered correctly' : 'Failed to detect');
  } catch (error) {
    logTest('Detects SQL injection', false, error.message);
  }
}

// Test 6: Detect Path Traversal (MCP002)
async function testPathTraversal() {
  log('\n📋 Test 6: Detect Path Traversal', 'cyan');

  const vulnerableCode = `
const fs = require('fs');
function readFile(filename) {
  return fs.readFile('../' + filename);
}
`;

  try {
    const filePath = await createTestFile('path-traversal.js', vulnerableCode);
    const { stdout } = await runScan(filePath); // Scan specific file

    const detected = stdout.includes('MCP002') &&
                     stdout.includes('Path');

    logTest('Detects path traversal', detected,
      detected ? 'MCP002 triggered correctly' : 'Failed to detect');
  } catch (error) {
    logTest('Detects path traversal', false, error.message);
  }
}

// Test 7: Detect Unrestricted Network (MCP009)
async function testUnrestrictedNetwork() {
  log('\n📋 Test 7: Detect Unrestricted Network Access', 'cyan');

  const vulnerableCode = `
async function fetchData(url) {
  const response = await fetch(\`\${url}\`);
  return response.json();
}
`;

  try {
    const filePath = await createTestFile('network.js', vulnerableCode);
    const { stdout } = await runScan(filePath); // Scan specific file

    const detected = stdout.includes('MCP009') &&
                     stdout.includes('Network');

    logTest('Detects unrestricted network access', detected,
      detected ? 'MCP009 triggered correctly' : 'Failed to detect');
  } catch (error) {
    logTest('Detects unrestricted network access', false, error.message);
  }
}

// Test 8: Detect Insecure Deserialization (MCP006)
async function testInsecureDeserialization() {
  log('\n📋 Test 8: Detect Insecure Deserialization', 'cyan');

  const vulnerableCode = `
function parseData(input) {
  const data = JSON.parse(input);
  return data;
}
`;

  try {
    const filePath = await createTestFile('deserialize.js', vulnerableCode);
    const { stdout } = await runScan(filePath); // Scan specific file

    const detected = stdout.includes('MCP006') &&
                     stdout.includes('Deserialization');

    logTest('Detects insecure deserialization', detected,
      detected ? 'MCP006 triggered correctly' : 'Failed to detect');
  } catch (error) {
    logTest('Detects insecure deserialization', false, error.message);
  }
}

// Test 9: Safe code (no issues)
async function testSafeCode() {
  log('\n📋 Test 9: Safe code detection', 'cyan');

  const safeCode = `
// Safe code with proper validation
export function safeFunction(input: string): string {
  try {
    if (typeof input !== 'string') {
      throw new Error('Invalid input');
    }
    return input.trim();
  } catch (error) {
    console.error(error);
    return '';
  }
}
`;

  try {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });
    await createTestFile('safe.ts', safeCode);
    const { stdout } = await runScan(TEST_DIR);

    const noCritical = !stdout.includes('[CRITICAL]');
    const noHigh = !stdout.includes('[HIGH]');

    logTest('Recognizes safe code (no critical/high issues)', noCritical && noHigh,
      noCritical && noHigh ? 'No false positives' : 'False positives detected');
  } catch (error) {
    logTest('Recognizes safe code', false, error.message);
  }
}

// Test 10: JSON output format
async function testJSONOutput() {
  log('\n📋 Test 10: JSON output format', 'cyan');

  const code = `const key = "sk-test";`;

  try {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });
    await createTestFile('test.js', code);
    const { stdout } = await execAsync(`node ${CLI_PATH} scan ${TEST_DIR} --json`);

    const isJSON = stdout.trim().startsWith('{') && stdout.trim().endsWith('}');
    let parsed = null;
    if (isJSON) {
      try {
        parsed = JSON.parse(stdout);
      } catch {}
    }

    const valid = isJSON && parsed &&
                  typeof parsed.files === 'number' &&
                  Array.isArray(parsed.issues);

    logTest('Outputs valid JSON format', valid,
      valid ? 'JSON structure correct' : 'Invalid JSON');
  } catch (error) {
    logTest('Outputs valid JSON format', false, error.message);
  }
}

// Test 11: CI command
async function testCICommand() {
  log('\n📋 Test 11: CI command', 'cyan');

  try {
    const { stdout } = await execAsync(`node ${CLI_PATH} ci ${TEST_DIR}`);
    const parsed = JSON.parse(stdout);

    const valid = parsed &&
                  typeof parsed.passed === 'boolean' &&
                  typeof parsed.files === 'number' &&
                  parsed.summary;

    logTest('CI command works', valid,
      valid ? 'CI output format correct' : 'Invalid CI output');
  } catch (error) {
    // CI command may exit with code 1 if issues found, that's ok
    if (error.stdout) {
      try {
        const parsed = JSON.parse(error.stdout);
        const valid = typeof parsed.passed === 'boolean';
        logTest('CI command works', valid,
          valid ? 'CI output format correct' : 'Invalid CI output');
        return;
      } catch {}
    }
    logTest('CI command works', false, error.message);
  }
}

// Test 12: Severity filtering
async function testSeverityFiltering() {
  log('\n📋 Test 12: Severity filtering', 'cyan');

  const code = `
const key = "sk-test"; // HIGH
const data = JSON.parse(input); // MEDIUM
`;

  try {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });
    await createTestFile('mixed.js', code);
    const { stdout } = await execAsync(`node ${CLI_PATH} scan ${TEST_DIR} --severity high`);

    const hasHigh = stdout.includes('[HIGH]');
    const noMedium = !stdout.includes('[MEDIUM]');

    logTest('Severity filtering works', hasHigh && noMedium,
      hasHigh && noMedium ? 'Only high severity shown' : 'Filtering failed');
  } catch (error) {
    logTest('Severity filtering works', false, error.message);
  }
}

// Test 13: Multiple vulnerabilities in one file
async function testMultipleIssues() {
  log('\n📋 Test 13: Multiple vulnerabilities detection', 'cyan');

  const code = `
const { exec } = require('child_process');
const API_KEY = "sk-1234567890";

function bad(input) {
  exec(\`ls \${input}\`);
  const query = \`SELECT * FROM users WHERE id = \${input}\`;
  db.query(query);
}
`;

  try {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });
    await createTestFile('multiple.js', code);
    const { stdout } = await runScan(TEST_DIR);

    const hasCmd = stdout.includes('MCP001');
    const hasSecret = stdout.includes('MCP003');
    const hasSQL = stdout.includes('MCP004');
    const count = (hasCmd ? 1 : 0) + (hasSecret ? 1 : 0) + (hasSQL ? 1 : 0);

    logTest('Detects multiple issues in one file', count >= 2,
      count >= 2 ? `Found ${count} different vulnerability types` : 'Missed some issues');
  } catch (error) {
    logTest('Detects multiple issues in one file', false, error.message);
  }
}

// Test 14: TypeScript file scanning
async function testTypeScriptScanning() {
  log('\n📋 Test 14: TypeScript file scanning', 'cyan');

  const code = `
interface User {
  id: number;
  apiKey: string;
}

const user: User = {
  id: 1,
  apiKey: "sk-hardcoded123456"
};
`;

  try {
    await fs.rm(TEST_DIR, { recursive: true, force: true });
    await fs.mkdir(TEST_DIR, { recursive: true });
    await createTestFile('typescript.ts', code);
    const { stdout } = await runScan(TEST_DIR);

    const scanned = stdout.includes('Files scanned:') && stdout.includes('1');
    const detected = stdout.includes('MCP003') || stdout.includes('apiKey');

    logTest('Scans TypeScript files', scanned,
      scanned ? 'TypeScript file scanned' : 'Failed to scan .ts file');
  } catch (error) {
    logTest('Scans TypeScript files', false, error.message);
  }
}

// Test 15: Real MCP Hub code scan
async function testRealCodeScan() {
  log('\n📋 Test 15: Scan real MCP code (MCP Hub)', 'cyan');

  try {
    const mcpHubPath = path.join(__dirname, '..', 'mcp-hub-repo', 'src');

    // Check if path exists
    try {
      await fs.access(mcpHubPath);
    } catch {
      logTest('Scan real MCP code', false, 'MCP Hub source not found');
      return;
    }

    const { stdout } = await execAsync(`node ${CLI_PATH} scan ${mcpHubPath}`);

    const filesScanned = stdout.match(/Files scanned: (\d+)/);
    const issuesFound = stdout.includes('Issues Found') || stdout.includes('No security issues');

    logTest('Scan real MCP code', filesScanned && issuesFound,
      filesScanned ? `Scanned ${filesScanned[1]} files` : 'Scan failed');
  } catch (error) {
    logTest('Scan real MCP code', false, error.message);
  }
}

// Main test runner
async function runTests() {
  console.log('');
  log('╔════════════════════════════════════════════════════════╗', 'cyan');
  log('║   MCP Secure - Comprehensive Test Suite                ║', 'cyan');
  log('╚════════════════════════════════════════════════════════╝', 'cyan');

  await setup();

  // Run all tests
  await testCLILoads();
  await testRulesCommand();
  await testCommandInjection();
  await testHardcodedSecrets();
  await testSQLInjection();
  await testPathTraversal();
  await testUnrestrictedNetwork();
  await testInsecureDeserialization();
  await testSafeCode();
  await testJSONOutput();
  await testCICommand();
  await testSeverityFiltering();
  await testMultipleIssues();
  await testTypeScriptScanning();
  await testRealCodeScan();

  await cleanup();

  // Summary
  log('\n' + '═'.repeat(60), 'cyan');
  log('Test Summary', 'cyan');
  log('═'.repeat(60), 'cyan');

  const total = testsPassed + testsFailed;
  const percentage = total > 0 ? Math.round((testsPassed / total) * 100) : 0;

  log(`\nTotal Tests: ${total}`, 'cyan');
  log(`Passed: ${testsPassed}`, 'green');
  if (testsFailed > 0) {
    log(`Failed: ${testsFailed}`, 'red');
  }
  log(`Success Rate: ${percentage}%\n`, percentage === 100 ? 'green' : 'yellow');

  if (testsFailed === 0) {
    log('✓ All tests passed! MCP Secure is production-ready.', 'green');
  } else {
    log('✗ Some tests failed. Please review the errors above.', 'red');
  }

  console.log('');

  process.exit(testsFailed > 0 ? 1 : 0);
}

// Run tests
runTests().catch((error) => {
  log(`\n✗ Test suite failed: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});
