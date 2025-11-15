// Test file with intentional vulnerabilities for testing
const exec = require('child_process').exec;

// MCP001: Command Injection
function runCommand(userInput) {
  exec(`ls ${userInput}`);
}

// MCP003: Hardcoded Secret
const API_KEY = "sk-1234567890abcdefghijklmnop";

// MCP004: SQL Injection
function getUser(username) {
  const query = `SELECT * FROM users WHERE name = '${username}'`;
  db.query(query);
}

// MCP009: Unrestricted Network
async function fetchData(url) {
  const response = await fetch(`${url}`);
}
