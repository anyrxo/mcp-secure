const { exec } = require('child_process');
function runCommand(userInput) {
  exec(`git clone ${userInput}`);
}
