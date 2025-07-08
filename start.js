const { spawn } = require('child_process');
function startBot() {
  const bot = spawn('node', ['init.js'], { stdio: 'inherit' });

  bot.on('close', (code) => {
    console.log(`website exited with code ${code}. Restarting in 3 seconds...`);
    setTimeout(startBot, 3000);
  });
}

startBot();
