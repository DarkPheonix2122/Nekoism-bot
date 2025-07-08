const { spawn } = require('child_process');
function startBot() {
  try{
    const bot = spawn('node', ['init.js'], { stdio: 'inherit' });
  }catch(err){
    require("./functions/errorListener").send(err);
  }
  bot.on('close', (code) => {
    console.log(`website exited with code ${code}. Restarting in 3 seconds...`);
    setTimeout(startBot, 3000);
  });
}

startBot();
