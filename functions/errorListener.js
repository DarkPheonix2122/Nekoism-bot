// errorListener.js
const { request } = require("undici");
const ERROR_WEBHOOK = "https://discord.com/api/webhooks/1380804629192769686/DanANlJnLnHLjB72rkFtWkndUZfQE7Z9TqB_aHfQ3n3OYD-B9TRWHIFPsBspLV3Gv515";

async function handleFatalError(error) {
    console.error('❌ Fatal Error:', error + '\nRebooting in 5 seconds...');
    setTimeout(() => process.exit(12), 5000);
};
let bneko = null;

async function sendErrorToDiscord(error, options = {}) {
  if (!ERROR_WEBHOOK) {
    console.warn("⚠️ ERROR_WEBHOOK not set in environment.");
    return;
  }

  const {
    source = "FRONT-END API",
    eventName = null,   // source tag like "neko", "process", etc.
    fatal = false, // fatal error flag
    debug = false // debug flag
  } = options;

  const errorType =
    error instanceof TypeError ? "[TYPE]" :
    error instanceof ReferenceError ? "[REF]" :
    error instanceof SyntaxError ? "[SYNTAX]" : "[ERROR]";
    let sourceTagStr = source;
  if(source.toLowerCase().startsWith("event")){
    if(source.toLowerCase().startsWith("event_")){
      const args = source.split("_")[1]
      sourceTagStr = `${args}_EVENT_${eventName}`
    }else{
      sourceTagStr = `EVENT_${eventName}`
    }
  }
  const debugTag = debug ? "[DEBUG]" : "";
  const fatalTag = fatal ? "[FATAL]" : "";
  const sourceTag = sourceTagStr ? `[${sourceTagStr.toUpperCase()}]` : "";

  const tags = [debugTag, errorType, fatalTag, sourceTag].filter(Boolean).join(" ");
  const errorMessage = error.stack || error.toString();

  try {
    await request(ERROR_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: `${tags} 🚨 **Unhandled Exception**:\n\`\`\`\n${errorMessage.slice(0, 1900)}\n\`\`\``
      }),
    });
    if(debug) {
      return
    }else console.log("✅ Error sent to Discord webhook.");
  } catch (err) {
    console.error("❌ Failed to send error to webhook:", err);
    await handleFatalError(err);
  }
}

async function startupProcess(neko){
  console.log("Error listener started.");
  process.on("uncaughtException", (error) => {
    sendErrorToDiscord(error, { fatal: true, source: "process" });
  });

  process.on("unhandledRejection", (reason) => {
    sendErrorToDiscord(reason, { source: "promise" });
  });
}

module.exports = startupProcess;
module.exports.send = sendErrorToDiscord;
