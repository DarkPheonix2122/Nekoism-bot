// errorHandler.js
const sendErrorToDiscord = require('./errorListener')

function errorHandler(err, req, res, next) {
  sendErrorToDiscord.send(err);

  res.status(err.status || 500).json({
    message: 'Something went wrong!',
  });
}

module.exports = errorHandler;
