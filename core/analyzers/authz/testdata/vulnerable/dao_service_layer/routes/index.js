const AllocationsHandler = require('./allocations');
const { isLoggedIn } = require('./session');
module.exports = (app, db) => {
  const allocationsHandler = new AllocationsHandler(db);
  app.get('/allocations/:userId', isLoggedIn, allocationsHandler.displayAllocations);
};
