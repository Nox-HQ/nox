const AllocationsDAO = require('../data/allocations-dao').AllocationsDAO;
function AllocationsHandler(db) {
  const allocationsDAO = new AllocationsDAO(db);
  this.displayAllocations = (req, res, next) => {
    const { userId } = req.params;
    allocationsDAO.getByUserId(userId, (err, allocations) => { // expect: AUTHZ-001
      if (err) return next(err);
      return res.render('allocations', { allocations });
    });
  };
}
module.exports = AllocationsHandler;
