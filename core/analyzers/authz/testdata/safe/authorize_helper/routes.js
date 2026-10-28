const router = require('express').Router();
const { requireAuth } = require('./auth');
const { authorize } = require('./policy');
const Report = require('./models/report');
router.get('/reports/:reportId', requireAuth, async (req, res) => {
  const report = await Report.findById(req.params.reportId);
  await authorize(req.user, 'report:read', report);
  res.json(report);
});
module.exports = router;
