const router = require('express').Router();
const Note = require('../models/note');

router.delete('/:noteId', async (req, res, next) => {
  try {
    await Note.deleteOne({ _id: req.params.noteId }); // expect: AUTHZ-001
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
