const express = require('express');
const passportjs = require('passport');
const app = express();
app.use(passportjs.initialize());
app.use('/api/notes', passportjs.authenticate('jwt', { session: false }), require('./routes/notes'));
app.listen(3000);
