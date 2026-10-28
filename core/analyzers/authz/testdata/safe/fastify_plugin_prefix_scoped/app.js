const Fastify = require('fastify');
const app = Fastify();
app.register(require('./routes/notes'), { prefix: '/api/notes' });
