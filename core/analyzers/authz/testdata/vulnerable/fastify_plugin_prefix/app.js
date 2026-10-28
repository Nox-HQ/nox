const Fastify = require('fastify');
const app = Fastify();
app.register(require('./routes/invoices'), { prefix: '/api/invoices' });
app.listen({ port: 3000 });
