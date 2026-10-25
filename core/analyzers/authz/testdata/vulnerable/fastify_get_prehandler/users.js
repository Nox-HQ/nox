const fastify = require('fastify')();
const db = require('./db');

fastify.get('/v2/accounts/:id', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { rows } = await db.query('SELECT * FROM accounts WHERE id = $1', [request.params.id]); // expect: AUTHZ-001
  return rows[0];
});
