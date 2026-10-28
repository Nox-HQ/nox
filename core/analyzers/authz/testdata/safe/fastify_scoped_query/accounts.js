const fastify = require('fastify')();
const db = require('./db');

fastify.get('/v2/accounts/:id', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { rows } = await db.query('SELECT * FROM accounts WHERE id = $1 AND owner_id = $2', [request.params.id, request.user.sub]);
  return rows[0];
});
