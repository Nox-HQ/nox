const fastify = require('fastify')();
const db = require('./db');

fastify.get('/documents/:id', { onRequest: [fastify.authenticate] }, async (request, reply) => {
  const { rows } = await db.query('SELECT * FROM documents WHERE id = $1', [request.params.id]);
  const doc = rows[0];
  if (!doc) return reply.code(404).send();
  if (doc.owner_id !== request.user.id) return reply.code(403).send({ error: 'forbidden' });
  return doc;
});
