const fastify = require('fastify')();
const db = require('./db');

fastify.delete('/documents/:docId', async (request, reply) => {
  await request.jwtVerify();
  await db.query('DELETE FROM documents WHERE id = $1', [request.params.docId]); // expect: AUTHZ-001
  return reply.code(204).send();
});
