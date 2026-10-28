const db = require('../db');

module.exports = async function (fastify, opts) {
  fastify.addHook('onRequest', fastify.authenticate);

  fastify.get('/:id', async (request, reply) => {
    const { rows } = await db.query('SELECT * FROM invoices WHERE id = $1', [request.params.id]); // expect: AUTHZ-001
    return rows[0];
  });
};
