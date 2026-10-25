const fastify = require('fastify')();
const db = require('./db');

fastify.get('/products/:id', async (request, reply) => {
  const { rows } = await db.query('SELECT * FROM products WHERE id = $1', [request.params.id]);
  return rows[0];
});
