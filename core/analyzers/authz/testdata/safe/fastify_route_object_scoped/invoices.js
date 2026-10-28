const fastify = require('fastify')();
const prisma = require('./prisma');

fastify.route({
  method: 'GET',
  url: '/invoices/:invoiceId',
  preHandler: fastify.auth([fastify.verifyJWT]),
  handler: async (request, reply) => {
    return prisma.invoice.findFirst({ where: { id: request.params.invoiceId, ownerId: request.user.sub } });
  },
});
