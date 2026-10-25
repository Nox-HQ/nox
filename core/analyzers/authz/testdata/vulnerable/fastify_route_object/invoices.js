const fastify = require('fastify')({ logger: true });
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

fastify.route({
  method: 'GET',
  url: '/invoices/:invoiceId',
  onRequest: [fastify.authenticate],
  handler: async (request, reply) => {
    const invoice = await prisma.invoice.findUnique({ where: { id: request.params.invoiceId } }); // expect: AUTHZ-001
    return invoice;
  },
});
