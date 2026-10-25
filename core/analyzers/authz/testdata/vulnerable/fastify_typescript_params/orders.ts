import Fastify from 'fastify';
import { prisma } from './db';

const app = Fastify();

app.get<{ Params: { id: string } }>('/orders/:id', { onRequest: [app.authenticate] }, async (request, reply) => {
  const { id } = request.params as { id: string };
  return prisma.order.findUnique({ where: { id } }); // expect: AUTHZ-001
});
