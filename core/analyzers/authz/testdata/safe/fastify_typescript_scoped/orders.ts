import Fastify from 'fastify';
import { prisma } from './db';

const app = Fastify();

app.get<{ Params: { id: string } }>('/orders/:id', { onRequest: [app.authenticate] }, async (request, reply) => {
  const { id } = request.params as { id: string };
  const order = await prisma.order.findUnique({ where: { id } });
  if (!order || order.userId !== request.user.id) {
    return reply.code(404).send();
  }
  return order;
});
