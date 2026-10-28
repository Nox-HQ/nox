module.exports = async function (fastify, opts) {
  fastify.addHook('preHandler', fastify.authenticate);

  fastify.get('/:id', async (request, reply) => {
    const note = await fastify.mongo.db.collection('notes').findOne({ _id: request.params.id, userId: request.user.id });
    return note;
  });
};
