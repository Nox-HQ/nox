import { Router } from 'express';
import { prisma } from '../db';
import { authenticate } from '../middleware/auth';

export const documents = Router();
documents.use(authenticate);

documents.get('/:documentId', async (req, res) => {
  const doc = await prisma.document.findUnique({ where: { id: req.params.documentId } }); // expect: AUTHZ-001
  if (!doc) return res.sendStatus(404);
  return res.json(doc);
});
