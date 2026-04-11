import { randomUUID } from 'crypto';

export default function correlationId(req, res, next) {
  const incoming = req.headers['x-correlation-id'];
  req.correlationId = incoming || randomUUID();
  res.setHeader('x-correlation-id', req.correlationId);
  next();
}
