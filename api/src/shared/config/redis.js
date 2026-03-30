import Redis from 'ioredis';
import logger from '../utils/logger.js';

const redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

// 🔒 SEC-16: Use structured Winston logger instead of console
redisClient.on('connect', () => {
  logger.info('Connected to Redis successfully');
});

redisClient.on('error', (err) => {
  logger.error('Redis Connection Error', { error: err.message });
});

export default redisClient;
