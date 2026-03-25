import winston from 'winston';

const { combine, timestamp, errors, json, colorize, printf } = winston.format;

// ───────────────────────────────────────────────────────────
// Custom log format for development
// ───────────────────────────────────────────────────────────
const devFormat = printf(({ level, message, timestamp, stack, ...meta }) => {
  return `${timestamp} [${level}]: ${stack || message} ${
    Object.keys(meta).length ? JSON.stringify(meta) : ''
  }`;
});

// ───────────────────────────────────────────────────────────
// Logger instance
// ───────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',

  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    json()
  ),

  defaultMeta: {
    service: 'cloud-iam-platform',
  },

  transports: [
    // Console transport
    new winston.transports.Console({
      format:
        process.env.NODE_ENV === 'production'
          ? combine(timestamp(), json())
          : combine(colorize(), devFormat),
    }),
  ],
});

export default logger;