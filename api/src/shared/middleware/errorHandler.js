import logger from '../utils/logger.js';
import AppError from '../utils/AppError.js';

// ───────────────────────────────────────────────────────────
// Handle Prisma-specific errors
// ───────────────────────────────────────────────────────────
const handlePrismaError = (err) => {
  switch (err.code) {
    case 'P2002':
      return new AppError(
        `A record with this ${err.meta?.target?.join(', ')} already exists`,
        409,
        'DUPLICATE_ENTRY'
      );

    case 'P2025':
      return new AppError('Record not found', 404, 'NOT_FOUND');

    case 'P2003':
      return new AppError('Related record not found', 400, 'FOREIGN_KEY_ERROR');

    default:
      return new AppError('Database operation failed', 500, 'DB_ERROR');
  }
};

// ───────────────────────────────────────────────────────────
// Main Error Handler
// ───────────────────────────────────────────────────────────
export const errorHandler = (err, req, res, next) => {
  let error = err;

  // ─────────────────────────────────────────────
  // 1. Normalize unknown errors
  // ─────────────────────────────────────────────
  if (!(error instanceof AppError)) {
    error = new AppError(err.message || 'Internal Server Error', 500, 'INTERNAL_ERROR');
  }

  // ─────────────────────────────────────────────
  // 2. Handle Prisma errors
  // ─────────────────────────────────────────────
  if (err.constructor?.name === 'PrismaClientKnownRequestError') {
    error = handlePrismaError(err);
  }

  // ─────────────────────────────────────────────
  // 3. Handle JWT errors
  // ─────────────────────────────────────────────
  if (err.name === 'JsonWebTokenError') {
    error = new AppError('Invalid token', 401, 'TOKEN_INVALID');
  }

  if (err.name === 'TokenExpiredError') {
    error = new AppError('Token has expired', 401, 'TOKEN_EXPIRED');
  }

  const statusCode = error.statusCode || 500;
  const isProduction = process.env.NODE_ENV === 'production';

  // ─────────────────────────────────────────────
  // 4. Structured logging (VERY IMPORTANT)
  // ─────────────────────────────────────────────
  if (statusCode >= 500) {
    logger.error('SERVER_ERROR', {
      message: err.message,
      stack: err.stack,
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userId: req.user?.id || null,
    });
  } else {
    logger.warn('CLIENT_ERROR', {
      message: error.message,
      code: error.code,
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userId: req.user?.id || null,
    });
  }

  // ─────────────────────────────────────────────
  // 5. Safe response (NO leakage)
  // ─────────────────────────────────────────────
  const responsePayload = {
    success: false,
    code: error.code || 'INTERNAL_ERROR',
    message: error.isOperational || !isProduction ? error.message : 'An unexpected error occurred',
  };

  if (error.errors) {
    responsePayload.errors = error.errors;
  }

  if (!isProduction) {
    responsePayload.stack = err.stack;
  }

  res.status(statusCode).json(responsePayload);
};
// ───────────────────────────────────────────────────────────
// 404 Handler
// ───────────────────────────────────────────────────────────
export const notFoundHandler = (req, res, next) => {
  next(
    new AppError(
      `Route ${req.method} ${req.originalUrl} not found`,
      404,
      'NOT_FOUND'
    )
  );
};