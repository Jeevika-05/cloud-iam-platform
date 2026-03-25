import rateLimit from 'express-rate-limit';

/**
 * 🔐 General API Rate Limiter
 * Used for normal endpoints
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // allow more requests
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many requests. Please try again later.'
  }
});


/**
 * 🔐 Strict Auth Rate Limiter (LOGIN / REGISTER)
 * Protects against brute-force attacks
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // very strict
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many login attempts. Try again after 15 minutes.'
  }
});


/**
 * 🔐 Admin Rate Limiter (very sensitive routes)
 */
export const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many admin requests. Slow down.'
  }
});