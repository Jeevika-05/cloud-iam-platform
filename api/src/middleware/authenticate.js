import { verifyAccessToken } from '../utils/jwt.js';
import AppError from '../utils/AppError.js';
import prisma from '../config/database.js';
import logger from '../utils/logger.js';

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // ─────────────────────────────────────────────
    // 1. Validate Authorization Header
    // ─────────────────────────────────────────────
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError(
        'Authorization header missing or malformed',
        401,
        'AUTH_REQUIRED'
      );
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
      throw new AppError('Token missing', 401, 'AUTH_REQUIRED');
    }

    // ─────────────────────────────────────────────
    // 2. Verify JWT
    // ─────────────────────────────────────────────
    const decoded = verifyAccessToken(token);

    // ─────────────────────────────────────────────
    // 3. Validate payload (defensive check)
    // ─────────────────────────────────────────────
    if (!decoded.sub) {
      throw new AppError('Invalid token payload', 401, 'TOKEN_INVALID');
    }

    // ─────────────────────────────────────────────
    // 4. Check user still exists
    // ─────────────────────────────────────────────
    const user = await prisma.user.findUnique({
      where: { id: decoded.sub },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
      },
    });

    if (!user) {
      throw new AppError('User no longer exists', 401, 'USER_NOT_FOUND');
    }

    // ─────────────────────────────────────────────
    // 5. Attach user to request
    // ─────────────────────────────────────────────
    req.user = user;

    // Optional: attach token payload if needed later
    req.auth = decoded;

    next();

  } catch (err) {
    // 🔐 Optional: log suspicious access attempts
    logger.warn('AUTH_FAILURE', {
      path: req.originalUrl,
      ip: req.ip,
      error: err.message,
    });

    next(err);
  }
};

export default authenticate;