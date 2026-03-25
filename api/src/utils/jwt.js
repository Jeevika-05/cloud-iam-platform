import jwt from 'jsonwebtoken';
import AppError from './AppError.js';

// ───────────────────────────────────────────────────────────
// ENV VALIDATION (CRITICAL)
// ───────────────────────────────────────────────────────────
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error('JWT secrets are not defined in environment variables');
}

const ACCESS_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

const ACCESS_EXPIRES = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

const ISSUER = 'cloud-iam-platform';
const AUDIENCE = 'cloud-iam-users';

// ───────────────────────────────────────────────────────────
// GENERATE ACCESS TOKEN
// ───────────────────────────────────────────────────────────
export const generateAccessToken = (payload) => {
  return jwt.sign(
    {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
    },
    ACCESS_SECRET,
    {
      expiresIn: ACCESS_EXPIRES,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256', // 🔐 Explicit algorithm
    }
  );
};

// ───────────────────────────────────────────────────────────
// GENERATE REFRESH TOKEN
// ───────────────────────────────────────────────────────────
export const generateRefreshToken = (payload) => {
  return jwt.sign(
    {
      sub: payload.sub,
    },
    REFRESH_SECRET,
    {
      expiresIn: REFRESH_EXPIRES,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
    }
  );
};

// ───────────────────────────────────────────────────────────
// VERIFY ACCESS TOKEN
// ───────────────────────────────────────────────────────────
export const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, ACCESS_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'], // 🔐 restrict allowed algos
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new AppError('Access token has expired', 401, 'TOKEN_EXPIRED');
    }
    throw new AppError('Invalid access token', 401, 'TOKEN_INVALID');
  }
};

// ───────────────────────────────────────────────────────────
// VERIFY REFRESH TOKEN
// ───────────────────────────────────────────────────────────
export const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, REFRESH_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new AppError('Refresh token has expired', 401, 'REFRESH_TOKEN_EXPIRED');
    }
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }
};