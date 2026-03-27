import jwt from 'jsonwebtoken';
import AppError from './AppError.js';

// ─────────────────────────────────────────────
// ENV VALIDATION
// ─────────────────────────────────────────────
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error('JWT secrets are not defined');
}

const ACCESS_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

const ACCESS_EXPIRES = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

const ISSUER = 'cloud-iam-platform';
const AUDIENCE = 'cloud-iam-users';

// ─────────────────────────────────────────────
// GENERATE ACCESS TOKEN
// ─────────────────────────────────────────────
export const generateAccessToken = (payload) => {
  return jwt.sign(
    {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
      type: 'access',
      jti: payload.jti, // include session id for potential revocation
    },
    ACCESS_SECRET,
    {
      expiresIn: ACCESS_EXPIRES,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
    }
  );
};

// ─────────────────────────────────────────────
// GENERATE REFRESH TOKEN
// ─────────────────────────────────────────────
export const generateRefreshToken = (payload, jti) => {
  return jwt.sign(
    {
      sub: payload.sub,
      type: 'refresh', // 🔥 prevent misuse
    },
    REFRESH_SECRET,
    {
      expiresIn: REFRESH_EXPIRES,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: 'HS256',
      jwtid: jti, // session id
    }
  );
};

// ─────────────────────────────────────────────
// VERIFY ACCESS TOKEN
// ─────────────────────────────────────────────
export const verifyAccessToken = (token) => {
  try {
    const decoded = jwt.verify(token, ACCESS_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
      clockTolerance: 5,
    });

    if (!decoded.sub || decoded.type !== 'access') {
      throw new AppError('Invalid token payload', 401, 'TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new AppError('Access token expired', 401, 'TOKEN_EXPIRED');
    }
    throw new AppError('Invalid access token', 401, 'TOKEN_INVALID');
  }
};

// ─────────────────────────────────────────────
// VERIFY REFRESH TOKEN
// ─────────────────────────────────────────────
export const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, REFRESH_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'],
      clockTolerance: 5,
    });

    if (!decoded.sub || decoded.type !== 'refresh' || !decoded.jti) {
      throw new AppError('Invalid refresh token payload', 401, 'REFRESH_TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      throw new AppError('Refresh token expired', 401, 'REFRESH_TOKEN_EXPIRED');
    }
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }
};