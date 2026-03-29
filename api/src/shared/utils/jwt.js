import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import AppError from './AppError.js';

// ─────────────────────────────────────────────
// ALLOWED ALGORITHM (single source of truth)
// ─────────────────────────────────────────────
const ALLOWED_ALGORITHM = 'HS256';
const ALLOWED_ALGORITHMS = [ALLOWED_ALGORITHM];

// ─────────────────────────────────────────────
// ENV VALIDATION
// ─────────────────────────────────────────────
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
  throw new Error('JWT secrets are not defined');
}

const ACCESS_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

const ACCESS_EXPIRES = process.env.JWT_EXPIRES_IN || '15m';
const TEMP_EXPIRES = '5m';
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
      algorithm: ALLOWED_ALGORITHM,
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
      algorithm: ALLOWED_ALGORITHM,
      jwtid: jti, // session id
    }
  );
};

// ─────────────────────────────────────────────
// GENERATE TEMP TOKEN (FOR MFA)
// ─────────────────────────────────────────────
export const generateTempToken = (payload) => {
  const jti = crypto.randomUUID();
  return jwt.sign(
    {
      sub: payload.sub || payload.id,
      type: 'temp',
      jti,
    },
    ACCESS_SECRET,
    {
      expiresIn: TEMP_EXPIRES,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: ALLOWED_ALGORITHM,
    }
  );
};

// ─────────────────────────────────────────────
// STRUCTURAL PRE-VALIDATION (defense-in-depth)
// Rejects malformed tokens before they reach
// jwt.verify(), preventing edge-case parser bugs.
// ─────────────────────────────────────────────
const BLOCKED_ALGORITHMS = new Set([
  'none', 'None', 'NONE', 'nOnE',  // CVE-2015-9235 variants
]);

const validateTokenStructure = (token) => {
  if (typeof token !== 'string' || !token.length) {
    throw new AppError('Token is empty or not a string', 401, 'TOKEN_MALFORMED');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new AppError(
      `Token must have 3 parts, found ${parts.length}`,
      401,
      'TOKEN_MALFORMED'
    );
  }

  // Reject empty signature segment (alg:none attack indicator)
  if (!parts[2] || parts[2].trim().length === 0) {
    throw new AppError(
      'Token has empty signature — possible alg:none attack',
      401,
      'SIGNATURE_MISSING'
    );
  }

  // Decode header to check algorithm before verification
  try {
    const headerStr = Buffer.from(parts[0], 'base64url').toString('utf8');
    const header = JSON.parse(headerStr);

    if (BLOCKED_ALGORITHMS.has(header.alg)) {
      throw new AppError(
        `Blocked algorithm: ${header.alg}`,
        401,
        'ALGORITHM_NOT_ALLOWED'
      );
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError('Token header is malformed', 401, 'TOKEN_MALFORMED');
  }
};

// ─────────────────────────────────────────────
// VERIFY ACCESS TOKEN
// ─────────────────────────────────────────────
export const verifyAccessToken = (token) => {
  try {
    // Phase 1: Structural pre-validation
    validateTokenStructure(token);

    // Phase 2: Cryptographic verification (signature + expiry + claims)
    const decoded = jwt.verify(token, ACCESS_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ALLOWED_ALGORITHMS,  // ONLY HS256 — rejects alg:none
      clockTolerance: 5,
      ignoreExpiration: false,          // explicit: never skip expiry check
    });

    // Phase 3: Business-logic claim validation
    if (!decoded.sub || decoded.type !== 'access') {
      throw new AppError('Invalid token payload', 401, 'TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    // Re-throw AppErrors from pre-validation as-is (preserve specific codes)
    if (err instanceof AppError) throw err;

    if (err.name === 'TokenExpiredError') {
      throw new AppError('Access token expired', 401, 'TOKEN_EXPIRED');
    }
    if (err.name === 'JsonWebTokenError') {
      throw new AppError(
        `JWT verification failed: ${err.message}`,
        401,
        'SIGNATURE_INVALID'
      );
    }
    throw new AppError('Invalid access token', 401, 'TOKEN_INVALID');
  }
};

// ─────────────────────────────────────────────
// VERIFY REFRESH TOKEN
// ─────────────────────────────────────────────
export const verifyRefreshToken = (token) => {
  try {
    validateTokenStructure(token);

    const decoded = jwt.verify(token, REFRESH_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ALLOWED_ALGORITHMS,
      clockTolerance: 5,
      ignoreExpiration: false,
    });

    if (!decoded.sub || decoded.type !== 'refresh' || !decoded.jti) {
      throw new AppError('Invalid refresh token payload', 401, 'REFRESH_TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (err.name === 'TokenExpiredError') {
      throw new AppError('Refresh token expired', 401, 'REFRESH_TOKEN_EXPIRED');
    }
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }
};

// ─────────────────────────────────────────────
// VERIFY TEMP TOKEN
// ─────────────────────────────────────────────
export const verifyTempToken = (token) => {
  try {
    validateTokenStructure(token);

    const decoded = jwt.verify(token, ACCESS_SECRET, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ALLOWED_ALGORITHMS,
      clockTolerance: 5,
      ignoreExpiration: false,
    });

    if (!decoded.sub || decoded.type !== 'temp' || !decoded.jti) {
      throw new AppError('Invalid temp token or missing JTI', 401, 'TOKEN_INVALID');
    }

    return decoded;
  } catch (err) {
    if (err instanceof AppError) throw err;
    if (err.name === 'TokenExpiredError') {
      throw new AppError('Temporary token expired', 401, 'TOKEN_EXPIRED');
    }
    throw new AppError('Invalid temp token', 401, 'TOKEN_INVALID');
  }
};