import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import prisma from '../config/database.js';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from '../utils/jwt.js';
import { SECURITY_CONFIG } from '../config/security.js';

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;
const MAX_SESSIONS = 5; // optional limit

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async ({ name, email, password, ipAddress, userAgent }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (existing) {
    throw new AppError('Email already registered', 409, 'DUPLICATE_EMAIL');
  }

  const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

  const user = await prisma.user.create({
    data: {
      name,
      email: normalizedEmail,
      password: hashedPassword,
      role: 'USER',
    },
  });

  const { password: _, ...safeUser } = user;

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  logger.info('REGISTER_SUCCESS', { userId: user.id });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
export const login = async ({ email, password, ipAddress, userAgent }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  // Prevent user enumeration
  if (!user) {
    await bcrypt.compare(password, '$2b$12$invalidhashplaceholderXXXXXXXXXXXXXXXXXXXXXXXXXX');
    logger.warn('LOGIN_FAILED', { email: normalizedEmail, ip: ipAddress });
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  // Account Lockout Protection
  if (user.lockUntil && user.lockUntil > new Date()) {
    logger.warn('ACCOUNT_LOCKED_ATTEMPT', { userId: user.id, ip: ipAddress });
    throw new AppError(
  'Account temporarily locked due to multiple failed attempts',
  403,
  'ACCOUNT_LOCKED'
);
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    // Increment failedLoginAttempts
    const attempts = (user.failedLoginAttempts || 0) + 1;
    let lockUntil = user.lockUntil;

    if (attempts >= SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS) {
      lockUntil = new Date(Date.now() + SECURITY_CONFIG.LOCK_TIME);

      await prisma.session.updateMany({
        where: { userId: user.id },
        data: { revoked: true }
      });

      logger.warn('ALL_SESSIONS_REVOKED_ON_LOCK', {
        userId: user.id
      });
      logger.warn('ACCOUNT_LOCKED', { userId: user.id, ip: ipAddress });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: attempts, lockUntil }
    });

    logger.warn('LOGIN_FAILED', { userId: user.id, ip: ipAddress });
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  // Reset counters on successful login
  if (user.failedLoginAttempts > 0 || user.lockUntil) {
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockUntil: null }
    });
  }

  const { password: _, ...safeUser } = user;

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  logger.info('LOGIN_SUCCESS', { userId: user.id, ip: ipAddress });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// REFRESH TOKEN (ROTATION)
// ─────────────────────────────────────────────
export const refresh = async (token, { ipAddress, userAgent }) => {
  if (!token) {
    throw new AppError('Refresh token missing', 401, 'REFRESH_TOKEN_MISSING');
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch (err) {
    // Basic verify failed, but could be reuse/compromise attempts
    const attemptDecoded = jwt.decode(token);
    if (attemptDecoded?.sub) {
       logger.warn('TOKEN_REUSE_DETECTED_INVALID_SIG', { userId: attemptDecoded.sub, ipAddress });
    }
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  if (!decoded?.jti || !decoded?.sub) {
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  const session = await prisma.session.findUnique({
    where: { id: decoded.jti },
    include: { user: true },
  });

  // 🔥 CRITICAL VALIDATION & Replay Attack Detection
  if (!session || session.revoked) {
    logger.warn('TOKEN_REUSE_DETECTED', { userId: decoded.sub, jti: decoded.jti, ipAddress });
    await prisma.session.updateMany({
      where: { userId: decoded.sub },
      data: { revoked: true }
    });
    throw new AppError('Session compromised', 401, 'SESSION_COMPROMISED');
  }

  if (session.expiresAt < new Date()) {
    throw new AppError('Session expired or invalid', 401, 'REFRESH_TOKEN_INVALID');
  }

  const user = session.user;

  if (user.lockUntil && user.lockUntil > new Date()) {
    logger.warn('REFRESH_BLOCKED_ACCOUNT_LOCKED', {
      userId: user.id,
      ipAddress
    });

    throw new AppError(
      'Account temporarily locked',
      403,
      'ACCOUNT_LOCKED'
    );
  }

  // Validate hashed token
  if (session.refreshTokenHash) {
    const isTokenMatch = await bcrypt.compare(token, session.refreshTokenHash);
    if (!isTokenMatch) {
      logger.warn('TOKEN_REUSE_DETECTED', { userId: session.userId, jti: decoded.jti, ipAddress });
      await prisma.session.updateMany({
        where: { userId: session.userId },
        data: { revoked: true }
      });
      throw new AppError('Session compromised', 401, 'SESSION_COMPROMISED');
    }
  }

  // 🔐 OPTIONAL: Device/IP check (log suspicious activity)
  if (
    (session.ipAddress && session.ipAddress !== ipAddress) ||
    (session.userAgent && session.userAgent !== userAgent)
  ) {
    logger.warn('SUSPICIOUS_SESSION_USE', {
      userId: session.userId,
      originalIp: session.ipAddress,
      currentIp: ipAddress,
    });
  }

  // 🔄 ROTATION: mark old session revoked instead of deleting
  await prisma.session.update({
    where: { id: decoded.jti },
    data: { revoked: true }
  });

  const { password: _, ...safeUser } = session.user;

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  logger.info('TOKEN_ROTATED', { userId: safeUser.id, oldJti: decoded.jti });

  return tokens;
};

// ─────────────────────────────────────────────
// LOGOUT (CURRENT SESSION)
// ─────────────────────────────────────────────
export const logout = async (token) => {
  if (!token) {
    throw new AppError('Token missing', 401, 'LOGOUT_FAILED');
  }

  const decoded = verifyRefreshToken(token);

  if (!decoded?.jti) {
    throw new AppError('Invalid token', 401, 'LOGOUT_FAILED');
  }

  const session = await prisma.session.findUnique({
    where: { id: decoded.jti },
  });

  if (!session || session.revoked) {
    throw new AppError('Session already invalid', 400, 'LOGOUT_FAILED');
  }

  // 🚪 Logical logout (audit preserve)
  await prisma.session.update({
    where: { id: decoded.jti },
    data: { revoked: true }
  });

  logger.info('LOGOUT', { userId: decoded.sub, jti: decoded.jti });
};

// ─────────────────────────────────────────────
// GET PROFILE
// ─────────────────────────────────────────────
export const getProfile = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      email: true,
      role: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!user) {
    throw new AppError('User not found', 404, 'NOT_FOUND');
  }

  return user;
};

// ─────────────────────────────────────────────
// GET ACTIVE SESSIONS
// ─────────────────────────────────────────────
export const getActiveSessions = async (userId) => {
  return prisma.session.findMany({
    where: {
      userId,
      revoked: false,
      expiresAt: { gt: new Date() },
    },
    select: {
      id: true,
      userAgent: true,
      ipAddress: true,
      createdAt: true,
      expiresAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });
};

// ─────────────────────────────────────────────
// GET CURRENT SESSION
// ─────────────────────────────────────────────
export const getCurrentSession = async (jti) => {
  const session = await prisma.session.findUnique({
    where: { id: jti },
  });

  if (!session) {
    throw new AppError('Session not found', 404, 'NOT_FOUND');
  }

  return session;
};

// ─────────────────────────────────────────────
// REVOKE SINGLE SESSION
// ─────────────────────────────────────────────
export const revokeSession = async (sessionId, userId) => {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
  });

  if (!session || session.revoked) {
    throw new AppError('Session not found', 404, 'NOT_FOUND');
  }

  if (session.userId !== userId) {
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }

  await prisma.session.update({
    where: { id: sessionId },
    data: { revoked: true }
  });

  logger.info('SESSION_REVOKED', { userId, sessionId });
};

// ─────────────────────────────────────────────
// REVOKE ALL SESSIONS
// ─────────────────────────────────────────────
export const revokeAllSessions = async (userId) => {
  await prisma.session.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true }
  });

  logger.info('ALL_SESSIONS_REVOKED', { userId });
};

// ─────────────────────────────────────────────
// INTERNAL: ISSUE TOKENS
// ─────────────────────────────────────────────
const issueTokens = async (user, { ipAddress, userAgent } = {}) => {
  // 🔒 Limit active sessions
  const sessions = await prisma.session.findMany({
    where: { userId: user.id, revoked: false },
    orderBy: { createdAt: 'asc' },
  });

  if (sessions.length >= MAX_SESSIONS) {
    await prisma.session.update({
      where: { id: sessions[0].id },
      data: { revoked: true }
    });
  }
  const jti = crypto.randomUUID();
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    jti:jti
  };

 
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload, jti);

  const decoded = jwt.decode(refreshToken);
  const expiresAt = new Date(decoded.exp * 1000);

  // 🔄 Hash refresh token for secure storage
  const refreshTokenHash = await bcrypt.hash(refreshToken, BCRYPT_ROUNDS);

  await prisma.session.create({
    data: {
      id: jti,
      userId: user.id,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      expiresAt,
      refreshTokenHash,
      revoked: false
    },
  });

  return { accessToken, refreshToken };
};