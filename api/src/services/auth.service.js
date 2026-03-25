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
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  const { password: _, ...safeUser } = user;

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  logger.info('LOGIN_SUCCESS', { userId: user.id });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// REFRESH TOKEN (ROTATION)
// ─────────────────────────────────────────────
export const refresh = async (token, { ipAddress, userAgent }) => {
  const decoded = verifyRefreshToken(token);

  if (!decoded?.jti) {
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  const session = await prisma.session.findUnique({
    where: { id: decoded.jti },
    include: { user: true },
  });

  // 🔥 CRITICAL VALIDATION
  if (!session || session.expiresAt < new Date()) {
    throw new AppError('Session expired or invalid', 401, 'REFRESH_TOKEN_INVALID');
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

  // 🔄 ROTATION: delete old session
  await prisma.session.delete({
    where: { id: decoded.jti },
  });

  const { password: _, ...safeUser } = session.user;

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  logger.info('TOKEN_REFRESH', { userId: safeUser.id });

  return tokens;
};

// ─────────────────────────────────────────────
// LOGOUT (CURRENT SESSION)
// ─────────────────────────────────────────────
export const logout = async (token) => {
  const decoded = verifyRefreshToken(token);

  if (!decoded?.jti) {
    throw new AppError('Invalid token', 401, 'LOGOUT_FAILED');
  }

  const session = await prisma.session.findUnique({
    where: { id: decoded.jti },
  });

  if (!session) {
    throw new AppError('Session already invalid', 400, 'LOGOUT_FAILED');
  }

  await prisma.session.delete({
    where: { id: decoded.jti },
  });

  logger.info('LOGOUT_SUCCESS', { userId: decoded.sub });
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

  if (!session) {
    throw new AppError('Session not found', 404, 'NOT_FOUND');
  }

  if (session.userId !== userId) {
    throw new AppError('Forbidden', 403, 'FORBIDDEN');
  }

  await prisma.session.delete({
    where: { id: sessionId },
  });

  logger.info('SESSION_REVOKED', { userId, sessionId });
};

// ─────────────────────────────────────────────
// REVOKE ALL SESSIONS
// ─────────────────────────────────────────────
export const revokeAllSessions = async (userId) => {
  await prisma.session.deleteMany({
    where: { userId },
  });

  logger.info('ALL_SESSIONS_REVOKED', { userId });
};

// ─────────────────────────────────────────────
// INTERNAL: ISSUE TOKENS
// ─────────────────────────────────────────────
const issueTokens = async (user, { ipAddress, userAgent } = {}) => {
  // 🔒 Limit active sessions
  const sessions = await prisma.session.findMany({
    where: { userId: user.id },
    orderBy: { createdAt: 'asc' },
  });

  if (sessions.length >= MAX_SESSIONS) {
    await prisma.session.delete({
      where: { id: sessions[0].id },
    });
  }

  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
  };

  const jti = crypto.randomUUID();

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload, jti);

  const decoded = jwt.decode(refreshToken);
  const expiresAt = new Date(decoded.exp * 1000);

  await prisma.session.create({
    data: {
      id: jti,
      userId: user.id,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      expiresAt,
    },
  });

  return { accessToken, refreshToken };
};