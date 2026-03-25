import bcrypt from 'bcryptjs';
import prisma from '../config/database.js';
import AppError from '../utils/AppError.js';
import logger from '../utils/logger.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from '../utils/jwt.js';

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// ───────────────────────────────────────────────────────────
// REGISTER
// ───────────────────────────────────────────────────────────
export const register = async ({ name, email, password }) => {
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
      role: 'USER', // 🔐 Prevent role injection
    },
    select: {
      id: true,
      name: true,
      email: true,
      role: true,
      createdAt: true,
    },
  });

  const tokens = await issueTokens(user);

  logger.info('REGISTER_SUCCESS', { userId: user.id, email: user.email });

  return { user, ...tokens };
};

// ───────────────────────────────────────────────────────────
// LOGIN
// ───────────────────────────────────────────────────────────
export const login = async ({ email, password }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  // Prevent user enumeration
  if (!user) {
    await bcrypt.compare(password, '$2b$12$invalidhashplaceholderXXXXXXXXXXXXXXXXXXXXXXXXXX');
    logger.warn('LOGIN_FAILED', { email: normalizedEmail });
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    logger.warn('LOGIN_FAILED', { userId: user.id });
    throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  const { password: _, refreshToken: __, ...safeUser } = user;

  const tokens = await issueTokens(safeUser);

  logger.info('LOGIN_SUCCESS', { userId: user.id });

  return { user: safeUser, ...tokens };
};

// ───────────────────────────────────────────────────────────
// REFRESH TOKEN
// ───────────────────────────────────────────────────────────
export const refresh = async (token) => {
  const decoded = verifyRefreshToken(token);

  const user = await prisma.user.findUnique({
    where: { id: decoded.sub },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      refreshToken: true,
    },
  });

  if (!user) {
    throw new AppError('Invalid token', 401, 'REFRESH_TOKEN_INVALID');
  }

  // 🔐 Compare hashed refresh token
  const isValid = await bcrypt.compare(token, user.refreshToken || '');

  if (!isValid) {
    throw new AppError('Invalid or revoked refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  const tokens = await issueTokens(user);

  logger.info('TOKEN_REFRESH', { userId: user.id });

  return tokens;
};

// ───────────────────────────────────────────────────────────
// LOGOUT
// ───────────────────────────────────────────────────────────
export const logout = async (userId) => {
  await prisma.user.update({
    where: { id: userId },
    data: { refreshToken: null },
  });

  logger.info('LOGOUT_SUCCESS', { userId });
};

// ───────────────────────────────────────────────────────────
// GET PROFILE
// ───────────────────────────────────────────────────────────
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

// ───────────────────────────────────────────────────────────
// INTERNAL: ISSUE TOKENS
// ───────────────────────────────────────────────────────────
const issueTokens = async (user) => {
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
  };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  // 🔐 Store hashed refresh token (CRITICAL SECURITY)
  const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken: hashedRefreshToken },
  });

  return { accessToken, refreshToken };
};