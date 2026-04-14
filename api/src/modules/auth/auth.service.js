import crypto from 'crypto';
import jwtLib from 'jsonwebtoken';
import prisma from '../../shared/config/database.js';
import redisClient from '../../shared/config/redis.js';
import config from '../../shared/config/index.js';
import AppError from '../../shared/utils/AppError.js';
import logger from '../../shared/utils/logger.js';
import { hashPassword, verifyPassword, dummyVerify } from '../../shared/utils/password.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateTempToken,
  verifyTempToken
} from '../../shared/utils/jwt.js';
import { logSecurityEvent } from './audit.service.js';
import { SECURITY_CONFIG } from '../../shared/config/security.js';
import { 
  accountLockCounter, sessionSecurityCounter, 
  loginFailuresTotal, mfaFailuresTotal, distributedMfaLockTotal 
} from '../../metrics/metrics.js';

const MAX_SESSIONS = config.security.maxSessions;

// ─────────────────────────────────────────────
// ROLE RESOLUTION (Auth vs Authorization separation)
// ─────────────────────────────────────────────
/**
 * Resolves the IAM role for a new OAuth-provisioned user.
 *
 * Security rules (in order):
 *   0. OAUTH_ADMIN_ENABLED must be 'true' — otherwise all users are forced to 'USER'
 *   1. Email must be verified by the identity provider
 *   2. Email in ADMIN_EMAILS allowlist → ADMIN
 *   3. Email domain matches ADMIN_DOMAIN → ADMIN
 *      - If ADMIN_DOMAIN_STRICT=true, email must also be verified (enforced above)
 *   4. Default → 'USER'
 *
 * NOTE: Called ONLY for net-new provisioning.
 *       Existing users keep their db role — this function never runs for them.
 *
 * @param {string}  email         - Normalized (lowercase, trimmed) email
 * @param {boolean} emailVerified - Whether the identity provider verified the email
 * @returns {'ADMIN'|'USER'}
 */
function resolveUserRole(email, emailVerified) {
  // 0. Feature flag: opt-in to any OAuth admin assignment (safe default: off)
  if (process.env.OAUTH_ADMIN_ENABLED !== 'true') {
    return { role: 'USER', roleSource: 'DEFAULT' };
  }

  // 1. Unverified emails may NEVER receive elevated roles
  if (!emailVerified) {
    logger.warn('OAUTH_ROLE_RESOLUTION_SKIPPED_UNVERIFIED', { email });
    return { role: 'USER', roleSource: 'DEFAULT' };
  }

  const adminEmails = (process.env.ADMIN_EMAILS || '')
    .split(',')
    .map(e => e.trim().toLowerCase())
    .filter(Boolean);

  const adminDomain = (process.env.ADMIN_DOMAIN || '').trim().toLowerCase();

  // Safe-default guard: warn operators if neither source is configured
  if (!adminEmails.length && !adminDomain) {
    logger.warn('OAUTH_ADMIN_CONFIG_MISSING', {
      message: 'OAUTH_ADMIN_ENABLED=true but no ADMIN_EMAILS or ADMIN_DOMAIN configured — all users default to USER',
    });
  }

  // 2. Explicit email allowlist check
  if (adminEmails.includes(email)) {
    logger.warn('ADMIN_ROLE_ASSIGNED', { email, reason: 'ADMIN_EMAILS', provider: 'google' });
    return { role: 'PENDING_ADMIN', roleSource: 'ADMIN_EMAILS' };
  }

  // 3. Domain-based grant
  if (adminDomain && email.endsWith(`@${adminDomain}`)) {
    // ADMIN_DOMAIN_STRICT: require verified email (already guaranteed above, but log clearly)
    if (process.env.ADMIN_DOMAIN_STRICT === 'true' && !emailVerified) {
      logger.warn('OAUTH_DOMAIN_ADMIN_BLOCKED_UNVERIFIED', { email, adminDomain });
      return { role: 'USER', roleSource: 'DEFAULT' };
    }
    logger.warn('ADMIN_ROLE_ASSIGNED', { email, reason: 'ADMIN_DOMAIN', provider: 'google' });
    return { role: 'PENDING_ADMIN', roleSource: 'ADMIN_DOMAIN' };
  }

  return { role: 'USER', roleSource: 'DEFAULT' };
}

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async ({ name, email, password, ipAddress, userAgent, correlationId }) => {
  const regKey = `velocity:reg:${ipAddress}`;
  const regCount = await redisClient.incr(regKey);
  if (regCount === 1) await redisClient.expire(regKey, 3600);

  if (regCount > 5) {
    await logSecurityEvent({ action: 'REGISTRATION_RATE_EXCEEDED', status: 'FAILURE', ip: ipAddress, correlationId });
    throw new AppError('Too many registrations from this IP. Try again later.', 429, 'RATE_LIMIT_EXCEEDED');
  }

  const normalizedEmail = email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (existing) {
    throw new AppError('Email already registered', 409, 'DUPLICATE_EMAIL');
  }

  const hashedPassword = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      name,
      email: normalizedEmail,
      password: hashedPassword,
      role: 'USER',
    },
  });

  const { password: _, ...safeUser } = user;

  logger.info('REGISTER_SUCCESS', { userId: user.id });

  return { user: safeUser };
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
export const login = async ({ email, password, ipAddress, userAgent, correlationId }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  // Prevent user enumeration — dummy hash burns same CPU time
  if (!user) {
    await dummyVerify(password);
    loginFailuresTotal.inc({ status: 'INVALID_CREDENTIALS' });
    logger.warn('LOGIN_FAILED', { email: normalizedEmail, ip: ipAddress });
    await logSecurityEvent({ action: 'LOGIN_FAILED', status: 'FAILURE', ip: ipAddress, correlationId });
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

  const isMatch = await verifyPassword(user.password, password);

  if (!isMatch) {
    loginFailuresTotal.inc({ status: 'INVALID_CREDENTIALS' });
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
      accountLockCounter.inc({ reason: 'brute_force' });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: attempts, lockUntil }
    });

    logger.warn('LOGIN_FAILED', { userId: user.id, ip: ipAddress });
    await logSecurityEvent({ userId: user.id, action: 'LOGIN_FAILED', status: 'FAILURE', ip: ipAddress, correlationId });
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

  if (user.totpEnabled) {
    const tempToken = generateTempToken(user);
    return { status: "MFA_REQUIRED", tempToken };
  }

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent, mfaVerified: false });

  await logSecurityEvent({ userId: user.id, action: 'LOGIN_SUCCESS', status: 'SUCCESS', ip: ipAddress, userAgent, correlationId, sessionId: tokens.jti });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// GOOGLE OAUTH LOGIN
// 🔐 SECURITY FIX: No silent account linking
// ─────────────────────────────────────────────
export const handleGoogleAuth = async ({ googleId, email, name, emailVerified, ipAddress, userAgent, correlationId }) => {
  const normalizedEmail = email.toLowerCase().trim();
  let user = await prisma.user.findUnique({ where: { googleId } });

  if (!user) {
    // Check if an account with this email already exists
    const existingUser = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    if (existingUser) {
      // 🔐 SECURITY FIX: Do NOT auto-link. Prevent account takeover via Google OAuth.
      logger.warn('GOOGLE_OAUTH_LINK_BLOCKED', {
        email: normalizedEmail,
        existingUserId: existingUser.id,
        ip: ipAddress
      });
      throw new AppError(
        'An account with this email already exists. Please login with your password and link Google from settings.',
        409,
        'ACCOUNT_EXISTS'
      );
    }

    // Provision net-new user (no existing account conflict)
    const { role: assignedRole, roleSource } = resolveUserRole(normalizedEmail, emailVerified);
    const roleStatus = assignedRole === 'PENDING_ADMIN' ? 'PENDING' : 'ACTIVE';

    user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        name,
        googleId,
        provider: 'google',
        role: assignedRole,
        roleSource,
        roleStatus
      }
    });

    logger.info('OAUTH_USER_PROVISIONED', {
      email: normalizedEmail,
      role: assignedRole,
      provider: 'google',
      userId: user.id,
    });

    if (assignedRole === 'PENDING_ADMIN') {
      logger.warn("ADMIN_PENDING_APPROVAL", {
        email: normalizedEmail,
        source: roleSource
      });
    }
  }

  // Re-use core IAM lockout protection identically
  if (user.lockUntil && user.lockUntil > new Date()) {
    throw new AppError('Account temporarily locked', 403, 'ACCOUNT_LOCKED');
  }

  // Erase latent attempt tracking if recovering securely via OIDC
  if (user.failedLoginAttempts > 0 || user.lockUntil) {
    user = await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockUntil: null }
    });
  }

  const { password: _, ...safeUser } = user;

  // Re-use core IAM MFA tracking natively (DO NOT BYPASS)
  if (user.totpEnabled) {
    const tempToken = generateTempToken(user);
    return { status: "MFA_REQUIRED", tempToken };
  }

  // Issue standard tokens
  const tokens = await issueTokens(safeUser, { ipAddress, userAgent, mfaVerified: false });
  
  await logSecurityEvent({ userId: user.id, action: 'LOGIN_SUCCESS', status: 'SUCCESS_GOOGLE', ip: ipAddress, userAgent, correlationId, sessionId: tokens.jti });

  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// VALIDATE MFA LOGIN
// ─────────────────────────────────────────────
export const validateMfaLogin = async ({ code, tempToken, ipAddress, userAgent, correlationId }) => {
  const decoded = verifyTempToken(tempToken);

  const user = await prisma.user.findUnique({ where: { id: decoded.sub } });

  // W-5 FIX: Check per-user MFA lockout BEFORE attempting verification.
  // This is the enforcement gate for the distributed brute-force counter.
  try {
    const lockKey  = `mfa:locked:${decoded.sub}`;
    const isLocked = await redisClient.get(lockKey);
    if (isLocked) {
      logger.warn('MFA_USER_LOCK_ENFORCED', { userId: decoded.sub, ip: ipAddress });
      throw new AppError(
        'MFA temporarily locked due to too many failed attempts. Please try again later.',
        429,
        'MFA_RATE_LIMITED'
      );
    }
  } catch (err) {
    if (err instanceof AppError) throw err; // re-throw our own AppError
    // Redis failure: fail open (do not block legitimate user)
    logger.error('MFA_LOCK_CHECK_REDIS_ERROR', { error: err.message, userId: decoded.sub });
  }

  if (!user || (user.lockUntil && user.lockUntil > new Date()) || !user.totpEnabled) {
    throw new AppError('Invalid MFA login attempt', 403, 'FORBIDDEN');
  }

  // PATCH 1: Fix Race Condition in Temp Token Replay Protection (ATOMIC UPDATE)
  const updated = await prisma.user.updateMany({
    where: {
      id: user.id,
      OR: [
        { lastTempTokenJti: null },
        { lastTempTokenJti: { not: decoded.jti } }
      ]
    },
    data: {
      lastTempTokenJti: decoded.jti,
      lastTempTokenUsedAt: new Date()
    }
  });

  if (updated.count === 0) {
    throw new AppError("Temp token already used", 401, "TOKEN_REUSE_DETECTED");
  }

  // Decrypt TOTP Secret
  const { decrypt } = await import('../../shared/utils/cipher.js');
  
  if (user.totpSecret && !user.totpSecretKeyVersion) {
    throw new AppError(
      'Invalid encryption state',
      500,
      'CRYPTO_STATE_INVALID'
    );
  }

  if (!user.totpSecretKeyVersion) {
    throw new AppError('MFA key version missing', 500, 'MFA_KEY_ERROR');
  }
  const decryptedSecret = decrypt(user.totpSecret, user.totpSecretKeyVersion);

  const speakeasy = (await import('speakeasy')).default;
  const verified = speakeasy.totp.verify({
    secret: decryptedSecret,
    encoding: 'base32',
    token: code,
    window: 1,
  });

  if (!verified) {
    mfaFailuresTotal.inc();
    // W-5 FIX: Per-user MFA attempt counter — defeats distributed brute force.
    //
    // Problem: IP-only rate limiting fails when a distributed attack sends 1 req
    // from each of N IPs. Each IP stays under the per-IP limit, but the target
    // user accumulates N invalid MFA attempts.
    //
    // Solution: INCR mfa:attempts:<userId> with a 10-minute sliding window.
    // After MFA_MAX_ATTEMPTS failures from ANY IPs, the user's MFA is locked
    // for MFA_LOCK_SECONDS. The lock key is separate so it survives window reset.
    const MFA_WINDOW_SECONDS = 600;   // 10-minute attempt window
    const MFA_MAX_ATTEMPTS   = 10;    // failures allowed before lockout
    const MFA_LOCK_SECONDS   = 600;   // 10-minute lockout duration

    const attemptsKey = `mfa:attempts:${user.id}`;
    const lockKey     = `mfa:locked:${user.id}`;

    try {
      const attempts = await redisClient.incr(attemptsKey);
      // Set TTL only on first increment (EXPIRE is a no-op on existing keys
      // when using EXPIRE without GT, so manually only set on first write)
      if (attempts === 1) {
        await redisClient.expire(attemptsKey, MFA_WINDOW_SECONDS);
      }
      if (attempts >= MFA_MAX_ATTEMPTS) {
        if (attempts === MFA_MAX_ATTEMPTS) {
          distributedMfaLockTotal.inc();
        }
        await redisClient.set(lockKey, '1', 'EX', MFA_LOCK_SECONDS, 'NX');
        logger.warn('MFA_USER_LOCKED_DISTRIBUTED_BRUTE', {
          userId:   user.id,
          attempts,
          ip:       ipAddress,
        });
      }
    } catch (redisErr) {
      // Redis failure must not block the auth path — fail open for the counter.
      logger.error('MFA_RATE_LIMIT_REDIS_ERROR', { error: redisErr.message, userId: user.id });
    }

    await logSecurityEvent({ userId: user.id, action: 'LOGIN_FAILED', status: 'MFA_FAILED', ip: ipAddress, userAgent, correlationId });
    throw new AppError('Invalid MFA code', 400, 'INVALID_MFA_CODE');
  }

  const { password: _, ...safeUser } = user;
  const tokens = await issueTokens(safeUser, { ipAddress, userAgent, mfaVerified: true });

  // W-5: Reset per-user MFA attempt counters on successful login.
  // Ensures a legitimate user is not penalised by a prior attack window.
  try {
    await redisClient.del(`mfa:attempts:${user.id}`, `mfa:locked:${user.id}`);
  } catch (redisErr) {
    logger.warn('MFA_COUNTER_RESET_FAILED', { error: redisErr.message, userId: user.id });
  }

  await logSecurityEvent({ userId: user.id, action: 'LOGIN_SUCCESS', status: 'MFA_SUCCESS', ip: ipAddress, userAgent, correlationId, sessionId: tokens.jti });
  
  return { user: safeUser, ...tokens };
};

// ─────────────────────────────────────────────
// REFRESH TOKEN (ROTATION)
// ─────────────────────────────────────────────
export const refresh = async (token, { ipAddress, userAgent, correlationId }) => {
  if (!token) {
    throw new AppError('Refresh token missing', 401, 'REFRESH_TOKEN_MISSING');
  }

  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch (err) {
    // Basic verify failed, but could be reuse/compromise attempts
    const attemptDecoded = jwtLib.decode(token);
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

  // If NOT found -> throw REFRESH_TOKEN_INVALID
  if (!session) {
    logger.warn('REFRESH_TOKEN_NOT_FOUND', { jti: decoded.jti, ipAddress });
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  // Check if session is explicitly revoked
  if (session.revoked) {
    logger.warn('REFRESH_TOKEN_REVOKED', { userId: decoded.sub, jti: decoded.jti, ipAddress });
    throw new AppError('Invalid refresh token', 401, 'REFRESH_TOKEN_INVALID');
  }

  // REUSE DETECTION: If found AND isUsed === true
  if (session.isUsed) {
    // IDEMPOTENT REFRESH: Check if tokens were JUST generated by another tab
    const cachedTokensJson = await redisClient.get(`refresh_concurrency:${decoded.jti}`);
    if (cachedTokensJson) {
      logger.info('CONCURRENT_REFRESH_CACHE_HIT', { userId: decoded.sub, jti: decoded.jti, ipAddress });
      return JSON.parse(cachedTokensJson);
    }

    logger.warn('TOKEN_REUSE_DETECTED', { userId: decoded.sub, jti: decoded.jti, ipAddress });
    sessionSecurityCounter.inc({ event: 'token_reuse' });
    await prisma.session.updateMany({
      where: { userId: decoded.sub },
      data: { revoked: true }
    });

    await logSecurityEvent({
      userId: decoded.sub,
      action: 'TOKEN_REUSE_DETECTED',
      status: 'FAILURE',
      ip: ipAddress,
      userAgent,
      correlationId,
      metadata: { jti: decoded.jti, allSessionsRevoked: true },
    });

    sessionSecurityCounter.inc({ event: 'session_compromised' });
    throw new AppError('Refresh token reuse detected. All sessions revoked.', 401, 'SESSION_COMPROMISED');
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

  // Validate hashed token — use Argon2 verification
  if (session.refreshTokenHash) {
    const { verifyPassword: verifyHash } = await import('../../shared/utils/password.js');
    const isTokenMatch = await verifyHash(session.refreshTokenHash, token);
    if (!isTokenMatch) {
      logger.warn('TOKEN_MISMATCH_REUSE_DETECTED', { userId: session.userId, jti: decoded.jti, ipAddress });
      sessionSecurityCounter.inc({ event: 'token_hash_mismatch' });
      await prisma.session.updateMany({
        where: { userId: session.userId },
        data: { revoked: true }
      });
      throw new AppError('Refresh token reuse detected. All sessions revoked.', 401, 'SESSION_COMPROMISED');
    }
  }

  // 🔐 Active Session Defense
  if (
    (session.ipAddress && session.ipAddress !== ipAddress) ||
    (session.userAgent && session.userAgent !== userAgent)
  ) {
    await prisma.session.update({
      where: { id: decoded.jti },
      data: { revoked: true }
    });
    
    await logSecurityEvent({
      userId: session.userId,
      action: 'SESSION_REVOKED',
      status: 'SUSPICIOUS_SESSION_DETECTED',
      ip: ipAddress,
      userAgent,
      correlationId,
      sessionId: decoded.jti
    });
    
    logger.warn('SUSPICIOUS_SESSION_REVOKED', { userId: session.userId, ipAddress, userAgent });
    sessionSecurityCounter.inc({ event: 'session_hijack' });
    throw new AppError('Session anomalously accessed and revoked', 403, 'SESSION_COMPROMISED');
  }

  // ATOMIC UPDATE to mark as used (Requirement 5)
  const updatedSession = await prisma.session.updateMany({
    where: {
      id: decoded.jti,
      isUsed: false
    },
    data: {
      isUsed: true
    }
  });

  if (updatedSession.count === 0) {
    logger.warn('CONCURRENT_REFRESH_RACE', { userId: session.userId, jti: decoded.jti, ipAddress });
    
    // Another request is generating tokens. Wait and fetch them.
    let cachedTokens = null;
    for (let i = 0; i < 30; i++) { // Wait up to 3 seconds
      const cached = await redisClient.get(`refresh_concurrency:${decoded.jti}`);
      if (cached) {
        cachedTokens = JSON.parse(cached);
        break;
      }
      await new Promise(r => setTimeout(r, 100));
    }

    if (cachedTokens) {
      logger.info('CONCURRENT_REFRESH_CACHE_HIT_DELAYED', { userId: session.userId, jti: decoded.jti, ipAddress });
      return cachedTokens;
    }

    // Race condition detected! Real replay attack outside grace window.
    logger.warn('TOKEN_REUSE_DETECTED_RACE_CONDITION', { userId: session.userId, jti: decoded.jti, ipAddress });
    sessionSecurityCounter.inc({ event: 'token_race' });
    await prisma.session.updateMany({
      where: { userId: session.userId },
      data: { revoked: true }
    });
    throw new AppError('Refresh token reuse detected. All sessions revoked.', 401, 'SESSION_COMPROMISED');
  }

  const { password: _, ...safeUser } = session.user;

  const tokens = await issueTokens(safeUser, { ipAddress, userAgent });

  // IDEMPOTENT REFRESH: Store exact result with 15 second expiry
  await redisClient.set(`refresh_concurrency:${decoded.jti}`, JSON.stringify(tokens), 'EX', 15);

  await logSecurityEvent({
    userId: safeUser.id,
    action: 'TOKEN_REFRESHED',
    status: 'SUCCESS',
    ip: ipAddress,
    userAgent,
    correlationId,
    sessionId: tokens.jti,
    metadata: { oldJti: decoded.jti },
  });

  logger.info('TOKEN_ROTATED', { userId: safeUser.id, oldJti: decoded.jti });

  return tokens;
};

// ─────────────────────────────────────────────
// LOGOUT (CURRENT SESSION)
// ─────────────────────────────────────────────
export const logout = async (token, { correlationId } = {}) => {
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

  await prisma.session.update({
    where: { id: decoded.jti },
    data: { revoked: true }
  });

  await logSecurityEvent({
    userId: decoded.sub,
    action: 'LOGOUT',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    correlationId,
    sessionId: decoded.jti,
    metadata: { jti: decoded.jti },
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
      totpEnabled: true,
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
// UPDATE PROFILE
// ─────────────────────────────────────────────
export const updateProfile = async (userId, { name }) => {
  if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) {
    throw new AppError('Name must be between 2 and 100 characters', 400, 'VALIDATION_ERROR');
  }

  const user = await prisma.user.update({
    where: { id: userId },
    data: { name: name.trim() },
    select: {
      id: true,
      name: true,
      email: true,
      role: true,
      totpEnabled: true,
      createdAt: true,
      updatedAt: true,
    },
  });

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
      updatedAt: true,
      mfaVerified: true,
      lastUsedAt: true,
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
export const revokeSession = async (sessionId, userId, { correlationId } = {}) => {
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

  await logSecurityEvent({
    userId,
    action: 'SESSION_REVOKED',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    correlationId,
    sessionId,
    metadata: { revokedSessionId: sessionId },
  });

  logger.info('SESSION_REVOKED', { userId, sessionId });
};

// ─────────────────────────────────────────────
// REVOKE ALL SESSIONS
// ─────────────────────────────────────────────
export const revokeAllSessions = async (userId, { correlationId } = {}) => {
  const result = await prisma.session.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true }
  });

  await logSecurityEvent({
    userId,
    action: 'ALL_SESSIONS_REVOKED',
    status: 'SUCCESS',
    ip: null,
    userAgent: null,
    correlationId,
    metadata: { sessionsRevoked: result.count },
  });

  logger.info('ALL_SESSIONS_REVOKED', { userId, count: result.count });
};

// ─────────────────────────────────────────────
// INTERNAL: ISSUE TOKENS
// ─────────────────────────────────────────────
const issueTokens = async (user, { ipAddress, userAgent, mfaVerified = false } = {}) => {
  // 🔒 Limit active sessions (only un-rotated strictly active endpoints)
  const sessions = await prisma.session.findMany({
    where: { userId: user.id, revoked: false, isUsed: false },
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
    jti: jti,
    mfaVerified: mfaVerified
  };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload, jti);

  const decoded = jwtLib.decode(refreshToken);
  const expiresAt = new Date(decoded.exp * 1000);

  // Hash refresh token with Argon2 for secure storage
  const refreshTokenHash = await hashPassword(refreshToken);

  await prisma.session.create({
    data: {
      id: jti,
      userId: user.id,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      expiresAt,
      refreshTokenHash,
      revoked: false,
      mfaVerified
    },
  });

  return { accessToken, refreshToken, jti };
};
