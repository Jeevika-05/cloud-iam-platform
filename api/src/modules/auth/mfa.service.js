import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import prisma from '../../shared/config/database.js';
import AppError from '../../shared/utils/AppError.js';
import logger from '../../shared/utils/logger.js';
import { logSecurityEvent } from './audit.service.js';
import { encrypt, decrypt } from '../../shared/utils/cipher.js';
import { encryption } from '../../shared/config/index.js';
import { verifyPassword } from '../../shared/utils/password.js';

export const setupMfa = async (userId) => {
  const secret = speakeasy.generateSecret({
    name: `CloudIAM (${userId})`,
  });

  const qr = await qrcode.toDataURL(secret.otpauth_url);

  // Store encrypted secret using active key version from config
  const version = encryption.activeKeyVersion;

  const encryptedSecret = encrypt(secret.base32, version);

  await prisma.user.update({
    where: { id: userId },
    data: { 
      totpSecret: encryptedSecret, 
      totpEnabled: false,
      totpSecretKeyVersion: version
    }
  });

  return {
    qr,
    // 🔒 SEC-10: manual plain-text key removed. Return ONLY QR/URI to prevent leakage.
    otpauth_url: secret.otpauth_url
  };
};

export const verifyMfa = async (userId, code) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  
  if (!user || !user.totpSecret) {
    throw new AppError('MFA secret not found. Setup first.', 400, 'MFA_NOT_SETUP');
  }

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

  const verified = speakeasy.totp.verify({
    secret: decryptedSecret,
    encoding: 'base32',
    token: code,
    window: 1, // Allow 30 seconds drift before/after
  });

  if (!verified) {
    // Audit log failure
    await logSecurityEvent({
      userId, action: 'MFA_ENABLED', status: 'FAILED'
    });
    throw new AppError('Invalid MFA code', 400, 'INVALID_MFA_CODE');
  }

  // Finalize setup
  await prisma.user.update({
    where: { id: userId },
    data: { totpEnabled: true },
  });

  await logSecurityEvent({
    userId, action: 'MFA_ENABLED', status: 'SUCCESS'
  });

  return { success: true };
};

// ─────────────────────────────────────────────
// DISABLE MFA — Requires re-authentication
//
// Security gate: caller must supply EITHER:
//   • totpCode  — a valid current TOTP token (preferred)
//   • password  — the user's account password (fallback)
//
// This prevents a stolen access token from being used to
// silently downgrade account security.
// ─────────────────────────────────────────────
export const disableMfa = async (userId, { totpCode, password } = {}) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new AppError('User not found', 404, 'NOT_FOUND');
  }

  if (!user.totpEnabled) {
    throw new AppError('MFA is not enabled', 400, 'MFA_NOT_ENABLED');
  }

  // ── Re-authentication gate ────────────────────────────────────
  // At least one proof-of-identity credential must be supplied.
  if (!totpCode && !password) {
    logger.warn('MFA_DISABLE_NO_REAUTH', { userId });
    throw new AppError(
      'Re-authentication required. Provide your current TOTP code or account password to disable MFA.',
      401,
      'REAUTH_REQUIRED'
    );
  }

  let reauthed = false;

  // ── Option A: Verify current TOTP code ───────────────────────
  if (totpCode) {
    if (typeof totpCode !== 'string' || !/^\d{6}$/.test(totpCode)) {
      throw new AppError('TOTP code must be a 6-digit number', 400, 'INVALID_MFA_FORMAT');
    }

    if (!user.totpSecret || !user.totpSecretKeyVersion) {
      throw new AppError('Invalid MFA state — cannot verify TOTP', 500, 'CRYPTO_STATE_INVALID');
    }

    const decryptedSecret = decrypt(user.totpSecret, user.totpSecretKeyVersion);
    const verified = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token: totpCode,
      window: 1,
    });

    if (!verified) {
      await logSecurityEvent({ userId, action: 'MFA_DISABLED', status: 'REAUTH_FAILED_TOTP' });
      throw new AppError(
        'Re-authentication failed. Invalid TOTP code.',
        401,
        'REAUTH_REQUIRED'
      );
    }

    reauthed = true;
  }

  // ── Option B: Verify account password (fallback) ─────────────
  // Only evaluated if TOTP was not provided or failed to satisfy.
  if (!reauthed && password) {
    if (!user.password) {
      // OAuth-only accounts have no password — steer them to TOTP
      throw new AppError(
        'This account has no password set. Please provide your TOTP code instead.',
        400,
        'NO_PASSWORD_SET'
      );
    }

    if (typeof password !== 'string' || password.length > 128) {
      throw new AppError('Invalid password format', 400, 'VALIDATION_ERROR');
    }

    const passwordMatch = await verifyPassword(user.password, password);
    if (!passwordMatch) {
      await logSecurityEvent({ userId, action: 'MFA_DISABLED', status: 'REAUTH_FAILED_PASSWORD' });
      throw new AppError(
        'Re-authentication failed. Invalid password.',
        401,
        'REAUTH_REQUIRED'
      );
    }

    reauthed = true;
  }

  // Defensive guard — should never reach here given the checks above
  if (!reauthed) {
    throw new AppError('Re-authentication required', 401, 'REAUTH_REQUIRED');
  }

  // ── Re-auth passed — safe to disable MFA ─────────────────────
  await prisma.user.update({
    where: { id: userId },
    data: { totpEnabled: false, totpSecret: null, totpSecretKeyVersion: null },
  });

  await logSecurityEvent({
    userId, action: 'MFA_DISABLED', status: 'SUCCESS'
  });

  logger.info('MFA_DISABLED', { userId });

  return { success: true };
};
