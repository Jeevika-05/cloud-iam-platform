import crypto from 'crypto';
import { extractClientInfo } from '../../shared/utils/clientInfo.js';
import * as authService from './auth.service.js';
import * as googleAuthService from './googleAuth.service.js';
import { successResponse } from '../../shared/utils/response.js';
import { loginCounter, mfaCounter, loginDuration } from '../../metrics/metrics.js';
import { app as appConfig } from '../../shared/config/index.js';
import AppError from '../../shared/utils/AppError.js';

// Cookie config (reuse everywhere)
const getCookieOptions = (req) => {
  const isProd = process.env.NODE_ENV === 'production';
  // Use SameSite: None explicitly if scaling out to strict multi-domain production. 
  // Otherwise, fallback to Lax which natively protects identical-domain setups.
  const isCrossDomain = process.env.CROSS_DOMAIN_PROD === 'true'; 
  const sameSiteMode = isCrossDomain ? 'none' : 'lax';

  return {
    httpOnly: true,
    secure: isProd || (isCrossDomain && sameSiteMode === 'none'), // None MUST be secure
    sameSite: sameSiteMode,
    path: "/"
  };
};

// ─────────────────────────────────────────────
// CSRF TOKEN GENERATION
// ─────────────────────────────────────────────
export const getCsrfToken = (req, res) => {
  let token = req.cookies.csrf_token;
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
   res.cookie('csrf_token', token, {
  ...getCookieOptions(req),
  httpOnly: false,   // JS must be able to read this — that is the point of double-submit
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/'
});
  }
  res.json(successResponse('CSRF token generated', { csrfToken: token }));
};

// ─────────────────────────────────────────────
// GOOGLE OAUTH
// ─────────────────────────────────────────────
export const googleAuth = (req, res) => {
  const state = crypto.randomBytes(32).toString('hex');
  const cookieOpts = getCookieOptions(req);
  res.cookie('oauth_state', state, { ...cookieOpts, maxAge: 10 * 60 * 1000 });
  res.redirect(googleAuthService.getAuthUrl(state));
};

export const googleCallback = async (req, res, next) => {
  try {
    const { code, state } = req.query;
    const stateCookie = req.cookies.oauth_state;

    if (!code) {
      const idTokenHeader = req.headers['x-google-id-token'];
      if (!idTokenHeader || typeof idTokenHeader !== 'string') throw new Error('Authorization code missing');
      if (idTokenHeader.length > 4096) throw new Error('ID token too large');
      req.query.idToken = idTokenHeader;
    } else {
      // Validate OAuth State to prevent CSRF / Session Fixation
      if (!stateCookie || !state || stateCookie !== state) {
        throw new AppError('Invalid OAuth state parameter', 403, 'OAUTH_CSRF_FAILED');
      }
      res.clearCookie('oauth_state', getCookieOptions(req));
    }

    const idToken = req.query.idToken || (await googleAuthService.exchangeCodeForIdToken(code));
    const { googleId, email, name, emailVerified } = await googleAuthService.verifyGoogleIdToken(idToken);

    const result = await authService.handleGoogleAuth({
      googleId,
      email,
      name,
      emailVerified,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
      correlationId: req.correlationId
    });

    if (result.status === 'MFA_REQUIRED') {
      return successResponse(res, result, 'MFA token required');
    }

    res.cookie('refreshToken', result.refreshToken, {
      ...getCookieOptions(req),
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    return res.redirect(`${frontendUrl}/auth/callback`);
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    await authService.register({
      name,
      email,
      password,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
      correlationId: req.correlationId
    });

    return successResponse(res, {}, 'User registered successfully');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
export const login = async (req, res, next) => {
  const end = loginDuration.startTimer();
  try {
    const { email, password } = req.body;

    const result = await authService.login({
      email,
      password,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
      correlationId: req.correlationId
    });

    if (result.status === 'MFA_REQUIRED') {
      loginCounter.inc({ status: 'mfa_required' });
      end();
      return successResponse(res, result, 'MFA token required');
    }

    loginCounter.inc({ status: 'success' });
    end();

    // Set refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      ...getCookieOptions(req),
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      {
        accessToken: result.accessToken,
        user: result.user,
      },
      'Login successful'
    );
  } catch (err) {
    loginCounter.inc({ status: 'failure' });
    end();
    next(err);
  }
};

// ─────────────────────────────────────────────
// VALIDATE MFA LOGIN
// ─────────────────────────────────────────────
export const validateMfaLogin = async (req, res, next) => {
  try {
    const { code, tempToken } = req.body;

    if (!tempToken || typeof tempToken !== 'string') {
      throw new AppError('tempToken is required', 400, 'VALIDATION_ERROR');
    }
    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      throw new AppError('MFA code must be a 6-digit number', 400, 'VALIDATION_ERROR');
    }

    const result = await authService.validateMfaLogin({
      code,
      tempToken,
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
      correlationId: req.correlationId
    });

    mfaCounter.inc({ status: 'success' });

    // Set refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      ...getCookieOptions(req),
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      {
        accessToken: result.accessToken,
        user: result.user,
      },
      'Login successful'
    );
  } catch (err) {
    mfaCounter.inc({ status: 'failure' });
    next(err);
  }
};

// ─────────────────────────────────────────────
// REFRESH TOKEN (ROTATION)
// ─────────────────────────────────────────────
export const refresh = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    const tokens = await authService.refresh(refreshToken, {
      ipAddress: extractClientInfo(req).ip,
      userAgent: extractClientInfo(req).userAgent,
      correlationId: req.correlationId
    });

    // Rotate cookie (replace old token)
    res.cookie('refreshToken', tokens.refreshToken, {
      ...getCookieOptions(req),
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      { accessToken: tokens.accessToken },
      'Token refreshed successfully'
    );
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// LOGOUT (CURRENT SESSION)
// ─────────────────────────────────────────────
export const logout = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      await authService.logout(refreshToken, { correlationId: req.correlationId });
    }

    // Clear cookie
    res.clearCookie('refreshToken', getCookieOptions(req));

    return successResponse(res, {}, 'Logged out successfully');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET PROFILE
// ─────────────────────────────────────────────
export const getProfile = async (req, res, next) => {
  try {
    const user = await authService.getProfile(req.user.id);

    return successResponse(res, { user }, 'Profile retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// UPDATE PROFILE
// ─────────────────────────────────────────────
export const updateProfile = async (req, res, next) => {
  try {
    const { name } = req.body;

    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      throw new AppError('Invalid name', 400, 'VALIDATION_ERROR');
    }

    const user = await authService.updateProfile(req.user.id, { name: name.trim() });

    return successResponse(res, { user }, 'Profile updated');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET ALL ACTIVE SESSIONS
// ─────────────────────────────────────────────
export const getSessions = async (req, res, next) => {
  try {
    const sessions = await authService.getActiveSessions(req.user.id);

    return successResponse(res, { sessions }, 'Sessions retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET CURRENT SESSION
// ─────────────────────────────────────────────
export const getCurrentSession = async (req, res, next) => {
  try {
    const session = await authService.getCurrentSession(req.auth.jti);

    return successResponse(res, { session }, 'Current session retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REVOKE SPECIFIC SESSION
// ─────────────────────────────────────────────
export const revokeSession = async (req, res, next) => {
  try {
    const { id } = req.params;

    await authService.revokeSession(id, req.user.id, { correlationId: req.correlationId });

    return successResponse(res, {}, 'Session revoked');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REVOKE ALL SESSIONS
// ─────────────────────────────────────────────
export const revokeAllSessions = async (req, res, next) => {
  try {
    await authService.revokeAllSessions(req.user.id, { correlationId: req.correlationId });

    // Clear cookie for security
    res.clearCookie('refreshToken', getCookieOptions(req));

    return successResponse(res, {}, 'All sessions revoked');
  } catch (err) {
    next(err);
  }
};
