import * as authService from '../services/auth.service.js';
import { successResponse } from '../utils/response.js';

// Cookie config (reuse everywhere)
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  path: '/api/v1/auth', // restrict cookie scope
};

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    const result = await authService.register({
      name,
      email,
      password,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Set refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    return successResponse(
      res,
      {
        accessToken: result.accessToken,
        user: result.user,
      },
      'Registration successful',
      201
    );
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const result = await authService.login({
      email,
      password,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Set refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
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
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'],
    });

    // Rotate cookie (replace old token)
    res.cookie('refreshToken', tokens.refreshToken, {
      ...REFRESH_COOKIE_OPTIONS,
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
      await authService.logout(refreshToken);
    }

    // Clear cookie
    res.clearCookie('refreshToken', REFRESH_COOKIE_OPTIONS);

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

    await authService.revokeSession(id, req.user.id);

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
    await authService.revokeAllSessions(req.user.id);

    // Clear cookie for security
    res.clearCookie('refreshToken', REFRESH_COOKIE_OPTIONS);

    return successResponse(res, {}, 'All sessions revoked');
  } catch (err) {
    next(err);
  }
};