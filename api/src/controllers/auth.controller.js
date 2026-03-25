import * as authService from '../services/auth.service.js';
import { successResponse } from '../utils/response.js';

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body; // 🔐 remove role from input

    const result = await authService.register({
      name,
      email,
      password,
    });

    return successResponse(res, result, 'Registration successful', 201);

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

    const result = await authService.login({ email, password });

    return successResponse(res, result, 'Login successful');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// REFRESH TOKEN
// ─────────────────────────────────────────────
export const refresh = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    const tokens = await authService.refresh(refreshToken);

    return successResponse(res, tokens, 'Token refreshed successfully');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// LOGOUT
// ─────────────────────────────────────────────
export const logout = async (req, res, next) => {
  try {
    await authService.logout(req.user.id);

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