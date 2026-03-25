import { body, param, validationResult } from 'express-validator';
import AppError from '../utils/AppError.js';

// ───────────────────────────────────────────────────────────
// Validation Result Handler
// ───────────────────────────────────────────────────────────
export const validate = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const details = errors.array().map((e) => ({
      field: e.path,
      message: e.msg,
    }));

    const err = new AppError('Validation failed', 422, 'VALIDATION_ERROR');
    err.errors = details;

    return next(err);
  }

  next();
};

export const userIdParamRule = [
  param('id')
    .notEmpty().withMessage('User ID is required')
    .isUUID().withMessage('Invalid user ID format'),
];

// ───────────────────────────────────────────────────────────
// REGISTER RULES
// ───────────────────────────────────────────────────────────
export const registerRules = [
  body('name')
    .trim()
    .escape() // 🔐 Prevent XSS
    .notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters'),

  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email address')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),

  // 🔐 Do NOT allow role from user input (IMPORTANT FIX)
  body('role')
    .optional()
    .custom(() => {
      throw new Error('Role assignment is not allowed');
    }),
];

// ───────────────────────────────────────────────────────────
// LOGIN RULES
// ───────────────────────────────────────────────────────────
export const loginRules = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email address')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required'),
];

// ───────────────────────────────────────────────────────────
// REFRESH TOKEN RULES
// ───────────────────────────────────────────────────────────
export const refreshRules = [
  body('refreshToken')
    .notEmpty().withMessage('Refresh token is required')
    .isString().withMessage('Refresh token must be a string')
    .isLength({ min: 10 }).withMessage('Invalid refresh token'),
];