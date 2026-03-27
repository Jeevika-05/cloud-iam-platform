import { body, param, validationResult } from 'express-validator';
import AppError from '../utils/AppError.js';

// ─────────────────────────────────────────────
// Validation Result Handler
// ─────────────────────────────────────────────
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

// ─────────────────────────────────────────────
// PARAM RULES
// ─────────────────────────────────────────────
export const userIdParamRule = [
  param('id')
    .notEmpty().withMessage('User ID is required')
    .isUUID().withMessage('Invalid user ID format'),
];

export const sessionIdParamRule = [
  param('id')
    .notEmpty().withMessage('Session ID is required')
    .isUUID().withMessage('Invalid session ID format'),
];

// ─────────────────────────────────────────────
// REGISTER RULES
// ─────────────────────────────────────────────
export const registerRules = [
  body('name')
    .trim()
    .notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Name must be between 2 and 50 characters')
    .escape(),

  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email address')
    .normalizeEmail({
      gmail_remove_dots: false,
      gmail_remove_subaddress: false,
    }),

  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 10 }).withMessage('Password must be at least 10 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])/)
    .withMessage(
      'Password must contain uppercase, lowercase, number, and special character'
    ),

  // 🔐 Prevent privilege escalation on registration
  body('role')
    .optional()
    .custom(() => {
      throw new Error('Role assignment is not allowed');
    }),
];

// ─────────────────────────────────────────────
// LOGIN RULES
// ─────────────────────────────────────────────
export const loginRules = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email address')
    .normalizeEmail()
    .customSanitizer((value) => value.toLowerCase()),

  body('password')
    .notEmpty().withMessage('Password is required'),
];

// ─────────────────────────────────────────────
// UPDATE ROLE RULES (ADMIN ONLY)
// Updated to accept SECURITY_ANALYST instead of ANALYST
// ─────────────────────────────────────────────
export const updateRoleRules = [
  body('role')
    .notEmpty().withMessage('Role is required')
    .isIn(['USER', 'ADMIN', 'SECURITY_ANALYST'])   // ← updated
    .withMessage('Invalid role. Must be USER, ADMIN, or SECURITY_ANALYST'),
];
