import * as userService from '../services/user.service.js';
import { successResponse } from '../utils/response.js';
import AppError from '../utils/AppError.js';

const ALLOWED_ROLES = ['USER', 'ADMIN', 'ANALYST'];

// ─────────────────────────────────────────────
// GET ALL USERS
// ─────────────────────────────────────────────
export const getAllUsers = async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(Math.max(1, parseInt(req.query.limit) || 20), 100);
    const role = req.query.role;

    if (role && !ALLOWED_ROLES.includes(role)) {
      throw new AppError('Invalid role filter', 400, 'VALIDATION_ERROR');
    }

    const result = await userService.getAllUsers({ page, limit, role });

    return successResponse(res, result, 'Users retrieved');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// GET USER BY ID
// ─────────────────────────────────────────────
export const getUserById = async (req, res, next) => {
  try {
    const user = await userService.getUserById(req.params.id);

    return successResponse(res, { user }, 'User retrieved');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// UPDATE USER ROLE
// ─────────────────────────────────────────────
export const updateUserRole = async (req, res, next) => {
  try {
    const { role } = req.body;

    if (!ALLOWED_ROLES.includes(role)) {
      throw new AppError('Invalid role', 400, 'VALIDATION_ERROR');
    }

    const user = await userService.updateUserRole(
      req.params.id,
      role,
      req.user // 🔐 pass current user for security checks
    );

    return successResponse(res, { user }, 'User role updated');

  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// DELETE USER
// ─────────────────────────────────────────────
export const deleteUser = async (req, res, next) => {
  try {
    const targetUserId = req.params.id;

    if (targetUserId === req.user.id) {
      throw new AppError('Cannot delete your own account', 403, 'SELF_DELETE');
    }

    await userService.deleteUser(targetUserId, req.user); // 🔐 pass current user

    return successResponse(res, {}, 'User deleted');

  } catch (err) {
    next(err);
  }
};