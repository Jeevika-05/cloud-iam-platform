import prisma from '../../shared/config/database.js';
import AppError from '../../shared/utils/AppError.js';
import logger from '../../shared/utils/logger.js';
import { successResponse } from '../../shared/utils/response.js';

export const getPendingUsers = async (req, res, next) => {
  try {
    const pendingUsers = await prisma.user.findMany({
      where: {
        role: 'PENDING_ADMIN',
        roleStatus: 'PENDING'
      },
      select: {
        id: true,
        email: true,
        role: true,
        roleSource: true,
        createdAt: true
      }
    });
    
    return successResponse(res, pendingUsers, 'Pending users retrieved successfully');
  } catch (err) {
    next(err);
  }
};

export const approveUser = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new AppError('Email is required', 400, 'VALIDATION_ERROR');
    }

    const normalizedEmail = email.toLowerCase().trim();

    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (!user) {
      throw new AppError('User not found', 404, 'NOT_FOUND');
    }

    if (user.role === 'PENDING_ADMIN') {
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: {
          role: 'ADMIN',
          roleStatus: 'ACTIVE'
        }
      });

      logger.info('ADMIN_APPROVED', {
        email: updatedUser.email,
        approvedBy: req.user.id
      });

      return successResponse(res, { 
        id: updatedUser.id,
        email: updatedUser.email,
        role: updatedUser.role,
        roleStatus: updatedUser.roleStatus
      }, 'Admin access approved successfully');
    } else {
      throw new AppError('User is not awaiting admin approval', 400, 'BAD_REQUEST');
    }
  } catch (err) {
    next(err);
  }
};

export const rejectUser = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new AppError('Email is required', 400, 'VALIDATION_ERROR');
    }

    const normalizedEmail = email.toLowerCase().trim();

    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (!user) {
      throw new AppError('User not found', 404, 'NOT_FOUND');
    }

    if (user.role === 'PENDING_ADMIN') {
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: {
          role: 'USER',
          roleStatus: 'ACTIVE'
        }
      });

      logger.warn('ADMIN_REQUEST_REJECTED', {
        email: updatedUser.email,
        rejectedBy: req.user.id
      });

      return successResponse(res, { 
        id: updatedUser.id,
        email: updatedUser.email,
        role: updatedUser.role,
        roleStatus: updatedUser.roleStatus
      }, 'Admin request rejected successfully');
    } else {
      throw new AppError('User is not awaiting admin approval', 400, 'BAD_REQUEST');
    }
  } catch (err) {
    next(err);
  }
};

export const getPendingCount = async (req, res, next) => {
  try {
    const count = await prisma.user.count({
      where: {
        role: 'PENDING_ADMIN',
        roleStatus: 'PENDING'
      }
    });
    
    return successResponse(res, { count }, 'Pending count retrieved');
  } catch (err) {
    next(err);
  }
};
