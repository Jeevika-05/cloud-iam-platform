import * as mfaService from './mfa.service.js';
import { successResponse } from '../../shared/utils/response.js';
import AppError from '../../shared/utils/AppError.js';

export const setupMfa = async (req, res, next) => {
  try {
    const result = await mfaService.setupMfa(req.user.id);
    return successResponse(res, result, 'MFA setup initiated');
  } catch (err) {
    next(err);
  }
};

export const verifyMfa = async (req, res, next) => {
  try {
    const code = req.body.token || req.body.code;

    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      throw new AppError('MFA code must be a 6-digit number', 400, 'INVALID_MFA_FORMAT');
    }

    await mfaService.verifyMfa(req.user.id, code);
    return successResponse(res, {}, 'MFA successfully enabled');
  } catch (err) {
    next(err);
  }
};

export const disableMfa = async (req, res, next) => {
  try {
    const { totpCode, password } = req.body;

    await mfaService.disableMfa(req.user.id, { totpCode, password });
    return successResponse(res, {}, 'MFA disabled successfully');
  } catch (err) {
    next(err);
  }
};
