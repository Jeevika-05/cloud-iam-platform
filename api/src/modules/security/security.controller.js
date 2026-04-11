import * as securityService from './security.service.js';
import { successResponse, errorResponse } from '../../shared/utils/response.js';

// ─────────────────────────────────────────────
// GET /api/v1/security/attacks
// Returns the list of available attack types.
// Frontend maps this to dynamically render buttons.
// ─────────────────────────────────────────────
export const getAttackTypes = (req, res, next) => {
  try {
    const attacks = securityService.getAttackTypes();
    return successResponse(res, { attacks }, 'Attack types retrieved');
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────
// POST /api/v1/security/simulate
// Body: { type: string }
// Triggers the named attack simulation.
// ─────────────────────────────────────────────
export const simulate = async (req, res, next) => {
  try {
    const { type } = req.body;

    // Body-level validation — service validates enum membership
    if (!type || typeof type !== 'string') {
      return errorResponse(res, '"type" is required and must be a string', 400, 'VALIDATION_ERROR');
    }

    const result = await securityService.runSimulation({
      type: type.trim().toUpperCase(),
      userId: req.user.id,
      correlationId: req.correlationId,
    });

    return successResponse(
      res,
      {
        message: result.message,
        attack: result.attack,
        label: result.label,
        group: result.group,
        timestamp: new Date().toISOString(),
      },
      'Simulation triggered'
    );
  } catch (err) {
    next(err);
  }
};
