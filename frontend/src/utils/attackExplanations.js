/**
 * ─────────────────────────────────────────────────────────────
 * Attack Explanation Engine
 * ─────────────────────────────────────────────────────────────
 *
 * Maps attack actions/scenarios to human-readable explanations
 * of WHY the attack succeeded or failed, and what defense was
 * triggered (if any).
 *
 * Used by SecuritySimulation and SimulationPanel to display
 * post-simulation insights to admins and analysts.
 * ─────────────────────────────────────────────────────────────
 */

const EXPLANATIONS = {
  // ── Authentication Attacks ──────────────────────────────────
  BRUTE_FORCE: {
    title: 'Brute Force Attack',
    explanation: 'Multiple rapid login attempts with different passwords were sent from the same IP. After exceeding the threshold, the defense engine recorded strikes and triggered an IP ban.',
    defense: 'Rate limiting + IP strike system → automatic temporary ban after 5 failed attempts.',
    severity: 'HIGH',
  },
  CREDENTIAL_STUFFING: {
    title: 'Credential Stuffing',
    explanation: 'Leaked credential pairs were tested against the login endpoint. The system detected the anomalous pattern of sequential failures from a single source.',
    defense: 'Failed login counter + behavioral anomaly detection → account lockout + IP flagging.',
    severity: 'HIGH',
  },
  PASSWORD_SPRAY: {
    title: 'Password Spray',
    explanation: 'A common password was tested across multiple user accounts to avoid per-account lockout thresholds. The system correlated failures across accounts from the same IP.',
    defense: 'Cross-account failure correlation → IP-level ban regardless of individual account thresholds.',
    severity: 'HIGH',
  },
  MFA_BYPASS: {
    title: 'MFA Bypass Attempt',
    explanation: 'Multiple invalid TOTP codes were submitted to brute-force MFA. A direct authentication attempt bypassing the MFA step was also detected and blocked.',
    defense: 'MFA rate limiter (5 attempts/15min) + temp token validation prevents skipping MFA step.',
    severity: 'CRITICAL',
  },

  // ── Token Attacks ──────────────────────────────────────────
  SESSION_HIJACK_CHAIN: {
    title: 'Session Hijack + Lateral Movement',
    explanation: 'A stolen token was replayed, triggering reuse detection. The attacker then attempted MFA brute-force and privilege escalation, creating a multi-step attack chain.',
    defense: 'Token rotation + reuse detection → session revocation. MFA limiter blocked brute-force. RBAC denied privilege escalation.',
    severity: 'CRITICAL',
  },
  TOKEN_FORGERY: {
    title: 'JWT Token Forgery',
    explanation: 'A forged JWT with an invalid signature was presented. An algorithm confusion attack (e.g., HS256 vs RS256) was attempted, followed by replaying an expired token.',
    defense: 'Strict algorithm validation (RS256 only) + signature verification + token expiry enforcement.',
    severity: 'CRITICAL',
  },
  SESSION_FIXATION: {
    title: 'Session Fixation',
    explanation: 'An attacker tried to inject a pre-authenticated session ID, then attempted cookie tampering and session reuse after token rotation.',
    defense: 'Session regeneration on login + secure cookie settings (httpOnly, SameSite) + rotation detection.',
    severity: 'HIGH',
  },

  // ── API Attacks ────────────────────────────────────────────
  API_ABUSE: {
    title: 'API Abuse',
    explanation: 'Rapid unauthorized requests were sent to protected endpoints, attempting to enumerate resources or abuse rate limits.',
    defense: 'ABAC policy engine denied access. Rate limiter throttled requests. Repeated violations triggered IP strikes.',
    severity: 'MEDIUM',
  },
  RATE_LIMIT_BYPASS: {
    title: 'Rate Limit Bypass',
    explanation: 'Requests were sent from rotating IPs to circumvent per-IP rate limits. The system correlated the pattern across multiple source addresses.',
    defense: 'Distributed rate limiting + behavioral fingerprinting detects rotation patterns.',
    severity: 'MEDIUM',
  },
  INJECTION_ATTACK: {
    title: 'Injection Attack',
    explanation: 'SQL injection, XSS, and NoSQL injection payloads were sent to multiple endpoints. Input validation and parameterized queries prevented execution.',
    defense: 'Input sanitization middleware + parameterized queries (Prisma ORM) + Content-Security-Policy headers.',
    severity: 'CRITICAL',
  },

  // ── Authorization Attacks ──────────────────────────────────
  PRIVILEGE_ESCALATION: {
    title: 'Privilege Escalation',
    explanation: 'A lower-privileged user attempted to access admin endpoints, modify their own role, and trigger security simulations without authorization.',
    defense: 'RBAC permission checks (requirePermission middleware) + ABAC policy engine blocked all attempts.',
    severity: 'CRITICAL',
  },
  RBAC_BYPASS: {
    title: 'RBAC Bypass',
    explanation: 'Direct requests were made to permission-protected endpoints (roles API, simulate, metrics, users) without the required permissions.',
    defense: 'Multi-layer enforcement: requirePermission() + authorizePolicy() + role-based route guards.',
    severity: 'CRITICAL',
  },
};

// ── Action-level explanations for individual events ──────────
const ACTION_EXPLANATIONS = {
  LOGIN_FAILED: 'Login attempt with incorrect credentials was rejected by the authentication service.',
  MFA_FAILED: 'Invalid MFA code submitted — TOTP validation failed.',
  MFA_SKIP_ATTEMPT: 'Attempt to bypass MFA step entirely — blocked by temp token enforcement.',
  TOKEN_REUSE_DETECTED: 'Previously rotated refresh token was replayed — session immediately revoked.',
  TOKEN_INVALID_SIGNATURE: 'JWT with forged/invalid signature was rejected by verification middleware.',
  TOKEN_ALGORITHM_MISMATCH: 'JWT used an unexpected signing algorithm — blocked by algorithm whitelist.',
  TOKEN_EXPIRED_REUSE: 'Expired JWT was presented — token lifetime enforcement prevented access.',
  RBAC_ACCESS_DENIED: 'Request lacked the required RBAC permission for the target resource.',
  ABAC_ACCESS_DENIED: 'Attribute-based access control policy denied the request.',
  PERMISSION_DENIED: 'User does not hold the required permission for this operation.',
  ROLE_MODIFICATION_DENIED: 'Unauthorized attempt to elevate role — only admins can modify roles.',
  RATE_LIMIT_EXCEEDED: 'Request rate exceeded the configured threshold — temporarily throttled.',
  INJECTION_DETECTED: 'Malicious input payload detected and sanitized before processing.',
  SESSION_FIXATION_DETECTED: 'Pre-authenticated session injection attempt was blocked.',
  COOKIE_TAMPERING_DETECTED: 'Cookie integrity check failed — request rejected.',
  SESSION_REUSE_AFTER_ROTATION: 'Session ID was reused after rotation — potential replay attack blocked.',
  BLOCKED_BANNED_IP: 'Request from a banned IP address was automatically rejected.',
  IP_BANNED: 'IP address exceeded strike threshold and was temporarily banned.',
  STRIKE_RECORDED: 'A security strike was recorded against the source IP.',
};

const resolveRiskSeverity = (riskScore, fallbackSeverity = 'MEDIUM') => {
  if (typeof riskScore !== 'number' || Number.isNaN(riskScore)) {
    return fallbackSeverity;
  }

  if (riskScore < 20) return 'LOW';
  if (riskScore < 60) return 'MEDIUM';
  if (riskScore < 85) return 'HIGH';
  return 'CRITICAL';
};

export const explainAttack = (action, riskScore, defense) => {
  if (action === "JWT_TAMPER") {
    return "Token integrity violation detected. Request was cryptographically rejected before risk escalation.";
  }

  if (action === "MFA_FAILED" && defense) {
    return "Multiple failed MFA attempts detected. Risk threshold exceeded → automated defense triggered.";
  }

  const actionSummary = getActionExplanation(action);
  const defenseTriggered = Boolean(defense);

  if (typeof riskScore === 'number' && !Number.isNaN(riskScore)) {
    if (riskScore < 20) {
      return `${actionSummary} Attack blocked early due to validation checks.`;
    }

    if (riskScore >= 20 && riskScore < 60) {
      return `${actionSummary} Suspicious behavior detected but below defense threshold.`;
    }

    if (riskScore >= 60 && defenseTriggered) {
      return `${actionSummary} High-risk attack detected and automated defense triggered.`;
    }

    if (riskScore >= 60) {
      return `${actionSummary} High-risk behavior detected and escalated for containment.`;
    }
  }

  if (defenseTriggered) {
    return `${actionSummary} Defensive controls engaged automatically.`;
  }

  return actionSummary;
};

/**
 * Get the full explanation for an attack type.
 *
 * @param {string} attackType - e.g. 'BRUTE_FORCE', 'TOKEN_FORGERY'
 * @returns {{ title, explanation, defense, severity } | null}
 */
export const getAttackExplanation = (attackType) => {
  if (!attackType) return null;
  const key = attackType.toUpperCase().trim();
  return EXPLANATIONS[key] || null;
};

/**
 * Get a short explanation for an individual event action.
 *
 * @param {string} action - e.g. 'LOGIN_FAILED', 'MFA_FAILED'
 * @returns {string}
 */
export const getActionExplanation = (action) => {
  if (!action) return 'Security policy evaluated the request.';
  return ACTION_EXPLANATIONS[action.toUpperCase()] || 'Security policy evaluated the request.';
};

/**
 * Build a structured explanation object from a simulation result.
 *
 * @param {Object} result - { type, label, correlationId, message, ... }
 * @returns {Object} enriched explanation
 */
export const buildSimulationExplanation = (result) => {
  const baseExplanation = getAttackExplanation(result?.type);
  const riskScore =
    result?.riskScore ??
    result?.risk_score ??
    result?.result?.riskScore ??
    result?.result?.risk_score;
  const action =
    result?.action ??
    result?.eventAction ??
    result?.event_action ??
    result?.type;
  const defense =
    result?.defense ??
    result?.defenseAction ??
    result?.defense_action ??
    result?.result?.defense ??
    result?.result?.defenseAction ??
    result?.result?.defense_action ??
    '';

  if (!baseExplanation) {
    return {
      title: result?.label || result?.type || 'Unknown Attack',
      explanation: explainAttack(action, riskScore, defense),
      defense: defense || 'Standard security policies were applied.',
      severity: resolveRiskSeverity(riskScore, 'MEDIUM'),
      riskScore,
    };
  }

  return {
    ...baseExplanation,
    explanation: explainAttack(action, riskScore, defense) || baseExplanation.explanation,
    defense: defense || baseExplanation.defense,
    severity: resolveRiskSeverity(riskScore, baseExplanation.severity),
    riskScore,
  };
};

export default {
  explainAttack,
  getAttackExplanation,
  getActionExplanation,
  buildSimulationExplanation,
};
