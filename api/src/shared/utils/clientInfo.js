// ─────────────────────────────────────────────────────────────
// CLIENT INFO — Secure IP Resolution
// ─────────────────────────────────────────────────────────────
// 🔒 SEC-06: Use req.ip (respects Express trust proxy setting)
//            NEVER read raw X-Forwarded-For — prevents IP spoofing.
//
// Simulation mode: When SIMULATION_MODE=true, the X-Simulated-IP
// header is accepted as an override. In production this header
// is always ignored, even if present.
// ─────────────────────────────────────────────────────────────

const SIMULATION_MODE = (process.env.SIMULATION_MODE || '').toLowerCase() === 'true';

/**
 * Returns the client IP from Express's trust-proxy-aware req.ip.
 *
 * In simulation mode only, the X-Simulated-IP header is honoured
 * so the Rust attack engine can inject controlled source IPs
 * without polluting real defense state.
 *
 * @param {import('express').Request} req
 * @returns {string}
 */
export const getClientIp = (req) => {
  // Simulation override — production MUST ignore this header
  if (SIMULATION_MODE) {
    const simulated = req.headers['x-simulated-ip'];
    if (simulated) return simulated.trim();
  }

  // 🔒 Primary: Express trust-proxy-aware IP (honours `app.set('trust proxy', 1)`)
  return req.ip || req.socket?.remoteAddress || 'unknown';
};

export function extractClientInfo(req) {
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'unknown';
  return { ip, userAgent };
}
