// ─────────────────────────────────────────────────────────────
// IP CLASSIFIER — Single source of truth for IP type detection
// ─────────────────────────────────────────────────────────────
// Used by: activeDefender, audit.service, neo4j_ingest
// Centralizes the logic for detecting simulated vs real IPs
// to prevent inconsistencies across the pipeline.
// ─────────────────────────────────────────────────────────────

/**
 * RFC 1918 / RFC 5737 private ranges used by the simulation engine.
 * Covers: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 */
const PRIVATE_IP_RE = /^(192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/;

/**
 * Classify an IP + optional user-agent as SIMULATED or REAL.
 *
 * @param {string|null|undefined} ip
 * @param {string|null|undefined} userAgent
 * @returns {'SIMULATED' | 'REAL' | 'UNKNOWN'}
 */
export const classifyIp = (ip, userAgent) => {
  if (!ip) return 'UNKNOWN';
  if (PRIVATE_IP_RE.test(ip)) return 'SIMULATED';
  if (userAgent?.includes('attack-engine')) return 'SIMULATED';
  return 'REAL';
};

/**
 * Check if an IP belongs to a private / simulation range.
 * Used to decide whether events should be tagged as simulation data.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export const isSimulationIp = (ip) => {
  if (!ip) return false;
  return PRIVATE_IP_RE.test(ip);
};
