// 🔒 SEC-06: Use req.ip (respects trust proxy setting) instead of raw X-Forwarded-For
export function extractClientInfo(req) {
  const ip =
    req.ip ||
    req.socket?.remoteAddress ||
    'unknown';

  const userAgent =
    req.headers['user-agent'] || 'unknown';

  return { ip, userAgent };
}
