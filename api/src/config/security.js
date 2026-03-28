export const SECURITY_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCK_TIME:
    process.env.NODE_ENV === 'development'
      ? 60 * 1000      // 1 minute (dev)
      : 15 * 60 * 1000 // 15 minutes (prod)
};
