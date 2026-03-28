export const policies = [
  // 🔥 ADMIN: full access with Strict Network Bounds
  {
    roles: ['ADMIN'],
    actions: ['*'],
    resources: ['*'],
   condition: ({ context }) => {
  const TRUSTED_IP = process.env.TRUSTED_IP || '::1';

  return (
    context.ip === TRUSTED_IP ||
    context.ip === '127.0.0.1' ||
    context.ip.includes('172.19.')   // 🔥 allow docker network
  );
}
  },

  // 🔒 SENSITIVE ACTION: Requires fully verified MFA lifecycle
  {
    roles: ['ADMIN', 'SECURITY_ANALYST', 'USER'],
    actions: ['modify_security', 'billing', 'delete'],
    resources: ['sensitive'],
    condition: ({ user, context }) => {
      // Must have enabled TOTP and completed the current session's MFA challenge successfully
      return user.totpEnabled === true && context.session?.mfaVerified === true;
    }
  },

  // 👤 USER: read/update only own profile
  {
    roles: ['USER'],
    actions: ['read', 'update'],
    resources: ['user'],
    condition: ({ user, resource }) => user.id === resource.id,
  },

  // 🛡️ SECURITY_ANALYST: read all users
  {
    roles: ['SECURITY_ANALYST'],
    actions: ['read'],
    resources: ['user'],
  },

  // 🔐 USER: manage own sessions
  {
    roles: ['USER'],
    actions: ['delete'],
    resources: ['session'],
    condition: ({ user, resource }) => user.id === resource.userId,
  }
];
