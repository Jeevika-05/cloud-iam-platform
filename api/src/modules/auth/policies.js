export const policies = [
  // 🔥 ADMIN: full access with Strict Network Bounds
  {
    roles: ['ADMIN'],
    actions: ['*'],
    resources: ['*'],
    // 🔒 SEC-07: Restrict ADMIN to loopback + RFC 1918 private ranges (Docker/K8s)
    condition: ({ context }) => {
      const cleanIP = (context.ip || '').replace('::ffff:', '');
      return (
        cleanIP === '127.0.0.1' ||
        cleanIP === '::1' ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIP) ||
        cleanIP.startsWith('10.') ||
        cleanIP.startsWith('192.168.')
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

  // 🛡️ SECURITY_ANALYST: read all users, view audit/metrics, simulate attacks
  {
    roles: ['SECURITY_ANALYST'],
    actions: ['read', 'simulate'],
    resources: ['user', 'audit', 'metrics', 'security', 'graph', 'rbac'],
  },

  // 👤 USER: read own audit events
  {
    roles: ['USER'],
    actions: ['read'],
    resources: ['audit'],
  },

  // 🔐 USER: manage own sessions
  {
    roles: ['USER'],
    actions: ['read', 'delete'],
    resources: ['session'],
    condition: ({ user, resource }) => user.id === resource.userId,
  }
];
