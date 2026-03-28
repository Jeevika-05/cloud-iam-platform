export const policies = [
  // 🔥 ADMIN: full access
  {
    roles: ['ADMIN'],
    actions: ['*'],
    resources: ['*'],
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
