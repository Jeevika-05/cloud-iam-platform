import React from 'react';
import usePermission from '../hooks/usePermission';

/**
 * RoleGuard
 *
 * Renders children only when the user holds the required permission.
 * Renders `fallback` (or null) otherwise — never redirects.
 * Compose inside ProtectedRoute so auth is already guaranteed.
 *
 * Props:
 *   permission  {string}     - e.g. 'users:list', 'audit:view'
 *   children    {ReactNode}  - content to show if permitted
 *   fallback    {ReactNode}  - optional UI to show when denied (default: null)
 *
 * Usage:
 *   <ProtectedRoute>
 *     <RoleGuard permission="users:list" fallback={<Unauthorized />}>
 *       <UsersPage />
 *     </RoleGuard>
 *   </ProtectedRoute>
 */
const RoleGuard = ({ permission, children, fallback = null }) => {
  const hasPermission = usePermission();

  if (!hasPermission(permission)) {
    return fallback;
  }

  return children;
};

export default RoleGuard;
