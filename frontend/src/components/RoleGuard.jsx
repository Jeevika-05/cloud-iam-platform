import React from 'react';
import { Navigate } from 'react-router-dom';
import usePermission from '../hooks/usePermission';

/**
 * RoleGuard
 *
 * Renders children only when the user holds the required permission.
 * Redirects to /forbidden by default when denied — override with `fallback`.
 * Compose inside ProtectedRoute so auth is already guaranteed.
 *
 * Props:
 *   permission  {string}     - e.g. 'users:list', 'audit:view'
 *   children    {ReactNode}  - content to show if permitted
 *   fallback    {ReactNode}  - optional UI to show when denied (default: redirect to /forbidden)
 *
 * Usage:
 *   <ProtectedRoute>
 *     <RoleGuard permission="users:list" fallback={<Unauthorized />}>
 *       <UsersPage />
 *     </RoleGuard>
 *   </ProtectedRoute>
 */
const RoleGuard = ({ permission, children, fallback = <Navigate to="/forbidden" replace /> }) => {
  const hasPermission = usePermission();

  if (!hasPermission(permission)) {
    return fallback;
  }

  return children;
};

export default RoleGuard;
