import React, { createContext, useState, useEffect, useCallback } from 'react';
import { getMyPermissions } from '../api/rbac.api';
import { AuthContext } from './AuthContext';

export const RbacContext = createContext(null);

export const RbacProvider = ({ children }) => {
  const [role, setRole] = useState(null);
  const [permissions, setPermissions] = useState([]);

  // Reach into AuthContext directly (no hook — avoids circular dep with useAuth)
  const auth = React.useContext(AuthContext);

  // ─── Fetch permissions whenever auth state changes ────────────────────────
  const fetchPermissions = useCallback(async () => {
    if (!auth?.isAuthenticated) {
      setRole(null);
      setPermissions([]);
      return;
    }

    try {
      const res = await getMyPermissions();
      const { role: userRole, permissions: userPermissions } = res.data;

      setRole(userRole ?? null);
      setPermissions(Array.isArray(userPermissions) ? userPermissions : []);
    } catch {
      // Token might not be set yet or request failed
      setRole(null);
      setPermissions([]);
    }
  }, [auth?.isAuthenticated]);

  useEffect(() => {
    if (!auth?.isAuthenticated || auth?.loading) return;
    fetchPermissions();
  }, [auth?.isAuthenticated, auth?.loading, fetchPermissions]);

  // ─── Permission check ─────────────────────────────────────────────────────
  const hasPermission = useCallback(
    (permission) => permissions.includes(permission),
    [permissions]
  );

  const value = {
    role,
    permissions,
    hasPermission,
  };

  return (
    <RbacContext.Provider value={value}>
      {children}
    </RbacContext.Provider>
  );
};
