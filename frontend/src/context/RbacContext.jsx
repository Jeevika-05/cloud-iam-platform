import React, { useState, useEffect, useCallback } from 'react';
import { getMyPermissions } from '../api/rbac.api';
import { AuthContext } from './auth-context';
import { RbacContext } from './rbac-context';

const EMPTY_PERMISSIONS = [];

export const RbacProvider = ({ children }) => {
  const [stateRole, setRoleState] = useState(null);
  const [statePermissions, setPermissionsState] = useState(EMPTY_PERMISSIONS);

  // Reach into AuthContext directly (no hook — avoids circular dep with useAuth)
  const auth = React.useContext(AuthContext);

  const role = auth?.isAuthenticated ? stateRole : null;
  const permissions = auth?.isAuthenticated ? statePermissions : EMPTY_PERMISSIONS;

  // ─── Fetch permissions whenever auth state changes ────────────────────────
  useEffect(() => {
    if (!auth?.isAuthenticated || auth?.loading) {
      return;
    }

    let isMounted = true;

    const fetchPerms = async () => {
      try {
        const res = await getMyPermissions();
        if (!isMounted) return;
        
        const { role: userRole, permissions: userPermissions } = res;
        setRoleState(userRole ?? null);
        setPermissionsState(Array.isArray(userPermissions) ? userPermissions : EMPTY_PERMISSIONS);
      } catch {
        if (!isMounted) return;
        setRoleState(null);
        setPermissionsState(EMPTY_PERMISSIONS);
      }
    };

    fetchPerms();

    return () => {
      isMounted = false;
    };
  }, [auth?.isAuthenticated, auth?.loading]);

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
