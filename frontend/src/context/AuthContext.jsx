import React, { useState, useEffect, useCallback } from 'react';
import * as authApi from '../api/auth.api';
import * as userApi from '../api/user.api';
import { setAccessToken, fetchCsrfToken, resetCsrfState } from '../api/client';
import { AuthContext } from './auth-context';

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [tempToken, setTempToken] = useState(null);

  // ─── Refresh Token ──────────────────────────────────────────────────────────
  const refreshToken = useCallback(async () => {
    try {
      const res = await authApi.refresh();
      const { accessToken } = res;

      setAccessToken(accessToken);

      const profile = await userApi.getProfile();
      setUser(profile);
      setIsAuthenticated(true);
    } catch {
      // Refresh cookie absent or expired — stay unauthenticated silently
      setAccessToken(null);
      setUser(null);
      setIsAuthenticated(false);
    }
  }, []);

  // ─── On App Load ────────────────────────────────────────────────────────────
  useEffect(() => {
    let isMounted = true;

    const bootstrap = async () => {
      try {
        await fetchCsrfToken(); // ensure CSRF is ready

        const res = await authApi.refresh();
        if (!isMounted) return;

        const { accessToken } = res;
        setAccessToken(accessToken);

        const profile = await userApi.getProfile();
        if (!isMounted) return;

        setUser(profile);
        setIsAuthenticated(true);
      } catch {
        if (!isMounted) return;

        setAccessToken(null);
        setUser(null);
        setIsAuthenticated(false);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    bootstrap();

    return () => {
      isMounted = false;
    };
  }, []);

  // ─── Login ──────────────────────────────────────────────────────────────────
  const login = useCallback(async (email, password) => {
    const data = await authApi.login({ email, password });

    // ✅ Reset CSRF only if login attempt is valid
    if (data?.accessToken || data?.status === 'MFA_REQUIRED') {
      resetCsrfState();
    }

    if (data?.status === 'MFA_REQUIRED') {
      setTempToken(data.tempToken);
      return { mfaRequired: true };
    }

    const { accessToken, user: loggedInUser } = data;
    setAccessToken(accessToken);
    setUser(loggedInUser);
    setIsAuthenticated(true);

    return { success: true, user: loggedInUser };
  }, []);

  // ─── Logout ─────────────────────────────────────────────────────────────────
  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // ignore errors
    }

    // ✅ Reset CSRF state
    resetCsrfState();

    setAccessToken(null);
    setUser(null);
    setIsAuthenticated(false);
    setTempToken(null);
  }, []);

  // ─── Complete MFA Login ─────────────────────────────────────────────────────
  const completeMfaLogin = useCallback((accessToken, mfaUser) => {
    // ✅ Reset CSRF state
    resetCsrfState();

    setAccessToken(accessToken);
    setUser(mfaUser);
    setIsAuthenticated(true);
    setTempToken(null);
  }, []);

  const value = {
    user,
    isAuthenticated,
    loading,
    tempToken,
    login,
    logout,
    refreshToken,
    completeMfaLogin,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};