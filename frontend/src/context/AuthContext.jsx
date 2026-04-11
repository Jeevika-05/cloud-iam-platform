import React, { createContext, useState, useEffect, useCallback } from 'react';
import * as authApi from '../api/auth.api';
import * as userApi from '../api/user.api';
import { setAccessToken } from '../api/client';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [tempToken, setTempToken] = useState(null);

  // ─── Refresh Token ──────────────────────────────────────────────────────────
  const refreshToken = useCallback(async () => {
    try {
      const res = await authApi.refresh();
      const { accessToken } = res.data.data;

      setAccessToken(accessToken);

      const profile = await userApi.getProfile();
      setUser(profile.data.user || profile.data);
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
    const bootstrap = async () => {
      await refreshToken();
      setLoading(false);
    };
    bootstrap();
  }, [refreshToken]);

  // ─── Login ──────────────────────────────────────────────────────────────────
  // Returns a status object — the calling component handles navigation.
  const login = useCallback(async (email, password) => {
    const res = await authApi.login({ email, password });
    const data = res.data;

    if (data?.status === 'MFA_REQUIRED') {
      setTempToken(data.tempToken);
      return { mfaRequired: true };
    }

    const { accessToken, user: loggedInUser } = data;
    setAccessToken(accessToken);
    setUser(loggedInUser);
    setIsAuthenticated(true);
    return { success: true };
  }, []);

  // ─── Logout ─────────────────────────────────────────────────────────────────
  // Invalidates backend session, then clears client state.
  // Always clears client state even if the API call fails.
  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // Backend unreachable or session already expired — clear client state anyway
    }
    setAccessToken(null);
    setUser(null);
    setIsAuthenticated(false);
    setTempToken(null);
  }, []);

  // ─── Complete MFA Login ─────────────────────────────────────────────────────
  // Called by MfaPage after successful TOTP validation.
  // Sets token + user + auth state directly — same as login() success path.
  const completeMfaLogin = useCallback((accessToken, mfaUser) => {
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
