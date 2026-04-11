import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import useAuth from '../hooks/useAuth';

/**
 * ProtectedRoute
 *
 * Renders children only when the user is authenticated.
 * Waits for the auth bootstrap (refresh token check) to complete
 * before making any redirect decision — prevents flicker.
 *
 * Usage:
 *   <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
 */
const ProtectedRoute = ({ children }) => {
  const { user, isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="auth-loading" aria-label="Verifying session">
        <span className="auth-loading__spinner" />
        <p>Loading…</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  // 🔒 Enforce MFA Setup for Administrators
  if (user?.role === 'ADMIN' && user?.totpEnabled === false && location.pathname !== '/profile') {
    return <Navigate to="/profile" replace />;
  }

  return children;
};

export default ProtectedRoute;
