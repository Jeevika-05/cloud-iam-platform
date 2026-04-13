import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';

// Pages
import Login from '../pages/Login';
import Register from '../pages/Register';
import MfaPage from '../pages/MfaPage';
import Dashboard from '../pages/Dashboard';
import Profile from '../pages/Profile';
import Sessions from '../pages/Sessions';
import UsersPage from '../pages/Users';
import AuditPage from '../pages/Audit';
import AuthCallback from '../pages/AuthCallback';

// Guards
import ProtectedRoute from '../components/ProtectedRoute';
import RoleGuard from '../components/RoleGuard';
import Navbar from '../components/Navbar';

const GlobalEventHandler = () => {
  const navigate = useNavigate();
  React.useEffect(() => {
    const handleForbidden = () => navigate('/forbidden', { replace: true });
    window.addEventListener('auth:forbidden', handleForbidden);
    return () => window.removeEventListener('auth:forbidden', handleForbidden);
  }, [navigate]);
  return null;
};

const AppRouter = () => {
  return (
    <BrowserRouter>
      <GlobalEventHandler />
      <Navbar />
      <Routes>
        {/* ── Public ──────────────────────────────────────────── */}
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/mfa" element={<MfaPage />} />
        <Route path="/auth/callback" element={<AuthCallback />} />

        {/* ── Protected: auth required ────────────────────────── */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />

        <Route
          path="/profile"
          element={
            <ProtectedRoute>
              <Profile />
            </ProtectedRoute>
          }
        />

        <Route
          path="/sessions"
          element={
            <ProtectedRoute>
              <Sessions />
            </ProtectedRoute>
          }
        />

        {/* ── Protected: auth + permission ────────────────────── */}
        <Route
          path="/users"
          element={
            <ProtectedRoute>
              <RoleGuard permission="users:list">
                <UsersPage />
              </RoleGuard>
            </ProtectedRoute>
          }
        />

        <Route
          path="/audit"
          element={
            <ProtectedRoute>
              <RoleGuard permission="audit:view">
                <AuditPage />
              </RoleGuard>
            </ProtectedRoute>
          }
        />



        <Route
          path="/forbidden"
          element={
            <div style={{ padding: '40px', textAlign: 'center' }}>
              <h2>403 — Access Denied</h2>
              <p>You don't have permission to access this resource.</p>
              <a href="/dashboard">Return to Dashboard</a>
            </div>
          }
        />

        {/* ── Catch-all ───────────────────────────────────────── */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default AppRouter;
