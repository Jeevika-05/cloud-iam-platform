import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';

// Pages
import Login from '../pages/Login';
import Register from '../pages/Register';
import MfaPage from '../pages/MfaPage';
import Dashboard from '../pages/Dashboard';
import Profile from '../pages/Profile';
import Sessions from '../pages/Sessions';
import UsersPage from '../pages/Users';
import AuditPage from '../pages/Audit';
import SecuritySimulation from '../pages/SecuritySimulation';

// Guards
import ProtectedRoute from '../components/ProtectedRoute';
import RoleGuard from '../components/RoleGuard';

const AppRouter = () => {
  return (
    <BrowserRouter>
      <Routes>
        {/* ── Public ──────────────────────────────────────────── */}
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/mfa" element={<MfaPage />} />

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
          path="/security"
          element={
            <ProtectedRoute>
              <RoleGuard permission="security:simulate">
                <SecuritySimulation />
              </RoleGuard>
            </ProtectedRoute>
          }
        />

        {/* ── Catch-all ───────────────────────────────────────── */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
};

export default AppRouter;
