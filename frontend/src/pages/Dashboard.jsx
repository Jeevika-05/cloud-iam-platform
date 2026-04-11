import React from 'react';
import { useNavigate, Link } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import usePermission from '../hooks/usePermission';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const hasPermission = usePermission();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="dashboard-container">
      <h2>Dashboard</h2>

      <div className="user-info">
        <p><strong>Name:</strong> {user?.name || '—'}</p>
        <p><strong>Email:</strong> {user?.email || '—'}</p>
        <p><strong>Role:</strong> {user?.role || '—'}</p>
      </div>

      <nav className="dashboard-nav">
        <Link to="/profile">Profile</Link>
        <Link to="/sessions">Sessions</Link>

        {hasPermission('users:list') && (
          <Link to="/users">Admin Panel</Link>
        )}

        {hasPermission('audit:view') && (
          <Link to="/audit">Audit Logs</Link>
        )}

        {hasPermission('security:simulate') && (
          <Link to="/security">Attack Simulation</Link>
        )}
      </nav>

      <button onClick={handleLogout}>Logout</button>
    </div>
  );
};

export default Dashboard;
