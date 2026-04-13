import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import usePermission from '../hooks/usePermission';

const Navbar = () => {
  const { isAuthenticated, logout } = useAuth();
  const hasPermission = usePermission();
  const navigate = useNavigate();

  // Do not render the navbar if the user is not logged in!
  if (!isAuthenticated) return null;

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <nav style={{
      position: 'sticky',
      top: 0,
      zIndex: 1000,
      backgroundColor: '#0f172a',
      color: '#ffffff',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '12px 24px',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '32px' }}>
        <h1 style={{ margin: 0, fontSize: '18px', fontWeight: 700, letterSpacing: '-0.5px' }}>
          Secure IAM Platform
        </h1>
        
        <div style={{ display: 'flex', gap: '20px' }}>
          <Link to="/dashboard" style={{ color: '#cbd5e1', textDecoration: 'none', fontSize: '14px', fontWeight: 500 }}>Dashboard</Link>
          {hasPermission('users:list') && (
            <Link to="/users" style={{ color: '#cbd5e1', textDecoration: 'none', fontSize: '14px', fontWeight: 500 }}>Users</Link>
          )}
          {hasPermission('audit:view') && (
            <Link to="/audit" style={{ color: '#cbd5e1', textDecoration: 'none', fontSize: '14px', fontWeight: 500 }}>Audit</Link>
          )}
        </div>
      </div>

      <button 
        onClick={handleLogout}
        style={{
          backgroundColor: 'transparent',
          border: '1px solid #334155',
          color: '#f8fafc',
          padding: '6px 14px',
          borderRadius: '6px',
          fontSize: '13px',
          fontWeight: 500,
          cursor: 'pointer',
          transition: 'all 0.2s'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.backgroundColor = '#1e293b';
          e.currentTarget.style.borderColor = '#475569';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.backgroundColor = 'transparent';
          e.currentTarget.style.borderColor = '#334155';
        }}
      >
        Logout
      </button>
    </nav>
  );
};

export default Navbar;
