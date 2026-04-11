import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import * as authApi from '../api/auth.api';
import useAuth from '../hooks/useAuth';

const AuthCallback = () => {
  const navigate = useNavigate();
  const { refreshToken } = useAuth();
  const hasProcessed = useRef(false);

  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const restoreSession = async () => {
      try {
        // 1. Explicitly call refresh endpoint to restore session from cookie
        await authApi.refresh();
        
        // 2. Refresh AuthContext state using our restored session
        await refreshToken(); 
        
        // 3. Redirect to dashboard on success
        navigate('/dashboard', { replace: true });
      } catch (err) {
        console.error('Failed to restore session:', err);
        // 4. Redirect to login on failure
        navigate('/login', { replace: true });
      }
    };

    restoreSession();
  }, [navigate, refreshToken]);

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', flexDirection: 'column' }}>
      <h2>Authenticating...</h2>
      <p style={{ marginTop: '10px', color: '#666' }}>Please wait while we log you in...</p>
    </div>
  );
};

export default AuthCallback;
