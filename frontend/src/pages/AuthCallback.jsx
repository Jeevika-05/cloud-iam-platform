import React, { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import * as authApi from '../api/auth.api';

const AuthCallback = () => {
  const navigate = useNavigate();
  const hasProcessed = useRef(false);

  useEffect(() => {
    if (hasProcessed.current) return; // prevent double call
    hasProcessed.current = true;

    const handleAuth = async () => {
      try {
        console.log("OAuth callback started");

        const res = await authApi.refresh(); // ✅ FIXED
        console.log("Refresh success:", res);

        navigate("/dashboard", { replace: true });
      } catch (err) {
        console.error("OAuth failed:", err);
        navigate("/login", { replace: true });
      }
    };

    handleAuth();
  }, [navigate]);

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      height: '100vh',
      flexDirection: 'column'
    }}>
      <h2>Authenticating...</h2>
      <p style={{ marginTop: '10px', color: '#666' }}>
        Please wait while we log you in...
      </p>
    </div>
  );
};

export default AuthCallback;