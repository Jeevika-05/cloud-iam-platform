import React, { useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import * as authApi from '../api/auth.api';
import * as userApi from '../api/user.api';
import { setAccessToken } from '../api/client';
import useAuth from '../hooks/useAuth';

const AuthCallback = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const hasProcessed = useRef(false);
  const { completeMfaLogin } = useAuth();   // reuse existing context updater

  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const handleAuth = async () => {
      try {
        // FIX: check for OAuth error first
        const error = searchParams.get('error');
        if (error) {
          navigate('/login?error=oauth_failed', { replace: true });
          return;
        }

        // FIX: MFA required during OAuth
        const mfa = searchParams.get('mfa');
        const tempToken = searchParams.get('tempToken');
        if (mfa && tempToken) {
          // Store tempToken for MFA page (via sessionStorage — short-lived, same tab)
          sessionStorage.setItem('oauth_temp_token', tempToken);
          navigate('/mfa', { replace: true });
          return;
        }

        // FIX: read access token passed from backend redirect
        const token = searchParams.get('token');
        if (token) {
          setAccessToken(token);
          // Fetch profile to complete AuthContext hydration
          const profile = await userApi.getProfile();
          completeMfaLogin(token, profile);  // reuse: sets user + isAuthenticated + clears tempToken
          navigate('/dashboard', { replace: true });
          return;
        }

        // Fallback: try refresh cookie (covers cases where cookie did work)
        const res = await authApi.refresh();
        const { accessToken } = res;
        setAccessToken(accessToken);
        const profile = await userApi.getProfile();
        completeMfaLogin(accessToken, profile);
        navigate('/dashboard', { replace: true });

      } catch (err) {
        console.error('OAuth callback failed:', err);
        navigate('/login?error=oauth_failed', { replace: true });
      }
    };

    handleAuth();
  }, [navigate, searchParams, completeMfaLogin]);

  return (
    <div className="flex justify-center items-center h-screen flex-col gap-3">
      <div className="animate-spin w-8 h-8 border-4 border-indigo-600 border-t-transparent rounded-full" />
      <p className="text-slate-600 text-sm font-medium">Completing authentication…</p>
    </div>
  );
};

export default AuthCallback;