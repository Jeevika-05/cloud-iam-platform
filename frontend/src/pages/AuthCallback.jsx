import React, { useEffect, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import * as authApi from '../api/auth.api';
import * as userApi from '../api/user.api';
import { setAccessToken, resetCsrfState, fetchCsrfToken } from '../api/client'; // ✅ FIXED IMPORT
import useAuth from '../hooks/useAuth';

const AuthCallback = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const hasProcessed = useRef(false);
  const { completeMfaLogin } = useAuth();

  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;

    const handleAuth = async () => {
      try {
        // 🔴 OAuth error
        const error = searchParams.get('error');
        if (error) {
          navigate('/login?error=oauth_failed', { replace: true });
          return;
        }

        // 🔐 MFA required
        const mfa = searchParams.get('mfa');
        const tempToken = searchParams.get('tempToken');
        if (mfa && tempToken) {
          sessionStorage.setItem('oauth_temp_token', tempToken);
          navigate('/mfa', { replace: true });
          return;
        }

        // ✅ Access token from backend redirect
        const token = searchParams.get('token');
        if (token) {
          setAccessToken(token);

          // 🔥 CRITICAL FIX: reset + refetch CSRF after OAuth
          resetCsrfState();
          await fetchCsrfToken();

          const profile = await userApi.getProfile();
          completeMfaLogin(token, profile);

          navigate('/dashboard', { replace: true });
          return;
        }

        // 🔄 Fallback: use refresh cookie
        const res = await authApi.refresh();
        const { accessToken } = res;

        setAccessToken(accessToken);

        // (optional but safe) also refresh CSRF here
        resetCsrfState();
        await fetchCsrfToken();

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
      <p className="text-slate-600 text-sm font-medium">
        Completing authentication…
      </p>
    </div>
  );
};

export default AuthCallback;