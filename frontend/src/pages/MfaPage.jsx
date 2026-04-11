import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import { validateMfaLogin } from '../api/auth.api';

const MfaPage = () => {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const { tempToken, completeMfaLogin } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    try {
      const res = await validateMfaLogin({ tempToken, code });
      const { accessToken, user } = res.data.data;

      // Set token + user + isAuthenticated in one shot — mirrors login() success
      completeMfaLogin(accessToken, user);

      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid code. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  // Guard: if no tempToken, user shouldn't be here
  if (!tempToken) {
    return (
      <div className="mfa-container">
        <h2>MFA Verification</h2>
        <p>No MFA session found. Please <a href="/login">login</a> first.</p>
      </div>
    );
  }

  return (
    <div className="mfa-container">
      <h2>MFA Verification</h2>
      <p>Enter the 6-digit code from your authenticator app.</p>

      {error && <p className="error-message">{error}</p>}

      <form onSubmit={handleSubmit}>
        <div>
          <label>Code: </label>
          <input
            type="text"
            inputMode="numeric"
            maxLength={6}
            pattern="[0-9]{6}"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            autoFocus
            required
          />
        </div>
        <button type="submit" disabled={submitting || code.length !== 6}>
          {submitting ? 'Verifying…' : 'Verify'}
        </button>
      </form>
    </div>
  );
};

export default MfaPage;
