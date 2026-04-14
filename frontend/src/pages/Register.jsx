import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import * as authApi from '../api/auth.api';
import PasswordInput from '../components/PasswordInput';

const Register = () => {
  const [name, setName]                       = useState('');
  const [email, setEmail]                     = useState('');
  const [password, setPassword]               = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMsg, setErrorMsg]               = useState(null);
  const [successMsg, setSuccessMsg]           = useState(null);
  const [submitting, setSubmitting]           = useState(false);

  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (password !== confirmPassword) {
      setErrorMsg('Passwords do not match.');
      return;
    }

    if (password.length < 8) {
      setErrorMsg('Password must be at least 8 characters.');
      return;
    }

    setSubmitting(true);
    try {
      await authApi.register({ name, email, password });
      setSuccessMsg('Account created! Redirecting to login…');
      setTimeout(() => navigate('/login'), 1500);
    } catch (error) {
      setErrorMsg(error.message || 'Registration failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const passwordsMatch = confirmPassword.length > 0 && password === confirmPassword;
  const passwordsMismatch = confirmPassword.length > 0 && password !== confirmPassword;

  return (
    <div className="auth-page">
      <div className="auth-card">

        {/* Header */}
        <div className="auth-header">
          <div className="auth-logo">🛡️</div>
          <h1 className="auth-title">Create account</h1>
          <p className="auth-subtitle">Join the IAM Security Platform</p>
        </div>

        {/* Banners */}
        {errorMsg && (
          <div className="auth-error" role="alert">
            <span className="auth-error__icon">⚠</span>
            {errorMsg}
          </div>
        )}
        {successMsg && (
          <div className="auth-success" role="status">
            <span>✓</span> {successMsg}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          <div className="auth-field">
            <label htmlFor="reg-name" className="auth-label">Full name</label>
            <input
              id="reg-name"
              type="text"
              className="auth-input"
              placeholder="Jane Smith"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoComplete="name"
              required
              minLength={2}
            />
          </div>

          <div className="auth-field">
            <label htmlFor="reg-email" className="auth-label">Email address</label>
            <input
              id="reg-email"
              type="email"
              className="auth-input"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </div>

          <div className="auth-field">
            <label htmlFor="reg-password" className="auth-label">Password</label>
            <PasswordInput
              id="reg-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
              autoComplete="new-password"
              showStrength
            />
          </div>

          <div className="auth-field">
            <label htmlFor="reg-confirm" className="auth-label">
              Confirm password
              {passwordsMatch   && <span className="auth-match-ok">  ✓ Match</span>}
              {passwordsMismatch && <span className="auth-match-err"> ✗ Mismatch</span>}
            </label>
            <PasswordInput
              id="reg-confirm"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Repeat your password"
              autoComplete="new-password"
            />
          </div>

          <button
            type="submit"
            className="auth-btn auth-btn--primary"
            disabled={submitting}
          >
            {submitting ? (
              <span className="auth-btn__spinner" />
            ) : 'Create account'}
          </button>
        </form>

        <p className="auth-footer-link">
          Already have an account?{' '}
          <Link to="/login">Sign in</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
