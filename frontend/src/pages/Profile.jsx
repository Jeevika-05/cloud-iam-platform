import React, { useState, useEffect } from 'react';
import { getProfile, setupMfa, verifyMfa, disableMfa } from '../api/user.api';

const Profile = () => {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // MFA setup flow state
  const [mfaSetup, setMfaSetup] = useState(null); // { qrCode, secret }
  const [mfaCode, setMfaCode] = useState('');
  const [mfaMessage, setMfaMessage] = useState('');

  const fetchProfile = async () => {
    try {
      const res = await getProfile();
      setProfile(res.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load profile.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  // ─── Enable MFA (step 1: setup) ──────────────────────────────────────────
  const handleEnableMfa = async () => {
    setMfaMessage('');
    try {
      const res = await setupMfa();
      setMfaSetup(res.data);
    } catch (err) {
      setMfaMessage(err.response?.data?.message || 'Failed to start MFA setup.');
    }
  };

  // ─── Enable MFA (step 2: verify) ─────────────────────────────────────────
  const handleVerifyMfa = async (e) => {
    e.preventDefault();
    setMfaMessage('');
    try {
      await verifyMfa({ code: mfaCode });
      setMfaSetup(null);
      setMfaCode('');
      setMfaMessage('MFA enabled successfully.');
      fetchProfile(); // refresh totpEnabled
    } catch (err) {
      setMfaMessage(err.response?.data?.message || 'Invalid code.');
    }
  };

  // ─── Disable MFA ─────────────────────────────────────────────────────────
  const handleDisableMfa = async () => {
    setMfaMessage('');
    try {
      await disableMfa();
      setMfaMessage('MFA disabled.');
      fetchProfile();
    } catch (err) {
      setMfaMessage(err.response?.data?.message || 'Failed to disable MFA.');
    }
  };

  if (loading) return <p>Loading profile…</p>;
  if (error) return <p className="error-message">{error}</p>;

  return (
    <div className="profile-container">
      <h2>Profile</h2>

      <div className="profile-info">
        <p><strong>Name:</strong> {profile?.name || '—'}</p>
        <p><strong>Email:</strong> {profile?.email || '—'}</p>
        <p><strong>Role:</strong> {profile?.role || '—'}</p>
        <p><strong>MFA:</strong> {profile?.totpEnabled ? 'Enabled' : 'Disabled'}</p>
      </div>

      {/* MFA actions */}
      <div className="mfa-actions">
        {!profile?.totpEnabled && !mfaSetup && (
          <button onClick={handleEnableMfa}>Enable MFA</button>
        )}

        {profile?.totpEnabled && (
          <button onClick={handleDisableMfa}>Disable MFA</button>
        )}
      </div>

      {/* MFA setup flow — QR code + verify input */}
      {mfaSetup && (
        <div className="mfa-setup">
          <h3>Scan QR Code</h3>
          {mfaSetup.qrCode && (
            <img src={mfaSetup.qrCode} alt="MFA QR Code" />
          )}
          {mfaSetup.secret && (
            <p><strong>Manual key:</strong> {mfaSetup.secret}</p>
          )}
          <form onSubmit={handleVerifyMfa}>
            <label>Enter code from app: </label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              pattern="[0-9]{6}"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
              required
            />
            <button type="submit" disabled={mfaCode.length !== 6}>Verify</button>
          </form>
        </div>
      )}

      {mfaMessage && <p className="mfa-message">{mfaMessage}</p>}
    </div>
  );
};

export default Profile;
