import React, { useState, useEffect } from 'react';
import { getSessions, revokeSession, revokeAllSessions } from '../api/auth.api';

const Sessions = () => {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const fetchSessions = async () => {
    try {
      const res = await getSessions();
      setSessions(Array.isArray(res) ? res : []);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load sessions.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  const handleRevoke = async (id) => {
    setMessage('');
    try {
      await revokeSession(id);
      setMessage('Session revoked.');
      fetchSessions();
    } catch (err) {
      setMessage(err.response?.data?.message || 'Failed to revoke session.');
    }
  };

  const handleRevokeAll = async () => {
    setMessage('');
    try {
      await revokeAllSessions();
      setMessage('All sessions revoked.');
      fetchSessions();
    } catch (err) {
      setMessage(err.response?.data?.message || 'Failed to revoke sessions.');
    }
  };

  if (loading) return <p>Loading sessions…</p>;
  if (error) return <p className="error-message">{error}</p>;

  return (
    <div className="sessions-container">
      <h2>Active Sessions</h2>

      {message && <p className="session-message">{message}</p>}

      {sessions.length === 0 ? (
        <p>No active sessions found.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>IP</th>
                <th>Last Used</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id || session._id}>
                  <td>{session.device || session.userAgent || '—'}</td>
                  <td>{session.ip || '—'}</td>
                  <td>
                    {session.lastUsedAt
                      ? new Date(session.lastUsedAt).toLocaleString()
                      : '—'}
                  </td>
                  <td>
                    <button onClick={() => handleRevoke(session.id || session._id)}>
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <button onClick={handleRevokeAll}>Revoke All Sessions</button>
        </>
      )}
    </div>
  );
};

export default Sessions;
