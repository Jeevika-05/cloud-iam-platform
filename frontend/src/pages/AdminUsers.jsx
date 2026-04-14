import React, { useEffect, useState } from 'react';
import * as adminApi from '../api/admin.api';
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";

dayjs.extend(relativeTime);

const AdminUsers = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [processingId, setProcessingId] = useState(null);

  useEffect(() => {
    fetchPendingUsers();
  }, []);

  const fetchPendingUsers = async () => {
    try {
      setLoading(true);
      const data = await adminApi.getPendingUsers();
      setUsers(data?.data || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch pending users');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (user) => {
    try {
      setProcessingId(user.id);
      await adminApi.approveUser(user.email);
      setUsers((prev) => prev.filter((u) => u.id !== user.id));
      alert('User approved successfully!');
    } catch (err) {
      alert(err.message || 'Approval failed');
    } finally {
      setProcessingId(null);
    }
  };

  const handleReject = async (user) => {
    if (!window.confirm("Reject admin access?")) return;
    try {
      setProcessingId(user.id);
      await adminApi.rejectUser(user.email);
      setUsers((prev) => prev.filter((u) => u.id !== user.id));
      alert('User rejected successfully!');
    } catch (err) {
      alert(err.message || 'Rejection failed');
    } finally {
      setProcessingId(null);
    }
  };

  if (loading) return <div style={{ padding: '24px' }}>Loading pending users...</div>;
  if (error) return <div style={{ padding: '24px', color: 'red' }}>Error: {error}</div>;

  return (
    <div style={{ padding: '32px', maxWidth: '1000px', margin: '0 auto' }}>
      <h2 style={{ marginBottom: '24px' }}>Admin Approvals</h2>
      {users.length === 0 ? (
        <div style={{ padding: '24px', backgroundColor: '#1e293b', borderRadius: '8px', color: '#94a3b8' }}>
          No pending approvals found.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', backgroundColor: '#1e293b', borderRadius: '8px', overflow: 'hidden' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #334155', backgroundColor: '#0f172a' }}>
              <th style={{ padding: '16px', textAlign: 'left', color: '#cbd5e1' }}>Email</th>
              <th style={{ padding: '16px', textAlign: 'left', color: '#cbd5e1' }}>Role Source</th>
              <th style={{ padding: '16px', textAlign: 'left', color: '#cbd5e1' }}>Status</th>
              <th style={{ padding: '16px', textAlign: 'left', color: '#cbd5e1' }}>Created</th>
              <th style={{ padding: '16px', textAlign: 'right', color: '#cbd5e1' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} style={{ borderBottom: '1px solid #334155' }}>
                <td style={{ padding: '16px', color: '#f8fafc' }}>{user.email}</td>
                <td style={{ padding: '16px', color: '#94a3b8' }}>{user.roleSource}</td>
                <td style={{ padding: '16px' }}>
                  <span className={`badge ${user.role}`} style={{ 
                    backgroundColor: '#ca8a04', 
                    color: '#fff', 
                    padding: '4px 8px', 
                    borderRadius: '4px', 
                    fontSize: '12px',
                    fontWeight: 500
                  }}>
                    PENDING_ADMIN
                  </span>
                </td>
                <td style={{ padding: '16px', color: '#94a3b8' }}>{dayjs(user.createdAt).fromNow()}</td>
                <td style={{ padding: '16px', textAlign: 'right', display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                  <button
                    onClick={() => handleApprove(user)}
                    disabled={processingId === user.id}
                    style={{
                      backgroundColor: processingId === user.id ? '#475569' : '#16a34a',
                      color: 'white',
                      border: 'none',
                      padding: '8px 16px',
                      borderRadius: '4px',
                      cursor: processingId === user.id ? 'not-allowed' : 'pointer',
                      fontSize: '14px',
                      fontWeight: 500
                    }}
                  >
                    {processingId === user.id ? 'Processing...' : 'Approve'}
                  </button>
                  <button
                    onClick={() => handleReject(user)}
                    disabled={processingId === user.id}
                    style={{
                      backgroundColor: processingId === user.id ? '#475569' : '#dc2626',
                      color: 'white',
                      border: 'none',
                      padding: '8px 16px',
                      borderRadius: '4px',
                      cursor: processingId === user.id ? 'not-allowed' : 'pointer',
                      fontSize: '14px',
                      fontWeight: 500
                    }}
                  >
                    Reject
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default AdminUsers;
