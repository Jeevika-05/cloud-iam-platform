import React, { useState, useEffect, useRef } from 'react';
import api from '../api/client';

const ActivityFeed = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [viewFilter, setViewFilter] = useState('all');

  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;

    const fetchData = async () => {
      try {
        const response = await api.get('/audit/events?limit=10');
        if (isMounted.current && response.data?.events) {
          setEvents(response.data.events);
        }
        if (isMounted.current) setError(null);
      } catch (err) {
        if (isMounted.current) {
          setError(
            err.status === 403 || err.response?.status === 403
              ? 'You do not have permission to view activity.'
              : 'Failed to load activity feed.'
          );
        }
      } finally {
        if (isMounted.current) {
          setLoading(false);
        }
      }
    };

    fetchData();

    // Refresh every 12 seconds
    const interval = setInterval(fetchData, 12000);

    return () => {
      isMounted.current = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div style={{ background: 'var(--bg-card)', borderRadius: '12px', padding: '20px', border: '1px solid var(--border)', height: '100%', overflowY: 'auto' }}>
      <h3 style={{ marginTop: 0, marginBottom: '20px', fontSize: '16px', color: 'var(--text)', display: 'flex', alignItems: 'center' }}>
        <span style={{ marginRight: '8px' }}>📜</span> Recent Activity
      </h3>
      
      {loading && events.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px 0' }}>Loading activity...</div>
      ) : error && events.length === 0 ? (
        <div style={{ color: '#ef4444', padding: '10px', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '6px' }}>{error}</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
            {['all', 'attacks', 'defense'].map(f => (
              <button 
                key={f}
                onClick={() => setViewFilter(f)}
                style={{
                  padding: '4px 12px',
                  fontSize: '12px',
                  borderRadius: '16px',
                  background: viewFilter === f ? '#3b82f6' : 'var(--bg-app)',
                  color: viewFilter === f ? '#fff' : 'var(--text)',
                  border: '1px solid var(--border)',
                  cursor: 'pointer'
                }}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
          {events.filter(e => {
            if (viewFilter === 'all') return true;
            const isDef = e.action === 'STRIKE' || e.action.includes('BAN') || e.metadata?.event_type === 'DEFENSE';
            if (viewFilter === 'defense') return isDef;
            if (viewFilter === 'attacks') return !isDef && (e.metadata?.event_type === 'ATTACK' || e.action.includes('FAIL') || e.action.includes('DENIED') || e.action.includes('DETECTED') || ['HIGH', 'CRITICAL'].includes(e.severity));
            return true;
          }).map((e) => {
            const severity = e.severity || e.metadata?.severity || 'LOW';
            return (
            <div key={e.event_id || e.id} style={{ padding: '12px', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '14px', background: 'var(--bg-app)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <strong style={{ color: e.action.includes('FAIL') || e.action.includes('DENIED') ? '#ef4444' : 'var(--text)' }}>
                    {e.action}
                  </strong>
                  <span style={{
                    padding: '2px 6px',
                    borderRadius: '6px',
                    fontSize: '10px',
                    fontWeight: 700,
                    background:
                      severity === 'CRITICAL' ? '#dc2626' :
                      severity === 'HIGH' ? '#ef4444' :
                      severity === 'MEDIUM' ? '#f59e0b' :
                      '#10b981',
                    color: '#fff'
                  }}>
                    {severity}
                  </span>
                </div>
                <span style={{ fontSize: '11px', padding: '2px 8px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>
                  {e.role}
                </span>
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '12px' }}>
                {new Date(e.timestamp).toLocaleString()} {e.source_ip ? `· ${e.source_ip}` : ''}
              </div>
            </div>
          )})}
          {events.length === 0 && (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px 0' }}>No recent activity.</div>
          )}
        </div>
      )}
    </div>
  );
};

export default ActivityFeed;
