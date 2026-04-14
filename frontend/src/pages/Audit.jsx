import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import client from '../api/client';

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const AuditPage = () => {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [limit, setLimit] = useState(50);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('limit', limit);
      if (severityFilter) params.set('severity', severityFilter);
      if (actionFilter) params.set('action', actionFilter);

      const res = await client.get(`/audit/events?${params.toString()}`);
      const data = res.data;
      setEvents(data?.events || []);
    } catch (err) {
      setError(err.message || 'Failed to load audit events.');
    } finally {
      setLoading(false);
    }
  }, [severityFilter, actionFilter, limit]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const handleRowClick = (event) => {
    const correlationId =
      event?.correlation_id ||
      event?.correlationId ||
      event?.metadata?.correlation_id ||
      event?.metadata?.correlationId;

    if (!correlationId) {
      return;
    }

    localStorage.setItem('lastCorrelationId', correlationId);
    navigate(`/graph?correlation_id=${encodeURIComponent(correlationId)}`);
  };

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '36px 24px' }}>
      <header style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '26px', fontWeight: 700, margin: 0, letterSpacing: '-0.5px' }}>
          📋 Audit Logs
        </h1>
        <p style={{ color: 'var(--text)', fontSize: '14px', marginTop: '6px' }}>
          Security events across the platform. Filter by severity or action type.
        </p>
      </header>

      {/* Filters */}
      <div style={{
        display: 'flex', gap: '16px', marginBottom: '20px', flexWrap: 'wrap',
        padding: '16px', background: 'var(--bg-card, #f8f9fa)', borderRadius: '10px',
        border: '1px solid var(--border, #e5e7eb)', alignItems: 'center'
      }}>
        <div>
          <label style={{ marginRight: '8px', fontWeight: 600, fontSize: '13px' }}>Severity:</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border, #d1d5db)' }}
          >
            <option value="">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
        <div>
          <label style={{ marginRight: '8px', fontWeight: 600, fontSize: '13px' }}>Action:</label>
          <input
            type="text"
            placeholder="e.g. LOGIN_FAILED"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border, #d1d5db)', width: '180px' }}
          />
        </div>
        <div>
          <label style={{ marginRight: '8px', fontWeight: 600, fontSize: '13px' }}>Limit:</label>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border, #d1d5db)' }}
          >
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={200}>200</option>
          </select>
        </div>
        <button
          onClick={fetchEvents}
          disabled={loading}
          style={{
            padding: '6px 16px', borderRadius: '6px', border: '1px solid var(--accent-border, #3b82f6)',
            background: 'var(--accent-bg, #eff6ff)', color: 'var(--accent, #3b82f6)',
            fontWeight: 600, fontSize: '13px', cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.65 : 1
          }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          padding: '12px 18px', borderRadius: '8px', marginBottom: '16px',
          background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', color: '#ef4444',
          fontSize: '14px'
        }}>
          ⚠️ {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text, #6b7280)' }}>
          Loading audit events…
        </div>
      )}

      {/* Table */}
      {!loading && !error && (
        <>
          <div style={{ fontSize: '13px', color: 'var(--text, #6b7280)', marginBottom: '10px' }}>
            Showing {events.length} event{events.length !== 1 ? 's' : ''}
          </div>
          <div style={{ overflowX: 'auto', borderRadius: '10px', border: '1px solid var(--border, #e5e7eb)' }}>
            <table style={{
              width: '100%', borderCollapse: 'collapse', fontSize: '13px',
              background: 'var(--bg-card, #fff)'
            }}>
              <thead>
                <tr style={{ background: 'var(--bg-app, #f3f4f6)', borderBottom: '2px solid var(--border, #e5e7eb)' }}>
                  <th style={thStyle}>Timestamp</th>
                  <th style={thStyle}>Action</th>
                  <th style={thStyle}>User / Email</th>
                  <th style={thStyle}>Source / Detail</th>
                  <th style={thStyle}>Severity</th>
                  <th style={thStyle}>IP</th>
                  <th style={thStyle}>Role</th>
                  <th style={thStyle}>Status</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: '#999' }}>
                      No audit events found.
                    </td>
                  </tr>
                ) : (
                  events.map((event, idx) => {
                    const severity = event.severity || event.metadata?.severity || 'LOW';
                    const correlationId =
                      event?.correlation_id ||
                      event?.correlationId ||
                      event?.metadata?.correlation_id ||
                      event?.metadata?.correlationId;
                    
                    const eventEmail = event.metadata?.email || event.user?.email || '—';
                    const eventSource = event.metadata?.source || event.metadata?.roleSource || '—';
                    return (
                      <tr
                        key={event.event_id || event.id || idx}
                        onClick={() => handleRowClick(event)}
                        title={correlationId ? 'Open related attack graph' : 'No correlation ID available for this event'}
                        style={{
                          borderBottom: '1px solid var(--border, #e5e7eb)',
                          transition: 'background 0.15s',
                          cursor: correlationId ? 'pointer' : 'default',
                          background: correlationId ? 'rgba(59, 130, 246, 0.02)' : 'transparent',
                        }}
                      >
                        <td style={tdStyle}>
                          {event.timestamp
                            ? new Date(event.timestamp).toLocaleString()
                            : '—'}
                        </td>
                        <td style={{ ...tdStyle, fontWeight: 600 }}>
                          {event.action}
                        </td>
                        <td style={tdStyle}>
                          <span style={{ fontSize: '12px', color: '#6b7280' }}>{eventEmail}</span>
                        </td>
                        <td style={tdStyle}>
                          {eventSource !== '—' && (
                            <span style={{ padding: '2px 6px', background: '#e2e8f0', borderRadius: '4px', fontSize: '11px', color: '#475569', fontWeight: 500 }}>
                              {eventSource}
                            </span>
                          )}
                        </td>
                        <td style={tdStyle}>
                          <span style={{
                            padding: '2px 8px', borderRadius: '6px', fontSize: '11px',
                            fontWeight: 700, color: '#fff',
                            background: SEVERITY_COLORS[severity] || '#6b7280'
                          }}>
                            {severity}
                          </span>
                        </td>
                        <td style={{ ...tdStyle, fontFamily: 'monospace', fontSize: '12px' }}>
                          {event.source_ip || '—'}
                        </td>
                        <td style={tdStyle}>
                          <span style={{
                            padding: '2px 8px', borderRadius: '12px', fontSize: '11px',
                            fontWeight: 600, background: 'var(--bg-app, #f3f4f6)',
                            border: '1px solid var(--border, #e5e7eb)',
                          }}>
                            {event.role || '—'}
                          </span>
                        </td>
                        <td style={tdStyle}>
                          <span style={{
                            color: event.status === 'SUCCESS' ? '#10b981' : '#ef4444',
                            fontWeight: 600, fontSize: '12px'
                          }}>
                            {event.status || '—'}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
};

const thStyle = {
  padding: '12px 14px',
  textAlign: 'left',
  fontWeight: 700,
  fontSize: '12px',
  textTransform: 'uppercase',
  letterSpacing: '0.5px',
  color: 'var(--text, #374151)',
};

const tdStyle = {
  padding: '10px 14px',
  color: 'var(--text, #4b5563)',
};

export default AuditPage;
