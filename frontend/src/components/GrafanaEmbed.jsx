import React, { useState, useEffect, useCallback } from 'react';
import client from '../api/client';

/**
 * Reusable Grafana dashboard embed component.
 *
 * @param {Object}  props
 * @param {string}  props.dashboard  - Dashboard identifier passed to the backend.
 * @param {string}  [props.title]    - Accessible iframe title (defaults to dashboard name).
 * @param {string}  [props.height]   - CSS height for the iframe (default "400px").
 * @param {string}  [props.className] - Optional extra CSS class on the wrapper.
 */
const GrafanaEmbed = ({ dashboard, title, height = '400px', className = '' }) => {
  const [url, setUrl] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchEmbedUrl = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await client.get('/dashboard/embed-url', {
        params: { dashboard },
      });
      const embedUrl = res.data?.data?.url ?? res.data?.url;
      if (embedUrl) {
        setUrl(embedUrl);
      } else {
        setError('No embed URL returned');
      }
    } catch (err) {
      console.error(`GrafanaEmbed — failed to load "${dashboard}":`, err);
      setError(err.message || 'Unable to load dashboard');
    } finally {
      setLoading(false);
    }
  }, [dashboard]);

  useEffect(() => {
    fetchEmbedUrl();
  }, [fetchEmbedUrl]);

  /* ── Loading state ──────────────────────────────── */
  if (loading) {
    return (
      <div className={`grafana-placeholder ${className}`} style={{
        backgroundColor: 'var(--code-bg)',
        borderRadius: '10px',
        height: height
      }}>
        <div style={{
          width: '32px',
          height: '32px',
          border: '3px solid rgba(0,0,0,0.05)',
          borderTop: '3px solid var(--accent)',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite'
        }} />
        <style>
          {`
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
          `}
        </style>
        <span style={{ fontWeight: 500 }}>Loading Grafana dashboard…</span>
      </div>
    );
  }

  /* ── Error state ────────────────────────────────── */
  if (error) {
    return (
      <div className={className}>
        <div className="error-banner" role="alert">⚠️ {error}</div>
        <div className="grafana-placeholder">
          <span className="icon">📉</span>
          Grafana dashboard is not available right now.
        </div>
      </div>
    );
  }

  /* ── Loaded ─────────────────────────────────────── */
  return (
    <iframe
      className={`grafana-iframe ${className}`}
      src={url}
      width="100%"
      height={height}
      title={title || `Grafana — ${dashboard}`}
      sandbox="allow-scripts allow-same-origin"
    />
  );
};

export default GrafanaEmbed;
