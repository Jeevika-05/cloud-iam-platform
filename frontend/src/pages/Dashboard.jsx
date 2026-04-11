import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import useAuth from '../hooks/useAuth';
import usePermission from '../hooks/usePermission';
import useMetrics from '../hooks/useMetrics';
import GraphView from '../components/GraphView';
import GrafanaEmbed from '../components/GrafanaEmbed';
import ActivityFeed from '../components/ActivityFeed';
import SystemStatus from '../components/SystemStatus';
import './Dashboard.css';

/* ─── Constants ──────────────────────────────────────── */
const METRIC_CARDS = [
  { key: 'totalRequests',  label: 'Total Requests',  icon: '📡', variant: 'requests' },
  { key: 'failedLogins',   label: 'Failed Logins',   icon: '🔒', variant: 'failed'   },
  { key: 'activeSessions', label: 'Active Sessions',  icon: '🟢', variant: 'sessions' },
  { key: 'blockedIPs',     label: 'Blocked IPs',      icon: '🛡️', variant: 'blocked'  },
];

const GRAFANA_DASHBOARD_ID = 'iam-system-overview';

/* ─── Helpers ────────────────────────────────────────── */
function formatMetric(n) {
  if (n == null) return '—';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

/**
 * Animated number that counts up from 0 to the target value.
 */
const AnimatedNumber = ({ value }) => {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    if (value == null) {
      setDisplayValue(null);
      return;
    }

    let start = 0;
    const end = value;
    const duration = 800;
    let rafId;

    const step = () => {
      start += end / (duration / 16);
      if (start < end) {
        setDisplayValue(Math.floor(start));
        rafId = requestAnimationFrame(step);
      } else {
        setDisplayValue(end);
      }
    };

    if (end > 0) {
      rafId = requestAnimationFrame(step);
    } else {
      setDisplayValue(end);
    }

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
    };
  }, [value]);

  return <>{formatMetric(displayValue)}</>;
};

/* ─── Component ──────────────────────────────────────── */
const Dashboard = () => {
  const { user, logout } = useAuth();
  const hasPermission = usePermission();
  const navigate = useNavigate();

  // ── Theme state
  const [darkMode, setDarkMode] = useState(false);

  // ── Metrics (via reusable hook)
  const { metrics, loading: metricsLoading, error: metricsError } = useMetrics();

  /* ── Logout handler ──────────────────────────────── */
  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  /* ── Render ──────────────────────────────────────── */
  const role = user?.role?.toUpperCase() || 'USER';
  const roleExact = role === 'SECURITY_ANALYST' ? 'ANALYST' : role;

  return (
    <div className={`dashboard-page ${darkMode ? 'theme-dark' : 'theme-light'}`}>
      {/* ─── Header ─── */}
      <header className="dashboard-header">
        <div>
          <h1>Dashboard</h1>
          <p className="dashboard-header-subtitle">
            Welcome back, <strong>{user?.name || user?.email || 'User'}</strong>
            {user?.role && <> &middot; <code>{user.role}</code></>}
          </p>
        </div>
        <div className="dashboard-header-actions" style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <SystemStatus />
          <button className="btn-toggle-theme" onClick={() => setDarkMode(!darkMode)}>
            {darkMode ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>
      </header>

      {/* ─── Role Based Views ─── */}
      {roleExact === 'ADMIN' && (
        <AdminDashboard 
          metrics={metrics} loading={metricsLoading} error={metricsError} 
          darkMode={darkMode} 
        />
      )}
      {roleExact === 'ANALYST' && (
        <AnalystDashboard 
          metrics={metrics} loading={metricsLoading} error={metricsError} 
          darkMode={darkMode} 
        />
      )}
      {roleExact === 'USER' && (
        <UserDashboard />
      )}
    </div>
  );
};

/* ─── Shared Sections ────────────────────────────────── */
const MetricsSection = ({ metrics, loading, error }) => (
  <section>
    <h2 className="section-title">
      <span className="icon">📊</span> Security Metrics
    </h2>
    {error && <div className="error-banner" role="alert">⚠️ {error}</div>}
    <div className="metrics-grid">
      {METRIC_CARDS.map(({ key, label, icon, variant }) => (
        <div key={key} className={`metric-card ${variant}`} id={`metric-${key}`}>
          {loading ? (
            <div className="metric-skeleton">
              <div className="skeleton-line wide" />
              <div className="skeleton-line narrow" />
            </div>
          ) : (
            <>
              <div className="metric-card-header">
                <span className="metric-dot" />
                <span className="metric-icon">{icon}</span>
              </div>
              <div className="metric-label">{label}</div>
              <div className="metric-value">
                <AnimatedNumber value={metrics?.[key]} />
              </div>
            </>
          )}
        </div>
      ))}
    </div>
  </section>
);

const GraphSection = ({ darkMode }) => (
  <section className="graph-section">
    <h2 className="section-title">
      <span className="icon">🕸️</span> Threat Graph
    </h2>
    <GraphView darkMode={darkMode} />
  </section>
);

const GrafanaSection = () => (
  <section className="grafana-section">
    <h2 className="section-title">
      <span className="icon">📈</span> Grafana — IAM System Overview
    </h2>
    <GrafanaEmbed
      dashboard={GRAFANA_DASHBOARD_ID}
      title="IAM System Overview — Grafana"
      height="420px"
    />
  </section>
);

const ActivitySection = () => (
  <section className="activity-section">
    <ActivityFeed />
  </section>
);

/* ─── Role Dashboard Components ──────────────────────── */
const AdminDashboard = ({ metrics, loading, error, darkMode }) => (
  <>
    <MetricsSection metrics={metrics} loading={loading} error={error} />
    <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', alignItems: 'start' }}>
      <GraphSection darkMode={darkMode} />
      <ActivitySection />
    </div>
    <GrafanaSection />
  </>
);

const AnalystDashboard = ({ metrics, loading, error, darkMode }) => (
  <>
    <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', alignItems: 'start' }}>
      <GraphSection darkMode={darkMode} />
      <ActivitySection />
    </div>
    <MetricsSection metrics={metrics} loading={loading} error={error} />
  </>
);

const UserDashboard = () => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
    <section className="user-dashboard-section" style={{ padding: '24px', border: '1px solid var(--border)', borderRadius: '12px', background: 'var(--bg-card)' }}>
      <h2 className="section-title" style={{ marginBottom: '12px' }}>
        <span className="icon">👤</span> Personal Activity
      </h2>
      <p style={{ color: 'var(--text)', marginBottom: '24px', lineHeight: '1.6' }}>
        Welcome to the IAM Security Platform. You can review your active sessions, account details, and security events below.
      </p>
      <div style={{ display: 'flex', gap: '16px' }}>
        <Link to="/sessions" style={{ padding: '8px 16px', background: '#3b82f6', color: '#fff', borderRadius: '6px', textDecoration: 'none', fontWeight: 500 }}>
          View Active Sessions
        </Link>
        <Link to="/profile" style={{ padding: '8px 16px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text)', borderRadius: '6px', textDecoration: 'none', fontWeight: 500 }}>
          Manage Profile
        </Link>
      </div>
    </section>
    
    <ActivitySection />
  </div>
);

export default Dashboard;
