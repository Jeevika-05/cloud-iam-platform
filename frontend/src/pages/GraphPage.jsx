import React, { useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import GraphView from '../components/GraphView';

/**
 * GraphPage — Standalone graph visualization page.
 *
 * Reads `correlation_id` from the URL query string to auto-filter
 * the graph to a specific attack simulation's event chain.
 *
 * Route: /graph?correlation_id=<uuid>
 * Permission: security:view (ADMIN + SECURITY_ANALYST)
 */
const GraphPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlId = searchParams.get('correlation_id');
  const storedId = localStorage.getItem('lastCorrelationId');
  const correlationId = urlId || storedId || null;

  useEffect(() => {
    if (correlationId) {
      localStorage.setItem('lastCorrelationId', correlationId);
    }
  }, [correlationId]);

  const clearFilter = () => {
    localStorage.removeItem('lastCorrelationId');
    setSearchParams({});
  };

  if (!correlationId) {
    return (
      <div className="empty-state" style={{ padding: '40px', textAlign: 'center', color: '#6b7280', fontSize: '16px' }}>
        No attack selected. Please run a simulation first.
      </div>
    );
  }

  return (
    <div style={{
      maxWidth: '1400px',
      margin: '0 auto',
      padding: '36px 24px',
      minHeight: 'calc(100vh - 80px)',
      display: 'flex',
      flexDirection: 'column',
      gap: '24px',
    }}>
      {/* Header */}
      <header>
        <h1 style={{
          fontSize: '26px',
          fontWeight: 700,
          margin: 0,
          letterSpacing: '-0.5px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          <span>🕸️</span> Attack Graph Visualization
        </h1>
        <p style={{ color: 'var(--text, #6b7280)', fontSize: '14px', marginTop: '6px' }}>
          Explore attack paths, defense responses, and event correlations from the Neo4j graph database.
        </p>
      </header>

      {/* Correlation ID Banner */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        padding: '12px 18px',
        background: 'rgba(59, 130, 246, 0.08)',
        border: '1px solid rgba(59, 130, 246, 0.25)',
        borderRadius: '10px',
        fontSize: '14px',
      }}>
        <span style={{ fontSize: '16px' }}>🔗</span>
        <span>
          Filtered by Correlation ID:{' '}
          <code title="Unique tracking identifier that links all events of this specific attack sequence" style={{
            background: 'rgba(59, 130, 246, 0.12)',
            padding: '2px 8px',
            borderRadius: '4px',
            fontWeight: 600,
            color: '#3b82f6',
            fontSize: '13px',
          }}>
            {correlationId}
          </code>
        </span>
        <button
          onClick={clearFilter}
          style={{
            marginLeft: 'auto',
            padding: '4px 12px',
            borderRadius: '6px',
            border: '1px solid rgba(59, 130, 246, 0.3)',
            background: 'transparent',
            color: '#3b82f6',
            fontSize: '13px',
            fontWeight: 500,
            cursor: 'pointer',
          }}
        >
          Clear Filter
        </button>
      </div>

      {/* Graph Component */}
      <div style={{
        border: '1px solid var(--border, #e5e7eb)',
        borderRadius: '14px',
        padding: '20px',
        background: 'var(--bg, #fff)',
        flex: 1,
        minHeight: '600px',
      }}>
        <GraphView correlationId={correlationId} />
      </div>
    </div>
  );
};

export default GraphPage;
