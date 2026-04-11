import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const SystemStatus = () => {
  const [status, setStatus] = useState({
    API: 'PENDING',
    Database: 'PENDING',
    Neo4j: 'PENDING',
    Redis: 'PENDING'
  });

  const isMounted = useRef(true);

  useEffect(() => {
    isMounted.current = true;

    const fetchHealth = async () => {
      try {
        const res = await axios.get('/health', { timeout: 5000 });
        if (isMounted.current) {
          const isUp = res.data?.status === 'ok' || res.status === 200 || res.data?.data?.status === 'ok';
          setStatus({
            API: isUp ? 'UP' : 'DOWN',
            Database: res.data?.data?.database || (isUp ? 'UP' : 'DOWN'),
            Neo4j: res.data?.data?.neo4j || (isUp ? 'UP' : 'DOWN'),
            Redis: res.data?.data?.redis || (isUp ? 'UP' : 'DOWN')
          });
        }
      } catch (err) {
        if (isMounted.current) {
          setStatus({
            API: 'DOWN',
            Database: 'DOWN',
            Neo4j: 'DOWN',
            Redis: 'DOWN'
          });
        }
      }
    };

    fetchHealth();
    // Refresh every 30 seconds
    const interval = setInterval(fetchHealth, 30000);
    return () => {
      isMounted.current = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <div style={{
      display: 'flex',
      gap: '24px',
      background: 'var(--bg-card)',
      padding: '12px 24px',
      borderRadius: '8px',
      border: '1px solid var(--border)',
      alignItems: 'center'
    }}>
      <span style={{ fontWeight: 600, color: 'var(--text)', fontSize: '14px' }}>
        <span style={{ marginRight: '6px' }}>⚡</span> System Status:
      </span>
      <div style={{ display: 'flex', gap: '16px' }}>
        {Object.entries(status).map(([service, state]) => (
          <div key={service} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', color: 'var(--text-muted)' }}>
            <span>{service}</span>
            <span style={{
              padding: '2px 6px',
              borderRadius: '6px',
              fontSize: '11px',
              fontWeight: 700,
              background: state === 'UP' ? 'rgba(16, 185, 129, 0.15)' : state === 'PENDING' ? 'var(--bg-app)' : 'rgba(239, 68, 68, 0.15)',
              color: state === 'UP' ? '#10b981' : state === 'PENDING' ? 'var(--text-muted)' : '#ef4444'
            }}>
              {state}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SystemStatus;
