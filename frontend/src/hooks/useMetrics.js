import { useState, useEffect, useCallback } from 'react';
import client from '../api/client';

/**
 * Reusable hook that fetches the IAM metrics summary.
 *
 * @returns {{ metrics: object|null, loading: boolean, error: string|null, refetch: () => void }}
 */
export default function useMetrics() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchMetrics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await client.get('/metrics/summary');
      const data = res.data?.data ?? res.data;
      setMetrics({
        totalRequests:  data.totalRequests  ?? 0,
        failedLogins:   data.failedLogins   ?? 0,
        activeSessions: data.activeSessions ?? 0,
        blockedIPs:     data.blockedIPs     ?? 0,
      });
    } catch (err) {
      console.error('useMetrics — fetch failed:', err);
      setError(err.message || 'Unable to load metrics');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
  }, [fetchMetrics]);

  return { metrics, loading, error, refetch: fetchMetrics };
}
