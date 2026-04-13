import React, { useState, useEffect, useCallback } from 'react';
import { getAttackTypes, simulateAttack } from '../api/security.api';

const GROUP_RULES = [
  { keyword: 'BRUTE',       group: 'Authentication' },
  { keyword: 'CREDENTIAL',  group: 'Authentication' },
  { keyword: 'PASSWORD',    group: 'Authentication' },
  { keyword: 'LOGIN',       group: 'Authentication' },
  { keyword: 'TOKEN',       group: 'Token' },
  { keyword: 'SESSION',     group: 'Token' },
  { keyword: 'JWT',         group: 'Token' },
  { keyword: 'API',         group: 'API' },
  { keyword: 'RATE',        group: 'API' },
  { keyword: 'INJECTION',   group: 'API' },
  { keyword: 'PRIVILEGE',   group: 'Authorization' },
  { keyword: 'ESCALATION',  group: 'Authorization' },
  { keyword: 'RBAC',        group: 'Authorization' },
];

const resolveGroup = (attack) => {
  if (attack.group) return attack.group;
  const upper = (attack.type || '').toUpperCase();
  const match = GROUP_RULES.find((r) => upper.includes(r.keyword));
  return match ? match.group : 'Other';
};

export default function SimulationPanel({ onSimulationComplete }) {
  const [attackTypes, setAttackTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeAttack, setActiveAttack] = useState(null);
  const [lastResult, setLastResult] = useState(null); // { type, correlationId, date }

  const loadAttackTypes = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAttackTypes();
      const list = Array.isArray(res) ? res : res.data ?? res.attacks ?? [];
      setAttackTypes(list);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAttackTypes();
  }, [loadAttackTypes]);

  const handleSimulate = async (attack) => {
    if (!window.confirm(`Run ${attack.label}?`)) return;
    setActiveAttack(attack.type);
    try {
      const res = await simulateAttack(attack.type);
      const data = res.data ?? res; // Ensure correct unwrap
      const newResult = {
        type: attack.type,
        label: attack.label,
        correlationId: data.correlationId || null,
        date: new Date()
      };
      setLastResult(newResult);
      if (onSimulationComplete) {
        onSimulationComplete(newResult);
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Simulation failed');
    } finally {
      setActiveAttack(null);
    }
  };

  if (loading) return <div style={{ padding: '20px' }}>Loading simulation types...</div>;

  const grouped = {};
  attackTypes.forEach(a => {
    const g = resolveGroup(a);
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(a);
  });

  return (
    <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '12px', padding: '20px' }}>
      <h2 style={{ margin: '0 0 16px 0', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span>⚔️</span> SIMULATION CONTROL PANEL
      </h2>
      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '20px' }}>
        {Object.entries(grouped).map(([group, attacks]) => (
          <div key={group} style={{ flex: '1 1 200px', border: '1px solid var(--border)', borderRadius: '8px' }}>
            <div style={{ padding: '8px 12px', background: 'var(--bg-app)', borderBottom: '1px solid var(--border)', fontWeight: 600, fontSize: '14px', borderTopLeftRadius: '8px', borderTopRightRadius: '8px' }}>
              {group}
            </div>
            <div style={{ padding: '8px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {attacks.map(att => (
                <button
                  key={att.type}
                  onClick={() => handleSimulate(att)}
                  disabled={!!activeAttack}
                  style={{
                    padding: '8px',
                    textAlign: 'left',
                    background: activeAttack === att.type ? '#3b82f6' : 'var(--bg-card)',
                    color: activeAttack === att.type ? '#fff' : 'var(--text)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    cursor: activeAttack ? 'not-allowed' : 'pointer',
                    fontSize: '13px'
                  }}
                >
                  <span style={{ marginRight: '6px' }}>🔴</span>
                  {att.label}
                  {activeAttack === att.type && <span style={{ marginLeft: '8px' }}>...</span>}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
      {lastResult && (
        <div style={{ padding: '12px', background: 'var(--bg-app)', borderRadius: '8px', border: '1px solid var(--border)', fontSize: '13px' }}>
          <div><strong>Last Simulation:</strong> {lastResult.label} at {lastResult.date.toLocaleTimeString()}</div>
          {lastResult.correlationId && (
            <div style={{ marginTop: '4px' }}>
              <strong>Correlation:</strong> <code>{lastResult.correlationId}</code>
              <span style={{ color: '#3b82f6', marginLeft: '12px' }}>[Viewed in Graph]</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
