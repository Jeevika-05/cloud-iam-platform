import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAttackTypes, simulateAttack } from '../api/security.api';
import { buildSimulationExplanation } from '../utils/attackExplanations';
import AttackTimeline from './AttackTimeline';

const GROUP_RULES = [
  { keyword: 'BRUTE',       group: 'Authentication' },
  { keyword: 'CREDENTIAL',  group: 'Authentication' },
  { keyword: 'PASSWORD',    group: 'Authentication' },
  { keyword: 'LOGIN',       group: 'Authentication' },
  { keyword: 'MFA',         group: 'Authentication' },
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

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

export default function SimulationPanel({ onSimulationComplete }) {
  const navigate = useNavigate();
  const [attackTypes, setAttackTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeAttack, setActiveAttack] = useState(null);
  const [lastResult, setLastResult] = useState(null);

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
    setLastResult(null);
    try {
      const res = await simulateAttack(attack.type);
      const correlationId = res.correlationId || res.correlation_id || null;
      const newResult = {
        type: attack.type,
        label: attack.label || res.label,
        correlationId,
        date: new Date(),
        action: res.action || res.eventAction || res.event_action || attack.type,
        riskScore: res.riskScore ?? res.risk_score ?? null,
        defense: res.defense || res.defenseAction || res.defense_action || '',
        defenseTriggered: res.defenseTriggered ?? res.defense_triggered ?? Boolean(res.defense || res.defenseAction || res.defense_action),
        result: res
      };
      if (correlationId) {
        localStorage.setItem('lastCorrelationId', correlationId);
      }
      setLastResult(newResult);
      if (onSimulationComplete) {
        onSimulationComplete(newResult);
      }
    } catch (err) {
      alert(err.message || 'Simulation failed. Please try again.');
    } finally {
      setActiveAttack(null);
    }
  };

  const handleViewInGraph = () => {
    if (lastResult?.correlationId) {
      navigate(`/graph?correlation_id=${lastResult.correlationId}`);
    }
  };

  if (loading) return <div style={{ padding: '20px' }}>Loading simulation types...</div>;

  const grouped = {};
  attackTypes.forEach(a => {
    const g = resolveGroup(a);
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(a);
  });

  const explanation = lastResult ? buildSimulationExplanation(lastResult) : null;

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
                    fontSize: '13px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between'
                  }}
                >
                  <span>
                    <span style={{ marginRight: '6px' }}>🔴</span>
                    {att.label}
                  </span>
                  {activeAttack === att.type && (
                    <div style={{
                      width: '12px', height: '12px', border: '2px solid rgba(255,255,255,0.3)',
                      borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 1s linear infinite'
                    }} />
                  )}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
      
      {lastResult && (
        <div style={{ 
          border: '1px solid rgba(34, 197, 94, 0.3)', 
          borderRadius: '8px', 
          overflow: 'hidden',
          animation: 'sim-slide-in 0.3s ease-out'
        }}>
          <div style={{ 
            padding: '12px', 
            background: 'var(--bg-app)', 
            borderBottom: '1px solid var(--border)', 
            fontSize: '13px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <div>
              <div><strong>✅ Sent:</strong> {lastResult.label} at {lastResult.date.toLocaleTimeString()}</div>
              {lastResult.correlationId && (
                <div style={{ marginTop: '4px' }}>
                  <strong>Correlation:</strong> <code style={{ background: 'rgba(0,0,0,0.05)', padding: '2px 6px', borderRadius: '4px' }}>{lastResult.correlationId}</code>
                </div>
              )}
            </div>
            {lastResult.correlationId && (
              <button 
                onClick={handleViewInGraph}
                style={{
                  padding: '6px 12px',
                  background: '#3b82f6',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontSize: '12px',
                }}
              >
                🕸️ View in Graph
              </button>
            )}
          </div>
          
          {explanation && (
            <div style={{ padding: '12px', background: 'rgba(34, 197, 94, 0.02)', fontSize: '13px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <strong>🧠 Explanation</strong>
                {explanation.severity && (
                  <span style={{
                    padding: '2px 8px', borderRadius: '10px', fontSize: '10px',
                    fontWeight: 700, color: '#fff', background: SEVERITY_COLORS[explanation.severity] || '#999'
                  }}>
                    {explanation.severity}
                  </span>
                )}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#666', fontWeight: 600, marginBottom: '2px' }}>Action</div>
                  <div>{explanation.explanation}</div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#059669', fontWeight: 600, marginBottom: '2px' }}>Defense</div>
                  <div>{explanation.defense}</div>
                </div>
              </div>
              <div style={{ marginTop: '12px' }}>
                <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#666', fontWeight: 600, marginBottom: '8px' }}>Timeline</div>
                <AttackTimeline result={lastResult} />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
