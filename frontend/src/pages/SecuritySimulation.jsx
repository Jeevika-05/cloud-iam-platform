import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAttackTypes, simulateAttack } from '../api/security.api';
import { buildSimulationExplanation } from '../utils/attackExplanations';
import AttackTimeline from '../components/AttackTimeline';
import './SecuritySimulation.css';

/**
 * Attack-type category groupings.
 * Maps a keyword found in the attack `type` to a human-readable group label.
 * If no keyword matches, the attack falls into the "Other" group.
 */
const GROUP_RULES = [
  { keyword: 'BRUTE',       group: 'Authentication Attacks' },
  { keyword: 'CREDENTIAL',  group: 'Authentication Attacks' },
  { keyword: 'PASSWORD',    group: 'Authentication Attacks' },
  { keyword: 'LOGIN',       group: 'Authentication Attacks' },
  { keyword: 'MFA',         group: 'Authentication Attacks' },
  { keyword: 'TOKEN',       group: 'Token Attacks' },
  { keyword: 'SESSION',     group: 'Token Attacks' },
  { keyword: 'JWT',         group: 'Token Attacks' },
  { keyword: 'API',         group: 'API Attacks' },
  { keyword: 'RATE',        group: 'API Attacks' },
  { keyword: 'INJECTION',   group: 'API Attacks' },
  { keyword: 'PRIVILEGE',   group: 'Authorization Attacks' },
  { keyword: 'ESCALATION',  group: 'Authorization Attacks' },
  { keyword: 'RBAC',        group: 'Authorization Attacks' },
];

/** Preferred rendering order for groups. Unlisted groups sort alphabetically after these. */
const GROUP_ORDER = [
  'Authentication Attacks',
  'Token Attacks',
  'API Attacks',
  'Authorization Attacks',
];

/**
 * Derive a group label for an attack, first checking `attack.group` (backend-provided),
 * then falling back to keyword matching against `attack.type`.
 */
const resolveGroup = (attack) => {
  if (attack.group) return attack.group;
  const upper = (attack.type || '').toUpperCase();
  const match = GROUP_RULES.find((r) => upper.includes(r.keyword));
  return match ? match.group : 'Other';
};

/**
 * Group a flat list of attacks into an array of { group, attacks } objects,
 * sorted by GROUP_ORDER (and then alphabetically for unlisted groups).
 */
const groupAttacks = (attacks) => {
  const map = {};
  attacks.forEach((attack) => {
    const group = resolveGroup(attack);
    if (!map[group]) map[group] = [];
    map[group].push(attack);
  });

  return Object.entries(map)
    .sort(([a], [b]) => {
      const ia = GROUP_ORDER.indexOf(a);
      const ib = GROUP_ORDER.indexOf(b);
      if (ia !== -1 && ib !== -1) return ia - ib;
      if (ia !== -1) return -1;
      if (ib !== -1) return 1;
      return a.localeCompare(b);
    })
    .map(([group, items]) => ({ group, attacks: items }));
};

/** Maps group names to a subtle icon/emoji for visual differentiation. */
const GROUP_ICONS = {
  'Authentication Attacks': '🔐',
  'Token Attacks': '🎟️',
  'API Attacks': '🌐',
  'Authorization Attacks': '🛡️',
  Other: '⚙️',
};

/** Severity badge colors */
const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ef4444',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const SecuritySimulation = () => {
  const navigate = useNavigate();

  // ─── State ────────────────────────────────────────────────────────────────
  const [attackTypes, setAttackTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  const [activeAttack, setActiveAttack] = useState(null);    // type currently running
  const [result, setResult] = useState(null);           // { type, status, message, correlationId }
  const [simError, setSimError] = useState(null);       // simulation error string

  // ─── Fetch attack types on mount ──────────────────────────────────────────
  const loadAttackTypes = useCallback(async () => {
    setLoading(true);
    setFetchError(null);
    try {
      const res = await getAttackTypes();
      // Backend may wrap payload under `data`, `attacks`, or return a flat array
      const list = Array.isArray(res) ? res : res.data ?? res.attacks ?? [];
      setAttackTypes(list);
    } catch (err) {
      setFetchError(
        err.message || 'Failed to load attack types'
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAttackTypes();
  }, [loadAttackTypes]);

  // ─── Simulate ─────────────────────────────────────────────────────────────
  const handleSimulate = async (attack) => {
    if (!window.confirm(`Run ${attack.label}? This will trigger a security simulation.`)) {
      return;
    }

    setActiveAttack(attack.type);
    setResult(null);
    setSimError(null);

    try {
      const res = await simulateAttack(attack.type);
      const correlationId = res.correlationId || res.correlation_id || null;
      setResult({
        type: attack.type,
        label: attack.label || res.label,
        status: 'success',
        message: res.message ?? 'Simulation completed successfully',
        correlationId,
        steps: res.steps || null,
        attackerIp: res.attackerIp || null,
        action: res.action || res.eventAction || res.event_action || attack.type,
        riskScore: res.riskScore ?? res.risk_score ?? null,
        defense: res.defense || res.defenseAction || res.defense_action || '',
        defenseTriggered: res.defenseTriggered ?? res.defense_triggered ?? Boolean(res.defense || res.defenseAction || res.defense_action),
      });
      if (correlationId) {
        localStorage.setItem('lastCorrelationId', correlationId);
      }
    } catch (err) {
      setSimError(
        err.message || 'Simulation failed. Please try again.'
      );
    } finally {
      setActiveAttack(null);
    }
  };

  // ─── Navigation ───────────────────────────────────────────────────────────
  const handleViewInGraph = () => {
    if (result?.correlationId) {
      navigate(`/graph?correlation_id=${result.correlationId}`);
    }
  };

  // ─── Dismiss helpers ─────────────────────────────────────────────────────
  const dismissResult = () => setResult(null);
  const dismissError = () => setSimError(null);

  // ─── Grouped data ─────────────────────────────────────────────────────────
  const grouped = groupAttacks(attackTypes);

  // ─── Explanation data ─────────────────────────────────────────────────────
  const explanation = result ? buildSimulationExplanation(result) : null;

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="sim-page">
      {/* Header */}
      <header className="sim-header">
        <h1 id="sim-title">Attack Simulation</h1>
        <p className="sim-subtitle">
          Trigger controlled security simulations to validate your platform's defenses.
          Each simulation generates real events that flow through the detection → defense → graph pipeline.
        </p>
      </header>

      {/* Success Result + Explanation Panel */}
      {result && (
        <div style={{
          borderRadius: '12px',
          border: '1px solid rgba(34, 197, 94, 0.3)',
          overflow: 'hidden',
          marginBottom: '24px',
          animation: 'sim-slide-in 0.35s ease-out',
        }}>
          {/* Success toast header */}
          <div className="sim-toast sim-toast--success" style={{ margin: 0, borderRadius: 0 }}>
            <span className="sim-toast__icon">✓</span>
            <span className="sim-toast__text">
              <strong>{attackTypes.find((a) => a.type === result.type)?.label ?? result.type}</strong>
              {' — '} {result.message}
              {result.correlationId && (
                <span style={{ display: 'block', fontSize: '12px', marginTop: '4px', opacity: 0.85 }}>
                  Correlation ID: <code style={{ background: 'rgba(0,0,0,0.1)', padding: '2px 6px', borderRadius: '4px' }}>{result.correlationId}</code>
                  {result.steps && <span style={{ marginLeft: '12px' }}>Steps: {result.steps}</span>}
                </span>
              )}
            </span>
            <button className="sim-toast__dismiss" onClick={dismissResult} aria-label="Dismiss">
              ×
            </button>
          </div>

          {/* Action buttons */}
          <div style={{
            display: 'flex',
            gap: '10px',
            padding: '12px 18px',
            background: 'rgba(34, 197, 94, 0.04)',
            borderBottom: explanation ? '1px solid rgba(34, 197, 94, 0.15)' : 'none',
          }}>
            {result.correlationId && (
              <button
                onClick={handleViewInGraph}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: '1px solid #3b82f6',
                  background: '#3b82f6',
                  color: '#fff',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
              >
                🕸️ View in Graph
              </button>
            )}
            <button
              onClick={() => navigate('/audit')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 16px',
                borderRadius: '8px',
                border: '1px solid var(--border, #d1d5db)',
                background: 'transparent',
                color: 'var(--text, #374151)',
                fontSize: '13px',
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              📋 View Audit Logs
            </button>
          </div>

          {/* Explanation panel */}
          {explanation && (
            <div style={{
              padding: '18px',
              background: 'rgba(34, 197, 94, 0.02)',
              fontSize: '14px',
              lineHeight: '1.6',
            }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                marginBottom: '12px',
              }}>
                <span style={{ fontSize: '18px' }}>🧠</span>
                <strong style={{ fontSize: '15px' }}>Attack Explanation</strong>
                {explanation.severity && (
                  <span style={{
                    padding: '2px 10px',
                    borderRadius: '12px',
                    fontSize: '11px',
                    fontWeight: 700,
                    color: '#fff',
                    background: SEVERITY_COLORS[explanation.severity] || '#6b7280',
                    marginLeft: '8px',
                  }}>
                    {explanation.severity}
                  </span>
                )}
              </div>

              <div style={{
                display: 'grid',
                gridTemplateColumns: '1fr',
                gap: '12px',
              }}>
                <div style={{
                  padding: '12px 16px',
                  background: 'var(--bg, #f9fafb)',
                  borderRadius: '8px',
                  border: '1px solid var(--border, #e5e7eb)',
                }}>
                  <div style={{ fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text, #6b7280)', marginBottom: '6px' }}>
                    What Happened
                  </div>
                  <div style={{ color: 'var(--text-h, #111827)' }}>{explanation.explanation}</div>
                </div>

                <div style={{
                  padding: '12px 16px',
                  background: 'rgba(16, 185, 129, 0.06)',
                  borderRadius: '8px',
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                }}>
                  <div style={{ fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px', color: '#059669', marginBottom: '6px' }}>
                    🛡️ Defense Response
                  </div>
                  <div style={{ color: 'var(--text-h, #111827)' }}>{explanation.defense}</div>
                </div>

                <div style={{
                  padding: '12px 16px',
                  background: 'var(--bg, #f9fafb)',
                  borderRadius: '8px',
                  border: '1px solid var(--border, #e5e7eb)',
                }}>
                  <div style={{ fontWeight: 600, fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.5px', color: 'var(--text, #6b7280)', marginBottom: '10px' }}>
                    Attack Timeline
                  </div>
                  <AttackTimeline result={result} />
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {simError && (
        <div className="sim-toast sim-toast--error" role="alert" id="sim-error-toast">
          <span className="sim-toast__icon">✗</span>
          <span className="sim-toast__text">{simError}</span>
          <button className="sim-toast__dismiss" onClick={dismissError} aria-label="Dismiss">
            ×
          </button>
        </div>
      )}

      {/* Body */}
      <div className="sim-body">
        {loading && (
          <div className="sim-loading" id="sim-loading">
            <div className="sim-spinner" />
            <p>Loading attack types…</p>
          </div>
        )}

        {fetchError && (
          <div className="sim-error-box" id="sim-fetch-error">
            <p>{fetchError}</p>
            <button className="sim-btn sim-btn--outline" onClick={loadAttackTypes}>
              Retry
            </button>
          </div>
        )}

        {!loading && !fetchError && attackTypes.length === 0 && (
          <p className="sim-empty" id="sim-empty">
            No attack types available from the backend.
          </p>
        )}

        {!loading &&
          !fetchError &&
          grouped.map(({ group, attacks }) => (
            <section className="sim-group" key={group} aria-label={group}>
              <h2 className="sim-group__title">
                <span className="sim-group__icon">{GROUP_ICONS[group] ?? '⚙️'}</span>
                {group}
                <span style={{ fontSize: '12px', fontWeight: 400, color: 'var(--text)', marginLeft: '8px' }}>
                  ({attacks.length})
                </span>
              </h2>

              <div className="sim-group__grid">
                {attacks.map((attack) => {
                  const isRunning = activeAttack === attack.type;
                  return (
                    <button
                      key={attack.type}
                      id={`sim-btn-${attack.type}`}
                      className={`sim-attack-btn ${isRunning ? 'sim-attack-btn--running' : ''}`}
                      disabled={activeAttack !== null}
                      onClick={() => handleSimulate(attack)}
                      aria-busy={isRunning}
                    >
                      {isRunning ? (
                        <span className="sim-attack-btn__spinner" />
                      ) : (
                        <span className="sim-attack-btn__icon">▶</span>
                      )}
                      <span className="sim-attack-btn__label">{attack.label}</span>
                    </button>
                  );
                })}
              </div>
            </section>
          ))}
      </div>
    </div>
  );
};

export default SecuritySimulation;
