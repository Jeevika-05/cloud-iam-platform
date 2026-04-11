import React, { useState, useEffect, useCallback } from 'react';
import { getAttackTypes, simulateAttack } from '../api/security.api';
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

const SecuritySimulation = () => {
  // ─── State ────────────────────────────────────────────────────────────────
  const [attackTypes, setAttackTypes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  const [activeAttack, setActiveAttack] = useState(null);    // type currently running
  const [result, setResult] = useState(null);           // { type, status, message }
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
        err.response?.data?.message || err.message || 'Failed to load attack types'
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
      setResult({
        type: attack.type,
        status: 'success',
        message: res.message ?? res.data?.message ?? 'Simulation completed successfully',
      });
    } catch (err) {
      setSimError(
        err.response?.data?.message || err.message || 'Simulation failed'
      );
    } finally {
      setActiveAttack(null);
    }
  };

  // ─── Dismiss helpers ─────────────────────────────────────────────────────
  const dismissResult = () => setResult(null);
  const dismissError = () => setSimError(null);

  // ─── Grouped data ─────────────────────────────────────────────────────────
  const grouped = groupAttacks(attackTypes);

  // ─── Render ───────────────────────────────────────────────────────────────
  return (
    <div className="sim-page">
      {/* Header */}
      <header className="sim-header">
        <h1 id="sim-title">Attack Simulation</h1>
        <p className="sim-subtitle">
          Trigger controlled security simulations to validate your platform's defenses.
        </p>
      </header>

      {/* Toast-style feedback */}
      {result && (
        <div className="sim-toast sim-toast--success" role="status" id="sim-success-toast">
          <span className="sim-toast__icon">✓</span>
          <span className="sim-toast__text">
            <strong>{attackTypes.find((a) => a.type === result.type)?.label ?? result.type}</strong>
            {' — '}
            {result.message}
          </span>
          <button className="sim-toast__dismiss" onClick={dismissResult} aria-label="Dismiss">
            ×
          </button>
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
