import React from 'react';

const STATUS_STYLES = {
  done: {
    color: '#0f766e',
    borderColor: 'rgba(15, 118, 110, 0.25)',
    background: 'rgba(16, 185, 129, 0.10)',
    dot: '#10b981',
    icon: '✓',
  },
  active: {
    color: '#1d4ed8',
    borderColor: 'rgba(37, 99, 235, 0.25)',
    background: 'rgba(59, 130, 246, 0.10)',
    dot: '#3b82f6',
    icon: '•',
  },
  safe: {
    color: '#6b7280',
    borderColor: 'rgba(107, 114, 128, 0.25)',
    background: 'rgba(107, 114, 128, 0.08)',
    dot: '#9ca3af',
    icon: '–',
  },
};

const getRiskStepStatus = (riskScore) => {
  if (riskScore == null) return 'active';
  return riskScore > 0 ? 'done' : 'safe';
};

const getDefenseLabel = (defenseTriggered, defenseText) => {
  if (defenseTriggered) {
    return defenseText ? `Defense Triggered: ${defenseText}` : 'Defense Triggered';
  }
  return 'No defense required';
};

const buildTimelineSteps = (result) => {
  const correlationId = result?.correlationId || result?.correlation_id || null;
  const riskScore = result?.riskScore ?? result?.risk_score ?? result?.result?.riskScore ?? result?.result?.risk_score ?? null;
  const defenseText =
    result?.defense ||
    result?.defenseAction ||
    result?.defense_action ||
    result?.result?.defense ||
    result?.result?.defenseAction ||
    result?.result?.defense_action ||
    '';
  const defenseTriggered = Boolean(
    result?.defenseTriggered ??
    result?.defense_triggered ??
    result?.result?.defenseTriggered ??
    result?.result?.defense_triggered ??
    defenseText
  );

  return [
    { label: 'Attack Triggered', status: 'done' },
    { label: correlationId ? `Event Logged (${correlationId})` : 'Event Logged', status: correlationId ? 'done' : 'active' },
    {
      label: riskScore == null ? 'Risk Computation Pending' : `Risk Computed${typeof riskScore === 'number' ? ` (${riskScore})` : ''}`,
      status: getRiskStepStatus(riskScore),
    },
    {
      label: getDefenseLabel(defenseTriggered, defenseText),
      status: defenseTriggered ? 'done' : 'safe',
    },
  ];
};

const AttackTimeline = ({ result }) => {
  const steps = buildTimelineSteps(result);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {steps.map((step, index) => {
        const style = STATUS_STYLES[step.status] || STATUS_STYLES.active;
        const isLast = index === steps.length - 1;

        return (
          <div key={`${step.label}-${index}`} style={{ display: 'flex', gap: '12px', alignItems: 'stretch' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '16px' }}>
              <div
                aria-hidden="true"
                style={{
                  width: '16px',
                  height: '16px',
                  borderRadius: '999px',
                  background: style.dot,
                  color: '#fff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '10px',
                  fontWeight: 700,
                  boxShadow: `0 0 0 3px ${style.background}`,
                }}
              >
                {style.icon}
              </div>
              {!isLast && (
                <div
                  aria-hidden="true"
                  style={{
                    width: '2px',
                    flex: 1,
                    minHeight: '28px',
                    marginTop: '6px',
                    background: 'rgba(148, 163, 184, 0.45)',
                  }}
                />
              )}
            </div>

            <div
              style={{
                flex: 1,
                padding: '10px 12px',
                borderRadius: '10px',
                border: `1px solid ${style.borderColor}`,
                background: style.background,
                color: style.color,
                fontSize: '13px',
                fontWeight: 600,
              }}
            >
              {step.label}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default AttackTimeline;
