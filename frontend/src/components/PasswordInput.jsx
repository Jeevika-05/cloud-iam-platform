import React, { useState } from 'react';
import { FaEye, FaEyeSlash } from 'react-icons/fa';

/**
 * Reusable password input with:
 *  - visibility toggle (eye icon)
 *  - optional strength meter (shown when showStrength=true)
 */

const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];
const STRENGTH_COLORS = ['', '#ef4444', '#f97316', '#eab308', '#22c55e'];

function getPasswordStrength(password) {
  if (!password) return 0;
  let score = 0;
  if (password.length >= 8) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  return score;
}

const PasswordInput = ({
  id,
  value,
  onChange,
  placeholder = 'Password',
  showStrength = false,
  autoComplete,
  className = '', // ✅ FIX: allow override
}) => {
  const [show, setShow] = useState(false);

  const strength = showStrength ? getPasswordStrength(value) : 0;
  const strengthLabel = STRENGTH_LABELS[strength];
  const strengthColor = STRENGTH_COLORS[strength];

  return (
    <div className="pw-wrapper">
      <div className="pw-input-group">
        <input
          id={id}
          type={show ? 'text' : 'password'}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          // ✅ FIX: use external class if provided
          className={className || 'pw-input'}
          required
        />

        <button
          type="button"
          className="pw-eye-btn"
          onClick={() => setShow(s => !s)}
          aria-label={show ? 'Hide password' : 'Show password'}
          tabIndex={-1}
        >
          {show ? <FaEyeSlash /> : <FaEye />}
        </button>
      </div>

      {showStrength && value.length > 0 && (
        <div className="pw-strength">
          <div className="pw-strength-track">
            {[1, 2, 3, 4].map(i => (
              <div
                key={i}
                className="pw-strength-seg"
                style={{
                  background: i <= strength ? strengthColor : '#e5e7eb'
                }}
              />
            ))}
          </div>
          <span
            className="pw-strength-label"
            style={{ color: strengthColor }}
          >
            {strengthLabel}
          </span>
        </div>
      )}
    </div>
  );
};

export default PasswordInput;