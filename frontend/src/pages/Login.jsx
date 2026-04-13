import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import useAuth from '../hooks/useAuth';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState(null);
  const { login } = useAuth();

  const location = useLocation();
  const navigate = useNavigate();

  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    try {
      const result = await login(email, password);
      if (result.mfaRequired) {
        navigate('/mfa');
      } else if (result.success) {
        if (result.user?.role === 'ADMIN' && result.user?.totpEnabled === false) {
          navigate('/profile', { replace: true });
        } else {
          navigate(from, { replace: true });
        }
      }
    } catch (error) {
      console.error('Login error', error);
      setErrorMsg(error.message || 'An error occurred during login');
    }
  };

  return (
    <div className="login-container">
      <h2>Login</h2>
      {errorMsg && <div className="error-banner" style={{ color: 'red', marginBottom: '16px' }}>{errorMsg}</div>}
      <form onSubmit={handleSubmit}>
        <div>
          <label>Email: </label>
          <input 
            type="email" 
            value={email} 
            onChange={(e) => setEmail(e.target.value)} 
            required 
          />
        </div>
        <div>
          <label>Password: </label>
          <input 
            type="password" 
            value={password} 
            onChange={(e) => setPassword(e.target.value)} 
            required 
          />
        </div>
        <button type="submit">Login</button>
      </form>
      <div>
        <Link to="/register">Don't have an account? Register here.</Link>
      </div>
    </div>
  );
};

export default Login;
