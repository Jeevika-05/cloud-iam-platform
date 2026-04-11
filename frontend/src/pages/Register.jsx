import React from 'react';
import { Link } from 'react-router-dom';

const Register = () => {
  return (
    <div className="register-container">
      <h2>Register</h2>
      <p>Placeholder for registration form.</p>
      <div>
        <Link to="/login">Already have an account? Login here.</Link>
      </div>
    </div>
  );
};

export default Register;
