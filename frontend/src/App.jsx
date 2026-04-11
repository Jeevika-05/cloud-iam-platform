import React from 'react';
import { AuthProvider } from './context/AuthContext';
import { RbacProvider } from './context/RbacContext';
import AppRouter from './routes/AppRouter';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <RbacProvider>
        <AppRouter />
      </RbacProvider>
    </AuthProvider>
  );
}

export default App;
