import { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';

/**
 * useAuth — returns the full AuthContext value.
 *
 * Throws a clear error if used outside <AuthProvider>.
 */
const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an <AuthProvider>');
  }
  return context;
};

export default useAuth;
