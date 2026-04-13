import { useContext } from 'react';
import { RbacContext } from '../context/rbac-context';

/**
 * usePermission — returns the hasPermission(permission) function.
 *
 * Throws a clear error if used outside <RbacProvider>.
 */
const usePermission = () => {
  const context = useContext(RbacContext);
  if (!context) {
    throw new Error('usePermission must be used within an <RbacProvider>');
  }
  return context.hasPermission;
};

export default usePermission;
