import client from './client';

/**
 * Fetch the list of supported attack types from the backend.
 * GET /security/attacks
 *
 * @returns {Promise<Array<{ type: string, label: string, group?: string }>>}
 */
export const getAttackTypes = async () => {
  const response = await client.get('/security/attacks');
  return response.data;
};

/**
 * Trigger a simulated attack of the given type.
 * POST /security/simulate
 *
 * @param {string} type - Attack type identifier (e.g. 'BRUTE_FORCE')
 * @returns {Promise<Object>} Simulation result from the backend
 */
export const simulateAttack = async (type) => {
  const response = await client.post('/security/simulate', { type });
  return response.data;
};
