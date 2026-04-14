import client from './client';

export const login = async (data) => {
  const response = await client.post('/auth/login', data);
  return response.data;
};

export const register = async (data) => {
  const response = await client.post('/auth/register', data);
  return response.data;
};

let refreshPromise = null;
export const refresh = async () => {
  if (refreshPromise) return refreshPromise;
  refreshPromise = client.post('/auth/refresh')
    .then(response => response.data)
    .catch((err) => {
      refreshPromise = null;   // reset immediately on failure so next call retries
      return Promise.reject(err);
    })
    .finally(() => { refreshPromise = null; });
  return refreshPromise;
};

export const validateMfaLogin = async (data) => {
  const response = await client.post('/auth/mfa/validate-login', data);
  return response.data;
};

export const logout = async () => {
  const response = await client.post('/auth/logout');
  return response.data;
};

export const getSessions = async () => {
  const response = await client.get('/auth/sessions');
  return response.data;
};

export const revokeSession = async (id) => {
  const response = await client.delete(`/auth/sessions/${id}`);
  return response.data;
};

export const revokeAllSessions = async () => {
  const response = await client.delete('/auth/sessions');
  return response.data;
};
