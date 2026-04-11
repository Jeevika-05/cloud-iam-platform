import client from './client';

export const getProfile = async () => {
  const response = await client.get('/auth/profile');
  return response.data;
};

export const updateProfile = async (data) => {
  const response = await client.patch('/auth/profile', data);
  return response.data;
};

export const setupMfa = async () => {
  const response = await client.post('/mfa/setup');
  return response.data;
};

export const verifyMfa = async (data) => {
  const response = await client.post('/mfa/verify', data);
  return response.data;
};

export const disableMfa = async () => {
  const response = await client.delete('/mfa');
  return response.data;
};
