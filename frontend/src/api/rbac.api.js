import client from './client';

export const getMyPermissions = async () => {
  const response = await client.get('/rbac/me');
  return response.data;
};
