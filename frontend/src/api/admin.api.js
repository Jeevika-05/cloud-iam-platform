import client from './client';

export const getPendingUsers = async () => {
  const { data } = await client.get('/admin/pending-users');
  return data;
};

export const getPendingCount = async () => {
  const { data } = await client.get('/admin/pending-count');
  return data;
};

export const approveUser = async (email) => {
  const { data } = await client.post('/admin/approve-user', { email });
  return data;
};

export const rejectUser = async (email) => {
  const { data } = await client.post('/admin/reject-user', { email });
  return data;
};
