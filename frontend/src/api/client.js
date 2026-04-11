import axios from 'axios';

let accessToken = null;

export const setAccessToken = (token) => {
  accessToken = token;
};

export const getAccessToken = () => accessToken;

const client = axios.create({
  baseURL: '/api/v1',
  withCredentials: true,
});

// Request Interceptor: Attach access token if available
client.interceptors.request.use(
  (config) => {
    const token = getAccessToken();
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response Interceptor: Handle 401 TOKEN_EXPIRED
client.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Check if the error is due to an expired token
    if (error.response?.status === 401 && error.response?.data?.code === 'TOKEN_EXPIRED' && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const res = await client.post('/auth/refresh');
        setAccessToken(res.data.data.accessToken);

        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers['Authorization'] = `Bearer ${res.data.data.accessToken}`;

        return client(originalRequest);
      } catch (refreshError) {
        // If refresh fails, we would typically log out or clear session here.
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default client;
