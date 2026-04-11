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

    // Route permissions (403 Forbidden)
    if (error.response?.status === 403 || error.response?.data?.code === 'PERMISSION_DENIED') {
      window.dispatchEvent(new CustomEvent('auth:forbidden'));
      return Promise.reject({
        message: 'Access denied',
        code: 'PERMISSION_DENIED',
        status: 403
      });
    } else if (error.response?.status === 401 && error.response?.data?.code === 'TOKEN_EXPIRED' && !originalRequest._retry) {
      // Check if the error is due to an expired token
      originalRequest._retry = true;

      try {
        const res = await client.post('/auth/refresh');
        setAccessToken(res.data.data.accessToken);

        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers['Authorization'] = `Bearer ${res.data.data.accessToken}`;

        return client(originalRequest);
      } catch (refreshError) {
        // If refresh fails, normalize the refresh error
        const refreshData = refreshError.response?.data || {};
        return Promise.reject({
          message: refreshData.message || 'Session expired',
          code: refreshData.code || 'SESSION_EXPIRED',
          status: refreshError.response?.status || 401
        });
      }
    }

    // Global Error Normalization
    const errorData = error.response?.data || {};
    return Promise.reject({
      message: errorData.message || error.message || 'Something went wrong',
      code: errorData.code || 'UNKNOWN_ERROR',
      status: error.response?.status || 500
    });
  }
);

export default client;
