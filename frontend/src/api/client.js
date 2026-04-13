import axios from 'axios';

let accessToken = null;

let isRefreshing = false;
let failedQueue = [];

export const setAccessToken = (token) => {
  accessToken = token;
};

export const getAccessToken = () => accessToken;

const processQueue = (error, token = null) => {
  failedQueue.forEach(({ resolve, reject }) => {
    error ? reject(error) : resolve(token);
  });
  failedQueue = [];
};

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

// Response Interceptor: Fast unwrapping & handle 401 TOKEN_EXPIRED
client.interceptors.response.use(
  (response) => {
    // Auto-unwrap the { success, data, message } envelope
    if (response.data && response.data.success !== undefined) {
      // NOTE: We replace response.data with response.data.data
      response.data = response.data.data;
    }
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
      
      if (isRefreshing) {
        // Queue the request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(token => {
          originalRequest.headers['Authorization'] = `Bearer ${token}`;
          return client(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const res = await client.post('/auth/refresh');
        // Unwrapped in success handler, so res.data is the actual API payload
        const newToken = res.data.accessToken; 
        
        setAccessToken(newToken);
        processQueue(null, newToken);

        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;

        return client(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
        
        // If refresh fails, normalize the refresh error
        const refreshData = refreshError.response?.data || {};
        return Promise.reject({
          message: refreshData.message || 'Session expired',
          code: refreshData.code || 'SESSION_EXPIRED',
          status: refreshError.response?.status || 401
        });
      } finally {
        isRefreshing = false;
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
