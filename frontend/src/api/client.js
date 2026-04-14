import axios from 'axios';

axios.defaults.withCredentials = true;

let accessToken = null;

let isRefreshing = false;
let failedQueue = [];

// Cross-tab Synchronization
const authChannel = typeof window !== 'undefined' ? new BroadcastChannel('auth') : null;

if (authChannel) {
  authChannel.onmessage = (event) => {
    switch (event.data.type) {
      case 'TOKEN_REFRESH_START':
        if (!isRefreshing) {
          isRefreshing = true;
          // Failsafe: if the refreshing tab is forcefully closed or disconnected
          setTimeout(() => {
            if (isRefreshing) {
              processQueue(new Error('Cross-tab refresh timeout'));
              isRefreshing = false;
            }
          }, 10000);
        }
        break;
      case 'TOKEN_UPDATED':
        setAccessToken(event.data.token);
        processQueue(null, event.data.token);
        isRefreshing = false;
        break;
      case 'TOKEN_REFRESH_FAILED':
        processQueue(new Error('Refresh failed in another tab'));
        isRefreshing = false;
        break;
    }
  };
}

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

export const fetchCsrfToken = async () => {
  try {
    const res = await client.get('/auth/csrf');
    const token = res.data?.csrfToken || res.data?.data?.csrfToken;
    if (!token) throw new Error('CSRF token missing from response');
    client.defaults.headers.common['X-CSRF-Token'] = token; 
    return token;
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
  }
};

const envUrl = import.meta.env.VITE_API_BASE_URL || "http://localhost:3000";
// 🔐 FIX: Provide relative path if env URL is a Docker-internal hostname, avoiding CORS/DNS errors and allowing Nginx to proxy
const BASE_URL = typeof window !== 'undefined' && envUrl.includes('backend:3000') 
  ? "" 
  : envUrl;

const client = axios.create({
  baseURL: BASE_URL ? `${BASE_URL}/api/v1` : '/api/v1',
  withCredentials: true,
  headers: {
    'X-Requested-With': 'XMLHttpRequest'
  }
});

axios.defaults.withCredentials = true;

let csrfPromise = null;

// Request Interceptor: Attach access token if available and handle CSRF fetching
client.interceptors.request.use(
  async (config) => {
    // Lazily evaluate CSRF lock natively before arbitrary mutations
    if (config.url !== '/auth/csrf' && !client.defaults.headers.common['X-CSRF-Token']) {
      if (!csrfPromise) {
        csrfPromise = fetchCsrfToken().catch(() => null);
      }
      await csrfPromise;
    }

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
    let rawData = response.data?.data || response.data;

    // Normalize response shape: unwrap `.user` if present (but keep accessToken intact)
    if (rawData && rawData.user && !rawData.accessToken) {
      rawData = rawData.user;
    }

    response.data = rawData;
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Route permissions (403 Forbidden)
    // AFTER
if (error.response?.status === 403 && error.response?.data?.code === 'PERMISSION_DENIED') {
  window.dispatchEvent(new CustomEvent('auth:forbidden'));
  return Promise.reject({ message: 'Access denied', code: 'PERMISSION_DENIED', status: 403 });
}

// CSRF failure on refresh during bootstrap — treat as unauthenticated, not forbidden
if (error.response?.status === 403 && ['CSRF_FAILED', 'AUTH_REQUIRED'].includes(error.response?.data?.code)) {
  return Promise.reject({ message: 'Not authenticated', code: 'UNAUTHENTICATED', status: 401 });
} else if (error.response?.status === 401 && error.response?.data?.code === 'TOKEN_EXPIRED' && !originalRequest._retry) {
      if (originalRequest.url.includes('/auth/refresh')) {
        return Promise.reject({
          message: 'Session expired',
          code: 'SESSION_EXPIRED',
          status: 401
        });
      }
      
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
      if (authChannel) authChannel.postMessage({ type: 'TOKEN_REFRESH_START' });

      try {
        const res = await client.post('/auth/refresh');
        // Unwrapped in success handler, so res.data is the actual API payload
        const newToken = res.data.accessToken; 
        
        setAccessToken(newToken);
        processQueue(null, newToken);
        if (authChannel) authChannel.postMessage({ type: 'TOKEN_UPDATED', token: newToken });

        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;

        return client(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
        if (authChannel) authChannel.postMessage({ type: 'TOKEN_REFRESH_FAILED' });
        
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
