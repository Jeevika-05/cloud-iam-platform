import AppError from '../utils/AppError.js';

export const requireCsrf = (req, res, next) => {
  const csrfCookie = req.cookies.csrf_token;
  const csrfHeader = req.headers['x-csrf-token'];

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return next(new AppError('Invalid or missing CSRF token', 403, 'CSRF_FAILED'));
  }

  next();
};