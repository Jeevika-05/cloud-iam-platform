const successResponse = (res, data = {}, message = 'Success', statusCode = 200, code = 'SUCCESS') => {
  return res.status(statusCode).json({
    success: true,
    code,
    message,
    data,
    timestamp: new Date().toISOString(),
  });
};

const errorResponse = (
  res,
  message = 'An error occurred',
  statusCode = 500,
  code = 'ERROR',
  errors = null
) => {
  if (typeof statusCode !== 'number') {
    throw new Error('Invalid statusCode passed to errorResponse');
  }

  const response = {
    success: false,
    code,
    message,
    timestamp: new Date().toISOString(),
  };

  if (errors) response.errors = errors;

  return res.status(statusCode).json(response);
};

export { successResponse, errorResponse };