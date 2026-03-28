
import { OAuth2Client } from 'google-auth-library';
import AppError from '../utils/AppError.js';

const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/v1/auth/google/callback'
);

export const getAuthUrl = () => {
  return client.generateAuthUrl({
    access_type: 'offline',
    scope: ['email', 'profile']
  });
};

export const exchangeCodeForIdToken = async (code) => {
  try {
    const { tokens } = await client.getToken(code);
    return tokens.id_token;
  } catch (error) {
    throw new AppError('Failed to exchange Google OAuth code', 400, 'GOOGLE_AUTH_FAILED');
  }
};

export const verifyGoogleIdToken = async (idToken) => {
  try {
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    
    if (!payload.email_verified) {
      throw new AppError('Google email not verified', 400, 'UNVERIFIED_EMAIL');
    }

    return {
      googleId: payload.sub,
      email: payload.email,
      name: payload.name,
    };
  } catch (error) {
    if (error.isAppError) throw error;
    throw new AppError('Invalid Google token', 401, 'INVALID_GOOGLE_TOKEN');
  }
};
