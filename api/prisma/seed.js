import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import { encrypt } from '../src/shared/utils/cipher.js';

const prisma = new PrismaClient();

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;

// 🔐 Do NOT hardcode passwords in production — use env vars
const DEFAULT_PASSWORDS = {
  ADMIN:            process.env.SEED_ADMIN_PASSWORD    || 'Admin@1234!',
  SECURITY_ANALYST: process.env.SEED_ANALYST_PASSWORD  || 'Analyst@1234!',
  USER:             process.env.SEED_USER_PASSWORD      || 'User@1234!',
};

async function main() {
  const users = [
    {
      name:     'Super Admin',
      email:    'admin@example.com',
      role:     'ADMIN',
      password: DEFAULT_PASSWORDS.ADMIN,
    },
    {
      name:     'Security Analyst',
      email:    'analyst@example.com',
      role:     'SECURITY_ANALYST',             
      password: DEFAULT_PASSWORDS.SECURITY_ANALYST,
    },
    {
      name:     'Regular User',
      email:    'user@example.com',
      role:     'USER',
      password: DEFAULT_PASSWORDS.USER,
    },
    {
      name:     'Admin Attack (MFA Test)',
      email:    process.env.MFA_TARGET_EMAIL || 'admin_attack@example.com',
      role:     'ADMIN',
      password: process.env.MFA_TARGET_PASSWORD || DEFAULT_PASSWORDS.ADMIN,
      totp:     true,
    },
  ];

  for (const userData of users) {
    const hashedPassword = await bcrypt.hash(userData.password, BCRYPT_ROUNDS);

    let totpData = {};
    if (userData.totp) {
      const secret = speakeasy.generateSecret().base32;
      const version = Number(process.env.ACTIVE_KEY_VERSION);
      const encryptedSecret = encrypt(secret, version);

      totpData = {
        totpSecret: encryptedSecret,
        totpEnabled: true,
        totpSecretKeyVersion: version
      };
    }

    const user = await prisma.user.upsert({
      where:  { email: userData.email.toLowerCase().trim() },
      update: {},   // do not overwrite existing users
      create: {
        name:     userData.name,
        email:    userData.email.toLowerCase().trim(),
        password: hashedPassword,
        role:     userData.role,
        ...totpData
      },
    });


    console.log(`✅ Seeded user: ${user.email} [${user.role}]`);
  }
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', {
      message: e.message,
      stack:   e.stack,
    });
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
