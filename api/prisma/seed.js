import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import speakeasy from 'speakeasy';
import { encrypt } from '../src/shared/utils/cipher.js';
import config from '../src/shared/config/index.js';

const prisma = new PrismaClient();

// Argon2id parameters from centralized config
const ARGON2_OPTIONS = {
  type:        argon2.argon2id,
  memoryCost:  config.hashing.memoryCost,
  timeCost:    config.hashing.timeCost,
  parallelism: config.hashing.parallelism,
  hashLength:  config.hashing.hashLength,
};

const DEFAULT_PASSWORDS = {
  ADMIN:            config.seed.adminPassword,
  SECURITY_ANALYST: config.seed.analystPassword,
  USER:             config.seed.userPassword,
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
      email:    config.seed.mfaTargetEmail,
      role:     'ADMIN',
      password: config.seed.mfaTargetPassword || DEFAULT_PASSWORDS.ADMIN,
      totp:     true,
    },
  ];

  for (const userData of users) {
    const hashedPassword = await argon2.hash(userData.password, ARGON2_OPTIONS);

    let totpData = {};
    if (userData.totp) {
      const secret = speakeasy.generateSecret().base32;
      const version = config.encryption.activeKeyVersion;
      const encryptedSecret = encrypt(secret, version);

      totpData = {
        totpSecret: encryptedSecret,
        totpEnabled: true,
        totpSecretKeyVersion: version
      };
    }

    const user = await prisma.user.upsert({
      where:  { email: userData.email.toLowerCase().trim() },
      update: {
        password: hashedPassword,
        ...totpData
      },
      create: {
        name:     userData.name,
        email:    userData.email.toLowerCase().trim(),
        password: hashedPassword,
        role:     userData.role,
        ...totpData
      },
    });


    console.log(`✅ Seeded user: ${user.email} [${user.role}] (Argon2id)`);
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
