import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;

// PATCH 6: Strict Key Resolver (No fallbacks)
function getKey(version) {
  if (!version) throw new Error("Key version is required");
  const key = process.env[`ENCRYPTION_KEY_V${version}`];
  if (!key) throw new Error(`ENCRYPTION_KEY_V${version} is missing`);
  return key;
}

const getEncryptionKey = (version) => {
  const key = getKey(version);
  
  if (key.length !== 64 || !/^[0-9a-fA-F]+$/.test(key)) {
    throw new Error(`Invalid ENCRYPTION_KEY_V${version}`);
  }
  return Buffer.from(key, 'hex');
};

export const encrypt = (text, version) => {
  if (!version) throw new Error("Encryption requires a valid version");
  if (!text) return text;
  
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getEncryptionKey(version), iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Format: iv:authTag:encryptedContent
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

export const decrypt = (encryptedText, version) => {
  if (!version) throw new Error("Decryption requires a valid version");
  if (!encryptedText) return encryptedText;
  
  const parts = encryptedText.split(':');
  
  // PATCH 2: Secure Encryption Handling (Remove Unsafe Fallback)
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted secret");
  }
  
  const [ivHex, authTagHex, contentHex] = parts;
  
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  
  const decipher = crypto.createDecipheriv(ALGORITHM, getEncryptionKey(version), iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(contentHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};
