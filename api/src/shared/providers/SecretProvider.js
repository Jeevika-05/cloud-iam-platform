/**
 * ─────────────────────────────────────────────────────────────
 * SECRET PROVIDER — Pluggable Secrets Management Interface
 * ─────────────────────────────────────────────────────────────
 *
 * Defines the contract for secret providers. All providers must
 * implement getSecret(key) → Promise<string>.
 *
 * Current providers:
 *   - EnvProvider      (active)   — reads from env vars / mounted files
 *   - DockerProvider   (placeholder) — reads from /run/secrets/*
 *   - VaultProvider    (placeholder) — reads from HashiCorp Vault API
 *
 * Usage:
 *   import { getSecretProvider } from './providers/SecretProvider.js';
 *   const provider = getSecretProvider();
 *   const dbUrl = await provider.getSecret('DATABASE_URL');
 *
 * To add a new provider:
 *   1. Create a class implementing the SecretProvider interface
 *   2. Add it to the PROVIDERS registry in this file
 *   3. Set SECRET_PROVIDER env var to the new provider name
 *
 * ─────────────────────────────────────────────────────────────
 */

import fs from 'fs';
import path from 'path';
import logger from '../utils/logger.js';

// ─────────────────────────────────────────────────────────────
// INTERFACE: SecretProvider
// All providers must implement this contract.
// ─────────────────────────────────────────────────────────────

/**
 * @interface SecretProvider
 * @method getSecret(key: string): Promise<string | undefined>
 * @method getName(): string
 * @method isAvailable(): Promise<boolean>
 */

// ─────────────────────────────────────────────────────────────
// PROVIDER 1: EnvProvider (Active)
// Reads secrets from environment variables or mounted files.
// Priority: file path env var → direct env var → undefined
// ─────────────────────────────────────────────────────────────

export class EnvProvider {
  getName() {
    return 'env';
  }

  async isAvailable() {
    return true; // Always available
  }

  /**
   * @param {string} key - Secret key name (e.g., 'DATABASE_URL')
   * @returns {Promise<string | undefined>}
   */
  async getSecret(key) {
    return process.env[key];
  }
}

// ─────────────────────────────────────────────────────────────
// PROVIDER 2: DockerSecretsProvider (Placeholder)
// Reads secrets from Docker Secrets mounted at /run/secrets/
// ─────────────────────────────────────────────────────────────

export class DockerSecretsProvider {
  constructor(basePath = '/run/secrets') {
    this.basePath = basePath;
  }

  getName() {
    return 'docker-secrets';
  }

  async isAvailable() {
    try {
      await fs.promises.access(this.basePath, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * @param {string} key - Secret key name (exact match mounted file)
   * @returns {Promise<string | undefined>}
   */
  async getSecret(key) {
    const secretPath = path.join(this.basePath, key);
    try {
      const value = await fs.promises.readFile(secretPath, 'utf8');
      return value.trim();
    } catch (err) {
      if (err.code === 'ENOENT') {
        throw new Error(`[PROVIDER ERROR] Docker secret file not found at ${secretPath} for key ${key}`);
      }
      logger.error('DOCKER_SECRETS_READ_FAILED', {
        key,
        path: secretPath,
        error: err.message,
      });
      throw err;
    }
  }
}

// ─────────────────────────────────────────────────────────────
// PROVIDER 3: VaultProvider (Placeholder — Future-Ready)
// Designed for HashiCorp Vault integration.
// ─────────────────────────────────────────────────────────────

export class VaultProvider {
  /**
   * @param {object} opts
   * @param {string} opts.address  - Vault address (e.g., 'https://vault.internal:8200')
   * @param {string} opts.token    - Vault authentication token
   * @param {string} opts.mountPath - KV engine mount path (default: 'secret')
   * @param {string} opts.secretPath - Path to the secret in Vault
   */
  constructor(opts = {}) {
    this.address = opts.address || process.env.VAULT_ADDR || 'http://127.0.0.1:8200';
    this.token = opts.token || process.env.VAULT_TOKEN;
    this.mountPath = opts.mountPath || process.env.VAULT_MOUNT_PATH || 'secret';
    this.secretPath = opts.secretPath || process.env.VAULT_SECRET_PATH || 'data/iam-platform';
  }

  getName() {
    return 'vault';
  }

  async isAvailable() {
    // Placeholder: In production, this would perform a health check
    // against the Vault API (GET /v1/sys/health)
    return !!this.token;
  }

  /**
   * @param {string} key - Secret key name within the Vault secret path
   * @returns {Promise<string | undefined>}
   *
   * @example
   * // Vault KV v2: GET /v1/secret/data/iam-platform
   * // Response: { data: { data: { DATABASE_URL: "postgres://..." } } }
   */
  async getSecret(key) {
    // ─────────────────────────────────────────────────────────
    // PLACEHOLDER IMPLEMENTATION
    // Replace with actual Vault HTTP API call when ready.
    //
    // Example implementation outline:
    //
    //   const url = `${this.address}/v1/${this.mountPath}/${this.secretPath}`;
    //   const response = await fetch(url, {
    //     headers: { 'X-Vault-Token': this.token }
    //   });
    //   const body = await response.json();
    //   return body?.data?.data?.[key];
    //
    // Consider:
    //   - Token renewal (lease management)
    //   - Response caching with TTL
    //   - AppRole or Kubernetes auth method
    //   - Dynamic secret generation (database credentials)
    // ─────────────────────────────────────────────────────────
    throw new Error(
      `VaultProvider.getSecret() is not yet implemented. ` +
      `Set SECRET_PROVIDER=env to use environment variables, ` +
      `or implement the Vault HTTP client for key: ${key}`
    );
  }
}

// ─────────────────────────────────────────────────────────────
// PROVIDER REGISTRY & FACTORY
// ─────────────────────────────────────────────────────────────

const PROVIDERS = {
  env: EnvProvider,
  'docker-secrets': DockerSecretsProvider,
  vault: VaultProvider,
};

/** @type {SecretProvider | null} */
let _instance = null;

export function getSecretProvider() {
  if (_instance) return _instance;

  const providerName = (process.env.SECRET_PROVIDER || 'env').toLowerCase();
  
  if (providerName === 'docker-secrets') {
    _instance = new DockerSecretsProvider();
  } else if (providerName === 'vault') {
    _instance = new VaultProvider();
  } else {
    _instance = new EnvProvider();
  }

  logger.info('SECRET_PROVIDER_INITIALIZED', { provider: _instance.getName() });
  return _instance;
}

export default { getSecretProvider, EnvProvider, DockerSecretsProvider, VaultProvider };
