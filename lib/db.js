const { Pool } = require('pg');

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Helper class for database operations
class LicenseDB {
  static async query(text, params = []) {
    const client = await pool.connect();
    try {
      const result = await client.query(text, params);
      return result;
    } finally {
      client.release();
    }
  }

  static async initializeTables() {
    try {
      await this.query(`
        CREATE TABLE IF NOT EXISTS licenses (
          id SERIAL PRIMARY KEY,
          license_key VARCHAR(255) UNIQUE NOT NULL,
          fingerprint TEXT,
          status VARCHAR(50) DEFAULT 'active',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP,
          activation_count INTEGER DEFAULT 0,
          max_activations INTEGER DEFAULT 1,
          metadata JSONB
        )
      `);

      await this.query(`
        CREATE TABLE IF NOT EXISTS activations (
          id SERIAL PRIMARY KEY,
          license_key VARCHAR(255),
          fingerprint TEXT,
          activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          ip_address VARCHAR(45),
          user_agent TEXT,
          FOREIGN KEY (license_key) REFERENCES licenses (license_key)
        )
      `);

      await this.query(`
        CREATE TABLE IF NOT EXISTS validations (
          id SERIAL PRIMARY KEY,
          license_key VARCHAR(255),
          fingerprint TEXT,
          validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          ip_address VARCHAR(45),
          status VARCHAR(50),
          FOREIGN KEY (license_key) REFERENCES licenses (license_key)
        )
      `);

      console.log('Database tables initialized');
    } catch (error) {
      console.error('Database initialization error:', error);
    }
  }

  static generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 16; i++) {
      if (i > 0 && i % 4 === 0) key += '-';
      key += chars[Math.floor(Math.random() * chars.length)];
    }
    return key;
  }

  static isLicenseExpired(expiresAt) {
    if (!expiresAt) return false;
    return new Date() > new Date(expiresAt);
  }

  static async findLicense(licenseKey) {
    const result = await this.query(
      'SELECT * FROM licenses WHERE license_key = $1',
      [licenseKey]
    );
    return result.rows[0];
  }

  static async createLicense(expiresAt = null, maxActivations = 1, metadata = {}) {
    const licenseKey = this.generateLicenseKey();
    
    const result = await this.query(
      'INSERT INTO licenses (license_key, expires_at, max_activations, metadata) VALUES ($1, $2, $3, $4) RETURNING license_key',
      [licenseKey, expiresAt, maxActivations, JSON.stringify(metadata)]
    );
    
    return result.rows[0].license_key;
  }

  static async updateLicenseFingerprint(licenseKey, fingerprint) {
    const result = await this.query(
      'UPDATE licenses SET fingerprint = $1, activation_count = activation_count + 1 WHERE license_key = $2',
      [fingerprint, licenseKey]
    );
    return result.rowCount;
  }

  static async recordActivation(licenseKey, fingerprint, ipAddress, userAgent) {
    const result = await this.query(
      'INSERT INTO activations (license_key, fingerprint, ip_address, user_agent) VALUES ($1, $2, $3, $4) RETURNING id',
      [licenseKey, fingerprint, ipAddress, userAgent]
    );
    return result.rows[0].id;
  }

  static async recordValidation(licenseKey, fingerprint, ipAddress, status) {
    const result = await this.query(
      'INSERT INTO validations (license_key, fingerprint, ip_address, status) VALUES ($1, $2, $3, $4) RETURNING id',
      [licenseKey, fingerprint, ipAddress, status]
    );
    return result.rows[0].id;
  }

  static async getAllLicenses(limit = 50) {
    const result = await this.query(
      'SELECT * FROM licenses ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    return result.rows;
  }

  static async getLicenseActivations(licenseKey, limit = 10) {
    const result = await this.query(
      'SELECT * FROM activations WHERE license_key = $1 ORDER BY activated_at DESC LIMIT $2',
      [licenseKey, limit]
    );
    return result.rows;
  }

  static async deactivateLicense(licenseKey) {
    const result = await this.query(
      'UPDATE licenses SET status = $1 WHERE license_key = $2',
      ['inactive', licenseKey]
    );
    return result.rowCount;
  }
}

module.exports = LicenseDB;
