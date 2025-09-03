// License Server - Node.js/Express
// Run: npm install express sqlite3 crypto uuid cors helmet dotenv

require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*'
}));
app.use(express.json({ limit: '10mb' }));

// Initialize SQLite database
const db = new sqlite3.Database('licenses.db');

// Create tables if they don't exist
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            fingerprint TEXT,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            activation_count INTEGER DEFAULT 0,
            max_activations INTEGER DEFAULT 1,
            metadata TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            fingerprint TEXT,
            activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (license_key) REFERENCES licenses (license_key)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS validations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            fingerprint TEXT,
            validated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            status TEXT,
            FOREIGN KEY (license_key) REFERENCES licenses (license_key)
        )
    `);
});

// Helper functions
class LicenseServer {
    static generateLicenseKey() {
        // Generate a license key in format: XXXX-XXXX-XXXX-XXXX
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let key = '';
        for (let i = 0; i < 16; i++) {
            if (i > 0 && i % 4 === 0) key += '-';
            key += chars[Math.floor(Math.random() * chars.length)];
        }
        return key;
    }

    static hashFingerprint(fingerprint, salt = '') {
        return crypto.createHash('sha256').update(fingerprint + salt).digest('hex');
    }

    static isLicenseExpired(expiresAt) {
        if (!expiresAt) return false; // No expiration set
        return new Date() > new Date(expiresAt);
    }

    static async validateLicenseKey(licenseKey) {
        return new Promise((resolve, reject) => {
            db.get(
                'SELECT * FROM licenses WHERE license_key = ?',
                [licenseKey],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                }
            );
        });
    }

    static async recordValidation(licenseKey, fingerprint, ipAddress, status) {
        return new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO validations (license_key, fingerprint, ip_address, status) VALUES (?, ?, ?, ?)',
                [licenseKey, fingerprint, ipAddress, status],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    static async recordActivation(licenseKey, fingerprint, ipAddress, userAgent) {
        return new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO activations (license_key, fingerprint, ip_address, user_agent) VALUES (?, ?, ?, ?)',
                [licenseKey, fingerprint, ipAddress, userAgent],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });
    }

    static async updateLicenseFingerprint(licenseKey, fingerprint) {
        return new Promise((resolve, reject) => {
            db.run(
                'UPDATE licenses SET fingerprint = ?, activation_count = activation_count + 1 WHERE license_key = ?',
                [fingerprint, licenseKey],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });
    }

    static async createLicense(expiresAt = null, maxActivations = 1, metadata = {}) {
        const licenseKey = this.generateLicenseKey();
        
        return new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO licenses (license_key, expires_at, max_activations, metadata) VALUES (?, ?, ?, ?)',
                [licenseKey, expiresAt, maxActivations, JSON.stringify(metadata)],
                function(err) {
                    if (err) reject(err);
                    else resolve(licenseKey);
                }
            );
        });
    }
}

// API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Validate license
app.post('/api/validate', async (req, res) => {
    try {
        const { licenseKey, fingerprint, extensionVersion } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;

        if (!licenseKey || !fingerprint) {
            return res.status(400).json({
                valid: false,
                reason: 'missing_parameters'
            });
        }

        const license = await LicenseServer.validateLicenseKey(licenseKey);

        if (!license) {
            await LicenseServer.recordValidation(licenseKey, fingerprint, ipAddress, 'invalid_key');
            return res.status(200).json({
                valid: false,
                reason: 'invalid_license_key'
            });
        }

        if (license.status !== 'active') {
            await LicenseServer.recordValidation(licenseKey, fingerprint, ipAddress, 'inactive');
            return res.status(200).json({
                valid: false,
                reason: 'license_inactive'
            });
        }

        if (LicenseServer.isLicenseExpired(license.expires_at)) {
            await LicenseServer.recordValidation(licenseKey, fingerprint, ipAddress, 'expired');
            return res.status(200).json({
                valid: false,
                reason: 'license_expired'
            });
        }

        // Check fingerprint match (if already activated)
        if (license.fingerprint && license.fingerprint !== fingerprint) {
            await LicenseServer.recordValidation(licenseKey, fingerprint, ipAddress, 'fingerprint_mismatch');
            return res.status(200).json({
                valid: false,
                reason: 'hardware_mismatch'
            });
        }

        // Valid license
        await LicenseServer.recordValidation(licenseKey, fingerprint, ipAddress, 'valid');
        
        res.json({
            valid: true,
            expires: license.expires_at,
            metadata: license.metadata ? JSON.parse(license.metadata) : {}
        });

    } catch (error) {
        console.error('Validation error:', error);
        res.status(500).json({
            valid: false,
            reason: 'server_error'
        });
    }
});

// Activate license (bind to hardware)
app.post('/api/activate', async (req, res) => {
    try {
        const { licenseKey, fingerprint, extensionVersion } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent');

        if (!licenseKey || !fingerprint) {
            return res.status(400).json({
                success: false,
                message: 'License key and fingerprint are required.'
            });
        }

        const license = await LicenseServer.validateLicenseKey(licenseKey);

        if (!license) {
            return res.status(200).json({
                success: false,
                message: 'Invalid license key.'
            });
        }

        if (license.status !== 'active') {
            return res.status(200).json({
                success: false,
                message: 'License is not active.'
            });
        }

        if (LicenseServer.isLicenseExpired(license.expires_at)) {
            return res.status(200).json({
                success: false,
                message: 'License has expired.'
            });
        }

        // Check if license is already bound to different hardware
        if (license.fingerprint && license.fingerprint !== fingerprint) {
            return res.status(200).json({
                success: false,
                message: 'License is already activated on another device.'
            });
        }

        // Check activation limit
        if (license.activation_count >= license.max_activations && !license.fingerprint) {
            return res.status(200).json({
                success: false,
                message: 'License activation limit exceeded.'
            });
        }

        // Bind license to hardware
        await LicenseServer.updateLicenseFingerprint(licenseKey, fingerprint);
        await LicenseServer.recordActivation(licenseKey, fingerprint, ipAddress, userAgent);

        // Check if this is a trial license and start trial
        const metadata = license.metadata ? JSON.parse(license.metadata) : {};
        if (metadata.isTrial) {
            // This is a trial license - start the trial period
            // Additional logic could be added here if needed
        }

        res.json({
            success: true,
            message: 'License activated successfully.',
            expires: license.expires_at,
            isTrial: metadata.isTrial || false
        });

    } catch (error) {
        console.error('Activation error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error during activation.'
        });
    }
});

// Admin: Create new license
app.post('/api/admin/create-license', async (req, res) => {
    try {
        // Simple API key authentication (implement proper auth in production)
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { expiresAt, maxActivations = 1, metadata = {} } = req.body;
        
        const licenseKey = await LicenseServer.createLicense(expiresAt, maxActivations, metadata);
        
        res.json({
            success: true,
            licenseKey,
            expiresAt,
            maxActivations,
            metadata
        });

    } catch (error) {
        console.error('License creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating license.'
        });
    }
});

// Admin: Get license info
app.get('/api/admin/license/:licenseKey', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { licenseKey } = req.params;
        const license = await LicenseServer.validateLicenseKey(licenseKey);

        if (!license) {
            return res.status(404).json({
                success: false,
                message: 'License not found.'
            });
        }

        // Get activation history
        const activations = await new Promise((resolve, reject) => {
            db.all(
                'SELECT * FROM activations WHERE license_key = ? ORDER BY activated_at DESC LIMIT 10',
                [licenseKey],
                (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                }
            );
        });

        res.json({
            success: true,
            license: {
                ...license,
                metadata: license.metadata ? JSON.parse(license.metadata) : {}
            },
            activations
        });

    } catch (error) {
        console.error('License info error:', error);
        res.status(500).json({
            success: false,
            message: 'Error retrieving license info.'
        });
    }
});

// Admin: Deactivate license
app.post('/api/admin/deactivate/:licenseKey', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { licenseKey } = req.params;

        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE licenses SET status = "inactive" WHERE license_key = ?',
                [licenseKey],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.changes);
                }
            );
        });

        res.json({
            success: true,
            message: 'License deactivated.'
        });

    } catch (error) {
        console.error('License deactivation error:', error);
        res.status(500).json({
            success: false,
            message: 'Error deactivating license.'
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`License server running on port ${PORT}`);
    console.log('Database initialized successfully');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Shutting down gracefully...');
    db.close((err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});

module.exports = app;