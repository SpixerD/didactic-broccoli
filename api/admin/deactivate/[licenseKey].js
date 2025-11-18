const LicenseDB = require('../../../lib/db');

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.env.ADMIN_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { licenseKey } = req.query;
    await LicenseDB.deactivateLicense(licenseKey);

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
}
