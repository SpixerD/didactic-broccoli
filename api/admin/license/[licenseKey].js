const LicenseDB = require('../../../lib/db');

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.env.ADMIN_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { licenseKey } = req.query;
    const license = await LicenseDB.findLicense(licenseKey);

    if (!license) {
      return res.status(404).json({
        success: false,
        message: 'License not found.'
      });
    }

    const activations = await LicenseDB.getLicenseActivations(licenseKey, 10);

    res.json({
      success: true,
      license: {
        ...license,
        metadata: license.metadata || {}
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
}
