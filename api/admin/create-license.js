const LicenseDB = require('../../lib/db');

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.env.ADMIN_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { expiresAt, maxActivations = 1, metadata = {} } = req.body;
    
    const licenseKey = await LicenseDB.createLicense(expiresAt, maxActivations, metadata);
    
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
}
