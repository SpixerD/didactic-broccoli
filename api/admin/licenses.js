const LicenseDB = require('../../lib/db');

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== process.env.ADMIN_API_KEY) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const licenses = await LicenseDB.getAllLicenses(50);

    res.json({
      success: true,
      licenses: licenses.map(license => ({
        ...license,
        metadata: license.metadata || {}
      }))
    });

  } catch (error) {
    console.error('Error fetching licenses:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching licenses.'
    });
  }
}
