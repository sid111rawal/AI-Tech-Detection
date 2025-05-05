const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const signatures = require('../utils/signatures.js');


router.post('/', (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ success: false, message: 'URL is required' });
  }

  const protocol = url.startsWith('https') ? https : http;

  protocol.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => {
          data += chunk;
      });
      response.on('end', () => {
        try {
            const detectedTechnologies = signatures.detectTechnologies(data);
            res.json({ success: true, message: 'Technologies detected', url: url, technologies: detectedTechnologies });
        } catch (error) {
            console.error('Error during technology detection:', error);
            res.status(500).json({ success: false, message: 'Error during technology detection', error: error.message });
        }

      });
  }).on('error', (error) => {
      console.error('Error fetching URL:', error);
      res.status(500).json({ success: false, message: 'Error fetching URL', error: error.message });
  });
});
module.exports = router;
