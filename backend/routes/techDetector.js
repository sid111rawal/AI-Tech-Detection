const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const signatures = require('../utils/signatures.js');
const url = require('url');

// Maximum number of redirects to follow
const MAX_REDIRECTS = 5;

// Browser-like User-Agent
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

// Request timeout in milliseconds
const REQUEST_TIMEOUT = 10000; // 10 seconds

/**
 * Fetch a URL with proper headers handling and redirect following
 * @param {string} urlToFetch - The URL to fetch
 * @param {number} redirectCount - Current redirect count
 * @param {Function} callback - Callback function(error, data, headers)
 */
function fetchUrl(urlToFetch, redirectCount, callback) {
  // Parse the URL
  const parsedUrl = url.parse(urlToFetch);
  const protocol = parsedUrl.protocol === 'https:' ? https : http;
  
  // Set request options
  const options = {
    hostname: parsedUrl.hostname,
    path: parsedUrl.path,
    method: 'GET',
    headers: {
      'User-Agent': USER_AGENT,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache',
      'Upgrade-Insecure-Requests': '1'
    },
    timeout: REQUEST_TIMEOUT
  };

  // Make the request
  const req = protocol.request(options, (response) => {
    // Check if we need to follow a redirect
    if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
      if (redirectCount >= MAX_REDIRECTS) {
        return callback(new Error(`Too many redirects (${MAX_REDIRECTS})`));
      }
      
      // Get the redirect URL
      let redirectUrl = response.headers.location;
      
      // Handle relative redirects
      if (redirectUrl.startsWith('/')) {
        redirectUrl = `${parsedUrl.protocol}//${parsedUrl.hostname}${redirectUrl}`;
      }
      
      // Follow the redirect
      return fetchUrl(redirectUrl, redirectCount + 1, callback);
    }
    
    // Check for successful status code
    if (response.statusCode !== 200) {
      return callback(new Error(`HTTP Error: ${response.statusCode}`));
    }
    
    let data = '';
    response.on('data', (chunk) => {
      data += chunk;
    });
    
    response.on('end', () => {
      callback(null, data, response.headers);
    });
  });
  
  req.on('error', (error) => {
    callback(error);
  });
  
  req.on('timeout', () => {
    req.destroy();
    callback(new Error('Request timed out'));
  });
  
  req.end();
}

router.post('/', (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ success: false, message: 'URL is required' });
  }

  fetchUrl(url, 0, (error, data, headers) => {
    if (error) {
      console.error('Error fetching URL:', error);
      return res.status(500).json({ success: false, message: 'Error fetching URL', error: error.message });
    }
    
    try {
      // Convert headers object to a format that's easier to work with
      const normalizedHeaders = {};
      for (const key in headers) {
        normalizedHeaders[key.toLowerCase()] = headers[key];
      }
      
      const detectedTechnologies = signatures.detectTechnologies(data, normalizedHeaders);
      res.json({ 
        success: true, 
        message: 'Technologies detected', 
        url: url, 
        technologies: detectedTechnologies 
      });
    } catch (error) {
      console.error('Error during technology detection:', error);
      res.status(500).json({ 
        success: false, 
        message: 'Error during technology detection', 
        error: error.message 
      });
    }
  });
});
module.exports = router;
