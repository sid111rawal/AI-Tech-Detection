/**
 * TechDetective Pro - Technology Signatures
 * 
 * This file contains the signature database for detecting web technologies.
 * Enhanced with patterns for obfuscated/minified code detection.
 */

const signatures = {
  // Analytics
  analytics: [
    {
      name: "Google Analytics",
      versions: {
        "Universal Analytics": {
          weight: 0.9,
          patterns: [ // Universal Analytics patterns
            { type: "script", pattern: /www\.google-analytics\.com\/analytics\.js/i, weight: 0.9 }, // Main UA script
            { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js/i, weight: 0.8 }, // Gtag script (can be used by both UA and GA4)
            { type: "cookie", pattern: /^_gid/, weight: 0.7 }, // Secondary GA cookie
            { type: "cookie", pattern: /^_gat/, weight: 0.6 }, // Throttle cookie
            { type: "jsGlobal", pattern: "ga", weight: 0.8 }, // Global function
            { type: "jsGlobal", pattern: "gtag" },
            { type: "jsGlobal", pattern: "dataLayer" },
            // Obfuscated patterns
            { type: "html", pattern: /function\s*\(\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*\)\s*\{\s*[a-z]\s*\.\s*[a-z]\s*=\s*[a-z]\s*\.\s*[a-z]\s*\|\|\s*\[\]/i, weight: 0.7 },
            { type: "networkRequest", pattern: /collect\?v=1&_v=j\d+&/i }
          ]
        },
        "GA4": {
          weight: 0.95,
          patterns: [ // GA4 patterns
            { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js\?id=G-/i, weight: 0.95 }, // GA4 script
            { type: "jsGlobal", pattern: "gtag" },
            { type: "networkRequest", pattern: /\/g\/collect\?v=2/i }
          ]
        }
      }
    },
    {
      name: "Mixpanel",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.mxpnl\.com\/libs\/mixpanel/i },
        { type: "script", pattern: /cdn\.mixpanel\.com\/mixpanel/i },
        { type: "cookie", pattern: /^mp_/ },
        { type: "jsGlobal", pattern: "mixpanel" },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /api\/2\.0\/track/i },
        { type: "html", pattern: /function\s*\(\s*[a-z]\s*\)\s*\{\s*return\s*[a-z]\s*\.\s*[a-z]+\s*\(\s*"mixpanel"\s*\)/i, weight: 0.7 }
      ]
    },
    {
      name: "Segment",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.segment\.com\/analytics\.js/i },
        { type: "cookie", pattern: /^ajs_/ },
        { type: "jsGlobal", pattern: "analytics" },
        { type: "networkRequest", pattern: /api\.segment\.io\/v1/i },
        // Obfuscated patterns
        { type: "html", pattern: /window\.analytics\s*=\s*window\.analytics\s*\|\|\s*\[\]/i, weight: 0.8 }
      ]
    },
    {
      name: "Zipkin",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /zipkin/i },
        { type: "header", pattern: "x-b3-traceid" },
        { type: "header", pattern: "x-b3-spanid" },
        { type: "header", pattern: "x-b3-sampled" },
        { type: "networkRequest", pattern: /api\/v2\/spans/i },
        { type: "html", pattern: /zipkin/i }
      ]
    }
  ],
  // Utility Libraries
  utility_libraries: [
    {
      name: "jQuery",
      versions: {
        versionProperty: "$.fn.jquery",
        "jQuery 1.x": {
          weight: 0.9,
          patterns: [
            { type: "jsVersion", pattern: /^1\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-1\./i, weight: 0.8 }
          ]
        },
        "jQuery 2.x": {
          weight: 0.9,
          patterns: [
            { type: "jsVersion", pattern: /^2\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-2\./i, weight: 0.8 }
          ]
        },
        "jQuery 3.x": {
          weight: 0.9,
          patterns: [
            { type: "jsVersion", pattern: /^3\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-3\./i, weight: 0.8 }
          ]
        },
        "jQuery Unspecified Version": {
          weight: 0.8,
          patterns: []
        },
        patterns: [
          { type: "jsGlobal", pattern: "jQuery", weight: 0.9 },
          { type: "jsGlobal", pattern: "$", weight: 0.9 },
          { type: "script", pattern: /jquery(\.min)?\.js/i, weight: 0.8 },
          { type: "html", pattern: /<script[^>]+jquery/i },
          { type: "html", pattern: /<script[^>]+jquery-migrate/i }
        ]
      },
      versionProperty: "$.fn.jquery"
    },
    {
      name: "Lodash",
      weight: 0.9,
      patterns: [
        { type: "jsGlobal", pattern: "_" },
        { type: "script", pattern: /lodash(\.min)?\.js/i }
      ]
    }
  ]
};

/**
 * Extracts version numbers from potential global JavaScript variables.
 * @param {string} html - The HTML content of the website.
 * @param {string[]} jsGlobals - Array of potential global JavaScript variable names.
 * @returns {object} - Object containing detected JavaScript versions by variable name (e.g., { 'React.version': '18.0.0', '$.fn.jquery': '3.6.0' }).
 */
const extractJsVersions = (html, jsGlobals) => {
  const jsVersions = {};

  // Check for angular.version
  const angularVersionMatch = html.match(/angular\.version\s*=\s*\{\s*full:\s*['"]([^'"]+)['"]/i);
  if (angularVersionMatch && angularVersionMatch[1]) {
    jsVersions["angular.version"] = angularVersionMatch[1];
  } else {
    jsVersions["angular.version"] = null;
  }

  // Check for Vue.version
  const vueVersionMatch = html.match(/Vue\.version\s*=\s*['"]([^'"]+)['"]/i);
  if (vueVersionMatch && vueVersionMatch[1]) {
    jsVersions["Vue.version"] = vueVersionMatch[1];
  } else {
    jsVersions["Vue.version"] = null;
  }

  // Check for React.version
  const reactVersionMatch = html.match(/React\.version\s*=\s*['"]([^'"]+)['"]/i);
  if (reactVersionMatch && reactVersionMatch[1]) {
    jsVersions["React.version"] = reactVersionMatch[1];
  } else {
    jsVersions["React.version"] = null;
  }

  // Check for $.fn.jquery (jQuery version)
  const jqueryVersionMatch = html.match(/\$\.fn\.jquery\s*=\s*['"]([^'"]+)['"]/i);
  if (jqueryVersionMatch && jqueryVersionMatch[1]) {
    jsVersions["$.fn.jquery"] = jqueryVersionMatch[1];
  } else {
    jsVersions["$.fn.jquery"] = null;
  }

  return jsVersions;
};

/**
 * Adds a new signature to the signatures database.
 */
function addSignature(signature) {
  if (!signatures[signature.category]) {
    signatures[signature.category] = [];
  }
  signatures[signature.category].push(signature);
}

/**
 * Deletes a signature from the signatures database by name.
 * @param {string} name - The name of the signature to delete.
 */
function deleteSignatureByName(name) {
  for (const category in signatures) {
    signatures[category] = signatures[category].filter(signature => signature.name !== name);
  }
}

// Define the detectTechnologies function
function detectTechnologies(html, headers) {
  const detected = {};

  for (const category in signatures) {
    detected[category] = [];

    for (const signature of signatures[category]) {
      for (const pattern of signature.patterns || []) {
        if (pattern.type === 'html' && pattern.pattern.test(html)) {
          detected[category].push({
            name: signature.name,
            confidence: pattern.weight || 1.0,
            detectedBy: 'html'
          });
        } else if (pattern.type === 'header' && headers[pattern.pattern.toLowerCase()]) {
          detected[category].push({
            name: signature.name,
            confidence: pattern.weight || 1.0,
            detectedBy: 'header'
          });
        }
      }
    }
  }

  return detected;
}

module.exports = {
  extractJsVersions,
  signatures,
  detectTechnologies,
  addSignature,
  deleteSignatureByName,
  extractCookies,
  checkVersionPattern,
  checkPattern,
  extractScripts,
  extractCssLinks,
  extractMetaTags,
  extractHeaders,
  extractHtmlComments,
  extractPotentialJsGlobals,
  extractPotentialNetworkRequests
};