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
            // Detects jQuery 1.x versions using the $().jquery property
            { type: "jsVersion", pattern: /^1\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-1\./i, weight: 0.8 }, // Fallback to script tag
          ]
        },
        "jQuery 2.x": {
          weight: 0.9,
          patterns: [
            // Detects jQuery 2.x versions using the $().jquery property
            { type: "jsVersion", pattern: /^2\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-2\./i, weight: 0.8 }, // Fallback to script tag
          ]
        },
        "jQuery 3.x": {
          weight: 0.9,
          patterns: [
            // Detects jQuery 3.x versions using the $().jquery property
            { type: "jsVersion", pattern: /^3\./, versionProperty: "$.fn.jquery", weight: 0.9 },
            { type: "script", pattern: /code\.jquery\.com\/jquery-3\./i, weight: 0.8 }, // Fallback to script tag
          ]
        },
        "jQuery Unspecified Version": { // For cases where version property isn't detected
          weight: 0.8,
          patterns: [
          ]
        },
        patterns: [
          { type: "jsGlobal", pattern: "jQuery", weight: 0.9 },
          { type: "jsGlobal", pattern: "$", weight: 0.9 },
          { type: "script", pattern: /jquery(\.min)?\.js/i, weight: 0.8 },
          { type: "html", pattern: /<script[^>]+jquery/i },
          { type: "html", pattern: /<script[^>]+jquery-migrate/i },
        ]
      },
      versionProperty: "$.fn.jquery",
    },
    {
      name: "Lodash",
      weight: 0.9,
      patterns: [
        { type: "jsGlobal", pattern: "_" },
        { type: "script", pattern: /lodash(\.min)?\.js/i }
      ]
    }
  ],

  // Payment Processors
  payment_processors: [
    {
      name: "Stripe",
      weight: 0.95,
      patterns: [
        { type: "script", pattern: /js\.stripe\.com/i, weight: 0.9 },
        { type: "cookie", pattern: /__stripe_mid/, weight: 0.7 },
        { type: "cookie", pattern: /__stripe_sid/, weight: 0.7 },
        { type: "jsGlobal", pattern: "Stripe", weight: 0.9 },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /api\.stripe\.com/i, weight: 0.8 },
        { type: "html", pattern: /data-stripe/i, weight: 0.7 }
      ]
    },
    {
      name: "PayPal",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /paypal\.com\/sdk/i },
        { type: "script", pattern: /paypalobjects\.com/i },
        { type: "jsGlobal", pattern: "paypal", weight: 0.9 },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /\.paypal\.com/i, weight: 0.8 },
        { type: "html", pattern: /data-paypal/i, weight: 0.6 },
        { type: "cookie", pattern: /paypal/i, weight: 0.6 },
        { type: "html", pattern: /paypalcheckout/i, weight: 0.6 }
      ]
    },
    {
      name: "BitPay",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /bitpay\.com\/bitpay\.js/i },
        { type: "script", pattern: /bitpay\.com\/bitpay\.min\.js/i },
        { type: "html", pattern: /data-bitpay/i },
        { type: "networkRequest", pattern: /bitpay\.com\/api/i },
        { type: "jsGlobal", pattern: "bitpay" }
      ]
    }
  ],

  // Security
  security: [
    {
      name: "HSTS",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "strict-transport-security" }
      ]
    },
    {
      name: "Content Security Policy",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "content-security-policy" },
        { type: "meta", pattern: { name: "content-security-policy" } }
      ]
    }
  ],
  
  // Miscellaneous
  miscellaneous: [
    {
      name: "Open Graph",
      weight: 0.9,
      patterns: [
        { type: "meta", pattern: { name: "og:title" } },
        { type: "meta", pattern: { name: "og:type" } },
        { type: "meta", pattern: { name: "og:image" } },
        { type: "meta", pattern: { name: "og:url" } },
        { type: "html", pattern: /property=["']og:/i }
      ]
    }
  ],
  
  // Cookie Compliance
  cookie_compliance: [
    {
      name: "OneTrust",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.cookielaw\.org/i },
        { type: "script", pattern: /optanon/i },
        { type: "cookie", pattern: /OptanonConsent/i },
        { type: "cookie", pattern: /OptanonAlertBoxClosed/i },
        { type: "jsGlobal", pattern: "OneTrust" },
        { type: "jsGlobal", pattern: "Optanon" },
        { type: "html", pattern: /onetrust/i }
      ]
    }
  ],

  self_hosted_cms: [
    {
      name: "WordPress",
      versions: {
        "Wordpress < 4.0": {
          patterns: [
            { type: "meta", pattern: { name: "generator", content: /WordPress ([0-3]\.\d+(\.\d+)?)/i }, weight: 0.9 }
          ]
        },
        "Wordpress >= 4.0": {
          weight: 0.9,
          patterns: [
            { type: "meta", pattern: { name: "generator", content: /WordPress ([4-9]\.\d+(\.\d+)?)/i }, weight: 0.9 }
          ]
        },
        "Wordpress >= 6.0": {
          weight: 0.9,
          patterns: [
            { type: "meta", pattern: { name: "generator", content: /WordPress ([6-9]\.\d+(\.\d+)?)/i }, weight: 0.9 }
          ]
        }
      },
      patterns: [
        { type: "script", pattern: /wp-content/, weight: 0.8 }, // Common script location
        { type: "script", pattern: /wp-includes/, weight: 0.8 }, // Common script location
        { type: "cookie", pattern: /wordpress_/, weight: 0.7 }, // Common WordPress cookie prefix
        { type: "cookie", pattern: /wp-settings-\d/, weight: 0.7 }, // Common WordPress cookie prefix
        { type: "cookie", pattern: /wp-settings-/, weight: 0.7 }, // Common WordPress cookie prefix
        { type: "networkRequest", pattern: /wp-json/i }, // Obfuscated patterns
        { type: "jsGlobal", pattern: "wp" }
      ]
    },
    {
      name: "Squarespace",
      category: "hosted_cms",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /squarespace-assets\.com/i, weight: 0.8 },
        { type: "html", pattern: /squarespace-cdn/i, weight: 0.8 },
        { type: "html", pattern: /class="sqs-/i, weight: 0.7 },
        { type: "networkRequest", pattern: /squarespace\.com/i, weight: 0.7 },
        { type: "meta", pattern: { name: "generator", content: /Squarespace/i }, weight: 0.9 }
      ]
    },
    {
      name: "Wix",
      weight: 0.9,
      patterns: [
        { type: "html", pattern: /wix\.com/i, weight: 0.9 },
        { type: "html", pattern: /static\.parastorage\.com/i, weight: 0.8 },
        { type: "script", pattern: /wixstatic\.com/i, weight: 0.8 },
        { type: "script", pattern: /wix\.com/i, weight: 0.8 },
        { type: "networkRequest", pattern: /wix\.com/i, weight: 0.7 },
        { type: "cookie", pattern: /WIX_LOCALE/i },
        { type: "cookie", pattern: /SESS/ }
      ]
    },
    {
      name: "Drupal",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /drupal\.js/i },
        { type: "html", pattern: /drupal-/i },
        { type: "html", pattern: /data-drupal/i },
        { type: "jsGlobal", pattern: /Drupal/i },
        { type: "meta", pattern: { name: "generator", content: /Drupal/i } },
        // Obfuscated patterns
        { type: "cookie", pattern: /SESS/ }
      ]
    },
    {
      name: "Joomla",
      category: "self_hosted_cms",
      weight: 0.8,
      patterns: [
        { type: "html", pattern: /joomla/i, weight: 0.8 },
        { type: "meta", pattern: { name: "generator", content: /Joomla!/i }, weight: 0.9 },
        { type: "script", pattern: /joomla-core/i, weight: 0.7 },
        { type: "networkRequest", pattern: /joomla/i, weight: 0.7 }
      ]
    }
  ],
  hosted_cms: [
    {
      name: "Ghost",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "x-ghost-cache-status" },
        { type: "meta", pattern: { name: "generator", content: /Ghost/i }, weight: 0.9 },
        { type: "html", pattern: /ghost/i },
        { type: "script", pattern: /ghost/i }
      ]
    }
  ],
  css_frameworks: [
    {
      name: "Bootstrap",
      category: "css_frameworks",
      versions: {
        "Bootstrap 3.x": {
          weight: 0.9,
          patterns: [
            // Detects Bootstrap 3.x versions using the script tag
            { type: "script", pattern: /bootstrapcdn\.com\/bootstrap\/3\./i, weight: 0.9 },
            // Detects Bootstrap 3.x versions using the css tag
            { type: "css", pattern: /bootstrapcdn\.com\/bootstrap\/3\./i, weight: 0.9 }
          ]
        },
        "Bootstrap 4.x": {
          weight: 0.9,
          patterns: [
            // Detects Bootstrap 4.x versions using the script tag
            { type: "script", pattern: /bootstrapcdn\.com\/bootstrap\/4\./i, weight: 0.9 },
            // Detects Bootstrap 4.x versions using the css tag with version in URL
            { type: "css", pattern: /bootstrap\/4\./i, weight: 0.9 },
            { type: "css", pattern: /bootstrapcdn\.com\/bootstrap\/4\./i, weight: 0.9 }
          ]
        },
        "Bootstrap 5.x": {
          weight: 0.9,
          patterns: [
            // Detects Bootstrap 5.x versions using the script tag
            { type: "script", pattern: /bootstrapcdn\.com\/bootstrap\/5\./i, weight: 0.9 },
            // Detects Bootstrap 5.x versions using the css tag with version in URL
            { type: "css", pattern: /bootstrap\/5\./i, weight: 0.9 },
            { type: "css", pattern: /bootstrapcdn\.com\/bootstrap\/5\./i, weight: 0.9 }
          ]
        },
        patterns: [
          { type: "script", pattern: /bootstrap(\.min)?\.js/i, weight: 0.8 }, // Common Bootstrap script
          { type: "css", pattern: /bootstrap(\.min)?\.css/i, weight: 0.8 }, // Common Bootstrap CSS
          { type: "html", pattern: /class="[^"]*navbar/i, weight: 0.7 }, // Common navbar class
          { type: "html", pattern: /class="[^"]*container/i, weight: 0.7 }, // Common container class
          { type: "html", pattern: /class="[^"]*row/i },
          { type: "html", pattern: /class="[^"]*col-/i },
          { type: "html", pattern: /class="[^"]*btn/i }
        ]
      }
    },
    {
      name: "Tailwind CSS",
      category: "css_frameworks",
      weight: 0.9,
      patterns: [
        { type: "css", pattern: /tailwind(\.min)?\.css/i },
        { type: "html", pattern: /class="[^"]*text-\w+-\d+/i },
        { type: "html", pattern: /class="[^"]*bg-\w+-\d+/i },
        { type: "html", pattern: /class="[^"]*p-\d+/i },
        { type: "html", pattern: /class="[^"]*m-\d+/i }
      ]
    }
  ],
  server_platforms: [
    {
      name: "Apache",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /apache/i, weight: 0.9 },
        { type: "header", pattern: "x-powered-by", value: /apache/i, weight: 0.7 },
        { type: "html", pattern: /Apache Web Server/, weight: 0.6 },
        { type: "error", pattern: /Apache/, weight: 0.7 }
      ]
    },  
    {
      name: "Nginx",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /nginx/i }
      ]
    },
    {
      name: "Express.js",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-powered-by", value: /express/i }
      ]
    }
  ],
  hosting_providers: [
    {
      name: "Cloudways",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /cloudways/i },
        { type: "networkRequest", pattern: /cloudwaysapps\.com/i },
        { type: "error", pattern: /cloudways/i }
      ]
    },
    {
      name: "Digital Ocean",
      weight: 0.7,
      patterns: [
        { type: "header", pattern: "server", value: /digitalocean/i },
        { type: "networkRequest", pattern: /digitalocean/i }
      ]
    }
  ],
  reverse_proxies: [
    {
      name: "AWS",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-amz-id-2" },
        { type: "header", pattern: "x-amz-cf-id" },
        { type: "networkRequest", pattern: /amazonaws\.com/i }
      ]
    },
    {
      name: "Google Cloud",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Google Frontend/i, weight: 0.9 },
        { type: "networkRequest", pattern: /googleapis\.com/i }
      ]
    }, 
    {
      name: "Cloudflare",
      weight: 0.95, // High confidence for Cloudflare
      patterns: [
        { type: "header", pattern: "cf-ray", weight: 0.9 }, // Cloudflare's unique header
        { type: "header", pattern: "cf-cache-status", weight: 0.8 }, // Cloudflare's unique header
        { type: "header", pattern: "server", value: /cloudflare/i, weight: 0.8 }, // Cloudflare often sets the server header
        { type: "cookie", pattern: /__cfduid/, weight: 0.7 }, // Common Cloudflare cookie
        { type: "cookie", pattern: /__cf_bm/, weight: 0.7 }, // Common Cloudflare cookie
        { type: "networkRequest", pattern: /cloudflare\.com/i, weight: 0.7 }
      ]
    },
    {
      name: "Envoy",
      category: "reverse_proxies",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /envoy/i },
        { type: "header", pattern: "x-envoy-upstream-service-time" }
      ]
    }
  ],
  programming_languages: [
    {
      // Check for X-Powered-By header or PHPSESSID cookie
      name: "PHP",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-powered-by", value: /php/i },
        { type: "cookie", pattern: /PHPSESSID/i }
      ]
    },
    {
      // Check for Phusion Passenger server header or Ruby session cookie
      name: "Ruby",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Phusion Passenger/i },
        { type: "cookie", pattern: /_session_id/i }
      ]
    },
    {
      // Check for Python server header or Django/Flask cookies
      name: "Python",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Python/i },
        { type: "cookie", pattern: /django_/i },
        { type: "cookie", pattern: /flask/i }
      ]
    }
  ],
  databases: [
    {
      name: "MySQL",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /mysql/i },
        { type: "error", pattern: /MySQL/i }
      ]
    },
    {
      name: "PostgreSQL",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /postgresql/i },
        { type: "error", pattern: /PostgreSQL/i }
      ]
    },
    {
      name: "MongoDB",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /mongodb/i },
        { type: "jsGlobal", pattern: "MongoDB" }
      ]
    },
    {
      name: "Redis",
      weight: 0.7,
      patterns: [
        { type: "html", pattern: /redis/i },
        { type: "header", pattern: "x-redis-info" },
        { type: "networkRequest", pattern: /redis/i },
        { type: "error", pattern: /Redis/i },
        { type: "jsGlobal", pattern: "Redis" }
      ]      
    }
  ],
  marketing_automation: [
    {
      name: "Mailchimp",
      weight: 0.8,
      patterns: [
        { type: "script", pattern: /cdn-images\.mailchimp\.com/i },
        { type: "html", pattern: /mailchimp/i },
        { type: "networkRequest", pattern: /mailchimp/i },
        { type: "jsGlobal", pattern: /mailchimp/i }
      ]
    },
    {
      name: "Adyen",
      weight: 0.8,
      patterns: [
        { type: "script", pattern: /checkout\.adyen\.com/i },
        { type: "html", pattern: /adyen\.com/i },
        { type: "jsGlobal", pattern: /Adyen/i },
        { type: "networkRequest", pattern: /adyen\.com/i }
      ]
    },
    {
      name: "ActiveCampaign",
      weight: 0.8,
      patterns: [
        { type: "script", pattern: /activehosted\.com/i },
        { type: "networkRequest", pattern: /activehosted\.com/i }
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
      jsVersions["React.version"] = null; // Indicate that React might be present but version wasn't found this way
  }

  // Check for $.fn.jquery (jQuery version)
  const jqueryVersionMatch = html.match(/\$\.fn\.jquery\s*=\s*['"]([^'"]+)['"]/i);
  if (jqueryVersionMatch && jqueryVersionMatch[1]) {
 jsVersions["$.fn.jquery"] = jqueryVersionMatch[1];
  }else {
      jsVersions["$.fn.jquery"] = null; // Indicate that jQuery was found but version wasn't
 }
 return jsVersions;
}

/**
 * Adds a new signature to the signatures database.
 */
function addSignature(signature) {
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



/**
 * @param {string} url - The URL of the website to detect technologies from.
 * Detect technologies used on a website
 * @param {string} html - The HTML content of the website
 * @param {object} httpHeaders - The HTTP headers from the response
 * @returns {object} - Object containing detected technologies by category
 */
const detectTechnologies = (html, httpHeaders = {}) => {
  const detected = {}; // Changed from const to let to allow re-assignment
  
  const metaHeaders = extractHeaders(html);
  // Note: This merge might overwrite actual headers if meta http-equiv is used for the same header name.
  // This is a limitation for now, but a proper solution would involve passing actual HTTP headers
  // from the request handling part.
  const headers = { ...metaHeaders, ...httpHeaders };
  
  // Extract meta tags
  const metaTags = extractMetaTags(html);
  
  // Extract cookies (can't be done server-side, but we'll check for patterns)
  const cookies = extractCookies(html);
  
  // Extract script sources
  const scripts = extractScripts(html);
  
  // Extract CSS sources
  const cssLinks = extractCssLinks(html);
  
  // Extract potential JS globals from inline scripts
  const potentialJsGlobals = extractPotentialJsGlobals(html);
  
  // Extract network requests from script tags (limited capability)
  const potentialNetworkRequests = extractPotentialNetworkRequests(html);
  
  // Extract HTML comments
  const htmlComments = extractHtmlComments(html);

  // Extract JavaScript versions
  const jsVersions = extractJsVersions(html, potentialJsGlobals); // Pass potentialJsGlobals

  // Iterate over each category in the signatures
  for (const category in signatures) {
    detected[category] = []; // Initialize the category array
    const categorySignatures = signatures[category];
    
    // Iterate over each signature in the category
    for (const signature of categorySignatures) {
      let detectedVersion = null;
      let maxConfidence = 0;
      let isDetected = false; // Flag to indicate if any version or the base signature is detected
      
      // Handle technologies with versions
      if (signature.versions) {
        for (const version in signature.versions) {
          const versionData = signature.versions[version];
          const versionPatterns = versionData.patterns;
          let versionConfidence = versionData.weight || 0.5;
          let versionMatches = 0;
          let totalPatterns = versionPatterns.length;

          for (const pattern of versionPatterns) {
            let match = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, cookies, potentialJsGlobals, potentialNetworkRequests, htmlComments, jsVersions);
            
            if (match) {
              versionMatches++;
              versionConfidence *= pattern.weight || 1;
            }
          }
          
          // If we have matches and confidence is higher than current max
          if (versionMatches > 0 && versionConfidence > maxConfidence) {
            maxConfidence = versionConfidence;
            detectedVersion = version;
            isDetected = true;
          }
        }
        // If we detected a version, add it to the results
        if (isDetected) {
          detected[category].push({ 
            name: signature.name,
            version: detectedVersion, 
            confidence: Math.round(maxConfidence * 100) 
          });          
        }
      }
      // Handle technologies without versions
      else {
        let confidence = signature.weight || 0.5;
        let matches = 0;
        let totalPatterns = signature.patterns.length;
        
        for (const pattern of signature.patterns) {
          let match = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, cookies, potentialJsGlobals, potentialNetworkRequests, htmlComments, jsVersions); // Pass jsVersions
          
          if (match) {
            matches++;
            confidence *= pattern.weight || 1;
            // If we have a high confidence match, no need to check more patterns
            if (confidence > 0.8) break;
          }
        }
        
        // If we have matches, add to results
        if (matches > 0) {
          detected[category].push({ 
            name: signature.name,
            version: null, 
            confidence: Math.round(confidence * 100) 
          });
        }
      }
    }
  }
  
  return detected;
}

// Helper function to check for version patterns in JS globals
const checkVersionPattern = (patternRegex, jsVersions, versionProperty) => { // Renamed pattern to patternRegex
  // The pattern here is the expected version regex from the signature
  if (jsVersions && versionProperty && jsVersions[versionProperty] !== undefined && jsVersions[versionProperty] !== null) {
    // You can add more sophisticated version comparison logic here if needed
    // For now, we'll just return the detected version string
    return jsVersions[versionProperty];
  }
  // If versionProperty is not found in jsVersions or is null/undefined
 return null;
}

// Helper function to check a pattern against various content types
const checkPattern = (pattern, html, scripts, cssLinks, headers, metaTags, cookies, jsGlobals, networkRequests, htmlComments, jsVersions) => {
  switch (pattern.type) {
    case "html":
      return pattern.pattern.test(html);


      
    case "script":
      return scripts.some(script => pattern.pattern.test(script));
      
    case "css":
      return cssLinks.some(css => pattern.pattern.test(css));
      
    case "header":
      if (pattern.value) {
        return headers[pattern.pattern] && pattern.value.test(headers[pattern.pattern]);
      }
      return pattern.pattern in headers;
      
    case "meta":
      if (pattern.content) {
        return metaTags[pattern.name] && pattern.content.test(metaTags[pattern.name]);
      }
      return pattern.name in metaTags;
      
    case "cookie":
      return cookies.some(cookie => pattern.pattern.test(cookie.name));
      
    case "jsGlobal":
      // Check if the global variable name appears in the HTML
 return jsGlobals.includes(pattern.pattern) ||
 new RegExp(`\\b${pattern.pattern}\\b`).test(html);

    case "networkRequest":
      return pattern.pattern.test(html) || networkRequests.some(req => pattern.pattern.test(req));

    case "jsVersion":
      const detectedVersion = checkVersionPattern(pattern.pattern, jsVersions, pattern.versionProperty); // Pass pattern.pattern as the regex
      if (detectedVersion === null || (pattern.pattern instanceof RegExp && !pattern.pattern.test(detectedVersion)) || (typeof pattern.pattern === 'string' && detectedVersion !== pattern.pattern) ) { // Test the detected version against the pattern regex or string
        return false;
      }
 return pattern.pattern.test(detectedVersion);
    case "htmlComment":
      return htmlComments.some(comment => pattern.pattern.test(comment) && (!pattern.value || comment.includes(pattern.value)));
    
    case "css":
      return false;
  }
}

// Extract cookies from script tags or inline scripts
const extractCookies = (html) => {
 const cookies = [];
 const cookieRegex = /document\.cookie\s*=\s*['"]([^'"]+?)=([^;'"]*)/gi; // Extract name=value pairs
 let match;
 while (match = cookieRegex.exec(html)) {
 const name = match[1];
 const value = match[2];
 cookies.push({ name: name, value: value });
  }
  return cookies;
}
// Extract script sources from HTML
const extractScripts = (html) => {
  const scripts = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = scriptRegex.exec(html)) {
    scripts.push(match[1]);
  }
  
  return scripts;
}

// Extract CSS link sources from HTML
const extractCssLinks = (html) => {
  const cssLinks = [];
  const cssRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/gi;
  const altCssRegex = /<link[^>]*href=["']([^"']+\.css[^"']*)["'][^>]*>/gi;
  let match;
  
  while (match = cssRegex.exec(html)) {
    cssLinks.push(match[1]);
  }
  
  while (match = altCssRegex.exec(html)) {
    cssLinks.push(match[1]);
  }
  
  return cssLinks;
}

// Extract meta tags from HTML
const extractMetaTags = (html) => {
  const metaTags = {};
  const metaRegex = /<meta[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>/gi;
  const altMetaRegex = /<meta[^>]*content=["']([^"']+)["'][^>]*name=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = metaRegex.exec(html)) {
    metaTags[match[1].toLowerCase()] = match[2];
  }
  
  while (match = altMetaRegex.exec(html)) {
    metaTags[match[2].toLowerCase()] = match[1];
  }
  
  return metaTags;
}

// Extract headers from meta http-equiv tags
const extractHeaders = (html) => {
  const headers = {};
  const headerRegex = /<meta[^>]*http-equiv=["']([^"']+)["'][^>]*content=["']([^"']+)["'][^>]*>/gi;
  const altHeaderRegex = /<meta[^>]*content=["']([^"']+)["'][^>]*http-equiv=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = headerRegex.exec(html)) {
    headers[match[1].toLowerCase()] = match[2];
  }
  
  while (match = altHeaderRegex.exec(html)) {
    headers[match[2].toLowerCase()] = match[1];
  }
  
  return headers;
}

// Extract HTML comments
const extractHtmlComments = (html) => {
    const comments = [];
    const commentRegex = /<!--([\s\S]*?)-->/gi;
    let match;

    while ((match = commentRegex.exec(html)) !== null) {
        comments.push(match[1]);
    }
    return comments;
}
// Extract potential JS globals from inline scripts
const extractPotentialJsGlobals = (html) => {
  const globals = [];
  const globalRegex = /(?:var|let|const|window\.)\s+(\w+)\s*=/gi;
  const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  let scriptMatch;
  
  while (scriptMatch = inlineScriptRegex.exec(html)) {
    const scriptContent = scriptMatch[1];
    while (match = globalRegex.exec(scriptContent)) {
      globals.push(match[1]);
    }
  }
  
  // Add common globals that might be referenced
  const commonGlobals = ["React", "ReactDOM", "Vue", "jQuery", "$", "_", "angular", "Stripe", "paypal", "ga", "gtag", "dataLayer"];
  commonGlobals.forEach(global => {
    if (html.includes(global)) {
      globals.push(global);
    }
  });
  return globals;
}

// Extract potential network requests from script tags or HTML
const extractPotentialNetworkRequests = (html) => {
  const requests = [];
  const urlRegex = /['"]https?:\/\/([^'"]+)['"]/gi;
  let match;
  
  while (match = urlRegex.exec(html)) {
    requests.push(match[1]);
  }
  
  return requests;
}

// Adding the new Google Analytics signature using the addSignature function
addSignature({
    name: "Google Analytics",
    category: "analytics",
    weight: 0.8,
    patterns: [
        { type: "cookie", pattern: /^_ga/i, weight: 0.8 }
    ]
});

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