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
          patterns: [
            { type: "script", pattern: /www\.google-analytics\.com\/analytics\.js/i },
            { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js/i },
            { type: "cookie", pattern: /^_ga/ },
            { type: "cookie", pattern: /^_gid/ },
            { type: "cookie", pattern: /^_gat/ },
            { type: "jsGlobal", pattern: "ga" },
            { type: "jsGlobal", pattern: "gtag" },
            { type: "jsGlobal", pattern: "dataLayer" },
            // Obfuscated patterns
            { type: "html", pattern: /function\s*\(\s*[a-z]\s*,\s*[a-z]\s*,\s*[a-z]\s*\)\s*\{\s*[a-z]\s*\.\s*[a-z]\s*=\s*[a-z]\s*\.\s*[a-z]\s*\|\|\s*\[\]/i, weight: 0.7 },
            { type: "networkRequest", pattern: /collect\?v=1&_v=j\d+&/i }
          ]
        },
        "GA4": {
          weight: 0.9,
          patterns: [
            { type: "script", pattern: /www\.googletagmanager\.com\/gtag\/js\?id=G-/i },
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

  // JavaScript Frameworks
  javascript_frameworks: [
    {
      name: "React",
      weight: 0.95,
      patterns: [
        { type: "jsGlobal", pattern: "React" },
        { type: "jsGlobal", pattern: "ReactDOM" },
        { type: "script", pattern: /react(\.development|\.production|\.min)?\.js/i },
        { type: "html", pattern: /data-reactroot/i },
        { type: "html", pattern: /data-reactid/i },
        // Obfuscated/minified patterns
        { type: "html", pattern: /_reactListening/i },
        { type: "html", pattern: /__REACT_DEVTOOLS_GLOBAL_HOOK__/i },
        { type: "html", pattern: /\[\s*"r"\s*,\s*"e"\s*,\s*"a"\s*,\s*"c"\s*,\s*"t"\s*\]/i, weight: 0.7 }
      ]
    },
    {
      name: "Emotion",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /emotion/i },
        { type: "html", pattern: /css-[a-zA-Z0-9]+/i },
        { type: "html", pattern: /data-emotion/i },
        { type: "jsGlobal", pattern: "emotion" },
        { type: "jsGlobal", pattern: "styled" }
      ]
    },
    {
      name: "Angular",
      versions: {
        "AngularJS": {
          weight: 0.9,
          patterns: [
            { type: "jsGlobal", pattern: "angular" },
            { type: "script", pattern: /angular(\.min)?\.js/i },
            { type: "html", pattern: /ng-app/i },
            { type: "html", pattern: /ng-controller/i },
            // Obfuscated patterns
            { type: "html", pattern: /\{\{\s*.*?\s*\}\}/i, weight: 0.6 }
          ]
        },
        "Angular 2+": {
          weight: 0.9,
          patterns: [
            { type: "html", pattern: /ng-version/i },
            { type: "html", pattern: /_nghost-/i },
            { type: "html", pattern: /_ngcontent-/i },
            // Obfuscated patterns
            { type: "networkRequest", pattern: /\.ngfactory\.js/i }
          ]
        }
      }
    },
    {
      name: "Vue.js",
      versions: {
        "Vue 2": {
          weight: 0.9,
          patterns: [
            { type: "jsGlobal", pattern: "Vue" },
            { type: "script", pattern: /vue(\.min)?\.js/i },
            { type: "html", pattern: /data-v-/i },
            // Obfuscated patterns
            { type: "html", pattern: /__vue__/i }
          ]
        },
        "Vue 3": {
          weight: 0.9,
          patterns: [
            { type: "jsGlobal", pattern: "Vue" },
            { type: "script", pattern: /vue@3/i },
            { type: "html", pattern: /data-v-/i }
          ]
        }
      }
    }
  ],

  // JavaScript Libraries
  javascript_libraries: [
    {
      name: "jQuery",
      weight: 0.9,
      patterns: [
        { type: "jsGlobal", pattern: "jQuery" },
        { type: "jsGlobal", pattern: "$" },
        { type: "script", pattern: /jquery(\.min)?\.js/i },
        // Obfuscated patterns
        { type: "html", pattern: /function\s*\(\s*[a-z]\s*,\s*[a-z]\s*\)\s*\{\s*return\s*new\s*[a-z]\.\s*fn\.init/i, weight: 0.7 }
      ]
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
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /js\.stripe\.com/i },
        { type: "cookie", pattern: /__stripe_mid/ },
        { type: "jsGlobal", pattern: "Stripe" },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /api\.stripe\.com/i },
        { type: "html", pattern: /data-stripe/i }
      ]
    },
    {
      name: "PayPal",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /paypal\.com\/sdk/i },
        { type: "jsGlobal", pattern: "paypal" },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /\.paypal\.com/i },
        { type: "html", pattern: /data-paypal/i }
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

  // CMS
  cms: [
    {
      name: "WordPress",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /wp-content/i },
        { type: "script", pattern: /wp-includes/i },
        { type: "html", pattern: /wp-content/i },
        { type: "meta", pattern: { name: "generator", content: /WordPress/i } },
        { type: "cookie", pattern: /wordpress_/ },
        // Obfuscated patterns
        { type: "networkRequest", pattern: /wp-json/i },
        { type: "jsGlobal", pattern: "wp" }
      ]
    },
    {
      name: "Drupal",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /drupal\.js/i },
        { type: "html", pattern: /drupal-/i },
        { type: "meta", pattern: { name: "generator", content: /Drupal/i } },
        // Obfuscated patterns
        { type: "jsGlobal", pattern: "Drupal" },
        { type: "cookie", pattern: /SESS/ }
      ]
    }
  ],

  // Frameworks
  web_frameworks: [
    {
      name: "Next.js",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /_next\//i },
        { type: "html", pattern: /data-next-page/i },
        { type: "html", pattern: /__NEXT_DATA__/i },
        // Obfuscated patterns
        { type: "jsGlobal", pattern: "__NEXT_DATA__" },
        { type: "networkRequest", pattern: /_next\/static/i }
      ]
    },
    {
      name: "Nuxt.js",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /_nuxt\//i },
        { type: "html", pattern: /data-n-head/i },
        { type: "html", pattern: /__NUXT__/i },
        // Obfuscated patterns
        { type: "jsGlobal", pattern: "__NUXT__" },
        { type: "networkRequest", pattern: /_nuxt\/static/i }
      ]
    }
  ],

  // UI Frameworks
  ui_frameworks: [
    {
      name: "Bootstrap",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /bootstrap(\.min)?\.js/i },
        { type: "css", pattern: /bootstrap(\.min)?\.css/i },
        { type: "html", pattern: /class="[^"]*navbar/i },
        { type: "html", pattern: /class="[^"]*container/i },
        { type: "html", pattern: /class="[^"]*row/i },
        { type: "html", pattern: /class="[^"]*col-/i },
        // Obfuscated patterns
        { type: "jsGlobal", pattern: "bootstrap" }
      ]
    },
    {
      name: "Tailwind CSS",
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

  // Server
  server: [
    {
      name: "Apache",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /apache/i },
        { type: "header", pattern: "x-powered-by", value: /apache/i }
      ]
    },
    {
      name: "nginx",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /nginx/i }
      ]
    },
    {
      name: "Express",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-powered-by", value: /express/i }
      ]
    }
  ],

  // Reverse Proxies
  reverse_proxies: [
    {
      name: "Cloudflare",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "cf-ray" },
        { type: "header", pattern: "server", value: /cloudflare/i },
        { type: "cookie", pattern: /__cfduid/ }
      ]
    },
    {
      name: "Envoy",
      weight: 0.9,
      patterns: [
        { type: "header", pattern: "server", value: /envoy/i },
        { type: "header", pattern: "x-envoy-upstream-service-time" }
      ]
    }
  ],

  // E-commerce
  ecommerce: [
    {
      name: "Shopify",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /cdn\.shopify\.com/i },
        { type: "html", pattern: /shopify/i },
        { type: "meta", pattern: { name: "generator", content: /Shopify/i } },
        { type: "jsGlobal", pattern: "Shopify" }
      ]
    },
    {
      name: "WooCommerce",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /woocommerce/i },
        { type: "html", pattern: /woocommerce/i },
        { type: "css", pattern: /woocommerce/i },
        { type: "jsGlobal", pattern: "woocommerce" }
      ]
    },
    {
      name: "Magento",
      weight: 0.9,
      patterns: [
        { type: "script", pattern: /magento/i },
        { type: "html", pattern: /magento/i },
        { type: "cookie", pattern: /mage-/i },
        { type: "jsGlobal", pattern: "Mage" }
      ]
    }
  ],

  // Programming Languages
  programming_languages: [
    {
      name: "PHP",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "x-powered-by", value: /php/i },
        { type: "cookie", pattern: /PHPSESSID/i }
      ]
    },
    {
      name: "Ruby",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Phusion Passenger/i },
        { type: "cookie", pattern: /_session_id/i }
      ]
    },
    {
      name: "Python",
      weight: 0.8,
      patterns: [
        { type: "header", pattern: "server", value: /Python/i },
        { type: "cookie", pattern: /django_/i },
        { type: "cookie", pattern: /flask/i }
      ]
    }
  ],

  // Databases
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
    }
  ]
};

/**
 * Detect technologies used on a website
 * @param {string} html - The HTML content of the website
 * @param {object} httpHeaders - The HTTP headers from the response
 * @returns {object} - Object containing detected technologies by category
 */
function detectTechnologies(html, httpHeaders = {}) {
  const detected = {};
  
  // Combine HTTP headers with meta http-equiv headers
  const metaHeaders = extractHeaders(html);
  const headers = { ...metaHeaders, ...httpHeaders };
  
  // Extract meta tags
  const metaTags = extractMetaTags(html);
  
  // Extract cookies (can't be done server-side, but we'll check for patterns)
  const cookies = {};
  
  // Extract script sources
  const scripts = extractScripts(html);
  
  // Extract CSS sources
  const cssLinks = extractCssLinks(html);
  
  // Extract potential JS globals from inline scripts
  const potentialJsGlobals = extractPotentialJsGlobals(html);
  
  // Extract network requests from script tags (limited capability)
  const potentialNetworkRequests = extractPotentialNetworkRequests(html);

  // Iterate over each category in the signatures
  for (const category in signatures) {
    detected[category] = []; // Initialize the category array
    const categorySignatures = signatures[category];
    
    // Iterate over each signature in the category
    for (const signature of categorySignatures) {
      let detectedVersion = null;
      let maxConfidence = 0;
      let isDetected = false;

      // Handle technologies with versions
      if (signature.versions) {
        for (const version in signature.versions) {
          const versionData = signature.versions[version];
          const versionPatterns = versionData.patterns;
          let versionConfidence = versionData.weight || 0.5;
          let versionMatches = 0;
          let totalPatterns = versionPatterns.length;

          for (const pattern of versionPatterns) {
            let match = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, cookies, potentialJsGlobals, potentialNetworkRequests);
            
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
          let match = checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, cookies, potentialJsGlobals, potentialNetworkRequests);
          
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

// Helper function to check a pattern against various content types
function checkPattern(pattern, html, scripts, cssLinks, headers, metaTags, cookies, jsGlobals, networkRequests) {
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
      // Simple check for cookie patterns in HTML (not reliable but better than nothing)
      return pattern.pattern.test(html);
      
    case "jsGlobal":
      // Check if the global variable name appears in the HTML
      return jsGlobals.includes(pattern.pattern) || 
             new RegExp(`\\b${pattern.pattern}\\b`).test(html);
      
    case "networkRequest":
      // Check for network request patterns in HTML
      return pattern.pattern.test(html) || 
             networkRequests.some(req => pattern.pattern.test(req));
      
    default:
      return false;
  }
}

// Extract script sources from HTML
function extractScripts(html) {
  const scripts = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while (match = scriptRegex.exec(html)) {
    scripts.push(match[1]);
  }
  
  return scripts;
}

// Extract CSS link sources from HTML
function extractCssLinks(html) {
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
function extractMetaTags(html) {
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
function extractHeaders(html) {
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

// Extract potential JS globals from inline scripts
function extractPotentialJsGlobals(html) {
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

// Extract potential network requests from script tags
function extractPotentialNetworkRequests(html) {
  const requests = [];
  const urlRegex = /['"]https?:\/\/([^'"]+)['"]/gi;
  let match;
  
  while (match = urlRegex.exec(html)) {
    requests.push(match[1]);
  }
  
  return requests;
}

module.exports = { signatures, detectTechnologies };