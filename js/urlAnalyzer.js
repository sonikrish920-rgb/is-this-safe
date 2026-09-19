/**
 * URL Analysis Module
 * Extracts and analyzes URLs from text for security risks
 */

export function extractUrlsFromText(text) {
  if (!text) return [];

  const urls = [];
  // Unused legacy pattern kept for reference — actual matching uses urlRegex below
  // const urlPattern = /(?:https?:\/\/|www\.|^|\s)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s]*)?)/gi;

  const urlRegex = /(?:https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s]*)?)/gi;

  let match;
  while ((match = urlRegex.exec(text)) !== null) {
    const rawUrl = match[0].trim();
    const normalized = normalizeUrl(rawUrl);
    if (normalized && !urls.some(u => u === normalized)) {
      urls.push(normalized);
    }
  }

  return urls;
}

function normalizeUrl(rawUrl) {
  if (!rawUrl) return null;

  // Remove trailing punctuation
  let url = rawUrl.replace(/[.,;:!?)\]]+$/, '');

  // Add protocol if missing
  if (!url.match(/^https?:\/\//i) && !url.match(/^www\./i)) {
    if (url.includes('.')) {
      url = 'http://' + url;
    } else {
      return null;
    }
  }

  if (url.match(/^www\./i)) {
    url = 'http://' + url;
  }

  return url;
}

export function analyzeUrl(url) {
  if (!url) {
    return {
      url: null, domain: null, isHttps: false, isShortener: false,
      isIpAddress: false, suspiciousTld: false, excessiveSubdomains: false,
      suspiciousKeywords: [], domainMismatch: null, urlRiskScore: 0, riskIndicators: []
    };
  }

  let score = 0;
  const indicators = [];

  // Parse domain and protocol
  let domain = '';
  let isHttps = false;
  let path = '';
  let port = '';

  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname;
    isHttps = urlObj.protocol === 'https:';
    path = urlObj.pathname + urlObj.search;
    port = urlObj.port;
  } catch {
    const m = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/?#:]+)/i);
    domain = m ? m[1] : '';
  }

  if (!domain) {
    return {
      url, domain: null, isHttps, isShortener: false, isIpAddress: false,
      suspiciousTld: false, excessiveSubdomains: false, suspiciousKeywords: [],
      domainMismatch: null, urlRiskScore: 0, riskIndicators: []
    };
  }

  const domainLower = domain.toLowerCase();

  // ── IP address ───────────────────────────────
  const isIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain);
  if (isIpAddress) {
    score += 10;
    indicators.push('IP address URL');
  }

  // ── URL shorteners ───────────────────────────
  const shorteners = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'is.gd', 't.co', 'ow.ly',
    'short.link', 'shorten.link', 'snip.ly', 'rb.gy', 'cutt.ly',
    'shorte.st', 'adf.ly', 'tiny.cc', 'rebrand.ly', 'lnkd.in'
  ];
  const isShortener = shorteners.some(s => domainLower === s || domainLower.endsWith('.' + s));
  if (isShortener) {
    // Score raised to 15 so a bare shortener URL alone reaches SUSPICIOUS threshold.
    // Legitimate services (newsletters, social media) that genuinely use shorteners
    // will typically also have message text that triggers benign-signal reductions.
    score += 15;
    indicators.push('URL shortener');
  }

  // ── Suspicious TLDs ──────────────────────────
  const suspiciousTlds = [
    'xyz', 'top', 'club', 'info', 'online', 'click', 'loan', 'icu',
    'cf', 'ga', 'ml', 'tk', 'download', 'tech', 'win', 'pw', 'cc',
    'rest', 'live', 'site', 'space', 'fun', 'monster', 'vip',
    'example'  // reserved test TLD
  ];
  const tldMatch = domainLower.match(/\.([a-z]{2,})$/);
  const tld = tldMatch ? tldMatch[1] : '';
  const suspiciousTld = suspiciousTlds.includes(tld);
  if (suspiciousTld) {
    score += 7;
    indicators.push('Suspicious TLD');
  }

  // ── Subdomain depth ──────────────────────────
  const parts = domainLower.split('.');
  const excessiveSubdomains = parts.length > 3;
  if (excessiveSubdomains) {
    score += 4;
    indicators.push('Excessive subdomains');
  }

  // ── Generic / test placeholder domains ───────
  // Matches both when the word is the TLD (random-domain.example)
  // and when it appears as a component of the domain name (suspicious-example.com)
  if (
    suspiciousTld && tld === 'example' ||
    /(?:^|[-\.])(?:example|test|random|placeholder|dummy|fake)(?:[-\.]|$)/.test(domainLower)
  ) {
    score += 5;
    indicators.push('Generic/test domain');
  }

  // ── Deceptive brand keywords in domain ───────
  // Only penalise when the real brand's legitimate domain is absent
  const brandKeywords = [
    { keyword: 'verify', weight: 3 },
    { keyword: 'confirm', weight: 3 },
    { keyword: 'secure', weight: 3 },
    { keyword: 'login', weight: 3 },
    { keyword: 'update', weight: 2 },
    { keyword: 'validate', weight: 3 },
    { keyword: 'account', weight: 2 },
    { keyword: 'bank', weight: 3 },
    { keyword: 'paypal', weight: 4 },
    { keyword: 'google', weight: 4 },
    { keyword: 'amazon', weight: 4 },
    { keyword: 'apple', weight: 4 },
    { keyword: 'microsoft', weight: 4 },
    { keyword: 'netflix', weight: 4 },
    { keyword: 'restore', weight: 3 },
    { keyword: 'billing', weight: 3 },
    { keyword: 'payment', weight: 3 },
    { keyword: 'refund', weight: 3 },
  ];
  const foundKeywords = brandKeywords.filter(b => domainLower.includes(b.keyword));
  if (foundKeywords.length > 0) {
    const isOtherwiseSuspicious = isShortener || suspiciousTld || isIpAddress || excessiveSubdomains;
    // Do not penalise if the domain IS the known brand's own domain
    // e.g. amazon.com, google.com, paypal.com, netflix.com
    const legitBrandDomains = [
      'amazon.com', 'amazon.in', 'google.com', 'paypal.com', 'microsoft.com',
      'apple.com', 'netflix.com', 'facebook.com', 'accounts.google.com',
      'outlook.com', 'icloud.com', 'hdfcbank.com', 'hdfc.com'
    ];
    const isOwnBrandDomain = legitBrandDomains.some(d => domainLower === d || domainLower.endsWith('.' + d));
    if (!isOwnBrandDomain && (isOtherwiseSuspicious || parts.length > 2 || domainLower.includes('-'))) {
      const kwScore = foundKeywords.reduce((s, b) => s + b.weight, 0);
      score += Math.min(8, kwScore);
      indicators.push(`Deceptive keyword in domain: ${foundKeywords.map(b => b.keyword).join(', ')}`);
    }
  }

  // ── HTTP (not HTTPS) ─────────────────────────
  // Only add a small penalty; HTTPS alone does NOT mean safe
  if (!isHttps && !isIpAddress) {
    score += 3;
    indicators.push('HTTP instead of HTTPS');
  }

  // ── Non-standard port ─────────────────────────
  if (port && !['80', '443', '8080', '8443', ''].includes(port)) {
    score += 4;
    indicators.push('Unusual port number');
  }

  // ── Typosquatting ─────────────────────────────
  const typoPatterns = {
    'google': ['g00gle', 'goggle', 'gogle', 'gooqle', 'goog1e', 'gooogle'],
    'amazon': ['amaz0n', 'amazan', 'amzon', 'amazn', 'amaz-on'],
    'paypal': ['paypa1', 'paypai', 'paupal', 'paypall', 'paypa-l'],
    'microsoft': ['micr0soft', 'microsft', 'micros0ft', 'micro-soft'],
    'facebook': ['faceb00k', 'facebk', 'facbok', 'face-book'],
    'apple': ['app1e', 'aple', 'appie', 'appl3'],
    'netflix': ['netfl1x', 'netfIix', 'net-flix', 'neflix'],
  };
  for (const [real, fakes] of Object.entries(typoPatterns)) {
    if (fakes.some(fake => domainLower.includes(fake))) {
      score += 10;
      indicators.push(`Possible typosquatting of ${real}`);
    }
  }

  // ── Random/long domain name ───────────────────
  // Strip known TLD and check for randomness
  const domainWithoutTld = parts.slice(0, -1).join('');
  if (/[a-z0-9]{18,}/i.test(domainWithoutTld)) {
    score += 4;
    indicators.push('Unusually long domain name');
  }

  // ── Suspicious path / query indicators ───────
  if (/(?:verify|confirm|update|secure|login|signin|account|validate|restore|reset)/.test(path.toLowerCase())) {
    // Only add a small penalty for path keywords — path alone is not strong evidence
    score += 2;
    indicators.push('Suspicious path keywords');
  }

  // ── Domain structure: brand name buried in subdomain ──
  // e.g. hdfc.suspicious-login.com → the real brand is in a subdomain
  const knownBrands = ['hdfc', 'sbi', 'icici', 'axis', 'google', 'amazon', 'paypal', 'microsoft', 'apple', 'netflix', 'facebook'];
  if (parts.length >= 3) {
    const subdomain = parts.slice(0, parts.length - 2).join('.');
    const registeredDomain = parts.slice(parts.length - 2).join('.');
    for (const brand of knownBrands) {
      if (subdomain.includes(brand) && !registeredDomain.includes(brand)) {
        score += 8;
        indicators.push(`Brand name in subdomain (deceptive): ${brand}`);
        break;
      }
    }
  }

  const urlRiskScore = Math.min(20, score);

  return {
    url, domain, isHttps, isShortener, isIpAddress,
    suspiciousTld, excessiveSubdomains,
    suspiciousKeywords: foundKeywords.map(b => b.keyword),
    domainMismatch: null,
    urlRiskScore,
    riskIndicators: indicators
  };
}

export function checkDomainMismatch(domain, messageText) {
  if (!domain || !messageText) return false;

  const organizations = [
    { name: 'HDFC', domains: ['hdfc.com', 'hdfcbank.com'], keywords: ['hdfc'] },
    { name: 'SBI', domains: ['sbi.co.in', 'onlinesbi.com'], keywords: ['sbi', 'state bank'] },
    { name: 'ICICI', domains: ['icicibank.com'], keywords: ['icici'] },
    { name: 'Axis', domains: ['axisbank.com'], keywords: ['axis bank'] },
    { name: 'Google', domains: ['google.com', 'accounts.google.com'], keywords: ['google', 'gmail'] },
    { name: 'Amazon', domains: ['amazon.in', 'amazon.com'], keywords: ['amazon'] },
    { name: 'PayPal', domains: ['paypal.com'], keywords: ['paypal'] },
    { name: 'Microsoft', domains: ['microsoft.com', 'outlook.com'], keywords: ['microsoft', 'outlook'] },
    { name: 'Apple', domains: ['apple.com', 'icloud.com'], keywords: ['apple', 'icloud', 'apple id'] },
    { name: 'Netflix', domains: ['netflix.com'], keywords: ['netflix'] },
  ];

  const domainLower = domain.toLowerCase();
  const textLower = messageText.toLowerCase();

  for (const org of organizations) {
    const mentioned = textLower.includes(org.name.toLowerCase()) ||
      org.keywords.some(kw => textLower.includes(kw));
    if (mentioned) {
      const matches = org.domains.some(d => {
        const registeredPart = d.split('.')[0];
        return domainLower.includes(registeredPart);
      });
      if (!matches) return true;
    }
  }

  return false;
}
