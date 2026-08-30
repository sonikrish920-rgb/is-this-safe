/**
 * URL Analysis Module
 * Extracts and analyzes URLs from text for security risks
 */

export function extractUrlsFromText(text) {
  if (!text) return [];
  
  const urls = [];
  
  // Pattern for URLs: http(s)://domain, www.domain, or domain.tld
  const urlPattern = /(?:https?:\/\/|www\.|^|\s)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s]*)?)/gi;
  
  let match;
  const urlRegex = /(?:https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s]*)?)/gi;
  
  while ((match = urlRegex.exec(text)) !== null) {
    const rawUrl = match[0].trim();
    const normalized = normalizeUrl(rawUrl);
    if (normalized && !urls.some(u => u.url === normalized)) {
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
      url: null,
      domain: null,
      isHttps: false,
      isShortener: false,
      isIpAddress: false,
      suspiciousTld: false,
      excessiveSubdomains: false,
      suspiciousKeywords: [],
      domainMismatch: null,
      urlRiskScore: 0,
      riskIndicators: []
    };
  }
  
  let score = 0;
  const indicators = [];
  
  // Extract domain and protocol
  let domain = '';
  let isHttps = false;
  
  try {
    const urlObj = new URL(url);
    domain = urlObj.hostname;
    isHttps = urlObj.protocol === 'https:';
  } catch (e) {
    // Try to extract domain manually
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/?#]+)/i);
    domain = match ? match[1] : '';
  }
  
  if (!domain) {
    return {
      url,
      domain: null,
      isHttps,
      isShortener: false,
      isIpAddress: false,
      suspiciousTld: false,
      excessiveSubdomains: false,
      suspiciousKeywords: [],
      domainMismatch: null,
      urlRiskScore: 0,
      riskIndicators: []
    };
  }
  
  // Check if IP address
  const isIpAddress = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain);
  if (isIpAddress) {
    score += 8;
    indicators.push('IP address URL');
  }
  
  // Check for URL shorteners
  const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'is.gd', 't.co', 'ow.ly', 'short.link', 'shorten.link', 'snip.ly'];
  const isShortener = shorteners.some(s => domain.toLowerCase().includes(s));
  if (isShortener) {
    score += 5;
    indicators.push('URL shortener');
  }
  
  // Check for suspicious TLDs
  const suspiciousTlds = ['xyz', 'top', 'club', 'info', 'online', 'click', 'loan', 'icu', 'cf', 'ga', 'ml', 'tk', 'download', 'tech', 'win'];
  const suspiciousTld = suspiciousTlds.some(tld => domain.toLowerCase().endsWith('.' + tld));
  if (suspiciousTld) {
    score += 6;
    indicators.push('Suspicious TLD');
  }
  
  // Check for excessive subdomains (more than 3 levels)
  const parts = domain.split('.');
  const excessiveSubdomains = parts.length > 3;
  if (excessiveSubdomains) {
    score += 3;
    indicators.push('Excessive subdomains');
  }
  
  // Check for suspicious/random domains (especially with "example" or common patterns)
  if (domain.toLowerCase().includes('example') || domain.toLowerCase().includes('test') || domain.toLowerCase().includes('random')) {
    score += 4;
    indicators.push('Generic/test domain');
  }
  
  // Check for suspicious keywords in domain
  const suspiciousKeywords = ['verify', 'confirm', 'account', 'secure', 'login', 'update', 'validate', 'bank', 'paypal', 'google', 'amazon'];
  const foundKeywords = suspiciousKeywords.filter(kw => domain.toLowerCase().includes(kw));
  if (foundKeywords.length > 0) {
    // Only penalize if combined with other suspicious factors OR if domain is unusual
    if (isShortener || suspiciousTld || isIpAddress || excessiveSubdomains) {
      score += foundKeywords.length * 2;
      indicators.push(`Suspicious keyword: ${foundKeywords.join(', ')}`);
    }
  }
  
  // Check for HTTP instead of HTTPS
  if (!isHttps && !isIpAddress) {
    score += 2;
    indicators.push('HTTP instead of HTTPS');
  }
  
  // Check for typosquatting (lookalike domains)
  const typoPatterns = {
    'google': ['g00gle', 'goggle', 'gogle', 'gooqle', 'goog1e'],
    'amazon': ['amaz0n', 'amazan', 'amzon', 'amazn'],
    'paypal': ['paypa1', 'paypai', 'paypa1', 'paupal'],
    'microsoft': ['micr0soft', 'microsft', 'micros0ft'],
    'facebook': ['faceb00k', 'facebk', 'facbok']
  };
  
  for (const [real, fakes] of Object.entries(typoPatterns)) {
    if (fakes.some(fake => domain.toLowerCase().includes(fake))) {
      score += 8;
      indicators.push(`Possible typosquatting of ${real}`);
    }
  }
  
  // Random/nonsense domain check (many random characters, or very long)
  const randomPattern = /[a-z0-9]{15,}/i;
  if (randomPattern.test(domain.replace(/\./g, ''))) {
    score += 4;
    indicators.push('Random domain name');
  }
  
  // Unfamiliar/suspicious domain patterns (generic .com with suspicious structure)
  if (!suspiciousTld && domain.toLowerCase().endsWith('.com')) {
    // Check if it looks like a randomly generated domain or has suspicious structure
    const domainName = domain.substring(0, domain.length - 4);
    if (domainName.length > 12 || /^[a-z0-9\-]+$/.test(domainName) && domainName.split('-').length > 2) {
      score += 2;
      indicators.push('Unusual domain structure');
    }
  }
  
  const urlRiskScore = Math.min(15, score);
  
  return {
    url,
    domain,
    isHttps,
    isShortener,
    isIpAddress,
    suspiciousTld,
    excessiveSubdomains,
    suspiciousKeywords: foundKeywords,
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
    { name: 'Axis', domains: ['axisbank.com'], keywords: ['axis'] },
    { name: 'Google', domains: ['google.com', 'accounts.google.com'], keywords: ['google', 'gmail'] },
    { name: 'Amazon', domains: ['amazon.in', 'amazon.com'], keywords: ['amazon'] },
    { name: 'PayPal', domains: ['paypal.com'], keywords: ['paypal'] },
    { name: 'Microsoft', domains: ['microsoft.com', 'outlook.com'], keywords: ['microsoft', 'outlook'] }
  ];
  
  for (const org of organizations) {
    if (messageText.toLowerCase().includes(org.name.toLowerCase()) || org.keywords.some(kw => messageText.toLowerCase().includes(kw))) {
      // Check if domain matches
      const matches = org.domains.some(d => domain.toLowerCase().includes(d.split('.')[0]));
      if (!matches) {
        return true;
      }
    }
  }
  
  return false;
}
