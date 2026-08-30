/**
 * Context-Aware Security Detectors
 * Analyzes message text for security risks with proper context
 */

export function detectUrgency(text) {
  const urgencyPatterns = [
    /(?:act|verify|click|respond|update|confirm|submit|authorize|activate|claim)\s+(?:now|immediately|today|asap|urgent|within \d+ hours|before \d+)/i,
    /urgent|immediately|right now|at once|within 24 hours|last chance|final notice|expires? (?:today|this week|in \d+ hours)/i,
    /account (?:will be|has been|is about to be) (?:blocked|suspended|closed|deactivated)/i,
    /(?:must|should|need to) (?:act|verify|click|respond) (?:now|immediately|today|asap)/i,
    /(?:do not|don't|never) delay|rush|hurry|don't wait/i,
    /(?:today|this week|before \d+|within \d+ hours)\s+(?:only|or|final|last)/i,
    /\b(?:claim|pay|send|transfer|act)\s+(?:today|this week|immediately|now|urgently|asap)/i
  ];
  
  for (const pattern of urgencyPatterns) {
    if (pattern.test(text)) {
      return {
        triggered: true,
        confidence: 0.85,
        matches: [text.match(pattern)[0]]
      };
    }
  }
  
  return { triggered: false, confidence: 0, matches: [] };
}

export function detectCredentialRequest(text) {
  // Check if merely mentioning credentials with safety advice first
  const mentionPatterns = [
    /(?:don't|do not|never|ensure)\s+(?:share|give|provide|enter|send)\s+(?:your\s+)?(?:password|otp|pin|credentials|login details)/i,
    /(?:password|otp|pin|cvv|verification code|security code|credentials)\s+(?:is|are)\s+(?:confidential|secret|protected|for your eyes only|never shared)/i,
    /we (?:will never|would never|don't) (?:ask|request)\s+(?:for\s+)?(?:your\s+)?(?:password|otp|credentials|personal details)/i
  ];
  
  for (const pattern of mentionPatterns) {
    if (pattern.test(text)) {
      return {
        triggered: false,
        confidence: 0,
        matches: [],
        isRequest: false,
        isSafetyAdvice: true
      };
    }
  }
  
  // Check if asking for credentials
  const requestPatterns = [
    /(?:send|provide|share|sharing|enter|confirm|verify|update|reset|change)\s+(?:your\s+)?(?:password|otp|pin|cvv|verification code|security code|login|credentials|access code)/i,
    /(?:enter|confirm|verify|provide)\s+(?:your\s+)?(?:otp|one.time password|password|pin|security code|login details)/i,
    /(?:click|link|url)\s+(?:and\s+)?(?:enter|confirm|verify)\s+(?:your\s+)?(?:otp|password|login|credentials)/i,
    /(?:verify your otp|enter your otp|share your otp|send your otp|provide your otp|sharing your otp|verify by entering otp|confirm otp)/i,
    /(?:we need|we require|we ask for|please provide|please share)\s+(?:your\s+)?(?:password|otp|credentials|login details|access code|verification code)/i
  ];
  
  for (const pattern of requestPatterns) {
    if (pattern.test(text)) {
      return {
        triggered: true,
        confidence: 0.90,
        matches: [text.match(pattern)[0]],
        isRequest: true
      };
    }
  }
  
  // Just mentioning OTP/password
  const simplePattern = /(?:otp|password|pin|cvv|verification code|security code|credentials|login)/i;
  if (simplePattern.test(text)) {
    return {
      triggered: false,
      confidence: 0,
      matches: [text.match(simplePattern)[0]],
      isRequest: false,
      isMention: true
    };
  }
  
  return { triggered: false, confidence: 0, matches: [], isRequest: false };
}

export function detectFinancialRequest(text) {
  const requestPatterns = [
    /(?:send|transfer|pay|deposit|wire|refund)\s+(?:₹|\$|£|€|rs|rupees?|dollars?|pounds?)\s*\d+|(?:send|transfer|pay|deposit|wire)\s+(?:money|amount|fee|payment)/i,
    /(?:bank|upi|paytm|googlepay|phonepay|account)\s+(?:details|number|info|credentials)/i,
    /pay(?:ment)?\s+(?:fee|taxes?|charges?|processing fee|delivery fee|refund fee)/i,
    /(?:claim|collect|receive)\s+(?:reward|prize|refund|bonus|cashback)\s+(?:by paying|after paying|by sending)\s+(?:fee|amount|money)/i,
    /(?:processing fee|service fee|verification fee|security fee|clearance fee|tax fee)\s+(?:required|needed|to be paid)/i
  ];
  
  for (const pattern of requestPatterns) {
    if (pattern.test(text)) {
      return {
        triggered: true,
        confidence: 0.88,
        matches: [text.match(pattern)[0]],
        isRequest: true
      };
    }
  }
  
  return { triggered: false, confidence: 0, matches: [], isRequest: false };
}

export function detectPrizeScam(text) {
  const prizePatterns = [
    /congratulations?|you.{0,10}(?:won|selected|chosen|qualified|eligible|won)|lucky winner|exclusive (?:offer|selected|recipient)|claim your (?:prize|reward|bonus)/i,
    /(?:prize|reward|bonus|cashback|refund|money)\s+(?:waiting|pending|claimed|won|selected|for you)/i,
    /(?:you have|you.ve|you're)\s+(?:won|selected|chosen|qualified|eligible)\s+(?:₹|\$|prize|reward)/i
  ];
  
  for (const pattern of prizePatterns) {
    if (pattern.test(text)) {
      return {
        triggered: true,
        confidence: 0.80,
        matches: [text.match(pattern)[0]]
      };
    }
  }
  
  return { triggered: false, confidence: 0, matches: [] };
}

export function detectImpersonation(text) {
  const orgs = [
    { name: 'HDFC', patterns: /\bhdfc\b/i },
    { name: 'SBI', patterns: /\bsbi\b|state bank/i },
    { name: 'RBI', patterns: /\brbi\b|reserve bank/i },
    { name: 'Google', patterns: /\bgoogle\b|gmail/i },
    { name: 'Amazon', patterns: /\bamazon\b/i },
    { name: 'PayPal', patterns: /\bpaypal\b/i },
    { name: 'Microsoft', patterns: /\bmicrosoft\b|outlook/i },
    { name: 'Government', patterns: /\bgovernment\b|income tax|customs|police|cbi|cid/i },
    { name: 'Telecom', patterns: /\bairtel\b|\bvodafone\b|\bjio\b|\bbsnl\b/i },
    { name: 'Courier', patterns: /\bdhl\b|\bfedex\b|\bups\b|courier/i }
  ];
  
  for (const org of orgs) {
    if (org.patterns.test(text)) {
      return {
        triggered: true,
        confidence: 0.75,
        matches: [org.name],
        organization: org.name
      };
    }
  }
  
  return { triggered: false, confidence: 0, matches: [] };
}

export function detectSuspiciousDownload(text) {
  const downloadPatterns = [
    /(?:download|install|run|execute|open)\s+(?:this\s+)?(?:app|apk|file|software|update|application|exe|dmg)/i,
    /download\s+(?:your\s+)?(?:refund|prize|documents|files|statement|password reset link)/i,
    /(?:disable|turn off|disable|uninstall)\s+(?:play protect|antivirus|security|defender|protection)/i,
    /(?:apk|executable|application)\s+(?:from|via|at)\s+(?:this link|this url|below|here)/i,
    /(?:click.*download|download.*click|install.*link|link.*install)/i
  ];
  
  for (const pattern of downloadPatterns) {
    if (pattern.test(text)) {
      return {
        triggered: true,
        confidence: 0.85,
        matches: [text.match(pattern)[0]]
      };
    }
  }
  
  return { triggered: false, confidence: 0, matches: [] };
}

export function detectAccountThreat(text) {
  const threatPatterns = [
    /account (?:will be|has been|is about to be) (?:suspended|blocked|closed|deactivated|terminated|locked)/i,
    /(?:sim|account|profile|access)\s+(?:will be|has been|is)\s+(?:blocked|suspended|closed|deactivated)/i,
    /(?:kyc|verification|authentication)\s+(?:failed|pending|incomplete|required)/i,
    /(?:legal|court|police) (?:action|case|complaint|notice|warrant)/i,
    /(?:your account|your sim|your access)\s+(?:is about to be|will be|has been)\s+(?:suspended|blocked)/i
  ];
  
  for (const pattern of threatPatterns) {
    if (pattern.test(text)) {
      return {
        triggered: true,
        confidence: 0.85,
        matches: [text.match(pattern)[0]]
      };
    }
  }
  
  return { triggered: false, confidence: 0, matches: [] };
}

export function detectSuspiciousUrl(urlAnalysis) {
  if (!urlAnalysis || !urlAnalysis.riskIndicators || urlAnalysis.riskIndicators.length === 0) {
    return { triggered: false, confidence: 0, matches: [] };
  }
  
  return {
    triggered: urlAnalysis.urlRiskScore > 0,
    confidence: Math.min(0.95, 0.5 + (urlAnalysis.urlRiskScore / 15) * 0.45),
    matches: urlAnalysis.riskIndicators,
    urlRiskScore: urlAnalysis.urlRiskScore
  };
}

export function detectBenignSignals(text) {
  const signals = [];
  
  // Safety advice that reduces risk
  const safetyPatterns = [
    /(?:do not|don't|never|do not ever)\s+(?:share|click|open|enter|provide|send)\s+(?:your\s+)?(?:password|otp|pin|credentials|personal data|sensitive information)/i,
    /(?:for your security|for security reasons|to protect you|for your protection)\s+(?:we|our|your|the)\s+(?:bank|company)\s+(?:will never|would never|doesn't|don't)\s+(?:ask|request)\s+(?:for|your)/i,
    /(?:use|contact|call|reach out|call us)\s+(?:official|authorized|legitimate|verified)\s+(?:number|website|channel|app|link)/i,
    /verify\s+(?:with|through|using)\s+(?:official|authorized|legitimate)\s+(?:channel|website|app|number)/i,
    /(?:legitimate|official|authorized)\s+(?:website|channel|app|source)/i
  ];
  
  for (const pattern of safetyPatterns) {
    if (pattern.test(text)) {
      signals.push('safety advice');
    }
  }
  
  // Legitimate notifications
  const legitPatterns = [
    /(?:thank|thanks|thankyou)\s+(?:for|to)\s+(?:banking|using|choosing|your)\s+(?:us|with us|our service)/i,
    /your (?:order|transaction|payment|transfer|recharge)\s+(?:has been|was)\s+(?:completed|successful|confirmed|processed)/i,
    /(?:order|transaction|payment|delivery)\s+(?:status|update|confirmation)/i,
    /(?:validity|validity extended|recharge|activation|bonus)\s+(?:until|till|till|until|extended)/i,
    /shipped|on the way|in delivery|out for delivery/i
  ];
  
  for (const pattern of legitPatterns) {
    if (pattern.test(text)) {
      signals.push('legitimate notification');
    }
  }
  
  return signals;
}

export function hasNegation(text, keyword) {
  const window = 50;
  const index = text.toLowerCase().indexOf(keyword.toLowerCase());
  if (index === -1) return false;
  
  const start = Math.max(0, index - window);
  const contextBefore = text.substring(start, index);
  
  const negationPatterns = [/\b(?:don't|do not|never|not)\s+\w*$/i];
  
  return negationPatterns.some(p => p.test(contextBefore));
}
