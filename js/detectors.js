/**
 * Context-Aware Security Detectors
 * Analyzes message text for security risks with proper context
 */

// ─────────────────────────────────────────────
// URGENCY / PRESSURE
// ─────────────────────────────────────────────
export function detectUrgency(text) {
  const patterns = [
    // Explicit time pressure
    /\b(?:act|verify|click|respond|update|confirm|submit|authorize|activate|claim|pay|call|contact)\s+(?:now|immediately|today|asap|urgently|at once|right now)\b/i,
    /\burgent(?:ly)?\b|\bimmediately\b|\bright now\b|\bat once\b/i,
    /\bwithin\s+\d+\s*(?:hour|hr|minute|min|day)\b/i,
    /\blast chance\b|\bfinal notice\b|\bfinal warning\b|\bexpires?\s+(?:today|soon|in \d+)\b/i,
    // Account suspension / service cutoff threats (also covered in threat, but drives urgency score)
    /\bwill be\s+(?:blocked|suspended|closed|deactivated|terminated|disconnected|cancelled|cut off)\b/i,
    /\b(?:is|are)\s+(?:about to be|going to be)\s+(?:blocked|suspended|closed|deactivated)\b/i,
    // Payment deadline pressure
    /\b(?:overdue|past due|outstanding|unpaid)\s+(?:balance|payment|invoice|amount|fee|bill)\b/i,
    /\b(?:avoid|prevent)\s+(?:service interruption|disconnection|suspension|cancellation|late fee)\b/i,
    // "Don't delay" style
    /\bdon.{0,3}t\s+(?:wait|delay|ignore)\b/i,
    /\bhurry\b|\brush\b/i,
    // Before deadline phrasing
    /\bbefore\s+(?:your|it|the|this)\b.{0,30}(?:expires?|ends?|closes?|deadline|due date)/i,
    /\bonly\s+\d+\s*(?:hour|hr|day|minute|min)\s+(?:left|remaining)\b/i,
  ];

  for (const pattern of patterns) {
    if (pattern.test(text)) {
      return { triggered: true, confidence: 0.85, matches: [text.match(pattern)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// CREDENTIAL / SENSITIVE-DATA REQUESTS
// Includes passwords, OTP, PIN, CVV, card, SSN,
// identity numbers, bank account details
// ─────────────────────────────────────────────
export function detectCredentialRequest(text) {
  // Explicit safety advice → not a request
  const safetyPatterns = [
    /(?:don.t|do not|never|ensure)\s+(?:share|give|provide|enter|send|disclose)\s+(?:your\s+)?(?:password|otp|pin|credentials|login details|card details|cvv|ssn)/i,
    /(?:password|otp|pin|cvv|verification code|security code|credentials)\s+(?:is|are)\s+(?:confidential|secret|protected|never shared)/i,
    /we\s+(?:will never|would never|don.t)\s+(?:ask|request)\s+(?:for\s+)?(?:your\s+)?(?:password|otp|credentials|card|cvv|ssn|personal details)/i,
    // Self-service password reset — the email guides the user through their own
    // requested reset; it is not asking the user to *surrender* their password.
    /\byou\s+(?:requested|initiated|asked\s+for)\s+(?:a\s+)?(?:password\s+reset|reset|account\s+(?:verification|recovery))\b/i,
  ];
  for (const p of safetyPatterns) {
    if (p.test(text)) {
      return { triggered: false, confidence: 0, matches: [], isRequest: false, isSafetyAdvice: true };
    }
  }

  // Direct requests for credentials / sensitive data
  // Article group (?:(?:your|the|a|an)\s+)? makes 'your OTP', 'the OTP', bare 'OTP' all match.
  const requestPatterns = [
    // OTP / verification codes — any article or none
    /(?:send|provide|share|sharing|enter|confirm|verify|submit)\s+(?:(?:your|the|a|an)\s+)?(?:otp|one.time\s*(?:password|code)|verification\s+code|security\s+code|access\s+code)\b/i,
    /(?:verify\s+(?:your|the)\s+otp|enter\s+(?:your|the)\s+otp|share\s+(?:your|the)\s+otp|provide\s+(?:your|the)\s+otp|confirm\s+(?:your|the\s+)?\s*otp)\b/i,
    // Third-party OTP/code relay: "send/forward the OTP/code to [agent/support/number]"
    /(?:send|forward|give|share|relay)\s+(?:(?:the|your|a|an)\s+)?(?:otp|code|pin|verification\s+code|security\s+code)\s+.{0,40}(?:to\s+(?:our|the|my|a)?\s*(?:agent|support|team|representative|executive|officer|number|us))/i,
    // Passwords / login — any article or none
    /(?:send|provide|share|enter|confirm|verify|update|reset)\s+(?:(?:your|the)\s+)?(?:password|login\s+(?:details|credentials)|credentials|username\s+and\s+password)\b/i,
    // Card / financial credentials
    /(?:confirm|provide|share|send|enter|verify)\s+(?:(?:your|the)\s+)?(?:card\s+(?:number|details)|cvv|credit\s+card|debit\s+card|expiry|expiration)\b/i,
    /\bcard\s+number\b.{0,40}(?:cvv|expiry|verify|confirm)/i,
    // PIN — any article or none
    /(?:provide|share|enter|send|confirm)\s+(?:(?:your|the)\s+)?(?:pin|atm\s*pin|4.digit\s+pin)\b/i,
    // Banking details in a request context
    /(?:provide|share|send|enter|submit|give)\s+(?:(?:your|the)\s+)?(?:bank\s+(?:account|details|information)|account\s+(?:number|details)|routing\s+number|ifsc|sort\s+code)\b/i,
    // National identity numbers
    /(?:provide|share|enter|send|confirm|verify)\s+(?:(?:your|the)\s+)?(?:ssn|social\s+security|aadhaar|aadhar|passport\s+number|national\s+id|date\s+of\s+birth|dob)\b/i,
    // Generic "verify your/the identity" in a context that implies information handover
    /(?:verify|confirm|validate)\s+(?:(?:your|the)\s+)?(?:identity|account|details|information)\s+(?:by\s+(?:entering|providing|sharing|sending)|to\s+(?:proceed|continue|unlock|restore|access))\b/i,
    // "We need / we require" patterns
    /(?:we\s+(?:need|require|ask\s+for)|please\s+(?:provide|share))\s+(?:(?:your|the)\s+)?(?:password|otp|cvv|card|ssn|account\s+details|credentials|personal\s+details|verification\s+code)\b/i,
  ];
  for (const p of requestPatterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.90, matches: [text.match(p)[0]], isRequest: true };
    }
  }

  // Just mentioning sensitive tokens without requesting them
  const mentionPattern = /\b(?:otp|password|pin|cvv|verification\s+code|security\s+code|credentials|login)\b/i;
  if (mentionPattern.test(text)) {
    return { triggered: false, confidence: 0, matches: [text.match(mentionPattern)[0]], isRequest: false, isMention: true };
  }

  return { triggered: false, confidence: 0, matches: [], isRequest: false };
}

// ─────────────────────────────────────────────
// PERSONAL INFORMATION REQUESTS
// Requests for identity details that go beyond
// credentials: name, address, DOB, SSN, national
// ID, phone number – combined with a suspicious context
// ─────────────────────────────────────────────
export function detectPersonalInfoRequest(text) {
  const patterns = [
    // Explicit multi-field PII harvesting
    /(?:full\s+name|date\s+of\s+birth|d\.?o\.?b\.?|home\s+address|residential\s+address)\s*(?:and|,|\+)?\s*(?:full\s+name|date\s+of\s+birth|d\.?o\.?b\.?|address|phone|contact)/i,
    /reply\s+with\s+(?:your\s+)?(?:full\s+name|name|address|dob|phone|contact\s+number|national\s+id|passport)/i,
    /(?:provide|share|send|submit|give\s+us)\s+(?:your\s+)?(?:full\s+name|home\s+address|date\s+of\s+birth|national\s+id|passport\s+number|phone\s+number)/i,
    // SSN / national ID request (any verb form including gerund)
    /(?:enter(?:ing)?|provide|provid(?:e|ing)|share|sharing|send(?:ing)?|confirm(?:ing)?|verify|verif(?:y|ying)|submitting?)\s+(?:your\s+)?(?:ssn|social\s+security\s+(?:number)?|aadhaar\s+(?:number)?|aadhar\s+(?:number)?|national\s+(?:id|identity)\s+(?:number)?|pan\s+(?:card|number))/i,
    // "Verify / confirm your details" implying PII
    /(?:verify|confirm|update|submit)\s+(?:your\s+)?(?:personal\s+(?:details|information|data)|kyc\s+details|identification\s+details)/i,
    // "To claim" or "to receive" requiring personal info
    /(?:to\s+(?:claim|collect|receive|process|release))\s+.{0,30}(?:provide|share|send|submit|enter)\s+(?:your\s+)?(?:name|address|id|details|information)/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.85, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// FINANCIAL REQUESTS
// Payment requests, fees, transfer demands
// ─────────────────────────────────────────────
export function detectFinancialRequest(text) {
  const patterns = [
    // Explicit send/transfer money
    /(?:send|transfer|pay|deposit|wire)\s+(?:₹|\$|£|€|rs\.?|rupees?|dollars?|pounds?|inr|usd)\s*[\d,.]+/i,
    /(?:send|transfer|pay|deposit|wire)\s+(?:money|amount|fee|payment|funds)\b/i,
    // Fee requests (delivery, processing, tax etc.)
    /\b(?:delivery|processing|service|verification|clearance|customs?|handling|activation|registration|admin)\s+fee\b.{0,40}(?:pay|required|needed|due|outstanding)/i,
    /(?:pay|settle|clear)\s+.{0,20}\bfee\b/i,
    // "Update payment / billing information" — also matches short form 'info'
    /(?:update|confirm|verify|re-enter|re-?submit)\s+(?:your\s+)?(?:payment\s+(?:information|details?|method|info)|billing\s+(?:information|details?|info)|credit\s+card\s+(?:information|details?|info))/i,
    // "Payment / billing failed — update / re-enter" (subscription renewal phishing)
    /\b(?:payment|billing|subscription)\s+(?:failed|declined|not\s+processed|unsuccessful|has\s+expired|expired)\b.{0,80}(?:update|re-?enter|confirm|verify|restore|continue|renew)/i,
    // UPI / wallet specific
    /(?:upi|paytm|googlepay|phonepay|gpay|neft|rtgs)\s+(?:transfer|payment|transaction|details|number|id)/i,
    /(?:bank|account)\s+(?:details|number|credentials)\s+(?:to|for)\s+(?:receive|process|transfer|credit|refund)/i,
    // Claim prize/refund by paying
    /(?:claim|collect|receive)\s+.{0,30}(?:by\s+paying|after\s+paying|by\s+sending|pay\s+a|send\s+a)\s+.{0,20}\b(?:fee|amount|money|payment)\b/i,
    // Cryptocurrency / investment
    /(?:send|transfer|deposit|invest)\s+.{0,20}(?:bitcoin|btc|ethereum|eth|usdt|crypto|cryptocurrency)/i,
    /(?:invest|deposit)\s+.{0,20}(?:earn|returns?|profits?|guaranteed)/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.88, matches: [text.match(p)[0]], isRequest: true };
    }
  }

  return { triggered: false, confidence: 0, matches: [], isRequest: false };
}

// ─────────────────────────────────────────────
// PRIZE / REWARD SCAM
// ─────────────────────────────────────────────
export function detectPrizeScam(text) {
  const patterns = [
    /\bcongratulations?\b/i,
    /\b(?:you.ve|you\s+have)\s+(?:won|been\s+(?:selected|chosen|picked))\b/i,
    /\blucky\s+(?:winner|draw|selection)\b/i,
    /\b(?:claim|collect)\s+(?:your\s+)?(?:prize|reward|bonus|gift|voucher|winnings?)\b/i,
    /\b(?:randomly|specially)\s+selected\b/i,
    /(?:prize|reward|bonus|cashback|winnings?|gift\s+card)\s+(?:waiting|pending|for\s+you|available)\b/i,
    /\bwin\s+.{0,20}(?:iphone|ipad|laptop|tv|car|cash|gift|prize)\b/i,
    /\byou\s+(?:are|have\s+been)\s+(?:eligible|qualified|chosen|selected)\s+(?:for|to\s+receive)\b/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.80, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// IMPERSONATION
// Detects mentions of organizations whose name is
// being used in a context that can imply impersonation.
// Note: impersonation alone ≠ scam; score is moderate
// and combination bonuses in the analyzer handle escalation.
// ─────────────────────────────────────────────
export function detectImpersonation(text) {
  // Context verbs that indicate a threat, request, verification demand, or suspicious action.
  // Impersonation is only meaningful when the brand name appears in this kind of context.
  const exploitContext = /\b(?:verify|verification|verified|confirm|confirmed|suspend(?:ed|ing)?|suspended|block(?:ed|ing)?|restrict(?:ed|ing)?|lock(?:ed|ing)?|close(?:d|ing)?|deactivat(?:e|ed|ing)|terminat(?:e|ed|ing)|disconn?ect(?:ed|ing)?|cancel(?:led|ing)?|frozen|failed|failure|invalid|unauthori[sz]ed|unusual|suspicious|alert|warning|urgent|immediately|now|asap|required|click|login|log\s*in|sign\s*in|update|upgrade|pay(?:ment|ing)?|fee|charge|due|overdue|access|restore|recover|hack(?:ed|ing)?|breach(?:ed)?|compromis(?:ed|ing)?|attempt(?:ed|ing)?|detected|unauthori[sz]ed\s+access|security\s+(?:alert|issue|notice|warning)|account\s+(?:issue|problem|error|notice)|password\s+reset|data\s+breach)\b/i;

  // Completed-action / informational context — brand mention is benign here.
  // If the message is dominated by these words and has NO exploit-context words,
  // do not trigger impersonation.
  const benignContext = /\b(?:shipped|delivered|delivery|dispatched|out\s+for\s+delivery|arrived|on\s+its\s+way|track(?:ing)?|statement|available|credited|deducted|receipt|invoice\s+ready|thank\s+you|thanks\s+for|shortlist(?:ed)?|application|interview|welcome|congratulations\s+on|successfully\s+(?:placed|processed|completed|registered)|no\s+action\s+(?:is\s+)?(?:required|needed))\b/i;

  const orgs = [
    { name: 'HDFC Bank',           pattern: /\bhdfc\b/i },
    { name: 'SBI',                  pattern: /\bsbi\b|\bstate\s+bank\b/i },
    { name: 'RBI',                  pattern: /\brbi\b|\breserve\s+bank\b/i },
    { name: 'ICICI',                pattern: /\bicici\b/i },
    { name: 'Axis Bank',            pattern: /\baxis\s+bank\b/i },
    { name: 'Google',               pattern: /\bgoogle\b|\bgmail\b/i },
    { name: 'Amazon',               pattern: /\bamazon\b/i },
    { name: 'PayPal',               pattern: /\bpaypal\b/i },
    { name: 'Microsoft',            pattern: /\bmicrosoft\b|\boutlook\b/i },
    { name: 'Apple',                pattern: /\bapple\b|\bicloud\b|\bapple\s+id\b/i },
    { name: 'Netflix',              pattern: /\bnetflix\b/i },
    { name: 'WhatsApp',             pattern: /\bwhatsapp\b/i },
    { name: 'Government',           pattern: /\bgovernment\b|\bincome\s+tax\b|\bcustoms\b|\bpolice\b|\bcbi\b|\bcid\b|\bits\s+department\b/i },
    { name: 'Telecom provider',     pattern: /\bairtel\b|\bvodafone\b|\bjio\b|\bbsnl\b|\bvi\b|\bt-mobile\b|\bat&t\b/i },
    { name: 'Courier service',      pattern: /\bdhl\b|\bfedex\b|\bups\b|\bcourier\b|\bparcel\b|\bpost\s+office\b/i },
    { name: 'Bank',                 pattern: /\byour\s+bank\b|\bour\s+bank\b|\bthe\s+bank\b|\bfraud\s+department\b|\bbank\s+(?:security|team|support|helpline)\b/i },
    { name: 'Electricity provider', pattern: /\belectricity\b|\bpower\s+(?:company|department|board)\b|\belectric\s+(?:company|board)\b|\butility\b/i },
  ];

  for (const org of orgs) {
    if (org.pattern.test(text)) {
      // Brand name found. Now check context:
      // Trigger if exploit-context words are present OR benign-context words are absent.
      // Suppress if benign-context words are present AND exploit-context words are absent.
      const hasExploit = exploitContext.test(text);
      const hasBenign  = benignContext.test(text);
      if (hasExploit || !hasBenign) {
        return { triggered: true, confidence: 0.70, matches: [org.name], organization: org.name };
      }
      // Benign context with no exploit context → informational mention, not impersonation
      return { triggered: false, confidence: 0, matches: [], organization: org.name };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// SUSPICIOUS DOWNLOAD
// ─────────────────────────────────────────────
export function detectSuspiciousDownload(text) {
  const patterns = [
    /(?:download|install|run|execute|open)\s+(?:this\s+)?(?:app|apk|file|software|update|application|exe|dmg|zip|rar)\b/i,
    /(?:download|get)\s+(?:your\s+)?(?:refund|prize|documents|files|statement|ticket|voucher)\s+(?:here|from|via|at|now|below)/i,
    /(?:disable|turn\s+off|uninstall)\s+(?:play\s+protect|antivirus|security|defender|firewall|protection)\b/i,
    /(?:apk|executable|application)\s+(?:from|via|at)\s+(?:this\s+link|this\s+url|below|here)/i,
    /click.{0,20}download|download.{0,20}click/i,
    /install.{0,20}link|link.{0,20}install/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.85, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// ACCOUNT THREAT
// Claims of account/service suspension, restriction,
// locking, blocking, disconnection
// ─────────────────────────────────────────────
export function detectAccountThreat(text) {
  const patterns = [
    // Standard suspension/blocking
    /\b(?:account|profile|access|subscription|service)\s+(?:has\s+been|will\s+be|is\s+(?:being|about\s+to\s+be))\s+(?:suspended|blocked|closed|deactivated|terminated|locked|restricted|cancelled|frozen)\b/i,
    // SIM / phone
    /\b(?:sim\s+card?|sim|number|line)\s+(?:will\s+be|has\s+been|is\s+(?:about\s+to\s+be)?)\s+(?:blocked|deactivated|suspended|disconnected)\b/i,
    // Utility disconnection
    /\b(?:electricity|power|gas|water|internet|service)\s+(?:will\s+be|is\s+scheduled\s+to\s+be)\s+(?:disconnected|cut\s+off|interrupted|terminated)\b/i,
    // KYC / verification required
    /\b(?:kyc|verification|authentication)\s+(?:failed|pending|incomplete|required|not\s+completed)\b/i,
    // Account locked / restricted / limited
    /\b(?:your\s+)?(?:account|id|profile)\s+(?:has\s+been|is)\s+(?:locked|restricted|limited|put\s+on\s+hold|flagged)\b/i,
    // Legal / police action
    /\b(?:legal|court|police)\s+(?:action|case|complaint|notice|warrant|proceeding)\b/i,
    // "Failed KYC" / "incomplete verification"
    /\b(?:failed|incomplete|pending)\s+(?:kyc|verification|document\s+verification)\b/i,
    // "Unusual activity" combined with action needed
    /\bunusual\s+(?:sign.?in|login|activity|access)\b.{0,60}(?:verify|confirm|secure|review)/i,
    // Fraud alert / security alert needing action
    /\b(?:fraud|security)\s+(?:alert|warning|notice|department)\b.{0,60}(?:verify|confirm|call|contact|provide)/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.85, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// EXTERNAL CONTACT / ACTION REDIRECT
// Message directing user to call a number, click a
// link, reply with info, or visit an external resource
// as the primary call-to-action
// ─────────────────────────────────────────────
export function detectExternalAction(text) {
  const patterns = [
    // Click link / visit URL
    /(?:click|tap|visit|open|go\s+to)\s+(?:the\s+)?(?:link|url|website|page|portal|button)\s+(?:to|and|below|here|now|immediately)/i,
    /click\s+here\s+to\s+(?:verify|confirm|update|restore|secure|access|activate|claim)/i,
    // Call a number with urgency context
    /(?:call|contact|reach)\s+(?:us|our|the)?\s*(?:helpline|hotline|support|team|number|immediately|now|urgently).{0,30}(?:\d{4,}|1-\d{3})/i,
    /(?:call|dial)\s+(?:immediately|now|urgently|asap)\b/i,
    /(?:call|contact)\s+.{0,20}\b(?:fraud\s+department|security\s+team|helpline|customer\s+care|toll.free)\b/i,
    // Reply with information
    /reply\s+(?:with|to\s+this|to\s+confirm|back\s+with)\s+(?:your\s+)?(?:name|details|information|account|number|code)/i,
    // "To restore/verify/claim, click/visit/call"
    /(?:to\s+(?:restore|verify|confirm|claim|secure|unlock|access|update|reactivate))\s+.{0,30}(?:click|visit|call|go\s+to|contact)\b/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.75, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// SOCIAL ENGINEERING THREAT
// Authority + coercive action combinations that do
// not rely on explicit brand names or known keywords:
// vishing (verbal code requests), arrest/legal threats,
// press-a-number IVR bait, SIM porting attacks,
// call-back urgency without a URL.
// ─────────────────────────────────────────────
export function detectSocialEngineeringThreat(text) {
  const patterns = [
    // Verbal / oral code handover request ("read it out", "tell the agent", "dictate")
    /(?:read(?:\s+it|\s+the\s+code)?|tell|dictate|say|speak)\s+(?:it\s+)?(?:out|aloud|to)\s+.{0,30}(?:agent|technician|executive|officer|representative|support)/i,
    // "Share/send/give/forward the OTP/code you receive to [agent/support/team/us]"
    // Covers both "share the code you receive" AND "send the OTP to our support agent"
    /(?:share|give|tell|read\s+out|send|forward)\s+(?:(?:the|your|a)\s+)?(?:code|number|otp|pin|verification\s+code)\s+(?:you\s+receive|sent\s+to\s+you|received\s+on\s+your\s+phone|that\s+(?:arrives?|comes?)|.{0,30}(?:to\s+(?:our|the|a)?\s*(?:agent|support|team|representative|executive|officer|us)))/i,
    // Press-a-number IVR bait
    /(?:press|dial)\s+[1-9*#]\s+(?:to\s+(?:avoid|prevent|stop|block|cancel|speak|connect|confirm)|or\s+(?:call|contact))/i,
    // Legal / arrest threat (generalised, not just police/court)
    /\b(?:arrest|arrested|detained|warrant\s+issued|fir\s+(?:has\s+been|will\s+be)|case\s+(?:has\s+been|will\s+be)\s+filed|summons?|prosecution|criminal\s+case)\b/i,
    // "To avoid arrest / charges / action" pressure
    /\bto\s+avoid\s+(?:arrest|prosecution|legal\s+action|penalty|charges|fine)\b/i,
    // SIM porting / number hijack alert + call-back
    /\b(?:porting\s+request|port\s+(?:request|out|your\s+number|initiated)|number\s+(?:porting|port))\b.{0,60}(?:call|contact|block|stop|cancel)/i,
    // Cyber crime / law enforcement impersonation + action
    /\b(?:cyber\s+crime|cybercrime|cyber\s+cell|enforcement\s+(?:agency|directorate)|ed\s+(?:office|notice)|income\s+tax\s+(?:raid|notice|officer))\b.{0,80}(?:call|contact|press|reply|register|verify|confirm)/i,
    // "A complaint has been registered against you / your number"
    /\bcomplaints?\s+(?:has\s+been|have\s+been|registered?)\s+against\s+(?:your|you|this)\b/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.82, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// HINGLISH / ROMANISED HINDI SCAM SIGNALS
// Covers common word-order-inverted constructions in
// romanised Hindi SMS scams. Vocabulary is general
// (financial, credential, prize, threat categories)
// not message-specific.
// ─────────────────────────────────────────────
export function detectHinglishScam(text) {
  // Narrowly-scoped normalisation: only expand known phonetic doublings used in
  // romanised Hindi scam vocabulary. Applied per-word, not globally, to avoid
  // corrupting unrelated Hinglish words (e.g. "baje", "aaye", "jaayega").
  const lower = text.toLowerCase();
  const normalised = lower
    // aadhaar / aadhar → adhar (identity doc spelling variants)
    .replace(/\baadha[a]?r\b/g, 'adhar')
    // aapka / aapko / aap → apka / apko / ap (possessive/pronoun)
    .replace(/\baapk([ao])\b/g, 'apk$1')
    .replace(/\baap\b/g, 'ap')
    // kk → k (double-consonant normalisation)
    .replace(/kk/g, 'k');

  // Patterns are grouped into named risk categories so the analyzer can issue
  // a compound bonus when a single message contains multiple dangerous categories.
  const categories = {
    credential: [
      // OTP / credential share requests — verb must follow within ≤8 chars
      /\b(?:otp|pin|password|verification\s*code)\s+.{0,8}(?:share\s+kar(?:ein|o|en|na|dein|do)?|bhej(?:ein|o|na|do|ta|ti)?|bata(?:ein|o|na|do)?|de\s+(?:dein|do|na))\b/i,
      // Personal PII send request — specific field + send verb within ≤15 chars
      /\bapna\s+(?:nam|naam|adhar|aadhaar|pan|dob)\s+.{0,15}(?:bhej(?:ein|o|na|do)?|share\s+kar(?:ein|o|na|do)?|send\s+kar(?:ein|o|na)?|dein|do)\b/i,
    ],
    threat: [
      // Account block / band — object + state-verb within ≤8 chars
      /\b(?:account|sim|card)\s+.{0,8}(?:block|band|suspend)\s+ho\s+(?:gaya|gayi|jayega|jayegi|sakta|sakti)\b/i,
    ],
    demand: [
      // "verify / kyc karne ke liye" — explicit action demand
      /\b(?:verify|kyc|activate|reactivate)\s+karne\s+ke\s+liye\b/i,
      // Financial detail send — specific data-noun + send-verb within ≤12 chars
      /(?:bank\s+details?|account\s+number|ifsc|upi\s+(?:id|pin)|card\s+details?)\s+.{0,12}(?:bhej(?:ein|o|na|dein|do)?|share\s+kar(?:ein|o|na|do)?|send\s+kar(?:ein|o|na)?)\b/i,
      // "Hamare agent / officer ko" — third-party handoff (vishing)
      /hamare\s+(?:agent|officer|executive|helpline)\s+(?:ko|par|pe)\b/i,
    ],
    urgency: [
      // Urgency marker + request verb within ≤20 chars
      /\b(?:abhi|turant|fauran)\s+.{0,20}(?:karein|karo|bhejein|share\s+kar|send\s+kar|call\s+kar)\b/i,
    ],
    prize: [
      // Prize-noun + result-verb within ≤8 chars
      /\b(?:inam|inaam|puraskar|lucky\s+draw)\s+.{0,8}(?:jeeta?|mila?|prapt|milega|milegi)\b/i,
      // Rupee amount + claim action within ≤15 chars
      /\d[\d,]*\s*(?:rupay(?:e|a)?|rs\.?|inr)\s+.{0,15}(?:jeeta?|prapt|claim|bhej(?:ein|o)?|send\s+kar)\b/i,
    ],
  };

  const matchedCategories = [];
  const allMatches = [];

  for (const [cat, patterns] of Object.entries(categories)) {
    for (const p of patterns) {
      if (p.test(normalised)) {
        matchedCategories.push(cat);
        allMatches.push(normalised.match(p)[0]);
        break; // one match per category is enough
      }
    }
  }

  if (matchedCategories.length === 0) {
    return { triggered: false, confidence: 0, matches: [] };
  }

  return {
    triggered: true,
    confidence: 0.78,
    matches: allMatches,
    categoryCount: matchedCategories.length,
    categories: matchedCategories,
  };
}

// ─────────────────────────────────────────────
// INVESTMENT / FINANCIAL OPPORTUNITY SCAM
// High-return guarantees, crypto bait, MLM patterns
// ─────────────────────────────────────────────
export function detectInvestmentScam(text) {
  const patterns = [
    // Guaranteed / unrealistic returns
    /(?:guaranteed|assured|certain|risk.?free)\s+(?:\d+%|\w+\s+%)?\s*(?:returns?|profit|earnings?|income)\b/i,
    /\b\d{2,3}%\s+(?:monthly|weekly|daily|annual)\s+(?:returns?|profit|earnings?|interest)\b/i,
    // "Send X to earn"
    /(?:send|invest|deposit)\s+.{0,30}(?:earn|make|receive)\s+.{0,30}(?:per\s+(?:day|week|month)|guaranteed)/i,
    // Crypto bait
    /(?:send|transfer|deposit)\s+.{0,20}(?:bitcoin|btc|ethereum|eth|usdt|litecoin|crypto)\s+.{0,30}(?:earn|returns?|profit|investment|multiply)/i,
    /\bdouble\s+your\s+(?:money|investment|bitcoin|crypto)\b/i,
    // Limited slots / exclusive offer pressure
    /\b(?:limited\s+(?:slots?|spots?|positions?|seats?)|exclusive\s+(?:offer|investment|opportunity))\b.{0,50}(?:available|remaining|left)/i,
  ];

  for (const p of patterns) {
    if (p.test(text)) {
      return { triggered: true, confidence: 0.82, matches: [text.match(p)[0]] };
    }
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// SUSPICIOUS URL SIGNAL (pass-through from urlAnalyzer)
// ─────────────────────────────────────────────
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

// ─────────────────────────────────────────────
// CRYPTO WALLET TRANSFER DETECTOR
// Fires when a message contains a transfer/send/payment
// instruction directed at a recognisable cryptocurrency
// wallet address — independent of investment-return language.
// Covers Bitcoin (legacy, P2SH, bech32/native-SegWit)
// and Ethereum address formats.
// ─────────────────────────────────────────────
export function detectCryptoWalletTransfer(text) {
  // Bitcoin legacy (1...) and P2SH (3...) — 26-34 base58 chars
  const btcLegacy = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/;
  // Bitcoin bech32 native-SegWit (bc1q... or bc1p...) — 39-62 chars
  const btcBech32 = /\bbc1[qp][a-z0-9]{6,87}\b/i;
  // Ethereum (0x + 40 hex chars)
  const ethAddr   = /\b0x[0-9a-fA-F]{40}\b/;

  const hasWalletAddress = btcLegacy.test(text) || btcBech32.test(text) || ethAddr.test(text);
  if (!hasWalletAddress) return { triggered: false, confidence: 0, matches: [] };

  // Only flag when there is also a transfer/send/payment instruction near it.
  // This prevents flagging educational or informational mentions of addresses.
  const transferInstruction = /\b(?:send|transfer|pay(?:ment)?|deposit|wire|submit|forward)\b.{0,120}(?:bc1|0x[0-9a-f]{4}|[13][a-km-z]{4})|(?:bc1|0x[0-9a-f]{4}|[13][a-km-z]{4}).{0,120}\b(?:send|transfer|pay(?:ment)?|deposit|wire|submit|forward)\b/i;

  if (transferInstruction.test(text)) {
    const walletMatch = (text.match(btcBech32) || text.match(ethAddr) || text.match(btcLegacy) || [])[0] || '';
    return { triggered: true, confidence: 0.88, matches: [walletMatch] };
  }

  return { triggered: false, confidence: 0, matches: [] };
}

// ─────────────────────────────────────────────
// BENIGN SIGNALS (reduce false positives)
// ─────────────────────────────────────────────
export function detectBenignSignals(text) {
  const signals = [];

  // Safety / security advice from the sender
  const safetyPatterns = [
    /(?:do\s+not|don.t|never)\s+(?:share|click|open|enter|provide|send)\s+(?:your\s+)?(?:password|otp|pin|credentials|personal\s+data|sensitive\s+information|card\s+details)/i,
    /(?:we|our\s+(?:bank|team|company))\s+(?:will\s+never|would\s+never|don.t|do\s+not)\s+(?:ask|request)\s+(?:for\s+)?(?:your\s+)?(?:password|otp|cvv|card|credentials|pin)/i,
    /(?:use|contact|call)\s+(?:only\s+)?(?:official|authorized|verified|legitimate)\s+(?:number|website|channel|app)/i,
  ];
  for (const p of safetyPatterns) {
    if (p.test(text)) signals.push('safety advice');
  }

  // Clearly legitimate notifications (completed actions, not requests)
  const legitPatterns = [
    /\b(?:thank\s+you|thanks)\s+for\s+(?:banking|using|choosing|your\s+purchase|shopping)\b/i,
    /\b(?:your\s+)?(?:order|transaction|payment|transfer|recharge)\s+(?:has\s+been|was)\s+(?:successfully\s+)?(?:completed|confirmed|processed|shipped|delivered)\b/i,
    /\byour\s+(?:order|package)\s+.{0,20}(?:will\s+arrive|is\s+on\s+its\s+way|has\s+shipped|has\s+been\s+dispatched|out\s+for\s+delivery)\b/i,
    /\b(?:shipment|delivery)\s+(?:status|tracking|update|confirmation)\b/i,
    /\brecharge\s+(?:successful|confirmed|completed)\b/i,
    /\btrack\s+(?:your\s+)?(?:order|package|shipment)\s+(?:at|on|using|via)\s+(?:amazon|flipkart|myntra|fedex|dhl|ups)\.com\b/i,
  ];
  for (const p of legitPatterns) {
    if (p.test(text)) signals.push('legitimate notification');
  }

  // User-initiated action confirmation — the recipient explicitly says they
  // requested this action, which is strong evidence of legitimacy.
  // Covers password resets, account verifications, sign-in confirmations.
  const userInitiatedPatterns = [
    /\byou\s+(?:requested|initiated|asked\s+for|triggered|started)\s+(?:a\s+)?(?:password\s+reset|reset|account\s+(?:verification|recovery)|sign.?in|login|two.factor|2fa|otp)\b/i,
    /\bif\s+(?:this\s+was|you\s+(?:did\s+this|initiated|requested|made\s+this))\b/i,
    /\bif\s+you\s+did\s+not\s+(?:request|initiate|make)\b/i,
    /\bno\s+action\s+(?:is\s+)?(?:needed|required|necessary)\s+(?:if|from\s+you)\b/i,
    /\bif\s+you\s+didn.t\s+(?:request|initiate|do\s+this)\b/i,
  ];
  for (const p of userInitiatedPatterns) {
    if (p.test(text)) signals.push('user-initiated');
  }

  return signals;
}

// ─────────────────────────────────────────────
// NEGATION HELPER (utility, not used in scoring)
// ─────────────────────────────────────────────
export function hasNegation(text, keyword) {
  const windowSize = 50;
  const index = text.toLowerCase().indexOf(keyword.toLowerCase());
  if (index === -1) return false;
  const contextBefore = text.substring(Math.max(0, index - windowSize), index);
  return /\b(?:don.t|do\s+not|never|not)\s+\w*$/i.test(contextBefore);
}
