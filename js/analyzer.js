import {
  detectUrgency,
  detectCredentialRequest,
  detectFinancialRequest,
  detectPrizeScam,
  detectImpersonation,
  detectSuspiciousDownload,
  detectAccountThreat,
  detectPersonalInfoRequest,
  detectExternalAction,
  detectInvestmentScam,
  detectSocialEngineeringThreat,
  detectHinglishScam,
  detectSuspiciousUrl,
  detectCryptoWalletTransfer,
  detectBenignSignals
} from './detectors.js';

import { extractUrlsFromText, analyzeUrl, checkDomainMismatch } from './urlAnalyzer.js';

export function analyzeMessage(inputText, urlText = '') {
  const messageText = (inputText || '').trim();
  const manualUrlText = (urlText || '').trim();

  if (!messageText && !manualUrlText) {
    return {
      verdict: 'SAFE',
      riskScore: 0,
      signals: [],
      summary: 'No message was provided for analysis.',
      actions: ['Enter text or a suspicious URL to begin the scan.'],
      explanation: '',
      engine: 'local-v3-context-aware'
    };
  }

  const combinedText = `${messageText} ${manualUrlText}`.trim();

  // ── URL extraction ────────────────────────────────────────
  const extractedUrls = extractUrlsFromText(messageText);
  const allUrls = manualUrlText ? [manualUrlText] : [];
  for (const url of extractedUrls) {
    if (!allUrls.includes(url)) allUrls.push(url);
  }

  // ── Run all detectors ─────────────────────────────────────
  const urgency       = detectUrgency(combinedText);
  const credential    = detectCredentialRequest(combinedText);
  const financial     = detectFinancialRequest(combinedText);
  const prize         = detectPrizeScam(combinedText);
  const impersonation = detectImpersonation(combinedText);
  const download      = detectSuspiciousDownload(combinedText);
  const threat        = detectAccountThreat(combinedText);
  const personalInfo  = detectPersonalInfoRequest(combinedText);
  const extAction     = detectExternalAction(combinedText);
  const investment    = detectInvestmentScam(combinedText);
  const socialEng     = detectSocialEngineeringThreat(combinedText);
  const hinglish      = detectHinglishScam(combinedText);
  const cryptoWallet  = detectCryptoWalletTransfer(combinedText);
  const benignSignals = detectBenignSignals(combinedText);

  let score = 0;
  const signals = [];

  // ── Individual detector scores ────────────────────────────

  if (urgency.triggered) {
    score += 7;
    signals.push({
      id: 'urgency',
      label: 'Urgency / pressure',
      description: 'Uses deadlines, threats, or time pressure to force quick action.',
      severity: 'medium',
      score: 7
    });
  }

  if (credential.triggered && credential.isRequest) {
    score += 14;
    signals.push({
      id: 'credential-request',
      label: 'Requests credentials or sensitive codes',
      description: 'Asks you to share a password, OTP, PIN, CVV, or login details.',
      severity: 'high',
      score: 14
    });
  }

  if (financial.triggered && financial.isRequest) {
    score += 14;
    signals.push({
      id: 'financial-request',
      label: 'Requests payment or financial details',
      description: 'Asks for money, bank details, payment information, or fees.',
      severity: 'high',
      score: 14
    });
  }

  if (prize.triggered) {
    score += 9;
    signals.push({
      id: 'prize-scam',
      label: 'Prize or reward claim',
      description: 'Claims you have won money, a prize, or an exclusive reward.',
      severity: 'medium',
      score: 9
    });
  }

  if (impersonation.triggered) {
    score += 6;
    signals.push({
      id: 'impersonation',
      label: 'Mentions a known organization',
      description: `Claims to be from or references ${impersonation.organization || 'a legitimate organization'}.`,
      severity: 'medium',
      score: 6
    });
  }

  if (download.triggered) {
    score += 12;
    signals.push({
      id: 'suspicious-download',
      label: 'Requests download or app installation',
      description: 'Asks you to download and install software, an APK, or a file.',
      severity: 'high',
      score: 12
    });
  }

  if (threat.triggered) {
    score += 10;
    signals.push({
      id: 'account-threat',
      label: 'Account or service threat',
      description: 'Claims your account, service, or SIM will be suspended, locked, or disconnected.',
      severity: 'high',
      score: 10
    });
  }

  if (personalInfo.triggered) {
    score += 15;
    signals.push({
      id: 'personal-info-request',
      label: 'Requests personal identification information',
      description: 'Asks for personal details such as name, address, date of birth, national ID, or SSN.',
      severity: 'high',
      score: 15
    });
  }

  if (extAction.triggered) {
    score += 6;
    signals.push({
      id: 'external-action',
      label: 'Directs to external action',
      description: 'Instructs you to click a link, call a number, or reply with information.',
      severity: 'medium',
      score: 6
    });
  }

  if (investment.triggered) {
    score += 14;
    signals.push({
      id: 'investment-scam',
      label: 'Investment or financial opportunity scam',
      description: 'Promises guaranteed returns, cryptocurrency gains, or unrealistic investment profits.',
      severity: 'high',
      score: 14
    });
  }

  if (socialEng.triggered) {
    score += 15;
    signals.push({
      id: 'social-engineering',
      label: 'Social engineering / coercive authority',
      description: 'Uses authority impersonation, arrest threats, IVR bait, or verbal-code requests to manipulate.',
      severity: 'high',
      score: 15
    });
  }

  if (hinglish.triggered) {
    score += 15;
    signals.push({
      id: 'hinglish-scam',
      label: 'Hinglish scam pattern',
      description: 'Contains romanised Hindi phrasing consistent with credential, financial, or prize scam messages.',
      severity: 'high',
      score: 15
    });
  }

  if (cryptoWallet.triggered) {
    score += 14;
    signals.push({
      id: 'crypto-wallet-transfer',
      label: 'Cryptocurrency wallet transfer instruction',
      description: 'Contains a cryptocurrency wallet address alongside a request to send or transfer funds.',
      severity: 'high',
      score: 14
    });
  }

  // ── URL analysis ──────────────────────────────────────────
  const urlSignals = [];
  for (const url of allUrls) {
    const urlAnalysis = analyzeUrl(url);
    if (urlAnalysis.urlRiskScore > 0) {
      const urlScore = Math.min(20, urlAnalysis.urlRiskScore);
      score += urlScore;
      urlSignals.push({
        id: 'suspicious-url',
        label: 'Suspicious URL',
        description: `Contains a suspicious link: ${urlAnalysis.riskIndicators.join(', ')}.`,
        severity: 'high',
        score: urlScore,
        url,
        urlDetails: urlAnalysis
      });
    }

    if (urlAnalysis.domain && checkDomainMismatch(urlAnalysis.domain, messageText)) {
      score += 12;
      urlSignals.push({
        id: 'domain-mismatch',
        label: 'Domain mismatch',
        description: 'The link domain does not match the organization mentioned in the message.',
        severity: 'high',
        score: 12,
        url
      });
    }
  }
  if (urlSignals.length > 0) signals.push(...urlSignals);

  // ── Combination bonuses ───────────────────────────────────
  // These reward coherent multi-signal attack patterns.
  // Suppressed entirely for user-initiated messages (e.g. legitimate password-reset
  // emails) because they legitimately contain impersonation + urgency + URL patterns.
  let combinationBonus = 0;
  const isUserInitiated = benignSignals.includes('user-initiated');

  if (!isUserInitiated) {
    // Classic phishing: authority claim + urgency + credential request + suspicious link
    if (impersonation.triggered && urgency.triggered && credential.triggered && credential.isRequest && urlSignals.length > 0) {
      combinationBonus += 18;
    }
    // Credential harvest + URL (without full bonus above)
    else if (credential.triggered && credential.isRequest && urlSignals.length > 0) {
      combinationBonus += 12;
    }
    // Credential harvest + urgency (no URL)
    else if (credential.triggered && credential.isRequest && urgency.triggered) {
      combinationBonus += 8;
    }

    // Account threat driving credential request
    if (threat.triggered && credential.triggered && credential.isRequest) {
      combinationBonus += 12;
    }

    // Impersonation + account threat + URL
    if (impersonation.triggered && threat.triggered && urlSignals.length > 0) {
      combinationBonus += 10;
    }

    // Financial pressure + urgency
    if (financial.triggered && financial.isRequest && urgency.triggered) {
      combinationBonus += 10;
    }

    // Financial + prize (upfront-fee / advance-fee fraud)
    if (financial.triggered && financial.isRequest && prize.triggered) {
      combinationBonus += 12;
    }

    // Credential + prize (account-details harvest via prize bait)
    if (credential.triggered && credential.isRequest && prize.triggered) {
      combinationBonus += 10;
    }

    // Personal info + prize (identity harvesting disguised as prize claim)
    if (personalInfo.triggered && prize.triggered) {
      combinationBonus += 10;
    }

    // Download + URL (malware delivery)
    if (download.triggered && urlSignals.length > 0) {
      combinationBonus += 10;
    }

    // Threat + urgency
    if (threat.triggered && urgency.triggered) {
      combinationBonus += 8;
    }

    // Impersonation + URL (any)
    if (impersonation.triggered && urlSignals.length > 0) {
      combinationBonus += 6;
    }

    // External action + threat (social engineering redirect)
    if (extAction.triggered && threat.triggered) {
      combinationBonus += 8;
    }

    // External action + financial request
    if (extAction.triggered && financial.triggered && financial.isRequest) {
      combinationBonus += 8;
    }

    // Personal info + impersonation (credential harvesting via authority)
    if (personalInfo.triggered && impersonation.triggered) {
      combinationBonus += 8;
    }

    // Social engineering + urgency (coercive call-back)
    if (socialEng.triggered && urgency.triggered) {
      combinationBonus += 8;
    }

    // Social engineering + threat (authority + consequence)
    if (socialEng.triggered && threat.triggered) {
      combinationBonus += 8;
    }

    // Hinglish + credential/financial/personal-info request
    if (hinglish.triggered && (
      (credential.triggered && credential.isRequest) ||
      (financial.triggered && financial.isRequest) ||
      personalInfo.triggered
    )) {
      combinationBonus += 8;
    }

    // Hinglish + prize (advance-fee or identity-harvest prize scam)
    if (hinglish.triggered && prize.triggered) {
      combinationBonus += 8;
    }

    // Hinglish + account threat (band ho jayega + urgency marker = coercive)
    if (hinglish.triggered && threat.triggered) {
      combinationBonus += 8;
    }

    // Hinglish standalone DANGEROUS threshold: if the Hinglish score alone reaches
    // the dangerous threshold via multiple signals, push it over.
    // This handles cases where Hinglish urgency is present but English urgency
    // detector doesn't understand the Hinglish phrasing.
    if (hinglish.triggered && (urgency.triggered || socialEng.triggered)) {
      combinationBonus += 8;
    }

    // Hinglish multi-category compound bonus: a Hinglish message containing
    // ≥2 distinct dangerous categories is structurally equivalent to an English
    // message with threat + credential-request — treat it accordingly.
    // categoryCount comes from the structured detectHinglishScam return value.
    if (hinglish.triggered && hinglish.categoryCount >= 2) {
      combinationBonus += 15;
    }

    // Crypto wallet + urgency (high-pressure transfer scam)
    if (cryptoWallet.triggered && urgency.triggered) {
      combinationBonus += 10;
    }

    // Crypto wallet + investment (fake-return crypto fraud)
    if (cryptoWallet.triggered && investment.triggered) {
      combinationBonus += 10;
    }
  }

  score += combinationBonus;

  // ── Benign signal reductions ──────────────────────────────
  // Only apply if the message contains safety-advice wording AND
  // there is no actual dangerous request being made.
  const hasDangerousRequest = (credential.triggered && credential.isRequest) ||
    (financial.triggered && financial.isRequest) ||
    personalInfo.triggered ||
    investment.triggered ||
    socialEng.triggered ||
    hinglish.triggered ||
    cryptoWallet.triggered;

  if (!hasDangerousRequest) {
    if (benignSignals.includes('user-initiated')) {
      score = Math.max(0, score - 15);
    }
    if (benignSignals.includes('safety advice')) {
      score = Math.max(0, score - 8);
    }
    if (benignSignals.includes('legitimate notification')) {
      score = Math.max(0, score - 5);
    }
  }

  const cappedScore = Math.min(100, Math.max(0, Math.round(score)));

  // ── Verdict thresholds ────────────────────────────────────
  let verdict = 'SAFE';
  if (cappedScore >= 30) {
    verdict = 'DANGEROUS';
  } else if (cappedScore >= 15) {
    verdict = 'SUSPICIOUS';
  }

  // Edge case: no signals → always SAFE regardless of score
  if (signals.length === 0) {
    verdict = 'SAFE';
  }

  const summary = buildSummary(verdict, signals, cappedScore);
  const explanation = buildExplanation(signals);
  const actions = buildActions(verdict, signals);

  return {
    verdict,
    riskScore: cappedScore,
    signals,
    summary,
    explanation,
    actions,
    engine: 'local-v3-context-aware'
  };
}

// ── Summary (short verdict sentence) ─────────────────────
function buildSummary(verdict, signals, riskScore) {
  if (signals.length === 0) {
    return 'No security concerns were detected. This message appears safe to interact with.';
  }

  if (verdict === 'DANGEROUS') {
    return `This message shows multiple serious warning signs of a phishing or scam attempt (risk score: ${riskScore}). Do not interact with any links or requests.`;
  }

  if (verdict === 'SUSPICIOUS') {
    return `This message contains suspicious indicators that warrant caution (risk score: ${riskScore}). Be careful before clicking links or sharing information.`;
  }

  return `This message appears mostly legitimate. If the sender is unfamiliar, verify through official channels before responding.`;
}

// ── Explanation (human-readable reason) ──────────────────
function buildExplanation(signals) {
  if (signals.length === 0) {
    return 'No suspicious patterns were found in this message.';
  }

  const parts = [];

  if (signals.some(s => s.id === 'impersonation')) {
    parts.push('the message claims to be from a known organization');
  }
  if (signals.some(s => s.id === 'account-threat')) {
    parts.push('threatens account suspension or service disconnection');
  }
  if (signals.some(s => s.id === 'urgency')) {
    parts.push('applies time pressure or urgency');
  }
  if (signals.some(s => s.id === 'credential-request')) {
    parts.push('requests passwords, OTPs, or login credentials');
  }
  if (signals.some(s => s.id === 'personal-info-request')) {
    parts.push('requests personal identification details');
  }
  if (signals.some(s => s.id === 'financial-request')) {
    parts.push('requests payment or financial information');
  }
  if (signals.some(s => s.id === 'investment-scam')) {
    parts.push('promises guaranteed financial returns');
  }
  if (signals.some(s => s.id === 'prize-scam')) {
    parts.push('claims you have won a prize or reward');
  }
  if (signals.some(s => s.id === 'suspicious-download')) {
    parts.push('asks you to download or install software');
  }
  if (signals.some(s => ['suspicious-url', 'domain-mismatch'].includes(s.id))) {
    parts.push('contains a suspicious or mismatched link');
  }
  if (signals.some(s => s.id === 'external-action')) {
    parts.push('directs you to call a number or follow an external link');
  }
  if (signals.some(s => s.id === 'social-engineering')) {
    parts.push('uses authority, legal threats, or verbal-code tricks to manipulate');
  }
  if (signals.some(s => s.id === 'hinglish-scam')) {
    parts.push('contains Hinglish phrasing consistent with credential or financial scams');
  }
  if (signals.some(s => s.id === 'crypto-wallet-transfer')) {
    parts.push('instructs you to transfer cryptocurrency to a wallet address');
  }

  if (parts.length === 0) return 'Multiple suspicious indicators were detected.';
  if (parts.length === 1) return `Suspicious because ${parts[0]}.`;

  const last = parts.pop();
  return `Suspicious because ${parts.join(', ')}, and ${last}.`;
}

// ── Recommended actions ───────────────────────────────────
function buildActions(verdict, signals) {
  if (verdict === 'SAFE' || signals.length === 0) {
    return [
      'Do not click links or open attachments unless you verify the sender independently.',
      'Never share passwords, OTPs, PINs, or banking details via message or email.'
    ];
  }

  if (verdict === 'DANGEROUS') {
    return [
      'Do not click any links or respond to requests in this message.',
      'Do not download files or install apps prompted by this message.',
      'Do not share your OTP, password, card details, or banking information.',
      'If you think this may be legitimate, contact the organization directly using their official website or number.',
      'Report the message to the organization and your security or telecom provider.'
    ];
  }

  // SUSPICIOUS
  return [
    'Do not click links or download files without verifying their legitimacy.',
    'Call the organization using their official phone number to confirm the request.',
    'Be skeptical of urgent requests for money, credentials, or personal information.',
    'If in doubt, do not interact with the message.'
  ];
}
