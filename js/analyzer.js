import {
  detectUrgency,
  detectCredentialRequest,
  detectFinancialRequest,
  detectPrizeScam,
  detectImpersonation,
  detectSuspiciousDownload,
  detectAccountThreat,
  detectSuspiciousUrl,
  detectBenignSignals
} from './detectors.js';

import { extractUrlsFromText, analyzeUrl } from './urlAnalyzer.js';

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
      engine: 'local-v2-context-aware'
    };
  }

  const combinedText = `${messageText} ${manualUrlText}`.trim();
  
  // Extract URLs from message
  const extractedUrls = extractUrlsFromText(messageText);
  const allUrls = [];
  
  if (manualUrlText) {
    allUrls.push(manualUrlText);
  }
  
  for (const url of extractedUrls) {
    if (!allUrls.includes(url)) {
      allUrls.push(url);
    }
  }

  let score = 0;
  const signals = [];
  const detectionResults = {};

  // Run all detectors
  const urgency = detectUrgency(combinedText);
  const credential = detectCredentialRequest(combinedText);
  const financial = detectFinancialRequest(combinedText);
  const prize = detectPrizeScam(combinedText);
  const impersonation = detectImpersonation(combinedText);
  const download = detectSuspiciousDownload(combinedText);
  const threat = detectAccountThreat(combinedText);
  const benignSignals = detectBenignSignals(combinedText);

  detectionResults.urgency = urgency;
  detectionResults.credential = credential;
  detectionResults.financial = financial;
  detectionResults.prize = prize;
  detectionResults.impersonation = impersonation;
  detectionResults.download = download;
  detectionResults.threat = threat;
  detectionResults.benign = benignSignals;

  // Score individual detectors
  if (urgency.triggered) {
    score += 6;
    signals.push({
      id: 'urgency',
      label: 'Urgency language',
      description: 'Uses pressure and time limits to push quick action.',
      severity: 'medium',
      score: 6
    });
  }

  if (credential.triggered && credential.isRequest) {
    score += 12;
    signals.push({
      id: 'credential-request',
      label: 'Requests credentials',
      description: 'Asks you to share a password, OTP, or login details.',
      severity: 'high',
      score: 12
    });
  }

  if (financial.triggered && financial.isRequest) {
    score += 12;
    signals.push({
      id: 'financial-request',
      label: 'Requests payment',
      description: 'Asks for money, bank details, or payment before providing access or goods.',
      severity: 'high',
      score: 12
    });
  }

  if (prize.triggered) {
    score += 8;
    signals.push({
      id: 'prize-scam',
      label: 'Prize or reward claim',
      description: 'Claims you have won money, a prize, or reward.',
      severity: 'medium',
      score: 8
    });
  }

  if (impersonation.triggered) {
    score += 7;
    signals.push({
      id: 'impersonation',
      label: 'Impersonation attempt',
      description: `Impersonates ${impersonation.organization || 'a legitimate organization'}.`,
      severity: 'medium',
      score: 7
    });
  }

  if (download.triggered) {
    score += 10;
    signals.push({
      id: 'suspicious-download',
      label: 'Suspicious download',
      description: 'Asks you to download and install software, an APK, or an app.',
      severity: 'high',
      score: 10
    });
  }

  if (threat.triggered) {
    score += 8;
    signals.push({
      id: 'account-threat',
      label: 'Account threat',
      description: 'Claims your account will be suspended, closed, or blocked.',
      severity: 'high',
      score: 8
    });
  }

  // Analyze URLs
  const urlSignals = [];
  for (const url of allUrls) {
    const urlAnalysis = analyzeUrl(url);
    if (urlAnalysis.urlRiskScore > 0) {
      score += Math.min(15, urlAnalysis.urlRiskScore);
      urlSignals.push({
        id: 'suspicious-url',
        label: 'Suspicious URL',
        description: `Contains a suspicious link: ${urlAnalysis.riskIndicators.join(', ')}.`,
        severity: 'high',
        score: Math.min(15, urlAnalysis.urlRiskScore),
        url: url,
        urlDetails: urlAnalysis
      });
    }
  }

  // Add URL signals to main signals
  if (urlSignals.length > 0) {
    signals.push(...urlSignals);
  }

  // Combination bonuses (dangerous patterns)
  let combinationBonus = 0;

  // Credential + Urgent + URL (very dangerous)
  if (credential.triggered && credential.isRequest && urgency.triggered && urlSignals.length > 0) {
    combinationBonus += 15;
  }

  // Credential + URL (dangerous)
  if (credential.triggered && credential.isRequest && urlSignals.length > 0) {
    combinationBonus += 10;
  }

  // Financial + Urgent (dangerous)
  if (financial.triggered && financial.isRequest && urgency.triggered) {
    combinationBonus += 10;
  }

  // Financial + Prize (dangerous)
  if (financial.triggered && financial.isRequest && prize.triggered) {
    combinationBonus += 10;
  }

  // Impersonation + Credential + Threat (very dangerous)
  if (impersonation.triggered && credential.triggered && credential.isRequest && threat.triggered) {
    combinationBonus += 15;
  }

  // Impersonation + Threat + URL
  if (impersonation.triggered && threat.triggered && urlSignals.length > 0) {
    combinationBonus += 12;
  }

  // Threat + Credential (dangerous)
  if (threat.triggered && credential.triggered && credential.isRequest) {
    combinationBonus += 12;
  }

  // Download + Suspicious URL (dangerous)
  if (download.triggered && urlSignals.length > 0) {
    combinationBonus += 9;
  }

  // Threat + Urgent (dangerous)
  if (threat.triggered && urgency.triggered) {
    combinationBonus += 8;
  }

  // Impersonation + URL
  if (impersonation.triggered && urlSignals.length > 0) {
    combinationBonus += 8;
  }

  score += combinationBonus;

  // Apply benign signal reductions (but not complete cancellation)
  let benignReduction = 0;
  if (benignSignals.includes('safety advice')) {
    benignReduction = 8;
  }
  if (benignSignals.includes('legitimate notification')) {
    benignReduction = 5;
  }

  // Only apply benign reduction if there are no actual dangerous indicators
  if (credential.triggered && credential.isSafetyAdvice && !credential.isRequest) {
    score = Math.max(0, score - benignReduction);
  }

  const cappedScore = Math.min(100, Math.max(0, Math.round(score)));

  // Determine verdict based on score thresholds
  let verdict = 'SAFE';
  if (cappedScore >= 30) {
    verdict = 'DANGEROUS';
  } else if (cappedScore >= 15) {
    verdict = 'SUSPICIOUS';
  }

  // Handle edge cases: if only benign signals, keep SAFE
  if (signals.length === 0 && benignSignals.length > 0) {
    verdict = 'SAFE';
  }

  const summary = buildSummary(verdict, signals, cappedScore);
  const actions = buildActions(verdict, signals);

  return {
    verdict,
    riskScore: cappedScore,
    signals,
    summary,
    actions,
    engine: 'local-v2-context-aware'
  };
}

function buildSummary(verdict, signals, riskScore) {
  if (signals.length === 0) {
    return 'No security concerns were detected. This message appears safe to interact with.';
  }

  if (verdict === 'DANGEROUS') {
    return `This message shows multiple serious warning signs of a phishing or scam attempt. Risk score: ${riskScore}. Do not interact with any links or requests.`;
  }

  if (verdict === 'SUSPICIOUS') {
    return `This message contains some suspicious indicators that warrant caution. Risk score: ${riskScore}. Be careful before clicking links or sharing information.`;
  }

  return `This message appears mostly legitimate. If the sender is unfamiliar, verify their identity through official channels before responding.`;
}

function buildActions(verdict, signals) {
  const base = [
    'Do not click any links or open attachments unless you verify the sender independently.',
    'Never share passwords, OTPs, PINs, or banking details via message or email.'
  ];

  if (verdict === 'SAFE' || signals.length === 0) {
    return base;
  }

  if (verdict === 'DANGEROUS') {
    return [
      'Do not click any links or respond to requests in this message.',
      'Do not download files or install apps from suspicious links.',
      'Do not share your OTP, password, or banking details.',
      'Report the message to the organization and your security provider.'
    ];
  }

  // SUSPICIOUS
  return [
    'Do not click links or download files unless you can verify their legitimacy.',
    'Call the organization using their official phone number to verify the request.',
    'Be skeptical of urgent requests for money or personal information.',
    'If in doubt, do not interact with the message.'
  ];
}
