import { detectorDefinitions } from './detectors.js';

export function analyzeMessage(inputText, urlText = '') {
  const combinedText = `${inputText || ''} ${urlText || ''}`.trim();

  if (!combinedText) {
    return {
      verdict: 'SAFE',
      riskScore: 0,
      signals: [],
      summary: 'No message was provided for analysis.',
      actions: ['Enter text or a suspicious URL to begin the scan.'],
      engine: 'local-v1'
    };
  }

  const normalized = combinedText.replace(/\s+/g, ' ').trim();

  let score = 0;
  const signals = [];

  for (const detector of detectorDefinitions) {
    const result = detector.check(normalized);
    if (!result.triggered) continue;

    score += detector.weight * Math.min(1, Math.max(0.6, result.confidence || 0.75));
    signals.push({
      id: detector.id,
      label: detector.label,
      description: detector.description,
      severity: detector.severity,
      matches: result.matches
    });
  }

  const cappedScore = Math.min(100, Math.round(score));
  let verdict = 'SAFE';
  if (cappedScore >= 70) verdict = 'DANGEROUS';
  else if (cappedScore >= 30) verdict = 'SUSPICIOUS';

  const summary = buildSummary(verdict, signals, cappedScore);
  const actions = buildActions(verdict, signals);

  return {
    verdict,
    riskScore: cappedScore,
    signals,
    summary,
    actions,
    engine: 'local-v1'
  };
}

function buildSummary(verdict, signals, riskScore) {
  if (!signals.length) {
    return 'No clear scam indicators were detected in the provided content. It appears low risk based on the current pattern checks.';
  }

  if (verdict === 'DANGEROUS') {
    return `This message strongly resembles a scam or phishing attempt with ${signals.length} warning signals detected and a risk score of ${riskScore}.`;
  }

  if (verdict === 'SUSPICIOUS') {
    return `This message shows some suspicious indicators and should be treated carefully before you click links or share information.`;
  }

  return `This message looks mostly benign, though some caution is still recommended if the sender is unknown.`;
}

function buildActions(verdict, signals) {
  const base = [
    'Do not click any links or open attachments unless you can verify the sender independently.',
    'Verify the request through an official channel before sharing credentials or personal data.'
  ];

  if (verdict === 'SAFE') {
    return [...base, 'If the sender is unfamiliar, keep the message in mind and avoid acting on it until you confirm the contact details.'];
  }

  const extras = [
    'Do not provide passwords, OTPs, banking details, or personal information.',
    'Report the message as suspicious and contact the organization using their official website or phone number.'
  ];

  return [...base, ...extras].slice(0, 4);
}
