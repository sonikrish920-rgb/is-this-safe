const sharedPatterns = {
  urgency: /act now|immediately|expires in|last chance|urgent|today only|within 24 hours|final notice/i,
  credential: /password|otp|one[- ]time password|login|verify account|update your details|enter your details|pin code|security code/i,
  payment: /send money|transfer|wire|bank details|pay a fee|claim reward|prize|winner|refund|deposit/i,
  threat: /account.*(blocked|suspended|closed)|legal action|arrested|suspended|locked|will be terminated|report to authorities/i,
  impersonation: /(hdfc|sbi|rbi|google|microsoft|paypal|amazon|bank|government|irs|tax office)/i,
  social: /you've been selected|congratulations|winner|exclusive offer|limited time offer|selected for reward|claim your bonus/i,
  personalInfo: /dob|date of birth|aadhar|ssn|social security|full name|address|mobile number|passport|id number/i,
  suspiciousLink: /(bit\.ly|tinyurl|goo\.gl|is\.gd|t\.co|https?:\/\/\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+(?:xyz|top|club|info|online|click|loan|icu|cf|ga))/i,
  spoofedDomain: /(g00gle|arnazon|paypa1|micr0soft|facebo0k|go0gle|l1nked1n|bank0famerica|p0ypal)/i,
  unusualLanguage: /!{2,}|[A-Z]{8,}|\b[a-z]{1,2}\b|\b(?:lol|omg|wtf)\b/i
};

export const detectorDefinitions = [
  {
    id: 'urgency',
    label: 'Urgency language',
    description: 'Uses pressure and time limits to push quick action.',
    weight: 18,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.urgency, 'urgency')
  },
  {
    id: 'credential',
    label: 'Credential request',
    description: 'Asks for a password, OTP, or account access details.',
    weight: 22,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.credential, 'credential')
  },
  {
    id: 'payment',
    label: 'Payment request',
    description: 'Requests money, a transfer, or a fee before access.',
    weight: 20,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.payment, 'payment')
  },
  {
    id: 'threat',
    label: 'Threat or consequence',
    description: 'Creates fear about account closure or legal action.',
    weight: 20,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.threat, 'threat')
  },
  {
    id: 'impersonation',
    label: 'Impersonation signal',
    description: 'Pretends to be a bank, company, or government body.',
    weight: 15,
    severity: 'medium',
    check: (text) => detectMatch(text, sharedPatterns.impersonation, 'impersonation')
  },
  {
    id: 'suspicious-link',
    label: 'Suspicious link',
    description: 'Contains a shortened or risky link or domain pattern.',
    weight: 25,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.suspiciousLink, 'suspicious-link')
  },
  {
    id: 'social-engineering',
    label: 'Social engineering',
    description: 'Uses reward or exclusivity language to manipulate trust.',
    weight: 15,
    severity: 'medium',
    check: (text) => detectMatch(text, sharedPatterns.social, 'social-engineering')
  },
  {
    id: 'unusual-language',
    label: 'Unusual language',
    description: 'Contains unusual capitalization, repeated punctuation, or odd phrasing.',
    weight: 8,
    severity: 'low',
    check: (text) => detectMatch(text, sharedPatterns.unusualLanguage, 'unusual-language')
  },
  {
    id: 'personal-info',
    label: 'Personal information request',
    description: 'Requests confidential data such as address, DOB, or ID numbers.',
    weight: 18,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.personalInfo, 'personal-info')
  },
  {
    id: 'spoofed-domain',
    label: 'Spoofed domain',
    description: 'Looks like a familiar brand but contains a typo or lookalike pattern.',
    weight: 22,
    severity: 'high',
    check: (text) => detectMatch(text, sharedPatterns.spoofedDomain, 'spoofed-domain')
  }
];

function detectMatch(text, pattern, id) {
  const match = text.match(pattern);

  return {
    triggered: Boolean(match),
    confidence: match ? 0.82 : 0,
    matches: match ? [match[0]] : [],
    description: match ? `${id} pattern detected` : '',
    severity: match ? 'high' : 'low'
  };
}
