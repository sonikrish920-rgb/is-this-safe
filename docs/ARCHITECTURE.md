# Is This Safe? — System Architecture

## 1. Overview

Is This Safe? is a browser-based security-awareness tool that helps users evaluate whether a message, email body, SMS text, or link may contain scam or phishing indicators. The interface is designed to be simple and understandable, with an analysis engine that highlights suspicious patterns and explains why a message may be risky.

The application does not require a backend or an API. It runs directly in the browser and processes text locally.

## 2. Architecture

User
  ↓
Input Message / Link
  ↓
Analysis Engine
  ↓
Security Indicators
  ↓
Risk Assessment
  ↓
Verdict
  ↓
Warning Signs
  ↓
Recommended Actions

The actual implementation follows this flow:

- the user enters content in the textarea and optional URL field
- the app validates the input
- the analysis engine checks patterns in the text
- weighted indicators are aggregated into a risk score
- the score produces a verdict of SAFE, SUSPICIOUS, or DANGEROUS
- the UI renders warning signs, summary text, and suggested actions
- recent scans are stored in browser localStorage

## 3. Frontend

The frontend is a static HTML/CSS/JavaScript application.

Structure:

- index.html contains the app shell and UI sections
- css/style.css defines global layout, colors, spacing, and desktop/mobile layout
- css/components.css defines form fields, buttons, result cards, and history UI
- css/animations.css contains transitions and motion styling
- js/app.js manages app behavior, event listeners, loading flow, and storage interactions
- js/ui.js handles rendering of result panels and history entries
- js/examples.js contains sample malicious inputs for demonstration
- js/history.js stores scan results in localStorage

The app uses a dark-themed interface, a risk gauge, a verdict badge, and a warning-signs panel to explain the result to the user.

## 4. Analysis Engine

The analysis engine is a context-aware, rule-based system implemented in JavaScript that understands message context, not just keywords.

### Key Modules:

**js/analyzer.js**: Main orchestrator
- Combines detection results with context awareness
- Implements weighted scoring with combination bonuses for dangerous patterns
- Extracts URLs automatically from message text
- Generates verdicts and recommendations based on score thresholds

**js/detectors.js**: Context-aware detection functions
- `detectUrgency()`: Identifies pressure tactics, deadlines, time pressure
- `detectCredentialRequest()`: Distinguishes between requesting OTP/password vs. safety advice about not sharing them
- `detectFinancialRequest()`: Identifies payment/refund/fee requests
- `detectPrizeScam()`: Detects lottery, reward, or prize claims
- `detectImpersonation()`: Flags messages pretending to be from banks, government, companies
- `detectSuspiciousDownload()`: Identifies malware/APK/app installation requests
- `detectAccountThreat()`: Detects claims about account suspension or blocking
- `detectBenignSignals()`: Identifies safety advice and legitimate notifications that reduce risk

**js/urlAnalyzer.js**: Dedicated URL analysis
- `extractUrlsFromText()`: Automatically extracts URLs from message text (no manual copy/paste needed)
- `analyzeUrl()`: Performs deep analysis of URL characteristics:
  - Checks for IP addresses, shorteners, suspicious TLDs
  - Detects typosquatting (g00gle, paypa1, etc.)
  - Identifies suspicious keywords in domains
  - Analyzes domain structure for randomness
  - Flags HTTP vs HTTPS usage

### Context Awareness:

Unlike simple keyword matching, the engine understands context:

- **"Your OTP is 123456. Do not share with anyone."** → SAFE (safety advice)
- **"Send us your OTP immediately at link"** → DANGEROUS (actual request + urgency + suspicious link)
- **"Download the movie from this website"** → SUSPICIOUS (URL without malware indicators)
- **"Download this APK to get your refund. Disable Play Protect and install now."** → SUSPICIOUS (suspicious download + urgency + pressure to disable security)

### Scoring System:

Individual indicator weights:
- Urgency: +6
- Credential request: +12
- Financial request: +12
- Prize/reward: +8
- Impersonation: +7
- Suspicious download: +10
- Account threat: +8
- Suspicious URL: +4 to +15 (depends on URL risk factors)

Combination bonuses for dangerous patterns:
- Credential + Urgent + URL: +15
- Credential + URL: +10
- Financial + Urgent: +10
- Impersonation + Credential + Threat: +15
- Threat + Credential: +12
- Impersonation + Threat + URL: +12
- Download + URL: +9
- Threat + Urgent: +8

Benign signal reductions:
- Safety advice (don't share credentials): -8
- Legitimate notification (order shipped, etc.): -5

These bonuses are crucial for avoiding false positives: a message mentioning "OTP" gets low/no score if it's just explaining that your bank won't ask for it.

## 5. Risk Assessment

The application calculates a weighted risk score and maps it to a verdict:

- 0–14: SAFE (no concerning indicators)
- 15–29: SUSPICIOUS (some warning signs, caution recommended)
- 30–100: DANGEROUS (multiple or severe indicators present)

The verdict determines:
- UI styling (color, icon, gauge appearance)
- Summary text (explanation for the user)
- Recommended actions (specific steps to take)

## 6. Explainability

The result panel includes:

- a risk-score gauge (0–100)
- a verdict badge (SAFE / SUSPICIOUS / DANGEROUS)
- a list of detected signals with individual scores
- each signal explains what was detected and why it matters
- a plain-language summary
- specific, actionable recommendations

## 7. Security Considerations

Relevant considerations for the current implementation:

- analysis runs on the client side; no request is sent to a remote analysis service
- no user account, login, or backend session is used
- message text and URLs are only processed locally in the browser
- scan history is stored in browser localStorage and is not sent to a server
- no secrets or API keys are required to run the current application

## 8. Current Limitations

This project is intentionally honest about its current scope:

- the detection engine is based on predefined rules, not a trained ML model
- it does not query live threat intelligence feeds
- it does not verify a website’s reputation in real time
- it is designed for awareness and educational use rather than authoritative triage

## 9. Future Architecture

Realistic future improvements include:

- AI-assisted semantic analysis for more nuanced phishing detection
- real-time URL reputation APIs
- threat intelligence feeds
- browser extension support
- mobile or desktop wrappers
- multilingual detection and localization
- more advanced explainability and confidence indicators

These improvements would require additional services or integrations and are not part of the current implementation.
