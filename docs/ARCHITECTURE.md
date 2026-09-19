# Is This Safe? — System Architecture

## 1. Overview

Is This Safe? is a browser-based security-awareness tool that helps users evaluate whether a message, email body, SMS text, or link may contain scam or phishing indicators. The interface is designed to be simple and understandable, with an analysis engine that highlights suspicious patterns and explains why a message may be risky.

The application does not require a backend or an API. It runs directly in the browser and processes text locally.

## 2. Architecture

User
  ↓
Input Message / Link
  ↓
Analysis Engine (analyzer.js)
  ↓
Security Signal Detectors (detectors.js) + URL Analyzer (urlAnalyzer.js)
  ↓
Risk Score + Combination Bonuses
  ↓
Verdict (SAFE / SUSPICIOUS / DANGEROUS)
  ↓
Warning Signs + Plain-Language Explanation + Recommended Actions

The actual implementation follows this flow:

- the user enters content in the textarea and optional URL field
- the app validates the input
- the analysis engine runs all detectors against the combined text
- weighted signals are aggregated with combination bonuses into a risk score
- benign-signal reductions are applied to prevent false positives
- the score produces a verdict of SAFE, SUSPICIOUS, or DANGEROUS
- the UI renders warning signs, explanation text, and suggested actions
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

The "What this suggests" section displays a distinct plain-language explanation (buildExplanation) that names the actual signals detected rather than repeating the verdict summary.

## 4. Analysis Engine (v3)

The analysis engine is a context-aware, rule-based system implemented in JavaScript. It evaluates security-relevant features in combination, not just isolated keywords.

### 4.1 Key Modules

**js/analyzer.js** — Main orchestrator
- Runs all detectors and URL analyzers
- Computes a weighted score from individual signals
- Applies combination bonuses for dangerous multi-signal patterns
- Applies benign-signal reductions to suppress false positives
- Generates verdicts, plain-language explanations, and recommendations
- Engine identifier: `local-v3-context-aware`

**js/detectors.js** — Ten context-aware detection functions:

| Function | Detects |
|---|---|
| `detectUrgency()` | Deadlines, pressure tactics, service cutoff threats, payment pressure |
| `detectCredentialRequest()` | OTP, password, PIN, CVV, card number, bank account number, national ID requests |
| `detectPersonalInfoRequest()` | Name, address, DOB, SSN, Aadhaar, passport, PAN requests |
| `detectFinancialRequest()` | Money transfer, payment fees, billing updates, crypto send requests |
| `detectPrizeScam()` | Lottery/prize claims, "you've been selected", gift card offers |
| `detectImpersonation()` | Brand/authority name mentions (banks, Apple, Netflix, Google, government, etc.) |
| `detectSuspiciousDownload()` | APK, software install, disable-security requests |
| `detectAccountThreat()` | Account suspension/locking, SIM blocking, utility disconnection, KYC threats |
| `detectExternalAction()` | "Click here to verify", "call immediately", "reply with your details" |
| `detectInvestmentScam()` | Guaranteed returns, crypto investment bait, limited-slots pressure |
| `detectBenignSignals()` | Safety advice and legitimate completion notifications (reduce false positives) |

**js/urlAnalyzer.js** — URL extraction and structural analysis:
- `extractUrlsFromText()`: Extracts URLs embedded in message text (with correct deduplication)
- `analyzeUrl()`: Scores a URL on structural risk indicators
- `checkDomainMismatch()`: Returns true when the URL domain does not match the brand mentioned in the message

### 4.2 Context Awareness

The engine understands context rather than matching isolated keywords:

- **"Your OTP is 123456. Do not share it."** → SAFE (safety advice detected, no request)
- **"Verify by sharing your OTP at suspicious-example.com"** → DANGEROUS (credential request + urgency + suspicious URL)
- **"Your Amazon order has shipped — track at amazon.com"** → SAFE (legitimate notification, matched own brand domain)
- **"Your Apple ID is locked. Verify at http://apple-id-restore.net"** → DANGEROUS (account threat + brand mismatch + suspicious URL)
- **"Win an iPhone! Reply with your name, address, and date of birth."** → DANGEROUS (prize scam + personal info harvest)
- **"Earn 40% monthly returns guaranteed. Send Bitcoin today."** → SUSPICIOUS (investment scam + financial request)

### 4.3 Scoring System

Individual signal weights:

| Signal | Score |
|---|---|
| Urgency / pressure | +7 |
| Credential request (OTP, password, card, CVV) | +14 |
| Financial request (payment, fee, billing update) | +14 |
| Investment scam (guaranteed returns, crypto bait) | +14 |
| Personal info request (name, DOB, SSN, national ID) | +12 |
| Suspicious download | +12 |
| Account or service threat | +10 |
| Prize / reward claim | +9 |
| Impersonation (brand mention) | +6 |
| External action redirect (click, call, reply) | +6 |
| Suspicious URL | +3 to +20 (depends on URL risk factors) |
| Domain mismatch | +12 |

Combination bonuses for dangerous multi-signal patterns:

| Combination | Bonus |
|---|---|
| Impersonation + urgency + credential request + URL | +18 |
| Credential request + URL | +12 |
| Threat + credential request | +12 |
| Financial + prize (advance fee fraud) | +12 |
| Credential request + urgency | +8 |
| Impersonation + threat + URL | +10 |
| Financial + urgency | +10 |
| Personal info + prize (identity harvest) | +10 |
| Download + URL (malware delivery) | +10 |
| External action + threat | +8 |
| External action + financial request | +8 |
| Personal info + impersonation | +8 |
| Threat + urgency | +8 |
| Impersonation + URL | +6 |

Benign signal reductions (only applied when no dangerous request is present):

- Safety advice detected: −8
- Legitimate completion notification detected: −5

### 4.4 URL Analysis

`analyzeUrl()` evaluates structural risk indicators. HTTPS alone is NOT treated as a safety signal.

Indicators evaluated:

| Check | Score |
|---|---|
| IP address URL | +10 |
| URL shortener | +7 |
| Suspicious TLD (.xyz, .top, .tk, .example, etc.) | +7 |
| Excessive subdomains (>3 levels) | +4 |
| Generic/test placeholder domain | +5 |
| Deceptive brand keyword in domain | +3 to +8 |
| HTTP instead of HTTPS | +3 |
| Non-standard port | +4 |
| Typosquatting (g00gle, paypa1, etc.) | +10 |
| Unusually long domain name | +4 |
| Suspicious path keywords | +2 |
| Brand name buried in subdomain | +8 |

The `urlRiskScore` is capped at 20 per URL.

Known legitimate brand domains (e.g. amazon.com, google.com, paypal.com) are not penalised for containing their own brand name.

## 5. Risk Assessment

The application calculates a weighted risk score and maps it to a verdict:

- **0–14: SAFE** — no significant warning signs
- **15–29: SUSPICIOUS** — some indicators; caution recommended
- **30–100: DANGEROUS** — multiple or severe indicators; likely phishing or scam

## 6. Explainability

The result panel includes:

- a risk-score gauge (0–100)
- a verdict badge (SAFE / SUSPICIOUS / DANGEROUS)
- a list of detected signals with individual descriptions
- a plain-language explanation naming the specific pattern detected (e.g. "Suspicious because the message claims to be from a known organization, threatens account suspension, and contains a suspicious link")
- specific, actionable recommendations

## 7. Security Considerations

- analysis runs on the client side; no request is sent to any remote analysis service
- no user account, login, or backend session is used
- message text and URLs are only processed locally in the browser
- scan history is stored in browser localStorage and is not sent to a server
- no secrets or API keys are required

## 8. Current Limitations

- the detection engine is based on predefined patterns, not a trained ML model
- it does not query live threat intelligence feeds or URL reputation databases
- it does not verify domain registration, WHOIS data, or certificate authorities
- detection is optimized for English; other languages may have reduced accuracy
- highly obfuscated or encoded messages may not be detected
- it is designed for awareness and educational use, not as an authoritative security triage tool

## 9. Future Architecture

Realistic future improvements include:

- AI-assisted semantic analysis for more nuanced phishing detection
- real-time URL reputation APIs (e.g. Google Safe Browsing, VirusTotal)
- threat intelligence feeds
- browser extension support
- mobile or desktop wrappers
- multilingual detection and localization
- more advanced explainability and confidence indicators

These improvements would require additional services or integrations and are not part of the current implementation.
