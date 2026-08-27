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

The current detection system is a rule-based, pattern-based engine implemented in JavaScript.

The logic is split across:

- js/detectors.js: detector definitions and regex-based match logic
- js/analyzer.js: scoring, verdict generation, and action generation

The detector set checks for patterns such as:

- urgency language
- credential requests
- payment or fee requests
- threat or consequence wording
- impersonation cues
- suspicious shortened or risky links
- social engineering language
- unusual capitalization or punctuation
- personal information harvesting patterns
- spoofed or lookalike domain patterns

Each detector contributes a weighted score. If a pattern is detected, the signal is included in the results and adds to the final risk value.

## 5. Risk Assessment

The application calculates a weighted risk score and then maps it to a verdict:

- 0–29: SAFE
- 30–69: SUSPICIOUS
- 70–100: DANGEROUS

This threshold logic is implemented in js/analyzer.js. The score is capped at 100 and the final verdict is used to style the UI and define the warning state.

## 6. Explainability

The result panel includes:

- a risk-score gauge
- a verdict badge
- a list of detected warning signs
- a plain-language explanation
- specific recommended actions

This makes the output understandable without requiring the user to inspect the raw detection logic.

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
