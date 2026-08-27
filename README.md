# Is This Safe?

> A simple security-awareness tool that helps users understand whether a suspicious message, email, or link may contain scam or phishing indicators.

## 🚀 Live Demo

https://is-this-safe-07.vercel.app/

## 🎯 Problem

People receive suspicious SMS messages, emails, links, OTP requests, payment demands, and account alerts every day. Many users do not know whether the message is legitimate, and a quick explanation can help them avoid unnecessary risk.

This project provides a simple interface for checking suspicious content and understanding the patterns that often appear in scam communications.

## 💡 Solution

Is This Safe? analyzes submitted text and optional URLs using a local client-side detection engine. It looks for common scam indicators, assigns a risk score, and presents a clear verdict with warning signals and recommended actions.

The goal is to make the assessment understandable to a general user without requiring a backend or a complex setup.

## ✨ Key Features

- Paste suspicious text or an optional URL
- Detect common scam patterns such as urgency, impersonation, credential requests, financial pressure, and shortened links
- Show a 0–100 risk score and verdict: SAFE, SUSPICIOUS, or DANGEROUS
- Display warning signals and plain-language explanations
- Provide recommended actions for the user
- Store recent scans in browser localStorage
- Run as a static front-end application with no server required

## 🔍 How It Works

User Input
↓
Security Analysis
↓
Threat / Security Indicators
↓
Risk Assessment
↓
Verdict
↓
Warning Signs
↓
Recommended Actions

## 🧠 Analysis Approach

The current analysis engine is pattern-based and runs entirely in the browser. It uses predefined detection rules in JavaScript to look for suspicious language and common scam patterns.

The system is not currently a trained ML model or application-backed AI engine. It evaluates indicators such as:

- urgency language
- credential requests
- payment or fee requests
- impersonation language
- suspicious links and shortened URLs
- social engineering patterns
- personal information harvesting language
- spoofed or lookalike domains

The risk score is aggregated from weighted detector matches, and the final verdict is produced from the cumulative score.

## 🏗️ Technology Stack

This project uses only the technologies that are present in the repository:

- HTML5
- CSS3
- Vanilla JavaScript (ES modules)
- Google Fonts CDN
- Inline SVG for the app icon
- Browser localStorage for recent scan history
- Vercel for deployment

## 🤖 IBM Bob

This project used IBM Bob as a development assistance tool for planning, implementation support, documentation refinement, and debugging review. IBM Bob was used to help structure the project and improve iteration quality during development.

IBM Bob is not the runtime threat-analysis engine for the deployed application. The live app runs as a client-side static web application using JavaScript pattern checks.

See: [docs/IBM_BOB_USAGE.md](docs/IBM_BOB_USAGE.md)

## 🏛️ Architecture

The application is a static front-end project structured around:

- HTML structure in index.html
- visual styling in css/
- behavior and analysis logic in js/
- localStorage-based history tracking
- Vercel-driven deployment

See: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## 🧪 Testing

Manual functional checks were performed for benign and phishing scenarios. The current testing notes are documented here:

See: [docs/TESTING.md](docs/TESTING.md)

## 🚀 Local Setup

Because this project is a static front-end application, no package install is required.

From the project root, run:

```bash
py -m http.server 8000
```

Then open:

```text
http://127.0.0.1:8000/
```

## ☁️ Deployment

The application is deployed on Vercel.

See: [DEPLOYMENT.md](DEPLOYMENT.md)

## ⚠️ Limitations

- The analyzer is rule-based and relies on predefined patterns.
- It does not perform live threat intelligence lookups.
- It does not use a trained ML model or backend AI service in the current runtime.
- It is intended for awareness and educational use, not as a substitute for formal security verification.

## 🔮 Future Scope

Possible future improvements include:

- semantic AI-assisted detection
- live URL reputation feeds
- threat intelligence integration
- browser extension support
- improved multilingual detection
- mobile-friendly enhancements
- richer explainability and confidence scoring

These are future improvements and are not part of the current implementation.

## 👥 Team

Team information is not available in the repository. This section is intentionally left as a placeholder for the final submission.

## 📄 License

This project is licensed under the MIT License.

See: [LICENSE](LICENSE)
