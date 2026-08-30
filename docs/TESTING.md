# Is This Safe? — Testing

## 1. Testing Strategy

The project uses a comprehensive automated test suite (`js/tests.js`) to validate the context-aware analysis engine. Tests verify that the analyzer correctly distinguishes between benign, suspicious, and dangerous content without producing false positives.

Key principles:
- Context awareness: Mentions of "OTP" or "password" are scored very differently if asking you to share them vs. warning you not to
- Combination detection: Dangerous patterns are more risky together (urgency + credential request + suspicious URL) than individually
- Benign signal recognition: Normal notifications (orders shipped, accounts credited) score low despite containing words like "account"
- URL extraction: URLs are automatically extracted from message text without requiring manual copy/paste

## 2. Automated Test Suite

The test suite in `js/tests.js` includes 10 comprehensive test cases:

### TEST 1: Benign OTP Notice
**Input:** "Your OTP for login is 123456. Do not share this OTP with anyone."
**Expected:** SAFE (score ≤ 14)
**Detects:** Safety advice (no credential request flagged)

### TEST 2: OTP Phishing
**Input:** "Your bank account will be blocked today. Verify immediately by sharing your OTP at https://suspicious-example.com"
**Expected:** DANGEROUS (score ≥ 30)
**Detects:** Account threat + Urgency + Credential request + Suspicious URL
**Why High Score:** Multiple dangerous signals combined

### TEST 3: Prize Scam
**Input:** "Congratulations! You have won ₹50,000. Pay ₹999 processing fee to claim your prize today."
**Expected:** DANGEROUS (score ≥ 30)
**Detects:** Prize claim + Financial request
**Why:** Payment request combined with false reward claim

### TEST 4: Suspicious Download
**Input:** "Download this APK to receive your refund. Install it immediately: https://random-domain.example/app.apk"
**Expected:** SUSPICIOUS (score 15-29)
**Detects:** Suspicious download + Suspicious URL + Urgency
**Note:** Refund baiting combined with app installation request

### TEST 5: Normal Message
**Input:** "Your order has been shipped and will arrive tomorrow."
**Expected:** SAFE (score ≤ 14)
**Detects:** No malicious indicators
**Why:** Legitimate business notification

### TEST 6: Normal Bank Alert
**Input:** "Dear Customer, your account has been credited with Rs. 114.89. Thank you for banking with us."
**Expected:** SAFE (score ≤ 14)
**Detects:** No credential/threat/payment requests
**Why:** "Account" word present but context is benign notification

### TEST 7: Telecom Message
**Input:** "Your SIM recharge was successful. Your validity is extended until 30 September."
**Expected:** SAFE (score ≤ 14)
**Detects:** No malicious indicators
**Why:** Legitimate service notification

### TEST 8: Suspicious Movie Download
**Input:** "For download latest movies click on this link https://random-domain.example"
**Expected:** SUSPICIOUS (score 15-29)
**Detects:** Suspicious download + Suspicious URL
**Why:** Potentially unsafe content without emergency/pressure

### TEST 9: Impersonation
**Input:** "Your SBI account will be suspended today. Verify your KYC immediately using this link: https://random-domain.example"
**Expected:** DANGEROUS (score ≥ 30)
**Detects:** Bank impersonation + Account threat + Urgency + Suspicious URL
**Why:** Multiple high-severity indicators

### TEST 10: Safety Advice
**Input:** "Never share your OTP, PIN or password with anyone. Your bank will never ask for these details."
**Expected:** SAFE (score ≤ 14)
**Detects:** Safety advice (no malicious intent despite OTP/password mentions)
**Why:** Educational message, not a request

## 3. Running the Tests

Execute the test suite with:

```bash
node --input-type=module -e "import { runTests } from './js/tests.js'; runTests();"
```

Expected output shows test results with 100% pass rate (10/10 passing).

## 4. Scoring Breakdown

Individual detector contributions:
- Urgency language: +6 points
- Credential request: +12 points
- Financial request: +12 points
- Prize/reward: +8 points
- Impersonation: +7 points
- Suspicious download: +10 points
- Account threat: +8 points
- Suspicious URL: +4 to +15 points

Combination bonuses (key to avoiding false positives):
- Credential + Urgent + URL: +15 (phishing attempt)
- Credential + URL: +10 (credential harvesting)
- Financial + Urgent: +10 (payment pressure)
- Impersonation + Credential + Threat: +15 (sophisticated phishing)
- Threat + Credential: +12 (account takeover attempt)
- Download + URL: +9 (malware distribution)
- Threat + Urgent: +8 (panic inducing)

Benign signal reductions:
- Safety advice present: -8 (legitimate warning)
- Legitimate notification: -5 (e.g., order shipped)

## 5. Verdict Thresholds

- **SAFE:** 0–14 points
  - No significant warning signs
  - Normal communications, notifications, educational content

- **SUSPICIOUS:** 15–29 points
  - Some warning signs present
  - Caution recommended before clicking links or sharing information
  - May be legitimate but has concerning elements

- **DANGEROUS:** 30+ points
  - Multiple serious indicators or severe combinations
  - Strong likelihood of phishing or scam
  - User should not interact with links or respond to requests

## 6. Context-Aware Examples

### False Positive Prevention:

1. **Mention vs. Request**
   - "Do not share your OTP" → SAFE (benign signal)
   - "Send us your OTP" → DANGEROUS (credential request)

2. **Legitimate vs. Suspicious**
   - "Your account has been credited" → SAFE
   - "Your account will be suspended" + suspicious URL → DANGEROUS

3. **Normal Download vs. Malware Bait**
   - "Download invoice" on official domain → SAFE
   - "Download APK" on suspicious domain + refund pressure → SUSPICIOUS/DANGEROUS

## 7. Known Limitations

1. **URL Analysis:** Does not make network requests; relies on local pattern analysis. Some legitimate domains might score as suspicious if they use unusual TLDs or structures.

2. **Language Variation:** Detection is optimized for English and Hinglish. Other languages may have reduced accuracy.

3. **Obfuscation:** Highly obfuscated or encoded messages may not be detected.

4. **External Context:** The analyzer has no knowledge of recent news, active scams, or user-specific context.

5. **False Negatives:** Very sophisticated phishing attempts using minimal indicators might not be flagged.

## 8. Browser Testing

Manual browser testing validates:
- UI responsiveness on desktop and mobile
- Input validation and error handling
- Correct rendering of results and warnings
- History persistence in localStorage
- Score gauge and verdict badges display correctly
- Recommended actions are clear and actionable

Start local server:
```bash
python -m http.server 8000 -b 127.0.0.1
```

Then navigate to `http://127.0.0.1:8000` and test with various inputs.

Expected behavior:
- credential detector triggers
- final verdict becomes suspicious or dangerous depending on other indicators

### Suspicious URLs

The app can process a suspicious URL or shortened URL in combination with text.

Expected behavior:
- risky domains or shortened links contribute to the score
- detection output includes suspicious link warning if patterns match

## 3. Test Case Format

| Test Case | Input Type | Expected Behavior | Actual Result | Status |
|---|---|---|---|---|
| Benign message | Normal text | SAFE verdict | Confirmed in manual validation | Pass |
| Bank impersonation scam | Suspicious message + URL | DANGEROUS verdict | Confirmed in manual validation | Pass |
| Urgency-based alert | High-pressure account warning | Suspicious or dangerous verdict | Confirmed in manual validation | Pass |
| Prize message | Fake reward claim | Suspicious or dangerous verdict | Confirmed through detector logic | Pass |
| OTP request | Verification code request | Credential pattern detected | Confirmed through rule checks | Pass |
| Empty input | No content | Validation error | Confirmed | Pass |

These tests reflect the actual smoke checks performed during development and validation.

## 4. Edge Cases

Relevant edge cases include:

- empty input should be rejected
- short text should trigger validation feedback
- messages with only mild suspicious language should remain in the suspicious range
- messages with multiple strong indicators should escalate to dangerous
- a real URL in the input should be evaluated alongside the message text

## 5. Known Limitations

- The app uses pattern matching, not a live reputation database.
- The engine does not validate organizations against external systems.
- It is designed for awareness and educational scenarios.
- It should not be used as an authoritative security source for high-risk decisions.
