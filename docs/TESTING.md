# Is This Safe? — Testing

## 1. Testing Strategy

This project was tested primarily through manual browser-based validation of the static app. The checks focused on input behavior, detection logic, verdict generation, rendering of warnings, and history persistence.

Testing was centered on whether the app correctly recognized scam-like language while keeping benign content low-risk.

## 2. Test Categories

### Safe / Benign Messages

Examples of benign content include normal project or meeting messages that do not contain urgency, scam language, or credential requests.

Expected behavior:
- low risk score
- SAFE verdict
- minimal warning signs

### Phishing Messages

Examples include messages pretending to be a bank or service and warning that the account is suspended or locked.

Expected behavior:
- elevated risk score
- suspicious or dangerous verdict
- warning signal list populated

### Urgency-Based Scams

Messages that pressure the user to act immediately, such as account suspension, verification deadline, or final notice wording.

Expected behavior:
- urgency detector triggered
- risk score increased
- user is shown clear action guidance

### Prize / Reward Scams

Messages that claim the user has won a prize, reward, or payment and ask for personal details or a processing fee.

Expected behavior:
- reward/social engineering triggers
- risk score rises
- final actions direct the user to avoid sharing information

### OTP / Credential Requests

Messages asking the user to provide OTPs, passwords, login details, or verification codes.

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
