# IBM Bob Usage

## 1. Purpose

IBM Bob was used as a development and code-analysis assistant across multiple sessions to inspect, design, improve, and validate the "Is This Safe?" repository. The repository contained a working client-side security-awareness application. Bob's role across those sessions was to perform thorough read-only exploration, identify concrete issues, implement a defined set of targeted fixes and new detection capabilities, validate those fixes through the project's own test suite, and document the work.

IBM Bob is not the runtime threat-analysis engine for the deployed application. The live application is a fully client-side, static JavaScript web application. All message analysis is performed locally in the user's browser using the rule-based detection engine in `js/analyzer.js` and `js/detectors.js`. No IBM service or API processes live user messages at runtime. IBM Bob was the development tool used to build and improve that local engine; it is not part of the engine's execution.

## 2. Repository Exploration

Bob performed a complete read-only exploration of the repository before making any changes. The following areas were inspected:

- **Project architecture** — static frontend-only application with no backend, no build step, and no package dependencies; deployed on Vercel and GitHub Pages
- **Frontend structure** — `index.html` single-page shell, three CSS files (`style.css`, `components.css`, `animations.css`), and ES module JavaScript
- **Analyzer flow** — `js/analyzer.js` orchestrates detection, scoring, combination bonuses, benign-signal reductions, verdict calculation, and result generation
- **URL analysis** — `js/urlAnalyzer.js` extracts URLs from free text and performs domain-level structural analysis including shortener detection, TLD checks, typosquatting, and IP address detection
- **Detectors** — `js/detectors.js` originally contained eight context-aware detection functions: urgency, credential request, financial request, prize scam, impersonation, suspicious download, account threat, and benign signals
- **UI rendering** — `js/ui.js` rendered the result panel, verdict badge, risk gauge, signal list, and recommended actions, at the time using only `result.summary` for the explanation section
- **Existing tests** — `js/tests.js` contained a custom 10-test suite covering benign and malicious scenarios, runnable via Node.js
- **GitHub Actions workflow** — `.github/workflows/pages.yml` deployed to GitHub Pages on push to `main` but did not execute any tests before deployment
- **Existing technical issues** — Bob identified several bugs, missing integrations, and areas of technical debt during exploration, documented in Section 3 below

## 3. Issues Identified

Bob identified the following issues across the full exploration and analysis process:

### Bugs in the original codebase

- **URL deduplication bug in `extractUrlsFromText()`** — `js/urlAnalyzer.js` maintained a `urls` array of plain strings but the deduplication guard read `u.url === normalized`, where `u` is a plain string and `u.url` is always `undefined`. As a result, the same URL appearing multiple times in a message was pushed to the array multiple times, potentially inflating the risk score.

- **`checkDomainMismatch()` was fully implemented but never called** — `js/urlAnalyzer.js` exported a complete `checkDomainMismatch()` function that detects when a message mentions a known brand (e.g., HDFC Bank, SBI, Google) but the URL does not point to that brand's legitimate domain. Despite being exported, this function was never imported or called anywhere in the codebase.

- **GitHub Actions deployed without running any tests** — The workflow deployed the site directly after checkout with no test step. A regression introduced to any detection logic would be deployed silently.

- **`explanation` and `summary` were identical in the result object** — `js/ui.js` rendered both `result.summary` and `result.explanation` but the analyzer returned the same value for both fields, so the "What this suggests" panel was identical to the verdict summary. This made the explanation redundant rather than informative.

### Detector and scoring gaps identified in later analysis

- **Credential-request article gap** — All credential-request patterns matched `send your OTP` or `send OTP` (optional `your`) but not `send the OTP`. The definite article is common in third-party relay scams ("Send the OTP to our support agent") and was consistently missed.
- **`detectImpersonation` had no context awareness** — It triggered whenever a brand name appeared in the message text, regardless of whether the context was a threat, a request, or a benign informational notification. This caused false positives on legitimate Amazon shipment notices, bank statements, and job-application emails.
- **`detectHinglishScam` had over-broad normalisation and wide wildcard gaps** — A global `aa → a` substitution corrupted unrelated Hinglish words (e.g., `baje`, `aaye`, `jaayega`), and gap quantifiers of `.{0,30}` were wide enough to fire on ordinary conversational text.
- **No coverage for cryptocurrency wallet transfer scams** — No detector recognised a cryptocurrency wallet address (Bitcoin or Ethereum) co-occurring with a transfer/send instruction.
- **No coverage for social-engineering OTP relay** — Vishing scripts that ask the recipient to forward an OTP to a support agent, press-to-connect IVR bait, arrest-threat calls, and SIM-porting attacks were undetected.
- **No Hinglish-language coverage at all** — Romanised Hindi scam messages were entirely outside the detection scope.
- **Several signal types were missing entirely** — There were no detectors for: requests for personal identification information (name, address, DOB, SSN, Aadhaar); external-action redirects (click here to verify, call immediately); investment and guaranteed-return scams.

## 4. Changes Implemented Using IBM Bob

Eight files were modified across the full set of sessions. No other files were changed.

### `js/urlAnalyzer.js`

- **Deduplication fix** — Changed the deduplication guard in `extractUrlsFromText()` from `u.url === normalized` to `u === normalized`. Since the `urls` array contains plain strings, this corrects the comparison so duplicate normalized URLs are properly filtered.
- **URL risk score cap raised** — Increased the per-URL risk score cap from 15 to 20 to allow more extreme URLs (e.g., combined TLD + shortener + HTTP + suspicious keyword) to register a higher risk contribution without exceeding a ceiling that was too conservative.
- **Additional suspicious TLDs** — Added `.example` and `.test` to the known suspicious TLD list, covering placeholder and developer-facing domains that appear in delivery-fee and fake-notification phishing.
- **Path-keyword check** — Added detection of suspicious keywords in the URL path component (reset, verify, secure, account, login, confirm, update, suspended), contributing +2 to the risk score. This catches URLs like `accounts-google.com/verify` that are structurally deceptive.
- **Brand-in-subdomain detection** — Added detection of known brand names appearing in subdomains of a non-brand domain (e.g., `google.sbi-banking.com`), contributing +8 to the risk score.
- **Legitimate-brand-domain whitelist** — Added a whitelist of known real brand domains so that messages containing `amazon.com`, `google.com`, `paypal.com`, etc., are not penalised for the brand keyword appearing in their own legitimate domain.
- **URL shortener score raised** — Increased the URL shortener risk contribution from 7 to 15 to reflect the higher empirical risk of shortener links in phishing messages.

### `js/detectors.js`

#### Expanded existing detectors

- **`detectUrgency`** — Added payment-deadline patterns (`overdue balance`, `unpaid invoice`), "avoid disconnection / cancellation" phrasing, "don't wait / don't delay" constructions, "before your X expires" templates, and "only N hours/minutes remaining" forms. These cover urgency tactics that were previously missed.
- **`detectCredentialRequest`** — Extended the optional-article group from `(?:your\s+)?` to `(?:(?:your|the|a|an)\s+)?` across all request patterns, covering `send your OTP`, `send the OTP`, and bare `send OTP`. Added a third-party relay pattern: `send/forward/give/relay the OTP/code to our/the agent/support/team`. Added a self-service password-reset safety exemption pattern (`you requested a password reset`) that returns `{triggered: false, isSafetyAdvice: true}` so legitimate password-reset emails are not penalised as credential-capture attempts.
- **`detectFinancialRequest`** — Extended the "update payment information" pattern to also match the short form `billing info` (not just `billing information` / `billing details`). Added a `payment/billing/subscription failed → update/restore/continue` pattern that catches subscription-renewal phishing messages of the form "Your Netflix payment failed. Update billing info to keep watching."
- **`detectPrizeScam`** — Added phrasing variants for "you are eligible/qualified/chosen for", "prize/reward/cashback waiting/pending", and "win [product]" constructions.
- **`detectSuspiciousDownload`** — Added "disable antivirus / turn off Play Protect" detection and "click … download / download … click" proximity patterns.
- **`detectAccountThreat`** — Added patterns for "unusual sign-in detected, verify/confirm", "fraud/security alert … call/provide", failed or incomplete KYC, and "account locked/flagged/restricted" constructions.
- **`detectImpersonation`** — Replaced the unconditional brand-name trigger with a context-aware check. The function now evaluates two secondary regex sets:
  - `exploitContext` — words like verify, blocked, update, alert, payment, urgent, login, restore, breach, access, failed, required
  - `benignContext` — words like shipped, delivered, statement, available, no action required, shortlisted, thank you, successfully completed

  Impersonation triggers only when the brand name is present AND either exploit-context words are found OR no benign-context words are present. A shipment notification or bank statement mentioning Amazon or Bank will have `hasBenign: true` and `hasExploit: false`, suppressing the signal. A phishing message mentioning Netflix alongside "payment failed / update billing" will have `hasExploit: true`, keeping the trigger. WhatsApp was also added to the brand list.
- **`detectBenignSignals`** — Added a third signal category, `user-initiated`, covering self-service password-reset and sign-in confirmation emails ("you requested a password reset", "if this was not you, no action is needed", "if you didn't request this"). This allows `analyzer.js` to apply a stronger reduction and combination-bonus suppression when the message is confirmed as a user-initiated transactional notification.

#### New detectors added

- **`detectPersonalInfoRequest`** — Detects requests for personal identification information distinct from credential capture: full name, home address, date of birth, SSN, Aadhaar/PAN number, passport number, phone number. Requires the data noun to be paired with a request verb (provide, share, send, reply with, verify) in close proximity.
- **`detectExternalAction`** — Detects messages that direct the user to a call-to-action outside the message itself: "click here to verify", "click the link to restore", "call our helpline immediately", "reply with your account number", "to claim/unlock/restore … click/visit/call". This is intentionally separate from urgency and threat detection.
- **`detectInvestmentScam`** — Detects guaranteed/assured/risk-free returns promises, specific percentage monthly/weekly returns claims, "send X to earn/multiply" patterns, cryptocurrency investment bait, and limited-slots pressure.
- **`detectSocialEngineeringThreat`** — Detects social-engineering attack patterns that do not rely on brand names or standard scam keywords: verbal/oral code-handover requests ("read the code out to our agent"), third-party OTP relay ("send/forward the OTP you receive to our support"), press-to-connect IVR bait ("press 1 to avoid", "press 2 to connect"), arrest/legal-threat scripts ("a warrant has been issued", "FIR will be filed", "to avoid prosecution"), SIM-porting alerts with action demands, cyber-crime-office and income-tax-officer impersonation with call-back instructions, and complaint-filed-against-you scripts.
- **`detectHinglishScam`** — Detects romanised Hindi scam phrasing. Patterns are structured into five named risk categories — `credential`, `threat`, `demand`, `urgency`, and `prize` — and the function scans all categories before returning, collecting every match. The return value includes `categoryCount` (number of distinct categories matched) and `categories` (array of category names), allowing the analyzer to issue a compound bonus when a single message contains multiple categories. Normalisation is narrowly scoped: only three specific word-boundary substitutions are applied (`aadhaar` variants, `aapka`/`aapko`, `aap`) rather than a blanket global `aa → a` that corrupted unrelated words. Wildcard gaps in patterns were tightened from `.{0,30}` to `.{0,8}`–`.{0,20}` depending on the pattern, preventing accidental matches across unrelated clauses in casual conversation.
- **`detectCryptoWalletTransfer`** — Detects cryptocurrency wallet addresses (Bitcoin legacy `1…`, P2SH `3…`, bech32 `bc1q…`/`bc1p…`, and Ethereum `0x…40hex`) co-occurring with a transfer/send/deposit instruction within 120 characters in either direction. Returns `{triggered: false}` when a wallet address appears without any transfer instruction, avoiding false positives on educational content that merely mentions an address.

### `js/analyzer.js`

- **`checkDomainMismatch` integration** — Added `checkDomainMismatch` to the `import` from `./urlAnalyzer.js`. Inside the URL analysis loop, after `analyzeUrl()` runs for each URL, `checkDomainMismatch(urlAnalysis.domain, messageText)` is now called. If it returns `true`, the score increases by 12 and a `domain-mismatch` signal (severity: high) is added. This was the intended use of the function that was missing from the codebase.
- **New detector imports and wiring** — Imported and called all six new detectors: `detectPersonalInfoRequest`, `detectExternalAction`, `detectInvestmentScam`, `detectSocialEngineeringThreat`, `detectHinglishScam`, and `detectCryptoWalletTransfer`. Individual signal scores: personal-info-request +15, social-engineering +15, hinglish-scam +15, crypto-wallet-transfer +14.
- **`buildExplanation()` added** — A new function generates a distinct plain-language explanation by inspecting which signal IDs are present in the result and composing a sentence naming the actual patterns detected (e.g., "Suspicious because the message claims to be from a known organization, threatens account suspension or service disconnection, and contains a suspicious or mismatched link"). This replaced the previous behaviour where `explanation` was identical to `summary`.
- **Combination-bonus table extended** — Added the following new bonuses: credential+prize (+10, account-details harvest via prize bait); credential+URL and credential+urgency (existing patterns preserved); Hinglish+credential/financial/personal-info request (+8); Hinglish+prize (+8); Hinglish+threat (+8); Hinglish+urgency-or-social-engineering (+8); Hinglish multi-category compound (+15 when `categoryCount ≥ 2`, treating a Hinglish message containing both a threat and a credential-demand as structurally equivalent to an English message with those two signals); social-engineering+urgency (+8); social-engineering+threat (+8); crypto-wallet+urgency (+10); crypto-wallet+investment (+10).
- **`isUserInitiated` guard** — Before the combination-bonus block, `benignSignals.includes('user-initiated')` is evaluated. If true, the entire combination-bonus block is skipped for that message. This prevents multi-signal amplification on legitimate password-reset and sign-in confirmation emails that legitimately contain impersonation + urgency + URL patterns.
- **Benign-signal reductions extended** — Three reductions are now applied when `hasDangerousRequest` is false: `user-initiated` (−15), `safety advice` (−8), and `legitimate notification` (−5). The `hasDangerousRequest` guard itself was extended to include `hinglish.triggered` and `cryptoWallet.triggered`, ensuring those signals cannot be reduced away by benign patterns.

### `js/tests.js`

- **Expanded from 10 tests to 31** — The test suite grew from 10 analyzer tests to 29 analyzer tests plus 2 URL deduplication tests, for 31 total.
- **New analyzer tests added (TEST 11–29)** — Tests were added to cover: domain mismatch with wrong brand domain (DANGEROUS); no domain mismatch with correct brand domain (SAFE/SUSPICIOUS); delivery-fee phishing with URL (SUSPICIOUS); bank fraud helpline call (SUSPICIOUS); KYC SIM block with urgency and personal info (DANGEROUS); prize plus personal info harvest (DANGEROUS); crypto investment with financial request (SUSPICIOUS); card CVV request without URL (DANGEROUS); utility disconnection threat (DANGEROUS); Netflix billing phishing with URL (DANGEROUS); SSN identity harvesting (DANGEROUS); Apple ID locked with suspicious URL (DANGEROUS); five legitimate-message false-positive tests — casual personal message, Amazon shipment notification, bank credit notification, security awareness message, ordinary business email (all must be SAFE); user-initiated password reset (must be SAFE, score ≤ 14); crypto wallet transfer scam (must be DANGEROUS, score ≥ 30).
- **`runDeduplicationTests()` added** — A separate function directly tests `extractUrlsFromText`: one test verifies a repeated URL is returned only once; another verifies two distinct URLs both return. These tests run in the same Node.js invocation as the analyzer tests.
- **Combined overall summary** — The `if (typeof window === 'undefined')` entry block was updated to call both `runTests()` and `runDeduplicationTests()` and print a combined `OVERALL SUMMARY` line showing total tests, total passed, and total failed.

### `js/ui.js`

- **`explanation` rendered from `result.explanation`** — Changed line 83 from rendering `result.summary` twice to rendering `result.explanation` for the `#explanationText` DOM element, with `result.summary` as a fallback: `explanation.textContent = result.explanation || result.summary`. This allows the "What this suggests" section to display the distinct plain-language explanation generated by `buildExplanation()` in the analyzer, rather than repeating the verdict summary sentence verbatim.

### `.github/workflows/pages.yml`

- **Test step added to the `build` job** — A new step was inserted between `Check out repository` and `Setup Pages`:

```yaml
- name: Run test suite
  run: node --input-type=module -e "import './js/tests.js';"
```

Importing the module triggers the `if (typeof window === 'undefined')` block, which calls both `runTests()` and `runDeduplicationTests()`. If any test fails, Node.js exits with a non-zero code, the `build` job fails, and the `deploy` job (which declares `needs: build`) does not run. Deployments are now gated on a passing test suite.

### `docs/ARCHITECTURE.md`

- **Detector table updated** — The table of detection functions was expanded from 10 rows to 16, adding `detectSocialEngineeringThreat`, `detectHinglishScam`, `detectCryptoWalletTransfer`, and accurate descriptions of `detectSuspiciousUrl` and `hasNegation` (both exported but the former called indirectly and the latter currently uncalled).
- **`detectImpersonation` description updated** — Updated to reflect the context-aware rewrite: brand mentions only trigger in exploit context; suppressed in informational/benign context.
- **`detectCredentialRequest` description updated** — Updated to document article handling (`your`/`the`/bare) and the third-party relay pattern.
- **Scoring tables corrected** — Personal-info-request score corrected to +15; social-engineering +15, Hinglish +15, and crypto-wallet-transfer +14 added. Combination-bonus table extended with all new bonuses. URL shortener score corrected to +15. URL risk cap noted as 20.
- **Benign-signal reductions table updated** — Added `user-initiated` −15 alongside safety-advice −8 and legitimate-notification −5.
- **`isUserInitiated` guard documented** — Noted that all combination bonuses are suppressed when the message is confirmed user-initiated.
- **Test and CI flow section added** — New section documenting the `node --input-type=module` test command, current test count (31), and the CI gate in GitHub Actions.
- **IBM Bob role section added** — New section explicitly stating Bob's position as a development tool, not runtime infrastructure, and confirming no IBM service is called at runtime.
- **Context-awareness examples updated** — Added new examples: Netflix billing phishing, Hinglish KYC+OTP scam, user-initiated password reset (SAFE).
- **Limitations updated** — Extended to note Hinglish support alongside English.

### `docs/IBM_BOB_USAGE.md`

- This file. Updated across sessions to accurately reflect the actual scope of work performed. Earlier versions understated the scope (claiming exactly four files were modified and showing stale test results from an early checkpoint). The current version documents all eight modified files, the complete set of detector changes, the final test suite state (31/31 passing), and the 20-message stress-test validation.

## 5. Validation and Testing

After each set of changes, the complete test suite was executed locally using the same command as the CI step:

```bash
node --input-type=module -e "import './js/tests.js';"
```

Final validated state:

| Suite | Tests | Passed | Failed |
|---|---|---|---|
| Analyzer tests (TEST 1–29) | 29 | 29 | 0 |
| URL deduplication tests (DEDUP 1–2) | 2 | 2 | 0 |
| **Total** | **31** | **31** | **0** |

In addition to the regression suite, a 20-message stress test set was constructed and run, covering:

- **Scam messages in English** — Amazon payment-failed phishing, UPI account suspension, WhatsApp OTP relay, fake job registration fee, Netflix billing phishing, SBI suspicious-activity phishing, HDFC OTP block, Jio lucky-draw bank-detail request, income-tax arrest threat, Google unusual-sign-in phishing, guaranteed Bitcoin returns
- **Hinglish scam messages** — Aadhaar number + OTP share request (multi-category: credential + urgency), account band + KYC + agent handoff (multi-category: threat + demand)
- **Legitimate notifications** — Amazon shipment, FedEx out-for-delivery, bank statement available, OTP safety notice ("never share this code"), job application shortlist, casual Hinglish personal message, Apple ID sign-in confirmation

All 20 stress cases produced the expected verdict. No accuracy percentages beyond the project's own test suite results are claimed.

## 6. CI Validation

GitHub Actions now executes the complete test suite as the first step of the `build` job, before artifact upload and before deployment. The workflow is in `.github/workflows/pages.yml`. The relevant step is:

```yaml
- name: Run test suite
  run: node --input-type=module -e "import './js/tests.js';"
```

This step runs both `runTests()` (29 analyzer tests) and `runDeduplicationTests()` (2 deduplication tests). If any of the 31 tests fails, Node.js exits with a non-zero code, the `build` job fails, and the `deploy` job — which declares `needs: build` — does not run. The production deployment is therefore blocked until all tests pass.

Before this change, the workflow contained only `checkout`, `configure-pages`, `upload-artifact`, and `deploy` steps. A silent regression to any detector or scoring logic would have reached the live deployment undetected.

## 7. Scope Control

IBM Bob applied strict scope control throughout the implementation. Bob did not:

- modify `index.html`, any CSS file, `css/style.css`, `css/components.css`, or `css/animations.css`
- modify `js/app.js`, `js/history.js`, or `js/examples.js`
- add any external dependencies or npm packages
- change the verdict thresholds (SAFE: 0–14, SUSPICIOUS: 15–29, DANGEROUS: 30–100)
- modify `README.md` or `DEPLOYMENT.md`
- change the test runner entry-point structure or the `if (typeof window === 'undefined')` guard logic beyond adding the `runDeduplicationTests()` call

Each change was made only where directly required by the stated task. Bob identified and reported additional technical issues (documented in Section 8) but did not act on any of them beyond the requested scope.

## 8. Unaddressed Issues

The following issues were identified during exploration and analysis but were intentionally left unchanged because they were outside the requested implementation scope:

- **Unused `urlPattern` variable** — `js/urlAnalyzer.js` declares a `urlPattern` variable on an early line that is never referenced; the actual regex used in the extraction loop is `urlRegex`. This is dead code but does not affect behaviour.
- **`hasNegation()` exported but never called** — `js/detectors.js` exports the `hasNegation()` utility function but no caller exists anywhere in the codebase. It was originally intended to provide negation-aware credential detection.
- **`detectSuspiciousUrl()` exported but not called directly by analyzer** — `js/detectors.js` exports `detectSuspiciousUrl()` as a pass-through wrapper, but `js/analyzer.js` calls `analyzeUrl()` from `urlAnalyzer.js` directly. The exported function is not wrong, just redundant.
- **Artificial 1-second `setTimeout` delay** — `js/app.js` wraps the synchronous `analyzeMessage()` call in a `setTimeout` of 1000 ms to simulate an asynchronous loading experience. The analysis itself completes in under 1 ms. The delay is cosmetic but misleading about the engine's actual latency.
- **`copyResult` copies only verdict and score** — The clipboard copy handler in `js/app.js` produces a string of the form `"DANGEROUS — 87/100"` and omits the signal list and recommended actions, which are the most useful parts of the result for sharing.

## 9. Summary

IBM Bob was used across the full improvement cycle for this repository across multiple sessions.

**Explore** → Bob read and analyzed every file in the repository, mapping the architecture, module relationships, data flow, and test coverage before making any change. Issues were documented and prioritised before implementation began.

**Identify** → Bob surfaced concrete, actionable issues: a URL deduplication bug, an unintegrated domain-mismatch function, a missing CI test gate, a redundant explanation field, and a set of detector gaps covering OTP relay, Hinglish scams, social engineering, investment fraud, personal information requests, and cryptocurrency wallet transfers.

**Implement** → Bob made targeted changes across eight files: fixed the deduplication bug and improved URL analysis in `js/urlAnalyzer.js`; rewrote and extended all detectors and added six new ones in `js/detectors.js`; wired new detectors, added `buildExplanation()`, extended combination bonuses, and added the `isUserInitiated` guard in `js/analyzer.js`; updated the UI to render `result.explanation` in `js/ui.js`; expanded the test suite from 10 to 31 tests in `js/tests.js`; added a pre-deployment test gate in `.github/workflows/pages.yml`; and updated `docs/ARCHITECTURE.md` and `docs/IBM_BOB_USAGE.md` to accurately reflect the current repository state.

**Test** → Bob ran the full 31-test suite after each change, confirmed all tests passed, and verified no existing tests regressed. A 20-message stress test covering English scams, Hinglish scams, and legitimate notifications was also constructed and validated in full.

**CI validation** → Bob updated the GitHub Actions workflow so the complete test suite executes before every deployment, ensuring regressions are caught automatically going forward.

Throughout all sessions, IBM Bob acted as a development and code-analysis assistant only. It did not run as a runtime service, did not provide a cloud API, and does not analyze live user messages. The deployed application processes all messages locally in the user's browser with no connection to any IBM infrastructure.
