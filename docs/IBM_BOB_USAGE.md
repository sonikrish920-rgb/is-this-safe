# IBM Bob Usage

## 1. Purpose

IBM Bob was used to inspect, improve, and validate the existing "Is This Safe?" repository. The repository contained a working client-side security-awareness application. Bob's role in this session was to perform a thorough read-only exploration, identify concrete issues, implement a defined set of targeted fixes, validate those fixes through the existing test suite, and document the work.

IBM Bob is not the runtime threat-analysis engine for the deployed application. The live app runs as a client-side static web application using JavaScript pattern checks.

## 2. Repository Exploration

Bob performed a complete read-only exploration of the repository before making any changes. The following areas were inspected:

- **Project architecture** — static frontend-only application with no backend, no build step, and no package dependencies; deployed on Vercel and GitHub Pages
- **Frontend structure** — `index.html` single-page shell, three CSS files (`style.css`, `components.css`, `animations.css`), and ES module JavaScript
- **Analyzer flow** — `js/analyzer.js` orchestrates detection, scoring, combination bonuses, benign signal reductions, verdict calculation, and action generation
- **URL analysis** — `js/urlAnalyzer.js` extracts URLs from free text and performs domain-level analysis including shortener detection, TLD checks, typosquatting, and IP address detection
- **Detectors** — `js/detectors.js` contains eight context-aware detectors: urgency, credential request, financial request, prize scam, impersonation, suspicious download, account threat, and benign signals
- **Existing tests** — `js/tests.js` contained a custom 10-test suite covering benign and malicious scenarios, runnable via Node.js
- **GitHub Actions workflow** — `.github/workflows/pages.yml` deployed to GitHub Pages on push to `main` but did not execute any tests before deployment
- **Existing technical issues** — Bob identified several bugs and areas of technical debt during exploration, documented below

## 3. Issues Identified

Bob identified the following issues that were directly relevant to the implemented work:

- **URL deduplication bug in `extractUrlsFromText()`** — `js/urlAnalyzer.js` maintained a `urls` array of strings but the deduplication check read `u.url === normalized`, where `u` is a plain string and `u.url` is always `undefined`. As a result, the same URL appearing multiple times in a message was pushed multiple times, potentially inflating the risk score.

- **`checkDomainMismatch()` was not integrated into the analyzer flow** — `js/urlAnalyzer.js` contained a complete, exported `checkDomainMismatch()` function that detects when a message mentions a known brand (e.g., HDFC, SBI, Google) but the URL does not point to that brand's legitimate domain. Despite being fully implemented, this function was never called anywhere in the codebase.

- **GitHub Actions did not execute the test suite before deployment** — The workflow deployed the site directly after checkout with no test step. A regression introduced to any detection logic would be deployed silently.

## 4. Changes Implemented Using IBM Bob

Exactly four files were modified. No other files were changed.

### `js/urlAnalyzer.js` — URL deduplication fix

Changed the deduplication check in `extractUrlsFromText()` from `u.url === normalized` to `u === normalized`. Since `urls` is an array of strings, this corrects the comparison so duplicate normalized URLs are properly filtered before being added to the result.

### `js/analyzer.js` — domain mismatch integration

- Added `checkDomainMismatch` to the import from `./urlAnalyzer.js`
- Inside the existing URL analysis loop, after `analyzeUrl()` runs for each URL, added a call to `checkDomainMismatch(urlAnalysis.domain, messageText)`. If it returns `true`, the score increases by 10 and a `domain-mismatch` signal (`severity: 'high'`) is added to the result. All existing scoring and detection logic was left unchanged.

### `js/tests.js` — new tests for domain mismatch and URL deduplication

- Added `import { extractUrlsFromText } from './urlAnalyzer.js'`
- Added **TEST 11** — a message mentioning HDFC Bank with a non-HDFC URL; expects `DANGEROUS`, `minScore: 30`, and the `domain-mismatch` signal present
- Added **TEST 12** — a message mentioning HDFC Bank with a legitimate `hdfcbank.com` URL; expects `SAFE`, `maxScore: 29`, and no `domain-mismatch` signal
- Added `runDeduplicationTests()` — a separate function with two direct tests of `extractUrlsFromText`: one verifying a repeated URL is returned only once, and one verifying two distinct URLs are both returned
- Updated the `if (typeof window === 'undefined')` entry block to call both `runTests()` and `runDeduplicationTests()` and print a combined overall summary

### `.github/workflows/pages.yml` — test execution before deployment

Added one step to the `build` job, between `Check out repository` and `Setup Pages`:

```yaml
- name: Run test suite
  run: node --input-type=module -e "import './js/tests.js';"
```

Importing the file triggers the `if (typeof window === 'undefined')` block, which calls both `runTests()` and `runDeduplicationTests()`. If any test fails, Node exits with a non-zero code and the deployment step does not run.

## 5. Validation and Testing

After implementation, the complete test suite was executed locally using the same command as the CI step:

```bash
node --input-type=module -e "import './js/tests.js';"
```

Results:

| # | Test | Verdict | Score | Result |
|---|---|---|---|---|
| 1 | Benign OTP Notice | SAFE | 0 | PASS |
| 2 | OTP Phishing | DANGEROUS | 77 | PASS |
| 3 | Prize Scam | DANGEROUS | 30 | PASS |
| 4 | Suspicious Download | SUSPICIOUS | 29 | PASS |
| 5 | Normal Message | SAFE | 0 | PASS |
| 6 | Normal Bank Alert | SAFE | 11 | PASS |
| 7 | Telecom Message | SAFE | 0 | PASS |
| 8 | Suspicious Movie Download | SUSPICIOUS | 23 | PASS |
| 9 | Impersonation | DANGEROUS | 63 | PASS |
| 10 | Safety Advice | SAFE | 0 | PASS |
| 11 | Domain Mismatch (wrong domain) | DANGEROUS | 63 | PASS |
| 12 | No Domain Mismatch (correct domain) | SAFE | 7 | PASS |
| DEDUP 1 | Repeated URL returns one entry | — | — | PASS |
| DEDUP 2 | Two different URLs return two entries | — | — | PASS |

**Total: 14 tests — 14 passed — 0 failed — 100% success rate**

All 10 original tests continued to pass without modification.

## 6. CI Validation

GitHub Actions now executes the complete test suite as the first step of the `build` job, before artifact upload and before deployment. The test step runs both the 12 analyzer tests and the 2 URL deduplication tests. If any test fails, the `build` job exits with a non-zero code, the `deploy` job (which `needs: build`) does not run, and the deployment is blocked.

## 7. Scope Control

IBM Bob was explicitly instructed to apply strict scope control throughout the implementation. Bob did not:

- modify UI, CSS, HTML, layout, colors, animations, or visual behavior
- add any dependencies or libraries
- refactor code unrelated to the three tasks
- modify unrelated files
- change existing detection rules, scoring weights, or verdict thresholds (other than the new `domain-mismatch` signal added by the integration)
- modify documentation during the implementation phase

Each change was made only where directly required by the stated task. Bob reported unrelated issues but did not act on them.

## 8. Unaddressed Issues

The following issues were identified during exploration but were intentionally left unchanged because they were outside the requested implementation scope:

- **Unused `urlPattern` variable** — `js/urlAnalyzer.js` line 12 declares `urlPattern` which is never used; the actual regex used in the loop is `urlRegex` defined on line 15
- **`hasNegation()` exported but never called** — `js/detectors.js` exports `hasNegation()` but no caller exists anywhere in the codebase
- **`detectSuspiciousUrl()` exported but not used by `analyzer.js`** — `js/detectors.js` exports this function but the analyzer calls `analyzeUrl()` from `urlAnalyzer.js` directly
- **Artificial 1-second `setTimeout` delay** — `js/app.js` wraps synchronous analysis in a `setTimeout(1000)` to simulate async behavior; the analysis completes in under 1ms
- **`explanation` and `summary` are identical in the result object** — `js/app.js` saves both `summary` and `explanation` with the same value; `js/ui.js` renders both to separate DOM elements with identical text
- **`copyResult` copies only verdict and score** — the clipboard copy in `js/app.js` produces only `"DANGEROUS — 87/100"` and omits signals and recommended actions

## 9. Summary

IBM Bob was used across the full improvement cycle for this repository:

**Explore** → Bob read and analyzed every file in the repository, mapping the architecture, module relationships, data flow, and test coverage before making any change.

**Identify** → Bob surfaced concrete, actionable issues from the exploration, distinguishing between issues in scope for the requested tasks and unrelated technical debt.

**Implement** → Bob made the minimum changes required for each task: one-line deduplication fix, domain mismatch wiring in the analyzer, new tests, and a CI test step.

**Test** → Bob ran the full test suite after each change, confirmed all 14 tests passed, and verified no existing tests regressed.

**CI validation** → Bob updated the GitHub Actions workflow so the complete test suite executes before every deployment, ensuring regressions are caught automatically going forward.
