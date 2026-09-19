/**
 * Test Suite for Security Analyzer
 * Tests context-aware detection and scoring
 */

import { analyzeMessage } from './analyzer.js';
import { extractUrlsFromText } from './urlAnalyzer.js';

const tests = [
  // ──────────────────────────────────────────────────────────
  // EXISTING TESTS (preserved from v2 suite)
  // ──────────────────────────────────────────────────────────
  {
    name: 'TEST 1: Benign OTP Notice',
    input: 'Your OTP for login is 123456. Do not share this OTP with anyone.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 2: OTP Phishing',
    input: 'Your bank account will be blocked today. Verify immediately by sharing your OTP at https://suspicious-example.com',
    expected: { verdict: 'DANGEROUS', minScore: 40 },
    expectedSignals: ['account-threat', 'credential-request', 'suspicious-url']
  },
  {
    name: 'TEST 3: Prize Scam',
    input: 'Congratulations! You have won ₹50,000. Pay ₹999 processing fee to claim your prize today.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['prize-scam', 'financial-request']
  },
  {
    name: 'TEST 4: Suspicious Download',
    input: 'Download this APK to receive your refund. Install it immediately: https://random-domain.example/app.apk',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['suspicious-download', 'suspicious-url']
  },
  {
    name: 'TEST 5: Normal Message',
    input: 'Your order has been shipped and will arrive tomorrow.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 6: Normal Bank Alert',
    input: 'Dear Customer, your account has been credited with Rs. 114.89. Thank you for banking with us.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 7: Telecom Message',
    input: 'Your SIM recharge was successful. Your validity is extended until 30 September.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 8: Suspicious Movie Download',
    input: 'For download latest movies click on this link https://random-domain.example',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['suspicious-url', 'suspicious-download']
  },
  {
    name: 'TEST 9: Impersonation',
    input: 'Your SBI account will be suspended today. Verify your KYC immediately using this link: https://random-domain.example',
    expected: { verdict: 'DANGEROUS', minScore: 40 },
    expectedSignals: ['impersonation', 'account-threat', 'suspicious-url']
  },
  {
    name: 'TEST 10: Safety Advice',
    input: 'Never share your OTP, PIN or password with anyone. Your bank will never ask for these details.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 11: Domain Mismatch (brand mentioned, wrong domain)',
    input: 'Dear HDFC Bank customer, your account has been suspended. Verify at https://random-domain.example/verify now.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['domain-mismatch']
  },
  {
    name: 'TEST 12: No Domain Mismatch (brand matches domain)',
    input: 'Dear HDFC Bank customer, please log in at https://hdfcbank.com/login to check your statement.',
    expected: { verdict: 'SAFE', maxScore: 29 },
    expectedSignals: []
  },

  // ──────────────────────────────────────────────────────────
  // NEW TESTS — coverage for v3 detection signals
  // Phishing and social engineering
  // ──────────────────────────────────────────────────────────
  {
    name: 'TEST 13: Delivery fee phishing (payment + URL)',
    input: 'Your parcel could not be delivered. Please pay the outstanding delivery fee to reschedule. Click here: http://parcel-rescheduling.com/pay',
    expected: { verdict: 'SUSPICIOUS', minScore: 15 },
    expectedSignals: ['impersonation', 'suspicious-url']
  },
  {
    name: 'TEST 14: Account restricted + call helpline (bank fraud)',
    input: 'Dear customer, your bank account has been temporarily restricted due to suspicious activity. Please call our helpline and provide your account details.',
    expected: { verdict: 'SUSPICIOUS', minScore: 15 },
    expectedSignals: ['credential-request', 'impersonation']
  },
  {
    name: 'TEST 15: KYC SIM block (urgency + threat + credential)',
    input: 'Your SIM card will be blocked in 24 hours due to failed KYC. Contact your telecom provider and verify your Aadhaar number to prevent disconnection.',
    expected: { verdict: 'DANGEROUS', minScore: 40 },
    expectedSignals: ['urgency', 'account-threat', 'personal-info-request']
  },
  {
    name: 'TEST 16: Prize + personal info harvest',
    input: 'Win an iPhone! You have been randomly selected. Reply with your full name, address, and date of birth to claim your prize.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['prize-scam', 'personal-info-request']
  },
  {
    name: 'TEST 17: Crypto investment scam',
    input: 'Investment opportunity: Earn 40% monthly returns guaranteed. Send Bitcoin to start earning today. Limited slots available.',
    expected: { verdict: 'SUSPICIOUS', minScore: 15 },
    expectedSignals: ['financial-request', 'investment-scam']
  },
  {
    name: 'TEST 18: Card CVV request (no URL)',
    input: 'Hi, I am calling from your bank fraud department. Someone is accessing your account. Please confirm your card number and CVV to block the transaction.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['credential-request', 'impersonation', 'account-threat']
  },
  {
    name: 'TEST 19: Utility disconnection threat',
    input: 'FINAL NOTICE: Your electricity will be disconnected in 2 hours due to non-payment. Call immediately to avoid service interruption.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['urgency', 'impersonation', 'account-threat']
  },
  {
    name: 'TEST 20: Netflix billing update phishing',
    input: 'Your Netflix subscription has expired. Update your payment information to continue watching at http://netflix-billing-update.com',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['financial-request', 'impersonation', 'suspicious-url']
  },
  {
    name: 'TEST 21: SSN identity harvesting',
    input: 'We have credited a bonus to your PayPal account. To withdraw funds, please verify your identity by entering your SSN.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['credential-request', 'impersonation', 'personal-info-request']
  },
  {
    name: 'TEST 22: Apple ID locked + suspicious link',
    input: 'Your Apple ID has been locked. To restore access, verify your information at http://apple-id-restore.net',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['impersonation', 'account-threat', 'suspicious-url']
  },

  // ──────────────────────────────────────────────────────────
  // BENIGN / LEGITIMATE MESSAGE TESTS (must stay SAFE)
  // ──────────────────────────────────────────────────────────
  {
    name: 'TEST 23: Casual personal message (no security content)',
    input: 'Hi Sarah, are you free for lunch tomorrow? I was thinking of trying that new Italian place downtown.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 24: Legitimate Amazon shipment notification',
    input: 'Your Amazon order has shipped and will arrive by Thursday. Track your package at amazon.com/orders',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 25: Legitimate bank credit notification',
    input: 'Your account has been credited with Rs. 5,000. Available balance: Rs. 12,450. Thank you for banking with us.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 26: Legitimate security awareness message',
    input: 'Security reminder: Never share your OTP or PIN with anyone. Your bank will never call and ask for your password.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 27: Ordinary business email (no threat)',
    input: 'Please find the attached invoice for services rendered in October. Payment is due within 30 days.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },

  // ──────────────────────────────────────────────────────────
  // STRESS TESTS — edge cases that previously failed
  // ──────────────────────────────────────────────────────────
  {
    name: 'TEST 28: User-initiated password reset (must be SAFE)',
    input: 'Hi, you requested a password reset for your Google account. Click the link below to reset your password. This link expires in 10 minutes. If this was not you, no action is needed. accounts.google.com/reset/token123',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 29: Crypto wallet transfer scam (must be DANGEROUS)',
    input: 'URGENT: Bitcoin price will 10x in 24 hours. Transfer your savings to this wallet immediately: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['crypto-wallet-transfer', 'urgency']
  }
];

export function runTests() {
  console.log('Starting Security Analyzer Test Suite...\n');

  let passed = 0;
  let failed = 0;
  const results = [];

  for (const test of tests) {
    const result = analyzeMessage(test.input, '');

    let testPassed = true;
    const errors = [];

    if (result.verdict !== test.expected.verdict) {
      testPassed = false;
      errors.push(`Expected verdict: ${test.expected.verdict}, got: ${result.verdict}`);
    }

    if (test.expected.maxScore !== undefined && result.riskScore > test.expected.maxScore) {
      testPassed = false;
      errors.push(`Expected max score: ${test.expected.maxScore}, got: ${result.riskScore}`);
    }

    if (test.expected.minScore !== undefined && result.riskScore < test.expected.minScore) {
      testPassed = false;
      errors.push(`Expected min score: ${test.expected.minScore}, got: ${result.riskScore}`);
    }

    if (test.expectedSignals && test.expectedSignals.length > 0) {
      const actualSignalIds = result.signals.map(s => s.id);
      for (const expectedId of test.expectedSignals) {
        if (!actualSignalIds.includes(expectedId)) {
          errors.push(`Missing expected signal: ${expectedId}`);
        }
      }
    }

    if (testPassed) {
      passed++;
      results.push({
        name: test.name,
        status: '✓ PASS',
        score: result.riskScore,
        verdict: result.verdict,
        signals: result.signals.map(s => s.id).join(', ')
      });
    } else {
      failed++;
      results.push({
        name: test.name,
        status: '✗ FAIL',
        score: result.riskScore,
        verdict: result.verdict,
        signals: result.signals.map(s => s.id).join(', '),
        errors: errors.join('; ')
      });
    }
  }

  console.log('\n========== TEST RESULTS ==========\n');
  for (const result of results) {
    console.log(`${result.status} - ${result.name}`);
    console.log(`  Verdict: ${result.verdict} | Score: ${result.score}`);
    if (result.signals) {
      console.log(`  Signals: ${result.signals || '(none)'}`);
    }
    if (result.errors) {
      console.log(`  Errors: ${result.errors}`);
    }
    console.log();
  }

  console.log(`\n========== SUMMARY ==========`);
  console.log(`Total: ${tests.length} | Passed: ${passed} | Failed: ${failed}`);
  console.log(`Success Rate: ${((passed / tests.length) * 100).toFixed(1)}%`);

  return { passed, failed, total: tests.length, results };
}

function runDeduplicationTests() {
  console.log('\n========== DEDUPLICATION TESTS ==========\n');
  let passed = 0;
  let failed = 0;

  const repeated = extractUrlsFromText('Check https://bit.ly/scam and also https://bit.ly/scam again.');
  const dedup1Pass = repeated.length === 1;
  if (dedup1Pass) {
    passed++;
    console.log('✓ PASS - DEDUP 1: Same URL repeated twice returns one entry');
    console.log(`  Returned: ${repeated.length} URL(s)`);
  } else {
    failed++;
    console.log('✗ FAIL - DEDUP 1: Same URL repeated twice returns one entry');
    console.log(`  Expected 1, got: ${repeated.length}`);
  }
  console.log();

  const different = extractUrlsFromText('Visit https://bit.ly/link1 and also https://example.com/page.');
  const dedup2Pass = different.length === 2;
  if (dedup2Pass) {
    passed++;
    console.log('✓ PASS - DEDUP 2: Two different URLs returns two entries');
    console.log(`  Returned: ${different.length} URL(s)`);
  } else {
    failed++;
    console.log('✗ FAIL - DEDUP 2: Two different URLs returns two entries');
    console.log(`  Expected 2, got: ${different.length}`);
  }
  console.log();

  console.log(`Deduplication: Passed: ${passed} | Failed: ${failed}`);
  return { passed, failed };
}

// Run tests if executed directly
if (typeof window === 'undefined') {
  // Node.js environment
  const analyzerResults = runTests();
  const dedupResults = runDeduplicationTests();
  const totalPassed = analyzerResults.passed + dedupResults.passed;
  const totalFailed = analyzerResults.failed + dedupResults.failed;
  console.log(`\n========== OVERALL SUMMARY ==========`);
  console.log(`Total: ${analyzerResults.total + 2} | Passed: ${totalPassed} | Failed: ${totalFailed}`);
  console.log(`Success Rate: ${((totalPassed / (analyzerResults.total + 2)) * 100).toFixed(1)}%`);
}
