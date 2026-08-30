/**
 * Test Suite for Security Analyzer
 * Tests context-aware detection and scoring
 */

import { analyzeMessage } from './analyzer.js';

const tests = [
  {
    name: 'TEST 1: Benign OTP Notice',
    input: 'Your OTP for login is 123456. Do not share this OTP with anyone.',
    expected: { verdict: 'SAFE', maxScore: 14 },
    expectedSignals: []
  },
  {
    name: 'TEST 2: OTP Phishing',
    input: 'Your bank account will be blocked today. Verify immediately by sharing your OTP at https://suspicious-example.com',
    expected: { verdict: 'DANGEROUS', minScore: 50 },
    expectedSignals: ['account-threat', 'credential-request', 'suspicious-url']
  },
  {
    name: 'TEST 3: Prize Scam',
    input: 'Congratulations! You have won ₹50,000. Pay ₹999 processing fee to claim your prize today.',
    expected: { verdict: 'DANGEROUS', minScore: 30 },
    expectedSignals: ['prize-scam', 'financial-request', 'urgency']
  },
  {
    name: 'TEST 4: Suspicious Download',
    input: 'Download this APK to receive your refund. Install it immediately: https://random-domain.example/app.apk',
    expected: { verdict: 'SUSPICIOUS', minScore: 20 },
    expectedSignals: ['suspicious-download', 'suspicious-url', 'urgency']
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
    expected: { verdict: 'SUSPICIOUS', minScore: 15 },
    expectedSignals: ['suspicious-url']
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

    // Check verdict
    if (result.verdict !== test.expected.verdict) {
      testPassed = false;
      errors.push(`Expected verdict: ${test.expected.verdict}, got: ${result.verdict}`);
    }

    // Check score range
    if (test.expected.maxScore && result.riskScore > test.expected.maxScore) {
      testPassed = false;
      errors.push(`Expected max score: ${test.expected.maxScore}, got: ${result.riskScore}`);
    }

    if (test.expected.minScore && result.riskScore < test.expected.minScore) {
      testPassed = false;
      errors.push(`Expected min score: ${test.expected.minScore}, got: ${result.riskScore}`);
    }

    // Check signals (if defined)
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

  // Print results
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

// Run tests if executed directly
if (typeof window === 'undefined') {
  // Node.js environment
  runTests();
}
