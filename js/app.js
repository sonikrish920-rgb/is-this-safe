import { analyzeMessage } from './analyzer.js';
import { examples } from './examples.js';
import { clearHistory, getHistory, saveHistoryEntry } from './history.js';
import { renderHistory, renderResult, replayHistoryEntry, setLoadingState } from './ui.js';

const messageInput = document.getElementById('messageInput');
const urlInput = document.getElementById('urlInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const validationMessage = document.getElementById('validationMessage');
const resultsPanel = document.getElementById('resultsPanel');
const howItWorksBtn = document.getElementById('howItWorksBtn');
const aboutSection = document.getElementById('aboutSection');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');
const copyResultBtn = document.getElementById('copyResultBtn');
const analyzeAnotherBtn = document.getElementById('analyzeAnotherBtn');

function validateInput() {
  const text = messageInput.value.trim();
  if (!text.length) {
    validationMessage.textContent = 'Please paste a message or example before scanning.';
    return false;
  }

  if (text.length < 10) {
    validationMessage.textContent = 'Enter a little more text so the detector has enough context.';
    return false;
  }

  validationMessage.textContent = '';
  return true;
}

async function runScan() {
  if (!validateInput()) return;

  setLoadingState(true);

  try {
    const result = analyzeMessage(messageInput.value, urlInput.value);

    setTimeout(() => {
      renderResult(result);
      setLoadingState(false);

      const timestamp = new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      const historyEntry = {
        id: Date.now(),
        message: messageInput.value,
        url: urlInput.value,
        verdict: result.verdict,
        riskScore: result.riskScore,
        timestamp,
        summary: result.summary,
        signals: result.signals,
        actions: result.actions,
        explanation: result.summary
      };

      saveHistoryEntry(historyEntry);
      renderHistory(getHistory());
    }, 1000);
  } catch (error) {
    setLoadingState(false);
    validationMessage.textContent = 'Something went wrong while analyzing the message. Please try again.';
    console.error(error);
  }
}

function loadExample(key) {
  const example = examples[key];
  if (!example) return;

  messageInput.value = example.text;
  urlInput.value = example.url || '';
  validationMessage.textContent = '';
  runScan();
}

function resetScanner() {
  resultsPanel.classList.add('hidden');
  messageInput.value = '';
  urlInput.value = '';
  validationMessage.textContent = '';
}

async function copyResult() {
  const text = `${document.getElementById('verdictBadge').textContent} — ${document.getElementById('riskScoreValue').textContent}/100`;

  try {
    await navigator.clipboard.writeText(text);
    copyResultBtn.textContent = 'Copied';
    setTimeout(() => {
      copyResultBtn.textContent = 'Copy Result';
    }, 1200);
  } catch {
    copyResultBtn.textContent = 'Copy unavailable';
  }
}

analyzeBtn.addEventListener('click', runScan);

messageInput.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
    runScan();
  }
});

howItWorksBtn.addEventListener('click', () => {
  aboutSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

clearHistoryBtn.addEventListener('click', () => {
  clearHistory();
  renderHistory([]);
});

copyResultBtn.addEventListener('click', copyResult);
analyzeAnotherBtn.addEventListener('click', resetScanner);

document.querySelectorAll('.example-button').forEach((button) => {
  button.addEventListener('click', () => loadExample(button.dataset.example));
});

document.getElementById('historyList').addEventListener('click', (event) => {
  const button = event.target.closest('[data-history-id]');
  if (!button) return;

  const entry = getHistory().find((item) => String(item.id) === String(button.dataset.historyId));
  if (!entry) return;

  replayHistoryEntry(entry);
  messageInput.value = entry.message || '';
  urlInput.value = entry.url || '';
});

renderHistory(getHistory());
