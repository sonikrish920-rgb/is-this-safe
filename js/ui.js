const verdictClasses = {
  SAFE: 'safe',
  SUSPICIOUS: 'warning',
  DANGEROUS: 'danger'
};

export function renderHistory(entries) {
  const container = document.getElementById('historyList');
  if (!container) return;

  if (!entries.length) {
    container.innerHTML = '<p class="empty-state">No scans yet.</p>';
    return;
  }

  container.innerHTML = entries
    .map((entry) => {
      const verdictClass = verdictClasses[entry.verdict] || 'safe';
      return `
        <div class="history-item">
          <button type="button" data-history-id="${entry.id}">
            <span class="history-badge ${verdictClass}">${entry.verdict}</span>
            <span class="history-meta">
              <span>${entry.timestamp}</span>
            </span>
            <span class="history-score">${entry.riskScore}</span>
          </button>
        </div>
      `;
    })
    .join('');
}

export function replayHistoryEntry(entry) {
  if (!entry) return;

  const resultsPanel = document.getElementById('resultsPanel');
  const badge = document.getElementById('verdictBadge');
  if (badge) badge.textContent = entry.verdict;
  if (resultsPanel) {
    resultsPanel.classList.remove('hidden');
  }

  renderResult(entry);
}

export function updateGauge(riskScore, verdict) {
  const progress = document.getElementById('gaugeProgress');
  const value = document.getElementById('riskScoreValue');
  const badge = document.getElementById('verdictBadge');
  const circleRadius = 60;
  const circumference = 2 * Math.PI * circleRadius;

  const safeColor = '#10b981';
  const warningColor = '#f59e0b';
  const dangerColor = '#ef4444';

  const colorMap = {
    SAFE: safeColor,
    SUSPICIOUS: warningColor,
    DANGEROUS: dangerColor
  };

  progress.style.stroke = colorMap[verdict] || safeColor;
  progress.style.strokeDasharray = String(circumference);
  progress.style.strokeDashoffset = String(circumference - (riskScore / 100) * circumference);
  value.textContent = String(riskScore);
  badge.className = `verdict-badge ${verdictClasses[verdict] || 'safe'}`;
  badge.textContent = verdict;
}

export function renderResult(result) {
  const resultsPanel = document.getElementById('resultsPanel');
  const summary = document.getElementById('resultSummary');
  const signalList = document.getElementById('signalList');
  const explanation = document.getElementById('explanationText');
  const actionsList = document.getElementById('actionsList');

  resultsPanel.classList.remove('is-safe', 'is-warning', 'is-danger');
  resultsPanel.classList.add(`is-${verdictClasses[result.verdict].toLowerCase() === 'warning' ? 'warning' : verdictClasses[result.verdict]}`);

  summary.textContent = result.summary;
  explanation.textContent = result.explanation || result.summary;

  signalList.innerHTML = result.signals.length
    ? result.signals
        .map(
          (signal) => `
          <li class="signal-item ${signal.severity}">
            <span class="signal-text"><strong>${signal.label}:</strong> ${signal.description}</span>
          </li>
        `
        )
        .join('')
    : '<li class="signal-item low"><span class="signal-text">No major signals were detected.</span></li>';

  actionsList.innerHTML = result.actions
    .map((action) => `<li class="action-item">${action}</li>`)
    .join('');

  updateGauge(result.riskScore, result.verdict);
  resultsPanel.classList.remove('hidden');
}

export function setLoadingState(isLoading) {
  const resultsPanel = document.getElementById('resultsPanel');
  if (!resultsPanel) return;

  if (isLoading) {
    resultsPanel.classList.remove('hidden');
    resultsPanel.classList.add('is-loading');
    resultsPanel.querySelector('#riskScoreValue').textContent = '...';
    resultsPanel.querySelector('#resultSummary').textContent = 'Scanning signals...';
  } else {
    resultsPanel.classList.remove('is-loading');
  }
}
