const STORAGE_KEY = 'is-this-safe-history';

export function getHistory() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveHistoryEntry(entry) {
  const history = getHistory();
  const normalizedEntry = {
    ...entry,
    id: entry.id || Date.now(),
    timestamp: entry.timestamp || new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
  };

  const next = [normalizedEntry, ...history].slice(0, 5);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  return next;
}

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEY);
}
