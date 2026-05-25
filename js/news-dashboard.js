/**
 * Cybersecurity News Dashboard
 * George Condrea — Portfolio Project
 *
 * Loads data/news.json and renders a filterable, searchable
 * article card layout. All external data is HTML-escaped before
 * insertion to prevent XSS from feed content.
 */

'use strict';

/* ─── State ─────────────────────────────────────────────────── */
const state = {
  allArticles:      [],
  filteredArticles: [],
  filters: {
    search:   '',
    category: '',
    severity: '',
    sort:     'newest',
  },
};

/* ─── DOM references ─────────────────────────────────────────── */
const $ = id => document.getElementById(id);

const articlesGrid   = $('articlesGrid');
const searchInput    = $('searchInput');
const categoryFilter = $('categoryFilter');
const severityFilter = $('severityFilter');
const sortFilter     = $('sortFilter');
const resetBtn       = $('resetBtn');
const resultsCount   = $('resultsCount');
const lastUpdatedEl  = $('lastUpdated');

const statEls = {
  total:    $('statTotal'),
  critical: $('statCritical'),
  high:     $('statHigh'),
  medium:   $('statMedium'),
  low:      $('statLow'),
};

/* ─── Security helper ────────────────────────────────────────── */
function escapeHtml(str) {
  if (str == null) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

/* ─── Formatting helpers ─────────────────────────────────────── */
function formatDate(dateStr) {
  if (!dateStr) return 'Unknown date';
  try {
    return new Date(dateStr).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'short', year: 'numeric',
    });
  } catch {
    return dateStr;
  }
}

function severityIcon(sev) {
  const icons = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵' };
  return icons[sev] ?? '⚪';
}

function severityClass(sev) {
  return `sev-${(sev || 'low').toLowerCase()}`;
}

/* ─── Card rendering ─────────────────────────────────────────── */
function buildCard(article) {
  const sevClass  = severityClass(article.severity);
  const tagsHtml  = (article.tags || [])
    .map(t => `<span class="tag-chip">#${escapeHtml(t)}</span>`)
    .join('');

  // Build the card as a DOM node to guarantee safe insertion
  const col = document.createElement('div');
  col.className = 'col-md-6 col-xl-4 mb-4';

  // Store filter data on the wrapper so applyFilters can read it
  col.dataset.category = article.category || '';
  col.dataset.severity = article.severity || '';
  col.dataset.date     = article.publishedDate || '';

  col.innerHTML = `
    <div class="news-card ${sevClass} h-100">
      <div class="card-inner">

        <!-- Badges -->
        <div class="badge-row">
          <span class="sev-badge ${sevClass}">
            ${severityIcon(article.severity)} ${escapeHtml(article.severity)}
          </span>
          <span class="cat-badge">${escapeHtml(article.category)}</span>
        </div>

        <!-- Title -->
        <h3 class="card-title">${escapeHtml(article.title)}</h3>

        <!-- Meta -->
        <div class="card-meta">
          <span class="source-name">${escapeHtml(article.source)}</span>
          <span class="meta-sep"></span>
          <span>${formatDate(article.publishedDate)}</span>
        </div>

        <!-- AI Summary -->
        <div class="summary-block">
          <div class="block-label">📋 AI Summary</div>
          <p class="summary-text">${escapeHtml(article.summary)}</p>
        </div>

        <!-- Why it matters -->
        <div class="matters-block">
          <div class="block-label">⚡ Why This Matters</div>
          <p class="matters-text">${escapeHtml(article.whyItMatters)}</p>
        </div>

        <!-- Tags -->
        ${tagsHtml ? `<div class="tags-row">${tagsHtml}</div>` : ''}

        <!-- Footer -->
        <div class="card-footer-row">
          <span class="ai-label">🤖 AI-generated summary</span>
          <a href="${escapeHtml(article.originalUrl)}"
             target="_blank"
             rel="noopener noreferrer"
             class="btn-read">Read Article →</a>
        </div>

      </div>
    </div>`;

  return col;
}

function renderCards(articles) {
  articlesGrid.innerHTML = '';

  if (!articles.length) {
    const empty = document.createElement('div');
    empty.className = 'col-12';
    empty.innerHTML = `
      <div class="state-box">
        <div class="state-icon">🔍</div>
        <h5>No articles match your filters</h5>
        <p>Try adjusting the search term or clearing the category and severity filters.</p>
      </div>`;
    articlesGrid.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  articles.forEach(a => fragment.appendChild(buildCard(a)));
  articlesGrid.appendChild(fragment);
}

/* ─── Stats ──────────────────────────────────────────────────── */
function updateStats(articles) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  articles.forEach(a => {
    if (a.severity in counts) counts[a.severity]++;
  });

  if (statEls.total)    statEls.total.textContent    = state.allArticles.length;
  if (statEls.critical) statEls.critical.textContent = counts.Critical;
  if (statEls.high)     statEls.high.textContent     = counts.High;
  if (statEls.medium)   statEls.medium.textContent   = counts.Medium;
  if (statEls.low)      statEls.low.textContent      = counts.Low;
}

/* ─── Filtering & sorting ────────────────────────────────────── */
function applyFilters() {
  const { search, category, severity, sort } = state.filters;
  const q = search.trim().toLowerCase();

  let result = state.allArticles.filter(a => {
    if (q) {
      const haystack = [
        a.title, a.summary, a.source, a.category, a.whyItMatters,
        ...(a.tags || []),
      ].join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    if (category && a.category !== category) return false;
    if (severity && a.severity !== severity) return false;
    return true;
  });

  result.sort((a, b) => {
    const da = new Date(a.publishedDate);
    const db = new Date(b.publishedDate);
    return sort === 'oldest' ? da - db : db - da;
  });

  state.filteredArticles = result;
  renderCards(result);

  if (resultsCount) {
    resultsCount.textContent = result.length === state.allArticles.length
      ? `Showing all ${result.length} article${result.length !== 1 ? 's' : ''}`
      : `Showing ${result.length} of ${state.allArticles.length} articles`;
  }
}

/* ─── Category dropdown ──────────────────────────────────────── */
function populateCategoryDropdown(articles) {
  if (!categoryFilter) return;
  const cats = [...new Set(articles.map(a => a.category).filter(Boolean))].sort();
  cats.forEach(cat => {
    const opt = document.createElement('option');
    opt.value       = cat;
    opt.textContent = cat;
    categoryFilter.appendChild(opt);
  });
}

/* ─── Reset ──────────────────────────────────────────────────── */
function resetFilters() {
  state.filters = { search: '', category: '', severity: '', sort: 'newest' };
  if (searchInput)    searchInput.value    = '';
  if (categoryFilter) categoryFilter.value = '';
  if (severityFilter) severityFilter.value = '';
  if (sortFilter)     sortFilter.value     = 'newest';
  syncStatChips('');
  applyFilters();
}

/* ─── Stat chip highlighting ─────────────────────────────────── */
function syncStatChips(activeSeverity) {
  document.querySelectorAll('.stat-chip[data-sev]').forEach(chip => {
    chip.classList.toggle('chip-active', chip.dataset.sev === activeSeverity);
  });
}

/* ─── Event listeners ────────────────────────────────────────── */
function setupEventListeners() {
  searchInput?.addEventListener('input', e => {
    state.filters.search = e.target.value;
    applyFilters();
  });

  categoryFilter?.addEventListener('change', e => {
    state.filters.category = e.target.value;
    applyFilters();
  });

  severityFilter?.addEventListener('change', e => {
    state.filters.severity = e.target.value;
    syncStatChips(e.target.value);
    applyFilters();
  });

  sortFilter?.addEventListener('change', e => {
    state.filters.sort = e.target.value;
    applyFilters();
  });

  resetBtn?.addEventListener('click', resetFilters);

  // Stat chip quick-filter (toggle on click)
  document.querySelectorAll('.stat-chip[data-sev]').forEach(chip => {
    chip.addEventListener('click', () => {
      const sev = chip.dataset.sev;
      const isActive = state.filters.severity === sev;
      state.filters.severity = isActive ? '' : sev;
      if (severityFilter) severityFilter.value = isActive ? '' : sev;
      syncStatChips(isActive ? '' : sev);
      applyFilters();
    });
  });

  // "All" chip resets severity filter
  $('chipAll')?.addEventListener('click', () => {
    state.filters.severity = '';
    if (severityFilter) severityFilter.value = '';
    syncStatChips('');
    applyFilters();
  });
}

/* ─── Data loading ───────────────────────────────────────────── */
async function loadNews() {
  // Show loading state
  articlesGrid.innerHTML = `
    <div class="col-12">
      <div class="state-box">
        <div class="spinner-border text-secondary mb-3" style="width:2rem;height:2rem;" role="status">
          <span class="visually-hidden">Loading…</span>
        </div>
        <p>Loading cybersecurity intelligence…</p>
      </div>
    </div>`;

  try {
    const res = await fetch('data/news.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    state.allArticles = Array.isArray(data.articles) ? data.articles : [];

    // Last updated timestamp
    if (lastUpdatedEl && data.lastUpdated) {
      const d = new Date(data.lastUpdated);
      lastUpdatedEl.textContent = d.toLocaleString('en-GB', {
        day: 'numeric', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
      }) + ' UTC';
    }

    updateStats(state.allArticles);
    populateCategoryDropdown(state.allArticles);
    applyFilters();

  } catch (err) {
    console.error('Failed to load news.json:', err);
    articlesGrid.innerHTML = `
      <div class="col-12">
        <div class="state-box">
          <div class="state-icon">⚠️</div>
          <h5>Could not load articles</h5>
          <p>
            Make sure you are running this page from a web server
            (e.g. VS Code Live Server) rather than directly from the file system,
            and that <code>data/news.json</code> exists.
          </p>
        </div>
      </div>`;
  }
}

/* ─── Init ───────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  loadNews();
});
