# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Deployment

**Always deploy by uploading files directly to IONOS** via FTP or the IONOS File Manager. Do not use GitHub Pages, GitHub Actions deploy workflows, or any CI/CD push-to-host pipeline. The repository exists for version control only — publishing to production is a manual upload step.

## Running the Site

This is a **static HTML site with no build step**. To preview it:

- Open any `.html` file directly in a browser, **or**
- Use VS Code's Live Server extension (`Right-click → Open with Live Server`) for hot-reload on save.

There is no package manager, no bundler, and no test suite.

## Architecture

### Tech Stack
- **Bootstrap 5.3.0** — loaded via CDN on every page (layout, navbar, modals, carousels, forms)
- **Bootstrap Icons 1.10.5** — loaded via CDN on pages that use icons (`about.html`, `curriculum-vitae.html`, `contact.html`)
- **LiquidEther** (`@reactbits/liquid-ether` via CDN) — animated canvas background, only used on `about.html`

### Page Structure
Each page is a self-contained HTML file. There are **no shared templates or components** — the navbar HTML is copy-pasted into every page. Styles are written as inline `<style>` blocks per page rather than a shared stylesheet.

**Exception:** `cybersecurity-news.html` uses a dedicated external stylesheet (`css/news-dashboard.css`) and script (`js/news-dashboard.js`) because of its unique dark-theme dashboard design.

| Page | Purpose |
|------|---------|
| `index.html` | Landing page with featured projects |
| `about.html` | Bio, skills, culinary gallery with Bootstrap modals, + LiquidEther animated background |
| `projects.html` | All projects with Bootstrap carousels |
| `curriculum-vitae.html` | CV with Bootstrap card sections and PDF download |
| `contact.html` | Contact form (Formspree) with Bootstrap validation |
| `cybersecurity-news.html` | AI-powered cybersecurity news dashboard (dark theme, filter/search) |
| `scamazon-website.html` | Scamazon project detail page with feature demo videos |
| `platformer.html` | Knight platformer detail page; game embedded via `<iframe>` |
| `project-form.html` | Interactive Scamazon account form demo (dodging button JS trick) |
| `donate.html` | Ko-fi donations page — explains what support funds (hosting, AI API, future projects) |

### JavaScript
- `background-script.js` — configures LiquidEther on the canvas `#liquid-bg` in `about.html`. Colors, speed, and resolution are set here.
- `js/news-dashboard.js` — loads `data/news.json`, renders article cards, handles all filtering/searching/sorting for `cybersecurity-news.html`. All feed content is HTML-escaped before insertion.
- `contact.html` — inline script handling Bootstrap form validation and a post-submit redirect.
- `project-form.html` — inline script for password strength checking and cursor-dodging button behaviour.

### Media & Assets
- `img/` — project screenshots and videos organised by project subfolder (`scamazon/`, `platformer/`, `pfms/`, `pig/`, `pasta-class/`, `fish-festival/`)
- `assets/Resume.pdf` — linked from `curriculum-vitae.html` for download
- `data/news.json` — processed cybersecurity article data read by the news dashboard; updated automatically by GitHub Actions
- `favicon.svg` — site favicon

### Cybersecurity News Dashboard
The dashboard has a separate automation layer:

```
.github/
  workflows/fetch-cybersecurity-news.yml   ← GitHub Actions (runs 07:00 + 19:00 UTC daily)
  scripts/fetch_news.py                    ← Python: RSS → Claude AI → data/news.json → IONOS FTP
css/news-dashboard.css                     ← Dark-theme dashboard styles (CSS variables)
js/news-dashboard.js                       ← Vanilla JS: load JSON, render, filter, search
data/news.json                             ← Article data (8 sample articles; replaced by automation)
docs/cybersecurity-news-setup.md           ← Step-by-step setup guide
```

The Python script requires: `pip install feedparser anthropic`. GitHub Secrets needed: `ANTHROPIC_API_KEY`, `FTP_HOST`, `FTP_USER`, `FTP_PASS`, `FTP_REMOTE_PATH`. See `docs/cybersecurity-news-setup.md` for full instructions.

## Writing Style Rules

- **No em dashes**: Do not use em dashes (`—`, `&mdash;`, `&#8212;`) anywhere in HTML content, copy, labels, descriptions, or any user-facing text. Use a comma, a colon, parentheses, or restructure the sentence instead. This applies to all pages and any text added going forward.

## Known Issues / Things to Be Aware Of

- **Formspree placeholder**: `contact.html` action is `https://formspree.io/f/your_form_id` — the `your_form_id` part must be replaced with a real Formspree endpoint before the form actually submits.
- **MKV files served as MP4**: `scamazon-website.html` uses `.mkv` video files but declares `type="video/mp4"`. Browsers may not play MKV natively; converting to `.mp4` would improve compatibility.
- **Navbar brand inconsistency**: `index.html` uses "George Condrea" as the brand; all other pages use "My Portfolio".
- **No CSS file**: All custom styles are inline per-page. When adding styles that need to appear on multiple pages, they must be duplicated manually.
- **Platformer game iframe**: `platformer.html` embeds the game via `<iframe src="https://animated-unicorn-2bde72.netlify.app">` — this is an external Netlify deployment and is not part of this repository.
- **Ko-fi floating button**: Every page has an inline `<style>` block defining `.kofi-fab` for the fixed-position bottom-right button. If this style needs changing, it must be updated on each page individually (no shared CSS). Ko-fi username: `georgecondrea`.
