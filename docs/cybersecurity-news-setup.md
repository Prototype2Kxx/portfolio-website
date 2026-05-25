# Cybersecurity News Dashboard — Setup Guide

This guide walks you through connecting the automation pipeline so your
portfolio's Security News page updates itself automatically twice a day.

---

## Overview of the Pipeline

```
GitHub repo (code + data/news.json)
      │
      ▼
GitHub Actions (free, runs on GitHub's servers)
      │  Python script runs at 07:00 and 19:00 UTC
      │
      ▼
RSS Feeds → Claude AI API → updated data/news.json
      │
      ▼
FTP upload → IONOS server → your live website
```

---

## Prerequisites

| What you need | Where to get it |
|---|---|
| GitHub account (free) | https://github.com |
| Anthropic API key | https://console.anthropic.com |
| IONOS FTP credentials | IONOS control panel (see Step 3) |

---

## Step 1 — Push Your Portfolio to GitHub

If you have not already, create a GitHub repository and push your portfolio files.

```bash
git init
git add .
git commit -m "Initial portfolio commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git push -u origin main
```

> **Tip:** Make the repository **public** if you want to share it as a portfolio.
> GitHub Actions is free for both public and private repositories.

---

## Step 2 — Get Your Anthropic API Key

1. Go to https://console.anthropic.com
2. Sign in or create a free account
3. Navigate to **API Keys** → **Create Key**
4. Copy the key — you will need it in Step 4

> **Cost estimate:** The script uses Claude Haiku (cheapest model).
> Processing up to 10 articles twice daily costs approximately
> **$0.01–$0.05 per day** at current Haiku pricing.
> Anthropic provides $5 free credit to new accounts.

---

## Step 3 — Find Your IONOS FTP Credentials

1. Log in to your IONOS control panel at https://my.ionos.co.uk
2. Go to **Hosting** → your hosting package → **FTP**
3. Note down:
   - **FTP Host** (e.g. `access.your-server.ionos.com`)
   - **FTP Username** (usually your domain or a sub-account username)
   - **FTP Password** (set or reset it here if you do not know it)
4. The remote path for `news.json` is the path on the IONOS server
   relative to the FTP root. For most IONOS setups this is:
   ```
   /data/news.json
   ```
   If your website files are in a subdirectory (e.g. `/public_html/`):
   ```
   /public_html/data/news.json
   ```
   You can confirm the correct path using an FTP client like **FileZilla**.

---

## Step 4 — Add GitHub Secrets

Secrets keep your credentials out of the code. They are encrypted and only
exposed to the GitHub Actions runner.

1. In your GitHub repository, go to **Settings → Secrets and variables → Actions**
2. Click **New repository secret** and add each of the following:

| Secret Name | Value |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key from Step 2 |
| `FTP_HOST` | IONOS FTP hostname from Step 3 |
| `FTP_USER` | IONOS FTP username from Step 3 |
| `FTP_PASS` | IONOS FTP password from Step 3 |
| `FTP_REMOTE_PATH` | Remote path, e.g. `/data/news.json` |

---

## Step 5 — Run the Workflow for the First Time

1. In your GitHub repository, click the **Actions** tab
2. In the left sidebar, click **Fetch Cybersecurity News**
3. Click **Run workflow** → **Run workflow** (manual trigger)
4. Watch the run — green tick means everything worked ✓
5. If it fails, click the failed step to read the logs

> On the first run the script will process up to 10 articles from each feed
> and upload a fresh `data/news.json` to your IONOS server.

---

## Step 6 — Verify the Live Site

1. Open your live portfolio site: `https://your-domain.com/cybersecurity-news.html`
2. The dashboard should load real articles (not the sample data)
3. The "Last updated" timestamp should reflect the run time

If articles are not appearing:
- Check that `FTP_REMOTE_PATH` points to the correct location on IONOS
- Verify the file exists on IONOS using FileZilla or the IONOS File Manager
- Check the browser console for any fetch errors

---

## Monitoring the Workflow

- **GitHub Actions tab** shows every run with logs
- Failed runs send a notification email to your GitHub account email address
- The workflow runs automatically at 07:00 and 19:00 UTC
- You can re-run any failed job manually from the Actions tab

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| `ANTHROPIC_API_KEY` error | Secret not set or incorrect | Re-add the secret in GitHub Settings |
| FTP connection refused | Wrong host or credentials | Double-check IONOS FTP settings; try FileZilla first |
| FTP upload fails on path | Wrong `FTP_REMOTE_PATH` | Confirm path with FileZilla |
| No new articles added | All current feed articles already exist in news.json | Normal — check back after new articles are published |
| AI returns invalid JSON | Rare Claude formatting issue | The script skips that article and continues; check logs |
| `data/news.json` not updating on site | File uploaded but browser cached | Hard-refresh (Ctrl+Shift+R) |

---

## Adding or Removing RSS Feeds

Edit the `RSS_FEEDS` list in `.github/scripts/fetch_news.py`:

```python
RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews", "name": "The Hacker News"},
    # Add a new feed:
    {"url": "https://www.schneier.com/blog/atom.xml",      "name": "Schneier on Security"},
]
```

Other good cybersecurity RSS feeds:
- Schneier on Security: `https://www.schneier.com/blog/atom.xml`
- SecurityWeek: `https://feeds.feedburner.com/SecurityWeek`
- Threatpost: `https://threatpost.com/feed/`
- US-CERT Alerts: `https://www.cisa.gov/uscert/ncas/alerts.xml`
- Naked Security (Sophos): `https://nakedsecurity.sophos.com/feed/`

---

## Adjusting Update Frequency

Edit the cron schedule in `.github/workflows/fetch-cybersecurity-news.yml`:

```yaml
schedule:
  - cron: '0 7 * * *'   # 07:00 UTC daily
  - cron: '0 19 * * *'  # 19:00 UTC daily
```

Cron syntax: `minute hour day month weekday`
- Once daily at 8am UTC: `0 8 * * *`
- Three times daily: add a third `- cron:` line

---

## Cost Summary

| Item | Cost |
|---|---|
| GitHub Actions | Free (unlimited for public repos; 2,000 min/month free for private) |
| Claude Haiku API | ~$0.01–$0.05/day for 10 articles twice daily |
| IONOS hosting | Already paid — no extra cost |
| GitHub repository | Free |

The Anthropic API charges per token. Claude Haiku is the most affordable
model and well-suited for structured summarisation tasks like this one.
