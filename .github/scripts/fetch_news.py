"""
Cybersecurity News Fetcher
George Condrea — Portfolio Project

Fetches articles from cybersecurity RSS feeds, processes each one
with the Claude AI API, and saves the result to data/news.json.
The updated file is then FTP-uploaded to the IONOS server.

Required environment variables (set as GitHub Secrets):
  ANTHROPIC_API_KEY  — Anthropic API key
  FTP_HOST           — IONOS FTP hostname (e.g. access.your-server.com)
  FTP_USER           — IONOS FTP username
  FTP_PASS           — IONOS FTP password
  FTP_REMOTE_PATH    — Remote path for news.json (e.g. /data/news.json)
"""

import os
import io
import json
import uuid
import re
import sys
import traceback
from datetime import datetime, timezone

import feedparser
import anthropic
import paramiko

# ─── Configuration ──────────────────────────────────────────────
MAX_ARTICLES_STORED = 50   # Maximum articles kept in news.json
MAX_NEW_PER_RUN     = 10   # Max new articles processed per run (cost control)
MAX_PER_FEED        = 5    # Max articles taken from each feed per run
CONTENT_SNIPPET_LEN = 1500 # Max characters of article content sent to AI

AI_MODEL = "claude-haiku-4-5-20251001"  # Fast and cost-effective

RSS_FEEDS = [
    {"url": "https://feeds.feedburner.com/TheHackersNews",                    "name": "The Hacker News"},
    {"url": "https://www.bleepingcomputer.com/feed/",                         "name": "BleepingComputer"},
    {"url": "https://krebsonsecurity.com/feed/",                              "name": "Krebs on Security"},
    {"url": "https://www.darkreading.com/rss.xml",                            "name": "Dark Reading"},
    {"url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",    "name": "NCSC UK"},
]

VALID_CATEGORIES = [
    "Ransomware", "Phishing", "Malware", "Data Breaches", "Vulnerabilities",
    "Zero-Day Exploits", "Cloud Security", "Network Security", "AI Security",
    "Privacy", "Digital Forensics", "Cybercrime", "Security Awareness",
    "Patching and Updates", "Other",
]

VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]

AI_PROMPT = """You are a cybersecurity news assistant. Analyse the following cybersecurity news article and return ONLY valid JSON — no markdown, no explanation, just the JSON object.

Article title: {title}
Article source: {source}
Article date: {date}
Article snippet: {content}

Your tasks:
1. Write a summary in 2–4 clear, student-friendly sentences. Do NOT copy the article word-for-word.
2. Choose ONE category from this list: Ransomware, Phishing, Malware, Data Breaches, Vulnerabilities, Zero-Day Exploits, Cloud Security, Network Security, AI Security, Privacy, Digital Forensics, Cybercrime, Security Awareness, Patching and Updates, Other
3. Assign a severity: Low, Medium, High, or Critical.
   - Critical: active exploitation, major breach, or urgent widespread risk.
   - High: serious threat with significant impact.
   - Medium: notable risk but not immediately critical.
   - Low: general awareness, guidance, or minor advisory.
4. Generate 3–6 lowercase hyphenated tags (e.g. "zero-day", "ransomware", "patch-now").
5. Explain in 1–3 sentences why this article matters in practical cybersecurity terms.

Return ONLY this JSON (no other text):
{{
  "summary": "",
  "category": "",
  "severity": "",
  "tags": [],
  "whyItMatters": ""
}}"""


# ─── Helpers ────────────────────────────────────────────────────

def log(msg: str):
    """Print a timestamped log line."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def strip_html(text: str) -> str:
    """Remove HTML tags from a string."""
    return re.sub(r"<[^>]+>", " ", text or "").strip()


def parse_entry_date(entry) -> str:
    """Return ISO date string from a feedparser entry, falling back to today."""
    for attr in ("published_parsed", "updated_parsed"):
        t = getattr(entry, attr, None)
        if t:
            try:
                import time
                return datetime(*t[:6], tzinfo=timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_existing() -> list:
    """Load current articles from data/news.json."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "news.json")
    path = os.path.normpath(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            articles = data.get("articles", [])
            log(f"Loaded {len(articles)} existing articles from data/news.json")
            return articles
    except FileNotFoundError:
        log("data/news.json not found — starting fresh.")
        return []
    except Exception as e:
        log(f"Warning: could not read existing articles: {e}")
        return []


def save_articles(articles: list):
    """Write the updated article list to data/news.json."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "news.json")
    path = os.path.normpath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    output = {
        "lastUpdated":    datetime.now(timezone.utc).isoformat(),
        "totalArticles":  len(articles),
        "articles":       articles,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    log(f"Saved {len(articles)} articles to data/news.json")
    return output


# ─── RSS fetching ────────────────────────────────────────────────

def fetch_rss_feeds(existing_urls: set) -> list:
    """Return a list of new article dicts from all configured RSS feeds."""
    new_articles = []

    for feed_info in RSS_FEEDS:
        try:
            log(f"Fetching: {feed_info['name']}")
            feed = feedparser.parse(feed_info["url"])

            if feed.bozo and not feed.entries:
                log(f"  ⚠ Feed parse warning for {feed_info['name']}: {feed.bozo_exception}")
                continue

            count = 0
            for entry in feed.entries:
                if count >= MAX_PER_FEED:
                    break

                url = (entry.get("link") or "").strip()
                if not url or url in existing_urls:
                    continue

                # Extract content snippet
                content = ""
                if hasattr(entry, "summary"):
                    content = strip_html(entry.summary)
                elif hasattr(entry, "content") and entry.content:
                    content = strip_html(entry.content[0].get("value", ""))
                content = content[:CONTENT_SNIPPET_LEN]

                new_articles.append({
                    "title":   (entry.get("title") or "Untitled").strip(),
                    "url":     url,
                    "source":  feed_info["name"],
                    "date":    parse_entry_date(entry),
                    "content": content,
                })
                existing_urls.add(url)
                count += 1

            log(f"  ✓ {count} new article(s) from {feed_info['name']}")

        except Exception as e:
            log(f"  ✗ Failed to fetch {feed_info['name']}: {e}")

    log(f"Total new candidates: {len(new_articles)}")
    return new_articles[:MAX_NEW_PER_RUN]


# ─── AI processing ───────────────────────────────────────────────

def process_with_ai(client: anthropic.Anthropic, article: dict) -> dict | None:
    """Send article to Claude and return a processed article dict, or None on failure."""
    try:
        prompt = AI_PROMPT.format(
            title   = article["title"],
            source  = article["source"],
            date    = article["date"],
            content = article["content"] or "(no content snippet available)",
        )

        response = client.messages.create(
            model      = AI_MODEL,
            max_tokens = 512,
            messages   = [{"role": "user", "content": prompt}],
        )

        raw = response.content[0].text.strip()

        # Strip markdown code fences if present
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        ai = json.loads(raw)

        # Validate and sanitise AI output
        category = ai.get("category", "Other")
        if category not in VALID_CATEGORIES:
            category = "Other"

        severity = ai.get("severity", "Medium")
        if severity not in VALID_SEVERITIES:
            severity = "Medium"

        tags = [str(t).lower()[:40] for t in ai.get("tags", []) if t][:6]

        return {
            "id":            f"art-{uuid.uuid4().hex[:8]}",
            "title":         article["title"],
            "source":        article["source"],
            "publishedDate": article["date"],
            "originalUrl":   article["url"],
            "summary":       str(ai.get("summary", ""))[:600],
            "category":      category,
            "severity":      severity,
            "tags":          tags,
            "whyItMatters":  str(ai.get("whyItMatters", ""))[:400],
            "image":         None,
            "processedAt":   datetime.now(timezone.utc).isoformat(),
        }

    except json.JSONDecodeError as e:
        log(f"  ✗ AI returned invalid JSON for '{article['title']}': {e}")
    except Exception as e:
        log(f"  ✗ AI processing failed for '{article['title']}': {e}")

    return None


# ─── SFTP upload ─────────────────────────────────────────────────

def sftp_upload(json_bytes: bytes):
    """Upload news.json to IONOS via SFTP (SSH File Transfer Protocol)."""
    host     = os.environ["FTP_HOST"]
    user     = os.environ["FTP_USER"]
    password = os.environ["FTP_PASS"]
    remote   = os.environ.get("FTP_REMOTE_PATH", "/data/news.json")

    log(f"Connecting via SFTP: {host}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=22, username=user, password=password, timeout=30)

    sftp = client.open_sftp()

    # Ensure the remote directory exists
    remote_dir = "/".join(remote.split("/")[:-1])
    if remote_dir:
        try:
            sftp.mkdir(remote_dir)
        except OSError:
            pass  # Directory already exists

    sftp.putfo(io.BytesIO(json_bytes), remote)
    sftp.close()
    client.close()
    log(f"✓ SFTP upload complete → {remote}")


# ─── Main ────────────────────────────────────────────────────────

def main():
    log("═══ Cybersecurity News Fetcher starting ═══")

    # Load existing articles and build URL set for deduplication
    existing_articles = load_existing()
    existing_urls     = {a.get("originalUrl", "") for a in existing_articles}

    # Fetch new articles from RSS feeds
    candidates = fetch_rss_feeds(existing_urls)

    if not candidates:
        log("No new articles found — nothing to process.")
    else:
        # Initialise Anthropic client
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            log("ERROR: ANTHROPIC_API_KEY environment variable is not set.")
            sys.exit(1)

        client      = anthropic.Anthropic(api_key=api_key)
        processed   = []

        for i, article in enumerate(candidates, 1):
            log(f"Processing [{i}/{len(candidates)}]: {article['title'][:70]}…")
            result = process_with_ai(client, article)
            if result:
                processed.append(result)
                log(f"  ✓ {result['severity']} / {result['category']}")

        log(f"Successfully processed {len(processed)} new article(s).")

        # Merge: new articles first, keep MAX_ARTICLES_STORED total
        existing_articles = processed + existing_articles
        existing_articles = existing_articles[:MAX_ARTICLES_STORED]

    # Save to disk
    updated_data = save_articles(existing_articles)

    # SFTP upload to IONOS
    json_bytes = json.dumps(updated_data, indent=2, ensure_ascii=False).encode("utf-8")
    try:
        sftp_upload(json_bytes)
    except Exception as e:
        log(f"ERROR: SFTP upload failed: {e}")
        traceback.print_exc()
        sys.exit(1)  # Fail the GitHub Action so it appears as a red ✗

    log("═══ Done ═══")


if __name__ == "__main__":
    main()
