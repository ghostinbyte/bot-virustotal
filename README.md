# Telegram VirusTotal Bot with Cloudflare Workers

This project is a Telegram bot integrated with the VirusTotal API, deployed using Cloudflare Workers. It allows you to scan files, URLs, IP addresses, domains, and file hashes for malware and security threats directly via Telegram chat.

---

## Features

- Scan files (up to 32MB) sent via Telegram
- Scan URLs with VirusTotal analysis
- IP address and domain reputation reports
- Lookup files by hash (MD5, SHA1, SHA256)
- Search VirusTotal database for queries
- Fully responsive and real-time Telegram bot
- Uses Cloudflare Workers for deployment (serverless, cost-effective, and scalable)

---

## Setup

### Prerequisites

- [Node.js](https://nodejs.org/) (v16+ recommended)
- [Cloudflare Workers CLI (wrangler)](https://developers.cloudflare.com/workers/cli-wrangler/)
- Telegram Bot Token (create bot via [BotFather](https://telegram.me/BotFather))
- VirusTotal API Key (register at [VirusTotal](https://www.virustotal.com/gui/join-us))

### Installation

```bash
git clone https://github.com/yourusername/telegram-virustotal-bot.git
cd telegram-virustotal-bot
npm install
```

### Configuration

Edit `wrangler.toml` and add your Cloudflare Worker info.

Set your environment variables in Cloudflare dashboard or in `wrangler.toml`:

| Variable           | Description                 |
|--------------------|-----------------------------|
| TELEGRAM_BOT_TOKEN  | Your Telegram bot token     |
| VIRUSTOTAL_API_KEY  | Your VirusTotal API key     |
| WORKER_URL          | Your deployed Worker URL (used for webhook URL) |

### Deploy

```bash
wrangler publish
```

Then set the Telegram webhook by visiting:

```
https://<your-worker-url>/set-webhook
```

or

```bash
curl -X GET https://<your-worker-url>/set-webhook
```

---

## Usage

Use your Telegram bot by sending commands or files:

- `/start` - Welcome message and instructions
- `/help` - User guide
- `/scan_url [URL]` - Scan URL
- `/scan_ip [IP]` - Get IP reputation report
- `/scan_domain [Domain]` - Get domain reputation report
- `/search [query]` - Search VirusTotal database
- `/hash [MD5|SHA1|SHA256]` - Lookup file by hash
- Send files directly for scanning

---

## Auto-deploy Button for Cloudflare Workers

You can add this button to your own GitHub README to enable one-click deployment to your Cloudflare account:

```markdown
[![Deploy to Cloudflare Workers](https://static.cloudflareinsights.com/deploy-to-cloudflare-workers-badge.svg)](https://binding.workers.dev/?repo=https://github.com/yourusername/telegram-virustotal-bot)
```

Replace `https://github.com/yourusername/telegram-virustotal-bot` with your repository URL.

---
