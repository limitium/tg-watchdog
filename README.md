# Telegram Watchdog Bot

**Why**  
Auto-monitor HTTP domains and SMTP servers with Telegram alerts.

**What**  
A Dockerized Python bot configurable via environment variables:
- Periodic HTTP & SMTP health checks  
- Inline **“Check Now”** button  
- Commands: `/start`, `/id`, `/status`

**How to use**  
1. Export environment variables:
   ```bash
   export TELEGRAM_TOKEN="your_token"
   export TELEGRAM_CHAT_ID="123456"
   export DOMAINS_HTTP="https://a.com,https://b.org"
   export SMTP_SERVERS="smtp.example.com:587:user:pass"
   export CHECK_INTERVAL="60"  # optional, defaults to 60
   ```
2. Build and run with Docker:
   ```bash
   docker build -t limitium/watchdog-bot .
   docker run -d --env-file .env limitium/watchdog-bot
   ```
3. Or with Docker Compose:
   ```yaml
   # docker-compose.yml
   version: '3.8'
   services:
     watchdog:
       image: limitium/watchdog-bot:latest
       env_file: .env
   ```
   Then:
   ```bash
   docker compose up -d
   ```

## Commands

- **`/start`**  
  Shows a welcome message and the **Check Now** button.

- **`/id`**  
  Replies with your Telegram chat ID.

- **`/status`**  
  Displays the current up/down status of all monitored services.

- **🔍 Check Now button**  
  Triggers an immediate health check and returns a summary.
