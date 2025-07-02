#!/usr/bin/env python3
import os
import logging
import asyncio
import httpx
import smtplib
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

# ——— CONFIGURATION ———
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "60"))  # seconds

# ——— READ HTTP DOMAINS FROM ENV ———
# Expects a comma-separated list, e.g. "https://a.com,https://b.org"
domains_http = [
    d.strip()
    for d in os.environ.get("DOMAINS_HTTP", "").split(",")
    if d.strip()
]
if not domains_http:
    raise RuntimeError("No HTTP domains configured. Set DOMAINS_HTTP environment variable.")

# ——— READ SMTP SERVERS FROM ENV ———
# Expects comma-separated entries of host:port:user:pass
# e.g. "smtp.example.com:587:user@example.com:password123,smtp.other.net:25:me@other.net:pw456"
mail_servers = []
raw = os.environ.get("SMTP_SERVERS", "")
for entry in raw.split(","):
    entry = entry.strip()
    if not entry:
        continue
    parts = entry.split(":")
    if len(parts) != 4:
        logging.warning("Skipping invalid SMTP_SERVERS entry: %r", entry)
        continue
    host, port_str, user, pw = parts
    try:
        port = int(port_str)
    except ValueError:
        logging.warning("Invalid port in SMTP_SERVERS entry: %r", entry)
        continue
    mail_servers.append((host, port, user, pw))

if not mail_servers:
    raise RuntimeError("No SMTP servers configured. Set SMTP_SERVERS environment variable.")

# ——— STATE TRACKERS ———
http_status = {domain: True for domain in domains_http}
mail_status = {(host, port): True for (host, port, *_ ) in mail_servers}

# ——— ENV VARS FOR TELEGRAM ———
TOKEN = os.environ["TELEGRAM_TOKEN"]
CHAT_ID = int(os.environ["TELEGRAM_CHAT_ID"])

# ——— LOGGING ———
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# ——— BOT COMMAND HANDLERS ———
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "👋 Watchdog bot is running!\n"
        f"Checking {len(domains_http)} HTTP domains and {len(mail_servers)} SMTP servers every "
        f"{CHECK_INTERVAL}s.\n\n"
        "Press the button below to run an immediate check:"
    )
    button = InlineKeyboardButton("🔍 Check Now", callback_data="check_now")
    markup = InlineKeyboardMarkup([[button]])
    await update.message.reply_text(text, reply_markup=markup)

async def id_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"Your chat ID is: `{update.effective_chat.id}`", parse_mode="Markdown"
    )

async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lines = []
    for domain, up in http_status.items():
        lines.append(f"HTTP {domain}: {'✅ up' if up else '❌ down'}")
    for (host, port), up in mail_status.items():
        lines.append(f"SMTP {host}:{port}: {'✅ up' if up else '❌ down'}")
    await update.message.reply_text("\n".join(lines))

# ——— PERIODIC CHECKS ———
async def check_http(context: ContextTypes.DEFAULT_TYPE):
    async with httpx.AsyncClient(timeout=10.0) as client:
        for domain in domains_http:
            try:
                resp = await client.get(domain)
                is_up = 200 <= resp.status_code < 400
            except Exception as e:
                logger.debug(f"HTTP check failed for {domain}: {e}")
                is_up = False

            if http_status[domain] and not is_up:
                await context.bot.send_message(CHAT_ID, f"🔴 HTTP {domain} is DOWN!")
            elif not http_status[domain] and is_up:
                await context.bot.send_message(CHAT_ID, f"🟢 HTTP {domain} is back UP.")
            http_status[domain] = is_up

async def check_smtp(context: ContextTypes.DEFAULT_TYPE):
    for host, port, user, pw in mail_servers:
        key = (host, port)
        try:
            def smtp_probe():
                if port == 465:
                    server = smtplib.SMTP_SSL(host, port, timeout=10)
                else:
                    server = smtplib.SMTP(host, port, timeout=10)
                    server.ehlo()
                    if port == 587:
                        server.starttls()
                        server.ehlo()
                server.login(user, pw)
                server.quit()

            await asyncio.to_thread(smtp_probe)
            is_up = True
        except Exception as e:
            logger.debug(f"SMTP check failed for {host}:{port}: {e}")
            is_up = False

        if mail_status[key] and not is_up:
            await context.bot.send_message(CHAT_ID, f"🔴 SMTP {host}:{port} is DOWN!")
        elif not mail_status[key] and is_up:
            await context.bot.send_message(CHAT_ID, f"🟢 SMTP {host}:{port} is back UP.")
        mail_status[key] = is_up

# ——— IMMEDIATE CHECK HANDLER ———
async def check_now_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer("Running checks…")
    await check_http(context)
    await check_smtp(context)

    lines = []
    for domain, up in http_status.items():
        lines.append(f"HTTP {domain}: {'✅ up' if up else '❌ down'}")
    for (host, port), up in mail_status.items():
        lines.append(f"SMTP {host}:{port}: {'✅ up' if up else '❌ down'}")

    await update.callback_query.message.reply_text(
        "📋 Current status of all monitored services:\n" + "\n".join(lines)
    )

# ——— MAIN ENTRYPOINT ———
def main():
    app = ApplicationBuilder().token(TOKEN).build()

    # register commands & callback
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("id", id_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    app.add_handler(CallbackQueryHandler(check_now_callback, pattern="^check_now$"))

    # schedule periodic health checks
    jq = app.job_queue
    jq.run_repeating(check_http, interval=CHECK_INTERVAL, first=10)
    jq.run_repeating(check_smtp, interval=CHECK_INTERVAL, first=20)

    app.run_polling()

if __name__ == "__main__":
    main()
