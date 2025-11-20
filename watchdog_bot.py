#!/usr/bin/env python3
import os
import logging
import asyncio
import socket
import ssl
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

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
CERT_WARN_DAYS = int(os.environ.get("CERT_WARN_DAYS", "14"))

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
# Store certificate expiry dates (None if not checked or failed)
http_cert_expiry = {
    domain: None
    for domain in domains_http
    if urlparse(domain).scheme == "https"
}
mail_cert_expiry = {(host, port): None for (host, port, *_ ) in mail_servers}
# Track previous cert status to avoid spam (True = OK, False = not OK)
http_cert_status_prev = {
    domain: True
    for domain in domains_http
    if urlparse(domain).scheme == "https"
}
mail_cert_status_prev = {(host, port): True for (host, port, *_ ) in mail_servers}


def _parse_cert_expiry(cert_dict):
    not_after = cert_dict.get("notAfter")
    if not_after is None:
        raise ValueError("Certificate missing notAfter field")
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    return expiry.replace(tzinfo=timezone.utc)


def fetch_cert_expiry(host: str, port: int):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    if not cert:
        raise ValueError("Remote certificate not provided")
    return _parse_cert_expiry(cert)


def _is_cert_ok(expiry: Optional[datetime]) -> bool:
    """Check if certificate is OK (valid and not expiring soon)."""
    if expiry is None:
        return False
    now = datetime.now(timezone.utc)
    remaining = expiry - now
    if remaining <= timedelta(seconds=0):
        return False
    if remaining <= timedelta(days=CERT_WARN_DAYS):
        return False
    return True


async def ensure_http_cert(domain: str, context: ContextTypes.DEFAULT_TYPE):
    parsed = urlparse(domain)
    if parsed.scheme != "https":
        return
    host = parsed.hostname
    if not host:
        return
    port = parsed.port or 443
    
    expiry = None
    failure_reason = None
    try:
        expiry = await asyncio.to_thread(fetch_cert_expiry, host, port)
    except (ssl.SSLCertVerificationError, ssl.CertificateError) as exc:
        failure_reason = str(exc)
        logger.debug(f"TLS cert check failed for {domain}: {exc}")
    except Exception as exc:
        logger.debug(f"TLS cert check failed for {domain}: {exc}")
    
    # Store expiry (or None if failed)
    http_cert_expiry[domain] = expiry
    
    # Check status
    is_ok = _is_cert_ok(expiry)
    prev_ok = http_cert_status_prev.get(domain, True)
    
    # Notify on status change
    if prev_ok and not is_ok:
        if expiry is None:
            reason = failure_reason or "validation failed"
            await context.bot.send_message(
                CHAT_ID, f"🔴 TLS cert for HTTP {domain} failed validation ({reason})."
            )
        else:
            now = datetime.now(timezone.utc)
            remaining = expiry - now
            if remaining <= timedelta(seconds=0):
                await context.bot.send_message(
                    CHAT_ID, f"🔴 TLS cert for HTTP {domain} expired on {expiry.date().isoformat()}."
                )
            else:
                days_left = int(remaining.total_seconds() // 86400)
                await context.bot.send_message(
                    CHAT_ID, f"🟠 TLS cert for HTTP {domain} expires in {days_left} days ({expiry.date().isoformat()})."
                )
    elif not prev_ok and is_ok:
        expiry_str = expiry.date().isoformat() if expiry else "unknown"
        await context.bot.send_message(
            CHAT_ID, f"🟢 TLS cert for HTTP {domain} is OK (exp {expiry_str})."
        )
    
    http_cert_status_prev[domain] = is_ok

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

def _format_cert_info(expiry: Optional[datetime]) -> str:
    """Format certificate expiry info with days remaining."""
    if expiry is None:
        return "❌ no cert"
    now = datetime.now(timezone.utc)
    remaining = expiry - now
    if remaining <= timedelta(seconds=0):
        days = int(abs(remaining.total_seconds()) // 86400)
        return f"❌ expired {days}d ago ({expiry.date().isoformat()})"
    days_left = int(remaining.total_seconds() // 86400)
    return f"✅ {days_left}d left (exp {expiry.date().isoformat()})"

async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lines = []
    for domain, up in http_status.items():
        lines.append(f"HTTP {domain}: {'✅ up' if up else '❌ down'}")
    for (host, port), up in mail_status.items():
        lines.append(f"SMTP {host}:{port}: {'✅ up' if up else '❌ down'}")
    for domain, expiry in http_cert_expiry.items():
        lines.append(f"CERT HTTP {domain}: {_format_cert_info(expiry)}")
    for (host, port), expiry in mail_cert_expiry.items():
        lines.append(f"CERT SMTP {host}:{port}: {_format_cert_info(expiry)}")
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
            await ensure_http_cert(domain, context)

async def check_smtp(context: ContextTypes.DEFAULT_TYPE):
    for host, port, user, pw in mail_servers:
        key = (host, port)
        cert_expiry = None
        failure_reason = None
        try:
            def smtp_probe():
                cert_expiry = None
                tls_context = ssl.create_default_context()
                if port == 465:
                    server = smtplib.SMTP_SSL(
                        host, port, timeout=10, context=tls_context
                    )
                else:
                    server = smtplib.SMTP(host, port, timeout=10)
                    server.ehlo()
                    if port == 587:
                        server.starttls(context=tls_context)
                        server.ehlo()
                try:
                    if isinstance(server.sock, ssl.SSLSocket):
                        cert = server.sock.getpeercert()
                        if cert:
                            cert_expiry = _parse_cert_expiry(cert)
                    server.login(user, pw)
                finally:
                    server.quit()
                return cert_expiry

            cert_expiry = await asyncio.to_thread(smtp_probe)
            is_up = True
        except (ssl.SSLCertVerificationError, ssl.CertificateError) as e:
            logger.debug(f"SMTP cert validation failed for {host}:{port}: {e}")
            failure_reason = str(e)
            is_up = False
        except Exception as e:
            logger.debug(f"SMTP check failed for {host}:{port}: {e}")
            is_up = False

        # Store cert expiry (even if None, e.g., port 25 without TLS)
        mail_cert_expiry[key] = cert_expiry
        
        # Check cert status
        is_cert_ok = _is_cert_ok(cert_expiry)
        prev_cert_ok = mail_cert_status_prev.get(key, True)
        
        # Notify on cert status change
        if prev_cert_ok and not is_cert_ok:
            if cert_expiry is None:
                reason = failure_reason or "validation failed"
                await context.bot.send_message(
                    CHAT_ID, f"🔴 TLS cert for SMTP {host}:{port} failed validation ({reason})."
                )
            else:
                now = datetime.now(timezone.utc)
                remaining = cert_expiry - now
                if remaining <= timedelta(seconds=0):
                    await context.bot.send_message(
                        CHAT_ID, f"🔴 TLS cert for SMTP {host}:{port} expired on {cert_expiry.date().isoformat()}."
                    )
                else:
                    days_left = int(remaining.total_seconds() // 86400)
                    await context.bot.send_message(
                        CHAT_ID, f"🟠 TLS cert for SMTP {host}:{port} expires in {days_left} days ({cert_expiry.date().isoformat()})."
                    )
        elif not prev_cert_ok and is_cert_ok:
            expiry_str = cert_expiry.date().isoformat() if cert_expiry else "unknown"
            await context.bot.send_message(
                CHAT_ID, f"🟢 TLS cert for SMTP {host}:{port} is OK (exp {expiry_str})."
            )
        
        mail_cert_status_prev[key] = is_cert_ok

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
    for domain, expiry in http_cert_expiry.items():
        lines.append(f"CERT HTTP {domain}: {_format_cert_info(expiry)}")
    for (host, port), expiry in mail_cert_expiry.items():
        lines.append(f"CERT SMTP {host}:{port}: {_format_cert_info(expiry)}")

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
