# Dockerfile
FROM python:3.11-slim

# (Optional) system deps, if you need them:
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# copy and install python deps (with job-queue extra)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy your bot code
COPY watchdog_bot.py .

# run the bot
CMD ["python", "watchdog_bot.py"]
