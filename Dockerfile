FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Rule clones and the rules database live under /data (a persistent volume in
# docker-compose.yml) so restarts reuse them instead of re-cloning/re-syncing.
ENV RULE_AGGREGATOR_CLONE_DIR=/data/clones

EXPOSE 8080

# Syncs all vendors on first start (docker-entrypoint.sh), then serves the
# dashboard. init_db() also runs at request time, so no schema step is needed.
CMD ["sh", "docker-entrypoint.sh"]
