FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# System packages: sqlite3 CLI for inspecting the database during the demo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Non-root user and a writable directory for the SQLite database.
RUN useradd --uid 10002 --create-home portaluser \
    && mkdir -p /state \
    && chown portaluser:portaluser /state
USER portaluser

ENV BURPLAB_HOST=0.0.0.0 BURPLAB_PORT=5000 BURPLAB_STATE=/state
EXPOSE 5000

CMD ["python", "app.py"]
