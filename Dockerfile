FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10002 --create-home portaluser && mkdir -p /state && chown portaluser:portaluser /state
USER portaluser
ENV BURPLAB_HOST=0.0.0.0 BURPLAB_PORT=5000 BURPLAB_STATE=/state
EXPOSE 5000
