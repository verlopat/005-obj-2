FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER nobody
EXPOSE 8001 9092
HEALTHCHECK --interval=15s --timeout=5s CMD \
  python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/healthz')"
CMD ["python", "app.py"]
