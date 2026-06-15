FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
VOLUME ["/reports"]
USER nobody
EXPOSE 9093
CMD ["python", "app.py"]
