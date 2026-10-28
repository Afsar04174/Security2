FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN useradd -m appuser && chown -R appuser /app
USER appuser
ENV PORT=8000 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/health'%os.environ.get('PORT','8000'))"
CMD ["python", "web_app.py"]
