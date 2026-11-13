FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY shadow_core ./shadow_core
COPY shadow-core-dashboard/main.py ./main.py
COPY shadow-core-dashboard/static ./static
ENV SHADOW_CORE_DB=/tmp/shadow-core/evidence.sqlite3
USER 10001
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
