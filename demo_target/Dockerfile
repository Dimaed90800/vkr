FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEMO_TARGET_MODE=vulnerable

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir fastapi uvicorn[standard] pydantic

COPY demo_target /app/demo_target

EXPOSE 8001

CMD ["uvicorn", "demo_target.main:app", "--host", "0.0.0.0", "--port", "8001"]
