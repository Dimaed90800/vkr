FROM mcr.microsoft.com/restlerfuzzer/restler:v8.5.0 AS restler_runtime
FROM eclipse-temurin:21-jre AS java_runtime

# ИСПРАВЛЕНИЕ 1: Использована актуальная версия Go
FROM golang:1.25.9-bookworm AS go_tools_builder
ENV GOTOOLCHAIN=auto

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.7.1 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0 && \
    go install github.com/ffuf/ffuf/v2@v2.1.0

# ИСПРАВЛЕНИЕ 4: Скачиваем готовый релиз CATS вместо сборки из исходников.
# Проект Endava/cats использует зависимости, требующие авторизации в GitHub Packages,
# из-за чего "mvn package" падает. Прямое скачивание решает проблему и сильно ускоряет билд.
FROM debian:bookworm-slim AS cats_builder
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/cats
RUN set -eux; \
    curl -fsSL https://api.github.com/repos/Endava/cats/releases/latest -o /tmp/cats-release.json; \
    python3 -c 'import json; release=json.load(open("/tmp/cats-release.json", encoding="utf-8")); assets=release.get("assets") or []; urls=[str(a.get("browser_download_url") or "") for a in assets if str(a.get("name") or "").lower().endswith(".jar") and "runner" in str(a.get("name") or "").lower()]; urls=urls or [str(a.get("browser_download_url") or "") for a in assets if str(a.get("name") or "").lower().endswith(".jar")]; print(next((u for u in urls if u), ""))' > /tmp/cats-asset-url; \
    CATS_URL="$(cat /tmp/cats-asset-url)"; \
    if [ -n "$CATS_URL" ]; then \
      curl -fL "$CATS_URL" -o cats-runner.jar; \
      test "$(stat -c%s cats-runner.jar)" -gt 100000 || (echo "CATS jar download too small"; stat -c%s cats-runner.jar; exit 1); \
    else \
      python3 -c 'import json; release=json.load(open("/tmp/cats-release.json", encoding="utf-8")); print("No jar asset found in latest CATS GitHub release: " + str(release.get("tag_name") or release.get("name") or "unknown"))' > CATS_RELEASE_UNAVAILABLE; \
    fi

FROM maven:3.9.9-eclipse-temurin-21 AS astf_builder
ARG ASTF_REF=main
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch ${ASTF_REF} https://github.com/OWASP/www-project-api-security-testing-framework.git astf
WORKDIR /src/astf
RUN mvn -q -DskipTests clean package

FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV JAVA_HOME=/opt/java/openjdk
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="/opt/java/openjdk/bin:${DOTNET_ROOT}:/usr/local/bin:${PATH}"

WORKDIR /app

# ИСПРАВЛЕНИЕ 2: Установка .NET 8 через официальный скрипт Microsoft
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    docker.io \
    wget \
    libicu72 \
    libgssapi-krb5-2 \
    libstdc++6 \
    zlib1g \
    && wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh \
    && chmod +x dotnet-install.sh \
    && ./dotnet-install.sh --channel 8.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && ./dotnet-install.sh --channel 5.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && rm dotnet-install.sh \
    && ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet \
    && rm -rf /var/lib/apt/lists/*

COPY --from=java_runtime /opt/java/openjdk /opt/java/openjdk

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

COPY --from=go_tools_builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go_tools_builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=go_tools_builder /go/bin/ffuf /usr/local/bin/ffuf
RUN chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx /usr/local/bin/ffuf

COPY --from=restler_runtime /RESTler /RESTler

# ИСПРАВЛЕНИЕ 3: Копируем CATS runtime directory. Если latest release не содержит jar asset,
# внутри будет marker, а preflight честно покажет CATS как unavailable/degraded.
COPY --from=cats_builder /opt/cats /opt/cats
COPY --from=astf_builder /src/astf/target/api-security-testing-framework-1.0-SNAPSHOT.jar /opt/astf/api-security-testing-framework-1.0-SNAPSHOT.jar

COPY backend/bin/restler /usr/local/bin/restler
COPY backend/bin/cats /usr/local/bin/cats
COPY backend/bin/astf /usr/local/bin/astf

RUN test -s /opt/astf/api-security-testing-framework-1.0-SNAPSHOT.jar && \
    test -x /opt/java/openjdk/bin/java && \
    test -x /usr/share/dotnet/dotnet && \
    chmod +x /usr/local/bin/restler /usr/local/bin/cats /usr/local/bin/astf

COPY backend /app
COPY scripts /app/scripts

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
