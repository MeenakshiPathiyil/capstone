# The web app as one container: the API serves the built React app at / and
# the analysis pipeline runs in-process. The model is not in here; it runs on
# the private ZeroGPU Space and is called over HTTP. See app/DEPLOY.md.
#
#   docker build -t capstone .
#   docker run --rm -p 8080:8080 -e CAPSTONE_ALLOWED_HOSTS='["localhost"]' capstone

# ---- The React build -------------------------------------------------------
FROM node:22-slim AS web

WORKDIR /web

COPY app/web/package.json app/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY app/web/ ./
RUN npm run build


# ---- The API and pipeline --------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Pango and HarfBuzz for the WeasyPrint PDF report, the same set CI installs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/capstone

COPY requirements.txt ./
COPY app/api/requirements.txt app/api/
RUN pip install -r app/api/requirements.txt

# .dockerignore lets through only what the app runs: the pipeline packages,
# their data, the bundled samples, the API and the deploy files.
COPY . .
COPY --from=web /web/dist app/web/dist

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin capstone \
    && install -d -m 700 -o capstone /var/cache/capstone

USER capstone

ENV CAPSTONE_CACHE_DIR=/var/cache/capstone \
    PORT=8080

EXPOSE 8080

CMD ["app/deploy/start.sh"]
