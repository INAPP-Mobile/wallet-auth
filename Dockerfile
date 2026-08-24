FROM node:22-alpine
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY docker-entrypoint.sh ./

# su-exec lets the entrypoint fix volume ownership then drop to unprivileged user.
RUN apk add --no-cache su-exec \
 && addgroup -S wa && adduser -S wa -G wa \
 && mkdir -p /data && chown -R wa:wa /data \
 && chmod +x ./docker-entrypoint.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
  CMD wget -qO- "http://127.0.0.1:${PORT:-8080}/health" || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
