FROM node:22-alpine AS builder
WORKDIR /app
COPY src ./src
RUN npm install --prefix /tmp/build-tools --no-save --no-audit --no-fund esbuild@0.28.2 \
    && /tmp/build-tools/node_modules/.bin/esbuild src/server.ts \
       --bundle \
       --platform=node \
       --format=esm \
       --target=node22 \
       --outfile=dist/server.mjs \
       --minify

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/dist/server.mjs ./dist/server.mjs
ENV PORT=8080
ENV SESSION_FILE=/data/session_state.json
VOLUME ["/data"]
EXPOSE 8080
CMD ["node", "dist/server.mjs"]
