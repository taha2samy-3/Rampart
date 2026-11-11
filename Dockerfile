# The UI is built first and embedded into the Go binary (docs/13 section 2).
FROM oven/bun:1.4.4-alpine AS web
WORKDIR /web
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile
COPY web/ ./
RUN bun --bun run build

FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/rampart ./cmd/rampart

FROM alpine:3.20

RUN addgroup -S rampart && adduser -S rampart -G rampart

WORKDIR /app
COPY --from=builder /bin/rampart /app/rampart

RUN mkdir -p /var/lib/rampart && chown rampart:rampart /var/lib/rampart

USER rampart:rampart

EXPOSE 8080 9090

ENTRYPOINT ["/app/rampart"]
CMD ["-target=all"]

