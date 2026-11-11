FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
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

