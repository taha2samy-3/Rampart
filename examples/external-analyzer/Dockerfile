FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /analyzer ./examples/external-analyzer

FROM scratch
COPY --from=builder /analyzer /analyzer
EXPOSE 50051
ENTRYPOINT ["/analyzer"]
