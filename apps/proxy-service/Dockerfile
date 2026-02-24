# ============================================================
# Shadow AI Sentinel — Proxy Service (Go)
# Multi-stage build: compile → minimal runtime image
# ============================================================

# --- Build stage ---
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /sentinel-proxy ./src/

# --- Runtime stage ---
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel

WORKDIR /app
COPY --from=builder /sentinel-proxy .

USER sentinel

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

CMD ["./sentinel-proxy"]
