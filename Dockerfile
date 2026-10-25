# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Download dependencies first for caching
COPY go.mod ./
RUN go mod download

# Copy source
COPY . .

# Build statically linked binary
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -o /bin/domain-doctor ./cmd/domain-doctor

# Runtime stage
FROM alpine:3.21

# Install ca-certificates and tzdata
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user and configuration directory
RUN addgroup -S domain-doctor && adduser -S domain-doctor -G domain-doctor && \
    mkdir -p /etc/domain-doctor && \
    chown -R domain-doctor:domain-doctor /etc/domain-doctor

COPY --from=builder /bin/domain-doctor /usr/local/bin/domain-doctor

USER domain-doctor
WORKDIR /etc/domain-doctor

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/domain-doctor"]
CMD ["-port", "8080"]
