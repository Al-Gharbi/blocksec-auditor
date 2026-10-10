# Build stage
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN make build VERSION=${VERSION}

# Final stage: static binary, non-root user
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 auditor
USER auditor
WORKDIR /home/auditor
COPY --from=builder /app/blocksec-auditor /usr/local/bin/blocksec-auditor
ENTRYPOINT ["blocksec-auditor"]
CMD ["--help"]
