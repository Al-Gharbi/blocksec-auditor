# Build stage
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache make git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

# Final stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /root/
COPY --from=builder /app/blocksec-auditor .
COPY --from=builder /app/testdata ./testdata
ENTRYPOINT ["./blocksec-auditor"]
CMD ["--help"]
