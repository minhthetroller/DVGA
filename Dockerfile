FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o /dvga ./cmd/dvga

# --- Runtime ---
FROM alpine:3.21

RUN apk add --no-cache iputils sqlite

WORKDIR /app
COPY --from=builder /dvga /app/dvga
COPY internal/ui/templates ./internal/ui/templates
COPY internal/ui/static ./internal/ui/static
COPY data/files ./data/files

EXPOSE 4280

CMD ["/app/dvga"]
