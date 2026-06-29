FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /provisioner .

FROM alpine:3.21
WORKDIR /app
COPY --from=builder /provisioner /app/provisioner
COPY templates /app/templates
EXPOSE 8080
CMD ["/app/provisioner"]
