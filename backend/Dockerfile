FROM golang:1.25.6-alpine AS builder
WORKDIR /usr/src/app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o application .

FROM alpine:3.22

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /usr/src/app/application ./app

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

CMD ["./app"]
