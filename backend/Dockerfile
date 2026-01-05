FROM golang:1.25.5-alpine3.22 AS builder
WORKDIR /usr/src/app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o application ./cmd/app

FROM alpine:3.22

# if your user's uid and gid are not 1000, then change to your uid and gid
RUN addgroup -g 1000 -S app \ 
 && adduser -D -u 1000 -G app app

WORKDIR /app

COPY --from=builder /usr/src/app/config*.yaml .
COPY --from=builder /usr/src/app/application ./app
COPY migrations migrations

RUN chown -R app:app /app

USER app

EXPOSE 8080

CMD ["./app"]
