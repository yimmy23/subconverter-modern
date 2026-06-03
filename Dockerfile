# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/subconverter-modern .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates && adduser -D -H -s /sbin/nologin app
COPY --from=build /out/subconverter-modern /usr/local/bin/subconverter-modern
USER app
EXPOSE 25500
ENTRYPOINT ["/usr/local/bin/subconverter-modern"]
