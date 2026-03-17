FROM alpine:3.21 AS builder

RUN apk add --no-cache gcc musl-dev make

WORKDIR /app

COPY . .

RUN make build

FROM alpine:3.21

WORKDIR /app

COPY --from=builder /app/build/daemon ./daemon

EXPOSE 8080

CMD ["./daemon"]
