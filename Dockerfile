FROM golang:1.23.1-alpine3.20 AS build

WORKDIR /app

RUN apk --no-cache add build-base

RUN go install github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@v2.2.0
COPY go.mod go.sum ./
RUN go mod tidy

COPY . .

RUN make build-release

RUN mkdir -p /etc && \
    echo 'nobody:x:65534:65534:nobody:/:' > /etc/passwd && \
    echo 'nobody:x:65534:' > /etc/group

FROM scratch

# in case the application requires these variables
ENV USER=appuser
ENV HOME=/home/$USER

# actual user
USER nobody:nobody

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build /app/out/bin/archonauth /app/archonauth

EXPOSE 3000

ENTRYPOINT ["/app/archonauth"]
