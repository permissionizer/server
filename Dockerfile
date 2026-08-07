FROM --platform=${BUILDPLATFORM} golang:1.26-alpine3.24 AS builder

WORKDIR /workspace

COPY go.mod go.sum /workspace/
RUN go mod download

ADD . /workspace

ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags "-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -trimpath -buildvcs=false -o bin/permissionizer .

FROM alpine:3.24
WORKDIR /app

COPY --from=builder /workspace/bin/permissionizer ./permissionizer

ENTRYPOINT ["/app/permissionizer"]
CMD ["--production"]
