FROM --platform=${BUILDPLATFORM} golang:1.24-alpine AS builder

WORKDIR /workspace

COPY go.mod go.sum /workspace/
RUN go mod download

ADD . /workspace

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
  go build -ldflags "-s -w" -trimpath -buildvcs=false -o bin/permissionizer .

FROM alpine:3.21.3
WORKDIR /app

COPY --from=builder /workspace/bin/permissionizer ./permissionizer

ENTRYPOINT ["/app/permissionizer"]
CMD ["--production"]