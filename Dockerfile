# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true
ARG TARGETOS
ARG TARGETARCH
ARG GIT_COMMIT=unknown
ARG GIT_REF=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X github.com/thelemail/keylog/cmd.buildCommit=${GIT_COMMIT} -X github.com/thelemail/keylog/cmd.buildRef=${GIT_REF}" \
      -o /out/keylog .


FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS runtime

RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 keylog \
 && adduser -S -u 10001 -G keylog -h /home/keylog keylog

COPY --from=builder /out/keylog /usr/local/bin/keylog

USER keylog
WORKDIR /home/keylog

ENTRYPOINT ["/usr/local/bin/keylog"]
CMD ["serve"]
