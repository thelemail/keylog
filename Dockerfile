# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS builder

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
