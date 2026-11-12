# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

ARG BUILDKIT_SBOM_SCAN_STAGE=true
ARG TARGETOS
ARG TARGETARCH
ARG GIT_COMMIT=unknown
ARG GIT_REF=unknown

ENV GOPRIVATE=github.com/thelemail/trust

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=netrc,target=/root/.netrc,required=true \
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
