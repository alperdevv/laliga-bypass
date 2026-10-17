FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/laliga-guard ./cmd/laliga-guard \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/alperdevv/laliga-bypass"
LABEL org.opencontainers.image.description="Detects LaLiga IP blocks on Cloudflare and switches allowed DNS records to DNS-only"
LABEL org.opencontainers.image.licenses="MIT"
COPY --from=build /out/laliga-guard /usr/local/bin/laliga-guard
COPY --from=build --chown=65532:65532 /out/data /data
ENV CONFIG_PATH=/etc/laliga-guard/config.yaml
USER 65532:65532
VOLUME ["/data"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=120s --retries=3 CMD ["/usr/local/bin/laliga-guard", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/laliga-guard"]
CMD ["run"]
