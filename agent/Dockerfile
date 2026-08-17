# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/toolchain-agent .

FROM scratch
COPY --from=build /out/toolchain-agent /toolchain-agent
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/toolchain-agent"]
