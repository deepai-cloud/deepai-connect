FROM --platform=$BUILDPLATFORM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags="-s -w -X github.com/deepai-cloud/deepai-connect/internal/buildinfo.Version=${VERSION}" -o /deepai-connect ./cmd/deepai-connect

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates
COPY --from=build /deepai-connect /usr/local/bin/deepai-connect
ENTRYPOINT ["/usr/local/bin/deepai-connect"]
