# FROM golang:1.23-alpine
FROM golang@sha256:47d337594bd9e667d35514b241569f95fb6d95727c24b19468813d596d5ae596

RUN apk update && apk upgrade && apk --no-cache add make

WORKDIR /go/src/github.com/vmware-analyzer/

COPY pkg/    pkg/
COPY cmd/    cmd/
COPY go.mod go.sum Makefile ./

RUN make mod
RUN make build

FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:1b6d711648229a1c987f39cfdfccaebe2bd92d0b5d8caa5dbaa5234a9278a0b2
RUN microdnf --nodocs -y upgrade

WORKDIR /np-guard
COPY --from=0 /go/src/github.com/vmware-analyzer/bin/nsxanalyzer .

ENTRYPOINT ["/np-guard/nsxanalyzer"]