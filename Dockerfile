# FROM golang:1.23-alpine
FROM golang@sha256:47d337594bd9e667d35514b241569f95fb6d95727c24b19468813d596d5ae596

RUN apk update && apk upgrade && apk --no-cache add make

WORKDIR /go/src/github.com/vmware-analyzer/

COPY pkg/    pkg/
COPY cmd/    cmd/
COPY internal/ internal/
COPY go.mod go.sum Makefile ./

RUN make mod
RUN make build

FROM scratch

WORKDIR /np-guard
COPY --from=0 /go/src/github.com/vmware-analyzer/bin/nsxanalyzer .

ENTRYPOINT ["/np-guard/nsxanalyzer"]

LABEL \
        name="github.com/np-guard/vmware-analyzer" \
        license="Apache License 2.0" \
        description="vmware-analyzer - NSX Analysis tool" \
        summary="vmware-analyzer - NSX Analysis tool"
