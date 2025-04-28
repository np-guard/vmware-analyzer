# FROM golang:1.24-alpine
FROM golang@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee

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
