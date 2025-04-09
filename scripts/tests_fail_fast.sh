#!/bin/bash
for s in $(go list ./...); do if ! go test -failfast -v -p 1 $s; then exit 1; fi; done
exit 0