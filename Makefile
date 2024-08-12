REPOSITORY := github.com/np-guard/nsx-api-demo
EXE:= nsxanalyzer
COVERAGE:=nsxanalyzer.coverprofile

mod: go.mod
	@echo -- $@ --
	go mod tidy
	go mod download

fmt:
	@echo -- $@ --
	goimports -local $(REPOSITORY) -w .

lint:
	@echo -- $@ --
	CGO_ENABLED=0 go vet ./...
	golangci-lint run

precommit: mod fmt lint

build:
	@echo -- $@ --
	CGO_ENABLED=0 go build -o ./bin/$(EXE) ./cmd

test:
	@echo -- $@ --
	go test ./... -v -coverpkg=./... -coverprofile $(COVERAGE)

coverage:
	go tool cover -html="$(COVERAGE)"


