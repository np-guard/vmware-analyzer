REPOSITORY := github.com/np-guard/vmware-analyzer
EXE:= nsxanalyzer
COVERAGE:=nsxanalyzer.coverprofile
EXE_WINDOWS:= nsxanalyzer_windows_amd64.exe
EXE_LINUX:= nsxanalyzer_linux_amd64

# TODO: update NSX_ANALYZER_IMAGE to the actual image name
NSX_ANALYZER_IMAGE = nsx-analyzer

# TODO: update IMAGE_REGISTRY to the actual image registry
IMAGE_REGISTRY      ?= docker.io
NSX_ANALYZER_TAG	?= latest

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

lint-fix:
	@echo -- $@ --
	CGO_ENABLED=0 go vet ./...
	golangci-lint run --fix

precommit: mod fmt lint

build:
	@echo -- $@ --
	CGO_ENABLED=0 go build -o ./bin/$(EXE) ./cmd


build-windows:
	@echo -- $@ --
	GOOS=windows GOARCH=amd64 go build -o ./bin/$(EXE_WINDOWS) ./cmd

build-linux:
	@echo -- $@ --
	GOOS=linux GOARCH=amd64 go build -o ./bin/$(EXE_LINUX) ./cmd

test:
	@echo -- $@ --
	go test ./... -v -coverpkg=./... -coverprofile $(COVERAGE)

coverage:
	go tool cover -html="$(COVERAGE)"

pkg/model/generated/nsx_sdk.go: schemas/top_level_schemas.txt
	schemas/generate_resources.sh schemas/top_level_schemas.txt $@

generate_sdk: pkg/model/generated/nsx_sdk.go


nsx-analyzer-image:
	docker build -t $(IMAGE_REGISTRY)/$(NSX_ANALYZER_IMAGE):$(NSX_ANALYZER_TAG) .

.DEFAULT_GOAL := build
