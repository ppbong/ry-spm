APP_NAME=spm

.DEFAULT_GOAL := build

.PHONY: help all build windows linux darwin

help:
	@echo "usage: make <option>"
	@echo " options and effects:"
	@echo " help   : Show help"
	@echo " all    : Build multiple binary of this project"
	@echo " build  : Build the binary of this project for current platform"
	@echo " windows: Build the windows binary of this project"
	@echo " linux  : Build the linux binary of this project"
	@echo " darwin : Build the darwin binary of this project"

all: build windows linux darwin

build:
	go build -o ${APP_NAME}

windows:
	@GOOS=windows go build -o ${APP_NAME}.exe

linux:
	@GOOS=linux go build -o ${APP_NAME}

darwin:
	@GOOS=darwin go build -o ${APP_NAME}-darwin

clean:
	@rm -rf ${APP_NAME}.exe ${APP_NAME} ${APP_NAME}-darwin

vet:
	go vet ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy