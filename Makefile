SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

ifneq (,$(wildcard .env))
include .env
export
endif

COMPOSE := docker compose
GOOSE := go tool goose
MIGRATIONS_DIR := db/migrations/postgres
POSTGRES_DSN = postgres://$(KEYLOG_POSTGRES_USER):$(KEYLOG_POSTGRES_PASSWORD)@$(KEYLOG_POSTGRES_HOST):$(KEYLOG_POSTGRES_PORT)/$(KEYLOG_POSTGRES_DB)?sslmode=$(KEYLOG_POSTGRES_SSLMODE)

.PHONY: help env infra infra-down infra-reset psql keys \
        migrate-create migrate-up migrate-down migrate-status migrate-redo \
        build run test lint lint-fix fixtures require-env

help:
	@printf "Targets:\n"
	@printf "  make env                                Create .env from .env.example\n"
	@printf "  make infra                              Start postgres\n"
	@printf "  make infra-down                         Stop, keep volumes\n"
	@printf "  make infra-reset                        Stop and destroy volumes\n"
	@printf "  make psql                               psql shell\n"
	@printf "\n"
	@printf "  make keys                               Generate a dev note + VRF keypair\n"
	@printf "  make migrate-create name=<snake_name>   Create a new SQL migration\n"
	@printf "  make migrate-up                         Apply all pending migrations\n"
	@printf "  make migrate-down                       Roll back the most recent migration\n"
	@printf "  make migrate-redo                       Roll back and re-apply the latest\n"
	@printf "  make migrate-status                     Show applied/pending migrations\n"
	@printf "\n"
	@printf "  make build                              go build -o bin/keylog .\n"
	@printf "  make run                                Run the server\n"
	@printf "  make test                               go test ./...\n"
	@printf "  make lint                               golangci-lint run\n"
	@printf "  make fixtures out=<path>                Regenerate client test vectors\n"

env:
	@if [ -f .env ]; then echo ".env already exists"; else cp .env.example .env && echo "wrote .env"; fi

infra:
	$(COMPOSE) up -d postgres

infra-down:
	$(COMPOSE) down

infra-reset:
	$(COMPOSE) down -v

psql:
	$(COMPOSE) exec postgres psql -U $(KEYLOG_POSTGRES_USER) -d $(KEYLOG_POSTGRES_DB)

keys:
	go run . generate-keys

require-env:
	@if [ -z "$(KEYLOG_POSTGRES_USER)" ]; then echo "no .env — run: make env" >&2; exit 1; fi

migrate-create:
	@if [ -z "$(name)" ]; then \
		echo "usage: make migrate-create name=<snake_name>" >&2; exit 1; \
	fi
	@mkdir -p $(MIGRATIONS_DIR)
	$(GOOSE) -dir $(MIGRATIONS_DIR) create $(name) sql

migrate-up: require-env
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(POSTGRES_DSN)" up

migrate-down: require-env
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(POSTGRES_DSN)" down

migrate-redo: require-env
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(POSTGRES_DSN)" redo

migrate-status: require-env
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(POSTGRES_DSN)" status

build:
	go build -o bin/keylog .

run:
	go run . serve

test:
	go test ./...

lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

fixtures:
	@if [ -z "$(out)" ]; then echo "usage: make fixtures out=<path>" >&2; exit 1; fi
	go run . fixtures --out $(out)
