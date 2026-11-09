# binoracle - developer tasks
PY ?= python3

.PHONY: help install install-all install-tools test samples lint clean \
        docker docker-build docker-down docker-shell docker-logs docker-test pwn-image clean-docker

help:
	@echo 'make install       - editable install (core, stdlib only)'
	@echo 'make install-all   - install with r2pipe + angr + pyelftools + capstone'
	@echo 'make install-tools - install the optional pentest toolchain (see binoracle tools)'
	@echo 'make test          - run the offline test suite'
	@echo 'make samples       - build the practice ELF/PE corpus via Docker'
	@echo 'make lint          - byte-compile the package'
	@echo 'make clean         - remove build artifacts and local state'
	@echo 'make docker        - build + run binoracle in Docker (web UI on http://127.0.0.1:8080)'
	@echo 'make docker-build  - build the image only (no run)'
	@echo 'make docker-test   - run the full "probar todo" smoke inside the container'
	@echo 'make docker-shell  - open a shell inside the running container'
	@echo 'make docker-logs   - follow the container logs'
	@echo 'make docker-down   - stop and remove the container'

install-tools:
	bash scripts/install-tools.sh

install:
	$(PY) -m pip install -e .

install-all:
	$(PY) -m pip install -e '.[all]' r2pipe

test:
	$(PY) -m pytest -q tests/

samples:
	bash samples/build.sh

lint:
	$(PY) -m compileall -q binoracle && echo 'compile ok'

clean:
	rm -rf build dist *.egg-info .binoracle .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# --- Docker (app image): one-command local run, incl. the exploit engine ---
# Uses `docker compose` (v2) if present, else falls back to legacy `docker-compose`.
DC := $(shell if docker compose version >/dev/null 2>&1; then echo 'docker compose'; else echo 'docker-compose'; fi)

docker: docker-build
	$(DC) up -d
	@echo 'binoracle web UI -> http://127.0.0.1:8080   (make docker-logs | make docker-down)'

docker-build:
	$(DC) build

docker-test:
	$(DC) run --rm binoracle bash scripts/docker-smoke.sh

docker-shell:
	$(DC) exec binoracle bash || $(DC) run --rm binoracle bash

docker-logs:
	$(DC) logs -f binoracle

docker-down:
	$(DC) down

pwn-image:
	docker build --platform linux/amd64 -t binoracle-pwn -f .docker/Dockerfile.pwn .docker

clean-docker:
	docker builder prune -f && docker image prune -f
