# binoracle - developer tasks
PY ?= python3

.PHONY: help install install-all install-tools test samples lint clean

help:
	@echo 'make install       - editable install (core, stdlib only)'
	@echo 'make install-all   - install with r2pipe + angr + pyelftools + capstone'
	@echo 'make install-tools - install the optional pentest toolchain (see binoracle tools)'
	@echo 'make test          - run the offline test suite'
	@echo 'make samples       - build the practice ELF/PE corpus via Docker'
	@echo 'make lint          - byte-compile the package'
	@echo 'make clean         - remove build artifacts and local state'

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

pwn-image:
	docker build --platform linux/amd64 -t binoracle-pwn -f .docker/Dockerfile.pwn .docker

clean-docker:
	docker builder prune -f && docker image prune -f
