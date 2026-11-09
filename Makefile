# Makefile: developer entry points, mirrored by .github/workflows/ci.yml.
# `make check` is the single gate a unit must pass before it's considered done.

.PHONY: check audit-voice fmt test

check:
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy
	uv run pytest
	uv run bandit -c pyproject.toml -r src
	uv run pip-audit --progress-spinner off
	$(MAKE) audit-voice

# Mirrors CI's "pip-audit (claudia-voice extra)": `uv sync` installs no
# extras, so the host's TTS stack is audited from a locked export instead.
audit-voice:
	uv export --locked --no-dev --extra claudia-voice --no-emit-project --format requirements-txt -o .voice-requirements.txt
	uv run pip-audit --progress-spinner off --disable-pip -r .voice-requirements.txt
	rm .voice-requirements.txt

fmt:
	uv run ruff format .
	uv run ruff check --fix .

test:
	uv run pytest
