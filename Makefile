.PHONY: setup check demo serve
setup:
	uv sync --locked
	uv run alembic upgrade head
check:
	uv run ruff check src tests migrations scripts sandbox
	uv run ruff format --check src tests migrations scripts sandbox
	uv run mypy src
	uv run bandit -q -r src sandbox
	uv run pytest -q
demo:
	uv run python scripts/demo.py
serve:
	uv run uvicorn sentinel.api:app --host 127.0.0.1 --port 8000 --no-proxy-headers
