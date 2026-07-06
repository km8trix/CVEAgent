.PHONY: install run worker dashboard up up-db down migrate test lint fmt

install:
	uv sync --extra dev

run:
	uv run uvicorn palisade.main:app --reload

worker:
	uv run python -m palisade.worker

dashboard:
	uv run --extra dashboard streamlit run dashboard/app.py

up:
	docker compose up -d

up-db:
	docker compose up -d db

down:
	docker compose down

migrate:
	uv run alembic upgrade head

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run mypy

fmt:
	uv run ruff format .
	uv run ruff check --fix .
