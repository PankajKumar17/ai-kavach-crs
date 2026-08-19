.PHONY: test lint run

test:
	pytest -v

lint:
	ruff check .

run:
	python -m ai_kavach.cli run
