PYTHON=python
PIP=pip

.PHONY: install run test lint compose-up compose-down

install:
	$(PIP) install -r requirements.txt

run:
	uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest -q

lint:
	$(PYTHON) -m compileall src tests

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down
