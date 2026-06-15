.PHONY: help up down build test lint benchmark storage-estimate \
        topics health logs clean

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  up               Start the full stack (Docker Compose)"
	@echo "  down             Stop and remove all containers and volumes"
	@echo "  build            Build all Docker images"
	@echo "  test             Run the full test suite"
	@echo "  lint             Lint Python services"
	@echo "  benchmark        Run k6 load test (requires k6 installed)"
	@echo "  storage-estimate Print storage growth estimates"
	@echo "  topics           Create Kafka topics"
	@echo "  health           Check health of all services"
	@echo "  logs             Tail logs from all services"
	@echo "  clean            Remove build artifacts and __pycache__"

up:
	cp -n .env.example .env 2>/dev/null || true
	docker-compose up -d --build
	@echo "Stack is up. Run 'make health' to verify."

down:
	docker-compose down -v --remove-orphans

build:
	docker-compose build --parallel

test:
	pip install -q -r tests/requirements.txt
	python -m pytest tests/ -v --cov=services --cov-report=term-missing

lint:
	pip install -q ruff
	ruff check services/ tests/

benchmark:
	k6 run --env BASE_URL=http://localhost:8000 benchmarks/k6/load_test.js

benchmark-locust:
	locust -f benchmarks/locust/locustfile.py --headless -u 200 -r 20 --run-time 60s

storage-estimate:
	python benchmarks/storage_analysis.py

topics:
	bash messaging/kafka-topics.sh

health:
	bash scripts/healthcheck.sh

logs:
	docker-compose logs -f --tail=100

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
	rm -rf .pytest_cache/ .coverage htmlcov/
