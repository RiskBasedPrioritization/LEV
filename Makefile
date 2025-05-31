# Makefile
# Makefile for LEV test suite

.PHONY: test test-unit test-integration test-mathematical test-performance test-all
.PHONY: test-coverage test-quick test-slow clean setup help

# Default target
help:
	@echo "LEV Test Suite Commands:"
	@echo "  test-quick      - Run quick unit tests only"
	@echo "  test-unit       - Run all unit tests"
	@echo "  test-mathematical - Run mathematical validation tests"
	@echo "  test-integration - Run integration tests"
	@echo "  test-performance - Run performance benchmarks"
	@echo "  test-all        - Run all tests"
	@echo "  test-coverage   - Run tests with coverage report"
	@echo "  test-slow       - Run slow/long-running tests"
	@echo "  setup          - Install test dependencies"
	@echo "  clean          - Clean test artifacts"

# Quick tests (unit tests, exclude slow/performance)
test-quick:
	pytest test/ -m "not slow and not performance" -v --tb=short

# Unit tests only
test-unit:
	pytest test/test_lev_unit_tests.py -v

# Mathematical validation tests
test-mathematical:
	pytest test/test_mathematical_validation.py -v

# Integration tests
test-integration:
	pytest test/test_integration_scenarios.py -v

# Performance benchmarks
test-performance:
	pytest test/ -m "performance" -v --tb=short

# All tests including slow ones
test-all:
	pytest test/ -v

# Test coverage
test-coverage:
	pytest test/ --cov=lev_calculator --cov-report=html --cov-report=term-missing -v

# Slow tests only
test-slow:
	pytest test/ -m "slow" -v --tb=long

# Parallel test execution
test-parallel:
	pytest test/ -n auto -v

# Setup test environment
setup:
	pip install -r test/test_requirements.txt

# Clean test artifacts
clean:
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

# Continuous integration target
test-ci:
	pytest test/ -m "not performance" --tb=short --maxfail=5