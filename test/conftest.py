# conftest.py
"""
Shared test configuration and fixtures for LEV test suite.
"""

import pytest
import tempfile
import os
import gzip
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import logging

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lev_calculator import OptimizedLEVCalculator


@pytest.fixture(scope="session")
def test_logger():
    """Provide a test logger for all tests."""
    logger = logging.getLogger("test_lev")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


@pytest.fixture
def temp_cache_dir():
    """Provide a temporary cache directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def basic_calculator(temp_cache_dir, test_logger):
    """Provide a basic calculator instance for testing."""
    return OptimizedLEVCalculator(cache_dir=temp_cache_dir, logger=test_logger)


@pytest.fixture
def sample_epss_data():
    """Provide sample EPSS data for testing."""
    base_date = datetime(2024, 1, 1)
    data = {}
    
    for i in range(30):
        date = base_date + timedelta(days=i)
        data[date] = {
            "CVE-2024-0001": 0.1 + i * 0.001,  # Slowly rising
            "CVE-2024-0002": max(0, 0.3 - i * 0.01),  # Declining
            "CVE-2024-0003": 0.05,  # Stable
            "CVE-2024-0004": 0.0,  # Zero
        }
    
    return data


@pytest.fixture
def sample_kev_data():
    """Provide sample KEV data for testing."""
    return {"CVE-2024-0001", "CVE-2024-0005", "CVE-2024-0006"}


@pytest.fixture
def calculator_with_data(basic_calculator, sample_epss_data, sample_kev_data):
    """Provide a calculator pre-loaded with test data."""
    basic_calculator.epss_data = sample_epss_data
    basic_calculator.kev_data = sample_kev_data
    return basic_calculator


@pytest.fixture
def mock_network_responses():
    """Provide mock network responses for download testing."""
    def _create_epss_response(cves_scores):
        """Create a mock EPSS file response."""
        content = "cve,epss\n"
        for cve, score in cves_scores.items():
            content += f"{cve},{score}\n"
        
        response = Mock()
        response.content = gzip.compress(content.encode())
        response.raise_for_status.return_value = None
        return response
    
    def _create_kev_response(cves):
        """Create a mock KEV file response."""
        content = "cveID,vendorProject,product\n"
        for i, cve in enumerate(cves):
            content += f"{cve},Vendor{i},Product{i}\n"
        
        response = Mock()
        response.content = content.encode()
        response.raise_for_status.return_value = None
        return response
    
    return {
        "epss": _create_epss_response,
        "kev": _create_kev_response
    }


# Test data constants
NIST_CSWP_41_EXAMPLES = {
    "CVE-2023-1730": {
        "publication_date": datetime(2023, 5, 2),
        "calculation_date": datetime(2024, 12, 12),
        "expected_lev": 0.70,
        "peak_epss": 0.16,
        "peak_date": datetime(2024, 1, 27),
        "epss_timeline": [
            (datetime(2023, 5, 2), 0.00),
            (datetime(2023, 6, 1), 0.00),
            (datetime(2023, 7, 1), 0.00),
            (datetime(2023, 7, 31), 0.05),
            (datetime(2023, 8, 30), 0.06),
            (datetime(2023, 9, 29), 0.06),
            (datetime(2023, 10, 29), 0.06),
            (datetime(2023, 11, 28), 0.10),
            (datetime(2023, 12, 28), 0.13),
            (datetime(2024, 1, 27), 0.16),
            (datetime(2024, 2, 26), 0.08),
            (datetime(2024, 3, 27), 0.05),
            (datetime(2024, 4, 26), 0.05),
            (datetime(2024, 5, 26), 0.04),
            (datetime(2024, 6, 25), 0.05),
            (datetime(2024, 7, 25), 0.05),
            (datetime(2024, 8, 24), 0.05),
            (datetime(2024, 9, 23), 0.05),
            (datetime(2024, 10, 23), 0.05),
            (datetime(2024, 11, 22), 0.08),
        ]
    },
    "CVE-2023-29373": {
        "publication_date": datetime(2023, 6, 14),
        "calculation_date": datetime(2025, 1, 22),
        "expected_lev": 0.54350,
        "peak_epss": 0.08,
        "peak_date": datetime(2024, 3, 10),
        "epss_timeline": [
            (datetime(2023, 6, 14), 0.00),
            (datetime(2023, 7, 14), 0.05),
            (datetime(2023, 8, 13), 0.02),
            (datetime(2023, 9, 12), 0.02),
            (datetime(2023, 10, 12), 0.03),
            (datetime(2023, 11, 11), 0.04),
            (datetime(2023, 12, 11), 0.05),
            (datetime(2024, 1, 10), 0.06),
            (datetime(2024, 2, 9), 0.08),
            (datetime(2024, 3, 10), 0.08),
            (datetime(2024, 4, 9), 0.07),
            (datetime(2024, 5, 9), 0.04),
            (datetime(2024, 6, 8), 0.04),
            (datetime(2024, 7, 8), 0.03),
            (datetime(2024, 8, 7), 0.03),
            (datetime(2024, 9, 6), 0.03),
            (datetime(2024, 10, 6), 0.03),
            (datetime(2024, 11, 5), 0.03),
            (datetime(2024, 12, 5), 0.03),
            (datetime(2025, 1, 4), 0.00),
        ]
    }
}


@pytest.fixture
def nist_examples():
    """Provide NIST CSWP 41 example data."""
    return NIST_CSWP_41_EXAMPLES


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as performance benchmark"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "mathematical: mark test as mathematical validation"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Mark performance tests
        if "performance" in item.nodeid.lower():
            item.add_marker(pytest.mark.performance)
        
        # Mark integration tests
        if "integration" in item.nodeid.lower() or "end_to_end" in item.nodeid.lower():
            item.add_marker(pytest.mark.integration)
        
        # Mark mathematical tests
        if "mathematical" in item.nodeid.lower() or "formula" in item.nodeid.lower():
            item.add_marker(pytest.mark.mathematical)
        
        # Mark slow tests
        if any(keyword in item.nodeid.lower() for keyword in ["large_dataset", "full_system", "benchmark"]):
            item.add_marker(pytest.mark.slow)


# Custom assertion helpers
def assert_valid_probability(value, tolerance=1e-10):
    """Assert that a value is a valid probability [0, 1]."""
    assert isinstance(value, (int, float)), f"Expected numeric value, got {type(value)}"
    assert -tolerance <= value <= 1 + tolerance, f"Probability {value} not in valid range [0, 1]"


def assert_lev_probability_properties(lev_result, epss_scores=None):
    """Assert that LEV probability has expected mathematical properties."""
    assert_valid_probability(lev_result)
    
    # LEV should be 0 if all EPSS scores are 0
    if epss_scores is not None and all(score == 0 for score in epss_scores):
        assert lev_result == 0.0
    
    # LEV should be > 0 if any EPSS score > 0
    if epss_scores is not None and any(score > 0 for score in epss_scores):
        assert lev_result >= 0.0


def assert_composite_probability_properties(composite_result):
    """Assert that composite probability has expected properties."""
    assert "epss_score" in composite_result
    assert "kev_score" in composite_result
    assert "lev_score" in composite_result
    assert "composite_probability" in composite_result
    
    # All components should be valid probabilities
    for component in ["epss_score", "kev_score", "lev_score", "composite_probability"]:
        assert_valid_probability(composite_result[component])
    
    # Composite should be max of components
    expected_max = max(
        composite_result["epss_score"],
        composite_result["kev_score"],
        composite_result["lev_score"]
    )
    assert abs(composite_result["composite_probability"] - expected_max) < 1e-10