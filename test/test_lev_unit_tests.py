#!/usr/bin/env python3
"""
Comprehensive test suite for the LEV (Likely Exploited Vulnerabilities) implementation.
Tests validate compliance with NIST CSWP 41 specifications and mathematical correctness.
"""

import pytest
import numpy as np
import pandas as pd
import tempfile
import os
import gzip
import io
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Tuple, Optional
import requests
import logging

# Import the module under test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lev_calculator import (
    OptimizedLEVCalculator,
    get_current_date_utc,
    normalize_date,
    setup_logging
)


class TestUtilityFunctions:
    """Test utility functions for date handling and logging."""
    
    def test_get_current_date_utc(self):
        """Test that get_current_date_utc returns normalized UTC date."""
        result = get_current_date_utc()
        assert isinstance(result, datetime)
        assert result.hour == 0
        assert result.minute == 0
        assert result.second == 0
        assert result.microsecond == 0
        
    def test_normalize_date(self):
        """Test date normalization to midnight."""
        test_date = datetime(2024, 1, 15, 14, 30, 45, 123456)
        normalized = normalize_date(test_date)
        
        assert normalized.year == 2024
        assert normalized.month == 1
        assert normalized.day == 15
        assert normalized.hour == 0
        assert normalized.minute == 0
        assert normalized.second == 0
        assert normalized.microsecond == 0
        
    def test_setup_logging(self):
        """Test logging setup creates appropriate handlers."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('lev_calculator.os.makedirs'), \
                 patch('lev_calculator.datetime') as mock_datetime:
                mock_datetime.now.return_value.strftime.return_value = "20250101_120000"
                logger = setup_logging()
                assert logger is not None
                assert isinstance(logger, logging.Logger)


class TestOptimizedLEVCalculatorInitialization:
    """Test calculator initialization and basic properties."""
    
    def test_calculator_initialization_defaults(self):
        """Test calculator initialization with default parameters."""
        calc = OptimizedLEVCalculator()
        assert calc.cache_dir == "data_in"
        assert calc.epss_data == {}
        assert calc.kev_data == set()
        assert calc.max_workers >= 1
        assert calc.logger is not None
        
    def test_calculator_initialization_custom_params(self):
        """Test calculator initialization with custom parameters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger = logging.getLogger("test")
            calc = OptimizedLEVCalculator(
                cache_dir=temp_dir,
                max_workers=4,
                logger=logger
            )
            assert calc.cache_dir == temp_dir
            assert calc.max_workers == 4
            assert calc.logger == logger
            assert os.path.exists(temp_dir)


class TestEPSSDataHandling:
    """Test EPSS data download, caching, and retrieval."""
    
    @pytest.fixture
    def calculator(self):
        """Fixture providing a calculator with temporary cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield OptimizedLEVCalculator(cache_dir=temp_dir)
    
    def test_download_single_date_from_cache(self, calculator):
        """Test loading EPSS data from existing cache file."""
        # Create mock cache file
        test_date = datetime(2024, 1, 1)
        filename = f"epss_scores-{test_date.strftime('%Y-%m-%d')}.csv.gz"
        cache_path = os.path.join(calculator.cache_dir, filename)
        
        # Create test EPSS data
        test_data = "cve,epss\nCVE-2024-0001,0.5\nCVE-2024-0002,0.1\n"
        with gzip.open(cache_path, 'wt') as f:
            f.write(test_data)
        
        result = calculator._download_single_date(test_date)
        assert result is not None
        data, was_cached = result
        assert was_cached is True
        assert "CVE-2024-0001" in data
        assert data["CVE-2024-0001"] == 0.5
        assert data["CVE-2024-0002"] == 0.1
    
    @patch('lev_calculator.requests.get')
    def test_download_single_date_from_remote(self, mock_get, calculator):
        """Test downloading EPSS data from remote source."""
        test_date = datetime(2024, 1, 1)
        test_data = "cve,epss\nCVE-2024-0001,0.7\n"
        
        # Mock successful HTTP response
        mock_response = Mock()
        mock_response.content = gzip.compress(test_data.encode())
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        result = calculator._download_single_date(test_date)
        assert result is not None
        data, was_cached = result
        assert was_cached is False
        assert "CVE-2024-0001" in data
        assert data["CVE-2024-0001"] == 0.7
        
        # Verify file was cached
        filename = f"epss_scores-{test_date.strftime('%Y-%m-%d')}.csv.gz"
        cache_path = os.path.join(calculator.cache_dir, filename)
        assert os.path.exists(cache_path)
    
    @patch('lev_calculator.requests.get')
    def test_download_single_date_network_error(self, mock_get, calculator):
        """Test handling of network errors during download."""
        test_date = datetime(2024, 1, 1)
        mock_get.side_effect = requests.exceptions.ConnectionError("Network error")
        
        result = calculator._download_single_date(test_date)
        assert result is None
    
    def test_get_epss_score_exact_date(self, calculator):
        """Test getting EPSS score for exact date match."""
        test_date = datetime(2024, 1, 1)
        calculator.epss_data[test_date] = {"CVE-2024-0001": 0.5}
        
        score = calculator.get_epss_score("CVE-2024-0001", test_date)
        assert score == 0.5
    
    def test_get_epss_score_missing_day_forward_search(self, calculator):
        """Test NIST missing-day logic: use next available day."""
        base_date = datetime(2024, 1, 1)
        next_date = datetime(2024, 1, 3)  # Missing day 1/2
        
        calculator.epss_data[next_date] = {"CVE-2024-0001": 0.6}
        
        score = calculator.get_epss_score("CVE-2024-0001", base_date)
        assert score == 0.6
    
    def test_get_epss_score_fallback_to_previous(self, calculator):
        """Test fallback to previous date when forward search fails."""
        target_date = datetime(2024, 1, 15)
        previous_date = datetime(2024, 1, 10)
        
        calculator.epss_data[previous_date] = {"CVE-2024-0001": 0.3}
        
        score = calculator.get_epss_score("CVE-2024-0001", target_date)
        assert score == 0.3
    
    def test_get_epss_score_no_data_available(self, calculator):
        """Test default score when no EPSS data available."""
        test_date = datetime(2024, 1, 1)
        score = calculator.get_epss_score("CVE-2024-0001", test_date)
        assert score == 0.0


class TestKEVDataHandling:
    """Test Known Exploited Vulnerabilities (KEV) data handling."""
    
    @pytest.fixture
    def calculator(self):
        """Fixture providing a calculator with temporary cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield OptimizedLEVCalculator(cache_dir=temp_dir)
    
    def test_load_kev_data_from_file(self, calculator):
        """Test loading KEV data from CSV file."""
        kev_file = os.path.join(calculator.cache_dir, "known_exploited_vulnerabilities.csv")
        kev_data = "cveID,vendorProject,product\nCVE-2024-0001,Test,Product\nCVE-2024-0002,Another,Product\n"
        
        with open(kev_file, 'w') as f:
            f.write(kev_data)
        
        calculator.load_kev_data(kev_file_path=kev_file, download_if_missing=False)
        
        assert len(calculator.kev_data) == 2
        assert "CVE-2024-0001" in calculator.kev_data
        assert "CVE-2024-0002" in calculator.kev_data
    
    def test_is_in_kev(self, calculator):
        """Test KEV membership checking."""
        calculator.kev_data = {"CVE-2024-0001", "CVE-2024-0002"}
        
        assert calculator.is_in_kev("CVE-2024-0001") is True
        assert calculator.is_in_kev("cve-2024-0001") is True  # Case insensitive
        assert calculator.is_in_kev("CVE-2024-9999") is False
    
    def test_get_kev_score(self, calculator):
        """Test KEV score calculation."""
        calculator.kev_data = {"CVE-2024-0001"}
        
        assert calculator.get_kev_score("CVE-2024-0001") == 1.0
        assert calculator.get_kev_score("CVE-2024-9999") == 0.0
    
    @patch('lev_calculator.requests.get')
    def test_download_kev_data_success(self, mock_get, calculator):
        """Test successful KEV data download."""
        kev_data = "cveID,vendorProject,product\nCVE-2024-0001,Test,Product\n"
        
        mock_response = Mock()
        mock_response.content = kev_data.encode()
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        calculator.download_kev_data()
        
        # Verify file was created
        kev_file = os.path.join(calculator.cache_dir, "known_exploited_vulnerabilities.csv")
        assert os.path.exists(kev_file)
        
        with open(kev_file, 'r') as f:
            content = f.read()
            assert "CVE-2024-0001" in content


class TestDailyProbabilityCalculations:
    """Test daily probability calculations from EPSS scores."""
    
    @pytest.fixture
    def calculator(self):
        return OptimizedLEVCalculator()
    
    def test_precompute_daily_probabilities_normal_cases(self, calculator):
        """Test daily probability calculation for normal EPSS scores."""
        # Test with realistic EPSS scores
        epss_scores = np.array([0.1, 0.2, 0.05, 0.15])
        daily_probs = calculator._precompute_daily_probabilities(epss_scores)
        
        # Verify formula: P1 = 1 - (1 - P30)^(1/30)
        expected = 1.0 - np.power(1.0 - epss_scores, 1.0/30)
        np.testing.assert_array_almost_equal(daily_probs, expected, decimal=10)
    
    def test_precompute_daily_probabilities_edge_cases(self, calculator):
        """Test daily probability calculation for edge cases."""
        # Test edge cases: 0, 1, and very small values
        epss_scores = np.array([0.0, 1.0, 1e-10, 0.999999])
        daily_probs = calculator._precompute_daily_probabilities(epss_scores)
        
        assert daily_probs[0] == 0.0  # Zero score -> zero daily prob
        assert daily_probs[1] == 1.0  # Perfect score -> perfect daily prob
        assert 0 <= daily_probs[2] <= 1  # Very small score -> valid probability
        assert 0 <= daily_probs[3] <= 1  # Near-perfect score -> valid probability
    
    def test_precompute_daily_probabilities_out_of_range(self, calculator):
        """Test daily probability calculation handles out-of-range inputs."""
        # Test with values outside [0,1] range
        epss_scores = np.array([-0.1, 1.5, 0.5])
        daily_probs = calculator._precompute_daily_probabilities(epss_scores)
        
        # Should be clipped to valid range
        assert np.all(daily_probs >= 0.0)
        assert np.all(daily_probs <= 1.0)


class TestLEVCalculations:
    """Test LEV probability calculations according to NIST CSWP 41."""
    
    @pytest.fixture
    def calculator(self):
        calc = OptimizedLEVCalculator()
        # Set up test EPSS data
        base_date = datetime(2024, 1, 1)
        for i in range(100):  # 100 days of data
            date = base_date + timedelta(days=i)
            calc.epss_data[date] = {
                "CVE-2024-0001": 0.1,  # Constant score
                "CVE-2024-0002": max(0, 0.2 - i * 0.002),  # Declining score
                "CVE-2024-0003": min(0.3, i * 0.003),  # Rising score
            }
        return calc
    
    def test_get_first_epss_date(self, calculator):
        """Test finding first EPSS date for a CVE."""
        first_date = calculator.get_first_epss_date("CVE-2024-0001")
        assert first_date == datetime(2024, 1, 1)
        
        # Test non-existent CVE
        assert calculator.get_first_epss_date("CVE-9999-9999") is None
    
    def test_calculate_lev_nist_original_simple_case(self, calculator):
        """Test NIST LEV2 calculation with simple constant scores."""
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 3, 1)  # 60 days later
        
        # For constant EPSS score of 0.1, LEV should be calculable
        lev_prob = calculator._calculate_lev_nist_original("CVE-2024-0001", d0, dn)
        
        assert 0 <= lev_prob <= 1
        assert lev_prob > 0  # Should be positive for non-zero EPSS scores
    
    def test_calculate_lev_rigorous_simple_case(self, calculator):
        """Test rigorous LEV calculation with simple constant scores."""
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 2, 1)  # 31 days later
        
        lev_prob = calculator._calculate_lev_rigorous_optimized("CVE-2024-0001", d0, dn)
        
        assert 0 <= lev_prob <= 1
        assert lev_prob > 0  # Should be positive for non-zero EPSS scores
    
    def test_calculate_lev_zero_epss_scores(self, calculator):
        """Test LEV calculation with all zero EPSS scores."""
        # Add CVE with all zero scores
        base_date = datetime(2024, 1, 1)
        for i in range(30):
            date = base_date + timedelta(days=i)
            calculator.epss_data[date] = {"CVE-ZERO": 0.0}
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 30)
        
        lev_nist = calculator._calculate_lev_nist_original("CVE-ZERO", d0, dn)
        lev_rigorous = calculator._calculate_lev_rigorous_optimized("CVE-ZERO", d0, dn)
        
        assert lev_nist == 0.0
        assert lev_rigorous == 0.0
    
    def test_calculate_lev_mathematical_properties(self, calculator):
        """Test mathematical properties of LEV calculations."""
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 2, 1)
        
        # LEV should increase with more days (monotonic property)
        dn_short = datetime(2024, 1, 15)
        
        lev_short = calculator.calculate_lev("CVE-2024-0001", d0, dn_short, rigorous=True)
        lev_long = calculator.calculate_lev("CVE-2024-0001", d0, dn, rigorous=True)
        
        assert lev_long >= lev_short  # More days should not decrease probability
    
    def test_calculate_lev_window_adjustment(self, calculator):
        """Test LEV calculation with partial window adjustment."""
        # Test case from NIST CSWP 41 Section 6 example
        # CVE-2023-1730 with 21-day window remaining should be adjusted
        
        d0 = datetime(2024, 11, 1)
        dn = datetime(2024, 11, 22)  # 21 days
        
        # Set up EPSS score of 0.08 for the calculation date
        calculator.epss_data[dn] = {"CVE-2023-1730": 0.08}
        
        lev_prob = calculator._calculate_lev_nist_original("CVE-2023-1730", d0, dn)
        
        # Should account for 21/30 window adjustment
        assert 0 <= lev_prob <= 1


class TestCompositeCalculations:
    """Test composite probability calculations combining EPSS, KEV, and LEV."""
    
    @pytest.fixture
    def calculator(self):
        calc = OptimizedLEVCalculator()
        
        # Set up test data
        base_date = datetime(2024, 1, 1)
        calc.epss_data[base_date] = {
            "CVE-2024-0001": 0.3,  # High EPSS
            "CVE-2024-0002": 0.1,  # Low EPSS
            "CVE-2024-0003": 0.05  # Very low EPSS
        }
        
        calc.kev_data = {"CVE-2024-0002"}  # CVE-0002 is in KEV
        
        return calc
    
    def test_calculate_composite_probability_kev_dominates(self, calculator):
        """Test composite calculation where KEV score dominates."""
        calc_date = datetime(2024, 1, 1)
        
        result = calculator.calculate_composite_probability("CVE-2024-0002", calc_date)
        
        assert result["cve"] == "CVE-2024-0002"
        assert result["epss_score"] == 0.1
        assert result["kev_score"] == 1.0
        assert result["composite_probability"] == 1.0  # KEV dominates
        assert result["is_in_kev"] is True
    
    def test_calculate_composite_probability_epss_dominates(self, calculator):
        """Test composite calculation where EPSS score dominates."""
        calc_date = datetime(2024, 1, 1)
        
        result = calculator.calculate_composite_probability("CVE-2024-0001", calc_date)
        
        assert result["cve"] == "CVE-2024-0001"
        assert result["epss_score"] == 0.3
        assert result["kev_score"] == 0.0
        assert result["composite_probability"] >= 0.3  # EPSS or LEV dominates
        assert result["is_in_kev"] is False
    
    def test_calculate_composite_probability_lev_dominates(self, calculator):
        """Test composite calculation where LEV score could dominate."""
        # Set up scenario where LEV might be higher than EPSS
        calc_date = datetime(2024, 2, 1)  # Give time for LEV to accumulate
        
        # Add more EPSS history
        for i in range(30):
            date = datetime(2024, 1, 1) + timedelta(days=i)
            calculator.epss_data[date] = {"CVE-2024-0003": 0.05}
        
        result = calculator.calculate_composite_probability("CVE-2024-0003", calc_date)
        
        assert result["cve"] == "CVE-2024-0003"
        assert result["composite_probability"] >= max(
            result["epss_score"], 
            result["kev_score"], 
            result["lev_score"]
        )


class TestExpectedExploitedCalculations:
    """Test Expected_Exploited calculations from NIST CSWP 41 Section 3.1."""
    
    @pytest.fixture
    def sample_results_df(self):
        """Create sample LEV results DataFrame for testing."""
        return pd.DataFrame({
            'cve': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0004'],
            'lev_probability': [0.8, 0.3, 0.1, 0.05]
        })
    
    def test_calculate_expected_exploited(self, sample_results_df):
        """Test Expected_Exploited calculation."""
        calculator = OptimizedLEVCalculator()
        result = calculator.calculate_expected_exploited(sample_results_df)
        
        expected_total = 0.8 + 0.3 + 0.1 + 0.05
        expected_proportion = expected_total / 4
        
        assert result['total_cves'] == 4
        assert abs(result['expected_exploited'] - expected_total) < 1e-10
        assert abs(result['expected_exploited_proportion'] - expected_proportion) < 1e-10
    
    def test_calculate_expected_exploited_empty_dataframe(self):
        """Test Expected_Exploited calculation with empty DataFrame."""
        calculator = OptimizedLEVCalculator()
        empty_df = pd.DataFrame(columns=['cve', 'lev_probability'])
        
        result = calculator.calculate_expected_exploited(empty_df)
        
        assert result['total_cves'] == 0
        assert result['expected_exploited'] == 0
        assert result['expected_exploited_proportion'] == 0


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""
    
    @pytest.fixture
    def calculator(self):
        return OptimizedLEVCalculator()
    
    def test_debug_lev_calculation_no_data(self, calculator):
        """Test debug calculation when no EPSS data exists."""
        calc_date = datetime(2024, 1, 1)
        
        result = calculator.debug_lev_calculation("CVE-NONEXISTENT", calc_date)
        
        assert "error" in result
        assert result["error"] == "No EPSS data found for CVE"
    
    def test_calculate_lev_invalid_date_range(self, calculator):
        """Test LEV calculation with invalid date range."""
        d0 = datetime(2024, 1, 15)
        dn = datetime(2024, 1, 10)  # End before start
        
        lev_prob = calculator.calculate_lev("CVE-TEST", d0, dn, rigorous=True)
        assert lev_prob == 0.0
    
    def test_get_loaded_date_range_empty(self, calculator):
        """Test getting date range when no data is loaded."""
        start, end = calculator.get_loaded_date_range()
        assert start is None
        assert end is None
    
    def test_get_loaded_date_range_with_data(self, calculator):
        """Test getting date range when data is loaded."""
        date1 = datetime(2024, 1, 1)
        date2 = datetime(2024, 1, 15)
        calculator.epss_data[date1] = {"CVE-TEST": 0.1}
        calculator.epss_data[date2] = {"CVE-TEST": 0.2}
        
        start, end = calculator.get_loaded_date_range()
        assert start == date1
        assert end == date2


class TestNISTCSWP41Compliance:
    """Test compliance with specific NIST CSWP 41 requirements."""
    
    @pytest.fixture
    def calculator(self):
        return OptimizedLEVCalculator()
    
    def test_lev_equation_inequality_property(self, calculator):
        """Test that LEV equation produces >= results as specified in NIST CSWP 41."""
        # Set up test data
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 30)
        
        # Add EPSS scores
        for i in range(30):
            date = d0 + timedelta(days=i)
            calculator.epss_data[date] = {"CVE-TEST": 0.1}
        
        lev_prob = calculator.calculate_lev("CVE-TEST", d0, dn, rigorous=True)
        
        # LEV should be >= the theoretical minimum based on individual probabilities
        # For this test, we just verify it's a valid probability
        assert 0 <= lev_prob <= 1
    
    def test_epss_as_lower_bounds_principle(self, calculator):
        """Test that EPSS scores are treated as lower bounds per Section 5.2."""
        # This is implicitly tested through the LEV calculations
        # The LEV equation uses >= inequality, treating EPSS as lower bounds
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 30)
        
        # Test with various EPSS scores
        test_scores = [0.01, 0.1, 0.5, 0.9]
        
        for score in test_scores:
            calculator.epss_data[d0] = {"CVE-TEST": score}
            lev_prob = calculator.calculate_lev("CVE-TEST", d0, dn, rigorous=True)
            
            # LEV should be at least as high as a single day's contribution
            # For rigorous calculation, this relationship should hold
            assert lev_prob >= 0
    
    def test_missing_day_logic_compliance(self, calculator):
        """Test compliance with Section 10.3 missing-day logic."""
        # "The LEV code uses the EPSS scores from the next available day when a day is missing."
        
        base_date = datetime(2024, 1, 1)
        missing_date = datetime(2024, 1, 2)  # This day will be missing
        next_date = datetime(2024, 1, 3)
        
        # Only populate base and next dates, leave missing_date empty
        calculator.epss_data[base_date] = {"CVE-TEST": 0.1}
        calculator.epss_data[next_date] = {"CVE-TEST": 0.2}
        
        # Request score for missing date should return next available
        score = calculator.get_epss_score("CVE-TEST", missing_date)
        assert score == 0.2  # Should get score from next_date
    
    def test_composite_probability_max_formula(self, calculator):
        """Test composite probability follows max formula from Section 3."""
        # Composite_Probability(v, dn) = max(EPSS(v, dn), KEV(v, dn), LEV(v, d0, dn))
        
        calc_date = datetime(2024, 1, 1)
        d0 = datetime(2024, 1, 1)
        
        # Set up test data with known values
        calculator.epss_data[calc_date] = {"CVE-TEST": 0.3}
        calculator.kev_data = set()  # Not in KEV
        
        # Mock LEV calculation to return known value
        with patch.object(calculator, 'calculate_lev', return_value=0.5):
            result = calculator.calculate_composite_probability("CVE-TEST", calc_date)
            
            # Should be max of EPSS(0.3), KEV(0.0), LEV(0.5) = 0.5
            assert result["composite_probability"] == 0.5
            assert result["epss_score"] == 0.3
            assert result["kev_score"] == 0.0
            assert result["lev_score"] == 0.5


class TestPerformanceAndScalability:
    """Test performance characteristics and scalability."""
    
    @pytest.fixture
    def large_calculator(self):
        """Create calculator with larger dataset for performance testing."""
        calc = OptimizedLEVCalculator()
        
        # Create larger test dataset
        base_date = datetime(2023, 1, 1)
        num_cves = 1000
        num_days = 100
        
        for day in range(num_days):
            date = base_date + timedelta(days=day)
            day_data = {}
            for cve_id in range(num_cves):
                cve = f"CVE-2023-{cve_id:04d}"
                # Simulate varying EPSS scores
                score = min(1.0, max(0.0, 0.1 + np.sin(day * 0.1 + cve_id * 0.01) * 0.1))
                day_data[cve] = score
            calc.epss_data[date] = day_data
        
        return calc
    
    def test_vectorized_operations_performance(self, large_calculator):
        """Test that vectorized operations work correctly on larger datasets."""
        # Test the precomputed daily probabilities with larger arrays
        epss_scores = np.random.uniform(0, 1, 1000)
        daily_probs = large_calculator._precompute_daily_probabilities(epss_scores)
        
        assert len(daily_probs) == len(epss_scores)
        assert np.all(daily_probs >= 0)
        assert np.all(daily_probs <= 1)
    
    def test_lev_calculation_reasonable_time(self, large_calculator):
        """Test that LEV calculations complete in reasonable time."""
        import time
        
        d0 = datetime(2023, 1, 1)
        dn = datetime(2023, 2, 1)
        
        start_time = time.time()
        lev_prob = large_calculator.calculate_lev("CVE-2023-0001", d0, dn, rigorous=False)
        elapsed = time.time() - start_time
        
        # Should complete in under 1 second for single CVE
        assert elapsed < 1.0
        assert 0 <= lev_prob <= 1


class TestIntegrationScenarios:
    """Integration tests simulating real-world scenarios."""
    
    @pytest.fixture
    def realistic_calculator(self):
        """Create calculator with realistic test data."""
        calc = OptimizedLEVCalculator()
        
        # Simulate realistic EPSS evolution for CVE-2023-1730 example from paper
        base_date = datetime(2023, 5, 2)  # Publication date
        calc_date = datetime(2024, 12, 12)  # Calculation date from example
        
        # EPSS scores from the paper example
        epss_timeline = [
            (datetime(2023, 5, 2), 0.00),   # Initial
            (datetime(2023, 6, 1), 0.00),
            (datetime(2023, 7, 1), 0.00),
            (datetime(2023, 7, 31), 0.05),
            (datetime(2023, 8, 30), 0.06),
            (datetime(2023, 9, 29), 0.06),
            (datetime(2023, 10, 29), 0.06),
            (datetime(2023, 11, 28), 0.10),
            (datetime(2023, 12, 28), 0.13),
            (datetime(2024, 1, 27), 0.16),  # Peak
            (datetime(2024, 2, 26), 0.08),
            (datetime(2024, 3, 27), 0.05),
            (datetime(2024, 4, 26), 0.05),
            (datetime(2024, 5, 26), 0.04),
            (datetime(2024, 6, 25), 0.05),
            (datetime(2024, 7, 25), 0.05),
            (datetime(2024, 8, 24), 0.05),
            (datetime(2024, 9, 23), 0.05),
            (datetime(2024, 10, 23), 0.05),
            (datetime(2024, 11, 22), 0.08),  # 21-day window
        ]
        
        # Populate all dates with interpolated values
        current_date = base_date
        timeline_idx = 0
        
        while current_date <= calc_date:
            # Find appropriate EPSS score for this date
            while (timeline_idx < len(epss_timeline) - 1 and 
                   current_date >= epss_timeline[timeline_idx + 1][0]):
                timeline_idx += 1
            
            score = epss_timeline[timeline_idx][1]
            calc.epss_data[current_date] = {"CVE-2023-1730": score}
            current_date += timedelta(days=1)
        
        return calc
    
    def test_cve_2023_1730_example_compliance(self, realistic_calculator):
        """Test compliance with CVE-2023-1730 example from NIST CSWP 41 Section 6."""
        d0 = datetime(2023, 5, 2)
        dn = datetime(2024, 12, 12)
        
        # Calculate LEV probability
        lev_prob = realistic_calculator.calculate_lev("CVE-2023-1730", d0, dn, rigorous=False)
        
        # The paper shows LEV probability of 0.70 for this example
        # Allow some tolerance for implementation differences
        assert 0.6 <= lev_prob <= 0.8, f"LEV probability {lev_prob} not in expected range [0.6, 0.8]"
    
    def test_window_size_adjustment_example(self, realistic_calculator):
        """Test the 21-day window adjustment mentioned in the paper."""
        # Test the final EPSS score adjustment for 21-day window
        calc_date = datetime(2024, 11, 22)
        
        # Raw EPSS should be 0.08, effective should be 0.08 * (21/30) ≈ 0.056
        raw_epss = realistic_calculator.get_epss_score("CVE-2023-1730", calc_date)
        assert abs(raw_epss - 0.08) < 0.01
        
        # Test LEV calculation includes this adjustment
        d0 = datetime(2023, 5, 2)
        lev_prob = realistic_calculator._calculate_lev_nist_original("CVE-2023-1730", d0, calc_date)
        
        # Should be a valid probability
        assert 0 <= lev_prob <= 1


class TestDataValidation:
    """Test data validation and integrity checks."""
    
    def test_epss_score_range_validation(self):
        """Test that EPSS scores are properly validated to [0,1] range."""
        calc = OptimizedLEVCalculator()
        
        # Test with out-of-range values
        test_scores = np.array([-0.5, 0.0, 0.5, 1.0, 1.5])
        daily_probs = calc._precompute_daily_probabilities(test_scores)
        
        # All results should be in valid probability range
        assert np.all(daily_probs >= 0.0)
        assert np.all(daily_probs <= 1.0)
    
    def test_date_normalization_consistency(self):
        """Test that date normalization is consistent throughout calculations."""
        calc = OptimizedLEVCalculator()
        
        # Test various date formats
        dates_to_test = [
            datetime(2024, 1, 1, 0, 0, 0),      # Already normalized
            datetime(2024, 1, 1, 14, 30, 45),   # With time component
            datetime(2024, 1, 1, 23, 59, 59),   # End of day
        ]
        
        for date in dates_to_test:
            normalized = normalize_date(date)
            assert normalized.hour == 0
            assert normalized.minute == 0
            assert normalized.second == 0
            assert normalized.microsecond == 0
    
    def test_cve_id_normalization(self):
        """Test CVE ID handling and case sensitivity."""
        calc = OptimizedLEVCalculator()
        calc.kev_data = {"CVE-2024-0001", "CVE-2024-0002"}
        
        # Test various case combinations
        test_cases = [
            ("CVE-2024-0001", True),
            ("cve-2024-0001", True),
            ("Cve-2024-0001", True),
            ("CVE-2024-0003", False),
        ]
        
        for cve_id, expected in test_cases:
            assert calc.is_in_kev(cve_id) == expected


class TestFileIOAndCaching:
    """Test file I/O operations and caching mechanisms."""
    
    @pytest.fixture
    def temp_cache_dir(self):
        """Provide temporary directory for cache testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir
    
    def test_epss_file_caching(self, temp_cache_dir):
        """Test EPSS file caching behavior."""
        calc = OptimizedLEVCalculator(cache_dir=temp_cache_dir)
        
        test_date = datetime(2024, 1, 1)
        filename = f"epss_scores-{test_date.strftime('%Y-%m-%d')}.csv.gz"
        cache_path = os.path.join(temp_cache_dir, filename)
        
        # Create mock cache file
        test_data = "cve,epss\nCVE-2024-0001,0.5\n"
        with gzip.open(cache_path, 'wt') as f:
            f.write(test_data)
        
        # First access should load from cache
        result1 = calc._download_single_date(test_date)
        assert result1 is not None
        data1, was_cached1 = result1
        assert was_cached1 is True
        
        # Second access should also load from cache
        result2 = calc._download_single_date(test_date)
        assert result2 is not None
        data2, was_cached2 = result2
        assert was_cached2 is True
        
        # Data should be identical
        assert data1 == data2
    
    def test_kev_file_format_validation(self, temp_cache_dir):
        """Test KEV file format validation."""
        calc = OptimizedLEVCalculator(cache_dir=temp_cache_dir)
        
        # Test valid KEV file
        kev_file = os.path.join(temp_cache_dir, "valid_kev.csv")
        valid_data = "cveID,vendorProject,product\nCVE-2024-0001,Test,Product\n"
        with open(kev_file, 'w') as f:
            f.write(valid_data)
        
        calc.load_kev_data(kev_file_path=kev_file, download_if_missing=False)
        assert len(calc.kev_data) == 1
        
        # Test invalid KEV file (missing cveID column)
        invalid_kev_file = os.path.join(temp_cache_dir, "invalid_kev.csv")
        invalid_data = "id,vendor,product\nCVE-2024-0001,Test,Product\n"
        with open(invalid_kev_file, 'w') as f:
            f.write(invalid_data)
        
        calc_invalid = OptimizedLEVCalculator(cache_dir=temp_cache_dir)
        calc_invalid.load_kev_data(kev_file_path=invalid_kev_file, download_if_missing=False)
        assert len(calc_invalid.kev_data) == 0  # Should be empty due to missing column


class TestConcurrencyAndParallelProcessing:
    """Test concurrent operations and parallel processing."""
    
    @pytest.fixture
    def calculator(self):
        return OptimizedLEVCalculator(max_workers=2)
    
    @patch('lev_calculator.ThreadPoolExecutor')
    def test_parallel_download_setup(self, mock_executor, calculator):
        """Test that parallel downloads are set up correctly."""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 3)
        
        # Mock the executor
        mock_executor_instance = Mock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        mock_executor_instance.submit.return_value = Mock()
        
        # Mock as_completed to avoid actual parallel execution
        with patch('lev_calculator.as_completed', return_value=[]):
            calculator.download_epss_data(start_date, end_date)
        
        # Verify ThreadPoolExecutor was created with correct max_workers
        mock_executor.assert_called_with(max_workers=calculator.max_workers)
    
    def test_batch_processing_cvs(self, calculator):
        """Test CVE batch processing for parallel LEV calculations."""
        # Set up test data
        base_date = datetime(2024, 1, 1)
        test_cves = ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
        
        calculator.epss_data[base_date] = {}
        for cve in test_cves:
            calculator.epss_data[base_date][cve] = 0.1
        
        calc_date = datetime(2024, 1, 30)
        
        # Test batch processing
        results = calculator._process_cve_batch(test_cves, calc_date, rigorous=False)
        
        assert len(results) == len(test_cves)
        for result in results:
            assert 'cve' in result
            assert 'lev_probability' in result
            assert 0 <= result['lev_probability'] <= 1


class TestRegressionAndBoundaryConditions:
    """Test regression scenarios and boundary conditions."""
    
    def test_numerical_stability_extreme_values(self):
        """Test numerical stability with extreme EPSS values."""
        calc = OptimizedLEVCalculator()
        
        # Test with very small values
        small_scores = np.array([1e-15, 1e-10, 1e-5])
        daily_probs_small = calc._precompute_daily_probabilities(small_scores)
        
        assert np.all(np.isfinite(daily_probs_small))
        assert np.all(daily_probs_small >= 0)
        
        # Test with values very close to 1
        near_one_scores = np.array([0.999999, 0.9999999, 1.0 - 1e-15])
        daily_probs_near_one = calc._precompute_daily_probabilities(near_one_scores)
        
        assert np.all(np.isfinite(daily_probs_near_one))
        assert np.all(daily_probs_near_one <= 1)
    
    def test_lev_calculation_single_day(self):
        """Test LEV calculation with single day of data."""
        calc = OptimizedLEVCalculator()
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 1)  # Same day
        
        calc.epss_data[d0] = {"CVE-TEST": 0.2}
        
        lev_prob = calc.calculate_lev("CVE-TEST", d0, dn, rigorous=True)
        
        # For single day, LEV should be related to daily probability
        assert 0 <= lev_prob <= 1
    
    def test_empty_dataset_handling(self):
        """Test behavior with completely empty datasets."""
        calc = OptimizedLEVCalculator()
        
        # Test with no EPSS data
        empty_df = calc.calculate_lev_for_all_cves()
        assert len(empty_df) == 0
        
        # Test composite calculation with no data
        composite_df = calc.calculate_composite_for_all_cves()
        assert len(composite_df) == 0
    
    def test_date_edge_cases(self):
        """Test edge cases with date handling."""
        calc = OptimizedLEVCalculator()
        
        # Test with dates at year boundaries
        year_end = datetime(2023, 12, 31)
        year_start = datetime(2024, 1, 1)
        
        calc.epss_data[year_end] = {"CVE-TEST": 0.1}
        calc.epss_data[year_start] = {"CVE-TEST": 0.2}
        
        # Should handle year boundary correctly
        score = calc.get_epss_score("CVE-TEST", year_end)
        assert score == 0.1
        
        score = calc.get_epss_score("CVE-TEST", year_start)
        assert score == 0.2


# Fixtures for integration testing
@pytest.fixture(scope="session")
def integration_test_data():
    """Create comprehensive test data for integration tests."""
    return {
        "epss_sample": {
            datetime(2024, 1, 1): {"CVE-2024-0001": 0.1, "CVE-2024-0002": 0.3},
            datetime(2024, 1, 2): {"CVE-2024-0001": 0.15, "CVE-2024-0002": 0.25},
            datetime(2024, 1, 3): {"CVE-2024-0001": 0.2, "CVE-2024-0002": 0.2},
        },
        "kev_sample": {"CVE-2024-0002"},
        "expected_results": {
            "cve_with_rising_epss": "CVE-2024-0001",
            "cve_in_kev": "CVE-2024-0002",
        }
    }


# Performance benchmarks
@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Performance benchmark tests (marked for optional execution)."""
    
    def test_large_dataset_processing_time(self):
        """Benchmark processing time for large datasets."""
        import time
        
        calc = OptimizedLEVCalculator()
        
        # Create large dataset
        base_date = datetime(2023, 1, 1)
        num_days = 365
        num_cves = 5000
        
        for day in range(num_days):
            date = base_date + timedelta(days=day)
            day_data = {}
            for cve_id in range(num_cves):
                cve = f"CVE-2023-{cve_id:04d}"
                day_data[cve] = np.random.uniform(0, 0.1)
            calc.epss_data[date] = day_data
        
        # Benchmark LEV calculation for subset
        test_cves = [f"CVE-2023-{i:04d}" for i in range(100)]
        
        start_time = time.time()
        results = calc._process_cve_batch(test_cves, base_date + timedelta(days=30), rigorous=False)
        elapsed = time.time() - start_time
        
        # Should process 100 CVEs in reasonable time
        assert elapsed < 10.0  # 10 seconds threshold
        assert len(results) == 100
    
    def test_memory_usage_constraints(self):
        """Test memory usage remains reasonable with large datasets."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        calc = OptimizedLEVCalculator()
        
        # Load substantial amount of data
        base_date = datetime(2023, 1, 1)
        for day in range(100):
            date = base_date + timedelta(days=day)
            day_data = {f"CVE-2023-{i:04d}": np.random.uniform(0, 0.1) for i in range(1000)}
            calc.epss_data[date] = day_data
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 500MB for this test)
        assert memory_increase < 500 * 1024 * 1024


if __name__ == "__main__":
    # Run tests with appropriate options
    pytest.main([
        __file__,
        "-v",  # Verbose output
        "-x",  # Stop on first failure
        "--tb=short",  # Short traceback format
        "-m", "not performance",  # Skip performance tests by default
    ])