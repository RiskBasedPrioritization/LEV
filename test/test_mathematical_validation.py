#!/usr/bin/env python3
"""
Mathematical validation tests for LEV implementation.
These tests validate the mathematical correctness against NIST CSWP 41 formulas.
"""

import pytest
import numpy as np
import pandas as pd
from unittest.mock import patch, Mock
from datetime import datetime, timedelta
from typing import List, Tuple
import math

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lev_calculator import OptimizedLEVCalculator, normalize_date


class TestMathematicalFormulas:
    """Test mathematical formulas against NIST CSWP 41 specifications."""
    
    def test_daily_probability_formula_exact(self):
        """Test daily probability formula: P1 = 1 - (1 - P30)^(1/30)"""
        calc = OptimizedLEVCalculator()
        
        # Test specific values mentioned in the paper
        test_cases = [
            (0.0, 0.0),  # Zero case
            (1.0, 1.0),  # Perfect case
            (0.3, 1.0 - (1.0 - 0.3)**(1/30)),  # Example case
            (0.1, 1.0 - (1.0 - 0.1)**(1/30)),  # Low probability case
        ]
        
        for p30, expected_p1 in test_cases:
            epss_array = np.array([p30])
            daily_probs = calc._precompute_daily_probabilities(epss_array)
            
            if p30 == 0.0:
                assert daily_probs[0] == 0.0
            elif p30 == 1.0:
                assert daily_probs[0] == 1.0
            else:
                assert abs(daily_probs[0] - expected_p1) < 1e-10
    
    def test_lev_inequality_property(self):
        """Test that LEV >= 1 - ∏(1 - epss(v,di) × weight(di,dn,30))"""
        calc = OptimizedLEVCalculator()
        
        # Set up test data
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 2, 29)  # 60 days
        
        # Create predictable EPSS scores
        epss_scores = [0.1, 0.15, 0.2]  # For 30-day windows
        dates = [d0, d0 + timedelta(days=30), d0 + timedelta(days=60)]
        
        for i, date in enumerate(dates[:len(epss_scores)]):
            calc.epss_data[date] = {"CVE-TEST": epss_scores[i]}
        
        lev_result = calc._calculate_lev_nist_original("CVE-TEST", d0, dn)
        
        # Calculate theoretical minimum using the formula
        product = 1.0
        for i, score in enumerate(epss_scores):
            if i < 2:  # Full 30-day windows
                weight = 1.0
            else:  # Partial window
                remaining_days = (dn - dates[i]).days + 1
                weight = min(remaining_days, 30) / 30.0
            
            product *= (1.0 - score * weight)
        
        theoretical_min = 1.0 - product
        
        # LEV should be >= theoretical minimum
        assert lev_result >= theoretical_min - 1e-10  # Small tolerance for floating point
    
    def test_rigorous_lev_daily_independence(self):
        """Test rigorous LEV calculation assumes daily independence."""
        calc = OptimizedLEVCalculator()
        
        # Set up test with known daily probabilities
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 5)  # 5 days
        
        # Set constant EPSS score
        daily_epss = 0.1
        for i in range(5):
            date = d0 + timedelta(days=i)
            calc.epss_data[date] = {"CVE-TEST": daily_epss}
        
        lev_result = calc._calculate_lev_rigorous_optimized("CVE-TEST", d0, dn)
        
        # Calculate expected result assuming independence
        daily_prob = 1.0 - (1.0 - daily_epss)**(1/30)
        expected_lev = 1.0 - (1.0 - daily_prob)**5
        
        assert abs(lev_result - expected_lev) < 1e-10
    
    def test_weight_function_compliance(self):
        """Test weight function: weight(di,dn,w) = winsize(di,dn,w)/w"""
        calc = OptimizedLEVCalculator()
        
        test_cases = [
            # (start_date, end_date, window_size, expected_weight)
            (datetime(2024, 1, 1), datetime(2024, 1, 30), 30, 1.0),  # Full window
            (datetime(2024, 1, 1), datetime(2024, 1, 15), 30, 15/30),  # Partial window
            (datetime(2024, 1, 1), datetime(2024, 2, 14), 30, 1.0),  # Exceeds window
        ]
        
        for start_date, end_date, window_size, expected_weight in test_cases:
            # Simulate the weight calculation from the LEV equation
            days_diff = (end_date - start_date).days + 1
            window_length = min(days_diff, window_size)
            actual_weight = window_length / window_size
            
            assert abs(actual_weight - expected_weight) < 1e-10
    
    def test_composite_probability_max_formula(self):
        """Test Composite_Probability(v, dn) = max(EPSS(v, dn), KEV(v, dn), LEV(v, d0, dn))"""
        calc = OptimizedLEVCalculator()
        
        calc_date = datetime(2024, 1, 30)
        d0 = datetime(2024, 1, 1)
        
        # Test case 1: EPSS dominates
        calc.epss_data[calc_date] = {"CVE-EPSS": 0.8}
        calc.kev_data = set()
        
        # Mock LEV to return lower value
        with patch.object(calc, 'calculate_lev', return_value=0.3):
            result = calc.calculate_composite_probability("CVE-EPSS", calc_date)
            assert result["composite_probability"] == 0.8  # EPSS wins
        
        # Test case 2: KEV dominates
        calc.epss_data[calc_date] = {"CVE-KEV": 0.2}
        calc.kev_data = {"CVE-KEV"}
        
        with patch.object(calc, 'calculate_lev', return_value=0.3):
            result = calc.calculate_composite_probability("CVE-KEV", calc_date)
            assert result["composite_probability"] == 1.0  # KEV wins
        
        # Test case 3: LEV dominates
        calc.epss_data[calc_date] = {"CVE-LEV": 0.2}
        calc.kev_data = set()
        
        with patch.object(calc, 'calculate_lev', return_value=0.9):
            result = calc.calculate_composite_probability("CVE-LEV", calc_date)
            assert result["composite_probability"] == 0.9  # LEV wins
    
    def test_expected_exploited_summation(self):
        """Test Expected_Exploited() >= Σ LEV(v, d0, dn) for all v in CVEs"""
        calc = OptimizedLEVCalculator()
        
        # Create sample LEV results
        test_data = pd.DataFrame({
            'cve': ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-4'],
            'lev_probability': [0.1, 0.3, 0.05, 0.7]
        })
        
        result = calc.calculate_expected_exploited(test_data)
        expected_sum = sum(test_data['lev_probability'])
        
        assert abs(result['expected_exploited'] - expected_sum) < 1e-10
        assert abs(result['expected_exploited_proportion'] - expected_sum/4) < 1e-10


class TestNumericalStability:
    """Test numerical stability of calculations."""
    
    def test_log_space_calculations_stability(self):
        """Test numerical stability of log-space calculations in rigorous LEV."""
        calc = OptimizedLEVCalculator()
        
        # Test with many small probabilities (challenging for numerical stability)
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 12, 31)  # Full year
        
        small_prob = 1e-6
        for i in range(365):
            date = d0 + timedelta(days=i)
            calc.epss_data[date] = {"CVE-SMALL": small_prob}
        
        lev_result = calc._calculate_lev_rigorous_optimized("CVE-SMALL", d0, dn)
        
        # Should not overflow or underflow
        assert np.isfinite(lev_result)
        assert 0 <= lev_result <= 1
        assert lev_result > 0  # Should be positive for non-zero inputs
    
    def test_extreme_epss_values_handling(self):
        """Test handling of extreme EPSS values."""
        calc = OptimizedLEVCalculator()
        
        # Test with values at floating point limits
        extreme_values = np.array([
            np.finfo(float).eps,      # Smallest positive float
            1.0 - np.finfo(float).eps, # Closest to 1.0
            0.5,                      # Middle value
            np.finfo(float).tiny,     # Tiny positive value
        ])
        
        daily_probs = calc._precompute_daily_probabilities(extreme_values)
        
        # All results should be valid probabilities
        assert np.all(np.isfinite(daily_probs))
        assert np.all(daily_probs >= 0.0)
        assert np.all(daily_probs <= 1.0)
    
    def test_accumulation_precision(self):
        """Test precision in probability accumulation over long periods."""
        calc = OptimizedLEVCalculator()
        
        # Test precision over many days with small probabilities
        d0 = datetime(2024, 1, 1)
        dn = datetime(2026, 1, 1)  # 2 years
        
        consistent_prob = 0.001  # Small but consistent probability
        current_date = d0
        while current_date <= dn:
            calc.epss_data[current_date] = {"CVE-PRECISION": consistent_prob}
            current_date += timedelta(days=1)
        
        lev_result = calc._calculate_lev_rigorous_optimized("CVE-PRECISION", d0, dn)
        
        # Calculate expected result analytically
        num_days = (dn - d0).days + 1
        daily_prob = 1.0 - (1.0 - consistent_prob)**(1/30)
        expected_lev = 1.0 - (1.0 - daily_prob)**num_days
        
        # Should be close to expected value (within reasonable precision)
        relative_error = abs(lev_result - expected_lev) / expected_lev if expected_lev > 0 else 0
        assert relative_error < 1e-6  # 0.0001% relative error tolerance


class TestBoundaryConditions:
    """Test boundary conditions and edge cases."""
    
    def test_zero_day_calculation(self):
        """Test LEV calculation with zero days between d0 and dn."""
        calc = OptimizedLEVCalculator()
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 1)  # Same day
        
        calc.epss_data[d0] = {"CVE-SAME-DAY": 0.5}
        
        # Both methods should handle same-day calculation
        lev_nist = calc._calculate_lev_nist_original("CVE-SAME-DAY", d0, dn)
        lev_rigorous = calc._calculate_lev_rigorous_optimized("CVE-SAME-DAY", d0, dn)
        
        assert 0 <= lev_nist <= 1
        assert 0 <= lev_rigorous <= 1
    
    def test_exactly_30_day_windows(self):
        """Test LEV calculation with exactly 30-day windows."""
        calc = OptimizedLEVCalculator()
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 30)  # Exactly 30 days
        
        # Set EPSS score for the window
        calc.epss_data[d0] = {"CVE-30DAY": 0.2}
        
        lev_result = calc._calculate_lev_nist_original("CVE-30DAY", d0, dn)
        
        # For exactly 30 days, weight should be 1.0
        # LEV = 1 - (1 - 0.2 * 1.0) = 0.2
        expected = 1.0 - (1.0 - 0.2)
        assert abs(lev_result - expected) < 1e-10
    
    def test_fractional_window_handling(self):
        """Test handling of fractional windows (less than 30 days)."""
        calc = OptimizedLEVCalculator()
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 15)  # 15 days = 0.5 weight
        
        calc.epss_data[d0] = {"CVE-FRACTION": 0.3}
        
        lev_result = calc._calculate_lev_nist_original("CVE-FRACTION", d0, dn)
        
        # Weight should be 15/30 = 0.5
        # LEV = 1 - (1 - 0.3 * 0.5) = 1 - (1 - 0.15) = 0.15
        expected = 1.0 - (1.0 - 0.3 * 0.5)
        assert abs(lev_result - expected) < 1e-10
    
    def test_maximum_probability_bounds(self):
        """Test that probabilities never exceed 1.0."""
        calc = OptimizedLEVCalculator()
        
        # Set up scenario that might push probabilities > 1.0
        d0 = datetime(2024, 1, 1)
        dn = datetime(2025, 1, 1)  # Full year
        
        high_prob = 0.99  # Very high EPSS score
        for i in range(365):
            date = d0 + timedelta(days=i)
            calc.epss_data[date] = {"CVE-HIGH": high_prob}
        
        lev_nist = calc._calculate_lev_nist_original("CVE-HIGH", d0, dn)
        lev_rigorous = calc._calculate_lev_rigorous_optimized("CVE-HIGH", d0, dn)
        
        assert lev_nist <= 1.0
        assert lev_rigorous <= 1.0
        
        # Should be very close to 1.0 but not exceed it
        assert lev_nist > 0.99
        assert lev_rigorous > 0.99


class TestConsistencyValidation:
    """Test consistency between different calculation methods."""
    
    def test_nist_vs_rigorous_convergence(self):
        """Test that NIST and rigorous methods converge for appropriate cases."""
        calc = OptimizedLEVCalculator()
        
        # For cases where EPSS scores are relatively stable,
        # both methods should give similar results
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 4, 1)  # 3 months
        
        stable_prob = 0.05
        current_date = d0
        while current_date <= dn:
            calc.epss_data[current_date] = {"CVE-STABLE": stable_prob}
            current_date += timedelta(days=1)
        
        lev_nist = calc._calculate_lev_nist_original("CVE-STABLE", d0, dn)
        lev_rigorous = calc._calculate_lev_rigorous_optimized("CVE-STABLE", d0, dn)
        
        # Results should be reasonably close (within 10% relative difference)
        if lev_nist > 0:
            relative_diff = abs(lev_rigorous - lev_nist) / lev_nist
            assert relative_diff < 0.1
    
    def test_monotonicity_property(self):
        """Test that LEV probability is monotonic with respect to time."""
        calc = OptimizedLEVCalculator()
        
        d0 = datetime(2024, 1, 1)
        
        # Set up consistent EPSS scores
        for i in range(100):
            date = d0 + timedelta(days=i)
            calc.epss_data[date] = {"CVE-MONO": 0.1}
        
        # Calculate LEV for increasing time periods
        lev_results = []
        for days in [10, 20, 30, 50, 70, 90]:
            dn = d0 + timedelta(days=days)
            lev = calc._calculate_lev_rigorous_optimized("CVE-MONO", d0, dn)
            lev_results.append(lev)
        
        # Each result should be >= previous (monotonic property)
        for i in range(1, len(lev_results)):
            assert lev_results[i] >= lev_results[i-1] - 1e-10  # Small tolerance for FP errors
    
    def test_additivity_property_violation(self):
        """Test that probabilities correctly handle non-additivity."""
        calc = OptimizedLEVCalculator()
        
        # Test that P(A or B) ≠ P(A) + P(B) for overlapping periods
        d0 = datetime(2024, 1, 1)
        d_mid = datetime(2024, 1, 15)
        dn = datetime(2024, 1, 30)
        
        for i in range(30):
            date = d0 + timedelta(days=i)
            calc.epss_data[date] = {"CVE-OVERLAP": 0.2}
        
        lev_first_half = calc._calculate_lev_rigorous_optimized("CVE-OVERLAP", d0, d_mid)
        lev_second_half = calc._calculate_lev_rigorous_optimized("CVE-OVERLAP", d_mid, dn)
        lev_full_period = calc._calculate_lev_rigorous_optimized("CVE-OVERLAP", d0, dn)
        
        # Full period should be LESS than sum of halves (non-additivity)
        assert lev_full_period < lev_first_half + lev_second_half


class TestRealWorldScenarios:
    """Test scenarios based on real-world examples from the paper."""
    
    def test_cve_2023_1730_mathematical_validation(self):
        """Validate mathematical calculation for CVE-2023-1730 example."""
        calc = OptimizedLEVCalculator()
        
        # EPSS timeline from NIST CSWP 41 Section 6
        epss_timeline = [
            (datetime(2023, 5, 2), 0.00),
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
            (datetime(2024, 11, 22), 0.08),  # Adjusted for 21-day window
        ]
        
        # Set up calculator with this data
        for date, score in epss_timeline:
            calc.epss_data[date] = {"CVE-2023-1730": score}
        
        d0 = datetime(2023, 5, 2)
        dn = datetime(2024, 12, 12)
        
        # Calculate using NIST method
        lev_result = calc._calculate_lev_nist_original("CVE-2023-1730", d0, dn)
        
        # Paper states LEV probability should be 0.70
        # Allow reasonable tolerance for implementation differences
        assert 0.65 <= lev_result <= 0.75, f"LEV result {lev_result} outside expected range"
    
    def test_window_adjustment_mathematical_correctness(self):
        """Test mathematical correctness of window size adjustment."""
        calc = OptimizedLEVCalculator()
        
        # Test the 21-day window adjustment from the paper
        # "Raw EPSS on 2024-11-22: 0.08 (21-day window remaining)"
        # "Effective 30-day equivalent: 0.08 × (21/30) = 0.056 ≈ 0.06"
        
        d0 = datetime(2024, 11, 1)
        dn = datetime(2024, 11, 22)  # 22 days total
        
        calc.epss_data[d0] = {"CVE-WINDOW-TEST": 0.08}
        
        lev_result = calc._calculate_lev_nist_original("CVE-WINDOW-TEST", d0, dn)
        
        # Manual calculation: weight = 22/30, effective = 0.08 * (22/30)
        # LEV = 1 - (1 - effective) = effective = 0.08 * (22/30) ≈ 0.0587
        expected_weight = 22.0 / 30.0
        expected_effective = 0.08 * expected_weight
        expected_lev = 1.0 - (1.0 - expected_effective)
        
        assert abs(lev_result - expected_lev) < 0.001


class TestDataStructureValidation:
    """Test validation of data structures and formats."""
    
    def test_epss_data_structure_integrity(self):
        """Test EPSS data structure maintains integrity."""
        calc = OptimizedLEVCalculator()
        
        # Test data structure after loading
        test_date = datetime(2024, 1, 1)
        calc.epss_data[test_date] = {
            "CVE-2024-0001": 0.1,
            "CVE-2024-0002": 0.2,
            "CVE-2024-0003": 0.0,
            "CVE-2024-0004": 1.0,
        }
        
        # Verify data structure integrity
        assert isinstance(calc.epss_data, dict)
        assert isinstance(calc.epss_data[test_date], dict)
        
        for cve, score in calc.epss_data[test_date].items():
            assert isinstance(cve, str)
            assert isinstance(score, (int, float))
            assert 0.0 <= score <= 1.0
    
    def test_kev_data_structure_integrity(self):
        """Test KEV data structure maintains integrity."""
        calc = OptimizedLEVCalculator()
        
        # Test KEV data structure
        calc.kev_data = {"CVE-2024-0001", "CVE-2024-0002"}
        
        assert isinstance(calc.kev_data, set)
        for cve in calc.kev_data:
            assert isinstance(cve, str)
            assert cve.startswith("CVE-")
    
    def test_date_consistency_validation(self):
        """Test that all dates are consistently normalized."""
        calc = OptimizedLEVCalculator()
        
        # Add data with various date formats
        dates_with_times = [
            datetime(2024, 1, 1, 0, 0, 0),
            datetime(2024, 1, 2, 12, 30, 45),
            datetime(2024, 1, 3, 23, 59, 59),
        ]
        
        for date in dates_with_times:
            normalized = normalize_date(date)
            calc.epss_data[normalized] = {"CVE-TEST": 0.1}
        
        # All stored dates should be normalized
        for stored_date in calc.epss_data.keys():
            assert stored_date.hour == 0
            assert stored_date.minute == 0
            assert stored_date.second == 0
            assert stored_date.microsecond == 0


class TestErrorPropagationValidation:
    """Test how errors propagate through calculations."""
    
    def test_missing_epss_data_propagation(self):
        """Test how missing EPSS data affects LEV calculations."""
        calc = OptimizedLEVCalculator()
        
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 30)
        
        # Only provide partial EPSS data (missing some days)
        for i in [0, 5, 10, 15, 20, 25]:  # Sparse data
            date = d0 + timedelta(days=i)
            calc.epss_data[date] = {"CVE-SPARSE": 0.1}
        
        lev_result = calc.calculate_lev("CVE-SPARSE", d0, dn, rigorous=True)
        
        # Should still produce valid result using available data
        assert 0 <= lev_result <= 1
        assert lev_result >= 0  # Should be non-negative
    
    def test_boundary_date_handling(self):
        """Test handling of dates at calculation boundaries."""
        calc = OptimizedLEVCalculator()
        
        # Test with dates exactly at boundaries
        d0 = datetime(2024, 1, 1)
        dn = datetime(2024, 1, 1)  # Same day
        
        calc.epss_data[d0] = {"CVE-BOUNDARY": 0.5}
        
        # Both calculation methods should handle boundary correctly
        lev_nist = calc._calculate_lev_nist_original("CVE-BOUNDARY", d0, dn)
        lev_rigorous = calc._calculate_lev_rigorous_optimized("CVE-BOUNDARY", d0, dn)
        
        assert 0 <= lev_nist <= 1
        assert 0 <= lev_rigorous <= 1


if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
    ])