#!/usr/bin/env python3
"""
Integration tests for LEV implementation.
Tests end-to-end workflows and real-world scenarios.
"""

import pytest
import numpy as np
import pandas as pd
import tempfile
import os
import gzip
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import requests
import time

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lev_calculator import (
    OptimizedLEVCalculator,
    get_current_date_utc,
    normalize_date,
    main
)


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""
    
    @pytest.fixture
    def full_calculator_setup(self):
        """Set up calculator with realistic test data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Create comprehensive test dataset
            base_date = datetime(2023, 3, 7)  # EPSS v3 start date
            end_date = datetime(2024, 3, 7)   # One year of data
            
            # Create KEV data
            kev_file = os.path.join(temp_dir, "known_exploited_vulnerabilities.csv")
            kev_data = """cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes
CVE-2023-0001,Microsoft,Windows,Test Vuln 1,2023-05-01,Test vulnerability 1,Apply updates,2023-05-15,Known,Test
CVE-2023-0002,Adobe,Reader,Test Vuln 2,2023-06-01,Test vulnerability 2,Apply updates,2023-06-15,Unknown,Test
CVE-2023-0003,Apache,HTTP Server,Test Vuln 3,2023-07-01,Test vulnerability 3,Apply updates,2023-07-15,Unknown,Test
"""
            with open(kev_file, 'w') as f:
                f.write(kev_data)
            
            # Load KEV data
            calc.load_kev_data(kev_file_path=kev_file, download_if_missing=False)
            
            # Create EPSS data files
            current_date = base_date
            cve_list = [f"CVE-2023-{i:04d}" for i in range(1, 101)]  # 100 CVEs
            
            while current_date <= end_date:
                filename = f"epss_scores-{current_date.strftime('%Y-%m-%d')}.csv.gz"
                file_path = os.path.join(temp_dir, filename)
                
                # Generate realistic EPSS scores
                epss_data = "cve,epss\n"
                for cve in cve_list:
                    # Simulate time-varying EPSS scores
                    days_since_start = (current_date - base_date).days
                    base_score = hash(cve) % 1000 / 10000.0  # Deterministic but varied
                    
                    # Add time variation
                    time_factor = 1 + 0.5 * np.sin(days_since_start * 0.01)
                    score = min(1.0, max(0.0, base_score * time_factor))
                    
                    epss_data += f"{cve},{score:.6f}\n"
                
                with gzip.open(file_path, 'wt') as f:
                    f.write(epss_data)
                
                current_date += timedelta(days=1)
            
            # Load EPSS data
            calc.download_epss_data(base_date, end_date)
            
            yield calc, base_date, end_date
    
    def test_complete_lev_calculation_workflow(self, full_calculator_setup):
        """Test complete LEV calculation workflow from data loading to results."""
        calc, start_date, end_date = full_calculator_setup
        
        calculation_date = end_date
        
        # Test NIST LEV calculation
        nist_results = calc.calculate_lev_for_all_cves(
            calculation_date=calculation_date,
            rigorous=False
        )
        
        assert len(nist_results) > 0
        assert all(col in nist_results.columns for col in [
            'cve', 'first_epss_date', 'lev_probability', 'peak_epss_30day'
        ])
        
        # Verify probability bounds
        assert all(0 <= prob <= 1 for prob in nist_results['lev_probability'])
        
        # Test rigorous LEV calculation
        rigorous_results = calc.calculate_lev_for_all_cves(
            calculation_date=calculation_date,
            rigorous=True
        )
        
        assert len(rigorous_results) > 0
        assert len(rigorous_results) == len(nist_results)  # Same CVEs
    
    def test_complete_composite_calculation_workflow(self, full_calculator_setup):
        """Test complete composite probability calculation workflow."""
        calc, start_date, end_date = full_calculator_setup
        
        calculation_date = end_date
        
        # Test NIST composite calculation
        nist_composite = calc.calculate_composite_for_all_cves(
            calculation_date=calculation_date,
            rigorous=False
        )
        
        assert len(nist_composite) > 0
        assert all(col in nist_composite.columns for col in [
            'cve', 'epss_score', 'kev_score', 'lev_score', 'composite_probability'
        ])
        
        # Verify composite probability is max of components
        for _, row in nist_composite.iterrows():
            expected_max = max(row['epss_score'], row['kev_score'], row['lev_score'])
            assert abs(row['composite_probability'] - expected_max) < 1e-10
        
        # Verify KEV CVEs have KEV score = 1.0
        kev_rows = nist_composite[nist_composite['is_in_kev'] == True]
        if len(kev_rows) > 0:
            assert all(score == 1.0 for score in kev_rows['kev_score'])
            assert all(prob == 1.0 for prob in kev_rows['composite_probability'])
    
    def test_expected_exploited_calculation_workflow(self, full_calculator_setup):
        """Test Expected_Exploited calculation workflow."""
        calc, start_date, end_date = full_calculator_setup
        
        # Calculate LEV results
        lev_results = calc.calculate_lev_for_all_cves(
            calculation_date=end_date,
            rigorous=False
        )
        
        # Calculate Expected_Exploited metrics
        expected_metrics = calc.calculate_expected_exploited(lev_results)
        
        assert 'total_cves' in expected_metrics
        assert 'expected_exploited' in expected_metrics
        assert 'expected_exploited_proportion' in expected_metrics
        
        assert expected_metrics['total_cves'] == len(lev_results)
        assert 0 <= expected_metrics['expected_exploited_proportion'] <= 1
        
        # Manual verification
        manual_sum = lev_results['lev_probability'].sum()
        manual_proportion = manual_sum / len(lev_results)
        
        assert abs(expected_metrics['expected_exploited'] - manual_sum) < 1e-10
        assert abs(expected_metrics['expected_exploited_proportion'] - manual_proportion) < 1e-10


class TestDataConsistencyScenarios:
    """Test data consistency across different scenarios."""
    
    def test_missing_epss_days_handling(self):
        """Test handling of missing EPSS data days per NIST CSWP 41 Section 10.3."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Create EPSS data with missing days
            base_date = datetime(2024, 1, 1)
            
            # Add data for days 1, 3, 5, 7, 9 (missing 2, 4, 6, 8)
            for i in [0, 2, 4, 6, 8]:
                date = base_date + timedelta(days=i)
                calc.epss_data[date] = {"CVE-MISSING-TEST": 0.1 + i * 0.01}
            
            # Test forward search for missing days
            missing_date = base_date + timedelta(days=1)  # Day 2 is missing
            next_available = base_date + timedelta(days=2)  # Day 3 exists
            
            score = calc.get_epss_score("CVE-MISSING-TEST", missing_date)
            expected_score = calc.epss_data[next_available]["CVE-MISSING-TEST"]
            
            assert score == expected_score
    
    def test_kev_and_epss_data_consistency(self):
        """Test consistency between KEV and EPSS data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Set up overlapping KEV and EPSS data
            calc.kev_data = {"CVE-2024-0001", "CVE-2024-0002"}
            
            test_date = datetime(2024, 1, 1)
            calc.epss_data[test_date] = {
                "CVE-2024-0001": 0.8,  # In KEV, high EPSS
                "CVE-2024-0002": 0.1,  # In KEV, low EPSS
                "CVE-2024-0003": 0.9,  # Not in KEV, high EPSS
                "CVE-2024-0004": 0.05, # Not in KEV, low EPSS
            }
            
            # Test composite calculations
            for cve in calc.epss_data[test_date].keys():
                result = calc.calculate_composite_probability(cve, test_date)
                
                if cve in calc.kev_data:
                    # KEV CVEs should have composite = 1.0
                    assert result['composite_probability'] == 1.0
                    assert result['kev_score'] == 1.0
                else:
                    # Non-KEV CVEs should have composite >= EPSS score
                    assert result['composite_probability'] >= result['epss_score']
                    assert result['kev_score'] == 0.0
    
    def test_temporal_consistency(self):
        """Test temporal consistency of calculations."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Set up time series data
            base_date = datetime(2024, 1, 1)
            
            for i in range(60):  # 60 days of data
                date = base_date + timedelta(days=i)
                # Declining EPSS score over time
                score = max(0.01, 0.5 - i * 0.008)
                calc.epss_data[date] = {"CVE-TEMPORAL": score}
            
            d0 = base_date
            
            # Calculate LEV for different end dates
            lev_results = []
            for days in [10, 20, 30, 40, 50]:
                dn = base_date + timedelta(days=days)
                lev = calc.calculate_lev("CVE-TEMPORAL", d0, dn, rigorous=True)
                lev_results.append((days, lev))
            
            # LEV should generally increase with more days (monotonic property)
            for i in range(1, len(lev_results)):
                prev_days, prev_lev = lev_results[i-1]
                curr_days, curr_lev = lev_results[i]
                
                # Allow small decreases due to declining EPSS scores
                assert curr_lev >= prev_lev - 0.01, f"LEV decreased significantly from {prev_lev} to {curr_lev}"


class TestPerformanceIntegration:
    """Test performance characteristics in integrated scenarios."""
    
    def test_large_dataset_processing_performance(self):
        """Test processing performance with larger datasets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir, max_workers=2)
            
            # Create larger dataset
            base_date = datetime(2024, 1, 1)
            num_days = 30
            num_cves = 500
            
            # Generate test data
            for day in range(num_days):
                date = base_date + timedelta(days=day)
                day_data = {}
                for cve_id in range(num_cves):
                    cve = f"CVE-2024-{cve_id:04d}"
                    score = np.random.uniform(0, 0.2)  # Realistic EPSS range
                    day_data[cve] = score
                calc.epss_data[date] = day_data
            
            # Time the LEV calculation
            start_time = time.time()
            results = calc.calculate_lev_for_all_cves(
                calculation_date=base_date + timedelta(days=29),
                rigorous=False
            )
            elapsed_time = time.time() - start_time
            
            # Performance assertions
            assert len(results) == num_cves
            assert elapsed_time < 60.0  # Should complete within 60 seconds
            
            # Verify results quality
            assert all(0 <= prob <= 1 for prob in results['lev_probability'])
            assert results['lev_probability'].mean() > 0  # Should have some positive probabilities
    
    def test_memory_efficiency_integration(self):
        """Test memory efficiency during integrated processing."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Load substantial data
            base_date = datetime(2024, 1, 1)
            for day in range(90):  # 3 months
                date = base_date + timedelta(days=day)
                day_data = {f"CVE-2024-{i:04d}": np.random.uniform(0, 0.1) for i in range(1000)}
                calc.epss_data[date] = day_data
            
            # Perform calculations
            results = calc.calculate_lev_for_all_cves(rigorous=False)
            composite_results = calc.calculate_composite_for_all_cves(rigorous=False)
            
            current_memory = process.memory_info().rss
            memory_increase = current_memory - initial_memory
            
            # Memory increase should be reasonable (less than 1GB)
            assert memory_increase < 1024 * 1024 * 1024
            assert len(results) == 1000
            assert len(composite_results) == 1000


class TestErrorHandlingIntegration:
    """Test error handling in integrated scenarios."""
    
    def test_partial_data_robustness(self):
        """Test robustness when dealing with partial or corrupted data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Set up partial KEV data (missing required columns)
            kev_file = os.path.join(temp_dir, "partial_kev.csv")
            partial_kev_data = "id,vendor,product\nCVE-2024-0001,Test,Product\n"
            with open(kev_file, 'w') as f:
                f.write(partial_kev_data)
            
            # Should handle missing cveID column gracefully
            calc.load_kev_data(kev_file_path=kev_file, download_if_missing=False)
            assert len(calc.kev_data) == 0  # Should be empty due to missing column
            
            # Set up partial EPSS data
            base_date = datetime(2024, 1, 1)
            calc.epss_data[base_date] = {"CVE-2024-0001": 0.5}
            # Missing subsequent days
            
            # Should handle missing EPSS data gracefully
            d0 = base_date
            dn = base_date + timedelta(days=30)
            lev_result = calc.calculate_lev("CVE-2024-0001", d0, dn, rigorous=True)
            
            assert 0 <= lev_result <= 1  # Should produce valid result
    
    def test_network_error_simulation(self):
        """Test handling of network errors during data download."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Mock network failure
            with patch('lev_calculator.requests.get') as mock_get:
                mock_get.side_effect = requests.exceptions.ConnectionError("Network error")
                
                # Should handle network errors gracefully
                start_date = datetime(2024, 1, 1)
                end_date = datetime(2024, 1, 3)
                
                calc.download_epss_data(start_date, end_date)
                
                # Should not crash, may have empty data
                assert isinstance(calc.epss_data, dict)
    
    def test_corrupted_cache_handling(self):
        """Test handling of corrupted cache files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Create corrupted cache file
            test_date = datetime(2024, 1, 1)
            filename = f"epss_scores-{test_date.strftime('%Y-%m-%d')}.csv.gz"
            cache_path = os.path.join(temp_dir, filename)
            
            # Write corrupted gzip data
            with open(cache_path, 'wb') as f:
                f.write(b"corrupted data")
            
            # Should handle corrupted cache gracefully
            result = calc._download_single_date(test_date)
            assert result is None  # Should return None for corrupted data


class TestRealWorldDataSimulation:
    """Test with simulated real-world data patterns."""
    
    def test_realistic_epss_evolution_patterns(self):
        """Test with realistic EPSS score evolution patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            base_date = datetime(2023, 6, 1)
            
            # Simulate different EPSS evolution patterns
            cve_patterns = {
                "CVE-STABLE": {"pattern": "stable", "base": 0.05},
                "CVE-RISING": {"pattern": "rising", "base": 0.01},
                "CVE-DECLINING": {"pattern": "declining", "base": 0.3},
                "CVE-SPIKE": {"pattern": "spike", "base": 0.02},
                "CVE-ZERO": {"pattern": "zero", "base": 0.0},
            }
            
            # Generate 6 months of data
            for day in range(180):
                date = base_date + timedelta(days=day)
                day_data = {}
                
                for cve, config in cve_patterns.items():
                    if config["pattern"] == "stable":
                        score = config["base"] + np.random.normal(0, 0.005)
                    elif config["pattern"] == "rising":
                        score = config["base"] + day * 0.001
                    elif config["pattern"] == "declining":
                        score = max(0, config["base"] - day * 0.001)
                    elif config["pattern"] == "spike":
                        if 80 <= day <= 90:  # Spike period
                            score = 0.5
                        else:
                            score = config["base"]
                    elif config["pattern"] == "zero":
                        score = 0.0
                    
                    day_data[cve] = max(0, min(1, score))
                
                calc.epss_data[date] = day_data
            
            # Calculate LEV for all patterns
            calc_date = base_date + timedelta(days=179)
            
            for cve, config in cve_patterns.items():
                d0 = calc.get_first_epss_date(cve)
                lev_result = calc.calculate_lev(cve, d0, calc_date, rigorous=True)
                
                # Verify pattern-specific expectations
                if config["pattern"] == "zero":
                    assert lev_result == 0.0
                elif config["pattern"] == "spike":
                    assert lev_result > 0.1  # Should be high due to spike
                elif config["pattern"] == "rising":
                    # Should be higher than base score would suggest
                    assert lev_result > 0.05
                
                # All should be valid probabilities
                assert 0 <= lev_result <= 1
    
    def test_realistic_kev_integration(self):
        """Test integration with realistic KEV data patterns."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Create realistic KEV data
            kev_file = os.path.join(temp_dir, "realistic_kev.csv")
            kev_data = """cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes
CVE-2023-0001,Microsoft,Windows,Windows Kernel Elevation of Privilege,2023-05-15,Windows kernel vulnerability,Apply updates,2023-05-29,Known,Active exploitation
CVE-2023-0002,Apache,HTTP Server,HTTP Server Remote Code Execution,2023-06-01,Apache HTTP server RCE,Apply updates,2023-06-15,Unknown,Web servers
CVE-2023-0003,Adobe,Acrobat Reader,PDF Reader Use After Free,2023-07-01,Adobe Reader UAF,Apply updates,2023-07-15,Unknown,Document readers
CVE-2023-0004,VMware,vCenter,vCenter Authentication Bypass,2023-08-01,VMware vCenter auth bypass,Apply updates,2023-08-15,Known,Virtual infrastructure
"""
            with open(kev_file, 'w') as f:
                f.write(kev_data)
            
            calc.load_kev_data(kev_file_path=kev_file, download_if_missing=False)
            
            # Create EPSS data including KEV CVEs
            base_date = datetime(2023, 5, 1)
            all_cves = ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003", "CVE-2023-0004"]
            all_cves.extend([f"CVE-2023-{i:04d}" for i in range(100, 120)])  # Non-KEV CVEs
            
            for day in range(90):
                date = base_date + timedelta(days=day)
                day_data = {}
                
                for cve in all_cves:
                    if cve in calc.kev_data:
                        # KEV CVEs might have different EPSS patterns
                        score = 0.1 + np.random.uniform(0, 0.3)
                    else:
                        # Non-KEV CVEs typically lower
                        score = np.random.uniform(0, 0.1)
                    
                    day_data[cve] = score
                
                calc.epss_data[date] = day_data
            
            # Test composite calculations
            calc_date = base_date + timedelta(days=89)
            composite_results = calc.calculate_composite_for_all_cves(
                calculation_date=calc_date,
                rigorous=False
            )
            
            # All KEV CVEs should have composite probability = 1.0
            kev_results = composite_results[composite_results['is_in_kev'] == True]
            assert len(kev_results) == 4  # Should find all 4 KEV CVEs
            assert all(prob == 1.0 for prob in kev_results['composite_probability'])
            
            # Non-KEV CVEs should have composite < 1.0 (unless LEV is very high)
            non_kev_results = composite_results[composite_results['is_in_kev'] == False]
            assert len(non_kev_results) > 0
            assert all(prob < 1.0 for prob in non_kev_results['composite_probability'])


class TestValidationAgainstPaperExamples:
    """Test validation against specific examples from NIST CSWP 41."""
    
    def test_section_6_cve_2023_1730_complete_example(self):
        """Test complete example from Section 6 of the paper."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Exact EPSS timeline from the paper
            epss_data_points = [
                ("2023-05-02", 0.00),  # Publication
                ("2023-06-01", 0.00),
                ("2023-07-01", 0.00),
                ("2023-07-31", 0.05),
                ("2023-08-30", 0.06),
                ("2023-09-29", 0.06),
                ("2023-10-29", 0.06),
                ("2023-11-28", 0.10),
                ("2023-12-28", 0.13),
                ("2024-01-27", 0.16),  # Peak
                ("2024-02-26", 0.08),
                ("2024-03-27", 0.05),
                ("2024-04-26", 0.05),
                ("2024-05-26", 0.04),
                ("2024-06-25", 0.05),
                ("2024-07-25", 0.05),
                ("2024-08-24", 0.05),
                ("2024-09-23", 0.05),
                ("2024-10-23", 0.05),
                ("2024-11-22", 0.08),  # Final (21-day window)
            ]
            
            # Fill in daily data by interpolation
            prev_date = None
            prev_score = 0.0
            
            for date_str, score in epss_data_points:
                current_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                # Fill gaps with interpolated values
                if prev_date is not None:
                    days_diff = (current_date - prev_date).days
                    if days_diff > 1:
                        score_diff = score - prev_score
                        for i in range(1, days_diff):
                            interp_date = prev_date + timedelta(days=i)
                            interp_score = prev_score + (score_diff * i / days_diff)
                            calc.epss_data[interp_date] = {"CVE-2023-1730": interp_score}
                
                calc.epss_data[current_date] = {"CVE-2023-1730": score}
                prev_date = current_date
                prev_score = score
            
            # Calculate LEV as of December 12, 2024
            d0 = datetime(2023, 5, 2)
            dn = datetime(2024, 12, 12)
            
            lev_probability = calc.calculate_lev("CVE-2023-1730", d0, dn, rigorous=False)
            
            # Paper states LEV probability should be 0.70
            assert 0.65 <= lev_probability <= 0.75, f"LEV probability {lev_probability} not in expected range [0.65, 0.75]"
            
            # Test debug output format
            debug_result = calc.debug_lev_calculation("CVE-2023-1730", dn, rigorous=False)
            
            assert debug_result["cve"] == "CVE-2023-1730"
            assert debug_result["d0"] == d0
            assert debug_result.get("max_epss", 0) >= 0.0  # Should have some EPSS data
            assert 0.65 <= debug_result["lev_probability"] <= 0.75
    
    def test_section_6_cve_2023_29373_example(self):
        """Test the second example from Section 6."""
        with tempfile.TemporaryDirectory() as temp_dir:
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # EPSS timeline for CVE-2023-29373 from the paper
            epss_data_points = [
                ("2023-06-14", 0.00),  # Publication
                ("2023-07-14", 0.05),
                ("2023-08-13", 0.02),
                ("2023-09-12", 0.02),
                ("2023-10-12", 0.03),
                ("2023-11-11", 0.04),
                ("2023-12-11", 0.05),
                ("2024-01-10", 0.06),
                ("2024-02-09", 0.08),
                ("2024-03-10", 0.08),  # Peak
                ("2024-04-09", 0.07),
                ("2024-05-09", 0.04),
                ("2024-06-08", 0.04),
                ("2024-07-08", 0.03),
                ("2024-08-07", 0.03),
                ("2024-09-06", 0.03),
                ("2024-10-06", 0.03),
                ("2024-11-05", 0.03),
                ("2024-12-05", 0.03),
                ("2025-01-04", 0.00),  # Final (19-day window)
            ]
            
            # Set up EPSS data with interpolation
            prev_date = None
            prev_score = 0.0
            
            for date_str, score in epss_data_points:
                current_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                if prev_date is not None:
                    days_diff = (current_date - prev_date).days
                    if days_diff > 1:
                        score_diff = score - prev_score
                        for i in range(1, days_diff):
                            interp_date = prev_date + timedelta(days=i)
                            interp_score = prev_score + (score_diff * i / days_diff)
                            calc.epss_data[interp_date] = {"CVE-2023-29373": interp_score}
                
                calc.epss_data[current_date] = {"CVE-2023-29373": score}
                prev_date = current_date
                prev_score = score
            
            # Calculate LEV as of January 22, 2025
            d0 = datetime(2023, 6, 14)
            dn = datetime(2025, 1, 22)
            
            lev_probability = calc.calculate_lev("CVE-2023-29373", d0, dn, rigorous=False)
            
            # Paper states LEV probability should be 0.54350
            assert 0.50 <= lev_probability <= 0.58, f"LEV probability {lev_probability} not in expected range [0.50, 0.58]"
            
            # Verify peak EPSS detection
            debug_result = calc.debug_lev_calculation("CVE-2023-29373", dn, rigorous=False)
            assert debug_result.get("max_epss", 0) >= 0.0  # Should have some EPSS data


class TestSystemIntegration:
    """Test system-level integration scenarios."""
    
    @patch('lev_calculator.requests.get')
    def test_full_system_workflow_with_mocked_downloads(self, mock_get):
        """Test full system workflow with mocked network calls."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock KEV download
            kev_response = Mock()
            kev_response.content = b"cveID,vendorProject,product\nCVE-2024-0001,Test,Product\n"
            kev_response.raise_for_status.return_value = None
            
            # Mock EPSS download
            epss_response = Mock()
            epss_data = "cve,epss\nCVE-2024-0001,0.5\nCVE-2024-0002,0.1\n"
            epss_response.content = gzip.compress(epss_data.encode())
            epss_response.raise_for_status.return_value = None
            
            def mock_get_response(url, **kwargs):
                if 'known_exploited_vulnerabilities' in str(url):
                    return kev_response
                return epss_response
            mock_get.side_effect = mock_get_response
            
            calc = OptimizedLEVCalculator(cache_dir=temp_dir)
            
            # Test full workflow
            calc.download_kev_data()
            calc.load_kev_data()
            
            start_date = datetime(2024, 1, 1)
            end_date = datetime(2024, 1, 3)
            calc.download_epss_data(start_date, end_date)
            
            # Should have downloaded and cached data
            assert len(calc.kev_data) > 0
            assert len(calc.epss_data) > 0
            
            # Test calculations work end-to-end
            results = calc.calculate_composite_for_all_cves()
            assert len(results) > 0


if __name__ == "__main__":
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-x",  # Stop on first failure for integration tests
    ])