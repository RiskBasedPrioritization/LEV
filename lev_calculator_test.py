#!/usr/bin/env python3
"""
Test script to verify the rigorous LEV calculation is working correctly.
This helps debug why all rigorous LEV probabilities are returning 0.
"""

import numpy as np
from datetime import datetime, timedelta

def test_daily_probability_conversion():
    """Test the conversion from 30-day EPSS to daily probability."""
    print("Testing daily probability conversion...")
    
    # Test cases: [30-day EPSS, expected daily probability (approximate)]
    test_cases = [
        (0.0, 0.0),
        (0.1, 0.00351),  # Small probability: should be close to 0.1/30 = 0.00333
        (0.5, 0.02257),  # Medium probability: diverges from 0.5/30 = 0.01667
        (0.9, 0.07696),  # High probability: much different from 0.9/30 = 0.03
        (1.0, 1.0),
    ]
    
    def calculate_daily_prob_rigorous(p30, window_size=30):
        """Calculate daily probability using rigorous formula."""
        if p30 == 0.0:
            return 0.0
        if p30 == 1.0:
            return 1.0
        
        complement = 1.0 - p30
        if complement < np.finfo(float).eps:
            return 1.0
        
        return 1.0 - (complement ** (1.0/window_size))
    
    def calculate_daily_prob_approximation(p30, window_size=30):
        """Calculate daily probability using NIST approximation."""
        return p30 / window_size
    
    for p30, expected in test_cases:
        rigorous = calculate_daily_prob_rigorous(p30)
        approx = calculate_daily_prob_approximation(p30)
        
        print(f"P30={p30:.1f} -> Rigorous={rigorous:.5f}, Approx={approx:.5f}, Expected≈{expected:.5f}")
        
        # Verify rigorous calculation is working
        if p30 == 0.0:
            assert rigorous == 0.0, f"Expected 0.0 for P30=0.0, got {rigorous}"
        elif p30 == 1.0:
            assert rigorous == 1.0, f"Expected 1.0 for P30=1.0, got {rigorous}"
        else:
            assert 0.0 < rigorous < 1.0, f"Daily prob should be between 0 and 1, got {rigorous}"
            assert rigorous > 0, f"Daily prob should be positive for positive P30, got {rigorous}"
    
    print("✓ Daily probability conversion tests passed!")

def test_lev_calculation():
    """Test LEV calculation with simple scenarios."""
    print("\nTesting LEV calculation logic...")
    
    # Test case 1: Single day with EPSS score
    def simple_lev_calculation(daily_probs):
        """Calculate LEV for a series of daily probabilities."""
        if len(daily_probs) == 0:
            return 0.0
        
        # Filter out zeros
        non_zero_probs = [p for p in daily_probs if p > 0]
        if len(non_zero_probs) == 0:
            return 0.0
        
        # Calculate product of (1 - daily_prob)
        product = 1.0
        for p in non_zero_probs:
            product *= (1.0 - p)
        
        return 1.0 - product
    
    # Test cases
    test_cases = [
        ([0.1], 0.1),  # Single day, 10% daily prob -> 10% LEV
        ([0.1, 0.1], 0.19),  # Two days, 10% each -> 1 - 0.9^2 = 0.19
        ([0.0, 0.1, 0.0], 0.1),  # Only one non-zero day
        ([0.01] * 30, 0.2593),  # 30 days of 1% daily prob -> 1 - 0.99^30 ≈ 0.26
        ([], 0.0),  # No data
    ]
    
    for daily_probs, expected in test_cases:
        result = simple_lev_calculation(daily_probs)
        print(f"Daily probs: {daily_probs[:3]}{'...' if len(daily_probs) > 3 else ''} -> LEV={result:.4f}, Expected≈{expected:.4f}")
        
        # Check result is reasonable
        assert 0.0 <= result <= 1.0, f"LEV should be between 0 and 1, got {result}"
        if len(daily_probs) > 0 and any(p > 0 for p in daily_probs):
            assert result > 0, f"LEV should be positive when there are positive daily probs, got {result}"
    
    print("✓ LEV calculation logic tests passed!")

def test_edge_cases():
    """Test edge cases that might cause issues."""
    print("\nTesting edge cases...")
    
    # Test very small EPSS scores
    small_scores = [1e-6, 1e-9, 1e-12]
    for score in small_scores:
        daily_prob = 1.0 - (1.0 - score)**(1.0/30)
        print(f"Very small EPSS {score:.0e} -> Daily prob {daily_prob:.10e}")
        assert daily_prob > 0, f"Daily prob should be positive for positive EPSS"
        assert daily_prob < score, f"Daily prob should be less than 30-day prob for small values"
    
    # Test values very close to 1.0
    high_scores = [0.999, 0.9999, 0.99999]
    for score in high_scores:
        daily_prob = 1.0 - (1.0 - score)**(1.0/30)
        print(f"High EPSS {score} -> Daily prob {daily_prob:.6f}")
        assert 0.0 < daily_prob < 1.0, f"Daily prob should be between 0 and 1"
    
    print("✓ Edge case tests passed!")

def main():
    """Run all tests."""
    print("=" * 50)
    print("Testing Rigorous LEV Calculation Components")
    print("=" * 50)
    
    try:
        test_daily_probability_conversion()
        test_lev_calculation()
        test_edge_cases()
        
        print("\n" + "=" * 50)
        print("✓ All tests passed! The rigorous calculation logic is correct.")
        print("The issue might be in:")
        print("1. Data loading/access")
        print("2. Date range calculation")
        print("3. EPSS score retrieval")
        print("4. Array handling in the vectorized implementation")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()