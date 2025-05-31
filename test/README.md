# LEV Implementation Test Suite

This comprehensive test suite validates the implementation of the Likely Exploited Vulnerabilities (LEV) metric as described in **NIST Cybersecurity White Paper CSWP 41**.

## Overview

The test suite ensures that the LEV implementation:
- Correctly implements the mathematical formulas from NIST CSWP 41
- Handles real-world data scenarios accurately
- Performs efficiently with large datasets
- Maintains numerical stability and precision
- Complies with all specifications in the paper

## Test Structure

```
test/
├── test_lev_unit_tests.py              # Core unit tests
├── test_mathematical_validation.py     # Mathematical formula validation
├── test_integration_scenarios.py       # End-to-end integration tests
├── conftest.py                         # Shared test configuration
├── test_requirements.txt               # Test dependencies
├── run_tests.py                        # Test runner script
├── test_data_generator.py              # Test data generation
└── README.md                           # This file
```

## Test Categories

### 1. Unit Tests (`test_lev_unit_tests.py`)
Tests individual components and functions:
- **Utility Functions**: Date handling, logging setup
- **Calculator Initialization**: Basic setup and configuration
- **EPSS Data Handling**: Download, caching, retrieval with missing-day logic
- **KEV Data Handling**: Loading, validation, membership checking
- **Daily Probability Calculations**: EPSS to daily probability conversion
- **LEV Calculations**: Both NIST LEV2 and rigorous implementations
- **Composite Calculations**: EPSS + KEV + LEV combination
- **Expected Exploited Calculations**: Statistical aggregation
- **Error Handling**: Graceful handling of edge cases
- **Performance**: Vectorized operations and scalability

### 2. Mathematical Validation (`test_mathematical_validation.py`)
Validates mathematical correctness against NIST CSWP 41:
- **Formula Implementation**: Daily probability formula P1 = 1 - (1 - P30)^(1/30)
- **LEV Inequality Property**: LEV >= 1 - ∏(1 - epss(v,di) × weight(di,dn,30))
- **Numerical Stability**: Log-space calculations, extreme values
- **Boundary Conditions**: Zero days, exact windows, fractional windows
- **Consistency**: NIST vs rigorous method convergence
- **Mathematical Properties**: Monotonicity, non-additivity
- **Real-world Examples**: CVE-2023-1730 and CVE-2023-29373 validation

### 3. Integration Tests (`test_integration_scenarios.py`)
Tests complete workflows and real-world scenarios:
- **End-to-end Workflows**: Complete LEV calculation pipelines
- **Data Consistency**: Missing EPSS days, KEV/EPSS integration
- **Performance Integration**: Large dataset processing
- **Error Handling**: Network errors, corrupted cache files
- **Real-world Simulation**: Realistic EPSS evolution patterns
- **NIST Examples**: Complete validation of paper examples
- **System Integration**: Mocked network calls, full workflows

## Key Validation Points

### NIST CSWP 41 Compliance
The test suite specifically validates:

1. **Section 4.1 LEV Equation**: Correct implementation of LEV probability calculation
2. **Section 4.2 LEV2 Equation**: Alternative rigorous calculation method
3. **Section 5.2 EPSS as Lower Bounds**: Treating EPSS scores as probability lower bounds
4. **Section 6 Examples**: CVE-2023-1730 and CVE-2023-29373 specific cases
5. **Section 10.3 Missing Day Logic**: Forward search for missing EPSS data
6. **Section 3 Composite Probability**: max(EPSS, KEV, LEV) formula

### Mathematical Properties
- **Probability Bounds**: All results ∈ [0, 1]
- **Monotonicity**: LEV probability increases with time
- **Lower Bound Property**: LEV >= theoretical minimum
- **Window Adjustment**: Correct handling of partial 30-day windows
- **Numerical Precision**: Stable calculations with extreme values

## Running Tests

### Quick Start
```bash
# Install dependencies
pip install -r test/test_requirements.txt

# Run all tests
python test/run_tests.py all

# Run quick tests only (excludes slow/performance tests)
python test/run_tests.py quick
```

### Specific Test Suites
```bash
# Unit tests only
python test/run_tests.py unit

# Mathematical validation
python test/run_tests.py mathematical

# Integration tests
python test/run_tests.py integration

# Performance benchmarks
python test/run_tests.py performance

# Coverage report
python test/run_tests.py coverage
```

### Using Make (if available)
```bash
make test-quick          # Quick unit tests
make test-mathematical   # Mathematical validation
make test-integration    # Integration tests
make test-performance    # Performance benchmarks
make test-all           # All tests
make test-coverage      # Coverage report
```

### Direct pytest Commands
```bash
# All tests with verbose output
pytest test/ -v

# Exclude slow tests
pytest test/ -m "not slow" -v

# Mathematical validation only
pytest test/test_mathematical_validation.py -v

# Specific test
pytest test/test_lev_unit_tests.py::TestLEVCalculations::test_calculate_lev_nist_original_simple_case -v
```

## Test Data

### Realistic Test Data Generation
Generate comprehensive test datasets:
```bash
python test/test_data_generator.py
```

This creates:
- 6 months of realistic EPSS data (500 CVEs)
- KEV dataset with 25 entries
- NIST CSWP 41 example data (CVE-2023-1730, CVE-2023-29373)

### Test Data Patterns
The generator creates CVEs with different EPSS evolution patterns:
- **Stable**: Consistent scores with minor variation
- **Rising**: Gradually increasing scores over time
- **Declining**: Decreasing scores over time
- **Spike**: Brief period of high scores
- **Mixed**: Seasonal/trend/noise combination

## Performance Benchmarks

Performance tests validate:
- **Processing Time**: Large datasets complete within reasonable time
- **Memory Usage**: Memory consumption stays within bounds
- **Scalability**: Performance scales appropriately with data size
- **Parallel Processing**: Multi-threaded operations work correctly

### Benchmark Targets
- 1000 CVEs × 365 days: < 60 seconds
- Memory usage: < 1GB for substantial datasets
- Individual LEV calculation: < 1 second

## Key Test Examples

### CVE-2023-1730 Validation
```python
def test_cve_2023_1730_compliance():
    """Validate CVE-2023-1730 example from NIST CSWP 41 Section 6."""
    # Set up exact EPSS timeline from paper
    # Calculate LEV probability
    # Assert result ≈ 0.70 (paper's stated result)
```

### Mathematical Formula Validation
```python
def test_daily_probability_formula():
    """Test P1 = 1 - (1 - P30)^(1/30) formula."""
    # Test with known values
    # Verify mathematical correctness
```

### Missing Day Logic
```python
def test_missing_day_forward_search():
    """Test Section 10.3 missing day logic."""
    # Create gaps in EPSS data
    # Verify forward search finds next available day
```

## Expected Test Results

### Mathematical Validation
- All probability calculations ∈ [0, 1]
- CVE-2023-1730 LEV ≈ 0.70 ± 0.05
- CVE-2023-29373 LEV ≈ 0.54 ± 0.05
- Daily probability formula matches theoretical values

### Performance Benchmarks
- 500 CVEs × 180 days: ~30 seconds
- Memory usage: ~500MB for large datasets
- Numerical stability maintained for extreme values

### Integration Tests
- Complete workflows execute without errors
- KEV integration produces composite probabilities correctly
- Missing data handled gracefully per NIST specification

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure the main module is in Python path
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

2. **Missing Dependencies**
   ```bash
   pip install -r test/test_requirements.txt
   ```

3. **Slow Tests**
   ```bash
   # Skip slow tests
   pytest test/ -m "not slow" -v
   ```

4. **Memory Issues**
   ```bash
   # Run tests with limited dataset
   pytest test/ -k "not large_dataset" -v
   ```

### Debug Mode
```bash
# Run with detailed debugging
pytest test/ -v -s --tb=long

# Run specific failing test with debug output
pytest test/test_mathematical_validation.py::test_lev_inequality_property -v -s
```

## Contributing to Tests

### Adding New Tests
1. Follow the existing test structure and naming conventions
2. Add appropriate markers (@pytest.mark.slow, @pytest.mark.performance)
3. Include docstrings explaining what is being tested
4. Validate against NIST CSWP 41 specifications where applicable

### Test Categories
- **Unit tests**: Individual function/method validation
- **Mathematical tests**: Formula and calculation correctness
- **Integration tests**: End-to-end workflow validation
- **Performance tests**: Speed and memory benchmarks

### Assertion Helpers
Use provided assertion helpers for consistency:
```python
assert_valid_probability(value)  # Ensures value ∈ [0, 1]
assert_lev_probability_properties(lev_result, epss_scores)
assert_composite_probability_properties(composite_result)
```

## Validation Coverage

The test suite provides comprehensive validation of:

✅ **Mathematical Correctness**
- Daily probability formula implementation
- LEV inequality property compliance
- Composite probability max() formula
- Numerical stability and precision

✅ **NIST CSWP 41 Compliance**
- All equations from Sections 4.1 and 4.2
- Missing day logic from Section 10.3
- Example calculations from Section 6
- Expected_Exploited formulas from Section 3.1

✅ **Real-world Scenarios**
- Realistic EPSS evolution patterns
- KEV integration workflows
- Large dataset processing
- Error handling and edge cases

✅ **Performance Characteristics**
- Processing time benchmarks
- Memory usage validation
- Scalability testing
- Parallel processing verification

## Test Metrics

### Coverage Targets
- **Code Coverage**: >95% line coverage
- **Mathematical Formula Coverage**: 100% of NIST equations tested
- **Scenario Coverage**: All major use cases validated
- **Performance Coverage**: All performance-critical paths benchmarked

### Quality Gates
All tests must pass these criteria:
- Mathematical results within specified tolerances
- Performance within established benchmarks
- Memory usage within acceptable limits
- No regression in existing functionality

## Continuous Integration

### CI Pipeline
The test suite is designed for continuous integration with:
- Fast feedback loop (quick tests < 2 minutes)
- Comprehensive validation (all tests < 15 minutes)
- Performance regression detection
- Coverage reporting

### Test Stages
1. **Quick Validation**: Unit tests, mathematical validation
2. **Integration Testing**: End-to-end workflows
3. **Performance Testing**: Benchmarks and scalability
4. **Coverage Analysis**: Code and scenario coverage

## References

- **NIST CSWP 41**: "Likely Exploited Vulnerabilities: A Proposed Metric for Vulnerability Exploitation Probability"
- **EPSS Documentation**: https://www.first.org/epss/
- **CISA KEV Catalog**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## Support

For test-related issues:
1. Check this README for common solutions
2. Review test output for specific error messages
3. Run individual test files to isolate issues
4. Use debug mode (-v -s --tb=long) for detailed output

---

**Note**: This test suite is designed to be the definitive validation of LEV implementation compliance with NIST CSWP 41. All mathematical formulas, algorithms, and examples from the paper are thoroughly tested to ensure correctness and reliability.