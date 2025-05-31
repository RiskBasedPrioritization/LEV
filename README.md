# Optimized Likely Exploited Vulnerabilities (LEV) Calculator

A high-performance Python implementation of the Likely Exploited Vulnerabilities (LEV) metric as described in NIST Cybersecurity White Paper [NIST CSWP 41: "Likely Exploited Vulnerabilities: A Proposed Metric for Vulnerability Exploitation Probability"](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf) by Peter Mell and Jonathan Spring.

This optimized version includes both the original NIST LEV2 approximation and a rigorous probabilistic implementation with significant performance improvements.

```
Mell P, Spring J (2025) Likely Exploited Vulnerabilities: A Proposed Metric for Vulnerability Exploitation Probability.
(National Institute of Standards and Technology, Gaithersburg, MD), NIST Cybersecurity White Paper (CSWP) NIST
CSWP 41. https://doi.org/10.6028/NIST.CSWP.41 
```

## Overview

This optimized tool calculates the probability that vulnerabilities have been observed to be exploited in the past, based on historical EPSS (Exploit Prediction Scoring System) scores. It includes two calculation methods:

1. **Original NIST LEV2**: The approximation method described in NIST CSWP 41
2. **Rigorous Probabilistic**: A mathematically precise implementation using probability theory

The LEV metric provides a mathematical framework for:

- Measuring the expected proportion of CVEs that have been exploited
- Estimating the comprehensiveness of Known Exploited Vulnerability (KEV) lists
- Augmenting vulnerability remediation prioritization
- Identifying potentially underscored vulnerabilities in EPSS

## Key Features

- **Triple Implementation**: NIST LEV2 approximation, rigorous probabilistic calculation, and composite probability
- **Automatic KEV Integration**: Downloads and integrates CISA's Known Exploited Vulnerabilities list
- **High Performance**: Optimized with parallel processing and vectorized computations
- **Timezone Agnostic**: Works consistently from any location using UTC time reference
- **Numerically Stable**: Uses log-space arithmetic to prevent overflow/underflow
- **NIST CSWP 41 Compliant**: Follows exact specifications including missing-day logic
- **Comprehensive Logging**: Detailed file logging with timestamped audit trails
- **Window-Based Calculation**: Uses 30-day windows as specified in the paper
- **Historical Context**: Calculates from each CVE's first EPSS score date
- **Proper Weighting**: Handles partial windows correctly
- **Comprehensive Output**: Provides detailed results with performance metrics
- **Parallel Downloads**: Concurrent EPSS and KEV data fetching for faster setup

## Installation

### Requirements

```bash
pip install pandas numpy requests
```

### Dependencies

- Python 3.7+
- pandas
- numpy
- requests

## Usage

### Command Line Usage

```bash
python optimized_lev_calculator.py
```

### Basic Usage via Python

```python
from optimized_lev_calculator import OptimizedLEVCalculator
from datetime import datetime

# Initialize calculator with optimal performance settings
calculator = OptimizedLEVCalculator(max_workers=8)

# Download EPSS data for date range (parallel processing)
start_date = datetime(2024, 1, 1)
end_date = datetime.today()
calculator.download_epss_data(start_date, end_date)

# Load KEV data (automatically downloads from CISA if missing)
calculator.load_kev_data(download_if_missing=True)

# Calculate LEV probabilities using NIST LEV2 approximation
nist_results_df = calculator.calculate_lev_for_all_cves(rigorous=False)

# Calculate LEV probabilities using rigorous probabilistic method
rigorous_results_df = calculator.calculate_lev_for_all_cves(rigorous=True)

# Calculate composite probabilities (EPSS + KEV + LEV)
composite_nist_df = calculator.calculate_composite_for_all_cves(rigorous=False)
composite_rigorous_df = calculator.calculate_composite_for_all_cves(rigorous=True)

# Get summary statistics
nist_summary = calculator.calculate_expected_exploited(nist_results_df)
rigorous_summary = calculator.calculate_expected_exploited(rigorous_results_df)

print(f"NIST LEV2 expected exploited: {nist_summary['expected_exploited']:.2f}")
print(f"Rigorous expected exploited: {rigorous_summary['expected_exploited']:.2f}")
print(f"Composite (NIST) CVEs with high probability: {len(composite_nist_df[composite_nist_df['composite_probability'] > 0.5])}")
```

This will:
1. Download EPSS data from January 1, 2024 to present using parallel processing
2. Automatically download the latest KEV data from CISA
3. Calculate LEV probabilities using both methods
4. Calculate composite probabilities combining EPSS, KEV, and LEV scores
5. Save results to compressed CSV files for all approaches
6. Display detailed performance metrics and summary statistics
7. Create timestamped log files in the `logs/` directory

## Implementation Notes

1. Any CVE present in the CISA CSV is treated as “in KEV now,” ignoring whether it was added to the KEV list after the calculation date. The paper does not require tracking “when” a CVE entered KEV; so simply treat the current CSV as “truth as of now.”
2. NVD data is not downloaded or processed i.e. the code does not fetch CVE publish dates, descriptions, or CPE triples from the NVD.


## Configuration

### Date Range Selection

For optimal results, choose your date range based on EPSS version:

```python
# EPSS v3 only (highest accuracy)
start_date = datetime(2023, 3, 7)

# EPSS v2 and v3
start_date = datetime(2022, 2, 4)

# All EPSS versions (includes less accurate v1 data)
start_date = datetime(2021, 4, 14)
```

### Performance Configuration

```python
# Optimize for your system
calculator = OptimizedLEVCalculator(
    cache_dir="custom_cache",
    max_workers=16  # Adjust based on CPU cores
)

# For large datasets, consider limiting date range initially
start_date = datetime(2024, 6, 1)  # Shorter range for testing
```

## Output Format

### CSV Output

The tool generates detailed CSV files for all calculation methods:

**NIST LEV2 Results** (`lev_probabilities_nist_detailed.csv.gz`):
**Rigorous Results** (`lev_probabilities_rigorous_detailed.csv.gz`):
**Composite NIST Results** (`composite_probabilities_nist.csv.gz`):
**Composite Rigorous Results** (`composite_probabilities_rigorous.csv.gz`):

#### LEV Files contain:
- `cve`: CVE identifier
- `first_epss_date`: First date the CVE received an EPSS score
- `lev_probability`: Calculated LEV probability
- `peak_epss_30day`: Highest 30-day EPSS score observed
- `peak_epss_date`: Date of the peak EPSS score
- `num_relevant_epss_dates`: Number of days with EPSS data

#### Composite Files contain:
- `cve`: CVE identifier
- `epss_score`: Current EPSS score
- `kev_score`: 1.0 if in KEV list, 0.0 otherwise
- `lev_score`: Calculated LEV probability
- `composite_probability`: max(EPSS, KEV, LEV)
- `is_in_kev`: Boolean flag indicating KEV membership

### Log Files

All operations are logged to timestamped files in `logs/YYYYMMDD_HHMMSS.log` containing:
- Download statistics and errors
- Processing progress and timing
- Mathematical calculation details
- Performance metrics and summaries

### Example Console Output

```
2025-05-31 15:30:45 - INFO - Logging initialized. Log file: logs/20250531_153045.log
2025-05-31 15:30:45 - INFO - Date range: 2023-03-07 to 2025-05-31
2025-05-31 15:30:45 - INFO - Current UTC time: 2025-05-31 15:30:45 UTC
2025-05-31 15:30:45 - INFO - Loading EPSS scores from 2023-03-07 to 2025-05-31...
2025-05-31 15:32:15 - INFO - Download completed. Statistics:
2025-05-31 15:32:15 - INFO -   Total attempted: 816
2025-05-31 15:32:15 - INFO -   Successful: 815
2025-05-31 15:32:15 - INFO -   Missing days (404): 1
2025-05-31 15:32:15 - INFO - Loading KEV (Known Exploited Vulnerabilities) data
2025-05-31 15:32:15 - INFO - Downloading KEV data from https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
2025-05-31 15:32:17 - INFO - Loaded 1,208 CVEs from KEV list

LEV CALCULATION SUMMARY (Original NIST LEV2)
==================================================
Calculation Date: 2025-05-31 15:35:22
Date Range: 2023-03-07 to 2025-05-31
Data: 2023-03-07 to 2025-05-31
Calculation Time: 165.54 seconds
Total CVEs analyzed: 292,351
Expected number of exploited vulnerabilities: 36687.40
Expected proportion of exploited vulnerabilities: 0.1255 (12.55%)

COMPOSITE PROBABILITY SUMMARY (NIST LEV2):
Total CVEs analyzed: 293,559
CVEs in KEV list: 1,208
CVEs with EPSS > 0: 292,351
CVEs with LEV > 0: 285,447
CVEs with Composite > 0.5: 26,875
CVEs with Composite > 0.1: 68,679
Mean composite probability: 0.126834

[PERFORMANCE] Total execution time: 1,245.67 seconds
[PERFORMANCE] Data loading: 90.32s (7.3%)
[PERFORMANCE] NIST LEV2 calculation: 165.54s (13.3%)
[PERFORMANCE] Rigorous LEV calculation: 452.31s (36.3%)
[PERFORMANCE] NIST composite calculation: 87.21s (7.0%)
[PERFORMANCE] Rigorous composite calculation: 450.29s (36.1%)
```

## Mathematical Background

The implementation includes three approaches:

### NIST LEV2 (Original Approximation)
```
LEV(v, d₀, dₙ) >= 1 - ∏(1 - epss(v, dᵢ) × weight(dᵢ, dₙ, 30))
```

This uses the approximation that daily probability ≈ EPSS₃₀/30.

### Rigorous Probabilistic Method
```
LEV(v, d₀, dₙ) = 1 - ∏(1 - P₁(v, dᵢ))
```

Where P₁(v, dᵢ) is the daily probability derived from the 30-day EPSS score:
```
P₁ = 1 - (1 - P₃₀)^(1/30)
```

### Composite Probability
```
Composite_Probability(v, dₙ) = max(EPSS(v, dₙ), KEV(v, dₙ), LEV(v, d₀, dₙ))
```

Where:
- **EPSS(v, dₙ)**: Current EPSS score for vulnerability v
- **KEV(v, dₙ)**: 1.0 if vulnerability is in CISA's KEV list, 0.0 otherwise
- **LEV(v, d₀, dₙ)**: Calculated LEV probability (using either method)

**Key Differences:**
- **NIST LEV2**: Computational approximation assuming small probabilities
- **Rigorous**: Mathematically correct probability conversion
- **Composite**: Integrates multiple vulnerability assessment sources
- **Performance**: Rigorous method uses vectorized operations for efficiency

The rigorous method is more accurate for high EPSS scores where the P₃₀/30 approximation breaks down. The composite method provides a comprehensive vulnerability assessment by leveraging the best available information from each source.

## Limitations

As noted in the NIST white paper:

- **Margin of Error**: The metric has an unknown margin of error
- **EPSS Dependency**: Accuracy depends on underlying EPSS performance
- **Data Availability**: Requires comprehensive historical EPSS data
- **Not a Replacement**: LEV lists do not replace KEV lists but augment them
- **Computational Approximation**: NIST LEV2 uses simplifying assumptions for tractability

## Data Sources

- **EPSS Scores**: Downloaded from `https://epss.empiricalsecurity.com/`
- **KEV List**: Downloaded from `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv`
- **Methodology**: Based on NIST CSWP 41 (May 19, 2025)
- **Timezone**: All calculations use UTC time for consistency across locations

## Performance Considerations

### Optimization Features

- **Parallel Processing**: Multi-threaded downloads and CVE batch processing
- **Vectorized Computations**: NumPy arrays for mathematical operations
- **Numerical Stability**: Log-space calculations prevent overflow/underflow
- **Memory Efficiency**: Optimized data structures and caching
- **Dynamic Batching**: Automatic adjustment based on system capabilities

### System Requirements

- **Memory**: 4-8 GB RAM recommended for full historical data
- **CPU**: Multi-core processor (4+ cores) for optimal performance
- **Storage**: 10-20 GB for cached EPSS files
- **Network**: Stable connection for initial EPSS data downloads

### Performance Benchmarks

Typical performance on modern hardware (8-core CPU, 16GB RAM):

- **Data Loading**: 200,000 CVEs/day data in ~90 seconds (parallel)
- **KEV Download**: ~1,200 entries in ~2 seconds
- **NIST LEV2**: ~300,000 CVEs in ~165 seconds
- **Rigorous LEV**: ~300,000 CVEs in ~450 seconds
- **Composite Calculations**: ~300,000 CVEs in ~85-450 seconds (depending on method)
- **Overall Speedup**: 3-5x improvement over naive implementation
- **Missing Day Handling**: Automatic fallback per NIST CSWP 41 Section 10.3

### Optimization Tips

1. **Parallel Processing**: Use max_workers parameter to match your CPU cores
2. **Memory Management**: Limit date range for systems with <8GB RAM
3. **Use Cache**: Cached files significantly speed up repeated runs
4. **Batch Processing**: Process CVE subsets for memory-constrained systems
5. **SSD Storage**: Use SSD for cache directory to improve I/O performance

## Validation and Testing

This implementation includes comprehensive validation tools to verify mathematical correctness and performance:

### Approximation Error Analysis (p30.py)

A utility script demonstrates the error introduced by the NIST LEV2 approximation P₁ ≈ P₃₀/30:

### Test Suite (test_rigorous_calculation.py)

Comprehensive unit tests verify:
- Daily probability conversion accuracy
- LEV calculation logic
- Edge case handling (very small/large probabilities)
- Numerical stability

Run tests with:
```bash
python lev_calculator_test.py
```

### Real-World Performance

From actual runs on 292,351 CVEs with 815 days of EPSS data and 1,208 KEV entries:

**Results Comparison:**
- **NIST LEV2**: 36,687 expected exploited vulnerabilities (12.55%)
- **Rigorous**: 37,362 expected exploited vulnerabilities (12.78%)
- **Composite (NIST)**: 68,679 CVEs with probability > 0.1 (23.4%)
- **Composite (Rigorous)**: 69,843 CVEs with probability > 0.1 (23.8%)
- **LEV Difference**: +675 vulnerabilities (+1.8% increase from rigorous method)

**Performance Metrics:**
- Data Loading: 90.3 seconds (parallel processing + KEV download)
- NIST LEV2: 165.5 seconds
- Rigorous LEV: 452.3 seconds (2.7x slower, but mathematically precise)
- Composite Calculations: 87-450 seconds (varies by LEV method used)

**KEV Integration Impact:**
- 1,208 additional CVEs identified through KEV list
- Composite scores provide more comprehensive vulnerability assessment
- Automatic daily updates ensure current threat landscape coverage

## Example Use Cases

### 1. Assess KEV List Comprehensiveness

```python
# Find high-probability CVEs not on a KEV list
high_prob_cves = results_df[results_df['lev_probability'] > 0.1]
print(f"Candidates for KEV inclusion: {len(high_prob_cves)}")
```

### 2. Compare Calculation Methods

```python
# Compare NIST approximation vs rigorous calculation
comparison_df = pd.merge(
    nist_results_df[['cve', 'lev_probability']].rename(columns={'lev_probability': 'nist_lev'}),
    rigorous_results_df[['cve', 'lev_probability']].rename(columns={'lev_probability': 'rigorous_lev'}),
    on='cve'
)

# Find CVEs where methods differ significantly
comparison_df['difference'] = abs(comparison_df['rigorous_lev'] - comparison_df['nist_lev'])
significant_diff = comparison_df[comparison_df['difference'] > 0.1]
print(f"CVEs with >10% difference between methods: {len(significant_diff)}")
```

### 3. Augment EPSS Scoring

```python
# Identify potentially underscored vulnerabilities
def composite_probability(epss_score, lev_score, is_on_kev):
    kev_score = 1.0 if is_on_kev else 0.0
    return max(epss_score, lev_score, kev_score)
```

### 4. Measure Expected Exploitation

```python
# Calculate proportion of exploited vulnerabilities
summary = calculator.calculate_expected_exploited(results_df)
proportion = summary['expected_exploited_proportion']
print(f"Estimated {proportion:.1%} of CVEs have been exploited")
```

### 5. Calculate Composite Probabilities

```python
# Calculate composite probability for a single CVE
cve_result = calculator.calculate_composite_probability("CVE-2021-44228", rigorous=True)
print(f"EPSS: {cve_result['epss_score']:.4f}")
print(f"KEV: {cve_result['kev_score']:.1f}")
print(f"LEV: {cve_result['lev_score']:.4f}")
print(f"Composite: {cve_result['composite_probability']:.4f}")

# Analyze composite probability distribution
composite_df = calculator.calculate_composite_for_all_cves(rigorous=True)
high_composite = composite_df[composite_df['composite_probability'] > 0.8]
print(f"CVEs with composite probability > 80%: {len(high_composite)}")
```

### 6. Compare KEV Coverage

```python
# Analyze KEV list coverage vs LEV predictions
kev_cves = composite_df[composite_df['is_in_kev'] == True]
high_lev_not_kev = composite_df[
    (composite_df['lev_score'] > 0.5) & 
    (composite_df['is_in_kev'] == False)
]
print(f"High LEV CVEs not in KEV: {len(high_lev_not_kev)} potential additions")
```

## Contributing

When contributing to this implementation:

1. Ensure mathematical accuracy with NIST CSWP 41
2. Include unit tests for critical functions using the provided test framework
3. Maintain compatibility with the paper's methodology
4. Document any deviations or extensions
5. Consider performance impact of changes
6. Test both calculation methods for consistency
7. Validate approximation errors using the p30.py analysis tool

### Testing Your Changes

Before submitting changes, run the full test suite:

```bash
# Run mathematical validation tests
python lev_calculator_test.py

# Analyze approximation errors
python p30.py

# Run performance benchmarks
python lev_calculator.py
```

## References

- Mell, P., & Spring, J. (2025). *Likely Exploited Vulnerabilities: A Proposed Metric for Vulnerability Exploitation Probability*. NIST Cybersecurity White Paper (CSWP) 41. https://doi.org/10.6028/NIST.CSWP.41

- EPSS Documentation: https://www.first.org/epss/

- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## License

This project is licensed under the Attribution-ShareAlike 4.0 International License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This implementation is based on the methodology described in NIST CSWP 41. The LEV metric has known limitations and should be used in conjunction with other vulnerability management practices. Users should understand the mathematical assumptions and limitations before making operational decisions based on these results.

### Important Notes on the Three Methods

- **NIST LEV2**: Uses the approximation P₁ ≈ P₃₀/30, which is only accurate for small EPSS scores (<0.1)
- **Rigorous Method**: Uses the mathematically correct formula P₁ = 1 - (1 - P₃₀)^(1/30)
- **Composite Method**: Combines EPSS, KEV, and LEV using max() operation per NIST CSWP 41
- **When to Use Each**: 
  - For research requiring mathematical precision, use the rigorous method
  - For operational use following NIST guidelines, use LEV2
  - For comprehensive vulnerability assessment, use composite probabilities
  - For high EPSS scores (>0.5), the rigorous method provides significantly more accurate results
- **Performance Trade-off**: Rigorous method is ~2.7x slower but eliminates approximation errors
- **KEV Integration**: Automatically downloads latest CISA KEV list for up-to-date threat intelligence
- **UTC Time Handling**: Works consistently across all timezones using UTC reference

**Approximation Error Impact:**
Based on real-world analysis of 292K CVEs, the rigorous method identifies 675 additional expected exploited vulnerabilities (+1.8%), while composite probabilities identify 23.4-23.8% of all CVEs as having significant exploitation risk when combining all three data sources. (+1.8%), demonstrating the practical significance of using the correct mathematical formulation.

---

*For questions about the underlying methodology, refer to NIST CSWP 41. For implementation-specific issues, please open an issue in this repository.*