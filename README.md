# Optimized Likely Exploited Vulnerabilities (LEV) Calculator

A high-performance Python implementation of: 

  - Mell P, Spring J (2025) [NIST CSWP 41: "Likely Exploited Vulnerabilities: A Proposed Metric for Vulnerability Exploitation Probability"](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf). (National Institute of Standards and Technology, Gaithersburg, MD), NIST Cybersecurity White Paper (CSWP) NIST CSWP 41. https://doi.org/10.6028/NIST.CSWP.41 

> [!IMPORTANT]  
> It is a "clean-room" implementation i.e. implemented from the whitepaper only as the source code and data use as part of the whitepaper are not available.
> 
> It is not endorsed or validated by, or associated with, the authors of White Paper NIST CSWP 41 or their employers.

> [!TIP]  
> This optimized version includes both the original NIST LEV2 approximation and a rigorous probabilistic implementation with significant performance improvements 
> 
> To solve the root problem of LEV2 calculation taking a long time, the correct computation is optimized via parallel processing and vectorized computations, rather than doing computation with approximations that only make sense for some cases i.e. when the EPSS scores are very small.

> [!NOTE]  
> See https://riskbasedprioritization.github.io/epss/LEV/ for high level details on Likely Exploited Vulnerabilities (LEV).

## Overview

This optimized tool calculates the probability that vulnerabilities have been observed to be exploited in the past, based on historical EPSS (Exploit Prediction Scoring System) scores. It includes two calculation methods:

1. **Original NIST LEV2**: The approximation method described in NIST CSWP 41
2. **Rigorous Probabilistic**: A mathematically precise implementation using proper probability theory

The LEV metric provides a mathematical framework for:

- Measuring the expected proportion of CVEs that have been exploited
- Estimating the comprehensiveness of Known Exploited Vulnerability (KEV) lists
- Augmenting vulnerability remediation prioritization
- Identifying potentially underscored vulnerabilities in EPSS

## Key Features

- **Dual Implementation**: Both NIST LEV2 approximation and rigorous probabilistic calculation
- **High Performance**: Optimized with parallel processing and vectorized computations
- **Numerically Stable**: Uses log-space arithmetic to prevent overflow/underflow
- **Accurate Implementation**: Follows the exact LEV equation from NIST CSWP 41
- **Window-Based Calculation**: Uses 30-day windows as specified in the paper
- **Historical Context**: Calculates from each CVE's first EPSS score date
- **Proper Weighting**: Handles partial windows correctly
- **Comprehensive Output**: Provides detailed results with performance metrics
- **Parallel Downloads**: Concurrent EPSS data fetching for faster setup

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
python lev_calculator.py
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

# Calculate LEV probabilities using NIST LEV2 approximation
nist_results_df = calculator.calculate_lev_for_all_cves(rigorous=False)

# Calculate LEV probabilities using rigorous probabilistic method
rigorous_results_df = calculator.calculate_lev_for_all_cves(rigorous=True)

# Get summary statistics
nist_summary = calculator.calculate_expected_exploited(nist_results_df)
rigorous_summary = calculator.calculate_expected_exploited(rigorous_results_df)

print(f"NIST LEV2 expected exploited: {nist_summary['expected_exploited']:.2f}")
print(f"Rigorous expected exploited: {rigorous_summary['expected_exploited']:.2f}")
```

This will:
1. Download EPSS data from January 1, 2024 to present using parallel processing
2. Calculate LEV probabilities using both methods
3. Save results to compressed CSV files for both approaches
4. Display detailed performance metrics and summary statistics

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

The tool generates detailed CSV files for both calculation methods:

**NIST LEV2 Results** (`lev_probabilities_nist_detailed.csv.gz`):
**Rigorous Results** (`lev_probabilities_rigorous_detailed.csv.gz`):

Both files contain:
- `cve`: CVE identifier
- `first_epss_date`: First date the CVE received an EPSS score
- `lev_probability`: Calculated LEV probability
- `peak_epss_30day`: Highest 30-day EPSS score observed
- `peak_epss_date`: Date of the peak EPSS score
- `num_relevant_epss_dates`: Number of days with EPSS data

### Example Console Output

```
python lev_calculator.py
[INFO] Loading EPSS data from 2024-01-01 to 2025-05-30
Loading EPSS scores from 2024-01-01 to 2025-05-30...
[LOAD] 1.9% - Loaded 10/516 files
[LOAD] 3.9% - Loaded 20/516 files
[LOAD] 5.8% - Loaded 30/516 files
[LOAD] 7.8% - Loaded 40/516 files
[LOAD] 9.7% - Loaded 50/516 files
[LOAD] 11.6% - Loaded 60/516 files
[LOAD] 13.6% - Loaded 70/516 files
[LOAD] 15.5% - Loaded 80/516 files
[LOAD] 17.4% - Loaded 90/516 files
[LOAD] 19.4% - Loaded 100/516 files
[LOAD] 21.3% - Loaded 110/516 files
[LOAD] 23.3% - Loaded 120/516 files
[LOAD] 25.2% - Loaded 130/516 files
[LOAD] 27.1% - Loaded 140/516 files
[LOAD] 29.1% - Loaded 150/516 files
[LOAD] 31.0% - Loaded 160/516 files
[LOAD] 32.9% - Loaded 170/516 files
[LOAD] 34.9% - Loaded 180/516 files
[LOAD] 36.8% - Loaded 190/516 files
[LOAD] 38.8% - Loaded 200/516 files
[LOAD] 40.7% - Loaded 210/516 files
[LOAD] 42.6% - Loaded 220/516 files
[LOAD] 44.6% - Loaded 230/516 files
[LOAD] 46.5% - Loaded 240/516 files
[LOAD] 48.4% - Loaded 250/516 files
[LOAD] 50.4% - Loaded 260/516 files
[LOAD] 52.3% - Loaded 270/516 files
[LOAD] 54.3% - Loaded 280/516 files
[LOAD] 56.2% - Loaded 290/516 files
[LOAD] 58.1% - Loaded 300/516 files
[LOAD] 60.1% - Loaded 310/516 files
[LOAD] 62.0% - Loaded 320/516 files
[LOAD] 64.0% - Loaded 330/516 files
[LOAD] 65.9% - Loaded 340/516 files
[ERROR] Failed to process 2024-12-01: 403 Client Error: Forbidden for url: https://epss.empiricalsecurity.com/epss_scores-2024-12-01.csv.gz
[LOAD] 67.8% - Loaded 350/516 files
[LOAD] 69.8% - Loaded 360/516 files
[LOAD] 71.7% - Loaded 370/516 files
[LOAD] 73.6% - Loaded 380/516 files
[LOAD] 75.6% - Loaded 390/516 files
[LOAD] 77.5% - Loaded 400/516 files
[LOAD] 79.5% - Loaded 410/516 files
[LOAD] 81.4% - Loaded 420/516 files
[LOAD] 83.3% - Loaded 430/516 files
[LOAD] 85.3% - Loaded 440/516 files
[LOAD] 87.2% - Loaded 450/516 files
[LOAD] 89.1% - Loaded 460/516 files
[LOAD] 91.1% - Loaded 470/516 files
[LOAD] 93.0% - Loaded 480/516 files
[LOAD] 95.0% - Loaded 490/516 files
[LOAD] 96.9% - Loaded 500/516 files
[LOAD] 98.8% - Loaded 510/516 files
[INFO] Loaded 515 files covering 515 dates
[INFO] Total EPSS records in memory: 132,760,714
[INFO] Data loading completed in 79.40 seconds

--- Debugging Sample CVE ---
Debug NIST for CVE-2006-3655:
  cve: CVE-2006-3655
  d0: 2024-01-01 00:00:00
  calculation_date: 2025-05-30 22:43:28.580151
  total_days: 516
  sample_dates: [datetime.datetime(2024, 1, 1, 0, 0), datetime.datetime(2024, 1, 2, 0, 0), datetime.datetime(2024, 1, 3, 0, 0), datetime.datetime(2024, 1, 4, 0, 0), datetime.datetime(2024, 1, 5, 0, 0)]
  sample_epss_scores: [0.90903, 0.90903, 0.90903, 0.90903, 0.90903]
  sample_daily_probs: [0.07679827670092954, 0.07679827670092954, 0.07679827670092954, 0.07679827670092954, 0.07679827670092954]
  max_epss: 0.90903
  max_daily_prob: 0.07679827670092954
  lev_probability: 1.0
  method: nist

Debug Rigorous for CVE-2006-3655:
  cve: CVE-2006-3655
  d0: 2024-01-01 00:00:00
  calculation_date: 2025-05-30 22:43:28.580616
  total_days: 516
  sample_dates: [datetime.datetime(2024, 1, 1, 0, 0), datetime.datetime(2024, 1, 2, 0, 0), datetime.datetime(2024, 1, 3, 0, 0), datetime.datetime(2024, 1, 4, 0, 0), datetime.datetime(2024, 1, 5, 0, 0)]
  sample_epss_scores: [0.90903, 0.90903, 0.90903, 0.90903, 0.90903]
  sample_daily_probs: [0.07679827670092954, 0.07679827670092954, 0.07679827670092954, 0.07679827670092954, 0.07679827670092954]
  max_epss: 0.90903
  max_daily_prob: 0.07679827670092954
  lev_probability: 0.9999999999999999
  method: rigorous

--- Calculating LEV probabilities using Original NIST LEV2 Formula ---
[INFO] Calculating NIST LEV2 probabilities as of 2025-05-30...
[INFO] Processing 292,351 CVEs in 33 batches using 8 workers...
[PROGRESS] 9.1% - Completed 3/33 batches
[PROGRESS] 18.2% - Completed 6/33 batches
[PROGRESS] 27.3% - Completed 9/33 batches
[PROGRESS] 36.4% - Completed 12/33 batches
[PROGRESS] 45.5% - Completed 15/33 batches
[PROGRESS] 54.5% - Completed 18/33 batches
[PROGRESS] 63.6% - Completed 21/33 batches
[PROGRESS] 72.7% - Completed 24/33 batches
[PROGRESS] 81.8% - Completed 27/33 batches
[PROGRESS] 90.9% - Completed 30/33 batches
[PROGRESS] 100.0% - Completed 33/33 batches
[INFO] Completed processing 292,351 CVEs
[INFO] NIST LEV2 calculation completed in 170.80 seconds
[INFO] Saved compressed NIST LEV2 results to ./data_out/lev_probabilities_nist_detailed.csv.gz
[INFO] Saved NIST LEV2 summary to ./data_out/lev_summary_nist.txt

LEV CALCULATION SUMMARY (Original NIST LEV2)
==================================================
Calculation Date: 2025-05-30 22:46:23
Date Range: 2024-01-01 to 2025-05-30
Data: 2024-01-01 to 2025-05-30
Calculation Time: 170.80 seconds
Total CVEs analyzed: 292,351
Expected number of exploited vulnerabilities: 36687.40
Expected proportion of exploited vulnerabilities: 0.1255 (12.55%)

LEV Probability Distribution:
Mean: 0.125491
Median: 0.025249
Max: 1.000000
Min: 0.000002
Standard Deviation: 0.244711

High Probability Analysis:
CVEs with LEV > 0.5: 25667
CVEs with LEV > 0.1: 67471
CVEs with LEV > 0.01: 216011

Top 10 highest LEV probabilities:
  CVE-2020-15227: LEV=1.0000, Peak EPSS=0.9731
  CVE-2007-2139: LEV=1.0000, Peak EPSS=0.9555
  CVE-2001-0925: LEV=1.0000, Peak EPSS=0.9479
  CVE-2015-5986: LEV=1.0000, Peak EPSS=0.9581
  CVE-2004-0597: LEV=1.0000, Peak EPSS=0.9641
  CVE-2012-0011: LEV=1.0000, Peak EPSS=0.9660
  CVE-2007-0981: LEV=1.0000, Peak EPSS=0.9700
  CVE-2013-0019: LEV=1.0000, Peak EPSS=0.9475
  CVE-2016-3386: LEV=1.0000, Peak EPSS=0.9436
  CVE-2009-2510: LEV=1.0000, Peak EPSS=0.9628

==================================================


--- Calculating LEV probabilities using Rigorous Probabilistic Approach ---
[INFO] Calculating Rigorous LEV probabilities as of 2025-05-30...
[INFO] Processing 292,351 CVEs in 33 batches using 8 workers...
[PROGRESS] 9.1% - Completed 3/33 batches
[PROGRESS] 18.2% - Completed 6/33 batches
[PROGRESS] 27.3% - Completed 9/33 batches
[PROGRESS] 36.4% - Completed 12/33 batches
[PROGRESS] 45.5% - Completed 15/33 batches
[PROGRESS] 54.5% - Completed 18/33 batches
[PROGRESS] 63.6% - Completed 21/33 batches
[PROGRESS] 72.7% - Completed 24/33 batches
[PROGRESS] 81.8% - Completed 27/33 batches
[PROGRESS] 90.9% - Completed 30/33 batches
[PROGRESS] 100.0% - Completed 33/33 batches
[INFO] Completed processing 292,351 CVEs
[INFO] Rigorous LEV calculation completed in 452.31 seconds
[INFO] Saved compressed rigorous LEV results to ./data_out/lev_probabilities_rigorous_detailed.csv.gz
[INFO] Saved Rigorous LEV summary to ./data_out/lev_summary_rigorous.txt

LEV CALCULATION SUMMARY (Rigorous Probabilistic)
==================================================
Calculation Date: 2025-05-30 22:53:58
Date Range: 2024-01-01 to 2025-05-30
Data: 2024-01-01 to 2025-05-30
Calculation Time: 452.31 seconds
Total CVEs analyzed: 292,351
Expected number of exploited vulnerabilities: 37361.63
Expected proportion of exploited vulnerabilities: 0.1278 (12.78%)

LEV Probability Distribution:
Mean: 0.127797
Median: 0.026257
Max: 1.000000
Min: 0.000002
Standard Deviation: 0.246789

High Probability Analysis:
CVEs with LEV > 0.5: 26270
CVEs with LEV > 0.1: 68730
CVEs with LEV > 0.01: 219135

Top 10 highest LEV probabilities:
  CVE-2022-22963: LEV=1.0000, Peak EPSS=0.9754
  CVE-2013-3893: LEV=1.0000, Peak EPSS=0.9685
  CVE-2007-0213: LEV=1.0000, Peak EPSS=0.9682
  CVE-2013-2010: LEV=1.0000, Peak EPSS=0.9721
  CVE-2018-20250: LEV=1.0000, Peak EPSS=0.9745
  CVE-2003-0719: LEV=1.0000, Peak EPSS=0.9640
  CVE-2013-1318: LEV=1.0000, Peak EPSS=0.9551
  CVE-2010-3232: LEV=1.0000, Peak EPSS=0.9644
  CVE-2010-1850: LEV=1.0000, Peak EPSS=0.9565
  CVE-2007-2280: LEV=1.0000, Peak EPSS=0.9707

==================================================


[PERFORMANCE] Total execution time: 709.71 seconds
[PERFORMANCE] Data loading: 79.40s
[PERFORMANCE] NIST LEV2 calculation: 170.80s
[PERFORMANCE] Rigorous LEV calculation: 452.31s
[PERFORMANCE] Rigorous vs NIST time ratio: 2.65x

```


## License

Creative Commons Attribution-ShareAlike 4.0 International
