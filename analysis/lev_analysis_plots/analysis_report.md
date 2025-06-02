
# LEV Analysis Summary Report
Generated on: 2025-06-02 21:43:35

## Dataset Overview
- Total CVEs: 293,324
- KEV CVEs: 1,352 (0.46%)

## Score Distributions
- EPSS: Mean=0.0348, Median=0.0024
- LEV: Mean=0.1465, Median=0.0332
- Composite: Mean=0.1477, Median=0.0332

## High-Risk CVE Counts by Threshold

### Threshold ≥ 0.1
- EPSS: 20,714 CVEs
- LEV: 79,519 CVEs  
- Composite: 79,730 CVEs

### Threshold ≥ 0.2
- EPSS: 13,621 CVEs
- LEV: 54,884 CVEs  
- Composite: 55,120 CVEs

### Threshold ≥ 0.5
- EPSS: 6,581 CVEs
- LEV: 30,506 CVEs  
- Composite: 30,864 CVEs

### Threshold ≥ 0.8
- EPSS: 2,683 CVEs
- LEV: 19,710 CVEs  
- Composite: 20,162 CVEs

## KEV Recall by LEV Thresholds
- LEV ≥ 0.1: 0.899 (89.9% of KEV CVEs)
- LEV ≥ 0.2: 0.849 (84.9% of KEV CVEs)
- LEV ≥ 0.5: 0.757 (75.7% of KEV CVEs)
- LEV ≥ 0.8: 0.673 (67.3% of KEV CVEs)

## Method Agreement
- EPSS-LEV Correlation: 0.695
- High EPSS AND High LEV: 20,629 CVEs
- High EPSS OR High LEV: 79,604 CVEs

## Key Insights
1. **LEV Complements EPSS**: LEV identifies 79,519 high-risk CVEs vs 20,714 by EPSS
2. **Composite Method**: Identifies 79,730 total high-risk CVEs (union of all methods)
3. **KEV Coverage**: LEV provides 89.9% recall of KEV list at 0.1 threshold
