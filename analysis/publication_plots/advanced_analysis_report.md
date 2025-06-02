
# Advanced LEV Analysis Report
Generated: 2025-06-02 21:53:25

## Key Findings

### 1. EPSS-LEV Correlation Analysis
- Correlation coefficient: 0.695
- Relationship strength: moderate
- Statistical significance: p = 0.00e+00

### 2. KEV Prediction Performance
- EPSS AUC for KEV prediction: 0.927
- LEV AUC for KEV prediction: 0.908
- Better KEV predictor: EPSS
- Performance difference: 0.019

### 3. Method Complementarity
- CVEs identified only by EPSS (≥0.1): 85
- CVEs identified only by LEV (≥0.1): 58,890
- CVEs identified by both methods: 20,629
- Complementarity score: 0.741

### 4. Temporal Effects
- Age-EPSS correlation: 0.114
- Age-LEV correlation: 0.278
- Older CVEs have higher LEV: True

### 5. Composite Method Value
- CVEs with significant composite improvement: 73,213
- Improvement rate: 25.0%
- KEV boost cases: 1,352
- KEV boost rate: 0.5%

## Implications for Vulnerability Management

1. **Complementary Nature**: EPSS and LEV identify different sets of high-risk CVEs, 
   supporting the NIST CSWP 41 recommendation to use them together.

2. **Composite Advantage**: The composite method provides 25.0% 
   improvement in coverage over individual methods.

3. **KEV Prediction**: EPSS 
   is a better predictor of KEV membership, but the difference is 
   0.019.

4. **Aging Effects**: Older CVEs tend to have higher LEV scores.

## Recommendations

1. **Use Composite Scoring**: Implement the max(EPSS, KEV, LEV) approach for comprehensive risk assessment.

2. **Threshold Selection**: Based on sensitivity analysis, consider:
   - Conservative approach: 0.1 threshold captures most high-risk CVEs
   - Aggressive approach: 0.5 threshold focuses on highest-confidence cases

3. **Method-Specific Insights**:
   - Use LEV to identify potentially underscored vulnerabilities
   - Use EPSS for forward-looking threat assessment
   - Use KEV for definitive exploitation evidence

4. **Regular Updates**: Implement daily updates for EPSS and periodic KEV refreshes to maintain accuracy.
