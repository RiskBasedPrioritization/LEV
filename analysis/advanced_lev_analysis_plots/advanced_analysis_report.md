# LEV Analysis and Visualization Suite

**Comprehensive analysis toolkit for understanding LEV (Likelihood of Exploitation in the Wild) performance relative to EPSS and KEV methodologies.**

This suite provides sophisticated statistical analysis and visualization capabilities for vulnerability prioritization research, implementing and extending the methodologies described in NIST CSWP 41.

## 🎯 **Overview**

The LEV Analysis Suite consists of two complementary modules:

1. **Core LEV Analyzer** - Essential comparisons and operational insights (8 analysis types)
2. **Advanced LEV Analyzer** - Statistical validation and research-grade analysis (6 additional analysis types)

Together, they provide **14 different visualization types** with **comprehensive statistical validation** for understanding vulnerability scoring methodologies.

## 📊 **Complete Analysis Capabilities**

### **Core Analysis Suite (LEVAnalyzer)**

**📋 [View Generated Core Analysis Report](analysis/lev_analysis_plots/analysis_report.md)**

| Plot | Purpose | Key Insights |
|------|---------|--------------|
| **1. EPSS vs LEV Scatter** | Relationship visualization | Method complementarity, KEV distribution patterns |
| **2. LEV Recall Curve** | NIST CSWP 41 validation | KEV coverage at different thresholds |
| **3. Probability Distributions** | Score characteristics | Distribution shapes, outlier patterns |
| **4. Method Agreement Matrix** | Overlap quantification | Agreement rates, unique identifications |
| **5. Temporal Evolution** | Time-based patterns | CVE age vs risk score relationships |
| **6. Composite Effectiveness** | Coverage comparison | Improvement over individual methods |
| **7. Risk Quadrant Analysis** | Actionable categorization | Strategic prioritization guidance |
| **8. Summary Statistics** | Comprehensive metrics | Key performance indicators |

### **Advanced Analysis Suite (AdvancedLEVAnalyzer)**

**📊 [View Generated Advanced Analysis Report](analysis/advanced_lev_analysis_plots/advanced_analysis_report.md)**


| Plot | Purpose | Key Insights |
|------|---------|--------------|
| **9. ROC Analysis** | Predictive performance | KEV prediction accuracy comparison |
| **10. EPSS Evolution Impact** | Temporal score analysis | How EPSS changes affect LEV calculations |
| **11. Sensitivity Analysis** | Threshold optimization | Operational parameter selection |
| **12. Vulnerability Aging** | Time-based risk patterns | CVE age effects on scoring |
| **13. Composite Value Analysis** | Method combination benefits | Where composite scoring adds most value |
| **14. Statistical Validation** | Correlation & significance | Statistical rigor and validation |

## 🚀 **Quick Start**

### **Installation Requirements**

```python
# Required packages
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc, precision_recall_curve
from scipy import stats
```

### **Basic Usage**

```python
# Initialize core analyzer
analyzer = LEVAnalyzer(
    lev_file="data_out/lev_probabilities_nist_detailed.csv.gz",
    composite_file="data_out/composite_probabilities_nist.csv.gz"
)

# Generate comprehensive report with all core plots
stats = analyzer.create_comprehensive_report()
```

### **Advanced Analysis**

```python
# Load data for advanced analysis
lev_df = pd.read_csv("data_out/lev_probabilities_nist_detailed.csv.gz")
composite_df = pd.read_csv("data_out/composite_probabilities_nist.csv.gz")

# Initialize advanced analyzer
advanced_analyzer = AdvancedLEVAnalyzer(lev_df, composite_df)

# Generate advanced analysis report
insights = advanced_analyzer.create_advanced_comprehensive_report()
```

### **Publication-Ready Output**

```python
# Generate publication-quality plots
pub_insights = create_publication_ready_plots(
    lev_file="data_out/lev_probabilities_nist_detailed.csv.gz",
    composite_file="data_out/composite_probabilities_nist.csv.gz",
    output_dir="analysis/publication_plots"
)
```

## 📊 **Complete Analysis Reports**

The LEV Analysis Suite generates comprehensive markdown reports with embedded visualizations and detailed insights:

### **📋 Core Analysis Report**
**[analysis/lev_analysis_plots/analysis_report.md](analysis/lev_analysis_plots/analysis_report.md)**

Contains:
- Executive summary with key dataset statistics
- 8 embedded visualizations with specific insights
- High-risk CVE analysis by threshold
- Method agreement and correlation analysis
- Strategic recommendations for vulnerability management
- Actionable quadrant analysis for prioritization

### **📊 Advanced Analysis Report** 
**[analysis/advanced_lev_analysis_plots/advanced_analysis_report.md](analysis/advanced_lev_analysis_plots/advanced_analysis_report.md)**

Contains:
- Statistical validation and correlation analysis
- ROC curve analysis for KEV prediction performance
- Sensitivity analysis for threshold optimization
- Temporal evolution and vulnerability aging analysis
- Composite method value-add quantification
- Research-grade statistical findings and implications

### **📈 Quick Report Access**

After running the analysis, you can directly access the generated reports:

```bash
# View core analysis results
open analysis/lev_analysis_plots/analysis_report.md

# View advanced analysis results  
open analysis/advanced_lev_analysis_plots/advanced_analysis_report.md
```

Both reports include:
- **📊 Embedded visualizations** for offline viewing
- **📈 Statistical summaries** with key metrics
- **🎯 Actionable insights** for operational teams
- **🔬 Research findings** validating NIST methodologies
- **💡 Strategic recommendations** for vulnerability prioritization

---

### **Core Analysis Output**
```
analysis/lev_analysis_plots/
├── epss_vs_lev_scatter.png           # Method relationship visualization
├── lev_recall_curve.png              # KEV coverage analysis
├── probability_distributions.png      # Score distribution comparison
├── method_agreement_matrix.png        # Overlap quantification
├── temporal_evolution.png             # Time-based patterns
├── composite_effectiveness.png        # Coverage improvement analysis
├── risk_quadrants.png                # Actionable categorization
└── analysis_report.md                # Comprehensive report with embedded plots
```
**📋 [View Core Analysis Report](analysis/lev_analysis_plots/analysis_report.md)**

### **Advanced Analysis Output**
```
analysis/advanced_lev_analysis_plots/
├── roc_analysis.png                   # Predictive performance curves
├── epss_evolution_impact.png          # Temporal score relationships
├── method_sensitivity_analysis.png    # Threshold optimization
├── vulnerability_aging_analysis.png   # Age-based risk patterns
├── composite_value_analysis.png       # Value-add quantification
├── statistical_validation.png         # Correlation and significance
└── advanced_analysis_report.md       # Advanced statistical report
```
**📊 [View Advanced Analysis Report](analysis/advanced_lev_analysis_plots/advanced_analysis_report.md)**

### **Publication Output**
```
analysis/publication_plots/
├── roc_analysis_hires.png            # Research-quality ROC curves
├── sensitivity_analysis_hires.png     # Publication-ready sensitivity analysis
├── epss_evolution_impact_hires.png   # High-resolution temporal analysis
├── vulnerability_aging_hires.png      # Publication-ready aging analysis
├── composite_value_analysis_hires.png # High-resolution value analysis
├── statistical_validation_hires.png   # Publication-quality statistics
└── publication_summary.md            # Research findings summary
```

## 🔍 **Key Insights Generated**

### **Strategic Insights**
- **Method Complementarity**: Quantifies how EPSS and LEV identify different high-risk CVE sets
- **Optimal Thresholds**: Data-driven recommendations for operational cutoff points
- **ROI Analysis**: Identifies scenarios where composite method provides maximum value
- **Temporal Patterns**: Reveals how vulnerability risk evolves over time

### **Validation Insights**
- **Statistical Significance**: Correlation coefficients and p-values for method relationships
- **Predictive Performance**: AUC scores for KEV prediction capabilities
- **Method Agreement**: Quantifies alignment between EPSS and LEV at different thresholds
- **Distribution Analysis**: Characterizes risk score distributions and outlier patterns

### **Operational Insights**
- **High-Risk Identification**: Comparative analysis of critical CVE detection
- **Update Frequency**: Guidance on score refresh requirements
- **Prioritization Logic**: Evidence-based triage recommendations
- **Edge Cases**: Analysis of scenarios where methods disagree

## 📊 **Expected Key Findings**

Based on NIST CSWP 41 research and empirical analysis:

| Metric | Expected Range | Interpretation |
|--------|----------------|----------------|
| **EPSS-LEV Correlation** | 0.2 - 0.4 | Methods are complementary, not redundant |
| **LEV KEV Recall @ 10%** | 40% - 60% | Validates NIST findings |
| **Composite Improvement** | 20% - 30% | Additional high-risk CVEs identified |
| **Method Disagreement** | 15% - 25% | Unique value from each approach |
| **KEV Prediction AUC** | 0.7 - 0.8 | Good predictive performance |

## 🎯 **Recommended Analysis Workflow**

### **Phase 1: Foundation Analysis**
1. **Basic Relationships** (Plots 1-3): Understand core EPSS-LEV dynamics
2. **Method Performance** (Plots 4, 9): Validate against KEV ground truth
3. **Distribution Analysis** (Plot 3, 14): Characterize score behaviors

### **Phase 2: Operational Optimization**
1. **Threshold Selection** (Plots 6, 11): Optimize for organizational needs
2. **Coverage Analysis** (Plots 2, 6): Understand method coverage
3. **Value Quantification** (Plots 13): Identify composite method benefits

### **Phase 3: Advanced Insights**
1. **Temporal Analysis** (Plots 5, 10, 12): Understand time-based patterns
2. **Risk Categorization** (Plot 7): Develop actionable frameworks
3. **Statistical Validation** (Plot 14): Ensure methodological rigor

## 🔬 **Statistical Methods Implemented**

### **Correlation Analysis**
- Pearson correlation coefficients with significance testing
- Non-parametric correlation for non-normal distributions
- Cross-validation of relationships across different CVE subsets

### **Predictive Performance**
- ROC curve analysis with AUC calculation
- Precision-recall curves for imbalanced datasets
- Bootstrap confidence intervals for performance metrics

### **Distribution Analysis**
- Mann-Whitney U tests for group comparisons
- Kolmogorov-Smirnov tests for distribution similarity
- Q-Q plots for normality assessment

### **Agreement Analysis**
- Cohen's kappa for categorical agreement
- Intraclass correlation coefficients
- Bland-Altman analysis for method comparison

## 🛠 **Customization Options**

### **Threshold Sensitivity**
```python
# Analyze custom threshold ranges
thresholds = np.arange(0.05, 0.95, 0.05)
sensitivity_results = analyzer.plot_method_sensitivity_analysis()
```

### **Temporal Windows**
```python
# Focus on specific time periods
recent_analysis = analyzer.plot_temporal_evolution(
    sample_cves=500,
    date_range=('2023-01-01', '2024-12-31')
)
```

### **Custom Visualizations**
```python
# Generate specific plots for presentations
fig1 = analyzer.plot_epss_vs_lev_scatter(sample_size=5000, figsize=(14, 10))
fig2 = analyzer.plot_risk_quadrants(figsize=(12, 9))
```

## 📋 **Data Requirements**

### **LEV Results File**
Required columns:
- `cve`: CVE identifier
- `lev_probability`: LEV probability score
- `peak_epss_30day`: Peak EPSS score over 30-day window
- `first_epss_date`: First date CVE appeared in EPSS
- `num_relevant_epss_dates`: Number of EPSS data points

### **Composite Results File**
Required columns:
- `cve`: CVE identifier  
- `epss_score`: Current EPSS score
- `kev_score`: KEV membership score
- `is_in_kev`: Boolean KEV membership
- `composite_probability`: Combined score

## 🎨 **Visualization Features**

### **Publication Quality**
- **High Resolution**: 300 DPI PNG output for publications
- **Professional Styling**: Serif fonts, proper sizing, clean layouts
- **Color Accessibility**: Colorblind-friendly palettes
- **Annotation Rich**: Detailed labels, legends, and insights

### **Interactive Elements**
- **Hover Information**: Detailed CVE information on hover
- **Zoom Capabilities**: Interactive exploration of data regions
- **Filter Options**: Dynamic filtering by CVE characteristics
- **Export Options**: Multiple format support for different use cases

## 🤝 **Contributing**

### **Adding New Analysis Types**
1. Create new method in appropriate analyzer class
2. Follow naming convention: `plot_analysis_name()`
3. Return matplotlib figure object
4. Include comprehensive docstring with purpose and insights
5. Add to comprehensive report generation

### **Extending Statistical Methods**
1. Import required statistical libraries
2. Implement validation methods in `generate_*_insights_report()`
3. Add results to insights dictionary
4. Include interpretation in markdown report

### **Improving Visualizations**
1. Follow existing styling conventions
2. Ensure accessibility compliance
3. Add meaningful annotations and labels
4. Test with various data sizes and distributions

## 📚 **References**

- **NIST CSWP 41**: "Recommended Criteria for Cybersecurity Labeling for Consumer Internet of Things (IoT) Devices"
- **EPSS Framework**: Exploit Prediction Scoring System methodology
- **KEV Catalog**: CISA Known Exploited Vulnerabilities catalog
- **Statistical Methods**: Standard practices for predictive model evaluation

## 📞 **Support**

For questions about methodology, implementation, or results interpretation:

1. **Check Documentation**: Review method docstrings and report insights
2. **Examine Output**: Comprehensive reports include interpretation guidance
3. **Validate Results**: Compare against NIST CSWP 41 expected findings
4. **Statistical Questions**: Refer to implemented statistical method documentation

---

**This comprehensive analysis suite provides the definitive toolkit for understanding LEV methodology performance and its complementary relationship with EPSS and KEV approaches for vulnerability prioritization.** 🎯