#!/usr/bin/env python3
"""
LEV Analysis and Visualization Suite
Comprehensive plots and analysis for understanding LEV performance relative to EPSS and KEV.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

# Set style for publication-quality plots
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette("husl")


class LEVAnalyzer:
    """Comprehensive analysis and visualization suite for LEV results."""
    
    def __init__(self, lev_file: str, composite_file: str):
        """
        Initialize analyzer with LEV and composite results.
        
        Args:
            lev_file: Path to LEV results CSV
            composite_file: Path to composite results CSV
        """
        self.lev_df = pd.read_csv(lev_file)
        self.composite_df = pd.read_csv(composite_file)
        
        # Merge datasets for comprehensive analysis
        self.merged_df = pd.merge(
            self.lev_df[['cve', 'lev_probability', 'peak_epss_30day', 'first_epss_date']],
            self.composite_df[['cve', 'epss_score', 'kev_score', 'is_in_kev']],
            on='cve',
            how='outer'
        ).fillna(0)
        
        print(f"Loaded {len(self.lev_df):,} LEV results and {len(self.composite_df):,} composite results")
        print(f"Merged dataset: {len(self.merged_df):,} total CVEs")
        print(f"KEV CVEs: {self.merged_df['is_in_kev'].sum():,}")
    
    def plot_epss_vs_lev_scatter(self, sample_size: int = 10000, figsize: tuple = (12, 8)):
        """
        1. EPSS vs LEV scatter plot with KEV highlighting.
        
        Shows the relationship between current EPSS scores and LEV probabilities,
        with KEV CVEs highlighted in red.
        """
        # Sample for visualization performance
        if len(self.merged_df) > sample_size:
            plot_df = self.merged_df.sample(n=sample_size, random_state=42)
        else:
            plot_df = self.merged_df.copy()
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Plot non-KEV CVEs
        non_kev = plot_df[plot_df['is_in_kev'] == False]
        kev = plot_df[plot_df['is_in_kev'] == True]
        
        # Scatter plot
        ax.scatter(non_kev['epss_score'], non_kev['lev_probability'], 
                  alpha=0.6, s=20, c='lightblue', label=f'Non-KEV CVEs (n={len(non_kev):,})')
        
        ax.scatter(kev['epss_score'], kev['lev_probability'], 
                  alpha=0.8, s=40, c='red', label=f'KEV CVEs (n={len(kev):,})')
        
        # Add diagonal line (EPSS = LEV)
        max_val = max(plot_df['epss_score'].max(), plot_df['lev_probability'].max())
        ax.plot([0, max_val], [0, max_val], 'k--', alpha=0.5, label='EPSS = LEV')
        
        ax.set_xlabel('Current EPSS Score')
        ax.set_ylabel('LEV Probability')
        ax.set_title('EPSS vs LEV: Current Scores vs Historical Exploitation Likelihood')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        # Add quadrant labels
        ax.text(0.05, 0.95, 'High LEV\nLow EPSS', transform=ax.transAxes, 
                bbox=dict(boxstyle="round,pad=0.3", facecolor="yellow", alpha=0.5))
        ax.text(0.95, 0.05, 'Low LEV\nHigh EPSS', transform=ax.transAxes, ha='right',
                bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgreen", alpha=0.5))
        
        plt.tight_layout()
        return fig
    
    def plot_lev_recall_curve(self, figsize: tuple = (10, 6)):
        """
        2. LEV Recall of KEV Lists (from NIST CSWP 41 Figure 4).
        
        Shows how well LEV lists cover KEV entries at different probability thresholds.
        """
        kev_cves = self.merged_df[self.merged_df['is_in_kev'] == True]
        total_kev = len(kev_cves)
        
        if total_kev == 0:
            print("No KEV CVEs found in dataset")
            return None
        
        # Generate thresholds
        thresholds = np.arange(0.0, 1.01, 0.01)
        recall_values = []
        
        for threshold in thresholds:
            high_lev_kev = len(kev_cves[kev_cves['lev_probability'] >= threshold])
            recall = high_lev_kev / total_kev if total_kev > 0 else 0
            recall_values.append(recall)
        
        fig, ax = plt.subplots(figsize=figsize)
        ax.plot(thresholds, recall_values, 'b-', linewidth=2, label='LEV Recall of KEV')
        
        # Highlight key points
        for thresh in [0.1, 0.2, 0.5, 0.8]:
            idx = int(thresh * 100)
            if idx < len(recall_values):
                ax.plot(thresh, recall_values[idx], 'ro', markersize=8)
                ax.annotate(f'{recall_values[idx]:.2f}', 
                           xy=(thresh, recall_values[idx]), 
                           xytext=(10, 10), textcoords='offset points')
        
        ax.set_xlabel('Minimum LEV Probability (Threshold)')
        ax.set_ylabel('Recall (Coverage of KEV List)')
        ax.set_title('LEV Recall of KEV Lists\n(Higher = Better KEV Coverage)')
        ax.grid(True, alpha=0.3)
        ax.legend()
        
        # Add annotation
        ax.text(0.5, 0.2, f'Total KEV CVEs: {total_kev:,}', 
                transform=ax.transAxes, fontsize=12,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="lightblue", alpha=0.7))
        
        plt.tight_layout()
        return fig
    
    def plot_probability_distributions(self, figsize: tuple = (15, 5)):
        """
        3. Distribution comparison: EPSS vs LEV vs Composite.
        
        Shows how the three probability measures are distributed.
        """
        fig, axes = plt.subplots(1, 3, figsize=figsize)
        
        # EPSS distribution
        axes[0].hist(self.merged_df['epss_score'], bins=50, alpha=0.7, color='blue', density=True)
        axes[0].set_xlabel('EPSS Score')
        axes[0].set_ylabel('Density')
        axes[0].set_title('EPSS Score Distribution')
        axes[0].set_yscale('log')
        
        # LEV distribution
        axes[1].hist(self.merged_df['lev_probability'], bins=50, alpha=0.7, color='green', density=True)
        axes[1].set_xlabel('LEV Probability')
        axes[1].set_ylabel('Density')
        axes[1].set_title('LEV Probability Distribution')
        axes[1].set_yscale('log')
        
        # Composite distribution
        composite_probs = self.composite_df['composite_probability']
        axes[2].hist(composite_probs, bins=50, alpha=0.7, color='red', density=True)
        axes[2].set_xlabel('Composite Probability')
        axes[2].set_ylabel('Density')
        axes[2].set_title('Composite Probability Distribution')
        axes[2].set_yscale('log')
        
        plt.tight_layout()
        return fig
    
    def plot_method_agreement_matrix(self, figsize: tuple = (10, 8)):
        """
        4. Agreement matrix: Which method identifies high-risk CVEs?
        
        Shows overlap between EPSS, LEV, and KEV in identifying high-risk CVEs.
        """
        # Define thresholds
        epss_threshold = 0.1
        lev_threshold = 0.1
        
        # Create binary classifications
        df = self.merged_df.copy()
        df['high_epss'] = df['epss_score'] >= epss_threshold
        df['high_lev'] = df['lev_probability'] >= lev_threshold
        df['in_kev'] = df['is_in_kev'] == True
        
        # Create confusion matrix data
        methods = ['High EPSS', 'High LEV', 'In KEV']
        agreement_matrix = np.zeros((3, 3))
        
        # Calculate pairwise agreements
        for i, method1 in enumerate(['high_epss', 'high_lev', 'in_kev']):
            for j, method2 in enumerate(['high_epss', 'high_lev', 'in_kev']):
                if i == j:
                    agreement_matrix[i, j] = df[method1].sum()
                else:
                    agreement_matrix[i, j] = (df[method1] & df[method2]).sum()
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Create heatmap
        im = ax.imshow(agreement_matrix, cmap='Blues')
        
        # Add text annotations
        for i in range(len(methods)):
            for j in range(len(methods)):
                text = ax.text(j, i, f'{int(agreement_matrix[i, j]):,}',
                             ha="center", va="center", color="black", fontweight='bold')
        
        ax.set_xticks(range(len(methods)))
        ax.set_yticks(range(len(methods)))
        ax.set_xticklabels(methods)
        ax.set_yticklabels(methods)
        ax.set_title(f'Method Agreement Matrix\n(Thresholds: EPSS≥{epss_threshold}, LEV≥{lev_threshold})')
        
        # Add colorbar
        plt.colorbar(im, ax=ax, label='Number of CVEs')
        plt.tight_layout()
        return fig
    
    def plot_temporal_evolution(self, sample_cves: int = 100, figsize: tuple = (12, 8)):
        """
        5. Temporal evolution: How LEV and peak EPSS relate over time.
        
        Shows relationship between when CVEs first appeared and their risk scores.
        """
        # Convert first_epss_date to datetime
        df = self.merged_df.copy()
        df['first_epss_date'] = pd.to_datetime(df['first_epss_date'])
        df = df.dropna(subset=['first_epss_date'])
        
        if len(df) == 0:
            print("No valid first_epss_date data found")
            return None
        
        # Sample for performance
        if len(df) > sample_cves:
            df = df.sample(n=sample_cves, random_state=42)
        
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, sharex=True)
        
        # Plot 1: LEV probability over time
        kev_df = df[df['is_in_kev'] == True]
        non_kev_df = df[df['is_in_kev'] == False]
        
        ax1.scatter(non_kev_df['first_epss_date'], non_kev_df['lev_probability'], 
                   alpha=0.6, s=20, c='lightblue', label='Non-KEV CVEs')
        ax1.scatter(kev_df['first_epss_date'], kev_df['lev_probability'], 
                   alpha=0.8, s=40, c='red', label='KEV CVEs')
        
        ax1.set_ylabel('LEV Probability')
        ax1.set_title('Temporal Evolution of Vulnerability Risk Scores')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Peak EPSS over time
        ax2.scatter(non_kev_df['first_epss_date'], non_kev_df['peak_epss_30day'], 
                   alpha=0.6, s=20, c='lightgreen', label='Non-KEV CVEs')
        ax2.scatter(kev_df['first_epss_date'], kev_df['peak_epss_30day'], 
                   alpha=0.8, s=40, c='red', label='KEV CVEs')
        
        ax2.set_xlabel('First EPSS Date')
        ax2.set_ylabel('Peak EPSS Score')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_composite_effectiveness(self, figsize: tuple = (12, 6)):
        """
        6. Composite method effectiveness: Coverage vs individual methods.
        
        Shows how the composite method improves coverage compared to individual methods.
        """
        thresholds = np.arange(0.0, 1.01, 0.05)
        
        epss_coverage = []
        lev_coverage = []
        composite_coverage = []
        kev_coverage = []
        
        total_cves = len(self.merged_df)
        
        for threshold in thresholds:
            epss_high = (self.merged_df['epss_score'] >= threshold).sum()
            lev_high = (self.merged_df['lev_probability'] >= threshold).sum()
            composite_high = (self.composite_df['composite_probability'] >= threshold).sum()
            
            epss_coverage.append(epss_high / total_cves)
            lev_coverage.append(lev_high / total_cves)
            composite_coverage.append(composite_high / total_cves)
        
        # KEV coverage (constant)
        kev_count = self.merged_df['is_in_kev'].sum()
        kev_coverage = [kev_count / total_cves] * len(thresholds)
        
        fig, ax = plt.subplots(figsize=figsize)
        
        ax.plot(thresholds, epss_coverage, 'b-', linewidth=2, label='EPSS Only')
        ax.plot(thresholds, lev_coverage, 'g-', linewidth=2, label='LEV Only')
        ax.plot(thresholds, composite_coverage, 'r-', linewidth=3, label='Composite (EPSS+LEV+KEV)')
        ax.plot(thresholds, kev_coverage, 'k--', linewidth=2, label='KEV List')
        
        ax.set_xlabel('Probability Threshold')
        ax.set_ylabel('Proportion of CVEs Above Threshold')
        ax.set_title('Method Coverage Comparison\n(Higher = More CVEs Identified as High-Risk)')
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_yscale('log')
        
        plt.tight_layout()
        return fig
    
    def plot_risk_quadrants(self, figsize: tuple = (10, 8)):
        """
        7. Risk quadrant analysis: EPSS vs LEV with actionable insights.
        
        Divides CVEs into four quadrants based on EPSS and LEV scores.
        """
        # Define quadrant thresholds
        epss_threshold = 0.1
        lev_threshold = 0.1
        
        df = self.merged_df.copy()
        
        # Create quadrants
        df['quadrant'] = 'Low Risk'
        df.loc[(df['epss_score'] >= epss_threshold) & (df['lev_probability'] < lev_threshold), 'quadrant'] = 'High EPSS, Low LEV'
        df.loc[(df['epss_score'] < epss_threshold) & (df['lev_probability'] >= lev_threshold), 'quadrant'] = 'Low EPSS, High LEV'
        df.loc[(df['epss_score'] >= epss_threshold) & (df['lev_probability'] >= lev_threshold), 'quadrant'] = 'High Risk'
        
        fig, ax = plt.subplots(figsize=figsize)
        
        # Color by quadrant
        colors = {'Low Risk': 'lightblue', 'High EPSS, Low LEV': 'orange', 
                 'Low EPSS, High LEV': 'yellow', 'High Risk': 'red'}
        
        for quadrant, color in colors.items():
            quad_data = df[df['quadrant'] == quadrant]
            kev_data = quad_data[quad_data['is_in_kev'] == True]
            non_kev_data = quad_data[quad_data['is_in_kev'] == False]
            
            # Plot non-KEV CVEs
            if len(non_kev_data) > 0:
                ax.scatter(non_kev_data['epss_score'], non_kev_data['lev_probability'], 
                          c=color, alpha=0.6, s=20, label=f'{quadrant} (n={len(quad_data):,})')
            
            # Plot KEV CVEs with black border
            if len(kev_data) > 0:
                ax.scatter(kev_data['epss_score'], kev_data['lev_probability'], 
                          c=color, alpha=0.8, s=40, edgecolors='black', linewidth=1)
        
        # Add threshold lines
        ax.axhline(y=lev_threshold, color='gray', linestyle='--', alpha=0.7)
        ax.axvline(x=epss_threshold, color='gray', linestyle='--', alpha=0.7)
        
        # Add quadrant labels
        ax.text(0.05, 0.95, 'Potentially\nUnderscored by EPSS', transform=ax.transAxes, 
                bbox=dict(boxstyle="round,pad=0.3", facecolor="yellow", alpha=0.7))
        ax.text(0.95, 0.05, 'Future Risk\n(Not Yet Exploited)', transform=ax.transAxes, ha='right',
                bbox=dict(boxstyle="round,pad=0.3", facecolor="orange", alpha=0.7))
        ax.text(0.95, 0.95, 'Critical Priority\n(High Current & Historical)', transform=ax.transAxes, ha='right',
                bbox=dict(boxstyle="round,pad=0.3", facecolor="red", alpha=0.7))
        
        ax.set_xlabel('Current EPSS Score')
        ax.set_ylabel('LEV Probability (Historical Exploitation)')
        ax.set_title('Risk Quadrant Analysis\n(Black borders = KEV CVEs)')
        ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def generate_summary_statistics(self):
        """
        8. Generate comprehensive summary statistics.
        
        Returns key metrics for understanding the dataset and method performance.
        """
        stats = {}
        
        # Basic dataset stats
        stats['dataset'] = {
            'total_cves': len(self.merged_df),
            'kev_cves': self.merged_df['is_in_kev'].sum(),
            'kev_percentage': self.merged_df['is_in_kev'].mean() * 100
        }
        
        # Score distributions
        stats['distributions'] = {
            'epss_mean': self.merged_df['epss_score'].mean(),
            'epss_median': self.merged_df['epss_score'].median(),
            'lev_mean': self.merged_df['lev_probability'].mean(),
            'lev_median': self.merged_df['lev_probability'].median(),
            'composite_mean': self.composite_df['composite_probability'].mean(),
            'composite_median': self.composite_df['composite_probability'].median()
        }
        
        # High-risk CVE counts
        thresholds = [0.1, 0.2, 0.5, 0.8]
        stats['high_risk_counts'] = {}
        
        for threshold in thresholds:
            stats['high_risk_counts'][f'epss_{threshold}'] = (self.merged_df['epss_score'] >= threshold).sum()
            stats['high_risk_counts'][f'lev_{threshold}'] = (self.merged_df['lev_probability'] >= threshold).sum()
            stats['high_risk_counts'][f'composite_{threshold}'] = (self.composite_df['composite_probability'] >= threshold).sum()
        
        # KEV recall at different thresholds
        kev_cves = self.merged_df[self.merged_df['is_in_kev'] == True]
        stats['kev_recall'] = {}
        
        if len(kev_cves) > 0:
            for threshold in thresholds:
                lev_recall = (kev_cves['lev_probability'] >= threshold).sum() / len(kev_cves)
                stats['kev_recall'][f'lev_{threshold}'] = lev_recall
        
        # Method agreement
        stats['agreement'] = {
            'epss_lev_correlation': self.merged_df[['epss_score', 'lev_probability']].corr().iloc[0, 1],
            'high_epss_and_high_lev': ((self.merged_df['epss_score'] >= 0.1) & 
                                      (self.merged_df['lev_probability'] >= 0.1)).sum(),
            'high_epss_or_high_lev': ((self.merged_df['epss_score'] >= 0.1) | 
                                     (self.merged_df['lev_probability'] >= 0.1)).sum()
        }
        
        return stats
    
    def create_comprehensive_report(self, output_dir: str = "analysis/lev_analysis_plots"):
        """
        Generate all plots and save comprehensive analysis report.
        """
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        print("Generating LEV Analysis Report...")
        
        # Generate all plots
        plots = {
            'epss_vs_lev_scatter': self.plot_epss_vs_lev_scatter(),
            'lev_recall_curve': self.plot_lev_recall_curve(),
            'probability_distributions': self.plot_probability_distributions(),
            'method_agreement_matrix': self.plot_method_agreement_matrix(),
            'temporal_evolution': self.plot_temporal_evolution(),
            'composite_effectiveness': self.plot_composite_effectiveness(),
            'risk_quadrants': self.plot_risk_quadrants()
        }
        
        # Save all plots
        for name, fig in plots.items():
            if fig is not None:
                fig.savefig(f"{output_dir}/{name}.png", dpi=300, bbox_inches='tight')
                print(f"Saved {name}")
        
        # Generate and save summary statistics
        stats = self.generate_summary_statistics()
        
        # Create summary report
        report = f"""
# LEV Analysis Summary Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Dataset Overview
- Total CVEs: {stats['dataset']['total_cves']:,}
- KEV CVEs: {stats['dataset']['kev_cves']:,} ({stats['dataset']['kev_percentage']:.2f}%)

## Score Distributions
- EPSS: Mean={stats['distributions']['epss_mean']:.4f}, Median={stats['distributions']['epss_median']:.4f}
- LEV: Mean={stats['distributions']['lev_mean']:.4f}, Median={stats['distributions']['lev_median']:.4f}
- Composite: Mean={stats['distributions']['composite_mean']:.4f}, Median={stats['distributions']['composite_median']:.4f}

## High-Risk CVE Counts by Threshold
"""
        
        for threshold in [0.1, 0.2, 0.5, 0.8]:
            epss_count = stats['high_risk_counts'][f'epss_{threshold}']
            lev_count = stats['high_risk_counts'][f'lev_{threshold}']
            composite_count = stats['high_risk_counts'][f'composite_{threshold}']
            
            report += f"""
### Threshold ≥ {threshold}
- EPSS: {epss_count:,} CVEs
- LEV: {lev_count:,} CVEs  
- Composite: {composite_count:,} CVEs
"""
        
        if 'kev_recall' in stats:
            report += "\n## KEV Recall by LEV Thresholds\n"
            for threshold in [0.1, 0.2, 0.5, 0.8]:
                if f'lev_{threshold}' in stats['kev_recall']:
                    recall = stats['kev_recall'][f'lev_{threshold}']
                    report += f"- LEV ≥ {threshold}: {recall:.3f} ({recall*100:.1f}% of KEV CVEs)\n"
        
        report += f"""
## Method Agreement
- EPSS-LEV Correlation: {stats['agreement']['epss_lev_correlation']:.3f}
- High EPSS AND High LEV: {stats['agreement']['high_epss_and_high_lev']:,} CVEs
- High EPSS OR High LEV: {stats['agreement']['high_epss_or_high_lev']:,} CVEs

## Key Insights
1. **LEV Complements EPSS**: LEV identifies {stats['high_risk_counts']['lev_0.1']:,} high-risk CVEs vs {stats['high_risk_counts']['epss_0.1']:,} by EPSS
2. **Composite Method**: Identifies {stats['high_risk_counts']['composite_0.1']:,} total high-risk CVEs (union of all methods)
3. **KEV Coverage**: LEV provides {stats['kev_recall'].get('lev_0.1', 0)*100:.1f}% recall of KEV list at 0.1 threshold
"""
        
        with open(f"{output_dir}/analysis_report.md", 'w') as f:
            f.write(report)
        
        print(f"\nComprehensive analysis saved to {output_dir}/")
        print("Generated files:")
        print("- 7 visualization plots (PNG + PDF)")
        print("- analysis_report.md (summary statistics)")
        
        return stats


def example_usage():
    """Example of how to use the LEV analyzer."""
    # Initialize analyzer with your data files
    analyzer = LEVAnalyzer(
        lev_file="data_out/lev_probabilities_nist_detailed.csv.gz",
        composite_file="data_out/composite_probabilities_nist.csv.gz"
    )
    
    # Generate individual plots
    fig1 = analyzer.plot_epss_vs_lev_scatter()
    fig2 = analyzer.plot_lev_recall_curve()
    fig3 = analyzer.plot_risk_quadrants()
    
    # Or generate comprehensive report
    stats = analyzer.create_comprehensive_report()
    
    plt.show()


if __name__ == "__main__":
    example_usage()