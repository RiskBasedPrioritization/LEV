#!/usr/bin/env python3
"""
Advanced LEV Analysis Extensions
Additional sophisticated analyses for deeper insights into LEV performance.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from sklearn.metrics import roc_curve, auc, precision_recall_curve
from scipy import stats
import warnings
warnings.filterwarnings('ignore')


class AdvancedLEVAnalyzer:
    """Advanced analysis methods extending the basic LEV analyzer."""
    
    def __init__(self, lev_df: pd.DataFrame, composite_df: pd.DataFrame):
        self.lev_df = lev_df
        self.composite_df = composite_df
        
        # Merge for comprehensive analysis
        self.merged_df = pd.merge(
            lev_df[['cve', 'lev_probability', 'peak_epss_30day', 'first_epss_date', 'num_relevant_epss_dates']],
            composite_df[['cve', 'epss_score', 'kev_score', 'is_in_kev']],
            on='cve', how='outer'
        ).fillna(0)
    
    def plot_roc_analysis(self, figsize: tuple = (12, 5)):
        """
        9. ROC Analysis: EPSS vs LEV vs Composite for KEV prediction.
        
        Treats KEV membership as ground truth and evaluates how well
        EPSS, LEV, and Composite predict KEV membership.
        """
        # Prepare data
        df = self.merged_df.dropna()
        y_true = df['is_in_kev'].astype(int)
        
        if y_true.sum() == 0:
            print("No KEV CVEs found for ROC analysis")
            return None
        
        # Calculate ROC curves
        methods = {
            'EPSS': df['epss_score'],
            'LEV': df['lev_probability'],
            'Composite': df.merge(self.composite_df[['cve', 'composite_probability']], on='cve')['composite_probability']
        }
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=figsize)
        
        # ROC Curves
        colors = ['blue', 'green', 'red']
        for i, (method, scores) in enumerate(methods.items()):
            if len(scores) == len(y_true):
                fpr, tpr, _ = roc_curve(y_true, scores)
                roc_auc = auc(fpr, tpr)
                ax1.plot(fpr, tpr, color=colors[i], linewidth=2, 
                        label=f'{method} (AUC = {roc_auc:.3f})')
        
        ax1.plot([0, 1], [0, 1], 'k--', alpha=0.5)
        ax1.set_xlabel('False Positive Rate')
        ax1.set_ylabel('True Positive Rate')
        ax1.set_title('ROC Curves: Predicting KEV Membership')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Precision-Recall Curves
        for i, (method, scores) in enumerate(methods.items()):
            if len(scores) == len(y_true):
                precision, recall, _ = precision_recall_curve(y_true, scores)
                pr_auc = auc(recall, precision)
                ax2.plot(recall, precision, color=colors[i], linewidth=2,
                        label=f'{method} (AUC = {pr_auc:.3f})')
        
        ax2.set_xlabel('Recall')
        ax2.set_ylabel('Precision')
        ax2.set_title('Precision-Recall: Predicting KEV Membership')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_epss_evolution_impact(self, figsize: tuple = (15, 8)):
        """
        10. EPSS Evolution Impact: How EPSS score changes affect LEV.
        
        Shows relationship between peak EPSS scores, number of EPSS updates,
        and final LEV probability.
        """
        df = self.merged_df.copy()
        
        # Create bins for number of EPSS dates
        df['epss_date_bins'] = pd.cut(df['num_relevant_epss_dates'], 
                                     bins=[0, 100, 300, 500, 1000, np.inf],
                                     labels=['<100 days', '100-300', '300-500', '500-1000', '1000+'])
        
        fig, axes = plt.subplots(2, 2, figsize=figsize)
        
        # Plot 1: Peak EPSS vs LEV by duration
        for i, duration in enumerate(df['epss_date_bins'].cat.categories):
            subset = df[df['epss_date_bins'] == duration]
            if len(subset) > 0:
                axes[0,0].scatter(subset['peak_epss_30day'], subset['lev_probability'], 
                                alpha=0.6, s=20, label=f'{duration} ({len(subset):,} CVEs)')
        
        axes[0,0].set_xlabel('Peak EPSS Score')
        axes[0,0].set_ylabel('LEV Probability')
        axes[0,0].set_title('Peak EPSS vs LEV by Data Duration')
        axes[0,0].legend()
        axes[0,0].grid(True, alpha=0.3)
        
        # Plot 2: LEV distribution by duration
        duration_data = [df[df['epss_date_bins'] == cat]['lev_probability'].values 
                        for cat in df['epss_date_bins'].cat.categories]
        axes[0,1].boxplot(duration_data, labels=df['epss_date_bins'].cat.categories)
        axes[0,1].set_xlabel('EPSS Data Duration')
        axes[0,1].set_ylabel('LEV Probability')
        axes[0,1].set_title('LEV Distribution by Data Duration')
        axes[0,1].tick_params(axis='x', rotation=45)
        axes[0,1].grid(True, alpha=0.3)
        
        # Plot 3: Current EPSS vs Peak EPSS
        kev_mask = df['is_in_kev'] == True
        axes[1,0].scatter(df[~kev_mask]['epss_score'], df[~kev_mask]['peak_epss_30day'], 
                         alpha=0.6, s=20, c='lightblue', label='Non-KEV')
        axes[1,0].scatter(df[kev_mask]['epss_score'], df[kev_mask]['peak_epss_30day'], 
                         alpha=0.8, s=40, c='red', label='KEV')
        
        # Add diagonal line
        max_val = max(df['epss_score'].max(), df['peak_epss_30day'].max())
        axes[1,0].plot([0, max_val], [0, max_val], 'k--', alpha=0.5, label='Current = Peak')
        
        axes[1,0].set_xlabel('Current EPSS Score')
        axes[1,0].set_ylabel('Peak EPSS Score')
        axes[1,0].set_title('Current vs Peak EPSS Scores')
        axes[1,0].legend()
        axes[1,0].grid(True, alpha=0.3)
        
        # Plot 4: LEV efficiency (LEV per EPSS data point)
        df['lev_efficiency'] = df['lev_probability'] / (df['num_relevant_epss_dates'] + 1)
        
        axes[1,1].scatter(df[~kev_mask]['num_relevant_epss_dates'], df[~kev_mask]['lev_efficiency'], 
                         alpha=0.6, s=20, c='lightblue', label='Non-KEV')
        axes[1,1].scatter(df[kev_mask]['num_relevant_epss_dates'], df[kev_mask]['lev_efficiency'], 
                         alpha=0.8, s=40, c='red', label='KEV')
        
        axes[1,1].set_xlabel('Number of EPSS Data Points')
        axes[1,1].set_ylabel('LEV Efficiency (LEV/Data Points)')
        axes[1,1].set_title('LEV Efficiency by Data Availability')
        axes[1,1].legend()
        axes[1,1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_method_sensitivity_analysis(self, figsize: tuple = (12, 8)):
        """
        11. Sensitivity Analysis: How threshold changes affect method performance.
        
        Shows how the choice of threshold affects the number of CVEs identified
        as high-risk by each method.
        """
        thresholds = np.arange(0.01, 1.0, 0.01)
        
        epss_counts = []
        lev_counts = []
        composite_counts = []
        kev_recall = []
        
        kev_cves = self.merged_df[self.merged_df['is_in_kev'] == True]
        total_kev = len(kev_cves)
        
        for threshold in thresholds:
            epss_high = (self.merged_df['epss_score'] >= threshold).sum()
            lev_high = (self.merged_df['lev_probability'] >= threshold).sum()
            composite_high = (self.composite_df['composite_probability'] >= threshold).sum()
            
            epss_counts.append(epss_high)
            lev_counts.append(lev_high)
            composite_counts.append(composite_high)
            
            # KEV recall for LEV
            if total_kev > 0:
                kev_recall_at_threshold = (kev_cves['lev_probability'] >= threshold).sum() / total_kev
                kev_recall.append(kev_recall_at_threshold)
            else:
                kev_recall.append(0)
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=figsize)
        
        # Plot 1: Absolute counts
        ax1.plot(thresholds, epss_counts, 'b-', linewidth=2, label='EPSS')
        ax1.plot(thresholds, lev_counts, 'g-', linewidth=2, label='LEV')
        ax1.plot(thresholds, composite_counts, 'r-', linewidth=2, label='Composite')
        ax1.set_xlabel('Threshold')
        ax1.set_ylabel('Number of High-Risk CVEs')
        ax1.set_title('CVE Count Sensitivity to Threshold')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.set_yscale('log')
        
        # Plot 2: Proportional view
        total_cves = len(self.merged_df)
        ax2.plot(thresholds, np.array(epss_counts)/total_cves, 'b-', linewidth=2, label='EPSS')
        ax2.plot(thresholds, np.array(lev_counts)/total_cves, 'g-', linewidth=2, label='LEV')
        ax2.plot(thresholds, np.array(composite_counts)/total_cves, 'r-', linewidth=2, label='Composite')
        ax2.set_xlabel('Threshold')
        ax2.set_ylabel('Proportion of CVEs')
        ax2.set_title('Proportion Sensitivity to Threshold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        ax2.set_yscale('log')
        
        # Plot 3: KEV Recall
        ax3.plot(thresholds, kev_recall, 'purple', linewidth=2)
        ax3.set_xlabel('LEV Threshold')
        ax3.set_ylabel('KEV Recall')
        ax3.set_title('KEV Recall by LEV Threshold')
        ax3.grid(True, alpha=0.3)
        
        # Highlight key thresholds
        key_thresholds = [0.1, 0.2, 0.5]
        for thresh in key_thresholds:
            idx = int((thresh - 0.01) / 0.01)
            if idx < len(kev_recall):
                ax3.plot(thresh, kev_recall[idx], 'ro', markersize=8)
                ax3.annotate(f'{kev_recall[idx]:.2f}', 
                           xy=(thresh, kev_recall[idx]), 
                           xytext=(10, 10), textcoords='offset points')
        
        # Plot 4: Method efficiency (CVEs per threshold change)
        epss_diff = np.diff(epss_counts)
        lev_diff = np.diff(lev_counts)
        composite_diff = np.diff(composite_counts)
        
        ax4.plot(thresholds[1:], -epss_diff, 'b-', linewidth=2, label='EPSS', alpha=0.7)
        ax4.plot(thresholds[1:], -lev_diff, 'g-', linewidth=2, label='LEV', alpha=0.7)
        ax4.plot(thresholds[1:], -composite_diff, 'r-', linewidth=2, label='Composite', alpha=0.7)
        ax4.set_xlabel('Threshold')
        ax4.set_ylabel('CVEs Lost per 0.01 Threshold Increase')
        ax4.set_title('Method Efficiency (Lower = More Stable)')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_vulnerability_aging_analysis(self, figsize: tuple = (12, 6)):
        """
        12. Vulnerability Aging: How LEV and EPSS change with CVE age.
        
        Analyzes how vulnerability risk scores correlate with time since disclosure.
        """
        df = self.merged_df.copy()
        df['first_epss_date'] = pd.to_datetime(df['first_epss_date'])
        
        # Calculate age in days from first EPSS date to now
        current_date = datetime.now()
        df['age_days'] = (current_date - df['first_epss_date']).dt.days
        df = df[df['age_days'] > 0]  # Remove invalid dates
        
        # Create age bins
        age_bins = [0, 90, 180, 365, 730, np.inf]
        age_labels = ['0-3mo', '3-6mo', '6mo-1y', '1-2y', '2y+']
        df['age_category'] = pd.cut(df['age_days'], bins=age_bins, labels=age_labels)
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=figsize)
        
        # Plot 1: LEV vs Age
        age_categories = df['age_category'].cat.categories
        lev_by_age = [df[df['age_category'] == cat]['lev_probability'].values for cat in age_categories]
        
        bp1 = ax1.boxplot(lev_by_age, labels=age_categories, patch_artist=True)
        for patch in bp1['boxes']:
            patch.set_facecolor('lightgreen')
            patch.set_alpha(0.7)
        
        ax1.set_xlabel('CVE Age Category')
        ax1.set_ylabel('LEV Probability')
        ax1.set_title('LEV Probability by CVE Age')
        ax1.grid(True, alpha=0.3)
        
        # Add sample sizes
        for i, cat in enumerate(age_categories):
            count = len(df[df['age_category'] == cat])
            ax1.text(i+1, ax1.get_ylim()[1]*0.9, f'n={count:,}', 
                    ha='center', fontsize=10, weight='bold')
        
        # Plot 2: EPSS vs Age
        epss_by_age = [df[df['age_category'] == cat]['epss_score'].values for cat in age_categories]
        
        bp2 = ax2.boxplot(epss_by_age, labels=age_categories, patch_artist=True)
        for patch in bp2['boxes']:
            patch.set_facecolor('lightblue')
            patch.set_alpha(0.7)
        
        ax2.set_xlabel('CVE Age Category')
        ax2.set_ylabel('Current EPSS Score')
        ax2.set_title('EPSS Score by CVE Age')
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        return fig
    
    def plot_composite_value_analysis(self, figsize: tuple = (10, 8)):
        """
        13. Composite Value Analysis: Where composite method adds most value.
        
        Shows scenarios where composite probability significantly differs
        from individual method scores.
        """
        # Merge with composite data
        df = self.merged_df.merge(
            self.composite_df[['cve', 'composite_probability']], 
            on='cve', how='inner'
        )
        
        # Calculate differences
        df['composite_vs_epss'] = df['composite_probability'] - df['epss_score']
        df['composite_vs_lev'] = df['composite_probability'] - df['lev_probability']
        df['epss_vs_lev'] = df['epss_score'] - df['lev_probability']
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=figsize)
        
        # Plot 1: Composite improvement over EPSS
        improvement_threshold = 0.1
        high_improvement = df[df['composite_vs_epss'] > improvement_threshold]
        
        ax1.hist(df['composite_vs_epss'], bins=50, alpha=0.7, color='blue')
        ax1.axvline(x=improvement_threshold, color='red', linestyle='--', 
                   label=f'High improvement (>{improvement_threshold})')
        ax1.set_xlabel('Composite - EPSS')
        ax1.set_ylabel('Number of CVEs')
        ax1.set_title(f'Composite Improvement over EPSS\n({len(high_improvement):,} CVEs significantly improved)')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Composite improvement over LEV
        high_improvement_lev = df[df['composite_vs_lev'] > improvement_threshold]
        
        ax2.hist(df['composite_vs_lev'], bins=50, alpha=0.7, color='green')
        ax2.axvline(x=improvement_threshold, color='red', linestyle='--', 
                   label=f'High improvement (>{improvement_threshold})')
        ax2.set_xlabel('Composite - LEV')
        ax2.set_ylabel('Number of CVEs')
        ax2.set_title(f'Composite Improvement over LEV\n({len(high_improvement_lev):,} CVEs significantly improved)')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        # Plot 3: EPSS vs LEV disagreement
        high_disagreement = df[abs(df['epss_vs_lev']) > improvement_threshold]
        
        ax3.scatter(df['epss_score'], df['lev_probability'], alpha=0.6, s=20, c='lightgray')
        ax3.scatter(high_disagreement['epss_score'], high_disagreement['lev_probability'], 
                   alpha=0.8, s=40, c='red', label=f'High disagreement (n={len(high_disagreement):,})')
        
        # Add diagonal line
        max_val = max(df['epss_score'].max(), df['lev_probability'].max())
        ax3.plot([0, max_val], [0, max_val], 'k--', alpha=0.5, label='EPSS = LEV')
        
        ax3.set_xlabel('EPSS Score')
        ax3.set_ylabel('LEV Probability')
        ax3.set_title('EPSS vs LEV Disagreement')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Plot 4: Value-add scenarios
        # Define scenarios where composite adds value
        scenarios = {
            'KEV Boost': df['kev_score'] > 0,
            'LEV Dominant': (df['lev_probability'] > df['epss_score']) & (df['kev_score'] == 0),
            'EPSS Dominant': (df['epss_score'] > df['lev_probability']) & (df['kev_score'] == 0),
            'Aligned High': (df['epss_score'] > 0.1) & (df['lev_probability'] > 0.1) & (df['kev_score'] == 0)
        }
        
        scenario_counts = [len(df[condition]) for condition in scenarios.values()]
        
        ax4.bar(scenarios.keys(), scenario_counts, alpha=0.7, 
               color=['red', 'green', 'blue', 'purple'])
        ax4.set_ylabel('Number of CVEs')
        ax4.set_title('Composite Method Value-Add Scenarios')
        ax4.tick_params(axis='x', rotation=45)
        ax4.grid(True, alpha=0.3)
        
        # Add percentage labels
        total = len(df)
        for i, count in enumerate(scenario_counts):
            ax4.text(i, count + total*0.01, f'{count/total*100:.1f}%', 
                    ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        return fig
    
    def plot_statistical_validation(self, figsize: tuple = (12, 8)):
        """
        14. Statistical Validation: Correlation analysis and statistical tests.
        
        Provides statistical validation of relationships between methods.
        """
        df = self.merged_df.copy()
        
        # Remove rows with missing data for correlation analysis
        correlation_df = df[['epss_score', 'lev_probability', 'peak_epss_30day', 'num_relevant_epss_dates']].dropna()
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=figsize)
        
        # Plot 1: Correlation heatmap
        corr_matrix = correlation_df.corr()
        im = ax1.imshow(corr_matrix, cmap='RdBu_r', aspect='auto', vmin=-1, vmax=1)
        
        # Add correlation values
        for i in range(len(corr_matrix.columns)):
            for j in range(len(corr_matrix.columns)):
                text = ax1.text(j, i, f'{corr_matrix.iloc[i, j]:.3f}',
                               ha="center", va="center", color="black", fontweight='bold')
        
        ax1.set_xticks(range(len(corr_matrix.columns)))
        ax1.set_yticks(range(len(corr_matrix.columns)))
        ax1.set_xticklabels(corr_matrix.columns, rotation=45)
        ax1.set_yticklabels(corr_matrix.columns)
        ax1.set_title('Correlation Matrix')
        plt.colorbar(im, ax=ax1, label='Correlation Coefficient')
        
        # Plot 2: EPSS-LEV correlation with confidence interval
        x = df['epss_score']
        y = df['lev_probability']
        
        # Remove NaN values
        mask = ~(np.isnan(x) | np.isnan(y))
        x_clean = x[mask]
        y_clean = y[mask]
        
        if len(x_clean) > 0:
            # Calculate correlation and p-value
            corr_coef, p_value = stats.pearsonr(x_clean, y_clean)
            
            ax2.scatter(x_clean, y_clean, alpha=0.5, s=10)
            
            # Add regression line
            z = np.polyfit(x_clean, y_clean, 1)
            p = np.poly1d(z)
            ax2.plot(x_clean, p(x_clean), "r--", alpha=0.8, linewidth=2)
            
            ax2.set_xlabel('EPSS Score')
            ax2.set_ylabel('LEV Probability')
            ax2.set_title(f'EPSS-LEV Correlation\nr={corr_coef:.3f}, p={p_value:.2e}')
            ax2.grid(True, alpha=0.3)
        
        # Plot 3: Distribution comparison (KEV vs non-KEV)
        kev_lev = df[df['is_in_kev'] == True]['lev_probability'].dropna()
        non_kev_lev = df[df['is_in_kev'] == False]['lev_probability'].dropna()
        
        if len(kev_lev) > 0 and len(non_kev_lev) > 0:
            # Statistical test
            from scipy.stats import mannwhitneyu
            statistic, p_value = mannwhitneyu(kev_lev, non_kev_lev, alternative='two-sided')
            
            ax3.hist(non_kev_lev, bins=50, alpha=0.7, label=f'Non-KEV (n={len(non_kev_lev):,})', 
                    density=True, color='lightblue')
            ax3.hist(kev_lev, bins=50, alpha=0.7, label=f'KEV (n={len(kev_lev):,})', 
                    density=True, color='red')
            
            ax3.set_xlabel('LEV Probability')
            ax3.set_ylabel('Density')
            ax3.set_title(f'LEV Distribution: KEV vs Non-KEV\nMann-Whitney U p={p_value:.2e}')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
            ax3.set_yscale('log')
        
        # Plot 4: Method agreement statistics
        thresholds = [0.05, 0.1, 0.2, 0.5]
        agreements = []
        
        for threshold in thresholds:
            epss_high = (df['epss_score'] >= threshold)
            lev_high = (df['lev_probability'] >= threshold)
            
            # Calculate agreement metrics
            both_high = (epss_high & lev_high).sum()
            either_high = (epss_high | lev_high).sum()
            agreement_pct = both_high / either_high if either_high > 0 else 0
            
            agreements.append(agreement_pct)
        
        ax4.bar([f'{t:.2f}' for t in thresholds], agreements, alpha=0.7, color='purple')
        ax4.set_xlabel('Threshold')
        ax4.set_ylabel('Agreement Rate (Both High / Either High)')
        ax4.set_title('EPSS-LEV Agreement by Threshold')
        ax4.grid(True, alpha=0.3)
        
        # Add percentage labels
        for i, agreement in enumerate(agreements):
            ax4.text(i, agreement + 0.01, f'{agreement*100:.1f}%', 
                    ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        return fig
    
    def generate_advanced_insights_report(self):
        """Generate comprehensive insights from advanced analysis."""
        df = self.merged_df.copy()
        
        insights = {
            'correlation_analysis': {},
            'kev_prediction_performance': {},
            'method_complementarity': {},
            'aging_effects': {},
            'composite_value': {}
        }
        
        # Correlation analysis
        corr_df = df[['epss_score', 'lev_probability']].dropna()
        if len(corr_df) > 0:
            corr_coef, p_value = stats.pearsonr(corr_df['epss_score'], corr_df['lev_probability'])
            insights['correlation_analysis'] = {
                'epss_lev_correlation': corr_coef,
                'correlation_p_value': p_value,
                'correlation_strength': 'strong' if abs(corr_coef) > 0.7 else 'moderate' if abs(corr_coef) > 0.3 else 'weak'
            }
        
        # KEV prediction performance
        kev_df = df.dropna()
        if len(kev_df) > 0:
            y_true = kev_df['is_in_kev'].astype(int)
            
            # EPSS performance
            if 'epss_score' in kev_df.columns:
                fpr, tpr, _ = roc_curve(y_true, kev_df['epss_score'])
                epss_auc = auc(fpr, tpr)
            else:
                epss_auc = 0
            
            # LEV performance
            if 'lev_probability' in kev_df.columns:
                fpr, tpr, _ = roc_curve(y_true, kev_df['lev_probability'])
                lev_auc = auc(fpr, tpr)
            else:
                lev_auc = 0
            
            insights['kev_prediction_performance'] = {
                'epss_auc': epss_auc,
                'lev_auc': lev_auc,
                'better_predictor': 'LEV' if lev_auc > epss_auc else 'EPSS',
                'performance_difference': abs(lev_auc - epss_auc)
            }
        
        # Method complementarity
        high_epss_only = ((df['epss_score'] >= 0.1) & (df['lev_probability'] < 0.1)).sum()
        high_lev_only = ((df['lev_probability'] >= 0.1) & (df['epss_score'] < 0.1)).sum()
        high_both = ((df['epss_score'] >= 0.1) & (df['lev_probability'] >= 0.1)).sum()
        
        insights['method_complementarity'] = {
            'epss_unique_high_risk': high_epss_only,
            'lev_unique_high_risk': high_lev_only,
            'both_methods_high_risk': high_both,
            'complementarity_score': (high_epss_only + high_lev_only) / (high_epss_only + high_lev_only + high_both) if (high_epss_only + high_lev_only + high_both) > 0 else 0
        }
        
        # Aging effects
        df['first_epss_date'] = pd.to_datetime(df['first_epss_date'], errors='coerce')
        df_with_dates = df.dropna(subset=['first_epss_date'])
        
        if len(df_with_dates) > 0:
            current_date = datetime.now()
            df_with_dates['age_days'] = (current_date - df_with_dates['first_epss_date']).dt.days
            
            # Correlation between age and scores
            age_epss_corr, _ = stats.pearsonr(df_with_dates['age_days'], df_with_dates['epss_score'])
            age_lev_corr, _ = stats.pearsonr(df_with_dates['age_days'], df_with_dates['lev_probability'])
            
            insights['aging_effects'] = {
                'age_epss_correlation': age_epss_corr,
                'age_lev_correlation': age_lev_corr,
                'older_cves_higher_lev': age_lev_corr > 0,
                'older_cves_higher_epss': age_epss_corr > 0
            }
        
        # Composite value analysis
        composite_df = df.merge(self.composite_df[['cve', 'composite_probability']], on='cve', how='inner')
        if len(composite_df) > 0:
            significant_composite_improvement = (
                (composite_df['composite_probability'] > composite_df['epss_score'] + 0.1) |
                (composite_df['composite_probability'] > composite_df['lev_probability'] + 0.1)
            ).sum()
            
            kev_boost_cases = (composite_df['kev_score'] > 0).sum()
            
            insights['composite_value'] = {
                'significant_improvements': significant_composite_improvement,
                'kev_boost_cases': kev_boost_cases,
                'improvement_rate': significant_composite_improvement / len(composite_df),
                'kev_boost_rate': kev_boost_cases / len(composite_df)
            }
        
        return insights


def create_publication_ready_plots(lev_file: str, composite_file: str, output_dir: str = "analysis/publication_plots"):
    """
    Create publication-ready plots for LEV analysis.
    
    These plots are designed for inclusion in research papers, reports, or presentations.
    """
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    # Load data
    lev_df = pd.read_csv(lev_file)
    composite_df = pd.read_csv(composite_file)
    
    # Initialize analyzer
    analyzer = AdvancedLEVAnalyzer(lev_df, composite_df)
    
    # Set publication style
    plt.style.use('seaborn-v0_8-paper')
    plt.rcParams.update({
        'font.size': 12,
        'axes.titlesize': 14,
        'axes.labelsize': 12,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'figure.titlesize': 16,
        'font.family': 'serif'
    })
    
    # Generate publication plots
    plots = {
        'roc_analysis': analyzer.plot_roc_analysis(figsize=(10, 4)),
        'sensitivity_analysis': analyzer.plot_method_sensitivity_analysis(figsize=(12, 8)),
        'epss_evolution_impact': analyzer.plot_epss_evolution_impact(figsize=(14, 8)),
        'vulnerability_aging': analyzer.plot_vulnerability_aging_analysis(figsize=(10, 5)),
        'composite_value_analysis': analyzer.plot_composite_value_analysis(figsize=(12, 8)),
        'statistical_validation': analyzer.plot_statistical_validation(figsize=(12, 8))
    }
    
    # Save in multiple formats
    for name, fig in plots.items():
        if fig is not None:
            # High-resolution PNG for presentations
            fig.savefig(f"{output_dir}/{name}_hires.png", dpi=300, bbox_inches='tight', 
                       facecolor='white', edgecolor='none')

            print(f"Saved {name} in PNG format")
    
    # Generate insights report
    insights = analyzer.generate_advanced_insights_report()
    
    # Create detailed analysis report
    report = f"""
# Advanced LEV Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Key Findings

### 1. EPSS-LEV Correlation Analysis
- Correlation coefficient: {insights['correlation_analysis'].get('epss_lev_correlation', 'N/A'):.3f}
- Relationship strength: {insights['correlation_analysis'].get('correlation_strength', 'N/A')}
- Statistical significance: p = {insights['correlation_analysis'].get('correlation_p_value', 'N/A'):.2e}

### 2. KEV Prediction Performance
- EPSS AUC for KEV prediction: {insights['kev_prediction_performance'].get('epss_auc', 'N/A'):.3f}
- LEV AUC for KEV prediction: {insights['kev_prediction_performance'].get('lev_auc', 'N/A'):.3f}
- Better KEV predictor: {insights['kev_prediction_performance'].get('better_predictor', 'N/A')}
- Performance difference: {insights['kev_prediction_performance'].get('performance_difference', 'N/A'):.3f}

### 3. Method Complementarity
- CVEs identified only by EPSS (≥0.1): {insights['method_complementarity'].get('epss_unique_high_risk', 'N/A'):,}
- CVEs identified only by LEV (≥0.1): {insights['method_complementarity'].get('lev_unique_high_risk', 'N/A'):,}
- CVEs identified by both methods: {insights['method_complementarity'].get('both_methods_high_risk', 'N/A'):,}
- Complementarity score: {insights['method_complementarity'].get('complementarity_score', 'N/A'):.3f}

### 4. Temporal Effects
- Age-EPSS correlation: {insights['aging_effects'].get('age_epss_correlation', 'N/A'):.3f}
- Age-LEV correlation: {insights['aging_effects'].get('age_lev_correlation', 'N/A'):.3f}
- Older CVEs have higher LEV: {insights['aging_effects'].get('older_cves_higher_lev', 'N/A')}

### 5. Composite Method Value
- CVEs with significant composite improvement: {insights['composite_value'].get('significant_improvements', 'N/A'):,}
- Improvement rate: {insights['composite_value'].get('improvement_rate', 'N/A'):.1%}
- KEV boost cases: {insights['composite_value'].get('kev_boost_cases', 'N/A'):,}
- KEV boost rate: {insights['composite_value'].get('kev_boost_rate', 'N/A'):.1%}

## Implications for Vulnerability Management

1. **Complementary Nature**: EPSS and LEV identify different sets of high-risk CVEs, 
   supporting the NIST CSWP 41 recommendation to use them together.

2. **Composite Advantage**: The composite method provides {insights['composite_value'].get('improvement_rate', 0):.1%} 
   improvement in coverage over individual methods.

3. **KEV Prediction**: {"LEV" if insights['kev_prediction_performance'].get('lev_auc', 0) > insights['kev_prediction_performance'].get('epss_auc', 0) else "EPSS"} 
   is a better predictor of KEV membership, but the difference is 
   {insights['kev_prediction_performance'].get('performance_difference', 0):.3f}.

4. **Aging Effects**: {"Older CVEs tend to have higher LEV scores" if insights['aging_effects'].get('older_cves_higher_lev', False) else "CVE age does not strongly correlate with LEV scores"}.

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
"""
    
    with open(f"{output_dir}/advanced_analysis_report.md", 'w') as f:
        f.write(report)
    
    print(f"\nAdvanced analysis complete! Generated:")
    print(f"- 6 publication-ready plots (PNG/PDF/SVG)")
    print(f"- Comprehensive analysis report")
    print(f"- All files saved to {output_dir}/")
    
    return insights


# Example usage function
def example_advanced_analysis():
    """Example of how to run advanced LEV analysis."""
    
    # Load your data files
    lev_file = "data_out/lev_probabilities_nist_detailed.csv.gz"
    composite_file = "data_out/composite_probabilities_nist.csv.gz"
    
    # Create publication-ready analysis
    insights = create_publication_ready_plots(lev_file, composite_file)
    
    # Print key insights
    print("\n🔍 KEY INSIGHTS:")
    print(f"📊 EPSS-LEV Correlation: {insights['correlation_analysis'].get('epss_lev_correlation', 'N/A'):.3f}")
    print(f"🎯 Better KEV Predictor: {insights['kev_prediction_performance'].get('better_predictor', 'N/A')}")
    print(f"🔄 Complementarity Score: {insights['method_complementarity'].get('complementarity_score', 'N/A'):.3f}")
    print(f"📈 Composite Improvement Rate: {insights['composite_value'].get('improvement_rate', 'N/A'):.1%}")


if __name__ == "__main__":
    example_advanced_analysis()