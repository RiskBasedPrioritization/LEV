import pandas as pd
import numpy as np
import requests
import gzip
import io
import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp
from functools import partial


output_dir = "./data_out"


def setup_logging():
    """Set up logging to both file and console."""
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    # Create timestamp for log filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"logs/{timestamp}.log"
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename, encoding='utf-8'),
            logging.StreamHandler()  # Also log to console
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized. Log file: {log_filename}")
    return logger


class OptimizedLEVCalculator:
    """
    Optimized implementation of the Likely Exploited Vulnerabilities (LEV) metric
    as described in NIST CSWP 41, with rigorous probabilistic calculations.
    """
    
    def __init__(self, cache_dir: str = "data_in", max_workers: int = None, logger: logging.Logger = None):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.epss_data = {}  # {date: {cve: epss_score}}
        self.max_workers = max_workers or min(8, mp.cpu_count())
        self.logger = logger or logging.getLogger(__name__)
        
        # Pre-compute common values for rigorous calculation
        self._daily_prob_cache = {}  # Cache for daily probability calculations
        
    def _precompute_daily_probabilities(self, epss_scores: np.ndarray, window_size: int = 30) -> np.ndarray:
        """Vectorized computation of daily probabilities from 30-day EPSS scores."""
        # Handle edge cases
        epss_scores = np.clip(epss_scores, 0.0, 1.0)
        
        # Initialize output array
        daily_probs = np.zeros_like(epss_scores)
        
        # Handle zero scores (daily prob = 0)
        mask_zero = epss_scores == 0.0
        daily_probs[mask_zero] = 0.0
        
        # Handle perfect scores (daily prob = 1)
        mask_one = epss_scores == 1.0
        daily_probs[mask_one] = 1.0
        
        # Handle normal cases
        mask_normal = ~(mask_zero | mask_one)
        
        if np.any(mask_normal):
            normal_scores = epss_scores[mask_normal]
            
            # For the rigorous formula: P1 = 1 - (1 - P30)^(1/30)
            complement = 1.0 - normal_scores
            
            # Handle very small complements that could cause numerical issues
            min_complement = np.finfo(float).eps * 10
            complement = np.maximum(complement, min_complement)
            
            # Calculate daily probability
            try:
                daily_probs[mask_normal] = 1.0 - np.power(complement, 1.0/window_size)
            except (OverflowError, FloatingPointError) as e:
                # Fallback for numerical issues
                self.logger.warning(f"Numerical issue in daily probability calculation: {e}. Using fallback approximation.")
                daily_probs[mask_normal] = normal_scores / window_size
        
        # Ensure all results are valid probabilities
        daily_probs = np.clip(daily_probs, 0.0, 1.0)
        
        return daily_probs

    def download_epss_data(self, start_date: datetime, end_date: datetime):
        """Download EPSS data for the specified date range with parallel processing."""
        self.logger.info(f"Loading EPSS scores from {start_date.date()} to {end_date.date()}...")
        
        # Generate list of dates to process
        dates_to_process = []
        current_date = start_date
        while current_date <= end_date:
            dates_to_process.append(current_date)
            current_date += timedelta(days=1)
        
        self.logger.info(f"Total dates to process: {len(dates_to_process)}")
        
        # Track download statistics
        download_stats = {
            'attempted': 0,
            'successful': 0,
            'from_cache': 0,
            'downloaded': 0,
            'failed': 0,
            'failed_dates': []
        }
        
        # Use ThreadPoolExecutor for I/O bound operations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_date = {
                executor.submit(self._download_single_date, date): date 
                for date in dates_to_process
            }
            
            loaded_count = 0
            total_days = len(dates_to_process)
            
            for future in as_completed(future_to_date):
                date = future_to_date[future]
                download_stats['attempted'] += 1
                
                try:
                    result = future.result()
                    if result is not None:
                        data, was_cached = result
                        self.epss_data[date] = data
                        loaded_count += 1
                        download_stats['successful'] += 1
                        
                        if was_cached:
                            download_stats['from_cache'] += 1
                        else:
                            download_stats['downloaded'] += 1
                    else:
                        download_stats['failed'] += 1
                        download_stats['failed_dates'].append(date.strftime('%Y-%m-%d'))
                    
                    # Progress indicator
                    progress = download_stats['attempted'] / total_days * 100
                    if download_stats['attempted'] % 50 == 0:  # Update every 50 files
                        self.logger.info(f"[LOAD] {progress:.1f}% - Processed {download_stats['attempted']}/{total_days} files "
                                       f"(Success: {download_stats['successful']}, Failed: {download_stats['failed']})")
                        
                except Exception as e:
                    download_stats['failed'] += 1
                    download_stats['failed_dates'].append(date.strftime('%Y-%m-%d'))
                    self.logger.error(f"Failed to process {date.strftime('%Y-%m-%d')}: {e}")
        
        # Log final download statistics
        self.logger.info(f"Download completed. Statistics:")
        self.logger.info(f"  Total attempted: {download_stats['attempted']}")
        self.logger.info(f"  Successful: {download_stats['successful']}")
        self.logger.info(f"  From cache: {download_stats['from_cache']}")
        self.logger.info(f"  Downloaded: {download_stats['downloaded']}")
        self.logger.info(f"  Failed: {download_stats['failed']}")
        
        if download_stats['failed_dates']:
            self.logger.warning(f"Failed dates: {', '.join(download_stats['failed_dates'][:10])}")
            if len(download_stats['failed_dates']) > 10:
                self.logger.warning(f"... and {len(download_stats['failed_dates']) - 10} more")
        
        self.logger.info(f"Loaded {loaded_count} files covering {len(self.epss_data)} dates")
        
        # Print memory usage info
        total_records = sum(len(date_data) for date_data in self.epss_data.values())
        self.logger.info(f"Total EPSS records in memory: {total_records:,}")
    
    # NIST.CSWP.41.pdf 10.3. EPSS Download and Data:
    # "EPSS publishes the EPSS scores for all CVEs as zipped CSV files. There is one file per day, and
    # unfortunately there are a few missing days. The LEV code uses the EPSS scores from the next
    # available day when a day is missing."
    def _download_single_date(self, date: datetime) -> Optional[Tuple[Dict[str, float], bool]]:
        """Download EPSS data for a single date. Returns (data, was_cached) or None."""
        date_str = date.strftime("%Y-%m-%d")
        filename = f"epss_scores-{date_str}.csv.gz"
        cache_path = os.path.join(self.cache_dir, filename)
        
        try:
            if os.path.exists(cache_path):
                # Load from existing file
                with gzip.open(cache_path, 'rt') as f:
                    df = pd.read_csv(f, comment='#', usecols=["cve", "epss"])
                return dict(zip(df['cve'], df['epss'])), True
            else:
                # Download from remote if file doesn't exist
                url = f"https://epss.empiricalsecurity.com/{filename}"
                self.logger.debug(f"Downloading {url}")
                
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                # Save to cache
                with open(cache_path, 'wb') as f_out:
                    f_out.write(response.content)
                
                # Read the data
                with gzip.open(io.BytesIO(response.content), 'rt') as f:
                    df = pd.read_csv(f, comment='#', usecols=["cve", "epss"])
                
                time.sleep(0.1)  # Be nice to the server
                return dict(zip(df['cve'], df['epss'])), False
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error downloading {date_str}: {e}")
            return None
        except pd.errors.EmptyDataError as e:
            self.logger.error(f"Empty data file for {date_str}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error processing {date_str}: {e}")
            return None
    
    def get_loaded_date_range(self) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Get the date range of loaded data."""
        if not self.epss_data:
            return None, None
        dates = list(self.epss_data.keys())
        return min(dates), max(dates)
    
    def get_first_epss_date(self, cve: str) -> Optional[datetime]:
        """Find the first date when a CVE received an EPSS score (d0)."""
        for date in sorted(self.epss_data.keys()):
            if cve in self.epss_data[date]:
                return date
        return None
    
    def get_epss_score(self, cve: str, date: datetime) -> float:
        """Get EPSS score for a CVE on a specific date."""
        if date in self.epss_data and cve in self.epss_data[date]:
            return self.epss_data[date][cve]
        
        # If exact date not available, find the closest previous date
        available_dates = [d for d in sorted(self.epss_data.keys()) if d <= date]
        if available_dates:
            closest_date = available_dates[-1]
            if cve in self.epss_data[closest_date]:
                return self.epss_data[closest_date][cve]
        
        return 0.0  # Default to 0 if no score available
    
    def _calculate_lev_rigorous_optimized(self, cve: str, d0: datetime, dn: datetime) -> float:
        """
        Optimized rigorous LEV calculation using vectorized operations.
        """
        # Generate all dates from d0 to dn
        num_days = (dn - d0).days + 1
        
        if num_days <= 0:
            return 0.0
        
        # Get EPSS scores for all dates at once
        epss_scores = np.zeros(num_days)
        current_date = d0
        
        for i in range(num_days):
            epss_scores[i] = self.get_epss_score(cve, current_date)
            current_date += timedelta(days=1)
        
        # Convert to daily probabilities using vectorized computation
        daily_probs = self._precompute_daily_probabilities(epss_scores)
        
        # Filter out zero probabilities for efficiency (they don't affect the product)
        non_zero_probs = daily_probs[daily_probs > 0]
        
        if len(non_zero_probs) == 0:
            return 0.0
        
        # Calculate LEV using log-space computation for numerical stability
        # LEV = 1 - ∏(1 - daily_prob) = 1 - exp(∑log(1 - daily_prob))
        
        # For very small probabilities, use approximation log(1-x) ≈ -x
        # For larger probabilities, use exact calculation
        complement_probs = 1.0 - non_zero_probs
        
        # Handle edge cases where complement might be 0 or very close to 0
        min_complement = np.finfo(float).eps
        complement_probs = np.maximum(complement_probs, min_complement)
        
        log_complement_probs = np.log(complement_probs)
        log_product = np.sum(log_complement_probs)
        
        # Handle numerical edge cases
        if log_product < -700:  # exp(-700) is effectively 0
            return 1.0
        elif log_product > 0:  # This shouldn't happen but handle gracefully
            return 0.0
        
        product = np.exp(log_product)
        lev_result = 1.0 - product
        
        # Ensure result is in valid range
        return max(0.0, min(1.0, lev_result))
    
    def _calculate_lev_nist_original(self, cve: str, d0: datetime, dn: datetime) -> float:
        """
        Original NIST LEV2 calculation with optimizations.
        """
        # Generate 30-day window dates
        window_dates = []
        current_date = d0
        while current_date <= dn:
            window_dates.append(current_date)
            current_date += timedelta(days=30)
        
        if not window_dates:
            return 0.0
        
        # Vectorized weight calculation
        weights = np.array([
            min(30, (dn - di).days + 1) / 30.0 
            for di in window_dates
        ])
        
        # Get EPSS scores for window dates
        epss_scores = np.array([
            self.get_epss_score(cve, di) 
            for di in window_dates
        ])
        
        # Calculate product using log-space for numerical stability
        terms = 1.0 - (epss_scores * weights)
        
        # Handle edge cases
        terms = np.clip(terms, 1e-16, 1.0)  # Prevent log(0)
        
        log_product = np.sum(np.log(terms))
        
        if log_product < -700:
            return 1.0
        
        product = np.exp(log_product)
        return 1.0 - product
    
    def calculate_lev(self, cve: str, d0: datetime, dn: datetime, rigorous: bool = False) -> float:
        """
        Calculate LEV probability for a vulnerability using optimized methods.
        """
        if rigorous:
            return self._calculate_lev_rigorous_optimized(cve, d0, dn)
        else:
            return self._calculate_lev_nist_original(cve, d0, dn)
    
    def _process_cve_batch(self, cve_batch: List[str], calculation_date: datetime, rigorous: bool) -> List[Dict]:
        """Process a batch of CVEs for parallel computation."""
        results = []
        
        for cve in cve_batch:
            try:
                # Find first EPSS date for this CVE
                d0 = self.get_first_epss_date(cve)
                if d0 is None:
                    continue
                
                # Calculate LEV probability
                lev_prob = self.calculate_lev(cve, d0, calculation_date, rigorous=rigorous)
                
                # Get peak EPSS information efficiently
                peak_epss = 0.0
                peak_date = None
                num_relevant_dates = 0
                
                # Only check dates where we have data for this CVE
                for date in sorted(self.epss_data.keys()):
                    if d0 <= date <= calculation_date and cve in self.epss_data[date]:
                        score = self.epss_data[date][cve]
                        num_relevant_dates += 1
                        
                        if score > peak_epss:
                            peak_epss = score
                            peak_date = date
                
                results.append({
                    'cve': cve,
                    'first_epss_date': d0,
                    'lev_probability': lev_prob,
                    'peak_epss_30day': peak_epss,
                    'peak_epss_date': peak_date,
                    'num_relevant_epss_dates': num_relevant_dates,
                })
            except Exception as e:
                self.logger.error(f"Error processing CVE {cve}: {e}")
                continue
        
        return results
    
    def calculate_lev_for_all_cves(self, calculation_date: datetime = None, rigorous: bool = False) -> pd.DataFrame:
        """
        Calculate LEV probabilities for all CVEs using parallel processing.
        """
        if calculation_date is None:
            calculation_date = datetime.today()
        
        calc_type = "Rigorous LEV" if rigorous else "NIST LEV2"
        self.logger.info(f"Calculating {calc_type} probabilities as of {calculation_date.date()}...")
        
        # Get all unique CVEs
        all_cves = set()
        for date_data in self.epss_data.values():
            all_cves.update(date_data.keys())
        
        all_cves = list(all_cves)
        total_cves = len(all_cves)
        
        self.logger.info(f"Found {total_cves:,} unique CVEs in dataset")
        
        # Split CVEs into batches for parallel processing
        batch_size = max(100, total_cves // (self.max_workers * 4))  # Dynamic batch sizing
        cve_batches = [
            all_cves[i:i + batch_size] 
            for i in range(0, total_cves, batch_size)
        ]
        
        self.logger.info(f"Processing {total_cves:,} CVEs in {len(cve_batches)} batches using {self.max_workers} workers...")
        
        all_results = []
        processing_errors = 0
        
        # Use ThreadPoolExecutor for CPU-bound calculations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(self._process_cve_batch, batch, calculation_date, rigorous): batch_idx
                for batch_idx, batch in enumerate(cve_batches)
            }
            
            completed_batches = 0
            
            for future in as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)
                    completed_batches += 1
                    
                    if completed_batches % max(1, len(cve_batches) // 10) == 0:
                        progress = completed_batches / len(cve_batches) * 100
                        self.logger.info(f"[PROGRESS] {progress:.1f}% - Completed {completed_batches}/{len(cve_batches)} batches")
                        
                except Exception as e:
                    processing_errors += 1
                    self.logger.error(f"Failed to process batch {batch_idx}: {e}")
        
        if processing_errors > 0:
            self.logger.warning(f"Encountered {processing_errors} batch processing errors")
        
        self.logger.info(f"Completed processing {len(all_results):,} CVEs successfully")
        return pd.DataFrame(all_results)
    
    def debug_lev_calculation(self, cve: str, calculation_date: datetime = None, rigorous: bool = False) -> Dict:
        """
        Debug LEV calculation for a specific CVE to identify issues.
        """
        if calculation_date is None:
            calculation_date = datetime.today()
        
        # Find first EPSS date
        d0 = self.get_first_epss_date(cve)
        if d0 is None:
            return {"error": "No EPSS data found for CVE"}
        
        # Get some sample EPSS scores
        num_days = min(30, (calculation_date - d0).days + 1)
        sample_dates = []
        sample_scores = []
        
        current_date = d0
        for i in range(num_days):
            score = self.get_epss_score(cve, current_date)
            sample_dates.append(current_date)
            sample_scores.append(score)
            current_date += timedelta(days=1)
        
        # Calculate daily probabilities for sample
        sample_epss = np.array(sample_scores)
        daily_probs = self._precompute_daily_probabilities(sample_epss)
        
        # Calculate LEV
        lev_prob = self.calculate_lev(cve, d0, calculation_date, rigorous=rigorous)
        
        return {
            "cve": cve,
            "d0": d0,
            "calculation_date": calculation_date,
            "total_days": (calculation_date - d0).days + 1,
            "sample_dates": sample_dates[:5],  # First 5 dates
            "sample_epss_scores": sample_scores[:5],  # First 5 EPSS scores
            "sample_daily_probs": daily_probs[:5].tolist(),  # First 5 daily probs
            "max_epss": max(sample_scores) if sample_scores else 0,
            "max_daily_prob": float(np.max(daily_probs)) if len(daily_probs) > 0 else 0,
            "lev_probability": lev_prob,
            "method": "rigorous" if rigorous else "nist"
        }

    def calculate_expected_exploited(self, results_df: pd.DataFrame) -> Dict:
        """
        Calculate Expected_Exploited metrics as described in Section 3.1.
        
        Args:
            results_df (pd.DataFrame): DataFrame containing LEV calculation results
                                    with 'lev_probability' column
        
        Returns:
            Dict: Dictionary containing:
                - total_cves: Total number of CVEs analyzed
                - expected_exploited: Sum of all LEV probabilities (expected number exploited)
                - expected_exploited_proportion: Proportion of CVEs expected to be exploited
        """
        total_cves = len(results_df)
        expected_exploited = results_df['lev_probability'].sum()
        proportion = expected_exploited / total_cves if total_cves > 0 else 0
        
        return {
            'total_cves': total_cves,
            'expected_exploited': expected_exploited,
            'expected_exploited_proportion': proportion
        }


def main():
    """Main execution function with optimizations and logging."""
    # Set up logging
    logger = setup_logging()
    
    try:
        # Initialize calculator with optimal worker count
        calculator = OptimizedLEVCalculator(logger=logger)
        
        # Create output directory
        output_dir = "./data_out"
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output directory: {output_dir}")
        
        # Define date range - using EPSS v3 era (from 2023-03-07 onwards)
        start_date = datetime(2023, 3, 7)  # Adjust as needed
        end_date = datetime.today()
        
        logger.info(f"Date range: {start_date.date()} to {end_date.date()}")
        logger.info(f"Total days to process: {(end_date - start_date).days + 1}")
        
        # Download EPSS data with parallel processing
        logger.info("Starting EPSS data download phase")
        start_time = time.time()
        calculator.download_epss_data(start_date, end_date)
        download_time = time.time() - start_time
        logger.info(f"Data loading completed in {download_time:.2f} seconds")
        
        # Debug a specific CVE before full calculation
        logger.info("Running debug analysis on sample CVE")
        test_cve = "CVE-2006-3655"  # From the output showing high EPSS but zero LEV
        debug_nist = calculator.debug_lev_calculation(test_cve, rigorous=False)
        debug_rigorous = calculator.debug_lev_calculation(test_cve, rigorous=True)
        
        logger.info(f"Debug NIST for {test_cve}:")
        for key, value in debug_nist.items():
            logger.info(f"  {key}: {value}")
        
        logger.info(f"Debug Rigorous for {test_cve}:")
        for key, value in debug_rigorous.items():
            logger.info(f"  {key}: {value}")
        
        # --- Calculate LEV probabilities using the original NIST LEV2 formula ---
        logger.info("Starting NIST LEV2 calculation phase")
        nist_start_time = time.time()
        nist_results_df = calculator.calculate_lev_for_all_cves(rigorous=False)
        nist_calc_time = time.time() - nist_start_time
        logger.info(f"NIST LEV2 calculation completed in {nist_calc_time:.2f} seconds")
        
        # Save NIST results
        nist_output_data = nist_results_df[['cve', 'first_epss_date', 'lev_probability', 'peak_epss_30day', 'peak_epss_date', 'num_relevant_epss_dates']].copy()
        nist_output_filename = f"lev_probabilities_nist_detailed.csv.gz"
        nist_output_path = os.path.join(output_dir, nist_output_filename)
        with gzip.open(nist_output_path, 'wt', encoding='utf-8') as f:
            nist_output_data.to_csv(f, index=False)
        logger.info(f"Saved compressed NIST LEV2 results to {nist_output_path}")

        # Generate NIST summary
        nist_summary = calculator.calculate_expected_exploited(nist_results_df)
        loaded_start, loaded_end = calculator.get_loaded_date_range()
        data_info = f"Data: {loaded_start.date()} to {loaded_end.date()}" if loaded_start and loaded_end else "No data loaded"

        nist_summary_text = f"""LEV CALCULATION SUMMARY (Original NIST LEV2)
{'='*50}
Calculation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Date Range: {start_date.date()} to {end_date.date()}
{data_info}
Calculation Time: {nist_calc_time:.2f} seconds
Total CVEs analyzed: {nist_summary['total_cves']:,}
Expected number of exploited vulnerabilities: {nist_summary['expected_exploited']:.2f}
Expected proportion of exploited vulnerabilities: {nist_summary['expected_exploited_proportion']:.4f} ({nist_summary['expected_exploited_proportion']*100:.2f}%)

LEV Probability Distribution:
Mean: {nist_results_df['lev_probability'].mean():.6f}
Median: {nist_results_df['lev_probability'].median():.6f}
Max: {nist_results_df['lev_probability'].max():.6f}
Min: {nist_results_df['lev_probability'].min():.6f}
Standard Deviation: {nist_results_df['lev_probability'].std():.6f}

High Probability Analysis:
CVEs with LEV > 0.5: {len(nist_results_df[nist_results_df['lev_probability'] > 0.5])}
CVEs with LEV > 0.1: {len(nist_results_df[nist_results_df['lev_probability'] > 0.1])}
CVEs with LEV > 0.01: {len(nist_results_df[nist_results_df['lev_probability'] > 0.01])}
"""
        
        if len(nist_results_df) > 0:
            nist_summary_text += "\nTop 10 highest LEV probabilities:\n"
            top_10_nist = nist_results_df.nlargest(10, 'lev_probability')[['cve', 'lev_probability', 'peak_epss_30day']]
            for _, row in top_10_nist.iterrows():
                nist_summary_text += f"  {row['cve']}: LEV={row['lev_probability']:.4f}, Peak EPSS={row['peak_epss_30day']:.4f}\n"
        
        nist_summary_text += f"\n{'='*50}\n"
        
        nist_summary_path = os.path.join(output_dir, "lev_summary_nist.txt")
        with open(nist_summary_path, 'w', encoding='utf-8') as f:
            f.write(nist_summary_text)
        logger.info(f"Saved NIST LEV2 summary to {nist_summary_path}")
        
        # Log the summary (this will appear in both console and log file)
        for line in nist_summary_text.strip().split('\n'):
            logger.info(line)

        # --- Calculate LEV probabilities using the Rigorous Probabilistic approach ---
        logger.info("Starting Rigorous LEV calculation phase")
        rigorous_start_time = time.time()
        rigorous_results_df = calculator.calculate_lev_for_all_cves(rigorous=True)
        rigorous_calc_time = time.time() - rigorous_start_time
        logger.info(f"Rigorous LEV calculation completed in {rigorous_calc_time:.2f} seconds")

        # Save rigorous results
        rigorous_output_data = rigorous_results_df[['cve', 'first_epss_date', 'lev_probability', 'peak_epss_30day', 'peak_epss_date', 'num_relevant_epss_dates']].copy()
        rigorous_output_filename = f"lev_probabilities_rigorous_detailed.csv.gz"
        rigorous_output_path = os.path.join(output_dir, rigorous_output_filename)
        with gzip.open(rigorous_output_path, 'wt', encoding='utf-8') as f:
            rigorous_output_data.to_csv(f, index=False)
        logger.info(f"Saved compressed rigorous LEV results to {rigorous_output_path}")

        # Generate rigorous summary
        rigorous_summary = calculator.calculate_expected_exploited(rigorous_results_df)

        rigorous_summary_text = f"""LEV CALCULATION SUMMARY (Rigorous Probabilistic)
{'='*50}
Calculation Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Date Range: {start_date.date()} to {end_date.date()}
{data_info}
Calculation Time: {rigorous_calc_time:.2f} seconds
Total CVEs analyzed: {rigorous_summary['total_cves']:,}
Expected number of exploited vulnerabilities: {rigorous_summary['expected_exploited']:.2f}
Expected proportion of exploited vulnerabilities: {rigorous_summary['expected_exploited_proportion']:.4f} ({rigorous_summary['expected_exploited_proportion']*100:.2f}%)

LEV Probability Distribution:
Mean: {rigorous_results_df['lev_probability'].mean():.6f}
Median: {rigorous_results_df['lev_probability'].median():.6f}
Max: {rigorous_results_df['lev_probability'].max():.6f}
Min: {rigorous_results_df['lev_probability'].min():.6f}
Standard Deviation: {rigorous_results_df['lev_probability'].std():.6f}

High Probability Analysis:
CVEs with LEV > 0.5: {len(rigorous_results_df[rigorous_results_df['lev_probability'] > 0.5])}
CVEs with LEV > 0.1: {len(rigorous_results_df[rigorous_results_df['lev_probability'] > 0.1])}
CVEs with LEV > 0.01: {len(rigorous_results_df[rigorous_results_df['lev_probability'] > 0.01])}
"""
        
        if len(rigorous_results_df) > 0:
            rigorous_summary_text += "\nTop 10 highest LEV probabilities:\n"
            top_10_rigorous = rigorous_results_df.nlargest(10, 'lev_probability')[['cve', 'lev_probability', 'peak_epss_30day']]
            for _, row in top_10_rigorous.iterrows():
                rigorous_summary_text += f"  {row['cve']}: LEV={row['lev_probability']:.4f}, Peak EPSS={row['peak_epss_30day']:.4f}\n"
        
        rigorous_summary_text += f"\n{'='*50}\n"
        
        rigorous_summary_path = os.path.join(output_dir, "lev_summary_rigorous.txt")
        with open(rigorous_summary_path, 'w', encoding='utf-8') as f:
            f.write(rigorous_summary_text)
        logger.info(f"Saved Rigorous LEV summary to {rigorous_summary_path}")
        
        # Log the rigorous summary (this will appear in both console and log file)
        for line in rigorous_summary_text.strip().split('\n'):
            logger.info(line)

        # Performance comparison
        total_time = time.time() - start_time
        logger.info(f"PERFORMANCE SUMMARY:")
        logger.info(f"Total execution time: {total_time:.2f} seconds")
        logger.info(f"Data loading: {download_time:.2f}s ({download_time/total_time*100:.1f}%)")
        logger.info(f"NIST LEV2 calculation: {nist_calc_time:.2f}s ({nist_calc_time/total_time*100:.1f}%)")
        logger.info(f"Rigorous LEV calculation: {rigorous_calc_time:.2f}s ({rigorous_calc_time/total_time*100:.1f}%)")
        
        if nist_calc_time > 0:
            logger.info(f"Rigorous vs NIST time ratio: {rigorous_calc_time/nist_calc_time:.2f}x")

        # Log final comparison statistics
        difference_exploited = rigorous_summary['expected_exploited'] - nist_summary['expected_exploited']
        difference_percent = (difference_exploited / nist_summary['expected_exploited'] * 100) if nist_summary['expected_exploited'] > 0 else 0
        
        logger.info(f"METHOD COMPARISON:")
        logger.info(f"NIST LEV2 expected exploited: {nist_summary['expected_exploited']:.2f}")
        logger.info(f"Rigorous expected exploited: {rigorous_summary['expected_exploited']:.2f}")
        logger.info(f"Difference: +{difference_exploited:.2f} vulnerabilities ({difference_percent:+.2f}%)")

        logger.info("LEV calculation completed successfully")
        return nist_output_path, nist_summary_path, rigorous_output_path, rigorous_summary_path

    except Exception as e:
        logger.error(f"Fatal error in main execution: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise


def clear_individual_cache(cache_dir: str = "data_in"):
    """Utility function to clear individual EPSS files."""
    logger = logging.getLogger(__name__)
    
    if os.path.exists(cache_dir):
        files = [f for f in os.listdir(cache_dir) if f.startswith('epss_scores-') and f.endswith('.csv.gz')]
        for file in files:
            os.remove(os.path.join(cache_dir, file))
        logger.info(f"Cleared {len(files)} EPSS cache files from {cache_dir}")
    else:
        logger.info(f"No cache directory to clear at {cache_dir}")



def download_epss_range(start_date: datetime = None, end_date: datetime = None, cache_dir: str = "data_in"):
    """Utility function to pre-download EPSS files for a date range."""
    logger = logging.getLogger(__name__)
    
    if start_date is None:
        start_date = datetime(2023, 3, 7)  # EPSS v3 start
    if end_date is None:
        end_date = datetime.today()
    
    logger.info(f"Pre-downloading EPSS data from {start_date.date()} to {end_date.date()}")
    
    calculator = OptimizedLEVCalculator(cache_dir, logger=logger)
    calculator.download_epss_data(start_date, end_date)
    logger.info("EPSS download complete")


if __name__ == "__main__":
    main()