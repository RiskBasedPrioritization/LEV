# test_data_generator.py
#!/usr/bin/env python3
"""
Generate test data for LEV implementation testing.
Creates realistic EPSS and KEV datasets for comprehensive testing.
"""

import numpy as np
import pandas as pd
import gzip
import os
import json
from datetime import datetime, timedelta
from pathlib import Path


class DataGenerator:
    """Generate realistic test data for LEV testing."""
    
    def __init__(self, output_dir="test_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_realistic_epss_timeline(self, cve_id, start_date, end_date, pattern="mixed"):
        """Generate realistic EPSS score timeline for a CVE."""
        dates = []
        scores = []
        
        current_date = start_date
        base_score = np.random.uniform(0.01, 0.1)
        
        while current_date <= end_date:
            if pattern == "stable":
                score = base_score + np.random.normal(0, 0.005)
            elif pattern == "rising":
                days_elapsed = (current_date - start_date).days
                score = base_score + days_elapsed * 0.0005
            elif pattern == "declining":
                days_elapsed = (current_date - start_date).days
                score = max(0.001, base_score - days_elapsed * 0.0003)
            elif pattern == "spike":
                days_elapsed = (current_date - start_date).days
                if 60 <= days_elapsed <= 80:  # Spike period
                    score = 0.5 + np.random.uniform(-0.1, 0.1)
                else:
                    score = base_score + np.random.normal(0, 0.01)
            else:  # mixed
                days_elapsed = (current_date - start_date).days
                seasonal = 0.02 * np.sin(days_elapsed * 2 * np.pi / 365)
                trend = days_elapsed * 0.0001
                noise = np.random.normal(0, 0.005)
                score = base_score + seasonal + trend + noise
            
            score = max(0.0, min(1.0, score))
            dates.append(current_date)
            scores.append(score)
            current_date += timedelta(days=1)
        
        return list(zip(dates, scores))
    
    def generate_epss_dataset(self, start_date, end_date, num_cves=1000):
        """Generate complete EPSS dataset."""
        print(f"Generating EPSS dataset from {start_date} to {end_date} for {num_cves} CVEs...")
        
        # Generate CVE list
        cves = [f"CVE-2024-{i:04d}" for i in range(1, num_cves + 1)]
        
        # Assign patterns to CVEs
        patterns = ["stable", "rising", "declining", "spike", "mixed"]
        cve_patterns = {cve: np.random.choice(patterns) for cve in cves}
        
        # Generate timelines for each CVE
        cve_timelines = {}
        for cve in cves:
            pattern = cve_patterns[cve]
            timeline = self.generate_realistic_epss_timeline(cve, start_date, end_date, pattern)
            cve_timelines[cve] = dict(timeline)
        
        # Create daily EPSS files
        current_date = start_date
        file_count = 0
        
        while current_date <= end_date:
            filename = f"epss_scores-{current_date.strftime('%Y-%m-%d')}.csv.gz"
            filepath = self.output_dir / filename
            
            # Create CSV content
            csv_content = "cve,epss\n"
            for cve in cves:
                if current_date in cve_timelines[cve]:
                    score = cve_timelines[cve][current_date]
                    csv_content += f"{cve},{score:.6f}\n"
            
            # Write compressed file
            with gzip.open(filepath, 'wt') as f:
                f.write(csv_content)
            
            file_count += 1
            if file_count % 30 == 0:
                print(f"  Generated {file_count} EPSS files...")
            
            current_date += timedelta(days=1)
        
        print(f"Generated {file_count} EPSS files in {self.output_dir}")
        
        # Save metadata
        metadata = {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "num_cves": num_cves,
            "num_files": file_count,
            "cve_patterns": cve_patterns
        }
        
        with open(self.output_dir / "epss_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return cve_timelines
    
    def generate_kev_dataset(self, cves_subset=None, num_kev=50):
        """Generate realistic KEV dataset."""
        print(f"Generating KEV dataset with {num_kev} entries...")
        
        if cves_subset is None:
            cves_subset = [f"CVE-2024-{i:04d}" for i in range(1, 1001)]
        
        # Select random CVEs for KEV
        kev_cves = np.random.choice(cves_subset, size=min(num_kev, len(cves_subset)), replace=False)
        
        # Realistic vendor/product combinations
        vendors = ["Microsoft", "Adobe", "Apache", "Oracle", "VMware", "Cisco", "Google", "Apple"]
        products = ["Windows", "Office", "Reader", "HTTP Server", "Database", "vCenter", "Router", "Chrome"]
        
        # Create KEV CSV
        kev_data = "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,requiredAction,dueDate,knownRansomwareCampaignUse,notes\n"
        
        for cve in kev_cves:
            vendor = np.random.choice(vendors)
            product = np.random.choice(products)
            date_added = datetime(2024, np.random.randint(1, 13), np.random.randint(1, 29))
            due_date = date_added + timedelta(days=14)
            ransomware = np.random.choice(["Known", "Unknown"])
            
            kev_data += f"{cve},{vendor},{product},Test Vulnerability,{date_added.strftime('%Y-%m-%d')},Test description,Apply updates,{due_date.strftime('%Y-%m-%d')},{ransomware},Test notes\n"
        
        # Write KEV file
        kev_filepath = self.output_dir / "known_exploited_vulnerabilities.csv"
        with open(kev_filepath, 'w') as f:
            f.write(kev_data)
        
        print(f"Generated KEV file: {kev_filepath}")
        return list(kev_cves)
    
    def generate_nist_examples(self):
        """Generate the specific examples from NIST CSWP 41."""
        print("Generating NIST CSWP 41 examples...")
        
        # CVE-2023-1730 timeline from the paper
        cve_1730_timeline = [
            (datetime(2023, 5, 2), 0.00),
            (datetime(2023, 6, 1), 0.00),
            (datetime(2023, 7, 1), 0.00),
            (datetime(2023, 7, 31), 0.05),
            (datetime(2023, 8, 30), 0.06),
            (datetime(2023, 9, 29), 0.06),
            (datetime(2023, 10, 29), 0.06),
            (datetime(2023, 11, 28), 0.10),
            (datetime(2023, 12, 28), 0.13),
            (datetime(2024, 1, 27), 0.16),
            (datetime(2024, 2, 26), 0.08),
            (datetime(2024, 3, 27), 0.05),
            (datetime(2024, 4, 26), 0.05),
            (datetime(2024, 5, 26), 0.04),
            (datetime(2024, 6, 25), 0.05),
            (datetime(2024, 7, 25), 0.05),
            (datetime(2024, 8, 24), 0.05),
            (datetime(2024, 9, 23), 0.05),
            (datetime(2024, 10, 23), 0.05),
            (datetime(2024, 11, 22), 0.08),
        ]
        
        # Fill in daily interpolated values
        timeline_dict = dict(cve_1730_timeline)
        start_date = datetime(2023, 5, 2)
        end_date = datetime(2024, 12, 12)
        
        current_date = start_date
        while current_date <= end_date:
            filename = f"epss_scores-{current_date.strftime('%Y-%m-%d')}.csv.gz"
            filepath = self.output_dir / "nist_examples" / filename
            filepath.parent.mkdir(exist_ok=True)
            
            # Find appropriate EPSS score
            score = 0.0
            for timeline_date, timeline_score in cve_1730_timeline:
                if current_date >= timeline_date:
                    score = timeline_score
                else:
                    break
            
            csv_content = "cve,epss\nCVE-2023-1730,{:.6f}\n".format(score)
            
            with gzip.open(filepath, 'wt') as f:
                f.write(csv_content)
            
            current_date += timedelta(days=1)
        
        print("Generated NIST examples in test_data/nist_examples/")


def main():
    """Generate test datasets."""
    generator = TestDataGenerator()
    
    # Generate main test dataset
    start_date = datetime(2024, 1, 1)
    end_date = datetime(2024, 6, 30)  # 6 months
    
    cve_timelines = generator.generate_epss_dataset(start_date, end_date, num_cves=500)
    kev_cves = generator.generate_kev_dataset(list(cve_timelines.keys()), num_kev=25)
    
    # Generate NIST examples
    generator.generate_nist_examples()
    
    print("\n✅ Test data generation complete!")
    print(f"Output directory: {generator.output_dir}")
    print("Files generated:")
    print(f"  - {len(list(generator.output_dir.glob('epss_scores-*.csv.gz')))} EPSS files")
    print(f"  - 1 KEV file")
    print(f"  - NIST examples")


if __name__ == "__main__":
    main()