# run_tests.py
#!/usr/bin/env python3
"""
Test runner script for LEV implementation.
Provides convenient interface for running different test suites.
"""

import sys
import subprocess
import argparse
import os
from pathlib import Path


def run_command(cmd, description=""):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    if description:
        print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"\n✅ {description or 'Command'} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {description or 'Command'} failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"\n❌ Command not found: {cmd[0]}")
        print("Make sure pytest is installed: pip install pytest")
        return False


def main():
    parser = argparse.ArgumentParser(description="LEV Test Suite Runner")
    parser.add_argument(
        "suite",
        choices=["unit", "mathematical", "integration", "performance", "all", "quick", "coverage"],
        help="Test suite to run"
    )
    parser.add_argument(
        "--parallel", "-p",
        action="store_true",
        help="Run tests in parallel"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--failfast", "-x",
        action="store_true",
        help="Stop on first failure"
    )
    parser.add_argument(
        "--markers", "-m",
        help="Additional pytest markers"
    )
    
    args = parser.parse_args()
    
    # Base pytest command
    cmd = ["python", "-m", "pytest"]
    
    # Add test directory
    test_dir = Path(__file__).parent / "test"
    if not test_dir.exists():
        print(f"❌ Test directory not found: {test_dir}")
        sys.exit(1)
    
    cmd.append(str(test_dir))
    
    # Configure based on suite
    if args.suite == "unit":
        cmd.extend(["-m", "not slow and not performance and not integration"])
        description = "Unit Tests"
    elif args.suite == "mathematical":
        cmd.append("test_mathematical_validation.py")
        description = "Mathematical Validation Tests"
    elif args.suite == "integration":
        cmd.extend(["-m", "integration"])
        description = "Integration Tests"
    elif args.suite == "performance":
        cmd.extend(["-m", "performance"])
        description = "Performance Benchmarks"
    elif args.suite == "quick":
        cmd.extend(["-m", "not slow and not performance"])
        description = "Quick Tests"
    elif args.suite == "coverage":
        cmd.extend(["--cov=lev_calculator", "--cov-report=html", "--cov-report=term-missing"])
        description = "Coverage Tests"
    elif args.suite == "all":
        description = "All Tests"
    
    # Add optional flags
    if args.verbose:
        cmd.append("-v")
    
    if args.failfast:
        cmd.append("-x")
    
    if args.parallel:
        try:
            import pytest_xdist
            cmd.extend(["-n", "auto"])
        except ImportError:
            print("⚠️  pytest-xdist not installed, running sequentially")
    
    if args.markers:
        cmd.extend(["-m", args.markers])
    
    # Add standard options
    cmd.extend(["--tb=short"])
    
    # Run the tests
    success = run_command(cmd, description)
    
    if not success:
        sys.exit(1)
    
    print(f"\n🎉 {description} completed successfully!")


if __name__ == "__main__":
    main()
