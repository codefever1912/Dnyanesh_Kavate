#!/usr/bin/env python3
"""
CSV Reader Module for Attack Surface Monitoring Tool
This module handles reading domain names from CSV files.
"""

import csv
import os
import sys
from typing import List, Dict, Any


class CSVReader:
    """
    A class to read domain names from CSV files.
    """

    def __init__(self, file_path: str):
        """
        Initialize the CSVReader with the path to the CSV file.

        Args:
            file_path (str): Path to the CSV file containing domain names.
        """
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"CSV file not found: {file_path}")

    def read_domains(self) -> List[str]:
        """
        Read domain names from the CSV file.

        Returns:
            List[str]: A list of domain names.
        
        Raises:
            ValueError: If the CSV file does not contain a 'domain' column.
        """
        domains = []
        
        try:
            with open(self.file_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                
                # Check if 'domain' column exists
                if 'domain' not in reader.fieldnames: # type: ignore
                    raise ValueError("CSV file must contain a 'domain' column")
                
                # Extract domains
                for row in reader:
                    domain = row['domain'].strip()
                    if domain:  # Only add non-empty domains
                        domains.append(domain)
        
        except Exception as e:
            print(f"Error reading CSV file: {e}", file=sys.stderr)
            raise
        
        return domains


def read_domains_from_csv(file_path: str) -> List[str]:
    """
    Convenience function to read domains from a CSV file.

    Args:
        file_path (str): Path to the CSV file containing domain names.

    Returns:
        List[str]: A list of domain names.
    """
    reader = CSVReader(file_path)
    return reader.read_domains()


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) > 1:
        csv_path = sys.argv[1]
        try:
            domains = read_domains_from_csv(csv_path)
            print(f"Found {len(domains)} domains:")
            for domain in domains:
                print(f" - {domain}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    else:
        print("Usage: python csv_reader.py <path_to_csv>", file=sys.stderr)
