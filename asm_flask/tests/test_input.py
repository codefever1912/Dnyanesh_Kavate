#!/usr/bin/env python3
"""
Test module for the input components of the Attack Surface Monitoring Tool.
"""

import os
import sys
import unittest
import tempfile
import csv

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.input.csv_reader import read_domains_from_csv


class TestInputModule(unittest.TestCase):
    """Test cases for the input module."""

    def test_csv_reader_valid_file(self):
        """Test reading domains from a valid CSV file."""
        # Create a temporary CSV file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as temp_file:
            writer = csv.writer(temp_file)
            writer.writerow(['domain'])
            writer.writerow(['example.com'])
            writer.writerow(['google.com'])
            writer.writerow(['github.com'])
            temp_file_name = temp_file.name

        try:
            # Test reading domains from the CSV file
            domains = read_domains_from_csv(temp_file_name)
            
            # Verify the results
            self.assertEqual(len(domains), 3)
            self.assertIn('example.com', domains)
            self.assertIn('google.com', domains)
            self.assertIn('github.com', domains)
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_name)

    def test_csv_reader_empty_file(self):
        """Test reading domains from an empty CSV file."""
        # Create a temporary empty CSV file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as temp_file:
            writer = csv.writer(temp_file)
            writer.writerow(['domain'])
            temp_file_name = temp_file.name

        try:
            # Test reading domains from the empty CSV file
            domains = read_domains_from_csv(temp_file_name)
            
            # Verify the results
            self.assertEqual(len(domains), 0)
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_name)

    def test_csv_reader_invalid_file(self):
        """Test reading domains from a non-existent file."""
        # Test reading domains from a non-existent file
        with self.assertRaises(FileNotFoundError):
            read_domains_from_csv('non_existent_file.csv')

    def test_csv_reader_no_domain_column(self):
        """Test reading domains from a CSV file without a 'domain' column."""
        # Create a temporary CSV file without a 'domain' column
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as temp_file:
            writer = csv.writer(temp_file)
            writer.writerow(['url'])
            writer.writerow(['https://example.com'])
            temp_file_name = temp_file.name

        try:
            # Test reading domains from the CSV file
            with self.assertRaises(KeyError):
                read_domains_from_csv(temp_file_name)
        finally:
            # Clean up the temporary file
            os.unlink(temp_file_name)


if __name__ == '__main__':
    unittest.main()
