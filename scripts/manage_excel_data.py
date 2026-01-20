"""
Excel Test Data Sync and Validation Script
Sync test data from cloud storage, validate, and manage Excel test data
"""

import os
import json
import pandas as pd
from datetime import datetime
from pathlib import Path


class ExcelTestDataManager:
    """Manage Excel test data files"""
    
    EXCEL_FILE = 'test_data/calculator_tests.xlsx'
    DATA_DIR = 'test_data'
    BACKUP_DIR = 'test_data/backups'
    METADATA_FILE = 'test_data/.metadata.json'
    
    @staticmethod
    def ensure_directories():
        """Create necessary directories"""
        os.makedirs(ExcelTestDataManager.DATA_DIR, exist_ok=True)
        os.makedirs(ExcelTestDataManager.BACKUP_DIR, exist_ok=True)
    
    @staticmethod
    def backup_current_file():
        """Create backup of current Excel file"""
        if os.path.exists(ExcelTestDataManager.EXCEL_FILE):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(
                ExcelTestDataManager.BACKUP_DIR,
                f"calculator_tests_backup_{timestamp}.xlsx"
            )
            import shutil
            shutil.copy(ExcelTestDataManager.EXCEL_FILE, backup_file)
            print(f"✓ Backup created: {backup_file}")
            return backup_file
        return None
    
    @staticmethod
    def validate_excel_structure():
        """Validate Excel file structure and content"""
        if not os.path.exists(ExcelTestDataManager.EXCEL_FILE):
            return False, "Excel file not found"
        
        try:
            xls = pd.ExcelFile(ExcelTestDataManager.EXCEL_FILE)
            sheets = xls.sheet_names
            
            required_sheets = ['Addition', 'Subtraction', 'Multiplication', 'Division', 
                              'Security', 'Boundary', 'Performance']
            
            missing_sheets = [s for s in required_sheets if s not in sheets]
            if missing_sheets:
                return False, f"Missing sheets: {missing_sheets}"
            
            # Validate each sheet has data
            for sheet in required_sheets:
                df = pd.read_excel(ExcelTestDataManager.EXCEL_FILE, sheet_name=sheet)
                if df.empty:
                    return False, f"Sheet '{sheet}' is empty"
                if len(df) < 3:
                    return False, f"Sheet '{sheet}' has insufficient data ({len(df)} rows)"
            
            return True, "✓ Excel structure valid"
        
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    @staticmethod
    def get_metadata():
        """Get metadata about Excel test data"""
        ExcelTestDataManager.ensure_directories()
        
        metadata = {
            'file': ExcelTestDataManager.EXCEL_FILE,
            'last_updated': None,
            'sheets': {},
            'total_tests': 0,
            'validation_status': None
        }
        
        if os.path.exists(ExcelTestDataManager.EXCEL_FILE):
            metadata['last_updated'] = datetime.fromtimestamp(
                os.path.getmtime(ExcelTestDataManager.EXCEL_FILE)
            ).isoformat()
            
            xls = pd.ExcelFile(ExcelTestDataManager.EXCEL_FILE)
            for sheet in xls.sheet_names:
                df = pd.read_excel(ExcelTestDataManager.EXCEL_FILE, sheet_name=sheet)
                metadata['sheets'][sheet] = {
                    'rows': len(df),
                    'columns': list(df.columns),
                    'priorities': df['priority'].value_counts().to_dict() if 'priority' in df.columns else None
                }
                metadata['total_tests'] += len(df)
        
        # Validate
        is_valid, msg = ExcelTestDataManager.validate_excel_structure()
        metadata['validation_status'] = msg
        
        return metadata
    
    @staticmethod
    def print_metadata():
        """Print metadata in human-readable format"""
        metadata = ExcelTestDataManager.get_metadata()
        
        print("\n" + "="*70)
        print("EXCEL TEST DATA METADATA")
        print("="*70)
        print(f"\nFile: {metadata['file']}")
        print(f"Last Updated: {metadata['last_updated']}")
        print(f"Validation: {metadata['validation_status']}")
        print(f"\nTotal Test Cases: {metadata['total_tests']}")
        print("\nSheet Summary:")
        
        for sheet_name, sheet_data in metadata['sheets'].items():
            print(f"\n  📊 {sheet_name}:")
            print(f"     - Test Cases: {sheet_data['rows']}")
            print(f"     - Columns: {', '.join(sheet_data['columns'][:3])}...")
            if sheet_data['priorities']:
                print(f"     - Priorities: {sheet_data['priorities']}")
        
        print("\n" + "="*70 + "\n")
    
    @staticmethod
    def sync_from_github(github_token=None, force=False):
        """
        Sync Excel test data from GitHub repository
        
        Usage:
            ExcelTestDataManager.sync_from_github(github_token="your_token")
        """
        print("\n⚠️  GitHub sync feature requires setup.")
        print("Options:")
        print("1. Download from GitHub Actions artifacts")
        print("2. Pull from release tag")
        print("3. Clone from raw GitHub URL")
        print("\nExample:")
        print("  # Download directly from GitHub")
        print("  curl -o test_data/calculator_tests.xlsx \\")
        print("    https://github.com/shubham4545/calculator_pytest/releases/download/v1.0/calculator_tests.xlsx")
        print("\nFor CI/CD automation, see CI_CD_EXCEL_SYNC.md")
    
    @staticmethod
    def compare_with_backup():
        """Compare current Excel with latest backup"""
        backups = sorted(Path(ExcelTestDataManager.BACKUP_DIR).glob('*.xlsx'), 
                        key=os.path.getmtime, reverse=True)
        
        if not backups:
            print("No backups found")
            return
        
        latest_backup = backups[0]
        current_df = pd.read_excel(ExcelTestDataManager.EXCEL_FILE, sheet_name='Addition')
        backup_df = pd.read_excel(latest_backup, sheet_name='Addition')
        
        print(f"\n📊 Comparing with backup: {latest_backup.name}")
        print(f"Current: {len(current_df)} rows | Backup: {len(backup_df)} rows")
        
        if len(current_df) > len(backup_df):
            print(f"✓ Added {len(current_df) - len(backup_df)} new test cases")
        elif len(current_df) < len(backup_df):
            print(f"⚠️  Removed {len(backup_df) - len(current_df)} test cases")
        else:
            print("No row changes detected")


class ExcelDataValidator:
    """Validate Excel test data for consistency"""
    
    @staticmethod
    def validate_all():
        """Run all validations"""
        print("\n" + "="*70)
        print("EXCEL TEST DATA VALIDATION")
        print("="*70)
        
        results = {
            'file_exists': ExcelDataValidator._check_file_exists(),
            'structure': ExcelDataValidator._check_structure(),
            'data_quality': ExcelDataValidator._check_data_quality(),
            'test_count': ExcelDataValidator._check_test_count(),
        }
        
        print("\n" + "="*70)
        passed = sum(1 for v in results.values() if v['status'] == 'PASS')
        total = len(results)
        print(f"\nValidation Results: {passed}/{total} passed")
        print("="*70 + "\n")
        
        return results
    
    @staticmethod
    def _check_file_exists():
        """Check if Excel file exists"""
        exists = os.path.exists(ExcelTestDataManager.EXCEL_FILE)
        result = {
            'test': 'File Exists',
            'status': 'PASS' if exists else 'FAIL',
            'message': f"File found: {ExcelTestDataManager.EXCEL_FILE}" if exists else "File not found"
        }
        print(f"\n✓ {result['test']}: {result['status']}")
        print(f"  {result['message']}")
        return result
    
    @staticmethod
    def _check_structure():
        """Check Excel file structure"""
        try:
            xls = pd.ExcelFile(ExcelTestDataManager.EXCEL_FILE)
            required_sheets = ['Addition', 'Subtraction', 'Multiplication', 'Division', 
                              'Security', 'Boundary', 'Performance']
            missing = [s for s in required_sheets if s not in xls.sheet_names]
            
            status = 'PASS' if not missing else 'FAIL'
            result = {
                'test': 'Sheet Structure',
                'status': status,
                'message': f"All {len(required_sheets)} sheets present" if not missing else f"Missing: {missing}"
            }
            print(f"\n✓ {result['test']}: {result['status']}")
            print(f"  {result['message']}")
            return result
        except Exception as e:
            result = {
                'test': 'Sheet Structure',
                'status': 'FAIL',
                'message': str(e)
            }
            print(f"\n✗ {result['test']}: {result['status']}")
            print(f"  {result['message']}")
            return result
    
    @staticmethod
    def _check_data_quality():
        """Check data quality in sheets"""
        try:
            xls = pd.ExcelFile(ExcelTestDataManager.EXCEL_FILE)
            issues = []
            
            for sheet in xls.sheet_names:
                df = pd.read_excel(ExcelTestDataManager.EXCEL_FILE, sheet_name=sheet)
                
                # Check for empty rows
                if df.empty:
                    issues.append(f"Sheet '{sheet}' is empty")
                
                # Check for null values in critical columns
                critical_cols = ['TestID']
                for col in critical_cols:
                    if col in df.columns and df[col].isnull().any():
                        issues.append(f"Sheet '{sheet}' has null values in '{col}'")
            
            status = 'PASS' if not issues else 'FAIL'
            result = {
                'test': 'Data Quality',
                'status': status,
                'message': "No issues found" if not issues else "; ".join(issues)
            }
            print(f"\n✓ {result['test']}: {result['status']}")
            print(f"  {result['message']}")
            return result
        except Exception as e:
            result = {
                'test': 'Data Quality',
                'status': 'FAIL',
                'message': str(e)
            }
            return result
    
    @staticmethod
    def _check_test_count():
        """Check minimum test count"""
        try:
            total = 0
            xls = pd.ExcelFile(ExcelTestDataManager.EXCEL_FILE)
            
            for sheet in xls.sheet_names:
                df = pd.read_excel(ExcelTestDataManager.EXCEL_FILE, sheet_name=sheet)
                total += len(df)
            
            min_tests = 40
            status = 'PASS' if total >= min_tests else 'FAIL'
            result = {
                'test': 'Minimum Test Count',
                'status': status,
                'message': f"Total: {total} tests (minimum: {min_tests})"
            }
            print(f"\n✓ {result['test']}: {result['status']}")
            print(f"  {result['message']}")
            return result
        except Exception as e:
            result = {
                'test': 'Minimum Test Count',
                'status': 'FAIL',
                'message': str(e)
            }
            return result


def main():
    """Main CLI interface"""
    import sys
    
    ExcelTestDataManager.ensure_directories()
    
    if len(sys.argv) < 2:
        # Default: show metadata
        ExcelTestDataManager.print_metadata()
        return
    
    command = sys.argv[1].lower()
    
    if command == 'info':
        ExcelTestDataManager.print_metadata()
    
    elif command == 'validate':
        ExcelDataValidator.validate_all()
    
    elif command == 'backup':
        ExcelTestDataManager.backup_current_file()
    
    elif command == 'compare':
        ExcelTestDataManager.compare_with_backup()
    
    elif command == 'sync':
        ExcelTestDataManager.sync_from_github()
    
    else:
        print(f"Unknown command: {command}")
        print("\nAvailable commands:")
        print("  info      - Show Excel data metadata")
        print("  validate  - Validate Excel structure and data")
        print("  backup    - Create backup of current file")
        print("  compare   - Compare with latest backup")
        print("  sync      - Sync from GitHub (setup required)")


if __name__ == "__main__":
    main()
