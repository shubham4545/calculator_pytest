"""
Excel-Driven Parameterized Tests for Calculator
This module reads test data from Excel files and runs parameterized tests
"""

import pytest
import pandas as pd
import os
from calculator import Calculator


class ExcelTestDataProvider:
    """Central provider for Excel-based test data"""
    
    EXCEL_FILE = 'test_data/calculator_tests.xlsx'
    
    @staticmethod
    def _read_sheet(sheet_name):
        """Read a specific sheet from Excel file"""
        if not os.path.exists(ExcelTestDataProvider.EXCEL_FILE):
            pytest.skip(f"Excel test data file not found: {ExcelTestDataProvider.EXCEL_FILE}")
        
        try:
            df = pd.read_excel(ExcelTestDataProvider.EXCEL_FILE, sheet_name=sheet_name)
            return df
        except Exception as e:
            pytest.skip(f"Error reading Excel sheet '{sheet_name}': {str(e)}")
    
    @staticmethod
    def get_addition_tests():
        """Get addition test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Addition')
        # Return: (a, b, expected, description)
        return [(row['a'], row['b'], row['expected'], row['description']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_subtraction_tests():
        """Get subtraction test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Subtraction')
        return [(row['a'], row['b'], row['expected'], row['description']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_multiplication_tests():
        """Get multiplication test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Multiplication')
        return [(row['a'], row['b'], row['expected'], row['description']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_division_tests():
        """Get division test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Division')
        return [(row['a'], row['b'], row['expected'], row['description']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_security_tests():
        """Get security test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Security')
        # Return: (input, operation, should_fail, threat_type)
        return [(row['input'], row['operation'], row['should_fail'], row['threat_type']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_boundary_tests():
        """Get boundary test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Boundary')
        # Return: (operation, a, b, exception, description)
        return [(row['operation'], row['a'], row['b'], row['exception'], row['description']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_performance_tests():
        """Get performance test cases from Excel"""
        df = ExcelTestDataProvider._read_sheet('Performance')
        # Return: (operation, a, b, max_time_seconds, description)
        return [(row['operation'], row['a'], row['b'], row['max_time_seconds'], row['description']) 
                for _, row in df.iterrows()]
    
    @staticmethod
    def get_filtered_tests(sheet_name, priority=None):
        """Get filtered test cases by priority"""
        df = ExcelTestDataProvider._read_sheet(sheet_name)
        
        if priority:
            df = df[df['priority'] == priority]
        
        # Return based on sheet type
        if sheet_name == 'Addition':
            return [(row['a'], row['b'], row['expected'], row['description']) 
                    for _, row in df.iterrows()]
        elif sheet_name == 'Security':
            return [(row['input'], row['operation'], row['should_fail'], row['threat_type']) 
                    for _, row in df.iterrows()]
        else:
            return df.values.tolist()


# ============================================================================
# FUNCTIONAL TESTS FROM EXCEL
# ============================================================================

class TestAdditionFromExcel:
    """Addition tests driven by Excel data"""
    
    @pytest.mark.parametrize("a, b, expected, description", 
                            ExcelTestDataProvider.get_addition_tests())
    def test_addition_from_excel(self, a, b, expected, description):
        """Test addition with data from Excel"""
        result = Calculator.add(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected), f"Failed for: {description}"
        else:
            assert result == expected, f"Failed for: {description}"


class TestSubtractionFromExcel:
    """Subtraction tests driven by Excel data"""
    
    @pytest.mark.parametrize("a, b, expected, description", 
                            ExcelTestDataProvider.get_subtraction_tests())
    def test_subtraction_from_excel(self, a, b, expected, description):
        """Test subtraction with data from Excel"""
        result = Calculator.subtract(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected), f"Failed for: {description}"
        else:
            assert result == expected, f"Failed for: {description}"


class TestMultiplicationFromExcel:
    """Multiplication tests driven by Excel data"""
    
    @pytest.mark.parametrize("a, b, expected, description", 
                            ExcelTestDataProvider.get_multiplication_tests())
    def test_multiplication_from_excel(self, a, b, expected, description):
        """Test multiplication with data from Excel"""
        result = Calculator.multiply(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected), f"Failed for: {description}"
        else:
            assert result == expected, f"Failed for: {description}"


class TestDivisionFromExcel:
    """Division tests driven by Excel data"""
    
    @pytest.mark.parametrize("a, b, expected, description", 
                            ExcelTestDataProvider.get_division_tests())
    def test_division_from_excel(self, a, b, expected, description):
        """Test division with data from Excel"""
        if expected == 'ERROR':
            with pytest.raises(ValueError):
                Calculator.divide(a, b)
        else:
            result = Calculator.divide(a, b)
            if isinstance(expected, float):
                assert result == pytest.approx(expected), f"Failed for: {description}"
            else:
                assert result == expected, f"Failed for: {description}"


# ============================================================================
# SECURITY TESTS FROM EXCEL
# ============================================================================

class TestSecurityFromExcel:
    """Security tests driven by Excel data"""
    
    @pytest.mark.parametrize("input_val, operation, should_fail, threat_type", 
                            ExcelTestDataProvider.get_security_tests())
    def test_security_injection_from_excel(self, input_val, operation, should_fail, threat_type):
        """Test security injection patterns from Excel"""
        try:
            if operation == 'add':
                Calculator.add(input_val, 5)
            elif operation == 'subtract':
                Calculator.subtract(input_val, 5)
            elif operation == 'multiply':
                Calculator.multiply(input_val, 5)
            elif operation == 'divide':
                Calculator.divide(input_val, 5)
            elif operation == 'power':
                Calculator.power(input_val, 2)
            elif operation == 'modulo':
                Calculator.modulo(input_val, 5)
            elif operation == 'square_root':
                Calculator.square_root(input_val)
            elif operation == 'absolute':
                Calculator.absolute(input_val)
            
            # If we reach here and should_fail is True, test failed
            if should_fail:
                pytest.fail(f"Expected failure for {threat_type}: {input_val}")
        except (TypeError, ValueError):
            # Exception raised - this is expected for should_fail=True
            if not should_fail:
                pytest.fail(f"Unexpected failure for {threat_type}: {input_val}")


# ============================================================================
# BOUNDARY TESTS FROM EXCEL
# ============================================================================

class TestBoundaryFromExcel:
    """Boundary tests driven by Excel data"""
    
    @pytest.mark.parametrize("operation, a, b, exception, description", 
                            ExcelTestDataProvider.get_boundary_tests())
    def test_boundary_from_excel(self, operation, a, b, exception, description):
        """Test boundary conditions from Excel"""
        try:
            func = getattr(Calculator, operation)
            
            # Handle single-argument operations
            if operation in ['square_root', 'absolute']:
                result = func(a)
            else:
                result = func(a, b)
            
            # If exception expected, this should have failed
            if exception != 'OK':
                pytest.fail(f"Expected {exception} for: {description}")
            
            assert result is not None, f"Result should not be None: {description}"
        
        except (ValueError, TypeError, ZeroDivisionError) as e:
            if exception == 'OK':
                pytest.fail(f"Unexpected exception {type(e).__name__} for: {description}")
            elif exception not in str(type(e).__name__):
                pytest.fail(f"Expected {exception}, got {type(e).__name__} for: {description}")


# ============================================================================
# PERFORMANCE TESTS FROM EXCEL
# ============================================================================

class TestPerformanceFromExcel:
    """Performance tests driven by Excel data"""
    
    @pytest.mark.parametrize("operation, a, b, max_time, description", 
                            ExcelTestDataProvider.get_performance_tests())
    def test_performance_from_excel(self, operation, a, b, max_time, description):
        """Test performance thresholds from Excel"""
        import time
        
        func = getattr(Calculator, operation)
        
        start = time.time()
        
        try:
            if operation in ['square_root', 'absolute']:
                result = func(a)
            else:
                result = func(a, b)
        except (ValueError, TypeError):
            pytest.skip(f"Operation {operation} raised exception: {description}")
        
        elapsed = time.time() - start
        
        assert elapsed < max_time, \
            f"Performance test failed for {operation}: {elapsed:.4f}s > {max_time}s ({description})"


# ============================================================================
# FILTERED TESTS (By Priority)
# ============================================================================

class TestHighPriorityFromExcel:
    """High priority tests only from Excel"""
    
    @pytest.mark.parametrize("a, b, expected, description", 
                            ExcelTestDataProvider.get_filtered_tests('Addition', priority='HIGH'))
    def test_addition_high_priority(self, a, b, expected, description):
        """Test only HIGH priority addition cases"""
        result = Calculator.add(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected)
        else:
            assert result == expected


class TestCriticalSecurityFromExcel:
    """Critical security tests only from Excel"""
    
    @pytest.mark.parametrize("input_val, operation, should_fail, threat_type", 
                            ExcelTestDataProvider.get_filtered_tests('Security', priority='CRITICAL'))
    def test_security_critical(self, input_val, operation, should_fail, threat_type):
        """Test only CRITICAL priority security cases"""
        try:
            if operation == 'add':
                Calculator.add(input_val, 5)
            else:
                func = getattr(Calculator, operation)
                func(input_val, 5) if operation != 'square_root' else func(input_val)
            
            if should_fail:
                pytest.fail(f"Expected failure for {threat_type}")
        except (TypeError, ValueError):
            if not should_fail:
                pytest.fail(f"Unexpected failure for {threat_type}")


# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_test_report():
    """Generate a summary report of Excel test data"""
    print("\n" + "="*70)
    print("EXCEL-DRIVEN TEST DATA REPORT")
    print("="*70)
    
    sheets = ['Addition', 'Subtraction', 'Multiplication', 'Division', 'Security', 'Boundary', 'Performance']
    
    for sheet in sheets:
        try:
            df = ExcelTestDataProvider._read_sheet(sheet)
            print(f"\n📊 {sheet}:")
            print(f"   Total tests: {len(df)}")
            if 'priority' in df.columns:
                priorities = df['priority'].value_counts().to_dict()
                for priority, count in sorted(priorities.items()):
                    print(f"      - {priority}: {count}")
            if 'category' in df.columns:
                categories = df['category'].value_counts().to_dict()
                print(f"   Categories: {', '.join(f'{k}({v})' for k, v in sorted(categories.items()))}")
        except Exception as e:
            print(f"\n❌ {sheet}: Error - {str(e)}")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    generate_test_report()
