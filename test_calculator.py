"""
Test cases for the Calculator class using pytest
"""

import pytest
import time
from calculator import Calculator


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def calculator():
    """Fixture: Provides a Calculator instance"""
    return Calculator()


@pytest.fixture
def sample_numbers():
    """Fixture: Provides sample numbers for testing"""
    return {
        'positive': (5, 3),
        'negative': (-5, -3),
        'mixed': (5, -3),
        'with_zero': (5, 0),
        'large': (1e100, 1e100),
        'small': (1e-100, 1e-100),
    }


@pytest.fixture
def performance_timer():
    """Fixture: Provides a context manager for performance timing"""
    class Timer:
        def __init__(self):
            self.start_time = None
            self.elapsed = None
        
        def __enter__(self):
            self.start_time = time.time()
            return self
        
        def __exit__(self, *args):
            self.elapsed = time.time() - self.start_time
        
        def assert_under(self, max_seconds):
            assert self.elapsed < max_seconds, f"Execution took {self.elapsed}s, expected < {max_seconds}s"
    
    return Timer()


@pytest.fixture
def malicious_inputs():
    """Fixture: Provides malicious input patterns for security testing"""
    return [
        "5' OR '1'='1",  # SQL injection
        "__import__('os').system('rm -rf /')",  # Code injection
        "<script>alert('XSS')</script>",  # XSS
        "; DROP TABLE users;",  # Command injection
        "你好123",  # Unicode/encoding
        "5\x00injection",  # Null byte
        "9" * 10000,  # Buffer overflow
        None,  # None value
        [10],  # List
        {"value": 16},  # Dict
    ]


# ============================================================================
# PARAMETERIZED TESTS
# ============================================================================

class TestCalculatorAdditionParametrized:
    """Parameterized tests for addition operation"""
    
    @pytest.mark.parametrize("a, b, expected", [
        (5, 3, 8),
        (-5, -3, -8),
        (5, -3, 2),
        (0, 5, 5),
        (100, 200, 300),
        (0, 0, 0),
        (-1, 1, 0),
        (1.5, 2.5, 4.0),
    ])
    def test_add_various_numbers(self, a, b, expected):
        """Parameterized: Test addition with various number combinations"""
        result = Calculator.add(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected)
        else:
            assert result == expected


class TestCalculatorSubtractionParametrized:
    """Parameterized tests for subtraction operation"""
    
    @pytest.mark.parametrize("a, b, expected", [
        (10, 3, 7),
        (-5, -3, -2),
        (5, -3, 8),
        (5, 0, 5),
        (0, 5, -5),
        (100, 100, 0),
        (3.5, 1.5, 2.0),
    ])
    def test_subtract_various_numbers(self, a, b, expected):
        """Parameterized: Test subtraction with various number combinations"""
        result = Calculator.subtract(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected)
        else:
            assert result == expected


class TestCalculatorMultiplicationParametrized:
    """Parameterized tests for multiplication operation"""
    
    @pytest.mark.parametrize("a, b, expected", [
        (5, 3, 15),
        (-5, -3, 15),
        (5, -3, -15),
        (5, 0, 0),
        (0, 0, 0),
        (10, 10, 100),
        (2.5, 4, 10.0),
        (-1, -1, 1),
    ])
    def test_multiply_various_numbers(self, a, b, expected):
        """Parameterized: Test multiplication with various number combinations"""
        result = Calculator.multiply(a, b)
        if isinstance(expected, float):
            assert result == pytest.approx(expected)
        else:
            assert result == expected


class TestCalculatorDivisionParametrized:
    """Parameterized tests for division operation"""
    
    @pytest.mark.parametrize("a, b, expected", [
        (10, 2, 5),
        (-10, -2, 5),
        (10, -2, -5),
        (5, 2, 2.5),
        (1, 3, pytest.approx(0.333333, rel=0.01)),
        (100, 10, 10),
    ])
    def test_divide_various_numbers(self, a, b, expected):
        """Parameterized: Test division with various number combinations"""
        result = Calculator.divide(a, b)
        assert result == expected
    
    @pytest.mark.parametrize("a, b", [
        (10, 0),
        (0, 0),
        (-5, 0),
    ])
    def test_divide_by_zero_various(self, a, b):
        """Parameterized: Test division by zero raises ValueError"""
        with pytest.raises(ValueError):
            Calculator.divide(a, b)


class TestCalculatorPowerParametrized:
    """Parameterized tests for power operation"""
    
    @pytest.mark.parametrize("base, exponent, expected", [
        (2, 3, 8),
        (5, 0, 1),
        (2, -2, 0.25),
        (10, 2, 100),
        (-2, 2, 4),
        (-2, 3, -8),
        (1, 100, 1),
    ])
    def test_power_various_bases_exponents(self, base, exponent, expected):
        """Parameterized: Test power with various bases and exponents"""
        result = Calculator.power(base, exponent)
        assert result == pytest.approx(expected)


class TestCalculatorModuloParametrized:
    """Parameterized tests for modulo operation"""
    
    @pytest.mark.parametrize("a, b, expected", [
        (10, 3, 1),
        (-10, 3, 2),
        (0, 5, 0),
        (7, 7, 0),
        (15, 4, 3),
    ])
    def test_modulo_various_numbers(self, a, b, expected):
        """Parameterized: Test modulo with various number combinations"""
        result = Calculator.modulo(a, b)
        assert result == expected
    
    @pytest.mark.parametrize("a, b", [
        (10, 0),
        (0, 0),
        (-5, 0),
    ])
    def test_modulo_by_zero_various(self, a, b):
        """Parameterized: Test modulo by zero raises ValueError"""
        with pytest.raises(ValueError):
            Calculator.modulo(a, b)


class TestCalculatorSquareRootParametrized:
    """Parameterized tests for square root operation"""
    
    @pytest.mark.parametrize("value, expected", [
        (16, 4),
        (25, 5),
        (0, 0),
        (1, 1),
        (4, 2),
        (2, pytest.approx(1.414, rel=0.01)),
        (100, 10),
    ])
    def test_square_root_various_values(self, value, expected):
        """Parameterized: Test square root with various values"""
        result = Calculator.square_root(value)
        assert result == expected
    
    @pytest.mark.parametrize("negative_value", [
        -1,
        -4,
        -16,
        -0.5,
    ])
    def test_square_root_negative_various(self, negative_value):
        """Parameterized: Test square root of negative numbers raises ValueError"""
        with pytest.raises(ValueError):
            Calculator.square_root(negative_value)


class TestCalculatorAbsoluteParametrized:
    """Parameterized tests for absolute value operation"""
    
    @pytest.mark.parametrize("value, expected", [
        (5, 5),
        (-5, 5),
        (0, 0),
        (-3.14, pytest.approx(3.14)),
        (3.14, 3.14),
        (-100, 100),
        (100, 100),
    ])
    def test_absolute_various_values(self, value, expected):
        """Parameterized: Test absolute value with various values"""
        result = Calculator.absolute(value)
        assert result == expected


class TestCalculatorSecurityParametrized:
    """Parameterized security tests for injection prevention"""
    
    @pytest.mark.parametrize("malicious_input", [
        "5' OR '1'='1",  # SQL injection
        "__import__('os').system('rm -rf /')",  # Code injection
        "<script>alert('XSS')</script>",  # XSS
        "; DROP TABLE users;",  # Command injection
        "你好123",  # Unicode/encoding
        "5\x00injection",  # Null byte
    ])
    def test_string_injection_rejection(self, malicious_input):
        """Parameterized: Test string injection attempts are rejected"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add(malicious_input, 5)
    
    @pytest.mark.parametrize("malicious_input", [
        None,
        [10],
        {"value": 16},
        (1, 2),
        {1, 2, 3},
    ])
    def test_type_injection_rejection(self, malicious_input):
        """Parameterized: Test non-numeric type attempts are rejected"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add(malicious_input, 5)
    
    @pytest.mark.parametrize("function, args", [
        (Calculator.multiply, ("5 + 5", 2)),
        (Calculator.divide, ("10/2", 1)),
        (Calculator.power, ("2", "10")),
        (Calculator.modulo, ([10], 3)),
        (Calculator.square_root, ({"value": 16},)),
        (Calculator.absolute, (["value"],)),
    ])
    def test_operation_type_validation(self, function, args):
        """Parameterized: Test all operations validate input types"""
        with pytest.raises((TypeError, ValueError)):
            function(*args)


class TestCalculatorBoundariesParametrized:
    """Parameterized boundary and edge case tests"""
    
    @pytest.mark.parametrize("operation, a, b, exception_type", [
        (Calculator.divide, 5, 0, ValueError),
        (Calculator.modulo, 10, 0, ValueError),
    ])
    def test_zero_divisor_rejection(self, operation, a, b, exception_type):
        """Parameterized: Test zero divisor rejection across operations"""
        with pytest.raises(exception_type):
            operation(a, b)
    
    @pytest.mark.parametrize("large_value", [
        1e308,
        -1e308,
        1.7976931348623157e+308,
        -1.7976931348623157e+308,
    ])
    def test_extreme_values_handling(self, large_value):
        """Parameterized: Test extreme value handling"""
        result = Calculator.add(large_value, 0)
        assert result == large_value
    
    @pytest.mark.parametrize("special_value", [
        float('inf'),
        float('-inf'),
    ])
    def test_special_float_values(self, special_value):
        """Parameterized: Test special float value handling"""
        result = Calculator.add(special_value, 1)
        assert result == special_value



    """Test cases for addition operation"""

    def test_add_positive_numbers(self):
        """Test addition of two positive numbers"""
        assert Calculator.add(5, 3) == 8

    def test_add_negative_numbers(self):
        """Test addition of two negative numbers"""
        assert Calculator.add(-5, -3) == -8

    def test_add_mixed_numbers(self):
        """Test addition of positive and negative numbers"""
        assert Calculator.add(5, -3) == 2

    def test_add_zero(self):
        """Test addition with zero"""
        assert Calculator.add(0, 5) == 5


class TestCalculatorSubtraction:
    """Test cases for subtraction operation"""

    def test_subtract_positive_numbers(self):
        """Test subtraction of two positive numbers"""
        assert Calculator.subtract(10, 3) == 7

    def test_subtract_negative_numbers(self):
        """Test subtraction of two negative numbers"""
        assert Calculator.subtract(-5, -3) == -2

    def test_subtract_mixed_numbers(self):
        """Test subtraction of positive and negative numbers"""
        assert Calculator.subtract(5, -3) == 8

    def test_subtract_zero(self):
        """Test subtraction with zero"""
        assert Calculator.subtract(5, 0) == 5


class TestCalculatorMultiplication:
    """Test cases for multiplication operation"""

    def test_multiply_positive_numbers(self):
        """Test multiplication of two positive numbers"""
        assert Calculator.multiply(5, 3) == 15

    def test_multiply_negative_numbers(self):
        """Test multiplication of two negative numbers"""
        assert Calculator.multiply(-5, -3) == 15

    def test_multiply_mixed_numbers(self):
        """Test multiplication of positive and negative numbers"""
        assert Calculator.multiply(5, -3) == -15

    def test_multiply_by_zero(self):
        """Test multiplication by zero"""
        assert Calculator.multiply(5, 0) == 0


class TestCalculatorDivision:
    """Test cases for division operation"""

    def test_divide_positive_numbers(self):
        """Test division of two positive numbers"""
        assert Calculator.divide(10, 2) == 5

    def test_divide_negative_numbers(self):
        """Test division of two negative numbers"""
        assert Calculator.divide(-10, -2) == 5

    def test_divide_mixed_numbers(self):
        """Test division of positive and negative numbers"""
        assert Calculator.divide(10, -2) == -5

    def test_divide_by_zero(self):
        """Test division by zero raises ValueError"""
        with pytest.raises(ValueError):
            Calculator.divide(10, 0)

    def test_divide_result_float(self):
        """Test division resulting in float"""
        assert Calculator.divide(5, 2) == 2.5


class TestCalculatorPower:
    """Test cases for power operation"""

    def test_power_positive_numbers(self):
        """Test power of positive numbers"""
        assert Calculator.power(2, 3) == 8

    def test_power_zero_exponent(self):
        """Test power with zero exponent"""
        assert Calculator.power(5, 0) == 1

    def test_power_negative_exponent(self):
        """Test power with negative exponent"""
        assert Calculator.power(2, -2) == 0.25


class TestCalculatorModulo:
    """Test cases for modulo operation"""

    def test_modulo_positive_numbers(self):
        """Test modulo of two positive numbers"""
        assert Calculator.modulo(10, 3) == 1

    def test_modulo_negative_numbers(self):
        """Test modulo with negative numbers"""
        assert Calculator.modulo(-10, 3) == 2

    def test_modulo_by_zero(self):
        """Test modulo by zero raises ValueError"""
        with pytest.raises(ValueError):
            Calculator.modulo(10, 0)

    def test_modulo_zero(self):
        """Test modulo of zero"""
        assert Calculator.modulo(0, 5) == 0


class TestCalculatorSquareRoot:
    """Test cases for square root operation"""

    def test_square_root_perfect_square(self):
        """Test square root of perfect square"""
        assert Calculator.square_root(16) == 4

    def test_square_root_positive_number(self):
        """Test square root of positive number"""
        assert Calculator.square_root(2) == pytest.approx(1.414, rel=0.01)

    def test_square_root_zero(self):
        """Test square root of zero"""
        assert Calculator.square_root(0) == 0

    def test_square_root_one(self):
        """Test square root of one"""
        assert Calculator.square_root(1) == 1

    def test_square_root_negative_number(self):
        """Test square root of negative number raises ValueError"""
        with pytest.raises(ValueError):
            Calculator.square_root(-4)


class TestCalculatorAbsolute:
    """Test cases for absolute value operation"""

    def test_absolute_positive_number(self):
        """Test absolute value of positive number"""
        assert Calculator.absolute(5) == 5

    def test_absolute_negative_number(self):
        """Test absolute value of negative number"""
        assert Calculator.absolute(-5) == 5

    def test_absolute_zero(self):
        """Test absolute value of zero"""
        assert Calculator.absolute(0) == 0

    def test_absolute_float(self):
        """Test absolute value of float"""
        assert Calculator.absolute(-3.14) == pytest.approx(3.14)


# Integration tests
class TestCalculatorIntegration:
    """Integration tests for multiple operations"""

    def test_combined_operations(self):
        """Test combining multiple operations"""
        result = Calculator.add(Calculator.multiply(2, 3), 4)
        assert result == 10

    def test_complex_calculation(self):
        """Test complex calculation"""
        calc = Calculator()
        result = calc.divide(calc.add(10, 5), calc.subtract(5, 2))
        assert result == 5.0


# Security testing
class TestCalculatorSecurity:
    """Security tests for input validation and injection prevention"""

    def test_sql_injection_attempt_add(self):
        """Security: Reject SQL injection in add function"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add("5' OR '1'='1", 3)

    def test_sql_injection_attempt_subtract(self):
        """Security: Reject SQL injection in subtract function"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.subtract("10' OR '1'='1", 2)

    def test_code_injection_attempt(self):
        """Security: Reject code injection attempts"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add("__import__('os').system('rm -rf /')", 5)

    def test_xss_injection_attempt(self):
        """Security: Reject XSS injection"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add("<script>alert('XSS')</script>", 3)

    def test_command_injection_attempt(self):
        """Security: Reject command injection"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add("; DROP TABLE users;", 5)

    def test_unicode_encoding_attack(self):
        """Security: Reject unicode/encoding attacks"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add("你好123", 5)

    def test_very_large_number_handling(self):
        """Security: Handle very large numbers safely"""
        result = Calculator.add(1e100, 1e100)
        assert result == 2e100

    def test_very_small_number_handling(self):
        """Security: Handle very small numbers safely"""
        result = Calculator.add(1e-100, 1e-100)
        assert result == pytest.approx(2e-100)

    def test_special_float_inf(self):
        """Security: Handle infinity gracefully"""
        result = Calculator.add(float('inf'), 1)
        assert result == float('inf')

    def test_special_float_negative_inf(self):
        """Security: Handle negative infinity gracefully"""
        result = Calculator.add(float('-inf'), 1)
        assert result == float('-inf')

    def test_string_injection_multiply(self):
        """Security: Multiply rejects string input"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.multiply("5 + 5", 2)

    def test_string_injection_divide(self):
        """Security: Divide rejects string input"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.divide("10/2", 1)

    def test_none_value_injection(self):
        """Security: Handle None values safely"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add(None, 5)

    def test_null_byte_injection(self):
        """Security: Reject null byte injection"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.add("5\x00injection", 3)

    def test_buffer_overflow_long_input(self):
        """Security: Handle extremely long input safely"""
        long_string = "9" * 10000
        with pytest.raises((TypeError, ValueError)):
            Calculator.add(long_string, 5)

    def test_negative_zero_handling(self):
        """Security: Handle negative zero safely"""
        result = Calculator.add(-0.0, 5)
        assert result == 5.0

    def test_type_validation_power(self):
        """Security: Power function validates types"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.power("2", "10")

    def test_type_validation_modulo(self):
        """Security: Modulo function validates types"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.modulo([10], 3)

    def test_type_validation_sqrt(self):
        """Security: Square root function validates types"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.square_root({"value": 16})

    def test_type_validation_absolute(self):
        """Security: Absolute value function validates types"""
        with pytest.raises((TypeError, ValueError)):
            Calculator.absolute(["value"])


# Performance and stress testing
class TestCalculatorPerformance:
    """Performance tests to ensure no DoS vulnerabilities"""

    def test_large_number_multiplication_performance(self):
        """Performance: Large number operations complete quickly"""
        import time
        start = time.time()
        result = Calculator.multiply(1e308, 1)
        elapsed = time.time() - start
        assert elapsed < 1.0  # Should complete in < 1 second
        assert result == 1e308

    def test_many_operations_sequence(self):
        """Performance: Handle sequence of operations efficiently"""
        import time
        start = time.time()
        result = 5
        for _ in range(100):
            result = Calculator.add(result, 1)
        elapsed = time.time() - start
        assert elapsed < 1.0  # 100 operations in < 1 second
        assert result == 105

    def test_division_precision_performance(self):
        """Performance: Division calculations stay fast"""
        import time
        start = time.time()
        for _ in range(100):
            Calculator.divide(10, 3)
        elapsed = time.time() - start
        assert elapsed < 1.0  # 100 divisions in < 1 second

    def test_sqrt_performance(self):
        """Performance: Square root calculations are efficient"""
        import time
        start = time.time()
        for _ in range(100):
            Calculator.square_root(16)
        elapsed = time.time() - start
        assert elapsed < 1.0  # 100 sqrt in < 1 second


# Input boundary testing
class TestCalculatorBoundaries:
    """Boundary and edge case testing for security"""

    def test_zero_division_returns_error(self):
        """Boundary: Zero divisor properly rejected"""
        with pytest.raises(ValueError) as exc_info:
            Calculator.divide(5, 0)
        assert "divide by zero" in str(exc_info.value).lower()

    def test_negative_sqrt_returns_error(self):
        """Boundary: Negative square root properly rejected"""
        with pytest.raises(ValueError) as exc_info:
            Calculator.square_root(-1)
        assert "negative" in str(exc_info.value).lower()

    def test_modulo_zero_returns_error(self):
        """Boundary: Zero modulo properly rejected"""
        with pytest.raises(ValueError) as exc_info:
            Calculator.modulo(10, 0)
        assert "zero" in str(exc_info.value).lower()

    def test_float_precision_edge_case(self):
        """Boundary: Float precision handled correctly"""
        result = Calculator.divide(1, 3)
        assert pytest.approx(result, rel=1e-9) == 0.333333333

    def test_extreme_positive_number(self):
        """Boundary: Maximum positive number handled"""
        result = Calculator.add(1.7976931348623157e+308, 0)
        assert result == 1.7976931348623157e+308

    def test_extreme_negative_number(self):
        """Boundary: Maximum negative number handled"""
        result = Calculator.add(-1.7976931348623157e+308, 0)
        assert result == -1.7976931348623157e+308
