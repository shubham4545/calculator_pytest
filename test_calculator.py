"""
Test cases for the Calculator class using pytest
"""

import pytest
from calculator import Calculator


class TestCalculatorAddition:
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
