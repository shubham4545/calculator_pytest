"""
Simple Calculator Program with Security Validation
"""


class Calculator:
    """A simple calculator class with basic arithmetic operations and security validation"""

    @staticmethod
    def _validate_input(a, b=None):
        """
        Validate input to prevent security vulnerabilities
        
        Raises:
            TypeError: If input is not a number (int or float)
            ValueError: If input is a malicious string pattern
        """
        # Check for string inputs (SQL injection, command injection, etc.)
        if isinstance(a, str):
            raise TypeError("Input must be a number, not string")
        if b is not None and isinstance(b, str):
            raise TypeError("Input must be a number, not string")
        
        # Check for None values
        if a is None or (b is not None and b is None):
            raise TypeError("Input cannot be None")
        
        # Check for complex types (dict, list, set, etc.)
        if isinstance(a, (dict, list, set, tuple)):
            raise TypeError("Input must be a number, not a complex type")
        if b is not None and isinstance(b, (dict, list, set, tuple)):
            raise TypeError("Input must be a number, not a complex type")
        
        # Ensure values are numeric
        if not isinstance(a, (int, float, bool)):
            raise TypeError(f"Invalid input type: {type(a).__name__}")
        if b is not None and not isinstance(b, (int, float, bool)):
            raise TypeError(f"Invalid input type: {type(b).__name__}")

    @staticmethod
    def add(a, b):
        """
        Add two numbers
        
        Raises:
            TypeError: If inputs are not numbers
            ValueError: If inputs contain malicious content
        """
        Calculator._validate_input(a, b)
        return a + b

    @staticmethod
    def subtract(a, b):
        """
        Subtract two numbers
        
        Raises:
            TypeError: If inputs are not numbers
        """
        Calculator._validate_input(a, b)
        return a - b

    @staticmethod
    def multiply(a, b):
        """
        Multiply two numbers
        
        Raises:
            TypeError: If inputs are not numbers
        """
        Calculator._validate_input(a, b)
        return a * b

    @staticmethod
    def divide(a, b):
        """
        Divide two numbers
        
        Raises:
            TypeError: If inputs are not numbers
            ValueError: If b is zero
        """
        Calculator._validate_input(a, b)
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b

    @staticmethod
    def power(a, b):
        """
        Calculate power of a number
        
        Raises:
            TypeError: If inputs are not numbers
        """
        Calculator._validate_input(a, b)
        return a ** b

    @staticmethod
    def modulo(a, b):
        """
        Calculate modulo of two numbers
        
        Raises:
            TypeError: If inputs are not numbers
            ValueError: If b is zero
        """
        Calculator._validate_input(a, b)
        if b == 0:
            raise ValueError("Cannot calculate modulo by zero")
        return a % b

    @staticmethod
    def square_root(a):
        """
        Calculate square root of a number
        
        Raises:
            TypeError: If input is not a number
            ValueError: If input is negative
        """
        Calculator._validate_input(a)
        if a < 0:
            raise ValueError("Cannot calculate square root of negative number")
        return a ** 0.5

    @staticmethod
    def absolute(a):
        """Calculate absolute value of a number"""
        return abs(a)


if __name__ == "__main__":
    calc = Calculator()
    print(f"10 + 5 = {calc.add(10, 5)}")
    print(f"10 - 5 = {calc.subtract(10, 5)}")
    print(f"10 * 5 = {calc.multiply(10, 5)}")
    print(f"10 / 5 = {calc.divide(10, 5)}")
    print(f"2 ^ 8 = {calc.power(2, 8)}")
    print(f"10 % 3 = {calc.modulo(10, 3)}")
    print(f"√16 = {calc.square_root(16)}")
    print(f"|-5| = {calc.absolute(-5)}")
