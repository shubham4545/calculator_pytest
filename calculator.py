"""
Simple Calculator Program
"""


class Calculator:
    """A simple calculator class with basic arithmetic operations"""

    @staticmethod
    def add(a, b):
        """Add two numbers"""
        return a + b

    @staticmethod
    def subtract(a, b):
        """Subtract two numbers"""
        return a - b

    @staticmethod
    def multiply(a, b):
        """Multiply two numbers"""
        return a * b

    @staticmethod
    def divide(a, b):
        """Divide two numbers"""
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a / b

    @staticmethod
    def power(a, b):
        """Calculate power of a number"""
        return a ** b

    @staticmethod
    def modulo(a, b):
        """Calculate modulo of two numbers"""
        if b == 0:
            raise ValueError("Cannot calculate modulo by zero")
        return a % b


if __name__ == "__main__":
    calc = Calculator()
    print(f"10 + 5 = {calc.add(10, 5)}")
    print(f"10 - 5 = {calc.subtract(10, 5)}")
    print(f"10 * 5 = {calc.multiply(10, 5)}")
    print(f"10 / 5 = {calc.divide(10, 5)}")
    print(f"2 ^ 8 = {calc.power(2, 8)}")
    print(f"10 % 3 = {calc.modulo(10, 3)}")
