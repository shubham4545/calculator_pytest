# Simple Calculator Application

A simple Python calculator with comprehensive unit tests using pytest and CI/CD integration with Jenkins.

## Features

- Basic arithmetic operations: Add, Subtract, Multiply, Divide
- Advanced operations: Power, Modulo
- Comprehensive error handling
- Full test coverage with pytest
- Jenkins CI/CD pipeline with test reports

## Project Structure

```
.
├── calculator.py          # Main calculator class
├── test_calculator.py     # Pytest test cases
├── Jenkinsfile           # Jenkins pipeline configuration
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

## Installation

### Prerequisites
- Python 3.7+
- pip
- pytest

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd Automation Testing
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Run the Calculator

```bash
python calculator.py
```

### Run Tests Locally

```bash
# Run all tests
pytest test_calculator.py -v

# Run tests with coverage report
pytest test_calculator.py -v --cov=calculator --cov-report=html

# Run specific test class
pytest test_calculator.py::TestCalculatorAddition -v
```

## Calculator Operations

- **add(a, b)** - Adds two numbers
- **subtract(a, b)** - Subtracts two numbers
- **multiply(a, b)** - Multiplies two numbers
- **divide(a, b)** - Divides two numbers (raises ValueError if divisor is 0)
- **power(a, b)** - Calculates power (a^b)
- **modulo(a, b)** - Calculates modulo (raises ValueError if divisor is 0)

## Test Coverage

The project includes 25+ test cases covering:
- ✓ Positive number operations
- ✓ Negative number operations
- ✓ Mixed operations
- ✓ Edge cases (zero, division by zero)
- ✓ Error handling
- ✓ Integration tests

## Jenkins Integration

The `Jenkinsfile` contains the CI/CD pipeline configuration that:
1. Checks out source code
2. Sets up Python environment
3. Installs dependencies
4. Runs tests with coverage
5. Generates test and coverage reports
6. Publishes reports to Jenkins dashboard

### Pipeline Stages
- **Checkout** - Clone repository
- **Setup Python Environment** - Install required packages
- **Run Tests with Coverage** - Execute pytest with coverage metrics
- **Generate Test Report** - Process test results

### Reports Generated
- JUnit XML test results
- HTML code coverage report
- Console output

## Continuous Integration

This project is configured for continuous integration with Jenkins. Push changes to the repository and Jenkins will automatically:
1. Run all test cases
2. Generate coverage reports
3. Display results in the dashboard
4. Notify on failures

## Author

Created for automation testing demonstration
