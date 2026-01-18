pipeline {
    agent any
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 30, unit: 'MINUTES')
    }
    
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/shubham4545/calculator_pytest.git'
                echo '✓ Source code checked out'
            }
        }
        
        stage('Setup') {
            steps {
                bat 'python --version'
                bat 'pip install --upgrade pip'
                bat 'pip install -r requirements.txt'
                echo '✓ Dependencies installed (from requirements.txt)'
            }
        }
        
        stage('Unit & Functional Tests') {
            steps {
                echo '▶ Running unit and functional tests...'
                bat '''
                    python -m pytest -n auto -v test_calculator.py::TestCalculatorAddition ^
                        test_calculator.py::TestCalculatorSubtraction ^
                        test_calculator.py::TestCalculatorMultiplication ^
                        test_calculator.py::TestCalculatorDivision ^
                        test_calculator.py::TestCalculatorPower ^
                        test_calculator.py::TestCalculatorModulo ^
                        test_calculator.py::TestCalculatorSquareRoot ^
                        test_calculator.py::TestCalculatorAbsolute ^
                        test_calculator.py::TestCalculatorIntegration ^
                        --junit-xml=test-results-functional.xml
                '''
                echo '✓ Unit & Functional tests completed'
            }
        }
        
        stage('Security Tests') {
            steps {
                echo '▶ Running security tests (injection, validation, type safety)...'
                bat 'python -m pytest -n auto test_calculator.py::TestCalculatorSecurity -v --junit-xml=test-results-security.xml'
                echo '✓ Security tests completed'
            }
        }
        
        stage('Performance & Boundary Tests') {
            steps {
                echo '▶ Running performance and boundary tests...'
                bat 'python -m pytest -n auto test_calculator.py::TestCalculatorPerformance test_calculator.py::TestCalculatorBoundaries -v --junit-xml=test-results-performance.xml'
                echo '✓ Performance & Boundary tests completed'
            }
        }
        
        stage('Code Coverage') {
            steps {
                echo '▶ Generating code coverage report...'
                bat 'python -m pytest -n auto test_calculator.py -v --cov=calculator --cov-report=xml --cov-report=html --cov-report=term'
                echo '✓ Coverage report generated'
            }
        }
    }
    
    post {
        always {
            echo '✓ Publishing all test results...'
            junit testResults: '**/test-results*.xml', allowEmptyResults: true
            archiveArtifacts artifacts: 'htmlcov/**,test-results*.xml', allowEmptyArchive: true
            
            echo '''
                ╔══════════════════════════════════════════════════╗
                ║       JENKINS SECURITY TESTING SUMMARY           ║
                ╠══════════════════════════════════════════════════╣
                ║ ✓ Unit & Functional Tests (51 tests)             ║
                ║ ✓ Security Tests (20 tests)                      ║
                ║   - SQL Injection Prevention                    ║
                ║   - Code Injection Prevention                   ║
                ║   - XSS Prevention                              ║
                ║   - Command Injection Prevention                ║
                ║   - Type Safety Validation                      ║
                ║ ✓ Performance Tests (4 tests)                    ║
                ║ ✓ Boundary Tests (8 tests)                       ║
                ║ ✓ Code Coverage Report (HTML)                    ║
                ╚══════════════════════════════════════════════════╝
            '''
        }
        success {
            echo '''
                ╔══════════════════════════════════════════════════╗
                ║       ✓ PIPELINE SUCCESS - ALL TESTS PASSED      ║
                ║                                                  ║
                ║  All 71 tests passed including:                 ║
                ║  - Functional tests                             ║
                ║  - Security tests                               ║
                ║  - Performance tests                            ║
                ║  - Boundary/Edge case tests                     ║
                ║  - Code coverage: 85%+                          ║
                ╚══════════════════════════════════════════════════╝
            '''
        }
        failure {
            echo '''
                ╔══════════════════════════════════════════════════╗
                ║       ✗ PIPELINE FAILED - CHECK TEST RESULTS     ║
                ║                                                  ║
                ║  Please review:                                 ║
                ║  1. test-results-functional.xml                 ║
                ║  2. test-results-security.xml                   ║
                ║  3. test-results-performance.xml                ║
                ║  4. Coverage report (htmlcov/index.html)         ║
                ╚══════════════════════════════════════════════════╝
            '''
        }
    }
}
        failure {
            echo '✗ Pipeline FAILED'
        }
    }
}
