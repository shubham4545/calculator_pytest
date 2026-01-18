pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                echo 'Source code checked out successfully'
            }
        }

        stage('Setup Python Environment') {
            steps {
                script {
                    echo 'Setting up Python environment...'
                    sh 'python --version'
                    sh 'pip install --upgrade pip'
                    sh 'pip install pytest pytest-cov'
                }
            }
        }

        stage('Run Tests with Coverage') {
            steps {
                script {
                    echo 'Running pytest tests with coverage...'
                    sh '''
                        pytest test_calculator.py \
                            --verbose \
                            --cov=calculator \
                            --cov-report=xml \
                            --cov-report=html \
                            --junit-xml=test-results.xml \
                            --tb=short
                    '''
                }
            }
        }

        stage('Generate Test Report') {
            steps {
                script {
                    echo 'Test report generated successfully'
                }
            }
        }
    }

    post {
        always {
            script {
                echo 'Publishing test results...'
                // Publish JUnit test results
                junit testResults: 'test-results.xml', 
                      allowEmptyResults: true,
                      healthScaleFactor: 100.0
                
                // Publish coverage report
                publishHTML([
                    reportDir: 'htmlcov',
                    reportFiles: 'index.html',
                    reportName: 'Code Coverage Report'
                ])
            }
        }

        success {
            echo '✓ Pipeline completed successfully - All tests passed!'
        }

        failure {
            echo '✗ Pipeline failed - Tests did not pass'
        }

        unstable {
            echo '⚠ Pipeline unstable - Some tests failed'
        }
    }
}
