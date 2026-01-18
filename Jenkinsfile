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
                bat 'pip install pytest pytest-cov'
                echo '✓ Dependencies installed'
            }
        }
        
        stage('Test') {
            steps {
                bat '''
                    python -m pytest test_calculator.py ^
                        -v ^
                        --cov=calculator ^
                        --cov-report=xml ^
                        --cov-report=html ^
                        --junit-xml=test-results.xml
                '''
                echo '✓ Tests completed'
            }
        }
    }
    
    post {
        always {
            echo '✓ Publishing test results...'
            junit testResults: 'test-results.xml', allowEmptyResults: true
            archiveArtifacts artifacts: 'htmlcov/**', allowEmptyArchive: true
            echo '✓ Artifacts archived'
        }
        success {
            echo '✓ Pipeline SUCCESS - All tests passed!'
        }
        failure {
            echo '✗ Pipeline FAILED'
        }
    }
}
