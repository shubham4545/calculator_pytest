# 📊 Excel-Driven Parameterized Testing Guide

## Overview

This project now supports **Excel-based parameterized testing**, enabling data-driven test automation without modifying Python code. Test data is centralized in `test_data/calculator_tests.xlsx` with separate sheets for different test categories.

## Why Excel-Based Testing? 🎯

| Benefit | Impact |
|---------|--------|
| **Separation of Concerns** | Test logic stays in Python, data lives in Excel |
| **Non-Developer Friendly** | QA teams can add test cases without coding skills |
| **Easier Maintenance** | Change data once, all tests use updated values |
| **Traceability** | TestID, author, date, priority built into each row |
| **Scalability** | Add 100 test cases in minutes (drag & drop) |
| **CI/CD Integration** | Automatic validation before each test run |

---

## Project Structure

```
Automation Testing/
├── test_data/                              # Test data directory
│   ├── calculator_tests.xlsx              # Main Excel test data file
│   ├── backups/                           # Automatic backups (timestamped)
│   └── .metadata.json                     # Metadata tracking
├── test_excel_driven.py                   # Excel-based test classes
├── scripts/
│   ├── generate_excel_test_data.py       # Generate initial Excel files
│   └── manage_excel_data.py               # Manage/validate Excel data
├── test_calculator.py                     # Original hardcoded tests
├── Jenkinsfile                            # Updated with Excel-driven tests
└── .github/workflows/main.yml             # GitHub Actions with Excel validation
```

---

## Excel File Structure 📋

### Main File: `test_data/calculator_tests.xlsx`

**7 Sheets, 51 Total Test Cases:**

#### Sheet 1: Addition (8 tests)
```
| TestID | a    | b    | expected | category    | priority | description          | author   | date       |
|--------|------|------|----------|-------------|----------|----------------------|----------|------------|
| ADD-001| 5    | 3    | 8        | functional  | HIGH     | Positive numbers     | Shubham  | 2026-01-20 |
| ADD-002| -5   | -3   | -8       | functional  | HIGH     | Negative numbers     | Shubham  | 2026-01-20 |
| ...    | ...  | ...  | ...      | ...         | ...      | ...                  | ...      | ...        |
```

#### Sheet 2: Subtraction (7 tests)
#### Sheet 3: Multiplication (8 tests)
#### Sheet 4: Division (9 tests)
#### Sheet 5: Security (7 tests)
```
| TestID | input           | operation | should_fail | category | priority   | threat_type      | author   | date       |
|--------|-----------------|-----------|-------------|----------|------------|------------------|----------|------------|
| SEC-001| 5' OR '1'='1   | add       | TRUE        | security | CRITICAL   | SQL Injection    | Shubham  | 2026-01-20 |
| SEC-002| __import__(...) | subtract  | TRUE        | security | CRITICAL   | Code Injection   | Shubham  | 2026-01-20 |
```

#### Sheet 6: Boundary (8 tests)
#### Sheet 7: Performance (4 tests)

---

## Quick Start 🚀

### 1. View Test Data

```bash
# Show metadata and summary
python scripts/manage_excel_data.py info

# Output:
# ✓ 51 total test cases
# ✓ 7 sheets with full structure
# ✓ Priorities: CRITICAL, HIGH, MEDIUM, LOW
```

### 2. Validate Excel Data

```bash
# Run validation checks
python scripts/manage_excel_data.py validate

# Checks:
# ✓ File exists
# ✓ All required sheets present
# ✓ No empty rows
# ✓ No null values in critical columns
# ✓ Minimum test count (40+)
```

### 3. Run Excel-Driven Tests

```bash
# Run all Excel tests
python -m pytest test_excel_driven.py -v

# Output:
# TestAdditionFromExcel::test_addition_from_excel[5-3-8-Positive numbers] PASSED
# TestAdditionFromExcel::test_addition_from_excel[-5--3--8-Negative numbers] PASSED
# ...
# ✅ 59 passed in 2.73s
```

### 4. Run Specific Category

```bash
# Addition tests only
python -m pytest test_excel_driven.py::TestAdditionFromExcel -v

# Security tests only
python -m pytest test_excel_driven.py::TestSecurityFromExcel -v

# Excel tests + original tests + parallel execution
python -m pytest test_calculator.py test_excel_driven.py -n auto -v
```

### 5. Backup Current Data

```bash
python scripts/manage_excel_data.py backup

# Creates timestamped backup: test_data/backups/calculator_tests_backup_20260120_144500.xlsx
```

---

## Test Classes 🧪

### Available Test Classes

```python
# Functional Tests
TestAdditionFromExcel              # 8 tests
TestSubtractionFromExcel           # 7 tests
TestMultiplicationFromExcel        # 8 tests
TestDivisionFromExcel              # 9 tests

# Security Tests
TestSecurityFromExcel              # 7 tests (injection patterns)

# Boundary Tests
TestBoundaryFromExcel              # 8 tests (edge cases)

# Performance Tests
TestPerformanceFromExcel           # 4 tests (timing checks)

# Filtered Tests (High Priority Only)
TestHighPriorityFromExcel          # HIGH priority tests
TestCriticalSecurityFromExcel      # CRITICAL security tests
```

---

## Adding New Test Cases 📝

### Method 1: Open Excel File

1. Open `test_data/calculator_tests.xlsx` in Excel/Google Sheets
2. Go to appropriate sheet (Addition, Security, etc.)
3. Add new row with test data:
   ```
   | TestID | a | b | expected | category | priority | description | author | date |
   |--------|---|---|----------|----------|----------|-------------|--------|------|
   | ADD-009| 7 | 8 | 15       | functional| HIGH    | New test    | You    | Now  |
   ```
4. Save file
5. Next test run automatically includes new test case

### Method 2: Programmatic

```python
import pandas as pd

# Read existing data
df = pd.read_excel('test_data/calculator_tests.xlsx', sheet_name='Addition')

# Add new row
new_row = {
    'TestID': 'ADD-009',
    'a': 7,
    'b': 8,
    'expected': 15,
    'category': 'functional',
    'priority': 'HIGH',
    'description': 'New test case',
    'author': 'Your Name',
    'date': pd.Timestamp.now().date()
}

df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)

# Write back
with pd.ExcelWriter('test_data/calculator_tests.xlsx', engine='openpyxl') as writer:
    df.to_excel(writer, sheet_name='Addition', index=False)
```

---

## Filtering Tests by Priority 🎯

### Run Only HIGH Priority Tests

```bash
python -m pytest test_excel_driven.py::TestHighPriorityFromExcel -v
```

### Run Only CRITICAL Security Tests

```bash
python -m pytest test_excel_driven.py::TestCriticalSecurityFromExcel -v
```

### In Excel Data Provider

```python
# Get HIGH priority tests
high_priority = ExcelTestDataProvider.get_filtered_tests('Addition', priority='HIGH')

# Get CRITICAL security tests
critical = ExcelTestDataProvider.get_filtered_tests('Security', priority='CRITICAL')
```

---

## CI/CD Integration 🔄

### Jenkins Pipeline

```groovy
stage('Excel-Driven Tests') {
    steps {
        // Validate Excel structure
        bat 'python scripts/manage_excel_data.py validate'
        
        // Show metadata
        bat 'python scripts/manage_excel_data.py info'
        
        // Run tests
        bat 'python -m pytest -n auto test_excel_driven.py -v --junit-xml=test-results-excel.xml'
    }
}
```

### GitHub Actions

```yaml
- name: Validate Excel Test Data
  run: |
    python scripts/manage_excel_data.py validate
    python scripts/manage_excel_data.py info

- name: Run Excel-Driven Tests
  run: |
    python -m pytest -n auto test_excel_driven.py \
      -v --junitxml=tests-excel.xml
```

---

## Data Sync from Cloud ☁️

### Option 1: GitHub Release

```bash
# Download from GitHub releases
curl -L -o test_data/calculator_tests.xlsx \
  https://github.com/shubham4545/calculator_pytest/releases/download/v1.0/calculator_tests.xlsx

# Validate downloaded file
python scripts/manage_excel_data.py validate
```

### Option 2: GitHub Actions Artifact

1. Upload Excel file as artifact in workflow
2. Download before running tests:
```yaml
- name: Download test data
  uses: actions/download-artifact@v4
  with:
    name: excel-test-data
    path: test_data/
```

### Option 3: Google Drive/OneDrive

```python
# Use gdown library for Google Drive
import gdown

gdown.download(
    'https://drive.google.com/uc?id=YOUR_FILE_ID',
    'test_data/calculator_tests.xlsx',
    quiet=False
)

# Validate
os.system('python scripts/manage_excel_data.py validate')
```

---

## Troubleshooting 🔧

### Problem: "Excel file not found"

**Solution:**
```bash
# Generate fresh Excel file
python scripts/generate_excel_test_data.py

# Verify
python scripts/manage_excel_data.py info
```

### Problem: "Missing sheets error"

**Solution:**
```bash
# Check which sheets exist
python scripts/manage_excel_data.py validate

# Regenerate if corrupted
python scripts/generate_excel_test_data.py
```

### Problem: "Test data validation failed"

**Solution:**
```bash
# Create backup of current file
python scripts/manage_excel_data.py backup

# Check against latest backup
python scripts/manage_excel_data.py compare

# Regenerate from scratch
python scripts/generate_excel_test_data.py
```

### Problem: "Null byte character error"

**Solution:** Characters like `\x00` cannot be stored in Excel. Use string representation instead:
```python
# ❌ Don't use:
"5\x00injection"

# ✅ Use instead:
"5null-byte-injection"
```

---

## Commands Reference 📚

```bash
# View metadata
python scripts/manage_excel_data.py info

# Validate structure and data quality
python scripts/manage_excel_data.py validate

# Create timestamped backup
python scripts/manage_excel_data.py backup

# Compare with latest backup
python scripts/manage_excel_data.py compare

# Setup cloud sync (documentation)
python scripts/manage_excel_data.py sync

# Generate initial Excel files
python scripts/generate_excel_test_data.py

# Run all Excel-driven tests
python -m pytest test_excel_driven.py -v

# Run specific category
python -m pytest test_excel_driven.py::TestAdditionFromExcel -v

# Run with parallel execution
python -m pytest test_excel_driven.py -n auto -v

# Run with coverage
python -m pytest test_excel_driven.py --cov=calculator --cov-report=html

# Generate report
python -m pytest test_excel_driven.py --html=report.html --self-contained-html
```

---

## Performance Metrics 📊

**Test Execution Time:**
```
Hardcoded tests (155 tests):     6.08s (parallel)
Excel-driven tests (59 tests):    2.73s (parallel)
Combined (214 tests):             8.81s (parallel)
Sequential (for comparison):     15-20s
```

**Parallel Speedup:** 2-3x faster than sequential execution

---

## Best Practices ✅

1. **Always validate** before running tests:
   ```bash
   python scripts/manage_excel_data.py validate
   ```

2. **Use meaningful TestIDs** (e.g., `ADD-001`, `SEC-005`)

3. **Add descriptions** for easy identification in reports

4. **Set priorities** to enable filtering during CI/CD

5. **Include author** and date for traceability

6. **Create backups** before major changes:
   ```bash
   python scripts/manage_excel_data.py backup
   ```

7. **Test locally** before pushing:
   ```bash
   python -m pytest test_excel_driven.py -v
   ```

---

## Summary

✅ **51 test cases** stored in Excel  
✅ **Non-developers** can add test cases  
✅ **Fully integrated** with CI/CD (Jenkins + GitHub Actions)  
✅ **Automatic validation** on each run  
✅ **Cloud-ready** (support for sync from GitHub/Drive)  
✅ **Parallel execution** supported (2-3x faster)  
✅ **Comprehensive management** tools included  

**Next Step:** Use `python -m pytest test_excel_driven.py -v` to run all Excel-driven tests! 🎯
