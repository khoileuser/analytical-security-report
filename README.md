# Cryptographic Algorithms Comparative Analysis - Python Testing Scripts

This package contains three comprehensive Python scripts for analyzing and comparing cryptographic algorithms across three main categories: hashing, symmetric encryption, and asymmetric encryption.

## Overview

### Scripts Included

1. **hashing_analysis.py** - Hashing Algorithm Performance Testing
2. **symmetric_analysis.py** - Symmetric Encryption Performance Testing
3. **asymmetric_analysis.py** - Asymmetric Encryption Performance Testing

Each script performs comprehensive testing including performance metrics, resource consumption analysis, and security characteristics, generating CSV files for data storage and PNG images for visualization.

---

## Installation

Install requirements with:

```bash
python -m venv venv
```

then

```bash
pip install -r requirements.txt
```

---

## Script Descriptions

### 1. Hashing Algorithm Analysis (hashing_analysis.py)

**Algorithms Tested:**

-   MD5 (128-bit)
-   SHA-1 (160-bit)
-   SHA-256 (256-bit)
-   SHA-512 (512-bit)
-   SHA3-256 (256-bit)
-   SHA3-512(512-bit)
-   BLAKE2b (512-bit)

**Tests Performed:**

#### Performance Speed Test

-   Measures hashing throughput across varying data sizes (1KB to 50MB)
-   Calculates average execution time and standard deviation
-   Generates throughput metrics in MBps (Megabytes per second)
-   **Data Sizes:** 1KB, 10KB, 100KB, 1MB, 10MB, 50MB
-   **Iterations:** 100 runs per test

#### Resource Consumption Test

-   Monitors CPU usage during hashing operations
-   Tracks memory consumption (average and peak)
-   Tests on fixed 10MB dataset
-   **Output Metrics:** CPU time (ms), Average memory (MB), Peak memory (MB)

#### Collision Resistance & Avalanche Effect Test

-   Tests avalanche effect (small input changes produce large hash changes)
-   Analyzes output size and distribution
-   Verifies deterministic behavior (same input = same output)
-   Counts differing characters between similar inputs

**Output Files:**

-   `hashing_performance.csv` - Performance metrics
-   `hashing_resources.csv` - Resource consumption data
-   `hashing_collision.csv` - Collision resistance analysis
-   `hashing_performance_chart.png` - 4-panel visualization of performance
-   `hashing_resources_chart.png` - 4-panel visualization of resources
-   `hashing_collision_chart.png` - 4-panel visualization of collision resistance

**Running the Script:**

```bash
python src/hashing_analysis.py
```

Expected output will display test progress and file generation confirmations.

---

### 2. Symmetric Encryption Analysis (symmetric_analysis.py)

**Algorithms Tested:**

-   AES-128 (128-bit key)
-   AES-256 (256-bit key)
-   DES (56-bit key)
-   3DES (64-bit key)
-   Blowfish (64-bit key)

**Tests Performed:**

#### Performance Speed Test

-   Measures encryption and decryption speed across varying data sizes (256B to 10MB)
-   Tests CBC mode with random IVs
-   Calculates individual and combined throughput
-   **Data Sizes:** 256B, 1KB, 10KB, 100KB, 1MB, 10MB
-   **Iterations:** 100 runs per test

#### Resource Consumption Test

-   Monitors CPU and memory usage during encryption/decryption
-   Tests on fixed 10MB dataset
-   Includes full encrypt-then-decrypt cycle
-   **Output Metrics:** CPU time (ms), Average memory (MB), Peak memory (MB)

#### Key Schedule Efficiency Test

-   Measures cipher object creation time (key schedule overhead)
-   Analyzes IV generation
-   Calculates key schedule overhead as percentage of total operation
-   **Output Metrics:** Creation time (microseconds), IV size, Overhead percentage

**Output Files:**

-   `symmetric_performance.csv` - Encryption/decryption performance
-   `symmetric_resources.csv` - Resource consumption data
-   `symmetric_key_schedule.csv` - Key schedule efficiency analysis
-   `symmetric_performance_chart.png` - 4-panel performance visualization
-   `symmetric_resources_chart.png` - 4-panel resource visualization
-   `symmetric_key_schedule_chart.png` - 4-panel key schedule visualization

**Running the Script:**

```bash
python src/symmetric_analysis.py
```

Expected runtime: 5-15 minutes depending on system performance.

---

### 3. Asymmetric Encryption Analysis (asymmetric_analysis.py)

**Algorithms Tested:**

-   RSA-2048
-   RSA-3072
-   ECC-256 (P-256 curve)
-   ECC-384 (P-384 curve)

**Tests Performed:**

#### Key Generation Test

-   Measures time to generate cryptographic key pairs
-   Records key export size in bytes
-   Tests across different key sizes
-   **Iterations:** 20 runs per algorithm

#### Encryption/Decryption Test

-   Tests RSA encryption and decryption performance
-   Measures ciphertext sizes
-   Uses PKCS1-OAEP padding for security
-   **Message Size:** 56 bytes (fixed)
-   **Iterations:** 20 runs per algorithm

#### Digital Signature Test

-   Measures signature generation time (signing)
-   Measures signature verification time
-   Records signature size in bytes
-   Calculates generation/verification time ratio
-   Tests both RSA and ECC signatures
-   **Iterations:** 20 runs per algorithm

#### Resource Consumption Test

-   Monitors CPU and memory usage during key generation
-   Tests on all algorithm variants
-   **Output Metrics:** CPU time (ms), Average memory (MB), Peak memory (MB)

**Output Files:**

-   `asymmetric_performance.csv` - Key generation and encryption performance
-   `asymmetric_signatures.csv` - Digital signature performance
-   `asymmetric_resources.csv` - Resource consumption data
-   `asymmetric_performance_chart.png` - 4-panel performance visualization
-   `asymmetric_signatures_chart.png` - 4-panel signature visualization
-   `asymmetric_resources_chart.png` - 4-panel resource visualization

**Running the Script:**

```bash
python src/asymmetric_analysis.py
```

Expected runtime: 15-45 minutes depending on system performance (RSA key generation is computationally intensive).

---

## Running All Scripts

### Sequential Execution

Run scripts one after another:

```bash
python src/hashing_analysis.py
python src/symmetric_analysis.py
python src/asymmetric_analysis.py
```

### Batch Execution Script

Run with:

```bash
python main.py
```
