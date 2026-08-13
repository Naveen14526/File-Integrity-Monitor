# File Integrity Monitoring System (C++)

A defensive cybersecurity project written in C++ that detects file creation, modification, and deletion using SHA-256 hashes.

## Features
- Create a trusted baseline for files in a directory
- Detect created, modified, and deleted files
- SHA-256 hashing through the OpenSSL library
- Save baseline data in a simple text format
- Generate a readable integrity report
- Command-line interface

## Requirements
- C++17 or newer
- OpenSSL development libraries

## Build (Linux)
```bash
g++ -std=c++17 src/fim.cpp -o fim -lcrypto
```

## Usage

Create a baseline:
```bash
./fim baseline data
```

Check integrity:
```bash
./fim check data
```

Save a report:
```bash
./fim check data reports/integrity_report.txt
```

## How it works
1. The baseline command recursively scans regular files.
2. SHA-256 is calculated for every file.
3. Relative file paths and hashes are stored in `data/baseline.db`.
4. The check command calculates the current hashes.
5. Current and baseline records are compared.
6. The program reports CREATED, MODIFIED, and DELETED files.

## Security concept
File Integrity Monitoring is a defensive security control used to identify unexpected changes to important files. This project demonstrates cryptographic hashing, baseline comparison, filesystem traversal, and security reporting.

## Important limitation
This is an educational project. It does not determine whether a detected change was malicious and is not a replacement for enterprise endpoint security software.
