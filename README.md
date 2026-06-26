# File Hash Analyzer with VirusTotal Integration

A Python-based cybersecurity tool that calculates file hashes (MD5, SHA-1, and SHA-256) and integrates with the VirusTotal API to identify malicious and suspicious files.

## Features

* Calculate **MD5**, **SHA-1**, and **SHA-256** hashes
* Display human-readable file size
* Query the VirusTotal API using SHA-256 hashes
* Detect malicious and suspicious files
* Handle API rate limiting and network errors
* Secure API key management using environment variables
* Comprehensive exception handling

---

## Project Structure

```text
file-hash-analyzer/
│
├── hashanalyzer.py
├── requirements.txt
├── README.md
├── .gitignore
├── LICENSE
│
├── screenshots/
│   ├── hash_output.png
│   └── virustotal_output.png
│
└── examples/
    └── sample_output.txt
```

---

## Technologies Used

* Python 3
* hashlib
* requests
* VirusTotal API v3

---

## Installation

### Clone the repository

```bash
git clone https://github.com/KShrey00/virustotal-hash-analyzer.git
cd file-hash-analyzer
```

### Create a virtual environment (optional)

```bash
python -m venv venv
```

Activate the environment:

**Windows**

```cmd
venv\Scripts\activate
```

**Linux/macOS**

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Configure VirusTotal API

Obtain a free API key from VirusTotal and set it as an environment variable.

### Linux/macOS

```bash
export VIRUSTOTAL_API_KEY="YOUR_API_KEY"
```

### Windows Command Prompt

```cmd
set VIRUSTOTAL_API_KEY=YOUR_API_KEY
```

### Windows PowerShell

```powershell
$env:VIRUSTOTAL_API_KEY="YOUR_API_KEY"
```

---

## Usage

Run the script and provide a file path:

```bash
python hashanalyzer.py <filepath>
```

Example:

```bash
python hashanalyzer.py sample.exe
```

---

## Example Output

```text
======================================================================
File Hash Analyzer
======================================================================
File: hello.txt
Size: 5.00 B
======================================================================

MD5:
5d41402abc4b2a76b9719d911017c592

SHA-1:
aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d

SHA-256:
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

======================================================================
VirusTotal Results
======================================================================
Status: CLEAN
```

---

## Workflow

1. Accept a target file as input
2. Calculate MD5, SHA-1, and SHA-256 hashes
3. Retrieve file size information
4. Query the VirusTotal API using the SHA-256 hash
5. Parse detection statistics
6. Display malware analysis results

---

## Error Handling

The application handles:

* File not found errors
* Permission errors
* Invalid API keys
* VirusTotal API rate limits
* Network connection failures
* Request timeouts
* Unexpected API responses

---

## Security Features

* API keys are stored using environment variables
* No sensitive information is hardcoded
* SHA-256 is used for malware reputation lookup
* Robust exception handling prevents application crashes

---

## Future Improvements

* Batch file scanning
* JSON report export
* PDF report generation
* Colored terminal output
* Multi-threaded scanning
* File upload support to VirusTotal
* Integration with YARA rules
* Threat intelligence enrichment

---

## Learning Outcomes

This project demonstrates:

* Python file handling
* Cryptographic hashing
* REST API integration
* JSON parsing
* Exception handling
* Environment variable management
* Cybersecurity threat intelligence workflows

---

## License

This project is licensed under the MIT License.

---

## Author

**Shreya Kumari**

Cybersecurity Enthusiast | Computer Science Student
