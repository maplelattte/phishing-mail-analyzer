# Phishing Email Analyzer

A lightweight command-line tool written in Python to parse raw email files (`.eml`), extract vital headers, and perform DNS lookups to verify email authentication mechanisms (SPF and DMARC).

## Features

- **Header Extraction**: Parses core email metadata including `From`, `Return-Path`, and `Subject`.
- **SPF Verification**: Queries domain TXT records to check Sender Policy Framework configurations.
- **DMARC Verification**: Validates Domain-based Message Authentication, Reporting, and Conformance records.
- **CLI Interface**: Color-coded terminal output for quick identification of missing or valid configurations.

## Prerequisites

- Python 3.x

## Installation

1. Clone the repository:

```bash
   git clone https://github.com/maplelattte/phishing-email-analyzer.git
   cd phishing-email-analyzer
```

2. Create and activate a virtual environment:

   **Windows (PowerShell):**

```powershell
   python -m venv venv
   venv\Scripts\Activate.ps1
```

   **Linux / macOS:**

```bash
   python3 -m venv venv
   source venv/bin/activate
```

3. Install the required dependencies:

```bash
   pip install -r requirements.txt
```

## Usage

Run the script by providing the path to a raw `.eml` file:

```bash
python main.py path/to/email.eml
```

## License

This project is open-source and available under the [MIT License](LICENSE).
