# Web Vulnerability Scanner

A Python command-line tool that scans a target website for common 
security weaknesses — missing security headers, Cross-Site Scripting 
(XSS), and basic SQL Injection — and generates a professional PDF 
report summarizing the findings.

⚠️ **For educational and authorized testing only.** Only scan websites 
you own or have explicit permission to test. This project was built 
and tested against [Google Gruyere](https://google-gruyere.appspot.com/), 
an intentionally vulnerable web application provided by Google for 
security training.

## Features

- 🛡️ **Security Headers Check** — Detects missing HTTP security headers (X-Frame-Options, Content-Security-Policy, and more)
- 💉 **XSS Detection** — Tests whether user input is reflected unsanitized in the page output
- 🗃️ **SQL Injection Detection** — Checks for database error messages leaking through malformed input
- 📄 **PDF Report Generation** — Automatically produces a clean, readable PDF summary of all findings
- ⚠️ **Robust Error Handling** — Gracefully handles network failures, timeouts, and failed logins without crashing

## Installation & Usage

1. Clone the repository:
```bash
   git clone https://github.com/666luciferdevil/web-vuln-scanner.git
   cd web-vuln-scanner
```

2. Create a virtual environment:
```bash
   python -m venv venv
```

3. Activate the virtual environment:

   **Windows (CMD or Git Bash):**
```bash
   venv\Scripts\activate
```
   *(Git Bash users can also use: `source venv/Scripts/activate`)*

   **macOS / Linux:**
```bash
   source venv/bin/activate
```

4. Install dependencies:
```bash
   pip install -r requirements.txt
```

5. Run the scanner:
```bash
   python main.py
```

## Example
$ python main.py
Enter test account username: lucifer.dev11
Enter test account password: !@#.qwe.*&%

--- Security Headers ---
[-] X-Frame-Options
[-] X-Content-Type-Options
[-] Content-Security-Policy
[-] Strict-Transport-Security

--- XSS ---
[+] No XSS vulnerability detected (payload was sanitized or blocked)

--- SQL Injection ---
[+] No SQL Injection vulnerability detected

[+] Report saved as scan_report.pdf


## How It Works

### Security Headers
The tool sends a request to the target URL and checks the response 
headers against a list of important security headers. Missing headers 
are flagged as potential weaknesses (e.g. a missing `X-Frame-Options` 
header can leave a site vulnerable to clickjacking).

### XSS Detection
The tool logs in with a test account and submits a snippet containing 
a JavaScript payload (`<script>alert('XSS')</script>`). It then checks 
whether the exact payload appears unmodified in the response. If it 
does, the input was not sanitized — a real XSS vulnerability. If the 
site strips, escapes, or blocks the payload, it is considered safe.

### SQL Injection Detection
The tool appends a single quote (`'`) to a URL parameter — a classic 
technique to break SQL query syntax. It then scans the response for 
common database error messages (e.g. "SQL syntax", "mysql_fetch"). 
Their presence indicates the input was passed directly into a database 
query without proper sanitization.

### PDF Reporting
All results are compiled into a structured PDF report using `fpdf2`, 
making findings easy to save, share, or include in a portfolio.

## Tech Stack

- **Python 3** — Core language
- **`requests`** — HTTP requests and session handling (for login-based testing)
- **`fpdf2`** — PDF report generation
- **Git & GitHub** — Version control

## Disclaimer

This tool is intended for learning and authorized security testing 
only. Scanning websites without permission is illegal in most 
jurisdictions. The author is not responsible for any misuse of this 
tool.