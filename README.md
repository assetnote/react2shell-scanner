# react2shell-scanner

A command-line tool for detecting CVE-2025-55182 and CVE-2025-66478 in Next.js applications using React Server Components.

For technical details on the vulnerability and detection methodology, see our blog post: https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478

## How It Works

The scanner sends a crafted multipart POST request that triggers a specific error condition in vulnerable versions of React Server Components. Vulnerable hosts return a 500 status code with `E{"digest"` in the response body. This check differentiates vulnerable hosts from those that are simply running RSC.

## Requirements

- Python 3.9+
- requests
- tqdm

## Installation

```
pip install -r requirements.txt
```

## Usage

Scan a single host:

```
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

## Options

```
-u, --url         Single URL to check
-l, --list        File containing hosts (one per line)
-t, --threads     Number of concurrent threads (default: 10)
--timeout         Request timeout in seconds (default: 10)
-o, --output      Output file for results (JSON)
--all-results     Save all results, not just vulnerable hosts
-k, --insecure    Disable SSL certificate verification
-v, --verbose     Show response details for vulnerable hosts
-q, --quiet       Only output vulnerable hosts
--no-color        Disable colored output
--user-agent      Customize your User-Agent
```

## Output

Results are printed to the terminal. When using `-o`, vulnerable hosts are saved to a JSON file containing the full HTTP request and response for verification.
