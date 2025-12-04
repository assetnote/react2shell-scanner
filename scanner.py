#!/usr/bin/env python3
"""
React2Shell Scanner - High Fidelity Detection for RSC/Next.js RCE
CVE-2025-55182 & CVE-2025-66478

Based on research from Assetnote Security Research Team.
"""

import argparse
import sys
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Optional

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm")
    sys.exit(1)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    # Bright blue/cyan for Assetnote branding
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_CYAN = "\033[96m"


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def print_banner():
    """Print the tool banner."""
    assetnote_art = (
        "                        _               _       \n"
        "     /\\                | |             | |      \n"
        "    /  \\   ___ ___  ___| |_ _ __   ___ | |_ ___ \n"
        "   / /\\ \\ / __/ __|/ _ \\ __| '_ \\ / _ \\| __/ _ \\\n"
        "  / ____ \\\\__ \\__ \\  __/ |_| | | | (_) | ||  __/\n"
        " /_/    \\_\\___/___/\\___|\\__|_| |_|\\___/ \\__\\___|\n"
        "                                                \n"
        "                                                \n"
    )
    
    kangaroo = (
        "                                      :e\n"
        "                                    'M$\\\n"
        "                                   sf$$br\n"
        "                                 J\\J\\J$L$L\n"
        "                               :d  )fM$$$$$r\n"
        "                          ..P*\\ .4MJP   '*\\\n"
        "                 sed\"\"\"\"\"\" ser d$$$F\n"
        "             .M\\  ..JM$$$B$$$$BJ$MR  ...\n"
        "            dF  nMMM$$$R$$$$$$$h\"$ks$$\"$$r\n"
        "          J\\.. .MMM8$$$$$LM$P\\..'**\\    *\\\n"
        "         d :d$r \"M$$$$br'$M\\d$R\n"
        "        J\\MM\\ *L   *M$B8MM$B.**\n"
        "       :fd$>  :fhr 'MRM$$M$$\"\n"
        "       MJ$>    '5J5..M8$$>\n"
        "      :fMM     d$Fd$$R$$F\n"
        "      4M$P .$$*.J*$$**\n"
        "      M4$> '$>dRdF\n"
        "      MMM\\   *L*B.         \n"
        "     :$$F     ?k\"Re\n"
        "   .$$P\\        **'$$B...\n"
        ":e$F\"               '\"\"\"\"\n"
    )
    
    banner = f"""{Colors.CYAN}{assetnote_art}
  React2Shell Scanner | RSC/Next.js RCE Detection
  CVE-2025-55182 & CVE-2025-66478
  
{kangaroo}
{Colors.BRIGHT_CYAN}Assetnote Security Research{Colors.CYAN}
    
{Colors.RESET}"""
    print(banner)


def normalize_host(host: str) -> str:
    """Normalize host to include scheme if missing."""
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


def build_payload() -> tuple[str, str]:
    """Build the multipart form data payload for the vulnerability check."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def check_vulnerability(host: str, timeout: int = 10, verify_ssl: bool = True) -> dict:
    """
    Check if a host is vulnerable to CVE-2025-55182/CVE-2025-66478.

    Returns a dict with:
        - host: the target host
        - vulnerable: True/False/None (None if error)
        - status_code: HTTP status code
        - error: error message if any
        - request: the raw request sent
        - response: the raw response received
    """
    result = {
        "host": host,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "request": None,
        "response": None,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    host = normalize_host(host)
    if not host:
        result["error"] = "Invalid or empty host"
        return result

    body, content_type = build_payload()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 React2ShellScanner/1.0.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Next-Router-State-Tree": '%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    parsed = urlparse(host)
    request_str = f"POST / HTTP/1.1\r\n"
    request_str += f"Host: {parsed.netloc}\r\n"
    for k, v in headers.items():
        request_str += f"{k}: {v}\r\n"
    request_str += f"Content-Length: {len(body)}\r\n\r\n"
    request_str += body
    result["request"] = request_str

    try:
        response = requests.post(
            f"{host}/",
            headers=headers,
            data=body,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )

        result["status_code"] = response.status_code

        response_str = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        for k, v in response.headers.items():
            response_str += f"{k}: {v}\r\n"
        response_str += f"\r\n{response.text[:2000]}"
        result["response"] = response_str

        # Check vulnerability indicators:
        # 1. Status code 500
        # 2. Response contains 'E{"digest"'
        if response.status_code == 500 and 'E{"digest"' in response.text:
            result["vulnerable"] = True
        else:
            result["vulnerable"] = False

    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except RequestException as e:
        result["error"] = f"Request failed: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result


def load_hosts(hosts_file: str) -> list[str]:
    """Load hosts from a file, one per line."""
    hosts = []
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
    except FileNotFoundError:
        print(colorize(f"[ERROR] File not found: {hosts_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(colorize(f"[ERROR] Failed to read file: {e}", Colors.RED))
        sys.exit(1)
    return hosts


def save_results(results: list[dict], output_file: str, vulnerable_only: bool = True):
    if vulnerable_only:
        results = [r for r in results if r.get("vulnerable") is True]

    output = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "total_results": len(results),
        "results": results
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
    except Exception as e:
        print(colorize(f"\n[ERROR] Failed to save results: {e}", Colors.RED))


def print_result(result: dict, verbose: bool = False):
    host = result["host"]

    if result["vulnerable"] is True:
        status = colorize("[vulnerable]", Colors.RED + Colors.BOLD)
        print(f"  {status}  {colorize(host, Colors.WHITE + Colors.BOLD)} - status: {Colors.RED}{Colors.BOLD}{result['status_code']}{Colors.RESET}")
    elif result["vulnerable"] is False:
        status = colorize("[not vulnerable]", Colors.GREEN)
        print(f"  {status}  {colorize(host, Colors.WHITE)} - status: {Colors.GREEN}{result['status_code']}{Colors.RESET}")
    else:
        status = colorize("[error]", Colors.YELLOW)
        error_msg = result.get("error", "Unknown error")
        print(f"  {status}  {colorize(host, Colors.WHITE)} - {Colors.YELLOW}{error_msg}{Colors.RESET}")

    if verbose and result["vulnerable"]:
        print(f"  {Colors.CYAN}Response snippet:{Colors.RESET}")
        if result.get("response"):
            lines = result["response"].split("\r\n")[:10]
            for line in lines:
                print(f"    {line}")


class BannerArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that shows banner before errors/help."""
    def error(self, message):
        # Show banner before error message (when no args provided)
        print_banner()
        sys.stdout.flush()
        super().error(message)
    
    def print_help(self, file=None):
        # Show banner before help
        print_banner()
        sys.stdout.flush()
        super().print_help(file)


def main():
    parser = BannerArgumentParser(
        description="React2Shell Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -l hosts.txt --threads 50 --timeout 15
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-u", "--url",
        help="Single URL/host to check"
    )
    input_group.add_argument(
        "-l", "--list",
        help="File containing list of hosts (one per line)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for results (JSON format)"
    )

    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Save all results to output file, not just vulnerable hosts"
    )

    parser.add_argument(
        "-k", "--insecure",
        default=True,
        action="store_true",
        help="Disable SSL certificate verification"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show response snippets for vulnerable hosts)"
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (only show vulnerable hosts)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.MAGENTA = ""
        Colors.CYAN = ""
        Colors.WHITE = ""
        Colors.BOLD = ""
        Colors.RESET = ""

    if args.url:
        hosts = [args.url]
    else:
        hosts = load_hosts(args.list)

    if not hosts:
        print(colorize("[ERROR] No hosts to scan", Colors.RED))
        sys.exit(1)

    if not args.quiet:
        print(f"{Colors.CYAN}Configuration:{Colors.RESET}")
        print(f"  hosts: {Colors.BOLD}{len(hosts)}{Colors.RESET}")
        print(f"  threads: {Colors.BOLD}{args.threads}{Colors.RESET}")
        print(f"  timeout: {Colors.BOLD}{args.timeout}s{Colors.RESET}")
        if args.insecure:
            print(f"  ssl verification: {Colors.YELLOW}{Colors.BOLD}disabled{Colors.RESET}")
        print()

    results = []
    vulnerable_count = 0
    error_count = 0

    verify_ssl = not args.insecure

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(hosts) == 1:
        result = check_vulnerability(hosts[0], args.timeout, verify_ssl)
        results.append(result)
        if not args.quiet or result["vulnerable"]:
            print_result(result, args.verbose)
        if result["vulnerable"]:
            vulnerable_count = 1
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_vulnerability, host, args.timeout, verify_ssl): host
                for host in hosts
            }

            with tqdm(
                total=len(hosts),
                desc=colorize("Scanning", Colors.CYAN + Colors.BOLD),
                unit="host",
                ncols=80,
                disable=args.quiet
            ) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)

                    if result["vulnerable"]:
                        vulnerable_count += 1
                        tqdm.write("")
                        print_result(result, args.verbose)
                    elif result["error"]:
                        error_count += 1
                        if not args.quiet and args.verbose:
                            tqdm.write("")
                            print_result(result, args.verbose)
                    elif not args.quiet and args.verbose:
                        tqdm.write("")
                        print_result(result, args.verbose)

                    pbar.update(1)

    if not args.quiet:
        print()
        print(f"{Colors.CYAN}Summary:{Colors.RESET}")
        print(f"  total scanned: {Colors.BOLD}{len(hosts)}{Colors.RESET}")
        
        if vulnerable_count > 0:
            print(f"  vulnerable: {Colors.RED}{Colors.BOLD}{vulnerable_count}{Colors.RESET}")
        else:
            print(f"  vulnerable: {Colors.BOLD}{vulnerable_count}{Colors.RESET}")

        print(f"  not vulnerable: {Colors.BOLD}{len(hosts) - vulnerable_count - error_count}{Colors.RESET}")
        
        if error_count > 0:
            print(f"  errors: {Colors.YELLOW}{Colors.BOLD}{error_count}{Colors.RESET}")
        else:
            print(f"  errors: {Colors.BOLD}{error_count}{Colors.RESET}")

    if args.output:
        save_results(results, args.output, vulnerable_only=not args.all_results)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
