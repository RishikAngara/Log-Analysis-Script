"""
Log File Analysis Script

This script processes web server log files to extract meaningful insights:
- Top IP addresses by request count
- Most accessed endpoints
- Suspicious activity (failed login attempts)
It generates visualizations and saves results in a CSV file.
"""

import re
import csv
import logging
from collections import Counter, defaultdict
import matplotlib.pyplot as plt

# Precompiled Regular Expression Patterns
IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
)
REQUEST_ENDPOINT_PATTERN = re.compile(
    r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^ ]+)'
)
FAILED_LOGIN_PATTERN = re.compile(
    r"401|Invalid credentials", re.IGNORECASE
)

# Logging Configuration
logging.basicConfig(
    filename="log_analysis_error.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def extract_ip_addresses_from_logs(log_lines):
    """Extract IP addresses from each line of the log file."""
    return [
        IP_ADDRESS_PATTERN.search(line).group()
        for line in log_lines
        if IP_ADDRESS_PATTERN.search(line)
    ]


def extract_request_endpoints(log_lines):
    """Extract requested endpoints from each log line."""
    return [
        REQUEST_ENDPOINT_PATTERN.search(line).group(1)
        for line in log_lines
        if REQUEST_ENDPOINT_PATTERN.search(line)
    ]


def detect_failed_login_ips(log_lines, threshold_for_failed_logins=10):
    """Detect IPs that exceed the threshold of failed login attempts."""
    failed_login_attempts_by_ip = defaultdict(int)
    for line in log_lines:
        if FAILED_LOGIN_PATTERN.search(line):
            ip_match = IP_ADDRESS_PATTERN.search(line)
            if ip_match:
                failed_login_attempts_by_ip[ip_match.group()] += 1
    return {
        ip: count
        for ip, count in failed_login_attempts_by_ip.items()
        if count > threshold_for_failed_logins
    }


def generate_visualizations(ip_counts, endpoint_counts):
    """Generate visualizations for the top IP addresses and endpoints."""
    ip_addresses, request_counts = zip(*ip_counts[:10])
    plt.figure(figsize=(10, 6))
    plt.barh(ip_addresses, request_counts, color="skyblue")
    plt.xlabel("Request Count")
    plt.ylabel("IP Address")
    plt.title("Top 10 IPs by Request Count")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig("top_ips_requests.png")
    plt.show()

    endpoint_urls, access_counts = zip(*endpoint_counts[:10])
    plt.figure(figsize=(10, 6))
    plt.barh(endpoint_urls, access_counts, color="salmon")
    plt.xlabel("Access Count")
    plt.ylabel("Endpoint")
    plt.title("Top 10 Endpoints by Access Count")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig("top_endpoints.png")
    plt.show()


def save_results_to_csv(ip_counts, endpoint_counts, suspicious_ips, output_csv):
    """Save analysis results to a CSV file."""
    with open(output_csv, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_counts)
        writer.writerow([])

        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if endpoint_counts:
            writer.writerow(endpoint_counts[0])
        writer.writerow([])

        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())


def display_analysis_summary(ip_counts, endpoint_counts, suspicious_ips):
    """Display the analysis summary in a structured format."""
    print("\n" + "=" * 80)
    print(f"{'=' * 5} {'Requests per IP':^70} {'=' * 5}")
    print("=" * 80)
    print(f"\n{'IP Address':<30} {'Request Count':<20}")
    print("-" * 50)
    for ip, count in ip_counts:
        print(f"{ip:<30} {count:<20}")

    print(f"\n{'=' * 5} {'Most Frequently Accessed Endpoint':^70} {'=' * 5}")
    print("=" * 80)
    if endpoint_counts:
        most_accessed_endpoint, count = endpoint_counts[0]
        print(f"Endpoint: {most_accessed_endpoint} (Accessed {count} times)")
    else:
        print("No endpoints found.")

    print(f"\n{'=' * 5} {'Suspicious Activity Detected':^70} {'=' * 5}")
    print("=" * 80)
    if suspicious_ips:
        print(f"{'IP Address':<30} {'Failed Login Count':<20}")
        print("-" * 50)
        for ip, count in suspicious_ips.items():
            print(f"{ip:<30} {count:<20}")
    else:
        print("No suspicious activity detected.")

    print(f"\n{'=' * 5} {'Summary':^70} {'=' * 5}")
    print("=" * 80)
    print(f"Total Unique IPs: {len(ip_counts)}")
    print(f"Total Unique Endpoints: {len(endpoint_counts)}")


def analyze_log_file(
    log_file_path, threshold_for_failed_logins=10, output_csv="log_analysis_results.csv"
):
    """Process log file, extract data, detect suspicious activity, and generate reports."""
    try:
        with open(log_file_path, "r", encoding="utf-8") as log_file:
            log_lines = log_file.readlines()

        extracted_ip_addresses = extract_ip_addresses_from_logs(log_lines)
        extracted_endpoints = extract_request_endpoints(log_lines)
        suspicious_ips = detect_failed_login_ips(
            log_lines, threshold_for_failed_logins
        )

        ip_counts = Counter(extracted_ip_addresses).most_common(10)
        endpoint_counts = Counter(extracted_endpoints).most_common(10)

        display_analysis_summary(ip_counts, endpoint_counts, suspicious_ips)
        save_results_to_csv(ip_counts, endpoint_counts, suspicious_ips, output_csv)
        generate_visualizations(ip_counts, endpoint_counts)

    except FileNotFoundError:
        logging.error("Error: The file '%s' was not found.", log_file_path)
        print(f"Error: The file '{log_file_path}' was not found.")
    except (IOError, ValueError) as e:
        logging.error("An error occurred: %s", e)
        print(f"An error occurred: {e}")


# Run the analysis
LOG_FILE_PATH = "sample.log"
analyze_log_file(LOG_FILE_PATH)
