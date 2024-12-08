import re
import csv
from collections import defaultdict, Counter

# Input for the file path
LOG_FILE = 'sample.log'
OUTPUT_CSV_FILE = 'log_analysis_results.csv'

# Regex pattern to parse the log file
LOG_PATTERN = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) (HTTP/[\d.]+)" (\d+) (\d+)( "(.*?)")?'

# Data structures to store analysis results
request_counts = Counter()
endpoint_counts = Counter()
failed_logins = defaultdict(int)

print("Starting log analysis...")

# Read and process log file
with open(LOG_FILE, 'r') as file:
    for line in file:
        match = re.match(LOG_PATTERN, line)
        if match:
            ip, timestamp, method, endpoint, protocol, status_code, size, _, message = match.groups()

            # Count the requests per IP
            request_counts[ip] += 1
            
            # Count the requests per endpoint
            endpoint_counts[endpoint] += 1
            
            #  Detect failed login attempts (POST /login with 401 status and "Invalid credentials" message)
            if method == "POST" and endpoint == "/login" and status_code == "401" and message and "Invalid credentials" in message:
                failed_logins[ip] += 1

#  Display the results
print("\nRequests per IP Address:")
print(f"{'IP Address':<20} {'Request Count':<15}")
print("-" * 35)
for ip, count in request_counts.most_common(5):  # Top 5 IPs
    print(f"{ip:<20} {count:<15}")

#  Most frequently accessed endpoint
most_frequent_endpoint, access_count = endpoint_counts.most_common(1)[0]
print("\nMost Frequently Accessed Endpoint:")
print(f"{most_frequent_endpoint} (Accessed {access_count} times)")

#  Suspicious Activity Detected (failed login attempts)
if failed_logins:
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
    print("-" * 45)
    for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<25}")
else:
    print("\nNo suspicious activity detected.")

#  Write the analysis results to CSV
with open(OUTPUT_CSV_FILE, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['IP Address', 'Request Count', 'Failed Login Attempts'])
    for ip in request_counts:
        failed_attempts = failed_logins.get(ip, 0)  # Default to 0 if IP is not in failed_logins
        writer.writerow([ip, request_counts[ip], failed_attempts])

print("\nAnalysis complete! Results have been saved to 'log_analysis_results.csv'")
