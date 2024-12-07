# Log-Analysis-Script
This repository contains a Python script that analyzes web server log files to extract meaningful insights and generate reports. It provides a comprehensive overview of IP activity, frequently accessed endpoints, and suspicious login attempts. Additionally, it generates visualizations and stores the results in a CSV file for easy access.

----------------Features--------------------
1) Extracts Data:
Identifies and counts IP addresses and endpoints from the logs.
Detects suspicious failed login attempts.

2) Displays Analysis Summary:
Shows the top IP addresses by request count.
Lists the most frequently accessed endpoints.
Flags suspicious IPs based on a threshold of failed login attempts.

3) Generates Visualizations:
Top 10 IP addresses and endpoints visualized using bar charts.
Saves charts as PNG files (top_ips_requests.png and top_endpoints.png).

4) Exports Results:
Saves analysis results to a CSV file (log_analysis_results.csv).

5) Error Handling:
Logs any errors in log_analysis_error.log.

-----------------How To Use--------------------
1) Install Dependencies: Install Matplotlib
2) Add Your Log File: Ensure that your web server log file is in the same directory as the script or update the script to point to the correct file path.
3) Execute the script
4) View the Outputs: The analysis summary will be printed in the terminal, Results will be saved in the same directory as log_analysis_results.csv, Visualizations will be saved as top_ips_requests.png and top_endpoints.png.
