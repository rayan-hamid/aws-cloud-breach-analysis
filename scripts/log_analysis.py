"""
log_analysis.py

This script contains the Splunk queries and steps used to analyze AWS logs for suspicious activities.

Author: Rayan Hamid
"""

# Step 1: Query for detecting suspicious IP activity
splunk_query_1 = """
search index=aws_logs sourcetype="aws:s3" 
| stats count by ip_address, action 
| where action="GetObject"
"""

# Explanation: This query searches for suspicious GetObject events and groups them by IP address.

# Step 2: Query for identifying unauthorized access attempts
splunk_query_2 = """
search index=aws_logs sourcetype="aws:s3" 
| table _time, ip_address, action, file_name
| where action IN ("ListObjects", "GetObject")
"""

# Explanation: This query lists the timestamps, IP addresses, actions, and file names for suspicious events.

# Step 3: Query for bucket scanning and exfiltration
splunk_query_3 = """
search index=aws_logs sourcetype="aws:s3" 
| stats count by file_name, action 
| where action="GetObject"
"""

# Explanation: This query identifies the specific file targeted (e.g., "ring.txt") during the breach.

# Step 4: Query for timeline analysis of attacks
splunk_query_4 = """
search index=aws_logs sourcetype="aws:s3" 
| stats count by _time, ip_address, action 
| sort by _time
"""

# Explanation: This query visualizes the attack timeline, including the sequence of actions performed.

# Notes:
# - These queries were used in Splunk to analyze AWS activity logs.
# - The IP address "1.2.3.4" was identified as the source of suspicious activity.
