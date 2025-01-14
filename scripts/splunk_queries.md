# Splunk Queries for AWS Cloud Breach Analysis

This document contains the Splunk queries used to analyze AWS activity logs for unauthorized access, data exfiltration, and bucket scanning.

## Query 1: Detect Suspicious IP Activity:

search index=aws_logs sourcetype="aws:s3" 
| stats count by ip_address, action 
| where action="GetObject"

Description: This query identifies suspicious IP addresses performing GetObject actions on the S3 bucket.

## Query 2: Identify Unauthorized Access Attempts

search index=aws_logs sourcetype="aws:s3" 
| table _time, ip_address, action, file_name
| where action IN ("ListObjects", "GetObject")

Description: This query lists the timestamps, IP addresses, actions, and file names associated with unauthorized access attempts.

## Query 3: Analyze Bucket Scanning and Exfiltration

search index=aws_logs sourcetype="aws:s3" 
| stats count by file_name, action 
| where action="GetObject"

Description: This query identifies specific files targeted during the breach.

## Query 4: Visualize Attack Timeline

search index=aws_logs sourcetype="aws:s3" 
| stats count by _time, ip_address, action 
| sort by _time

Description: This query shows the sequence of actions performed by suspicious IP addresses over time.