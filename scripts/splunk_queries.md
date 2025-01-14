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

## Query 5: Detect Anomalous User Agents

search index=aws_logs sourcetype="aws:s3" 
| stats count by user_agent 
| where NOT user_agent IN ("aws-cli/1.18.136", "boto3/1.17.59")

Description: This query identifies unusual user agents accessing the S3 bucket, which may indicate suspicious activity.

## Query 6: Identify Geographic Origins of Suspicious IPs

search index=aws_logs sourcetype="aws:s3" 
| iplocation ip_address 
| table ip_address, City, Country

Description: This query uses geolocation to find the geographic origins of suspicious IP addresses.

## Query 7: Monitor High Frequency Access to Sensitive Files

search index=aws_logs sourcetype="aws:s3" 
| stats count by file_name, ip_address 
| where file_name="ring.txt" 
| sort - count

Description: This query identifies IP addresses that accessed sensitive files (like ring.txt) frequently.

## Query 8: Detect Failed Access Attempts

search index=aws_logs sourcetype="aws:s3" 
| stats count by ip_address, status 
| where status="403"

Description: This query identifies IP addresses with failed access attempts (403 Forbidden), which could indicate brute force attempts or misconfigurations.

## Query 9: Analyze Access Patterns by Time

search index=aws_logs sourcetype="aws:s3" 
| timechart span=1h count by action

Description: This query generates a time-based visualization of actions (e.g., GetObject, ListObjects) to detect unusual spikes or patterns.

## Query 10: Identify Misconfigured Buckets

search index=aws_logs sourcetype="aws:s3" 
| stats values(permissions) by bucket_name 
| where permissions="public"

Description: This query detects publicly accessible buckets, which may lead to unauthorized access.




