# AWS Cloud Breach Analysis

## Project Overview
This project analyzes a simulated AWS S3 bucket breach using Splunk and a cybersecurity incident response playbook. It demonstrates how to detect, analyze, and respond to cloud security incidents.

## Dataset
The project uses simulated logs from AWS EC2, focusing on activity in S3 buckets:
- **Targeted Technologies**: S3 buckets, AWS CLI
- **Insights**: Detection of unauthorized access, scanning activities, and file exfiltration.

## Tools and Technologies
- **Splunk**: For log analysis and visualization
- **VirusTotal**: For checking malicious IPs (e.g., [https://www.virustotal.com](https://www.virustotal.com))
- **Incident Response Playbook**: Cybersecurity Incident and Vulnerability Response Playbooks

## Incident Analysis
### Key Findings
1. **Unauthorized Access**: IP `1.2.3.4` accessed the S3 bucket `mordors3stack`.
2. **Data Exfiltration**: The file `ring.txt` was accessed and stolen using AWS CLI.
3. **Suspicious Activity**: Multiple `ListObjects` and `GetObject` events indicated bucket scanning.

### VirusTotal Analysis
The malicious IP `1.2.3.4` was flagged by 4/94 security vendors as malicious. VirusTotal provided details on its connections to known malicious activity, highlighting its involvement in this breach. You can view more information on VirusTotal's website: [VirusTotal](https://www.virustotal.com).

### Remediation Recommendations
- Restrict bucket access to authorized users.
- Set up IP whitelisting for AWS resources.
- Implement monitoring and alerts for suspicious activity.

## File Structure
- `data/`: Contains sample or anonymized log files.
- `playbook/`: The incident response playbook.
- `reports/`: Final project report and presentation.
- `scripts/`: Documented steps and Splunk queries used in the analysis.
- `requirements.txt`: (Optional) Includes any tools needed for analysis.

## Future Work
- Expand the dataset to include other AWS services.
- Integrate additional threat intelligence platforms for analysis.

## License
This project is licensed under the MIT License.
