# AWS Basic Governance Evidence Collector

Simple Python tool that checks an AWS account for common cloud governance and security issues, then generates a clean report.

## What it checks
- Public S3 buckets
- Root account MFA status
- Security groups open to the internet on SSH (port 22) or RDP (port 3389)

## Why this matters
These are basic but high-impact controls that Cloud Security Analysts and Governance teams monitor regularly. This project demonstrates automated evidence collection and turning technical findings into a business-friendly report.

## How to run
1. Configure AWS credentials with read-only access
2. `pip install boto3`
3. `python aws_evidence_collector.py`

## Example Output
See `evidence_report.json` and `governance_health_report.md`

## Skills Demonstrated
- AWS resource inspection with boto3
- Basic cloud security posture checking
- Automated evidence collection
- Using AI to generate clear governance reports

## Project Structure
```
aws-governance-evidence-collector/
│
├── aws_evidence_collector.py      # Main script
├── evidence_report.json           # Example scan output
├── governance_health_report.md    # AI-generated report
└── README.md
```
