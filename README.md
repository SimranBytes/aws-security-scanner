# AWS Cloud Security Scanner

A CLI tool that checks an AWS account against a subset of the **CIS AWS Foundations Benchmark** and reports misconfigurations sorted by severity.

## What it checks

| # | Check | CIS Control | Severity |
|---|---|---|---|
| 1 | S3 bucket publicly accessible via bucket policy (`Principal: *`) or ACL (`AllUsers` / `AuthenticatedUsers`) | CIS 2.1.1 | CRITICAL |
| 2 | S3 bucket public access block not fully enabled (any of the four settings off) | CIS 2.1.1 | MEDIUM |
| 3 | Root account does not have MFA enabled | CIS 1.5 | CRITICAL |
| 4 | IAM user has `AdministratorAccess` managed policy attached directly | CIS 1.16 | HIGH |
| 5 | IAM user inline policy grants `Action: *` on `Resource: *` | CIS 1.16 | HIGH |
| 6 | Security group allows ingress from `0.0.0.0/0` on a sensitive port (SSH 22, RDP 3389, MySQL 3306, PostgreSQL 5432, MongoDB 27017, Redis 6379, Elasticsearch 9200) | CIS 5.2 / 5.3 | CRITICAL |
| 7 | Security group allows ingress from `0.0.0.0/0` on any other port | CIS 5.2 / 5.3 | HIGH |
| 8 | EBS volume is not encrypted | CIS 2.2.1 | MEDIUM |

Findings are printed to stdout and written to a JSON report file.

## Sample output

```
========================================================================
AWS CLOUD SECURITY POSTURE REPORT
Account: 123456789012   Region: ap-south-1   Generated: 2026-09-20 10:15 UTC
========================================================================

Summary: 1 finding(s) — 0 Critical, 1 High, 0 Medium, 0 Low

[1] HIGH — Overly Permissive IAM Policy  (CIS 1.16)
    Resource:    user:Admin
    Detail:      user 'Admin' has AdministratorAccess attached directly.
    Remediation: Follow least privilege: scope down to only the permissions
                 this identity actually needs, and prefer group/role-based access.

Full JSON report written to scan_report.json
```

Full sample JSON: [`sample_output/scan_report.json`](sample_output/scan_report.json)

## Requirements

- Python 3.8+
- `boto3`

```bash
pip install boto3
```

AWS credentials must be configured before running (`aws configure`, environment variables, or an IAM role). The tool calls `sts:GetCallerIdentity` on startup and exits if no credentials are found.

## Usage

```bash
# Scan ap-south-1 (default) and write to scan_report.json
python aws_security_scanner.py

# Specify a region and output file
python aws_security_scanner.py --region us-east-1 --out results.json
```

| Flag | Default | Description |
|---|---|---|
| `--region` | `ap-south-1` | AWS region to scan for EC2/EBS/SG resources |
| `--out` | `scan_report.json` | Path to write the JSON report |

> **Note:** S3 and IAM checks are global — the `--region` flag only affects EC2 security group and EBS volume lookups.

## Required IAM permissions

The scanner only needs read-only access. Attach this policy to the IAM user or role you run it with:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetPublicAccessBlock",
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:GetAccountSummary",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Output format

The JSON report contains:

```json
{
  "account_id": "...",
  "region": "...",
  "generated_at": "...",
  "finding_count": 1,
  "findings": [
    {
      "resource": "user:Admin",
      "check": "Overly Permissive IAM Policy",
      "severity": "HIGH",
      "cis_control": "CIS 1.16",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

Real scan output may contain account metadata. Do not commit `*.json` report files to version control — the `.gitignore` excludes them by default.

## Scope and limitations

- Covers S3, IAM, EC2 security groups, and EBS for a single region per run
- Does not check: CloudTrail logging, VPC flow logs, GuardDuty, Config rules, KMS key rotation, or password policy
- Detects IAM `AdministratorAccess` and wildcard inline policies; does not recursively evaluate policy conditions or SCPs
- IPv6 CIDR (`0::/0`) ingress rules are not currently flagged
