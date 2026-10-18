#!/usr/bin/env python3

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}


class Finding:
    def __init__(self, resource, check, severity, cis_control, description, remediation):
        self.resource = resource
        self.check = check
        self.severity = severity
        self.cis_control = cis_control
        self.description = description
        self.remediation = remediation

    def to_dict(self):
        return {
            "resource": self.resource,
            "check": self.check,
            "severity": self.severity,
            "cis_control": self.cis_control,
            "description": self.description,
            "remediation": self.remediation,
        }


def check_s3_buckets(session):
    """Flag buckets that are publicly readable via bucket policy, ACL, or missing public access block."""
    findings = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"  [!] Could not list S3 buckets: {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        is_public = False
        reason = []

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):
                reason.append("public access block not fully enabled")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                reason.append("no public access block configuration set")

        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal")
                if principal == "*" or principal == {"AWS": "*"}:
                    if stmt.get("Effect") == "Allow":
                        is_public = True
                        reason.append("bucket policy grants access to Principal '*'")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                pass 

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public = True
                    reason.append(f"ACL grants access to {uri.split('/')[-1]}")
        except ClientError:
            pass 
        if is_public:
            findings.append(Finding(
                resource=f"s3://{name}",
                check="Public S3 Bucket",
                severity="CRITICAL",
                cis_control="CIS 2.1.1",
                description=f"Bucket is publicly accessible ({'; '.join(reason)}).",
                remediation="Remove public bucket policy grants, enable all four Block Public "
                             "Access settings, and switch ACLs to bucket-owner-enforced.",
            ))
        elif reason:
            findings.append(Finding(
                resource=f"s3://{name}",
                check="S3 Public Access Block Not Fully Enabled",
                severity="MEDIUM",
                cis_control="CIS 2.1.1",
                description="; ".join(reason),
                remediation="Enable all four Block Public Access settings at the bucket "
                             "(or account) level even if the bucket is not currently public.",
            ))

    return findings


def check_iam(session):
    """Flag IAM users/roles/groups with wildcard-permission or AdministratorAccess policies."""
    findings = []
    iam = session.client("iam")

    def policy_is_risky(policy_document):
        for stmt in policy_document.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and "*" in resources:
                return True
        return False

    def check_attached_managed_policies(entity_type, entity_name, list_fn):
        try:
            attached = list_fn(entity_name)
        except ClientError:
            return
        for pol in attached:
            if pol["PolicyName"] in ("AdministratorAccess",):
                findings.append(Finding(
                    resource=f"{entity_type}:{entity_name}",
                    check="Overly Permissive IAM Policy",
                    severity="HIGH",
                    cis_control="CIS 1.16",
                    description=f"{entity_type} '{entity_name}' has AdministratorAccess attached directly.",
                    remediation="Follow least privilege: scope down to only the permissions "
                                 "this identity actually needs, and prefer group/role-based access.",
                ))

    try:
        for user in iam.list_users()["Users"]:
            uname = user["UserName"]
            check_attached_managed_policies(
                "user", uname,
                lambda n: iam.list_attached_user_policies(UserName=n)["AttachedPolicies"]
            )
            for pol_name in iam.list_user_policies(UserName=uname)["PolicyNames"]:
                doc = iam.get_user_policy(UserName=uname, PolicyName=pol_name)["PolicyDocument"]
                if policy_is_risky(doc):
                    findings.append(Finding(
                        resource=f"user:{uname}",
                        check="Wildcard IAM Policy",
                        severity="HIGH",
                        cis_control="CIS 1.16",
                        description=f"Inline policy '{pol_name}' grants Action:* on Resource:*.",
                        remediation="Scope the policy to specific actions and resource ARNs.",
                    ))
    except ClientError as e:
        print(f"  [!] Could not list IAM users: {e}")

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append(Finding(
                resource="account:root",
                check="Root Account Without MFA",
                severity="CRITICAL",
                cis_control="CIS 1.5",
                description="The root account does not have MFA enabled.",
                remediation="Enable an MFA device (virtual or hardware) on the root user immediately.",
            ))
    except ClientError as e:
        print(f"  [!] Could not check root MFA status: {e}")

    return findings


def check_security_groups(session, region):
    """Flag security groups with ingress rules open to 0.0.0.0/0."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        print(f"  [!] Could not list security groups: {e}")
        return findings

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    port_desc = "all ports" if from_port is None else f"port {from_port}"
                    if from_port in SENSITIVE_PORTS:
                        severity = "CRITICAL"
                        port_desc = f"port {from_port} ({SENSITIVE_PORTS[from_port]})"
                    elif from_port is None:
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"
                    findings.append(Finding(
                        resource=f"{sg['GroupId']} ({sg['GroupName']})",
                        check="Security Group Open to the World",
                        severity=severity,
                        cis_control="CIS 5.2 / 5.3",
                        description=f"Ingress rule allows 0.0.0.0/0 on {port_desc}.",
                        remediation="Restrict the CIDR to known IP ranges (office/VPN) or "
                                     "front the service with a bastion / VPN / load balancer.",
                    ))
    return findings


def check_ebs_encryption(session, region):
    """Flag EBS volumes that are not encrypted."""
    findings = []
    ec2 = session.client("ec2", region_name=region)

    try:
        volumes = ec2.describe_volumes()["Volumes"]
    except ClientError as e:
        print(f"  [!] Could not list EBS volumes: {e}")
        return findings

    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append(Finding(
                resource=vol["VolumeId"],
                check="Unencrypted EBS Volume",
                severity="MEDIUM",
                cis_control="CIS 2.2.1",
                description=f"Volume {vol['VolumeId']} ({vol.get('Size')} GiB) is not encrypted.",
                remediation="Enable EBS encryption by default for the region, and re-create "
                             "or migrate existing volumes to encrypted copies.",
            ))
    return findings


def print_report(findings, account_id, region):
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print("\n" + "=" * 78)
    print(f"AWS CLOUD SECURITY POSTURE REPORT")
    print(f"Account: {account_id}   Region: {region}   Generated: {now}")
    print("=" * 78)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\nSummary: {len(findings)} finding(s) — "
          f"{counts['CRITICAL']} Critical, {counts['HIGH']} High, "
          f"{counts['MEDIUM']} Medium, {counts['LOW']} Low\n")

    if not findings:
        print("No misconfigurations detected by the checks in this scanner.")
        return

    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f.severity} — {f.check}  ({f.cis_control})")
        print(f"    Resource:    {f.resource}")
        print(f"    Detail:      {f.description}")
        print(f"    Remediation: {f.remediation}")
        print()


def save_json(findings, account_id, region, path):
    data = {
        "account_id": account_id,
        "region": region,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"\nFull JSON report written to {path}")


def main():
    parser = argparse.ArgumentParser(description="AWS Cloud Security Posture Scanner")
    parser.add_argument("--region", default="ap-south-1", help="AWS region to scan (default: ap-south-1)")
    parser.add_argument("--out", default="scan_report.json", help="Path to write the JSON report")
    args = parser.parse_args()

    try:
        session = boto3.Session()
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
    except NoCredentialsError:
        print("No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)
    except ClientError as e:
        print(f"Could not authenticate to AWS: {e}")
        sys.exit(1)

    print(f"Authenticated as {identity['Arn']}")
    print(f"Scanning account {account_id} in region {args.region} ...\n")

    all_findings = []

    print("[1/5] Checking S3 buckets for public access...")
    all_findings += check_s3_buckets(session)

    print("[2/5] Checking IAM users/policies and root MFA...")
    all_findings += check_iam(session)

    print("[3/5] Checking security groups for open ingress...")
    all_findings += check_security_groups(session, args.region)

    print("[4/5] Checking EBS volume encryption...")
    all_findings += check_ebs_encryption(session, args.region)

    print("[5/5] Compiling report...")
    print_report(all_findings, account_id, args.region)
    save_json(all_findings, account_id, args.region, args.out)


if __name__ == "__main__":
    main()
