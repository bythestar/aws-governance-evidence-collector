import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

def safe_call(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except ClientError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

def check_public_s3(s3):
    public = []
    result = safe_call(s3.list_buckets)
    if isinstance(result, dict) and "error" in result:
        return result
    for b in result.get("Buckets", []):
        name = b["Name"]
        acl = safe_call(s3.get_bucket_acl, Bucket=name)
        if isinstance(acl, dict) and "error" in acl:
            continue
        for g in acl.get("Grants", []):
            if g.get("Grantee", {}).get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                public.append(name)
                break
    return public

def check_root_mfa(iam):
    result = safe_call(iam.get_account_summary)
    if isinstance(result, dict) and "error" in result:
        return result
    return result.get("SummaryMap", {}).get("AccountMFAEnabled", 0) == 1

def check_open_sgs(ec2):
    open_sgs = []
    result = safe_call(ec2.describe_security_groups)
    if isinstance(result, dict) and "error" in result:
        return result
    for sg in result.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            ports = [perm.get("FromPort"), perm.get("ToPort")]
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0" and (22 in ports or 3389 in ports):
                    open_sgs.append({
                        "GroupId": sg["GroupId"],
                        "GroupName": sg.get("GroupName"),
                        "Port": perm.get("FromPort")
                    })
    return open_sgs

def main():
    print("Running AWS Evidence Collector...\n")

    s3 = boto3.client("s3", region_name="us-east-1")
    iam = boto3.client("iam", region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")

    results = {
        "scan_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "public_s3_buckets": check_public_s3(s3),
        "root_mfa_enabled": check_root_mfa(iam),
        "open_security_groups": check_open_sgs(ec2)
    }

    print(json.dumps(results, indent=2))

    with open("evidence_report.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nSaved to evidence_report.json")

if __name__ == "__main__":
    main()
