"""Realistic synthetic CloudTrail events for testing and demos.

Provides:
  * ATTACK_EVENTS  -- at least one malicious event per detection rule, covering
                      every technique in the rule set.
  * BENIGN_EVENTS  -- five legitimate events used for false-positive testing;
                      none of them must trigger a HIGH/CRITICAL alert.
  * get_mock_events() / get_attack_events() / get_benign_events() accessors.

Each event mirrors the shape of a genuine CloudTrail record: correct
eventSource/eventName, an RFC 5737 test source IP (198.51.100.0/24), a
realistic userIdentity, appropriate requestParameters, a plausible userAgent,
ISO-8601 eventTime, a real awsRegion, a correct readOnly flag and a unique
eventID.
"""

from __future__ import annotations

import itertools
import uuid
from datetime import datetime, timedelta, timezone

ACCOUNT_ID = "111122223333"
EXTERNAL_ACCOUNT = "999988887777"

# Monotonic clock + counter so every generated event gets a unique, ordered
# eventTime and a unique eventID.
_BASE_TIME = datetime(2026, 6, 23, 9, 0, 0, tzinfo=timezone.utc)
_counter = itertools.count()


def _identity(identity_type: str, *, user_name: str = "alice",
              role_name: str = "app-server-role", mfa: bool | None = None,
              account_id: str = ACCOUNT_ID) -> dict:
    """Build a realistic userIdentity block for the given identity type."""
    if identity_type == "Root":
        return {
            "type": "Root",
            "principalId": account_id,
            "arn": f"arn:aws:iam::{account_id}:root",
            "accountId": account_id,
        }
    if identity_type == "AssumedRole":
        attributes = {"creationDate": "2026-06-23T08:55:00Z"}
        if mfa is not None:
            attributes["mfaAuthenticated"] = "true" if mfa else "false"
        return {
            "type": "AssumedRole",
            "principalId": f"AROAEXAMPLEID:{role_name}-session",
            "arn": f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{role_name}-session",
            "accountId": account_id,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "arn": f"arn:aws:iam::{account_id}:role/{role_name}",
                    "userName": role_name,
                },
                "attributes": attributes,
            },
        }
    if identity_type == "AWSService":
        return {"type": "AWSService", "invokedBy": "ec2.amazonaws.com"}
    # Default: IAMUser
    return {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLEID",
        "arn": f"arn:aws:iam::{account_id}:user/{user_name}",
        "accountId": account_id,
        "userName": user_name,
    }


def _ct(event_name: str, event_source: str, *, region: str = "us-east-1",
        source_ip: str = "198.51.100.23",
        user_agent: str = "aws-cli/2.15.30 Python/3.11.6 Linux/5.10 botocore/2.4.5",
        identity: dict | None = None, request_params: dict | None = None,
        response_elements: dict | None = None, error_code: str | None = None,
        error_message: str | None = None, read_only: bool = False,
        additional_event_data: dict | None = None) -> dict:
    """Assemble one CloudTrail record."""
    seq = next(_counter)
    event_time = (_BASE_TIME + timedelta(seconds=seq * 30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record: dict = {
        "eventVersion": "1.09",
        "eventID": str(uuid.uuid4()),
        "eventTime": event_time,
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "userIdentity": identity if identity is not None else _identity("IAMUser"),
        "readOnly": read_only,
        "managementEvent": True,
        "recipientAccountId": ACCOUNT_ID,
    }
    if request_params is not None:
        record["requestParameters"] = request_params
    if response_elements is not None:
        record["responseElements"] = response_elements
    if error_code is not None:
        record["errorCode"] = error_code
    if error_message is not None:
        record["errorMessage"] = error_message
    if additional_event_data is not None:
        record["additionalEventData"] = additional_event_data
    return record


def get_attack_events() -> list[dict]:
    """One or more malicious events per detection rule (fresh each call)."""
    return [
        # --- T1078.004 Valid Accounts: Cloud Accounts ---
        # RULE-001: console login without MFA
        _ct("ConsoleLogin", "signin.amazonaws.com", source_ip="198.51.100.40",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            identity=_identity("IAMUser", user_name="bob"),
            response_elements={"ConsoleLogin": "Success"},
            additional_event_data={"MFAUsed": "No", "LoginTo": "https://console.aws.amazon.com/"},
            read_only=False),
        # RULE-002: failed console login
        _ct("ConsoleLogin", "signin.amazonaws.com", source_ip="198.51.100.41",
            user_agent="Mozilla/5.0 (X11; Linux x86_64)",
            identity=_identity("IAMUser", user_name="bob"),
            response_elements={"ConsoleLogin": "Failure"},
            additional_event_data={"MFAUsed": "No"},
            error_message="Failed authentication", read_only=False),

        # --- T1190 Exploit Public-Facing Application ---
        # RULE-003: Lambda config + code update
        _ct("UpdateFunctionConfiguration", "lambda.amazonaws.com", source_ip="198.51.100.50",
            identity=_identity("AssumedRole"),
            request_params={"functionName": "public-api-handler", "environment": {
                "variables": {"BACKDOOR": "1"}}}),
        _ct("UpdateFunctionCode", "lambda.amazonaws.com", source_ip="198.51.100.50",
            identity=_identity("AssumedRole"),
            request_params={"functionName": "public-api-handler"}),

        # --- T1136.003 Create Account: Cloud Account ---
        _ct("CreateUser", "iam.amazonaws.com", source_ip="198.51.100.60",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"userName": "backdoor-admin"},
            response_elements={"user": {"userName": "backdoor-admin"}}),  # RULE-004
        _ct("CreateRole", "iam.amazonaws.com", source_ip="198.51.100.60",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"roleName": "persistence-role"}),  # RULE-005

        # --- T1098.001 Additional Cloud Credentials ---
        _ct("CreateAccessKey", "iam.amazonaws.com", source_ip="198.51.100.61",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"userName": "svc-deploy"}),  # RULE-006
        _ct("CreateLoginProfile", "iam.amazonaws.com", source_ip="198.51.100.61",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"userName": "svc-deploy"}),  # RULE-007

        # --- T1546 Event Triggered Execution ---
        _ct("CreateFunction", "lambda.amazonaws.com", source_ip="198.51.100.62",
            identity=_identity("AssumedRole"),
            request_params={"functionName": "evil-trigger"}),  # RULE-008
        _ct("PutRule", "events.amazonaws.com", source_ip="198.51.100.62",
            identity=_identity("AssumedRole"),
            request_params={"name": "persistence-schedule",
                            "scheduleExpression": "rate(5 minutes)"}),  # RULE-009

        # --- T1098 Account Manipulation (priv-esc) ---
        # RULE-010: admin policy attached to a user
        _ct("AttachUserPolicy", "iam.amazonaws.com", source_ip="198.51.100.70",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"userName": "svc-deploy",
                            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        # RULE-011: policy attached to a role
        _ct("AttachRolePolicy", "iam.amazonaws.com", source_ip="198.51.100.70",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"roleName": "app-server-role",
                            "policyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}),

        # --- T1562.008 Impair Defenses: Disable/Modify Cloud Logs ---
        _ct("StopLogging", "cloudtrail.amazonaws.com", source_ip="198.51.100.80",
            identity=_identity("AssumedRole"),
            request_params={"name": "org-trail"}),  # RULE-012
        _ct("DeleteTrail", "cloudtrail.amazonaws.com", source_ip="198.51.100.80",
            identity=_identity("AssumedRole"),
            request_params={"name": "org-trail"}),  # RULE-013
        _ct("DeleteDetector", "guardduty.amazonaws.com", source_ip="198.51.100.81",
            identity=_identity("AssumedRole"),
            request_params={"detectorId": "abc123def456"}),  # RULE-014
        _ct("StopConfigurationRecorder", "config.amazonaws.com", source_ip="198.51.100.81",
            identity=_identity("AssumedRole"),
            request_params={"configurationRecorderName": "default"}),  # RULE-015

        # --- T1535 Unused/Unsupported Cloud Regions ---
        # RULE-016: RunInstances in an unexpected region (eu-west-1)
        _ct("RunInstances", "ec2.amazonaws.com", region="eu-west-1", source_ip="198.51.100.90",
            identity=_identity("AssumedRole"),
            request_params={"instanceType": "t3.medium", "maxCount": 1, "minCount": 1}),

        # --- T1578 Modify Cloud Compute Infrastructure ---
        _ct("CreateSnapshot", "ec2.amazonaws.com", source_ip="198.51.100.91",
            identity=_identity("AssumedRole"),
            request_params={"volumeId": "vol-0abc123"}),  # RULE-017
        _ct("ModifyInstanceAttribute", "ec2.amazonaws.com", source_ip="198.51.100.91",
            identity=_identity("AssumedRole"),
            request_params={"instanceId": "i-0abc123", "userData": {"value": "<base64>"}}),  # RULE-018

        # --- T1552.005 Unsecured Credentials: Cloud Instance Metadata API ---
        # RULE-019: GetSessionToken from assumed role with non-standard tooling
        _ct("GetSessionToken", "sts.amazonaws.com", source_ip="198.51.100.100",
            user_agent="python-requests/2.31.0",
            identity=_identity("AssumedRole", role_name="ec2-instance-role"),
            request_params={"durationSeconds": 43200}, read_only=True),

        # --- T1528 Steal Application Access Token ---
        _ct("AssumeRole", "sts.amazonaws.com", source_ip="198.51.100.101",
            identity=_identity("IAMUser", user_name="attacker"),
            request_params={"roleArn": f"arn:aws:iam::{ACCOUNT_ID}:role/admin-role",
                            "roleSessionName": "s"}),  # RULE-020
        _ct("AssumeRoleWithWebIdentity", "sts.amazonaws.com", source_ip="198.51.100.101",
            identity={"type": "WebIdentityUser", "principalId": "accounts.google.com:1234"},
            request_params={"roleArn": f"arn:aws:iam::{ACCOUNT_ID}:role/oidc-role",
                            "roleSessionName": "s"}),  # RULE-021

        # --- T1580 Cloud Infrastructure Discovery ---
        _ct("DescribeInstances", "ec2.amazonaws.com", source_ip="198.51.100.110",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-022
        _ct("DescribeSecurityGroups", "ec2.amazonaws.com", source_ip="198.51.100.110",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-023

        # --- T1069.003 Permission Groups Discovery: Cloud Groups ---
        _ct("ListUsers", "iam.amazonaws.com", source_ip="198.51.100.111",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-024
        _ct("GetAccountAuthorizationDetails", "iam.amazonaws.com", source_ip="198.51.100.111",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-025

        # --- T1526 Cloud Service Discovery ---
        _ct("ListBuckets", "s3.amazonaws.com", source_ip="198.51.100.112",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-026
        _ct("DescribeDBInstances", "rds.amazonaws.com", source_ip="198.51.100.112",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-027
        _ct("ListFunctions", "lambda.amazonaws.com", source_ip="198.51.100.112",
            identity=_identity("AssumedRole"), read_only=True),  # RULE-028

        # --- T1530 Data from Cloud Storage ---
        _ct("GetObject", "s3.amazonaws.com", source_ip="198.51.100.120",
            identity=_identity("AssumedRole"),
            request_params={"bucketName": "corp-secrets", "key": "db-backup.sql"},
            read_only=True),  # RULE-029
        _ct("GetBucketPolicy", "s3.amazonaws.com", source_ip="198.51.100.120",
            identity=_identity("AssumedRole"),
            request_params={"bucketName": "corp-secrets"}, read_only=True),  # RULE-030

        # --- T1537 Transfer Data to Cloud Account ---
        _ct("PutBucketReplication", "s3.amazonaws.com", source_ip="198.51.100.130",
            identity=_identity("AssumedRole"),
            request_params={"bucketName": "corp-data",
                            "replicationConfiguration": {"role": "arn:aws:iam::...:role/r"}}),  # RULE-031
        # RULE-032: snapshot shared with an external account
        _ct("ModifySnapshotAttribute", "ec2.amazonaws.com", source_ip="198.51.100.130",
            identity=_identity("AssumedRole"),
            request_params={"snapshotId": "snap-0abc123", "attributeType": "createVolumePermission",
                            "createVolumePermission": {"add": {"items": [
                                {"userId": EXTERNAL_ACCOUNT}]}}}),

        # --- T1567 Exfiltration Over Web Service ---
        # RULE-033: bucket policy opened to public principal
        _ct("PutBucketPolicy", "s3.amazonaws.com", source_ip="198.51.100.131",
            identity=_identity("AssumedRole"),
            request_params={"bucketName": "corp-data", "bucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                               "Resource": "arn:aws:s3:::corp-data/*"}]}}),

        # --- T1485 Data Destruction ---
        _ct("DeleteBucket", "s3.amazonaws.com", source_ip="198.51.100.140",
            identity=_identity("AssumedRole"),
            request_params={"bucketName": "corp-data"}),  # RULE-034
        _ct("TerminateInstances", "ec2.amazonaws.com", source_ip="198.51.100.140",
            identity=_identity("AssumedRole"),
            request_params={"instancesSet": {"items": [{"instanceId": "i-0abc123"}]}}),  # RULE-035
        _ct("DeleteDBInstance", "rds.amazonaws.com", source_ip="198.51.100.140",
            identity=_identity("AssumedRole"),
            request_params={"dBInstanceIdentifier": "prod-db", "skipFinalSnapshot": True}),  # RULE-036

        # --- T1486 Data Encrypted for Impact ---
        _ct("ScheduleKeyDeletion", "kms.amazonaws.com", source_ip="198.51.100.150",
            identity=_identity("AssumedRole"),
            request_params={"keyId": "arn:aws:kms:us-east-1:111122223333:key/abc",
                            "pendingWindowInDays": 7}),  # RULE-037
        _ct("DisableKey", "kms.amazonaws.com", source_ip="198.51.100.150",
            identity=_identity("AssumedRole"),
            request_params={"keyId": "arn:aws:kms:us-east-1:111122223333:key/abc"}),  # RULE-038

        # --- T1496 Resource Hijacking ---
        # RULE-039: GPU instance launched in an expected region (only GPU rule fires)
        _ct("RunInstances", "ec2.amazonaws.com", region="us-east-1", source_ip="198.51.100.160",
            identity=_identity("AssumedRole"),
            request_params={"instanceType": "p3.2xlarge", "maxCount": 8, "minCount": 8}),
    ]


def get_benign_events() -> list[dict]:
    """Five legitimate events that must not raise HIGH/CRITICAL alerts."""
    return [
        # A DescribeInstances from a known service role (LOW discovery at most).
        _ct("DescribeInstances", "ec2.amazonaws.com", source_ip="198.51.100.10",
            identity=_identity("AssumedRole", role_name="monitoring-role"),
            read_only=True),
        # A GetObject from a CI/CD pipeline service account (MEDIUM at most).
        _ct("GetObject", "s3.amazonaws.com", source_ip="198.51.100.11",
            identity=_identity("AssumedRole", role_name="ci-cd-deploy-role"),
            request_params={"bucketName": "build-artifacts", "key": "app.zip"},
            read_only=True),
        # A ConsoleLogin WITH MFA enabled (no alert).
        _ct("ConsoleLogin", "signin.amazonaws.com", source_ip="198.51.100.12",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            identity=_identity("IAMUser", user_name="admin"),
            response_elements={"ConsoleLogin": "Success"},
            additional_event_data={"MFAUsed": "Yes"}),
        # A ListBuckets from the root account (LOW at most).
        _ct("ListBuckets", "s3.amazonaws.com", source_ip="198.51.100.13",
            identity=_identity("Root"), read_only=True),
        # An AssumeRole within the same account (MEDIUM at most, standard tooling).
        _ct("AssumeRole", "sts.amazonaws.com", source_ip="198.51.100.14",
            identity=_identity("IAMUser", user_name="ci-runner"),
            request_params={"roleArn": f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-role",
                            "roleSessionName": "ci"}),
    ]


def get_mock_events() -> list[dict]:
    """All mock events: attack events followed by benign events."""
    return get_attack_events() + get_benign_events()


# Module-level snapshots (stable for the life of the process).
ATTACK_EVENTS: list[dict] = get_attack_events()
BENIGN_EVENTS: list[dict] = get_benign_events()
ALL_MOCK_EVENTS: list[dict] = ATTACK_EVENTS + BENIGN_EVENTS
