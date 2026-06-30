"""All detection rules expressed as data.

Architecture principle: rules are DATA, not code. Each rule is a
:class:`~core.models.DetectionRule`. The rules engine is generic and knows
nothing about specific techniques -- it only compares ``event_source`` /
``event_names`` and runs the optional ``condition`` callable defined here.

Detection logic lives in exactly two places:
  1. The declarative ``event_source`` + ``event_names`` match on each rule.
  2. The optional ``condition`` function (contextual / behavioural checks).

The ``condition`` callables below are intentionally defensive: they read nested
CloudTrail fields safely and fall back to ``False`` (non-match) rather than
raising. The engine additionally wraps every condition in a try/except, but
keeping conditions side-effect free and total is good hygiene.
"""

from __future__ import annotations

import json
import os

from core.models import DetectionRule, NormalizedEvent

# Default set of regions an organisation is expected to operate in. Overridable
# via the EXPECTED_REGIONS env var (comma separated). Read at call time so the
# value can be configured after this module is imported.
_DEFAULT_EXPECTED_REGIONS = "us-east-1,us-west-2"

# Instance family prefixes associated with expensive GPU compute, commonly
# abused for cryptomining / resource hijacking.
_GPU_INSTANCE_FAMILIES = ("p3", "p4", "p5", "g4", "g5")

# User-agent fragments that indicate first-party / expected AWS tooling. Their
# ABSENCE on a sensitive STS call is treated as a weak suspicious signal.
_STANDARD_UA_MARKERS = (
    "aws-cli",
    "aws-sdk",
    "Boto3",
    "botocore",
    "console.amazonaws.com",
    "signin.amazonaws.com",
)


# --------------------------------------------------------------------------- #
# Small, defensive helpers used by the condition callables.
# --------------------------------------------------------------------------- #
def _expected_regions() -> set[str]:
    raw = os.getenv("EXPECTED_REGIONS", _DEFAULT_EXPECTED_REGIONS)
    return {r.strip() for r in raw.split(",") if r.strip()}


def _params_as_text(event: NormalizedEvent) -> str:
    """Flatten requestParameters to a lowercase JSON string for substring
    checks. Returns empty string when there are no params."""
    if not event.request_params:
        return ""
    try:
        return json.dumps(event.request_params).lower()
    except (TypeError, ValueError):
        return str(event.request_params).lower()


def _mfa_used(event: NormalizedEvent) -> bool:
    """Best-effort extraction of whether MFA was used for a ConsoleLogin.

    CloudTrail exposes this in two places depending on identity type:
      * ``additionalEventData.MFAUsed`` == "Yes"
      * ``userIdentity.sessionContext.attributes.mfaAuthenticated`` == "true"
    """
    raw = event.raw_event or {}
    additional = raw.get("additionalEventData") or {}
    if str(additional.get("MFAUsed", "")).lower() == "yes":
        return True

    session_ctx = (event.user_identity or {}).get("sessionContext") or {}
    attributes = session_ctx.get("attributes") or {}
    if str(attributes.get("mfaAuthenticated", "")).lower() == "true":
        return True
    return False


# --------------------------------------------------------------------------- #
# Condition callables (one per rule that needs contextual logic).
# --------------------------------------------------------------------------- #
def cond_console_login_no_mfa(event: NormalizedEvent) -> bool:
    """RULE-001: a successful console login where MFA was NOT used."""
    response = event.response_elements or {}
    # Only consider successful logins; failures are RULE-002's job.
    if str(response.get("ConsoleLogin", "Success")).lower() == "failure":
        return False
    return not _mfa_used(event)


def cond_console_login_failed(event: NormalizedEvent) -> bool:
    """RULE-002: a failed console login attempt."""
    response = event.response_elements or {}
    if str(response.get("ConsoleLogin", "")).lower() == "failure":
        return True
    if event.error_code and "failed authentication" in event.error_code.lower():
        return True
    if event.error_message and "failed authentication" in event.error_message.lower():
        return True
    return False


def cond_policy_is_admin_or_wildcard(event: NormalizedEvent) -> bool:
    """RULE-010: a user-policy change granting admin / wildcard privileges."""
    text = _params_as_text(event)
    if not text:
        return False
    return (
        "administratoraccess" in text
        or '"action":"*"' in text.replace(" ", "")
        or '"resource":"*"' in text.replace(" ", "")
        or ":policy/poweruseraccess" in text
    )


def cond_unusual_region(event: NormalizedEvent) -> bool:
    """RULE-016: activity in a region outside the expected set."""
    return event.aws_region not in _expected_regions()


def cond_sts_assumed_role_odd_tooling(event: NormalizedEvent) -> bool:
    """RULE-019: GetSessionToken by an assumed role using non-standard tooling.

    A genuine instance/role calling GetSessionToken via the AWS SDK or CLI is
    routine; the same call from an unrecognised user-agent suggests credentials
    have been lifted off the host and replayed elsewhere.
    """
    if event.user_type != "AssumedRole":
        return False
    ua = (event.user_agent or "").lower()
    return not any(marker.lower() in ua for marker in _STANDARD_UA_MARKERS)


def cond_snapshot_shared_externally(event: NormalizedEvent) -> bool:
    """RULE-032: a snapshot's permissions modified to add an external account."""
    params = event.request_params or {}
    create_perm = params.get("createVolumePermission") or {}
    additions = create_perm.get("add") or {}
    # The 'add' block can be a dict with 'items' or a list, depending on shape.
    items = additions.get("items") if isinstance(additions, dict) else additions
    if not isinstance(items, list):
        # Fall back to a substring scan for an account id different from ours.
        text = _params_as_text(event)
        return "userid" in text and (event.account_id or "") not in text
    for entry in items:
        if not isinstance(entry, dict):
            continue
        target = str(entry.get("userId") or entry.get("group") or "")
        if target == "all":
            return True
        if target and target != (event.account_id or ""):
            return True
    return False


def cond_bucket_policy_public(event: NormalizedEvent) -> bool:
    """RULE-033: a bucket policy granting access to any principal ("*")."""
    text = _params_as_text(event).replace(" ", "")
    return '"principal":"*"' in text or '"aws":"*"' in text or '"principal":{"aws":"*"}' in text


def cond_gpu_instance(event: NormalizedEvent) -> bool:
    """RULE-039: launching GPU instance families (cryptomining signal)."""
    params = event.request_params or {}
    instance_type = str(params.get("instanceType", "")).lower()
    return any(instance_type.startswith(fam) for fam in _GPU_INSTANCE_FAMILIES)


# --------------------------------------------------------------------------- #
# The rule set. 39 rules across 22 distinct ATT&CK (sub-)techniques.
# --------------------------------------------------------------------------- #
RULES: list[DetectionRule] = [
    # ---- Initial Access -------------------------------------------------- #
    DetectionRule(
        rule_id="RULE-001",
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic="Initial Access",
        severity="HIGH",
        description="Console login without multi-factor authentication.",
        event_source="signin.amazonaws.com",
        event_names=["ConsoleLogin"],
        condition=cond_console_login_no_mfa,
    ),
    DetectionRule(
        rule_id="RULE-002",
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic="Initial Access",
        severity="MEDIUM",
        description="Failed console login attempt (possible credential guessing).",
        event_source="signin.amazonaws.com",
        event_names=["ConsoleLogin"],
        condition=cond_console_login_failed,
    ),
    DetectionRule(
        rule_id="RULE-003",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        severity="HIGH",
        description="Lambda function code/configuration modified (possible code injection into a public-facing app).",
        event_source="lambda.amazonaws.com",
        event_names=["UpdateFunctionConfiguration", "UpdateFunctionConfiguration20150331v2",
                     "UpdateFunctionCode", "UpdateFunctionCode20150331v2"],
        condition=None,
    ),
    # ---- Persistence ----------------------------------------------------- #
    DetectionRule(
        rule_id="RULE-004",
        technique_id="T1136.003",
        technique_name="Create Account: Cloud Account",
        tactic="Persistence",
        severity="HIGH",
        description="New IAM user created (potential persistence identity).",
        event_source="iam.amazonaws.com",
        event_names=["CreateUser"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-005",
        technique_id="T1136.003",
        technique_name="Create Account: Cloud Account",
        tactic="Persistence",
        severity="MEDIUM",
        description="New IAM role created (potential persistence identity).",
        event_source="iam.amazonaws.com",
        event_names=["CreateRole"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-006",
        technique_id="T1098.001",
        technique_name="Account Manipulation: Additional Cloud Credentials",
        tactic="Persistence",
        severity="HIGH",
        description="Access key created for an IAM user (additional credentials).",
        event_source="iam.amazonaws.com",
        event_names=["CreateAccessKey"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-007",
        technique_id="T1098.001",
        technique_name="Account Manipulation: Additional Cloud Credentials",
        tactic="Persistence",
        severity="MEDIUM",
        description="Login profile (console password) created for an IAM user.",
        event_source="iam.amazonaws.com",
        event_names=["CreateLoginProfile"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-008",
        technique_id="T1546",
        technique_name="Event Triggered Execution",
        tactic="Persistence",
        severity="MEDIUM",
        description="Lambda function created (possible event-triggered backdoor).",
        event_source="lambda.amazonaws.com",
        event_names=["CreateFunction", "CreateFunction20150331"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-009",
        technique_id="T1546",
        technique_name="Event Triggered Execution",
        tactic="Persistence",
        severity="MEDIUM",
        description="EventBridge rule/target created (event-driven execution trigger).",
        event_source="events.amazonaws.com",
        event_names=["PutRule", "PutTargets"],
        condition=None,
    ),
    # ---- Privilege Escalation ------------------------------------------- #
    DetectionRule(
        rule_id="RULE-010",
        technique_id="T1098",
        technique_name="Account Manipulation",
        tactic="Privilege Escalation",
        severity="CRITICAL",
        description="Administrator/wildcard policy attached or inlined to an IAM user (privilege escalation).",
        event_source="iam.amazonaws.com",
        event_names=["AttachUserPolicy", "PutUserPolicy"],
        condition=cond_policy_is_admin_or_wildcard,
    ),
    DetectionRule(
        rule_id="RULE-011",
        technique_id="T1098",
        technique_name="Account Manipulation",
        tactic="Privilege Escalation",
        severity="HIGH",
        description="Policy attached or inlined to an IAM role (possible privilege escalation).",
        event_source="iam.amazonaws.com",
        event_names=["AttachRolePolicy", "PutRolePolicy"],
        condition=None,
    ),
    # ---- Defense Evasion ------------------------------------------------- #
    DetectionRule(
        rule_id="RULE-012",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable or Modify Cloud Logs",
        tactic="Defense Evasion",
        severity="CRITICAL",
        description="CloudTrail logging stopped (defenders blinded).",
        event_source="cloudtrail.amazonaws.com",
        event_names=["StopLogging"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-013",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable or Modify Cloud Logs",
        tactic="Defense Evasion",
        severity="CRITICAL",
        description="CloudTrail trail deleted (audit trail destroyed).",
        event_source="cloudtrail.amazonaws.com",
        event_names=["DeleteTrail"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-014",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable or Modify Cloud Logs",
        tactic="Defense Evasion",
        severity="CRITICAL",
        description="GuardDuty detector deleted (threat detection disabled).",
        event_source="guardduty.amazonaws.com",
        event_names=["DeleteDetector"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-015",
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable or Modify Cloud Logs",
        tactic="Defense Evasion",
        severity="HIGH",
        description="AWS Config configuration recorder stopped (compliance logging disabled).",
        event_source="config.amazonaws.com",
        event_names=["StopConfigurationRecorder"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-016",
        technique_id="T1535",
        technique_name="Unused/Unsupported Cloud Regions",
        tactic="Defense Evasion",
        severity="MEDIUM",
        description="EC2 instance launched in a region outside the expected set.",
        event_source="ec2.amazonaws.com",
        event_names=["RunInstances"],
        condition=cond_unusual_region,
    ),
    DetectionRule(
        rule_id="RULE-017",
        technique_id="T1578",
        technique_name="Modify Cloud Compute Infrastructure",
        tactic="Defense Evasion",
        severity="MEDIUM",
        description="EBS snapshot created (possible data staging or infra tampering).",
        event_source="ec2.amazonaws.com",
        event_names=["CreateSnapshot"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-018",
        technique_id="T1578",
        technique_name="Modify Cloud Compute Infrastructure",
        tactic="Defense Evasion",
        severity="MEDIUM",
        description="EC2 instance attribute modified (possible infrastructure tampering).",
        event_source="ec2.amazonaws.com",
        event_names=["ModifyInstanceAttribute"],
        condition=None,
    ),
    # ---- Credential Access ---------------------------------------------- #
    DetectionRule(
        rule_id="RULE-019",
        technique_id="T1552.005",
        technique_name="Unsecured Credentials: Cloud Instance Metadata API",
        tactic="Credential Access",
        severity="HIGH",
        description="GetSessionToken from an assumed role using non-standard tooling (possible stolen instance credentials).",
        event_source="sts.amazonaws.com",
        event_names=["GetSessionToken"],
        condition=cond_sts_assumed_role_odd_tooling,
    ),
    DetectionRule(
        rule_id="RULE-020",
        technique_id="T1528",
        technique_name="Steal Application Access Token",
        tactic="Credential Access",
        severity="MEDIUM",
        description="AssumeRole call (temporary token issuance).",
        event_source="sts.amazonaws.com",
        event_names=["AssumeRole"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-021",
        technique_id="T1528",
        technique_name="Steal Application Access Token",
        tactic="Credential Access",
        severity="HIGH",
        description="AssumeRoleWithWebIdentity call (federated token issuance, possible token theft).",
        event_source="sts.amazonaws.com",
        event_names=["AssumeRoleWithWebIdentity"],
        condition=None,
    ),
    # ---- Discovery ------------------------------------------------------- #
    DetectionRule(
        rule_id="RULE-022",
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery",
        tactic="Discovery",
        severity="LOW",
        description="EC2 instance enumeration (DescribeInstances).",
        event_source="ec2.amazonaws.com",
        event_names=["DescribeInstances"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-023",
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery",
        tactic="Discovery",
        severity="LOW",
        description="Security group enumeration (DescribeSecurityGroups).",
        event_source="ec2.amazonaws.com",
        event_names=["DescribeSecurityGroups"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-024",
        technique_id="T1069.003",
        technique_name="Permission Groups Discovery: Cloud Groups",
        tactic="Discovery",
        severity="MEDIUM",
        description="IAM identity enumeration (ListUsers / ListRoles).",
        event_source="iam.amazonaws.com",
        event_names=["ListUsers", "ListRoles"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-025",
        technique_id="T1069.003",
        technique_name="Permission Groups Discovery: Cloud Groups",
        tactic="Discovery",
        severity="HIGH",
        description="GetAccountAuthorizationDetails dumps the entire IAM configuration in one call.",
        event_source="iam.amazonaws.com",
        event_names=["GetAccountAuthorizationDetails"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-026",
        technique_id="T1526",
        technique_name="Cloud Service Discovery",
        tactic="Discovery",
        severity="LOW",
        description="S3 bucket enumeration (ListBuckets).",
        event_source="s3.amazonaws.com",
        event_names=["ListBuckets"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-027",
        technique_id="T1526",
        technique_name="Cloud Service Discovery",
        tactic="Discovery",
        severity="LOW",
        description="RDS instance enumeration (DescribeDBInstances).",
        event_source="rds.amazonaws.com",
        event_names=["DescribeDBInstances"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-028",
        technique_id="T1526",
        technique_name="Cloud Service Discovery",
        tactic="Discovery",
        severity="LOW",
        description="Lambda function enumeration (ListFunctions).",
        event_source="lambda.amazonaws.com",
        event_names=["ListFunctions", "ListFunctions20150331"],
        condition=None,
    ),
    # ---- Collection ------------------------------------------------------ #
    DetectionRule(
        rule_id="RULE-029",
        technique_id="T1530",
        technique_name="Data from Cloud Storage",
        tactic="Collection",
        severity="MEDIUM",
        description="Object read from S3 (GetObject).",
        event_source="s3.amazonaws.com",
        event_names=["GetObject"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-030",
        technique_id="T1530",
        technique_name="Data from Cloud Storage",
        tactic="Collection",
        severity="MEDIUM",
        description="S3 bucket ACL/policy read (GetBucketAcl / GetBucketPolicy).",
        event_source="s3.amazonaws.com",
        event_names=["GetBucketPolicy", "GetBucketAcl"],
        condition=None,
    ),
    # ---- Exfiltration ---------------------------------------------------- #
    DetectionRule(
        rule_id="RULE-031",
        technique_id="T1537",
        technique_name="Transfer Data to Cloud Account",
        tactic="Exfiltration",
        severity="CRITICAL",
        description="S3 bucket replication configured (possible data transfer to another account).",
        event_source="s3.amazonaws.com",
        event_names=["PutBucketReplication"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-032",
        technique_id="T1537",
        technique_name="Transfer Data to Cloud Account",
        tactic="Exfiltration",
        severity="CRITICAL",
        description="EBS snapshot shared with an external AWS account.",
        event_source="ec2.amazonaws.com",
        event_names=["ModifySnapshotAttribute"],
        condition=cond_snapshot_shared_externally,
    ),
    DetectionRule(
        rule_id="RULE-033",
        technique_id="T1567",
        technique_name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        severity="HIGH",
        description="S3 bucket policy opened to a public ('*') principal.",
        event_source="s3.amazonaws.com",
        event_names=["PutBucketPolicy"],
        condition=cond_bucket_policy_public,
    ),
    # ---- Impact ---------------------------------------------------------- #
    DetectionRule(
        rule_id="RULE-034",
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        severity="CRITICAL",
        description="S3 bucket deleted (data destruction).",
        event_source="s3.amazonaws.com",
        event_names=["DeleteBucket"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-035",
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        severity="HIGH",
        description="EC2 instances terminated (data/compute destruction).",
        event_source="ec2.amazonaws.com",
        event_names=["TerminateInstances"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-036",
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic="Impact",
        severity="CRITICAL",
        description="RDS database instance deleted (data destruction).",
        event_source="rds.amazonaws.com",
        event_names=["DeleteDBInstance"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-037",
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        severity="CRITICAL",
        description="KMS key scheduled for deletion (ransomware / denial of access to encrypted data).",
        event_source="kms.amazonaws.com",
        event_names=["ScheduleKeyDeletion"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-038",
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic="Impact",
        severity="HIGH",
        description="KMS key disabled (denial of access to encrypted data).",
        event_source="kms.amazonaws.com",
        event_names=["DisableKey"],
        condition=None,
    ),
    DetectionRule(
        rule_id="RULE-039",
        technique_id="T1496",
        technique_name="Resource Hijacking",
        tactic="Impact",
        severity="HIGH",
        description="GPU instance family launched (possible cryptomining / resource hijacking).",
        event_source="ec2.amazonaws.com",
        event_names=["RunInstances"],
        condition=cond_gpu_instance,
    ),
]


def get_all_rules() -> list[DetectionRule]:
    """Return the full, immutable-by-convention rule set."""
    return RULES
