# MITRE ATT&CK Cloud TTP Detection Engine

This is a small detection engine for AWS CloudTrail. You feed it CloudTrail
events, it figures out which MITRE ATT&CK Cloud techniques they map to, attaches
the real ATT&CK metadata for each one, and hands back analyst-ready alerts. There's
a REST API in front of it and a dashboard that shows what you're catching and,
more usefully, what you're not.

The thing I cared about most while building it: detection rules are *data*, not
code. A rule is just an object that says "watch this service, these API calls,
and optionally run this extra check." The engine itself knows nothing about
ATT&CK — it loops over rules and asks "does this event match?" That separation is
the whole point. Adding a detection shouldn't mean editing the engine.

---

## How it fits together

```
                ┌───────────────────────────────────────────────────────────┐
                │                        FastAPI (main.py)                    │
                │   /ingest  /analyze  /alerts  /coverage  /dashboard /health │
                └───────────────┬─────────────────────────────┬─────────────┘
                                │ routes call the pipeline      │ read-only
                                ▼                               ▼
   raw CloudTrail        ┌────────────────────────────────────────────┐
   (file / boto3 /  ───► │              DetectionPipeline               │
    HTTP body)           │                                              │
                         │  normalize ─► evaluate ─► enrich ─► build     │
                         └─────┬───────────┬───────────┬──────────┬─────┘
                               ▼           ▼           ▼          ▼
                        normalizer.py  rules_engine  enricher  alert_builder
                          (reshape)     (rules = data) (STIX)    (Alert+UUID)
                               │            │            │          │
                               ▼            ▼            ▼          ▼
                        NormalizedEvent  RuleMatch  Technique-   Alert ──► in-memory
                                                    Metadata           alert store (list)
                                                       ▲
                                          data/enterprise-attack.json
                                          (official MITRE STIX bundle)
```

Each layer has one job and doesn't reach into the others:

| Layer        | File                       | What it does                                       |
|--------------|----------------------------|----------------------------------------------------|
| Models       | `core/models.py`           | Every Pydantic v2 shape lives here, nowhere else   |
| Rules        | `rules/cloud_ttp_rules.py` | 39 rule objects plus their condition functions     |
| Normalize    | `core/normalizer.py`       | CloudTrail JSON in, `NormalizedEvent` out          |
| Detect       | `core/rules_engine.py`     | Generic matching; has no idea what ATT&CK is       |
| Enrich       | `core/enricher.py`         | Loads the STIX bundle once, resolves technique data |
| Build        | `core/alert_builder.py`    | Stitches rule + event + metadata into an `Alert`   |
| Ingest       | `ingestion/`               | File/boto3 readers and a pile of realistic mocks   |
| API          | `api/`                     | Thin routes that just call the pipeline            |

A few rules I held myself to: the engine never enriches or mutates anything, the
normalizer and enricher never make detection decisions, and the route handlers
never contain detection logic. If you find any of those creeping in, something's
gone wrong.

---

## Getting it running

You'll need Python 3.10 or newer.

```bash
cd mitre-detection-engine
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # tweak if you like
```

### The ATT&CK data

The enricher reads `data/enterprise-attack.json` — the official MITRE STIX bundle
— exactly once at startup. If it's not there, the app refuses to start and tells
you where to get it. Grab it from <https://github.com/mitre/cti>
(`enterprise-attack/enterprise-attack.json`) and drop it in `data/`, or point
`STIX_DATA_PATH` somewhere else.

Heads up: it's a ~45 MB file and parsing it takes a few seconds on startup. That's
normal.

### Start the server

```bash
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000/dashboard> (the root path redirects there anyway), or
poke at the auto-generated docs at <http://127.0.0.1:8000/docs>.

### Run the tests

```bash
pytest tests/ -v
```

That's 33 tests covering the normalizer, the rules engine, the enricher (against
the actual STIX file — nothing mocked), the alert builder, and the mock events.

---

## The endpoints, with examples

Fire a single suspicious event at it — disabling CloudTrail logging, which is
about as loud as it gets:

```bash
curl -s -X POST http://127.0.0.1:8000/ingest \
  -H 'Content-Type: application/json' \
  -d '[{"eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com",
        "eventTime":"2026-06-23T09:00:00Z","awsRegion":"us-east-1",
        "sourceIPAddress":"198.51.100.80","userAgent":"x",
        "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/r/s"},
        "readOnly":false}]'
```

`/ingest` takes a JSON array; `/analyze` takes a single event and is handy for
interactive poking:

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"eventName":"GetObject","eventSource":"s3.amazonaws.com",
       "eventTime":"2026-06-23T09:00:00Z","awsRegion":"us-east-1",
       "sourceIPAddress":"198.51.100.23","userAgent":"x",
       "userIdentity":{"type":"AssumedRole"},"readOnly":true}'
```

Read back what it found. The filters stack, newest alerts come first:

```bash
curl -s 'http://127.0.0.1:8000/alerts'
curl -s 'http://127.0.0.1:8000/alerts?severity=CRITICAL'
curl -s 'http://127.0.0.1:8000/alerts?technique_id=T1562.008'
curl -s 'http://127.0.0.1:8000/alerts?tactic=Exfiltration&limit=10&offset=0'
curl -s 'http://127.0.0.1:8000/alerts/<alert-id>'      # 404 if it doesn't exist
```

Coverage — how much of the cloud matrix you actually detect, and a per-technique
lookup:

```bash
curl -s http://127.0.0.1:8000/coverage
curl -s http://127.0.0.1:8000/coverage/technique/T1530
curl -s http://127.0.0.1:8000/coverage/technique/T9999    # 404
```

And the rest:

```bash
curl -s http://127.0.0.1:8000/dashboard    # HTML
curl -s http://127.0.0.1:8000/health
```

If you just want to see the dashboard light up, push all the bundled mocks
through in one go:

```python
from ingestion.mock_events import get_mock_events
import requests
requests.post("http://127.0.0.1:8000/ingest", json=get_mock_events())
```

---

## Pointing it at real logs

`ingestion/cloudtrail_reader.py` has two readers. Both return a plain list of
event dicts, which is exactly what the pipeline wants.

From files — it copes with `{"Records": [...]}` log files, a bare JSON array, or
a whole directory of `.json` files:

```python
from ingestion.cloudtrail_reader import read_from_file
records = read_from_file("data/my_cloudtrail_logs/")     # file or directory
```

Or live, straight from the CloudTrail API (you'll need AWS credentials — it uses
whatever boto3 finds via `AWS_PROFILE`, env vars, or an instance role):

```python
from ingestion.cloudtrail_reader import read_from_aws
records = read_from_aws(region="us-east-1", max_events=100)
```

Either way, POST the list to `/ingest`. Set `CLOUDTRAIL_LOG_PATH` in `.env` if you
want a default file source.

---

## What it detects

39 rules, mapping to 20 distinct ATT&CK techniques across 9 tactics.

One thing worth being upfront about: the original brief's summary said "22
techniques," but the technique list it actually spelled out only contains 20
distinct IDs. I built exactly the rules that were enumerated (`RULE-001` through
`RULE-039`), so 20 is the honest number. Every rule in the spec is present.

| Tactic                 | Technique | Name | Rules |
|------------------------|-----------|------|-------|
| Initial Access         | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | 001, 002 |
| Initial Access         | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | 003 |
| Persistence            | [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Create Account: Cloud Account | 004, 005 |
| Persistence            | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | Account Manipulation: Additional Cloud Credentials | 006, 007 |
| Persistence            | [T1546](https://attack.mitre.org/techniques/T1546/) | Event Triggered Execution | 008, 009 |
| Privilege Escalation   | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | 010, 011 |
| Defense Evasion        | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | Impair Defenses: Disable or Modify Cloud Logs | 012, 013, 014, 015 |
| Defense Evasion        | [T1535](https://attack.mitre.org/techniques/T1535/) | Unused/Unsupported Cloud Regions | 016 |
| Defense Evasion        | [T1578](https://attack.mitre.org/techniques/T1578/) | Modify Cloud Compute Infrastructure | 017, 018 |
| Credential Access      | [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | Unsecured Credentials: Cloud Instance Metadata API | 019 |
| Credential Access      | [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | 020, 021 |
| Discovery              | [T1580](https://attack.mitre.org/techniques/T1580/) | Cloud Infrastructure Discovery | 022, 023 |
| Discovery              | [T1069.003](https://attack.mitre.org/techniques/T1069/003/) | Permission Groups Discovery: Cloud Groups | 024, 025 |
| Discovery              | [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | 026, 027, 028 |
| Collection             | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | 029, 030 |
| Exfiltration           | [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | 031, 032 |
| Exfiltration           | [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | 033 |
| Impact                 | [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | 034, 035, 036 |
| Impact                 | [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | 037, 038 |
| Impact                 | [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking | 039 |

### A few things the live ATT&CK data threw at me

Coverage is always computed from whatever STIX bundle you load — none of the
numbers are hardcoded. The bundle I tested against is a 2026 ATT&CK release, and
it surfaced some real-world messiness that the code handles on purpose:

- **The tactics got renamed.** "Defense Evasion" is "Stealth" in the current data,
  and there's a new "Defense Impairment" tactic. Alerts keep the classic tactic
  names from the rules (so `?tactic=Exfiltration` works like the brief expects),
  while `/coverage` groups by whatever the STIX file actually calls them.
- **T1562.008 is flagged `revoked`** in this release. That's a taxonomy change, not
  a sign the behavior stopped mattering — disabling CloudTrail is still about the
  worst thing you can see. So the enricher deliberately keeps revoked techniques
  (it only drops *deprecated* ones), and this detection still enriches and counts.
- **T1567 is a current technique but isn't tagged IaaS** in ATT&CK. `RULE-033`
  still detects it (someone opening a bucket policy to the world), but since it's
  not part of the cloud universe it doesn't show up in the IaaS coverage count.
  That's why `/coverage` reports 19 cloud techniques covered rather than 20 —
  T1567 is a bonus catch that lives outside the cloud scope.

### One deliberate departure on `ConsoleLogin`

The brief said to match `ConsoleLogin` (rules 001/002) on `iam.amazonaws.com`. In
real CloudTrail those events come from `signin.amazonaws.com`, so that's what the
rules use. If they matched the brief literally they'd never fire on actual logs.

---

## Assumptions worth knowing

The alert store is just a Python list hanging off `app.state`. That's fine because
uvicorn runs the handlers on a single event loop, so nothing mutates it
concurrently. Run multiple workers and you'd want a lock — but the brief said
in-memory only, so a list it is.

Both `/ingest` and `/analyze` save their alerts to that store, so the dashboard
and `/alerts` reflect everything, however it came in. And `events_processed`
counts the records that normalized cleanly; a malformed event gets logged and
skipped rather than blowing up the whole batch.
