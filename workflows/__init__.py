from pathlib import Path

WORKFLOWS_DIR = Path(__file__).parent

def get_workflow_path(name: str) -> Path:
    return WORKFLOWS_DIR / f"{name}.yml"

def list_workflows() -> list:
    return [f.stem for f in WORKFLOWS_DIR.glob("*.yml")]

AVAILABLE_WORKFLOWS = {
    "payment_bypass": "Payment/checkout business logic attacks",
    "auth_bypass": "Authentication and session bypass",
    "api_abuse": "API abuse and data extraction",
    "file_upload": "File upload bypass and RCE",
    "ssrf_chain": "SSRF to cloud metadata attacks",
    "sqli_escalate": "SQL injection to shell escalation",
}
