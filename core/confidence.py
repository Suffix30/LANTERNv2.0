from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class ConfidenceLevel(Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    @property
    def numeric(self) -> float:
        values = {
            "CONFIRMED": 1.0,
            "HIGH": 0.8,
            "MEDIUM": 0.6,
            "LOW": 0.4,
            "INFO": 0.2,
        }
        return values.get(self.value, 0.0)
    
    def __lt__(self, other):
        if isinstance(other, ConfidenceLevel):
            order = ["INFO", "LOW", "MEDIUM", "HIGH", "CONFIRMED"]
            return order.index(self.value) < order.index(other.value)
        return NotImplemented


@dataclass
class EvidenceItem:
    name: str
    description: str
    weight: float = 1.0
    category: str = "general"
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "weight": self.weight,
            "category": self.category,
        }


@dataclass
class ConfidenceResult:
    level: ConfidenceLevel
    score: float
    evidence: List[EvidenceItem]
    explanation: str
    missing_for_upgrade: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "score": self.score,
            "evidence": [e.to_dict() for e in self.evidence],
            "explanation": self.explanation,
            "missing_for_upgrade": self.missing_for_upgrade,
        }


EVIDENCE_DEFINITIONS = {
    "sqli": {
        "CONFIRMED": [
            EvidenceItem("data_extracted", "Actual database data was extracted", 1.0, "extraction"),
            EvidenceItem("union_columns_found", "UNION query returned enumerated columns", 0.9, "extraction"),
            EvidenceItem("time_delay_verified", "Consistent time delays across multiple tests", 0.85, "timing"),
            EvidenceItem("oob_callback_received", "Out-of-band callback confirmed", 1.0, "oob"),
            EvidenceItem("stacked_query_executed", "Stacked query was executed", 0.95, "execution"),
        ],
        "HIGH": [
            EvidenceItem("db_error_detailed", "Database-specific error message returned", 0.7, "error"),
            EvidenceItem("boolean_diff_verified", "True/false responses consistently differ", 0.75, "boolean"),
            EvidenceItem("syntax_error_triggered", "SQL syntax error on malformed input", 0.65, "error"),
            EvidenceItem("version_extracted", "Database version string extracted", 0.8, "extraction"),
        ],
        "MEDIUM": [
            EvidenceItem("error_message_generic", "Generic database error returned", 0.5, "error"),
            EvidenceItem("response_anomaly", "Response changed with SQL characters", 0.45, "behavior"),
            EvidenceItem("single_quote_diff", "Single quote causes different behavior", 0.5, "behavior"),
        ],
        "LOW": [
            EvidenceItem("payload_not_rejected", "SQL payload was not filtered", 0.3, "behavior"),
            EvidenceItem("no_error_on_injection", "No error returned on injection", 0.25, "behavior"),
        ],
    },
    "xss": {
        "CONFIRMED": [
            EvidenceItem("payload_executed", "JavaScript execution confirmed via callback", 1.0, "execution"),
            EvidenceItem("dom_manipulation_verified", "DOM was modified by injected script", 0.95, "execution"),
            EvidenceItem("alert_triggered", "Alert/prompt/confirm triggered in browser", 0.9, "execution"),
            EvidenceItem("oob_callback_received", "XSS triggered OOB callback", 1.0, "oob"),
        ],
        "HIGH": [
            EvidenceItem("unencoded_in_html", "Payload reflected without HTML encoding", 0.75, "reflection"),
            EvidenceItem("context_breakout", "Can break out of current context", 0.8, "context"),
            EvidenceItem("event_handler_injectable", "Event handler attribute injectable", 0.85, "context"),
            EvidenceItem("script_tag_injectable", "Script tag can be injected", 0.85, "injection"),
        ],
        "MEDIUM": [
            EvidenceItem("partial_reflection", "Payload partially reflected", 0.5, "reflection"),
            EvidenceItem("attribute_injection", "Can inject into HTML attribute", 0.55, "context"),
            EvidenceItem("csp_weak", "CSP is weak or bypassable", 0.45, "defense"),
        ],
        "LOW": [
            EvidenceItem("reflected_encoded", "Payload reflected but encoded", 0.3, "reflection"),
            EvidenceItem("filter_bypass_needed", "Filter present but may be bypassable", 0.35, "defense"),
        ],
    },
    "ssrf": {
        "CONFIRMED": [
            EvidenceItem("oob_callback_received", "HTTP/DNS callback received", 1.0, "oob"),
            EvidenceItem("internal_data_returned", "Internal service data in response", 0.95, "data"),
            EvidenceItem("metadata_accessed", "Cloud metadata endpoint accessed", 1.0, "cloud"),
            EvidenceItem("file_content_returned", "Local file content returned via file://", 0.95, "file"),
        ],
        "HIGH": [
            EvidenceItem("different_response_internal", "Different response for internal URL", 0.7, "behavior"),
            EvidenceItem("timing_indicates_request", "Timing suggests request was made", 0.65, "timing"),
            EvidenceItem("error_reveals_request", "Error message reveals request attempt", 0.75, "error"),
            EvidenceItem("dns_resolution_confirmed", "DNS resolution of payload confirmed", 0.8, "dns"),
        ],
        "MEDIUM": [
            EvidenceItem("url_parameter_accepted", "URL parameter accepted without error", 0.45, "behavior"),
            EvidenceItem("redirect_followed", "Server followed redirect to payload", 0.55, "behavior"),
        ],
        "LOW": [
            EvidenceItem("no_validation_error", "No URL validation error returned", 0.3, "behavior"),
        ],
    },
    "xxe": {
        "CONFIRMED": [
            EvidenceItem("file_content_extracted", "Local file content returned", 1.0, "extraction"),
            EvidenceItem("oob_callback_received", "OOB XXE callback received", 1.0, "oob"),
            EvidenceItem("ssrf_via_xxe", "SSRF achieved via XXE", 0.95, "ssrf"),
        ],
        "HIGH": [
            EvidenceItem("entity_parsed", "XML entity was parsed/expanded", 0.75, "parsing"),
            EvidenceItem("error_reveals_path", "Error reveals file path", 0.7, "error"),
            EvidenceItem("dtd_loaded", "External DTD was loaded", 0.8, "dtd"),
        ],
        "MEDIUM": [
            EvidenceItem("xml_parsed", "XML input was parsed", 0.5, "parsing"),
            EvidenceItem("entity_declared", "Entity declaration accepted", 0.55, "parsing"),
        ],
        "LOW": [
            EvidenceItem("xml_accepted", "XML content type accepted", 0.3, "behavior"),
        ],
    },
    "ssti": {
        "CONFIRMED": [
            EvidenceItem("math_evaluated", "Mathematical expression evaluated (7*7=49)", 1.0, "execution"),
            EvidenceItem("rce_achieved", "Remote code execution achieved", 1.0, "execution"),
            EvidenceItem("template_syntax_executed", "Template-specific syntax executed", 0.95, "execution"),
            EvidenceItem("oob_callback_received", "OOB callback via SSTI", 1.0, "oob"),
        ],
        "HIGH": [
            EvidenceItem("template_error", "Template engine error message", 0.75, "error"),
            EvidenceItem("object_access", "Template object/class accessed", 0.8, "access"),
            EvidenceItem("config_leaked", "Configuration data leaked", 0.85, "data"),
        ],
        "MEDIUM": [
            EvidenceItem("expression_reflected", "Template expression reflected differently", 0.5, "reflection"),
            EvidenceItem("syntax_error", "Template syntax error triggered", 0.55, "error"),
        ],
        "LOW": [
            EvidenceItem("special_chars_not_escaped", "Template special chars not escaped", 0.35, "behavior"),
        ],
    },
    "lfi": {
        "CONFIRMED": [
            EvidenceItem("file_content_returned", "File content returned (e.g., /etc/passwd)", 1.0, "extraction"),
            EvidenceItem("source_code_leaked", "Application source code leaked", 0.95, "extraction"),
            EvidenceItem("sensitive_file_read", "Sensitive config file read", 0.95, "extraction"),
        ],
        "HIGH": [
            EvidenceItem("path_traversal_works", "Path traversal sequences not filtered", 0.75, "traversal"),
            EvidenceItem("error_reveals_path", "Error reveals server file path", 0.7, "error"),
            EvidenceItem("wrapper_works", "PHP wrapper (php://filter) works", 0.85, "wrapper"),
        ],
        "MEDIUM": [
            EvidenceItem("different_response", "Different response for valid path", 0.5, "behavior"),
            EvidenceItem("null_byte_accepted", "Null byte not filtered", 0.55, "bypass"),
        ],
        "LOW": [
            EvidenceItem("path_param_exists", "File path parameter identified", 0.3, "discovery"),
        ],
    },
    "cmdi": {
        "CONFIRMED": [
            EvidenceItem("command_output_returned", "Command output in response", 1.0, "execution"),
            EvidenceItem("oob_callback_received", "OOB callback (curl/wget/dns)", 1.0, "oob"),
            EvidenceItem("file_created", "File created on server", 0.95, "execution"),
            EvidenceItem("time_delay_verified", "Sleep/timeout delay verified", 0.9, "timing"),
        ],
        "HIGH": [
            EvidenceItem("error_reveals_command", "Error reveals command execution", 0.75, "error"),
            EvidenceItem("shell_metachar_works", "Shell metacharacters not filtered", 0.7, "bypass"),
        ],
        "MEDIUM": [
            EvidenceItem("response_differs", "Response differs with command chars", 0.5, "behavior"),
        ],
        "LOW": [
            EvidenceItem("no_filtering", "No apparent input filtering", 0.3, "behavior"),
        ],
    },
    "upload": {
        "CONFIRMED": [
            EvidenceItem("code_executed", "Uploaded code was executed", 1.0, "execution"),
            EvidenceItem("shell_access", "Web shell provides access", 1.0, "execution"),
            EvidenceItem("rce_via_upload", "RCE achieved via upload", 1.0, "execution"),
        ],
        "HIGH": [
            EvidenceItem("executable_uploaded", "Executable file type uploaded", 0.8, "upload"),
            EvidenceItem("path_disclosed", "Upload path disclosed", 0.7, "disclosure"),
            EvidenceItem("extension_bypass", "Extension validation bypassed", 0.75, "bypass"),
            EvidenceItem("content_type_bypass", "Content-Type validation bypassed", 0.7, "bypass"),
        ],
        "MEDIUM": [
            EvidenceItem("file_accessible", "Uploaded file is accessible", 0.55, "access"),
            EvidenceItem("filename_preserved", "Original filename preserved", 0.5, "behavior"),
        ],
        "LOW": [
            EvidenceItem("upload_accepted", "File upload accepted", 0.3, "behavior"),
        ],
    },
    "idor": {
        "CONFIRMED": [
            EvidenceItem("other_user_data", "Accessed another user's data", 1.0, "access"),
            EvidenceItem("data_modified", "Modified another user's data", 1.0, "modification"),
            EvidenceItem("admin_data_accessed", "Accessed admin-only data", 0.95, "escalation"),
        ],
        "HIGH": [
            EvidenceItem("id_enumeration", "Can enumerate valid IDs", 0.7, "enumeration"),
            EvidenceItem("different_data_returned", "Different data for different IDs", 0.75, "access"),
            EvidenceItem("no_authz_check", "No authorization check on resource", 0.8, "access"),
        ],
        "MEDIUM": [
            EvidenceItem("predictable_ids", "IDs are sequential/predictable", 0.5, "enumeration"),
            EvidenceItem("id_in_response", "Resource ID exposed in response", 0.45, "disclosure"),
        ],
        "LOW": [
            EvidenceItem("direct_reference", "Direct object reference in URL", 0.3, "discovery"),
        ],
    },
    "auth": {
        "CONFIRMED": [
            EvidenceItem("bypass_achieved", "Authentication completely bypassed", 1.0, "bypass"),
            EvidenceItem("admin_access_gained", "Admin access without credentials", 1.0, "escalation"),
            EvidenceItem("credentials_extracted", "Valid credentials extracted", 0.95, "extraction"),
        ],
        "HIGH": [
            EvidenceItem("default_creds_work", "Default credentials accepted", 0.8, "credentials"),
            EvidenceItem("brute_force_possible", "No rate limiting on auth", 0.7, "bruteforce"),
            EvidenceItem("session_fixation", "Session fixation possible", 0.75, "session"),
            EvidenceItem("weak_password_accepted", "Weak password policy", 0.65, "policy"),
        ],
        "MEDIUM": [
            EvidenceItem("user_enumeration", "Username enumeration possible", 0.55, "enumeration"),
            EvidenceItem("timing_leak", "Timing difference reveals valid users", 0.5, "timing"),
            EvidenceItem("lockout_missing", "No account lockout", 0.5, "policy"),
        ],
        "LOW": [
            EvidenceItem("verbose_errors", "Verbose authentication errors", 0.35, "disclosure"),
        ],
    },
    "jwt": {
        "CONFIRMED": [
            EvidenceItem("none_algorithm_works", "'none' algorithm accepted", 1.0, "bypass"),
            EvidenceItem("key_confusion", "RS256/HS256 confusion exploited", 0.95, "bypass"),
            EvidenceItem("weak_secret_cracked", "Weak secret cracked", 0.9, "weakness"),
            EvidenceItem("forged_token_accepted", "Forged token was accepted", 1.0, "bypass"),
        ],
        "HIGH": [
            EvidenceItem("algorithm_not_verified", "Algorithm header not verified", 0.8, "weakness"),
            EvidenceItem("signature_not_verified", "Signature not properly verified", 0.85, "weakness"),
            EvidenceItem("expired_token_accepted", "Expired tokens accepted", 0.7, "weakness"),
        ],
        "MEDIUM": [
            EvidenceItem("sensitive_data_in_jwt", "Sensitive data in JWT payload", 0.5, "disclosure"),
            EvidenceItem("weak_expiry", "Very long token expiry", 0.45, "policy"),
        ],
        "LOW": [
            EvidenceItem("jwt_in_use", "JWT authentication in use", 0.3, "discovery"),
        ],
    },
    "cors": {
        "CONFIRMED": [
            EvidenceItem("arbitrary_origin_reflected", "Arbitrary origin reflected with credentials", 1.0, "misconfiguration"),
            EvidenceItem("null_origin_allowed", "null origin allowed with credentials", 0.95, "misconfiguration"),
            EvidenceItem("sensitive_data_exposed", "Sensitive data accessible cross-origin", 0.95, "data"),
        ],
        "HIGH": [
            EvidenceItem("wildcard_with_creds", "Wildcard with credentials (invalid but may work)", 0.7, "misconfiguration"),
            EvidenceItem("subdomain_takeover_risk", "Subdomain in CORS can be taken over", 0.8, "risk"),
        ],
        "MEDIUM": [
            EvidenceItem("origin_reflected", "Origin reflected without credentials", 0.5, "misconfiguration"),
            EvidenceItem("regex_bypass", "Origin regex can be bypassed", 0.55, "bypass"),
        ],
        "LOW": [
            EvidenceItem("cors_headers_present", "CORS headers present", 0.3, "discovery"),
        ],
    },
    "default": {
        "CONFIRMED": [
            EvidenceItem("exploited", "Vulnerability successfully exploited", 1.0, "exploitation"),
            EvidenceItem("data_extracted", "Sensitive data extracted", 0.95, "data"),
        ],
        "HIGH": [
            EvidenceItem("strong_indicator", "Strong vulnerability indicator", 0.75, "indicator"),
            EvidenceItem("error_based", "Error confirms vulnerability", 0.7, "error"),
        ],
        "MEDIUM": [
            EvidenceItem("behavior_change", "Behavior changed with payload", 0.5, "behavior"),
        ],
        "LOW": [
            EvidenceItem("possible", "Possibly vulnerable", 0.3, "possible"),
        ],
    },
}


class ConfidenceScorer:
    def __init__(self, definitions: Dict = None):
        self.definitions = definitions or EVIDENCE_DEFINITIONS
    
    def calculate(self, vuln_type: str, evidence_items: List[str]) -> ConfidenceResult:
        vuln_defs = self.definitions.get(vuln_type, self.definitions.get("default", {}))
        
        evidence_objs = []
        total_weight = 0.0
        
        for level_name in ["CONFIRMED", "HIGH", "MEDIUM", "LOW"]:
            level_evidence = vuln_defs.get(level_name, [])
            for ev in level_evidence:
                if ev.name in evidence_items:
                    evidence_objs.append(ev)
                    total_weight += ev.weight
        
        if not evidence_objs:
            return ConfidenceResult(
                level=ConfidenceLevel.INFO,
                score=0.0,
                evidence=[],
                explanation="No matching evidence found",
                missing_for_upgrade=self._get_upgrade_requirements(vuln_type, ConfidenceLevel.INFO),
            )
        
        max_weight = max(ev.weight for ev in evidence_objs)
        avg_weight = total_weight / len(evidence_objs)
        score = (max_weight * 0.6) + (avg_weight * 0.3) + (min(len(evidence_objs) / 3, 1.0) * 0.1)
        
        if score >= 0.9 or max_weight >= 0.95:
            level = ConfidenceLevel.CONFIRMED
        elif score >= 0.7 or max_weight >= 0.7:
            level = ConfidenceLevel.HIGH
        elif score >= 0.5:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW
        
        explanation = self._generate_explanation(level, evidence_objs, score)
        missing = self._get_upgrade_requirements(vuln_type, level)
        
        return ConfidenceResult(
            level=level,
            score=score,
            evidence=evidence_objs,
            explanation=explanation,
            missing_for_upgrade=missing,
        )
    
    def verify_and_upgrade(self, vuln_type: str, current_evidence: List[str], new_evidence: List[str]) -> ConfidenceResult:
        combined = list(set(current_evidence + new_evidence))
        return self.calculate(vuln_type, combined)
    
    def get_verification_steps(self, vuln_type: str, current_level: ConfidenceLevel) -> List[str]:
        vuln_defs = self.definitions.get(vuln_type, self.definitions.get("default", {}))
        
        target_levels = []
        found_current = False
        for level_name in ["CONFIRMED", "HIGH", "MEDIUM", "LOW"]:
            if level_name == current_level.value:
                found_current = True
            elif not found_current:
                target_levels.append(level_name)
        
        steps = []
        for level_name in target_levels:
            level_evidence = vuln_defs.get(level_name, [])
            for ev in level_evidence:
                steps.append(f"[{level_name}] {ev.name}: {ev.description}")
        
        return steps
    
    def adjust_severity(self, original_severity: str, confidence: ConfidenceLevel) -> str:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        
        if confidence == ConfidenceLevel.LOW:
            idx = severity_order.index(original_severity) if original_severity in severity_order else 2
            return severity_order[min(idx + 1, 4)]
        
        if confidence == ConfidenceLevel.INFO:
            return "INFO"
        
        return original_severity
    
    def _get_upgrade_requirements(self, vuln_type: str, current_level: ConfidenceLevel) -> List[str]:
        vuln_defs = self.definitions.get(vuln_type, self.definitions.get("default", {}))
        
        if current_level == ConfidenceLevel.CONFIRMED:
            return []
        
        level_map = {
            ConfidenceLevel.HIGH: "CONFIRMED",
            ConfidenceLevel.MEDIUM: "HIGH",
            ConfidenceLevel.LOW: "MEDIUM",
            ConfidenceLevel.INFO: "LOW",
        }
        
        target_level = level_map.get(current_level, "MEDIUM")
        target_evidence = vuln_defs.get(target_level, [])
        
        return [f"{ev.name}: {ev.description}" for ev in target_evidence[:3]]
    
    def _generate_explanation(self, level: ConfidenceLevel, evidence: List[EvidenceItem], score: float) -> str:
        evidence_names = [ev.name for ev in evidence]
        
        if level == ConfidenceLevel.CONFIRMED:
            return f"Confirmed with high-confidence evidence: {', '.join(evidence_names[:3])}"
        elif level == ConfidenceLevel.HIGH:
            return f"High confidence based on: {', '.join(evidence_names[:3])}"
        elif level == ConfidenceLevel.MEDIUM:
            return f"Medium confidence - behavioral indicators: {', '.join(evidence_names[:2])}"
        elif level == ConfidenceLevel.LOW:
            return f"Low confidence - weak indicators only: {', '.join(evidence_names[:2])}"
        else:
            return "Informational - no strong evidence"


def create_scorer(custom_definitions: Dict = None) -> ConfidenceScorer:
    return ConfidenceScorer(custom_definitions)


def quick_score(vuln_type: str, evidence: List[str]) -> ConfidenceResult:
    scorer = ConfidenceScorer()
    return scorer.calculate(vuln_type, evidence)
