import json
import sys
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass


@dataclass
class CICDConfig:
    fail_on: str = "HIGH"
    exit_codes: bool = True
    sarif_output: Optional[Path] = None
    junit_output: Optional[Path] = None
    threshold_critical: int = 0
    threshold_high: int = 0
    threshold_medium: int = -1
    threshold_low: int = -1


class ExitCodes:
    SUCCESS = 0
    VULNERABILITIES_FOUND = 1
    THRESHOLD_EXCEEDED = 2
    SCAN_ERROR = 3
    CONFIG_ERROR = 4


class CICDReporter:
    def __init__(self, config: CICDConfig):
        self.config = config
        self.severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    
    def calculate_exit_code(self, findings: List[Dict]) -> int:
        if not findings:
            return ExitCodes.SUCCESS
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for finding in findings:
            severity = finding.get("severity", "INFO").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        if self.config.threshold_critical >= 0 and severity_counts["CRITICAL"] > self.config.threshold_critical:
            return ExitCodes.THRESHOLD_EXCEEDED
        
        if self.config.threshold_high >= 0 and severity_counts["HIGH"] > self.config.threshold_high:
            return ExitCodes.THRESHOLD_EXCEEDED
        
        if self.config.threshold_medium >= 0 and severity_counts["MEDIUM"] > self.config.threshold_medium:
            return ExitCodes.THRESHOLD_EXCEEDED
        
        if self.config.threshold_low >= 0 and severity_counts["LOW"] > self.config.threshold_low:
            return ExitCodes.THRESHOLD_EXCEEDED
        
        fail_severity = self.severity_order.get(self.config.fail_on.upper(), 3)
        
        for finding in findings:
            finding_severity = self.severity_order.get(finding.get("severity", "INFO").upper(), 0)
            if finding_severity >= fail_severity:
                return ExitCodes.VULNERABILITIES_FOUND
        
        return ExitCodes.SUCCESS
    
    def generate_sarif(self, findings: List[Dict], target: str) -> Dict:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LANTERN",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/Suffix30/LANTERNv2.0",
                            "rules": self._generate_rules(findings),
                        }
                    },
                    "results": self._generate_results(findings),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }
        
        return sarif
    
    def _generate_rules(self, findings: List[Dict]) -> List[Dict]:
        rules = {}
        
        for finding in findings:
            rule_id = finding.get("module", "unknown")
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("description", rule_id),
                    "shortDescription": {"text": finding.get("description", "")[:100]},
                    "fullDescription": {"text": finding.get("description", "")},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.get("severity", "INFO"))
                    },
                    "properties": {
                        "security-severity": self._severity_to_score(finding.get("severity", "INFO"))
                    },
                }
        
        return list(rules.values())
    
    def _generate_results(self, findings: List[Dict]) -> List[Dict]:
        results = []
        
        for idx, finding in enumerate(findings):
            result = {
                "ruleId": finding.get("module", "unknown"),
                "level": self._severity_to_sarif_level(finding.get("severity", "INFO")),
                "message": {"text": finding.get("description", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("url", "")},
                        }
                    }
                ],
                "properties": {
                    "evidence": finding.get("evidence", ""),
                    "parameter": finding.get("parameter", ""),
                },
            }
            results.append(result)
        
        return results
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }
        return mapping.get(severity.upper(), "note")
    
    def _severity_to_score(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "9.0",
            "HIGH": "7.0",
            "MEDIUM": "5.0",
            "LOW": "3.0",
            "INFO": "1.0",
        }
        return mapping.get(severity.upper(), "1.0")
    
    def generate_junit(self, findings: List[Dict], target: str) -> str:
        test_count = len(findings) if findings else 1
        failure_count = sum(1 for f in findings if f.get("severity") in ["CRITICAL", "HIGH"])
        
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<testsuite name="LANTERN Security Scan" tests="{test_count}" failures="{failure_count}" errors="0">',
        ]
        
        if not findings:
            xml_lines.append(f'  <testcase name="No vulnerabilities found" classname="lantern.scan" time="0"/>')
        else:
            for finding in findings:
                name = finding.get("description", "Unknown")[:80].replace('"', '&quot;')
                classname = f"lantern.{finding.get('module', 'unknown')}"
                severity = finding.get("severity", "INFO")
                
                xml_lines.append(f'  <testcase name="{name}" classname="{classname}" time="0">')
                
                if severity in ["CRITICAL", "HIGH"]:
                    evidence = finding.get("evidence", "").replace('"', '&quot;').replace("<", "&lt;").replace(">", "&gt;")
                    xml_lines.append(f'    <failure message="{severity}: {name}" type="{severity}">')
                    xml_lines.append(f'      URL: {finding.get("url", "")}')
                    xml_lines.append(f'      Evidence: {evidence}')
                    xml_lines.append('    </failure>')
                
                xml_lines.append('  </testcase>')
        
        xml_lines.append('</testsuite>')
        
        return "\n".join(xml_lines)
    
    def write_outputs(self, findings: List[Dict], target: str) -> None:
        if self.config.sarif_output:
            sarif = self.generate_sarif(findings, target)
            self.config.sarif_output.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config.sarif_output, "w") as f:
                json.dump(sarif, f, indent=2)
        
        if self.config.junit_output:
            junit = self.generate_junit(findings, target)
            self.config.junit_output.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config.junit_output, "w") as f:
                f.write(junit)
    
    def exit_with_code(self, findings: List[Dict]) -> None:
        if self.config.exit_codes:
            code = self.calculate_exit_code(findings)
            sys.exit(code)


def create_cicd_config(args) -> CICDConfig:
    config = CICDConfig()
    
    if hasattr(args, "fail_on") and args.fail_on:
        config.fail_on = args.fail_on
    
    if hasattr(args, "ci") and args.ci:
        config.exit_codes = True
    
    if hasattr(args, "sarif") and args.sarif:
        config.sarif_output = Path(args.sarif)
    
    if hasattr(args, "junit") and args.junit:
        config.junit_output = Path(args.junit)
    
    if hasattr(args, "threshold_critical"):
        config.threshold_critical = args.threshold_critical
    
    if hasattr(args, "threshold_high"):
        config.threshold_high = args.threshold_high
    
    return config


def get_exit_code_description(code: int) -> str:
    descriptions = {
        ExitCodes.SUCCESS: "No vulnerabilities above threshold",
        ExitCodes.VULNERABILITIES_FOUND: "Vulnerabilities found at or above fail-on severity",
        ExitCodes.THRESHOLD_EXCEEDED: "Vulnerability count threshold exceeded",
        ExitCodes.SCAN_ERROR: "Scan error occurred",
        ExitCodes.CONFIG_ERROR: "Configuration error",
    }
    return descriptions.get(code, "Unknown exit code")
