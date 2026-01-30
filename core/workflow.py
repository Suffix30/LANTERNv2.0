import re
import json
import asyncio
import yaml
import copy
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlencode
from pathlib import Path


@dataclass
class StepResult:
    step_name: str
    success: bool
    status: int
    response: dict
    extracted: Dict[str, Any]
    error: Optional[str] = None
    elapsed: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "step_name": self.step_name,
            "success": self.success,
            "status": self.status,
            "extracted": self.extracted,
            "error": self.error,
            "elapsed": self.elapsed,
        }


@dataclass
class WorkflowResult:
    workflow_name: str
    success: bool
    steps_executed: List[StepResult]
    final_state: Dict[str, Any]
    errors: List[str]
    
    def to_dict(self) -> dict:
        return {
            "workflow_name": self.workflow_name,
            "success": self.success,
            "steps_executed": [s.to_dict() for s in self.steps_executed],
            "final_state": self.final_state,
            "errors": self.errors,
        }


@dataclass
class AttackResult:
    attack_name: str
    success: bool
    vulnerability: Optional[str]
    evidence: str
    steps: List[StepResult]
    severity: str = "MEDIUM"
    
    def to_dict(self) -> dict:
        return {
            "attack_name": self.attack_name,
            "success": self.success,
            "vulnerability": self.vulnerability,
            "evidence": self.evidence,
            "steps": [s.to_dict() for s in self.steps],
            "severity": self.severity,
        }


@dataclass
class WorkflowStep:
    name: str
    request: dict
    extract: Dict[str, str] = field(default_factory=dict)
    expect: Dict[str, Any] = field(default_factory=dict)
    optional: bool = False
    
    @classmethod
    def from_dict(cls, data: dict) -> "WorkflowStep":
        return cls(
            name=data.get("name", "unnamed"),
            request=data.get("request", {}),
            extract=data.get("extract", {}),
            expect=data.get("expect", {}),
            optional=data.get("optional", False),
        )


@dataclass
class WorkflowAttack:
    name: str
    description: str
    attack_type: str
    modifications: Dict[str, Any] = field(default_factory=dict)
    skip_steps: List[str] = field(default_factory=list)
    modify_step: Optional[str] = None
    sequence: List[dict] = field(default_factory=list)
    verify: List[dict] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict) -> "WorkflowAttack":
        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            attack_type=data.get("type", "modification"),
            modifications=data.get("modifications", {}),
            skip_steps=data.get("skip_steps", []),
            modify_step=data.get("modify_step"),
            sequence=data.get("sequence", []),
            verify=data.get("verify", []),
        )


@dataclass
class Workflow:
    name: str
    description: str
    steps: List[WorkflowStep]
    attacks: List[WorkflowAttack]
    variables: Dict[str, Any]
    
    @classmethod
    def from_dict(cls, data: dict) -> "Workflow":
        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            steps=[WorkflowStep.from_dict(s) for s in data.get("steps", [])],
            attacks=[WorkflowAttack.from_dict(a) for a in data.get("attacks", [])],
            variables=data.get("variables", {}),
        )
    
    @classmethod
    def from_yaml(cls, path: str) -> "Workflow":
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)


class WorkflowEngine:
    JSON_PATH_PATTERN = re.compile(r'\$\.([a-zA-Z0-9_.\[\]]+)')
    VAR_PATTERN = re.compile(r'\$\{([^}]+)\}')
    
    def __init__(self, http_client, auth_manager=None, base_url: str = ""):
        self.http = http_client
        self.auth = auth_manager
        self.base_url = base_url
        self.workflows: Dict[str, Workflow] = {}
        self.state: Dict[str, Any] = {}
    
    def set_base_url(self, url: str):
        self.base_url = url
    
    def load_workflow(self, path: str) -> Workflow:
        workflow = Workflow.from_yaml(path)
        self.workflows[workflow.name] = workflow
        return workflow
    
    def load_workflow_from_dict(self, data: dict) -> Workflow:
        workflow = Workflow.from_dict(data)
        self.workflows[workflow.name] = workflow
        return workflow
    
    async def execute(self, workflow: Workflow, role: str = None, initial_vars: Dict = None) -> WorkflowResult:
        self.state = workflow.variables.copy()
        if initial_vars:
            self.state.update(initial_vars)
        
        results = []
        errors = []
        
        for step in workflow.steps:
            result = await self._execute_step(step, role)
            results.append(result)
            
            if not result.success and not step.optional:
                errors.append(f"Step '{step.name}' failed: {result.error}")
                return WorkflowResult(
                    workflow_name=workflow.name,
                    success=False,
                    steps_executed=results,
                    final_state=self.state.copy(),
                    errors=errors,
                )
            
            self.state.update(result.extracted)
        
        return WorkflowResult(
            workflow_name=workflow.name,
            success=True,
            steps_executed=results,
            final_state=self.state.copy(),
            errors=errors,
        )
    
    async def execute_attack(self, workflow: Workflow, attack_name: str, role: str = None) -> AttackResult:
        attack = None
        for a in workflow.attacks:
            if a.name == attack_name:
                attack = a
                break
        
        if not attack:
            return AttackResult(
                attack_name=attack_name,
                success=False,
                vulnerability=None,
                evidence=f"Attack '{attack_name}' not found",
                steps=[],
            )
        
        self.state = workflow.variables.copy()
        results = []
        
        steps_to_run = []
        for step in workflow.steps:
            if step.name in attack.skip_steps:
                continue
            
            if attack.modify_step == step.name:
                modified_step = self._apply_modifications(step, attack.modifications)
                steps_to_run.append(modified_step)
            else:
                steps_to_run.append(step)
        
        for step in steps_to_run:
            result = await self._execute_step(step, role)
            results.append(result)
            
            if not result.success and not step.optional:
                break
            
            self.state.update(result.extracted)
        
        vulnerability = None
        evidence = ""
        severity = "MEDIUM"
        
        if attack.verify:
            for verification in attack.verify:
                verify_result = await self._verify_attack(verification, role)
                if verify_result:
                    vulnerability = attack.attack_type
                    evidence = verify_result
                    severity = "HIGH" if "skip" in attack.name.lower() or "bypass" in attack.name.lower() else "MEDIUM"
                    break
        else:
            last_result = results[-1] if results else None
            if last_result and last_result.success:
                vulnerability = attack.attack_type
                evidence = f"Attack completed: {attack.description}"
                severity = "HIGH"
        
        return AttackResult(
            attack_name=attack_name,
            success=vulnerability is not None,
            vulnerability=vulnerability,
            evidence=evidence,
            steps=results,
            severity=severity,
        )
    
    async def fuzz_workflow(self, workflow: Workflow, role: str = None) -> List[AttackResult]:
        results = []
        
        for attack in workflow.attacks:
            result = await self.execute_attack(workflow, attack.name, role)
            results.append(result)
        
        auto_attacks = self._generate_auto_attacks(workflow)
        for attack in auto_attacks:
            workflow_copy = copy.deepcopy(workflow)
            workflow_copy.attacks.append(attack)
            result = await self.execute_attack(workflow_copy, attack.name, role)
            results.append(result)
        
        return results
    
    async def _execute_step(self, step: WorkflowStep, role: str = None) -> StepResult:
        try:
            request = self._interpolate_request(step.request)
            
            method = request.get("method", "GET").upper()
            url = request.get("url", "/")
            
            if not url.startswith(("http://", "https://")):
                url = urljoin(self.base_url, url)
            
            headers = request.get("headers", {})
            data = request.get("data")
            json_data = request.get("json")
            params = request.get("params")
            
            if self.auth and role:
                response = await self.auth.request_as(role, method, url, headers=headers, data=data, json=json_data, params=params)
            else:
                if method == "GET":
                    response = await self.http.get(url, headers=headers, params=params)
                elif method == "POST":
                    response = await self.http.post(url, headers=headers, data=data, json=json_data)
                elif method == "PUT":
                    response = await self.http.put(url, headers=headers, data=data, json=json_data)
                elif method == "DELETE":
                    response = await self.http.delete(url, headers=headers)
                else:
                    response = await self.http.request(method, url, headers=headers, data=data, json=json_data)
            
            extracted = self._extract_values(response, step.extract)
            
            success = self._check_expectations(response, step.expect)
            
            return StepResult(
                step_name=step.name,
                success=success,
                status=response.get("status", 0),
                response=response,
                extracted=extracted,
                elapsed=response.get("elapsed", 0),
            )
        
        except Exception as e:
            return StepResult(
                step_name=step.name,
                success=False,
                status=0,
                response={},
                extracted={},
                error=str(e),
            )
    
    def _interpolate_request(self, request: dict) -> dict:
        result = {}
        
        for key, value in request.items():
            if isinstance(value, str):
                result[key] = self._interpolate_string(value)
            elif isinstance(value, dict):
                result[key] = self._interpolate_request(value)
            elif isinstance(value, list):
                result[key] = [self._interpolate_string(v) if isinstance(v, str) else v for v in value]
            else:
                result[key] = value
        
        return result
    
    def _interpolate_string(self, s: str) -> str:
        def replace_var(match):
            var_name = match.group(1)
            value = self.state.get(var_name, match.group(0))
            return str(value) if value is not None else match.group(0)
        
        return self.VAR_PATTERN.sub(replace_var, s)
    
    def _extract_values(self, response: dict, extract_rules: Dict[str, str]) -> Dict[str, Any]:
        extracted = {}
        
        for var_name, path in extract_rules.items():
            value = None
            
            if path.startswith("$."):
                value = self._extract_json_path(response.get("text", ""), path)
            elif path.startswith("header."):
                header_name = path[7:]
                value = response.get("headers", {}).get(header_name)
            elif path.startswith("cookie."):
                cookie_name = path[7:]
                cookies = response.get("headers", {}).get("Set-Cookie", "")
                for cookie in cookies.split(";"):
                    if cookie.strip().startswith(cookie_name + "="):
                        value = cookie.split("=", 1)[1]
                        break
            elif path.startswith("regex:"):
                pattern = path[6:]
                match = re.search(pattern, response.get("text", ""))
                if match:
                    value = match.group(1) if match.groups() else match.group(0)
            elif path == "status":
                value = response.get("status")
            elif path == "body":
                value = response.get("text", "")
            elif path == "url":
                value = response.get("url", "")
            
            if value is not None:
                extracted[var_name] = value
        
        return extracted
    
    def _extract_json_path(self, text: str, path: str) -> Any:
        try:
            data = json.loads(text)
            
            path = path[2:]
            
            parts = re.split(r'\.|\[|\]', path)
            parts = [p for p in parts if p]
            
            current = data
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list):
                    try:
                        current = current[int(part)]
                    except (ValueError, IndexError):
                        return None
                else:
                    return None
                
                if current is None:
                    return None
            
            return current
        except (json.JSONDecodeError, Exception):
            return None
    
    def _check_expectations(self, response: dict, expect: Dict[str, Any]) -> bool:
        if not expect:
            return response.get("status", 0) < 400
        
        status = response.get("status", 0)
        text = response.get("text", "")
        headers = response.get("headers", {})
        
        if "status" in expect:
            expected_status = expect["status"]
            if isinstance(expected_status, list):
                if status not in expected_status:
                    return False
            elif status != expected_status:
                return False
        
        if "body_contains" in expect:
            if expect["body_contains"] not in text:
                return False
        
        if "body_not_contains" in expect:
            if expect["body_not_contains"] in text:
                return False
        
        if "header_contains" in expect:
            for header, value in expect["header_contains"].items():
                if headers.get(header) != value:
                    return False
        
        if "json_path" in expect:
            for path, expected_value in expect["json_path"].items():
                actual = self._extract_json_path(text, path)
                if actual != expected_value:
                    return False
        
        return True
    
    def _apply_modifications(self, step: WorkflowStep, modifications: Dict) -> WorkflowStep:
        modified = copy.deepcopy(step)
        
        for key, value in modifications.items():
            parts = key.split(".")
            
            target = modified.request
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]
            
            target[parts[-1]] = value
        
        return modified
    
    async def _verify_attack(self, verification: dict, role: str = None) -> Optional[str]:
        request = verification.get("request", {})
        expect = verification.get("expect", {})
        
        step = WorkflowStep(
            name="verification",
            request=request,
            expect=expect,
        )
        
        result = await self._execute_step(step, role)
        
        if "body_contains" in expect:
            if expect["body_contains"] in result.response.get("text", ""):
                return f"Found unexpected content: {expect['body_contains']}"
        
        if "body_not_contains" in expect:
            if expect["body_not_contains"] not in result.response.get("text", ""):
                return f"Missing expected content: {expect['body_not_contains']}"
        
        return None
    
    def _generate_auto_attacks(self, workflow: Workflow) -> List[WorkflowAttack]:
        auto_attacks = []
        
        for i, step in enumerate(workflow.steps):
            if i < len(workflow.steps) - 1:
                auto_attacks.append(WorkflowAttack(
                    name=f"auto_skip_{step.name}",
                    description=f"Skip step {step.name}",
                    attack_type="step_skip",
                    skip_steps=[step.name],
                ))
        
        for step in workflow.steps:
            request = step.request
            if request.get("json") or request.get("data"):
                auto_attacks.append(WorkflowAttack(
                    name=f"auto_tamper_{step.name}",
                    description=f"Tamper with {step.name} data",
                    attack_type="parameter_tampering",
                    modify_step=step.name,
                    modifications=self._generate_tamper_mods(request),
                ))
        
        return auto_attacks
    
    def _generate_tamper_mods(self, request: dict) -> Dict:
        mods = {}
        
        data = request.get("json", {}) or request.get("data", {})
        
        tamper_keys = ["price", "amount", "total", "quantity", "qty", "discount", "role", "admin", "is_admin", "user_id", "id"]
        
        for key in data.keys():
            key_lower = key.lower()
            for tamper_key in tamper_keys:
                if tamper_key in key_lower:
                    if "price" in key_lower or "amount" in key_lower or "total" in key_lower:
                        mods[f"json.{key}"] = 0
                    elif "quantity" in key_lower or "qty" in key_lower:
                        mods[f"json.{key}"] = -1
                    elif "admin" in key_lower or "role" in key_lower:
                        mods[f"json.{key}"] = True
                    break
        
        return mods


def create_workflow_engine(http_client, auth_manager=None, base_url: str = "") -> WorkflowEngine:
    return WorkflowEngine(http_client, auth_manager, base_url)


async def run_workflow(http_client, workflow_path: str, base_url: str, role: str = None) -> WorkflowResult:
    engine = WorkflowEngine(http_client, base_url=base_url)
    workflow = engine.load_workflow(workflow_path)
    return await engine.execute(workflow, role)
