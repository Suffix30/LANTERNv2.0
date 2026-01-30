import re
import random
import string
import statistics
import struct
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from urllib.parse import quote, unquote
import json
import asyncio


@dataclass
class FuzzResult:
    payload: Any
    response: dict
    anomaly_type: Optional[str]
    anomaly_score: float
    evidence: str
    
    def to_dict(self) -> dict:
        return {
            "payload": str(self.payload)[:200],
            "status": self.response.get("status"),
            "length": len(self.response.get("text", "")),
            "anomaly_type": self.anomaly_type,
            "anomaly_score": self.anomaly_score,
            "evidence": self.evidence,
        }


@dataclass
class DifferentialResult:
    payload: Any
    responses: Dict[str, dict]
    differences: List[str]
    is_interesting: bool
    
    def to_dict(self) -> dict:
        return {
            "payload": str(self.payload)[:200],
            "differences": self.differences,
            "is_interesting": self.is_interesting,
        }


BOUNDARY_VALUES = {
    "integer": [
        0, 1, -1, 2, -2,
        127, 128, 255, 256,
        32767, 32768, 65535, 65536,
        2147483647, 2147483648, -2147483648, -2147483649,
        4294967295, 4294967296,
        9223372036854775807,
    ],
    "string": [
        "", " ", "  ",
        "null", "NULL", "nil", "None",
        "undefined", "NaN", "Infinity",
        "true", "false", "True", "False",
        "0", "1", "-1",
        "[]", "{}", "[[]]", "{{}}",
        "a", "A", "aA",
        "\x00", "\n", "\r\n", "\t",
        "\x00\x00\x00\x00",
    ],
    "length": [
        lambda: "a" * 1,
        lambda: "a" * 10,
        lambda: "a" * 100,
        lambda: "a" * 1000,
        lambda: "a" * 10000,
        lambda: "a" * 65535,
    ],
    "special": [
        None,
        True, False,
        [], {},
        [None], {"key": None},
        float('inf'), float('-inf'),
    ],
    "format_string": [
        "%s", "%d", "%n", "%x", "%p",
        "%s%s%s%s%s%s%s%s%s%s",
        "{}", "{0}", "{0}{1}{2}",
        "{{", "}}", "{{{{",
        "${}", "${{}}",
        "#{}", "#{{}}",
    ],
    "path_traversal": [
        "../", "..\\",
        "....//", "....\\\\",
        "../" * 10, "..\\" * 10,
        "%2e%2e%2f", "%2e%2e/",
        "..%252f", "..%c0%af",
        "....//....//",
        "/etc/passwd",
        "C:\\Windows\\System32",
    ],
    "sql": [
        "'", "''", "\"", "\"\"",
        "' OR '1'='1", "' OR 1=1--",
        "1' AND '1'='1", "1' AND '1'='2",
        "1 AND 1=1", "1 AND 1=2",
        "' UNION SELECT NULL--",
        "1; SELECT 1--",
        "/**/", "/*!*/",
    ],
    "xss": [
        "<", ">", "\"", "'",
        "<script>", "</script>",
        "<img src=x onerror=1>",
        "javascript:",
        "\\x3cscript\\x3e",
        "<svg onload=1>",
    ],
    "command": [
        ";", "|", "&", "&&", "||",
        "`", "$()", "${}",
        "\n", "\r\n",
        ";id", "|id", "&id",
        "`id`", "$(id)",
    ],
    "unicode": [
        "\u0000", "\u0001",
        "\ufeff", "\ufffe",
        "\u202e", "\u202d",
        "\ud800", "\udfff",
        "\U0001f600",
        "𐀀",
    ],
}

REDOS_PATTERNS = [
    ("a{1,100}a{1,100}", "a" * 50),
    ("(a+)+$", "a" * 30 + "!"),
    ("([a-zA-Z]+)*$", "a" * 30 + "1"),
    ("(a|aa)+$", "a" * 30 + "b"),
    ("(.*a){20}", "a" * 20 + "!"),
]


class MutationEngine:
    def __init__(self):
        self._random = random.Random()
    
    def mutate_string(self, s: str, count: int = 10) -> List[str]:
        mutations = [s]
        
        mutations.append(s.lower())
        mutations.append(s.upper())
        mutations.append(s.title())
        
        if len(s) > 0:
            mutations.append(s[:-1])
            mutations.append(s[1:])
        mutations.append(s + s)
        mutations.append(s + "\x00")
        mutations.append(s + " ")
        
        for encoding in ["url", "double_url", "unicode", "hex"]:
            mutations.append(self._encode(s, encoding))
        
        if len(s) < 100:
            mutations.append(s * 100)
        
        for i in range(min(5, len(s))):
            pos = self._random.randint(0, len(s))
            char = self._random.choice(string.printable)
            mutations.append(s[:pos] + char + s[pos:])
        
        for i in range(min(3, len(s))):
            if len(s) > 1:
                pos = self._random.randint(0, len(s) - 1)
                mutations.append(s[:pos] + s[pos + 1:])
        
        return list(set(mutations))[:count]
    
    def mutate_number(self, n: Union[int, float], count: int = 10) -> List[Union[int, float]]:
        mutations = [n]
        
        mutations.extend(BOUNDARY_VALUES["integer"][:15])
        
        mutations.append(n + 1)
        mutations.append(n - 1)
        mutations.append(n * 2)
        mutations.append(n * -1)
        mutations.append(n + 0.1)
        mutations.append(n - 0.1)
        
        if isinstance(n, int) and n > 0:
            mutations.append(int(str(n)[::-1]))
        
        return list(set(mutations))[:count]
    
    def mutate_json(self, obj: Any, preserve_structure: bool = True, count: int = 10) -> List[Any]:
        mutations = []
        
        if isinstance(obj, dict):
            for key in list(obj.keys())[:5]:
                mutated = obj.copy()
                if isinstance(obj[key], str):
                    for val in self.mutate_string(obj[key], 3):
                        m = obj.copy()
                        m[key] = val
                        mutations.append(m)
                elif isinstance(obj[key], (int, float)):
                    for val in self.mutate_number(obj[key], 3):
                        m = obj.copy()
                        m[key] = val
                        mutations.append(m)
            
            if not preserve_structure:
                for key in list(obj.keys())[:3]:
                    m = obj.copy()
                    del m[key]
                    mutations.append(m)
                
                mutations.append({**obj, "__proto__": {"admin": True}})
                mutations.append({**obj, "constructor": {"prototype": {"admin": True}}})
        
        elif isinstance(obj, list):
            mutations.append([])
            mutations.append(obj + obj)
            if obj:
                mutations.append(obj[:-1])
                mutations.append([obj[0]] * 100)
        
        elif isinstance(obj, str):
            mutations.extend(self.mutate_string(obj, count))
        
        elif isinstance(obj, (int, float)):
            mutations.extend(self.mutate_number(obj, count))
        
        return mutations[:count]
    
    def _encode(self, s: str, encoding: str) -> str:
        if encoding == "url":
            return quote(s, safe='')
        elif encoding == "double_url":
            return quote(quote(s, safe=''), safe='')
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in s)
        elif encoding == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in s)
        return s


class TimingAnalyzer:
    def __init__(self, baseline_samples: int = 5):
        self.baseline_samples = baseline_samples
        self.baselines: Dict[str, List[float]] = {}
    
    def record_baseline(self, key: str, times: List[float]):
        self.baselines[key] = times
    
    def add_sample(self, key: str, time: float):
        if key not in self.baselines:
            self.baselines[key] = []
        self.baselines[key].append(time)
        
        if len(self.baselines[key]) > 100:
            self.baselines[key] = self.baselines[key][-100:]
    
    def is_anomaly(self, key: str, time: float, threshold_std: float = 3.0) -> Tuple[bool, float]:
        if key not in self.baselines or len(self.baselines[key]) < 3:
            return False, 0.0
        
        baseline = self.baselines[key]
        mean = statistics.mean(baseline)
        std = statistics.stdev(baseline) if len(baseline) > 1 else 0.5
        
        if std < 0.1:
            std = 0.1
        
        z_score = (time - mean) / std
        
        return z_score > threshold_std, z_score
    
    def get_baseline_stats(self, key: str) -> Dict:
        if key not in self.baselines:
            return {}
        
        times = self.baselines[key]
        return {
            "mean": statistics.mean(times),
            "std": statistics.stdev(times) if len(times) > 1 else 0,
            "min": min(times),
            "max": max(times),
            "samples": len(times),
        }


class IntelligentFuzzer:
    def __init__(self, http_client):
        self.http = http_client
        self.mutation_engine = MutationEngine()
        self.timing_analyzer = TimingAnalyzer()
        self._baseline_responses: Dict[str, dict] = {}
    
    async def establish_baseline(self, url: str, method: str = "GET", **kwargs) -> dict:
        responses = []
        times = []
        
        for _ in range(5):
            if method == "GET":
                resp = await self.http.timed_get(url, **kwargs)
            else:
                resp = await self.http.post(url, **kwargs)
            responses.append(resp)
            times.append(resp.get("elapsed", 0))
        
        self.timing_analyzer.record_baseline(url, times)
        
        baseline = {
            "avg_length": statistics.mean([len(r.get("text", "")) for r in responses]),
            "avg_time": statistics.mean(times),
            "status": responses[0].get("status"),
            "response": responses[0],
        }
        
        self._baseline_responses[url] = baseline
        return baseline
    
    async def fuzz_parameter(self, url: str, param: str, baseline: dict = None) -> List[FuzzResult]:
        if baseline is None:
            baseline = await self.establish_baseline(url)
        
        results = []
        
        payloads = self._generate_payloads(param)
        
        for payload in payloads:
            result = await self._test_payload(url, param, payload, baseline)
            if result.anomaly_score > 0.3:
                results.append(result)
        
        return sorted(results, key=lambda r: r.anomaly_score, reverse=True)
    
    async def fuzz_json_body(self, url: str, body: dict, baseline: dict = None) -> List[FuzzResult]:
        if baseline is None:
            baseline = await self.establish_baseline(url, method="POST", json=body)
        
        results = []
        
        mutations = self.mutation_engine.mutate_json(body, preserve_structure=True, count=30)
        mutations.extend(self.mutation_engine.mutate_json(body, preserve_structure=False, count=20))
        
        for mutation in mutations:
            try:
                resp = await self.http.post(url, json=mutation)
                result = self._analyze_response(mutation, resp, baseline)
                if result.anomaly_score > 0.2:
                    results.append(result)
            except Exception:
                pass
        
        return sorted(results, key=lambda r: r.anomaly_score, reverse=True)
    
    async def differential_test(self, url: str, payload: Any, methods: List[str] = None) -> DifferentialResult:
        if methods is None:
            methods = ["GET", "POST"]
        
        responses = {}
        
        for method in methods:
            if method == "GET":
                responses[method] = await self.http.get(url, params={"q": str(payload)})
            elif method == "POST":
                responses["POST_FORM"] = await self.http.post(url, data={"q": str(payload)})
                responses["POST_JSON"] = await self.http.post(url, json={"q": payload})
        
        differences = self._find_differences(responses)
        
        return DifferentialResult(
            payload=payload,
            responses=responses,
            differences=differences,
            is_interesting=len(differences) > 0,
        )
    
    async def test_redos(self, url: str, param: str) -> List[FuzzResult]:
        results = []
        
        for pattern, evil_input in REDOS_PATTERNS:
            lengths = [10, 20, 30, 40]
            times = []
            
            for length in lengths:
                test_input = evil_input[:length] if len(evil_input) >= length else evil_input + "a" * (length - len(evil_input))
                resp = await self.http.timed_get(url, params={param: test_input})
                times.append(resp.get("elapsed", 0))
            
            if len(times) >= 3:
                if times[-1] > times[0] * 5:
                    results.append(FuzzResult(
                        payload=f"ReDoS pattern (length growth)",
                        response={"elapsed": times[-1]},
                        anomaly_type="redos",
                        anomaly_score=min(times[-1] / times[0] / 10, 1.0),
                        evidence=f"Time grew from {times[0]:.2f}s to {times[-1]:.2f}s",
                    ))
        
        return results
    
    def get_boundary_payloads(self, category: str) -> List[Any]:
        payloads = BOUNDARY_VALUES.get(category, [])
        result = []
        for p in payloads:
            if callable(p):
                result.append(p())
            else:
                result.append(p)
        return result
    
    def _generate_payloads(self, param: str) -> List[Any]:
        payloads = []
        
        payloads.extend(BOUNDARY_VALUES["integer"][:10])
        payloads.extend(BOUNDARY_VALUES["string"])
        
        for gen in BOUNDARY_VALUES["length"][:4]:
            payloads.append(gen())
        
        param_lower = param.lower()
        
        if any(kw in param_lower for kw in ["id", "num", "count", "page", "limit"]):
            payloads.extend(BOUNDARY_VALUES["integer"])
        
        if any(kw in param_lower for kw in ["path", "file", "dir", "url", "uri"]):
            payloads.extend(BOUNDARY_VALUES["path_traversal"])
        
        if any(kw in param_lower for kw in ["query", "search", "q", "filter", "sort"]):
            payloads.extend(BOUNDARY_VALUES["sql"])
        
        if any(kw in param_lower for kw in ["name", "title", "text", "comment", "msg"]):
            payloads.extend(BOUNDARY_VALUES["xss"])
        
        if any(kw in param_lower for kw in ["cmd", "exec", "command", "ping", "host"]):
            payloads.extend(BOUNDARY_VALUES["command"])
        
        payloads.extend(BOUNDARY_VALUES["format_string"])
        payloads.extend(BOUNDARY_VALUES["unicode"][:5])
        
        return payloads
    
    async def _test_payload(self, url: str, param: str, payload: Any, baseline: dict) -> FuzzResult:
        from core.http import inject_param
        
        if param:
            test_url = inject_param(url, param, str(payload))
        else:
            test_url = url
        
        resp = await self.http.timed_get(test_url)
        
        return self._analyze_response(payload, resp, baseline)
    
    def _analyze_response(self, payload: Any, response: dict, baseline: dict) -> FuzzResult:
        anomaly_type = None
        anomaly_score = 0.0
        evidence_parts = []
        
        status = response.get("status", 0)
        baseline_status = baseline.get("status", 200)
        
        if status != baseline_status:
            if status >= 500:
                anomaly_score += 0.5
                anomaly_type = "server_error"
                evidence_parts.append(f"Status {status}")
            elif status in [400, 403, 405]:
                anomaly_score += 0.2
                evidence_parts.append(f"Status {status}")
        
        text = response.get("text", "")
        length = len(text)
        baseline_length = baseline.get("avg_length", 0)
        
        if baseline_length > 0:
            length_ratio = abs(length - baseline_length) / baseline_length
            if length_ratio > 0.5:
                anomaly_score += min(length_ratio * 0.3, 0.3)
                evidence_parts.append(f"Length diff: {length_ratio:.1%}")
        
        elapsed = response.get("elapsed", 0)
        baseline_time = baseline.get("avg_time", 0)
        
        if baseline_time > 0:
            time_ratio = elapsed / baseline_time
            if time_ratio > 3:
                anomaly_score += min((time_ratio - 1) * 0.2, 0.4)
                anomaly_type = anomaly_type or "timing_anomaly"
                evidence_parts.append(f"Time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)")
        
        error_patterns = [
            (r"(?:error|exception|stack\s*trace|traceback)", "error_message"),
            (r"(?:sql|mysql|postgres|oracle|sqlite).*(?:error|syntax)", "sql_error"),
            (r"(?:undefined|null|NaN).*(?:reference|type)", "js_error"),
            (r"(?:warning|notice|fatal):", "php_error"),
        ]
        
        for pattern, error_type in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                anomaly_score += 0.3
                anomaly_type = anomaly_type or error_type
                evidence_parts.append(f"Found: {error_type}")
                break
        
        return FuzzResult(
            payload=payload,
            response=response,
            anomaly_type=anomaly_type,
            anomaly_score=min(anomaly_score, 1.0),
            evidence="; ".join(evidence_parts) if evidence_parts else "No anomaly",
        )
    
    def _find_differences(self, responses: Dict[str, dict]) -> List[str]:
        differences = []
        
        statuses = {k: v.get("status") for k, v in responses.items()}
        if len(set(statuses.values())) > 1:
            differences.append(f"Status differs: {statuses}")
        
        lengths = {k: len(v.get("text", "")) for k, v in responses.items()}
        max_len = max(lengths.values()) if lengths.values() else 0
        min_len = min(lengths.values()) if lengths.values() else 0
        
        if max_len > 0 and (max_len - min_len) / max_len > 0.2:
            differences.append(f"Length differs: {lengths}")
        
        return differences


def create_fuzzer(http_client) -> IntelligentFuzzer:
    return IntelligentFuzzer(http_client)
