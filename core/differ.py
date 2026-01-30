import re
import hashlib
import json
import statistics
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field
from enum import Enum


class ReflectionContext(Enum):
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"
    JAVASCRIPT_STRING = "js_string"
    JAVASCRIPT_CODE = "js_code"
    JSON_VALUE = "json_value"
    JSON_KEY = "json_key"
    URL_PATH = "url_path"
    URL_PARAM = "url_param"
    CSS_VALUE = "css_value"
    HTML_COMMENT = "html_comment"
    SCRIPT_BLOCK = "script_block"
    STYLE_BLOCK = "style_block"
    UNKNOWN = "unknown"


class EncodingType(Enum):
    NONE = "none"
    HTML_ENTITY = "html_entity"
    URL_ENCODED = "url_encoded"
    DOUBLE_URL = "double_url"
    UNICODE_ESCAPE = "unicode_escape"
    HEX_ESCAPE = "hex_escape"
    BASE64 = "base64"
    PARTIAL = "partial"


@dataclass
class ReflectionPoint:
    location: str
    context: ReflectionContext
    position: int
    encoding: EncodingType
    surrounding: str
    breakout_chars: List[str] = field(default_factory=list)
    exploitable: bool = False
    payload_intact: bool = True
    
    def to_dict(self) -> dict:
        return {
            "location": self.location,
            "context": self.context.value,
            "position": self.position,
            "encoding": self.encoding.value,
            "surrounding": self.surrounding,
            "breakout_chars": self.breakout_chars,
            "exploitable": self.exploitable,
            "payload_intact": self.payload_intact,
        }


@dataclass
class DiffResult:
    similarity: float
    length_diff: int
    length_ratio: float
    time_diff: float
    status_changed: bool
    header_changes: Dict[str, Tuple[str, str]]
    body_changes: List[str]
    is_meaningful: bool
    confidence: float
    normalized_similarity: float = 0.0
    structure_changed: bool = False
    
    def to_dict(self) -> dict:
        return {
            "similarity": self.similarity,
            "length_diff": self.length_diff,
            "length_ratio": self.length_ratio,
            "time_diff": self.time_diff,
            "status_changed": self.status_changed,
            "header_changes": self.header_changes,
            "body_changes": self.body_changes,
            "is_meaningful": self.is_meaningful,
            "confidence": self.confidence,
            "normalized_similarity": self.normalized_similarity,
            "structure_changed": self.structure_changed,
        }


class DynamicContentStripper:
    CSRF_PATTERNS = [
        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']?([^"\'>\s]+)',
        r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)',
        r'name=["\']?authenticity_token["\']?\s+value=["\']?([^"\'>\s]+)',
        r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']?([^"\'>\s]+)',
        r'csrf[_-]?token["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
        r'X-CSRF-TOKEN["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
        r'_csrf["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
    ]
    
    TIMESTAMP_PATTERNS = [
        r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b',
        r'\b\d{10,13}\b',
        r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},?\s+\d{4}',
        r'\b\d{1,2}/\d{1,2}/\d{2,4}\b',
        r'\b\d{1,2}\s+(?:seconds?|minutes?|hours?|days?)\s+ago\b',
    ]
    
    TOKEN_PATTERNS = [
        r'[a-f0-9]{32}',
        r'[a-f0-9]{40}',
        r'[a-f0-9]{64}',
        r'[A-Za-z0-9_-]{20,}\.{1,2}[A-Za-z0-9_-]+',
        r'session[_-]?id["\s:=]+["\']?([a-zA-Z0-9_-]+)',
        r'nonce["\s:=]+["\']?([a-zA-Z0-9_-]+)',
        r'["\']?state["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
    ]
    
    RANDOM_PATTERNS = [
        r'cb=\d+',
        r'_=\d+',
        r'rand=\d+',
        r'nocache=\d+',
        r'v=\d+\.\d+\.\d+',
    ]
    
    DYNAMIC_HEADERS = {
        'date', 'last-modified', 'expires', 'age', 'etag',
        'x-request-id', 'x-correlation-id', 'x-trace-id',
        'x-runtime', 'x-response-time', 'server-timing',
        'set-cookie', 'cf-ray', 'x-amz-request-id',
        'x-cache', 'via', 'x-served-by',
    }
    
    def __init__(self):
        self._custom_patterns = []
        self._learned_patterns = []
    
    def add_pattern(self, pattern: str, name: str = None):
        self._custom_patterns.append((pattern, name or "custom"))
    
    def learn_from_responses(self, resp1: dict, resp2: dict):
        text1 = resp1.get("text", "")
        text2 = resp2.get("text", "")
        
        for pattern, name in self.CSRF_PATTERNS + self.TOKEN_PATTERNS:
            matches1 = set(re.findall(pattern, text1, re.IGNORECASE))
            matches2 = set(re.findall(pattern, text2, re.IGNORECASE))
            if matches1 and matches2 and matches1 != matches2:
                self._learned_patterns.append((pattern, f"learned_{name}"))
    
    def strip(self, text: str) -> str:
        result = text
        
        all_patterns = (
            self.CSRF_PATTERNS + 
            self.TIMESTAMP_PATTERNS + 
            self.TOKEN_PATTERNS + 
            self.RANDOM_PATTERNS +
            self._custom_patterns +
            self._learned_patterns
        )
        
        for pattern in all_patterns:
            if isinstance(pattern, tuple):
                pattern = pattern[0]
            result = re.sub(pattern, '[DYNAMIC]', result, flags=re.IGNORECASE)
        
        return result
    
    def strip_headers(self, headers: dict) -> dict:
        return {
            k: v for k, v in headers.items() 
            if k.lower() not in self.DYNAMIC_HEADERS
        }
    
    def get_dynamic_values(self, text: str) -> Dict[str, List[str]]:
        found = {}
        
        for pattern in self.CSRF_PATTERNS:
            if isinstance(pattern, tuple):
                pattern = pattern[0]
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found.setdefault("csrf", []).extend(matches)
        
        for pattern in self.TOKEN_PATTERNS:
            if isinstance(pattern, tuple):
                pattern = pattern[0]
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found.setdefault("tokens", []).extend(matches)
        
        return found


class AdvancedResponseDiffer:
    def __init__(self, similarity_threshold: float = 0.95):
        self.similarity_threshold = similarity_threshold
        self.baselines: Dict[str, dict] = {}
        self.stripper = DynamicContentStripper()
        self._timing_samples: Dict[str, List[float]] = {}
    
    def set_baseline(self, key: str, response: dict):
        text = response.get("text", "")
        stripped = self.stripper.strip(text)
        
        self.baselines[key] = {
            "status": response.get("status"),
            "length": len(text),
            "stripped_length": len(stripped),
            "headers": self.stripper.strip_headers(response.get("headers", {})),
            "content_hash": self._hash(stripped[:5000]),
            "structure_hash": self._structure_hash(text),
            "word_count": len(text.split()),
            "line_count": text.count("\n"),
            "tag_sequence": self._extract_tag_sequence(text),
            "json_keys": self._extract_json_keys(text),
            "elapsed": response.get("elapsed", 0),
        }
        
        self._timing_samples.setdefault(key, []).append(response.get("elapsed", 0))
    
    def compare(self, key: str, response: dict) -> DiffResult:
        if key not in self.baselines:
            return DiffResult(
                similarity=1.0, length_diff=0, length_ratio=0, time_diff=0,
                status_changed=False, header_changes={}, body_changes=[],
                is_meaningful=False, confidence=0, normalized_similarity=1.0
            )
        
        baseline = self.baselines[key]
        text = response.get("text", "")
        stripped = self.stripper.strip(text)
        
        changes = []
        header_changes = {}
        
        status_changed = response.get("status") != baseline["status"]
        if status_changed:
            changes.append(f"status:{baseline['status']}→{response.get('status')}")
        
        length_diff = abs(len(text) - baseline["length"])
        length_ratio = length_diff / max(baseline["length"], 1)
        
        if length_ratio > 0.1:
            changes.append(f"length:{baseline['length']}→{len(text)} ({length_ratio:.1%})")
        
        stripped_ratio = abs(len(stripped) - baseline["stripped_length"]) / max(baseline["stripped_length"], 1)
        if stripped_ratio > 0.05:
            changes.append(f"stripped_length_diff:{stripped_ratio:.1%}")
        
        current_hash = self._hash(stripped[:5000])
        if current_hash != baseline["content_hash"]:
            changes.append("content_hash_changed")
        
        current_struct = self._structure_hash(text)
        structure_changed = current_struct != baseline["structure_hash"]
        if structure_changed:
            changes.append("structure_changed")
        
        current_tags = self._extract_tag_sequence(text)
        if current_tags != baseline["tag_sequence"]:
            changes.append("tag_sequence_changed")
        
        current_json_keys = self._extract_json_keys(text)
        if current_json_keys != baseline["json_keys"]:
            new_keys = current_json_keys - baseline["json_keys"]
            missing_keys = baseline["json_keys"] - current_json_keys
            if new_keys:
                changes.append(f"new_json_keys:{list(new_keys)[:5]}")
            if missing_keys:
                changes.append(f"missing_json_keys:{list(missing_keys)[:5]}")
        
        resp_headers = self.stripper.strip_headers(response.get("headers", {}))
        for header, value in resp_headers.items():
            if header in baseline["headers"] and baseline["headers"][header] != value:
                header_changes[header] = (baseline["headers"][header], value)
        for header in baseline["headers"]:
            if header not in resp_headers:
                header_changes[header] = (baseline["headers"][header], None)
        
        if header_changes:
            changes.append(f"headers_changed:{list(header_changes.keys())[:5]}")
        
        elapsed = response.get("elapsed", 0)
        time_diff = abs(elapsed - baseline["elapsed"])
        
        timing_samples = self._timing_samples.get(key, [])
        if len(timing_samples) >= 3:
            avg_time = statistics.mean(timing_samples)
            std_time = statistics.stdev(timing_samples) if len(timing_samples) > 1 else 0.5
            if elapsed > avg_time + (3 * std_time):
                changes.append(f"timing_anomaly:{elapsed:.2f}s (avg:{avg_time:.2f}s)")
        
        similarity = self._calculate_similarity(baseline, text, stripped)
        normalized_similarity = 1.0 - (len(changes) / 10)
        is_meaningful = len(changes) > 0 and (status_changed or length_ratio > 0.1 or structure_changed)
        confidence = min(len(changes) / 5, 1.0)
        
        return DiffResult(
            similarity=similarity,
            length_diff=length_diff,
            length_ratio=length_ratio,
            time_diff=time_diff,
            status_changed=status_changed,
            header_changes=header_changes,
            body_changes=changes,
            is_meaningful=is_meaningful,
            confidence=confidence,
            normalized_similarity=normalized_similarity,
            structure_changed=structure_changed,
        )
    
    def compare_two(self, resp1: dict, resp2: dict) -> DiffResult:
        temp_key = "__temp_compare__"
        self.set_baseline(temp_key, resp1)
        result = self.compare(temp_key, resp2)
        del self.baselines[temp_key]
        return result
    
    def find_reflection(self, response: dict, payload: str, check_encodings: bool = True) -> List[ReflectionPoint]:
        text = response.get("text", "")
        url = response.get("url", "")
        headers = response.get("headers", {})
        reflections = []
        
        variants = [(payload, EncodingType.NONE)]
        
        if check_encodings:
            from urllib.parse import quote, unquote
            import html
            
            if quote(payload) != payload:
                variants.append((quote(payload), EncodingType.URL_ENCODED))
            
            if quote(quote(payload)) != quote(payload):
                variants.append((quote(quote(payload)), EncodingType.DOUBLE_URL))
            
            html_encoded = html.escape(payload)
            if html_encoded != payload:
                variants.append((html_encoded, EncodingType.HTML_ENTITY))
            
            unicode_escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
            variants.append((unicode_escaped, EncodingType.UNICODE_ESCAPE))
            
            hex_escaped = "".join(f"\\x{ord(c):02x}" for c in payload)
            variants.append((hex_escaped, EncodingType.HEX_ESCAPE))
        
        for variant, encoding in variants:
            if variant in text:
                positions = [m.start() for m in re.finditer(re.escape(variant), text)]
                for pos in positions:
                    context = self._determine_context(text, pos)
                    surrounding = text[max(0, pos-50):pos+len(variant)+50]
                    breakout = self._get_breakout_chars(context)
                    exploitable = self._is_exploitable(context, payload, encoding)
                    
                    reflections.append(ReflectionPoint(
                        location="body",
                        context=context,
                        position=pos,
                        encoding=encoding,
                        surrounding=surrounding,
                        breakout_chars=breakout,
                        exploitable=exploitable,
                        payload_intact=(encoding == EncodingType.NONE),
                    ))
        
        for header_name, header_value in headers.items():
            for variant, encoding in variants:
                if variant in str(header_value):
                    reflections.append(ReflectionPoint(
                        location=f"header:{header_name}",
                        context=ReflectionContext.UNKNOWN,
                        position=str(header_value).find(variant),
                        encoding=encoding,
                        surrounding=str(header_value)[:100],
                        breakout_chars=[],
                        exploitable=False,
                        payload_intact=(encoding == EncodingType.NONE),
                    ))
        
        if url:
            for variant, encoding in variants:
                if variant in url:
                    reflections.append(ReflectionPoint(
                        location="url",
                        context=ReflectionContext.URL_PARAM,
                        position=url.find(variant),
                        encoding=encoding,
                        surrounding=url,
                        breakout_chars=[],
                        exploitable=False,
                        payload_intact=(encoding == EncodingType.NONE),
                    ))
        
        return reflections
    
    def calculate_similarity(self, resp1: dict, resp2: dict) -> float:
        text1 = self.stripper.strip(resp1.get("text", ""))
        text2 = self.stripper.strip(resp2.get("text", ""))
        
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0
        
        len_sim = 1 - abs(len(text1) - len(text2)) / max(len(text1), len(text2))
        
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 and not words2:
            return len_sim
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        jaccard = intersection / union if union > 0 else 0
        
        hash_sim = 1.0 if self._hash(text1[:3000]) == self._hash(text2[:3000]) else 0.5
        
        return (len_sim * 0.3) + (jaccard * 0.5) + (hash_sim * 0.2)
    
    def detect_boolean_behavior(self, true_responses: List[dict], false_responses: List[dict]) -> Optional[dict]:
        if not true_responses or not false_responses:
            return None
        
        true_lens = [len(r.get("text", "")) for r in true_responses]
        false_lens = [len(r.get("text", "")) for r in false_responses]
        
        avg_true = statistics.mean(true_lens)
        avg_false = statistics.mean(false_lens)
        len_diff = abs(avg_true - avg_false)
        
        true_statuses = [r.get("status") for r in true_responses]
        false_statuses = [r.get("status") for r in false_responses]
        status_diff = set(true_statuses) != set(false_statuses)
        
        true_words = [len(r.get("text", "").split()) for r in true_responses]
        false_words = [len(r.get("text", "").split()) for r in false_responses]
        word_diff = abs(statistics.mean(true_words) - statistics.mean(false_words))
        
        indicators = []
        confidence = 0.0
        
        if len_diff > 100:
            indicators.append(f"length_diff:{len_diff:.0f}")
            confidence += min(len_diff / 500, 0.4)
        
        if status_diff:
            indicators.append("status_diff")
            confidence += 0.3
        
        if word_diff > 20:
            indicators.append(f"word_diff:{word_diff:.0f}")
            confidence += min(word_diff / 100, 0.3)
        
        if not indicators:
            return None
        
        return {
            "type": "boolean_based",
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
            "true_avg_len": avg_true,
            "false_avg_len": avg_false,
            "len_diff": len_diff,
        }
    
    def detect_time_anomaly(self, responses: List[dict], baseline_time: float = None, threshold: float = 2.0) -> Optional[dict]:
        times = [r.get("elapsed", 0) for r in responses]
        
        if not times:
            return None
        
        if baseline_time is None:
            if len(times) < 3:
                return None
            baseline_time = statistics.median(times)
        
        anomalies = []
        for i, t in enumerate(times):
            if t > baseline_time + threshold:
                anomalies.append((i, t))
        
        if not anomalies:
            return None
        
        return {
            "type": "time_based",
            "confidence": min(len(anomalies) / len(times) + 0.3, 1.0),
            "baseline": baseline_time,
            "threshold": threshold,
            "anomaly_indices": [a[0] for a in anomalies],
            "anomaly_times": [a[1] for a in anomalies],
            "avg_anomaly_time": statistics.mean([a[1] for a in anomalies]),
        }
    
    def _hash(self, text: str) -> str:
        return hashlib.blake2b(text.encode(), digest_size=16).hexdigest()
    
    def _structure_hash(self, text: str) -> str:
        tags = re.findall(r'<(\w+)[^>]*/?>', text[:10000])
        structure = ":".join(tags[:100])
        return hashlib.blake2b(structure.encode(), digest_size=8).hexdigest()
    
    def _extract_tag_sequence(self, text: str) -> str:
        tags = re.findall(r'<(\w+)', text[:5000])
        return ":".join(tags[:50])
    
    def _extract_json_keys(self, text: str) -> set:
        keys = set()
        try:
            data = json.loads(text)
            self._walk_json_keys(data, keys)
        except:
            key_matches = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]{0,30})":', text[:5000])
            keys.update(key_matches)
        return keys
    
    def _walk_json_keys(self, obj, keys: set, depth: int = 0):
        if depth > 5:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(k)
                self._walk_json_keys(v, keys, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:10]:
                self._walk_json_keys(item, keys, depth + 1)
    
    def _calculate_similarity(self, baseline: dict, text: str, stripped: str) -> float:
        factors = []
        
        len_ratio = 1 - abs(len(text) - baseline["length"]) / max(baseline["length"], 1)
        factors.append(max(0, min(1, len_ratio)))
        
        word_ratio = 1 - abs(len(text.split()) - baseline["word_count"]) / max(baseline["word_count"], 1)
        factors.append(max(0, min(1, word_ratio)))
        
        hash_match = 1.0 if self._hash(stripped[:5000]) == baseline["content_hash"] else 0.3
        factors.append(hash_match)
        
        struct_match = 1.0 if self._structure_hash(text) == baseline["structure_hash"] else 0.5
        factors.append(struct_match)
        
        return statistics.mean(factors)
    
    def _determine_context(self, text: str, position: int) -> ReflectionContext:
        before = text[max(0, position-500):position]
        after = text[position:position+500]
        
        if re.search(r'<script[^>]*>[^<]*$', before, re.IGNORECASE | re.DOTALL):
            if "'" in before[-50:] or '"' in before[-50:]:
                return ReflectionContext.JAVASCRIPT_STRING
            return ReflectionContext.JAVASCRIPT_CODE
        
        if re.search(r'<style[^>]*>[^<]*$', before, re.IGNORECASE | re.DOTALL):
            return ReflectionContext.CSS_VALUE
        
        if re.search(r'<!--[^>]*$', before):
            return ReflectionContext.HTML_COMMENT
        
        tag_match = re.search(r'<\w+[^>]*$', before)
        if tag_match:
            attr_context = before[tag_match.start():]
            if re.search(r'=\s*["\'][^"\']*$', attr_context):
                return ReflectionContext.HTML_ATTRIBUTE
            if re.search(r'=\s*[^\s>"\']+$', attr_context):
                return ReflectionContext.HTML_ATTRIBUTE_UNQUOTED
        
        try:
            json.loads(text)
            if re.search(r':\s*["\'][^"\']*$', before):
                return ReflectionContext.JSON_VALUE
            return ReflectionContext.JSON_KEY
        except:
            pass
        
        return ReflectionContext.HTML_BODY
    
    def _get_breakout_chars(self, context: ReflectionContext) -> List[str]:
        breakouts = {
            ReflectionContext.HTML_BODY: ["<", ">"],
            ReflectionContext.HTML_ATTRIBUTE: ['"', "'", ">", " "],
            ReflectionContext.HTML_ATTRIBUTE_UNQUOTED: [" ", ">", "/"],
            ReflectionContext.JAVASCRIPT_STRING: ["'", '"', "\\", "`"],
            ReflectionContext.JAVASCRIPT_CODE: [";", "}", "{", "(", ")"],
            ReflectionContext.JSON_VALUE: ['"', "\\"],
            ReflectionContext.CSS_VALUE: ["}", ";", "<"],
            ReflectionContext.HTML_COMMENT: ["--", ">"],
        }
        return breakouts.get(context, [])
    
    def _is_exploitable(self, context: ReflectionContext, payload: str, encoding: EncodingType) -> bool:
        if encoding != EncodingType.NONE:
            return False
        
        exploitable_contexts = {
            ReflectionContext.HTML_BODY,
            ReflectionContext.HTML_ATTRIBUTE_UNQUOTED,
            ReflectionContext.JAVASCRIPT_CODE,
            ReflectionContext.SCRIPT_BLOCK,
        }
        
        if context in exploitable_contexts:
            return True
        
        breakout_chars = self._get_breakout_chars(context)
        for char in breakout_chars:
            if char in payload:
                return True
        
        return False


def create_differ(threshold: float = 0.95) -> AdvancedResponseDiffer:
    return AdvancedResponseDiffer(similarity_threshold=threshold)
