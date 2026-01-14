import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from modules.base import BaseModule
from core.utils import extract_params

class HppModule(BaseModule):
    name = "hpp"
    description = "HTTP Parameter Pollution Scanner"
    
    async def scan(self, target):
        self.findings = []
        params = extract_params(target)
        
        if not params:
            return self.findings
        
        await self._test_parameter_pollution(target, params)
        await self._test_parameter_precedence(target, params)
        await self._test_array_injection(target, params)
        
        return self.findings
    
    async def _test_parameter_pollution(self, target, params):
        parsed = urlparse(target)
        original_params = parse_qs(parsed.query, keep_blank_values=True)
        
        for param in params:
            polluted_params = original_params.copy()
            
            if param in polluted_params:
                original_value = polluted_params[param][0]
            else:
                original_value = "test"
            
            polluted_params[param] = [original_value, "POLLUTED"]
            
            new_query = urlencode(polluted_params, doseq=True)
            polluted_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            resp = await self.http.get(polluted_url)
            
            if resp.get("status"):
                text = resp.get("text", "")
                matches = self._detect_param_patterns(text, "POLLUTED")
                
                if "POLLUTED" in text or matches:
                    self.add_finding(
                        "MEDIUM",
                        f"Parameter Pollution: second value used",
                        url=target,
                        parameter=param,
                        evidence="Second parameter value reflected"
                    )
                elif original_value in text and "POLLUTED" not in text:
                    pass
                else:
                    baseline = await self.http.get(target)
                    if baseline.get("status") and len(text) != len(baseline.get("text", "")):
                        self.add_finding(
                            "LOW",
                            f"Parameter Pollution: response differs",
                            url=target,
                            parameter=param,
                            evidence="Response changed with duplicate parameters"
                        )
    
    async def _test_parameter_precedence(self, target, params):
        parsed = urlparse(target)
        
        for param in list(params)[:3]:
            original_params = parse_qs(parsed.query, keep_blank_values=True)
            
            test_value = "HPP_TEST_123"
            
            new_params = {param: [test_value]}
            new_params.update(original_params)
            
            query1 = urlencode(new_params, doseq=True)
            url1 = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query1, parsed.fragment))
            
            new_params2 = dict(original_params)
            new_params2[param] = original_params.get(param, ["original"]) + [test_value]
            query2 = urlencode(new_params2, doseq=True)
            url2 = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query2, parsed.fragment))
            
            resp1 = await self.http.get(url1)
            resp2 = await self.http.get(url2)
            
            if resp1.get("status") and resp2.get("status"):
                text1 = resp1.get("text", "")
                text2 = resp2.get("text", "")
                
                first_wins = test_value in text1
                last_wins = test_value in text2 and test_value not in text1
                
                if first_wins and last_wins:
                    self.add_finding(
                        "MEDIUM",
                        f"Parameter precedence inconsistency",
                        url=target,
                        parameter=param,
                        evidence="Both first and last parameter values may be used"
                    )
    
    async def _test_array_injection(self, target, params):
        parsed = urlparse(target)
        
        for param in list(params)[:3]:
            array_formats = [
                (f"{param}[]", "PHP array notation"),
                (f"{param}[0]", "Indexed array"),
                (f"{param}[key]", "Associative array"),
            ]
            
            for array_param, notation in array_formats:
                test_url = f"{target}&{array_param}=ARRAY_TEST"
                resp = await self.http.get(test_url)
                
                if resp.get("status"):
                    text = resp.get("text", "")
                    
                    if "ARRAY_TEST" in text:
                        self.add_finding(
                            "MEDIUM",
                            f"Array parameter injection: {notation}",
                            url=target,
                            parameter=array_param,
                            evidence="Array notation accepted and reflected"
                        )
                        break
                    
                    if "array" in text.lower() or "notice" in text.lower():
                        self.add_finding(
                            "LOW",
                            f"Array parameter causes error: {notation}",
                            url=target,
                            parameter=array_param,
                            evidence="Array injection may cause unexpected behavior"
                        )
                        break
    
    def _detect_param_patterns(self, text, test_value):
        patterns = [
            re.compile(rf'{re.escape(test_value)}', re.IGNORECASE),
            re.compile(r'Array\s*\(', re.IGNORECASE),
            re.compile(r'Notice:.*array', re.IGNORECASE),
            re.compile(r'Warning:.*expected', re.IGNORECASE),
        ]
        matches = []
        for pattern in patterns:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return matches
    
    def _extract_reflected_params(self, text):
        param_pattern = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=([^&\s]*)')
        return param_pattern.findall(text)
