import re
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

TechFingerprint = Tuple[str, str, List[str]]


@dataclass
class Technology:
    name: str
    category: str
    version: Optional[str] = None
    confidence: int = 100
    cpe: Optional[str] = None
    implies: List[str] = field(default_factory=list)
    relevant_modules: List[str] = field(default_factory=list)


class FingerprintDB:
    HEADERS: Dict[str, Dict[str, TechFingerprint]] = {
        "x-powered-by": {
            r"PHP/?([\d.]+)?": ("PHP", "backend", ["lfi", "upload", "deserial"]),
            r"ASP\.NET": ("ASP.NET", "backend", ["deserial", "upload"]),
            r"Express": ("Express.js", "backend", ["ssti", "prototype"]),
            r"Servlet": ("Java Servlet", "backend", ["deserial", "xxe"]),
            r"JSF": ("JavaServer Faces", "backend", ["deserial", "xxe"]),
            r"Phusion Passenger": ("Passenger", "backend", []),
            r"Next\.js": ("Next.js", "frontend", ["ssti"]),
            r"Nuxt": ("Nuxt.js", "frontend", []),
        },
        "server": {
            r"nginx/?([\d.]+)?": ("Nginx", "webserver", []),
            r"Apache/?([\d.]+)?": ("Apache", "webserver", ["lfi"]),
            r"Microsoft-IIS/?([\d.]+)?": ("IIS", "webserver", ["lfi", "upload"]),
            r"LiteSpeed": ("LiteSpeed", "webserver", []),
            r"Cloudflare": ("Cloudflare", "cdn", []),
            r"AmazonS3": ("Amazon S3", "storage", ["ssrf"]),
            r"openresty": ("OpenResty", "webserver", []),
            r"Caddy": ("Caddy", "webserver", []),
            r"Kestrel": ("Kestrel", "webserver", ["deserial"]),
            r"gunicorn": ("Gunicorn", "webserver", []),
            r"uvicorn": ("Uvicorn", "webserver", []),
            r"Werkzeug": ("Werkzeug", "webserver", ["ssti"]),
            r"Jetty": ("Jetty", "webserver", ["deserial"]),
            r"Tomcat": ("Tomcat", "webserver", ["deserial", "xxe"]),
            r"WildFly": ("WildFly", "webserver", ["deserial"]),
            r"WebLogic": ("WebLogic", "webserver", ["deserial"]),
            r"WebSphere": ("WebSphere", "webserver", ["deserial"]),
        },
        "x-aspnet-version": {
            r"([\d.]+)": ("ASP.NET", "backend", ["deserial"]),
        },
        "x-drupal-cache": {
            r".*": ("Drupal", "cms", ["sqli", "upload"]),
        },
        "x-generator": {
            r"Drupal\s*([\d.]+)?": ("Drupal", "cms", ["sqli", "upload"]),
            r"WordPress\s*([\d.]+)?": ("WordPress", "cms", ["sqli", "upload", "xss"]),
            r"Joomla": ("Joomla", "cms", ["sqli", "upload"]),
        },
        "x-shopify-stage": {
            r".*": ("Shopify", "ecommerce", []),
        },
        "x-wix-request-id": {
            r".*": ("Wix", "cms", []),
        },
        "x-magento-cache": {
            r".*": ("Magento", "ecommerce", ["sqli", "upload"]),
        },
        "x-varnish": {
            r".*": ("Varnish", "cache", []),
        },
        "x-cache": {
            r"Hit from cloudfront": ("CloudFront", "cdn", []),
            r".*Varnish.*": ("Varnish", "cache", []),
        },
        "x-amz-cf-id": {
            r".*": ("CloudFront", "cdn", []),
        },
        "x-azure-ref": {
            r".*": ("Azure", "cloud", ["ssrf"]),
        },
        "cf-ray": {
            r".*": ("Cloudflare", "cdn", []),
        },
        "x-sucuri-id": {
            r".*": ("Sucuri", "waf", []),
        },
        "x-kong-upstream-latency": {
            r".*": ("Kong", "gateway", []),
        },
        "via": {
            r".*cloudfront.*": ("CloudFront", "cdn", []),
            r".*akamai.*": ("Akamai", "cdn", []),
            r".*fastly.*": ("Fastly", "cdn", []),
        },
        "x-envoy-upstream-service-time": {
            r".*": ("Envoy", "proxy", []),
        },
    }
    
    COOKIES: Dict[str, TechFingerprint] = {
        r"PHPSESSID": ("PHP", "backend", ["lfi", "upload"]),
        r"JSESSIONID": ("Java", "backend", ["deserial", "xxe"]),
        r"ASP\.NET_SessionId": ("ASP.NET", "backend", ["deserial"]),
        r"ci_session": ("CodeIgniter", "framework", ["sqli"]),
        r"laravel_session": ("Laravel", "framework", ["sqli", "ssti"]),
        r"_rails_session": ("Ruby on Rails", "framework", ["deserial"]),
        r"express\.sid": ("Express.js", "backend", ["prototype"]),
        r"connect\.sid": ("Express.js", "backend", ["prototype"]),
        r"CFID|CFTOKEN": ("ColdFusion", "backend", ["lfi", "upload"]),
        r"wp-settings": ("WordPress", "cms", ["sqli", "upload"]),
        r"wordpress_logged_in": ("WordPress", "cms", ["sqli", "upload"]),
        r"Drupal\.visitor": ("Drupal", "cms", ["sqli"]),
        r"PrestaShop": ("PrestaShop", "ecommerce", ["sqli"]),
        r"frontend_cid": ("Magento", "ecommerce", ["sqli"]),
        r"_shopify_s": ("Shopify", "ecommerce", []),
        r"django_language": ("Django", "framework", ["ssti"]),
        r"csrftoken.*django": ("Django", "framework", ["ssti"]),
        r"flask": ("Flask", "framework", ["ssti"]),
        r"grafana_session": ("Grafana", "monitoring", ["ssrf"]),
        r"kibana": ("Kibana", "monitoring", ["ssrf"]),
    }
    
    BODY_PATTERNS = [
        (r"<meta\s+name=[\"']generator[\"']\s+content=[\"']WordPress\s*([\d.]+)?", "WordPress", "cms", ["sqli", "upload", "xss"]),
        (r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Drupal\s*([\d.]+)?", "Drupal", "cms", ["sqli", "upload"]),
        (r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Joomla", "Joomla", "cms", ["sqli", "upload"]),
        (r"<link[^>]+wp-content", "WordPress", "cms", ["sqli", "upload"]),
        (r"/wp-includes/", "WordPress", "cms", ["sqli", "upload"]),
        (r"/wp-json/", "WordPress", "cms", ["sqli", "upload"]),
        (r"Powered by WordPress", "WordPress", "cms", ["sqli", "upload"]),
        (r"/sites/default/files/", "Drupal", "cms", ["sqli"]),
        (r"Drupal\.settings", "Drupal", "cms", ["sqli"]),
        (r"/media/jui/", "Joomla", "cms", ["sqli"]),
        (r"jQuery\s*\(\s*Joomla", "Joomla", "cms", ["sqli"]),
        (r"Shopify\.theme", "Shopify", "ecommerce", []),
        (r"cdn\.shopify\.com", "Shopify", "ecommerce", []),
        (r"/skin/frontend/", "Magento", "ecommerce", ["sqli"]),
        (r"Mage\.Cookies", "Magento", "ecommerce", ["sqli"]),
        (r"var\s+Mage\s*=", "Magento", "ecommerce", ["sqli"]),
        (r"React\.createElement|ReactDOM|react-dom", "React", "frontend", ["xss", "prototype"]),
        (r"__NEXT_DATA__", "Next.js", "frontend", []),
        (r"ng-app|ng-controller|angular\.[^\"']+", "AngularJS", "frontend", ["xss", "ssti"]),
        (r"\[\[ngModel\]\]|@angular/core", "Angular", "frontend", ["xss"]),
        (r"Vue\s*\(|new\s+Vue|v-bind:|v-model|:class=", "Vue.js", "frontend", ["xss", "prototype"]),
        (r"__NUXT__", "Nuxt.js", "frontend", []),
        (r"ember-view|Ember\.Application", "Ember.js", "frontend", []),
        (r"<script[^>]+jquery[^>]*>|jQuery\s*\(", "jQuery", "library", ["xss"]),
        (r"bootstrap\.min\.(js|css)|class=[\"'][^\"']*btn\s+btn-", "Bootstrap", "library", []),
        (r"tailwindcss|class=[\"'][^\"']*(flex|grid|p-\d|m-\d|text-)", "Tailwind CSS", "library", []),
        (r"graphql|__schema|IntrospectionQuery", "GraphQL", "api", ["graphql"]),
        (r"/swagger-ui/|swagger\.json|openapi\.json", "Swagger", "api", ["api"]),
        (r"Spring\s*Security|spring-security", "Spring", "framework", ["deserial", "xxe"]),
        (r"struts|org\.apache\.struts", "Apache Struts", "framework", ["deserial", "cmdi"]),
        (r"laravel|Illuminate\\", "Laravel", "framework", ["sqli", "ssti"]),
        (r"symfony|sf2|Symfony\\", "Symfony", "framework", ["sqli"]),
        (r"django\.contrib|csrfmiddlewaretoken", "Django", "framework", ["ssti"]),
        (r"flask[^\"']+session|Werkzeug", "Flask", "framework", ["ssti"]),
        (r"express\(\)|app\.listen\(|express\.Router", "Express.js", "backend", ["prototype"]),
        (r"grails|Grails", "Grails", "framework", ["deserial"]),
        (r"ThinkPHP|thinkphp", "ThinkPHP", "framework", ["cmdi", "lfi"]),
        (r"CakePHP|cakephp", "CakePHP", "framework", ["sqli"]),
        (r"CodeIgniter|codeigniter", "CodeIgniter", "framework", ["sqli"]),
        (r"fckeditor|ckeditor", "CKEditor", "library", ["upload"]),
        (r"tinymce", "TinyMCE", "library", ["xss"]),
        (r"kindeditor", "KindEditor", "library", ["upload"]),
        (r"ueditor", "UEditor", "library", ["upload"]),
        (r"plupload", "Plupload", "library", ["upload"]),
        (r"dropzone", "Dropzone", "library", ["upload"]),
        (r"jenkins", "Jenkins", "devops", ["cmdi", "deserial"]),
        (r"gitlab", "GitLab", "devops", ["ssrf", "cmdi"]),
        (r"grafana", "Grafana", "monitoring", ["ssrf"]),
        (r"kibana", "Kibana", "monitoring", ["ssrf"]),
        (r"prometheus", "Prometheus", "monitoring", []),
        (r"zabbix", "Zabbix", "monitoring", ["sqli"]),
        (r"nagios", "Nagios", "monitoring", ["cmdi"]),
        (r"phpMyAdmin|phpmyadmin", "phpMyAdmin", "database", ["sqli", "lfi"]),
        (r"Adminer", "Adminer", "database", ["sqli"]),
        (r"mongo-express", "Mongo Express", "database", []),
        (r"elasticsearch|elastic\.co", "Elasticsearch", "database", ["ssrf"]),
        (r"redis|Redis", "Redis", "database", ["ssrf"]),
        (r"memcached", "Memcached", "database", []),
        (r"solr", "Apache Solr", "database", ["ssrf", "xxe"]),
    ]
    
    URL_PATTERNS = {
        r"/wp-admin": ("WordPress", "cms", ["sqli", "upload"]),
        r"/wp-login\.php": ("WordPress", "cms", ["sqli", "upload"]),
        r"/administrator": ("Joomla", "cms", ["sqli"]),
        r"/user/login": ("Drupal", "cms", ["sqli"]),
        r"/admin/login": ("Admin Panel", "admin", ["sqli", "auth"]),
        r"/phpmyadmin": ("phpMyAdmin", "database", ["sqli", "lfi"]),
        r"/adminer": ("Adminer", "database", ["sqli"]),
        r"\.aspx": ("ASP.NET", "backend", ["deserial"]),
        r"\.asp": ("ASP Classic", "backend", ["sqli"]),
        r"\.jsp": ("Java", "backend", ["deserial", "xxe"]),
        r"\.do": ("Apache Struts", "framework", ["deserial", "cmdi"]),
        r"\.action": ("Apache Struts", "framework", ["deserial", "cmdi"]),
        r"/api/v\d": ("REST API", "api", ["api", "idor"]),
        r"/graphql": ("GraphQL", "api", ["graphql"]),
        r"/actuator": ("Spring Boot", "framework", ["ssrf", "disclosure"]),
        r"/console": ("H2 Console", "database", ["sqli"]),
        r"/jenkins": ("Jenkins", "devops", ["cmdi", "deserial"]),
        r"/gitlab": ("GitLab", "devops", ["ssrf"]),
        r"/kibana": ("Kibana", "monitoring", ["ssrf"]),
        r"/grafana": ("Grafana", "monitoring", ["ssrf"]),
        r"/swagger": ("Swagger", "api", ["api"]),
        r"/api-docs": ("API Documentation", "api", ["api"]),
    }
    
    HASH_SIGNATURES = {
        "e3b0c44298fc1c149afbf4c8996fb924": ("Empty Response", "unknown", []),
    }


class TechDetector:
    def __init__(self):
        self.db = FingerprintDB()
        self._cache = {}
    
    def detect(self, response: Dict) -> List[Technology]:
        cache_key = self._cache_key(response)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        technologies = []
        seen = set()
        
        technologies.extend(self._check_headers(response.get("headers", {}), seen))
        technologies.extend(self._check_cookies(response.get("headers", {}), seen))
        technologies.extend(self._check_body(response.get("text", ""), seen))
        technologies.extend(self._check_url(response.get("url", ""), seen))
        
        technologies = self._resolve_implications(technologies)
        
        technologies.sort(key=lambda t: (-t.confidence, t.name))
        
        self._cache[cache_key] = technologies
        return technologies
    
    def _cache_key(self, response: Dict) -> str:
        url = response.get("url", "")
        headers_str = str(sorted(response.get("headers", {}).items()))
        body_sample = response.get("text", "")[:1000]
        return hashlib.md5(f"{url}{headers_str}{body_sample}".encode()).hexdigest()
    
    def _check_headers(self, headers: Dict, seen: Set) -> List[Technology]:
        results = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header_name, patterns in self.db.HEADERS.items():
            header_value = headers_lower.get(header_name, "")
            if not header_value:
                continue
            
            for pattern, (name, category, modules) in patterns.items():
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    if name not in seen:
                        seen.add(name)
                        version = match.group(1) if match.lastindex else None
                        results.append(Technology(
                            name=name,
                            category=category,
                            version=version,
                            confidence=100,
                            relevant_modules=modules,
                        ))
        
        return results
    
    def _check_cookies(self, headers: Dict, seen: Set) -> List[Technology]:
        results = []
        cookies = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        
        if not cookies:
            return results
        
        for pattern, (name, category, modules) in self.db.COOKIES.items():
            if re.search(pattern, cookies, re.IGNORECASE):
                if name not in seen:
                    seen.add(name)
                    results.append(Technology(
                        name=name,
                        category=category,
                        confidence=90,
                        relevant_modules=modules,
                    ))
        
        return results
    
    def _check_body(self, body: str, seen: Set) -> List[Technology]:
        results = []
        
        if not body:
            return results
        
        body_sample = body[:50000]
        
        for pattern, name, category, modules in self.db.BODY_PATTERNS:
            match = re.search(pattern, body_sample, re.IGNORECASE)
            if match:
                if name not in seen:
                    seen.add(name)
                    version = match.group(1) if match.lastindex else None
                    results.append(Technology(
                        name=name,
                        category=category,
                        version=version,
                        confidence=80,
                        relevant_modules=modules,
                    ))
        
        return results
    
    def _check_url(self, url: str, seen: Set) -> List[Technology]:
        results = []
        
        if not url:
            return results
        
        for pattern, (name, category, modules) in self.db.URL_PATTERNS.items():
            if re.search(pattern, url, re.IGNORECASE):
                if name not in seen:
                    seen.add(name)
                    results.append(Technology(
                        name=name,
                        category=category,
                        confidence=70,
                        relevant_modules=modules,
                    ))
        
        return results
    
    def _resolve_implications(self, technologies: List[Technology]) -> List[Technology]:
        implications = {
            "WordPress": ["PHP", "MySQL"],
            "Drupal": ["PHP"],
            "Joomla": ["PHP", "MySQL"],
            "Magento": ["PHP", "MySQL"],
            "Laravel": ["PHP"],
            "Symfony": ["PHP"],
            "Django": ["Python"],
            "Flask": ["Python"],
            "Express.js": ["Node.js"],
            "Next.js": ["Node.js", "React"],
            "Nuxt.js": ["Node.js", "Vue.js"],
            "Angular": ["TypeScript"],
            "Spring": ["Java"],
            "Spring Boot": ["Java", "Spring"],
            "Grails": ["Java", "Groovy"],
        }
        
        seen = {t.name for t in technologies}
        
        for tech in list(technologies):
            if tech.name in implications:
                for implied in implications[tech.name]:
                    if implied not in seen:
                        seen.add(implied)
                        technologies.append(Technology(
                            name=implied,
                            category="implied",
                            confidence=60,
                            relevant_modules=[],
                        ))
        
        return technologies
    
    def get_recommended_modules(self, technologies: List[Technology]) -> Set[str]:
        modules = set()
        
        for tech in technologies:
            modules.update(tech.relevant_modules)
        
        return modules
    
    def get_summary(self, technologies: List[Technology]) -> Dict:
        by_category = {}
        
        for tech in technologies:
            if tech.category not in by_category:
                by_category[tech.category] = []
            version_str = f" {tech.version}" if tech.version else ""
            by_category[tech.category].append(f"{tech.name}{version_str}")
        
        return {
            "technologies": [
                {
                    "name": t.name,
                    "category": t.category,
                    "version": t.version,
                    "confidence": t.confidence,
                }
                for t in technologies
            ],
            "by_category": by_category,
            "recommended_modules": list(self.get_recommended_modules(technologies)),
            "count": len(technologies),
        }


class TechFingerprinter:
    def __init__(self, http_client=None):
        self.http = http_client
        self.detector = TechDetector()
        self._results = {}
    
    async def fingerprint(self, url: str) -> Dict:
        if url in self._results:
            return self._results[url]
        
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        paths_to_check = [
            "/",
            "/robots.txt",
            "/favicon.ico",
            "/sitemap.xml",
        ]
        
        all_technologies = []
        seen = set()
        
        for path in paths_to_check:
            check_url = f"{base_url}{path}"
            
            try:
                response = await self.http.get(check_url)
                
                if response and response.get("status"):
                    response["url"] = check_url
                    techs = self.detector.detect(response)
                    
                    for tech in techs:
                        if tech.name not in seen:
                            seen.add(tech.name)
                            all_technologies.append(tech)
            except:
                pass
        
        result = self.detector.get_summary(all_technologies)
        result["url"] = url
        
        self._results[url] = result
        return result
    
    async def fingerprint_response(self, response: Dict) -> Dict:
        technologies = self.detector.detect(response)
        return self.detector.get_summary(technologies)
    
    def get_modules_for_target(self, url: str) -> Set[str]:
        if url in self._results:
            return set(self._results[url].get("recommended_modules", []))
        return set()


def detect_technologies(response: Dict) -> List[Technology]:
    detector = TechDetector()
    return detector.detect(response)


def get_recommended_modules(response: Dict) -> Set[str]:
    detector = TechDetector()
    technologies = detector.detect(response)
    return detector.get_recommended_modules(technologies)
