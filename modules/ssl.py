import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from modules.base import BaseModule

class SslModule(BaseModule):
    name = "ssl"
    description = "SSL/TLS Configuration Scanner"
    
    weak_ciphers = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
        "ADH", "AECDH", "LOW", "EXP", "PSK", "SRP", "IDEA", "SEED"
    ]
    
    async def scan(self, target):
        self.findings = []
        
        parsed = urlparse(target)
        host = parsed.netloc.split(":")[0]
        port = 443 if parsed.scheme == "https" else (int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 80)
        
        if parsed.scheme != "https" and port != 443:
            resp = await self.http.get(target.replace("http://", "https://"))
            if not resp.get("status"):
                self.add_finding(
                    "HIGH",
                    "HTTPS not available",
                    url=target,
                    evidence="Site does not support HTTPS"
                )
                return self.findings
        
        await self._check_certificate(host, port)
        await self._check_protocols(host, port)
        await self._check_ciphers(host, port)
        await self._check_headers(target)
        
        return self.findings
    
    async def _check_certificate(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    if cert:
                        not_after = cert.get("notAfter")
                        if not_after:
                            try:
                                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (exp_date - datetime.now()).days
                                
                                if days_left < 0:
                                    self.add_finding(
                                        "CRITICAL",
                                        "SSL Certificate Expired",
                                        url=f"https://{host}",
                                        evidence=f"Expired {abs(days_left)} days ago"
                                    )
                                elif days_left < 30:
                                    self.add_finding(
                                        "HIGH",
                                        "SSL Certificate Expiring Soon",
                                        url=f"https://{host}",
                                        evidence=f"Expires in {days_left} days"
                                    )
                            except:
                                pass
                        
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        
                        if subject.get("commonName") == issuer.get("commonName"):
                            self.add_finding(
                                "HIGH",
                                "Self-Signed Certificate",
                                url=f"https://{host}",
                                evidence="Certificate is self-signed"
                            )
                        
                        cn = subject.get("commonName", "")
                        san = cert.get("subjectAltName", [])
                        san_names = [x[1] for x in san if x[0] == "DNS"]
                        
                        if host not in san_names and not cn.replace("*.", "") in host:
                            self.add_finding(
                                "MEDIUM",
                                "Certificate hostname mismatch",
                                url=f"https://{host}",
                                evidence=f"CN: {cn}, Host: {host}"
                            )
        except ssl.SSLError as e:
            self.add_finding(
                "HIGH",
                f"SSL Error: {str(e)[:50]}",
                url=f"https://{host}",
                evidence="SSL handshake failed"
            )
        except Exception as e:
            pass
    
    async def _check_protocols(self, host, port):
        deprecated_protocols = [
            (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
            (ssl.PROTOCOL_TLSv1_1, "TLSv1.1"),
        ]
        
        for protocol, name in deprecated_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        self.add_finding(
                            "MEDIUM",
                            f"Deprecated protocol supported: {name}",
                            url=f"https://{host}",
                            evidence=f"{name} should be disabled"
                        )
            except:
                pass
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    self.add_finding(
                        "CRITICAL",
                        "SSLv3 supported (POODLE vulnerable)",
                        url=f"https://{host}",
                        evidence="SSLv3 must be disabled"
                    )
        except:
            pass
    
    async def _check_ciphers(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in self.weak_ciphers:
                            if weak.upper() in cipher_name.upper():
                                self.add_finding(
                                    "HIGH",
                                    f"Weak cipher in use: {cipher_name}",
                                    url=f"https://{host}",
                                    evidence=f"Contains weak component: {weak}"
                                )
                                break
                        
                        if cipher[2] and cipher[2] < 128:
                            self.add_finding(
                                "HIGH",
                                f"Weak cipher key length: {cipher[2]} bits",
                                url=f"https://{host}",
                                evidence="Key length should be >= 128 bits"
                            )
        except:
            pass
    
    async def _check_headers(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        if "strict-transport-security" not in headers:
            self.add_finding(
                "MEDIUM",
                "Missing HSTS header",
                url=target,
                evidence="Strict-Transport-Security not set"
            )
        else:
            hsts = headers["strict-transport-security"]
            if "includeSubDomains" not in hsts:
                self.add_finding(
                    "LOW",
                    "HSTS missing includeSubDomains",
                    url=target,
                    evidence=f"Current: {hsts}"
                )
            if "preload" not in hsts:
                self.add_finding(
                    "INFO",
                    "HSTS missing preload directive",
                    url=target,
                    evidence="Consider adding preload for browser preload list"
                )
