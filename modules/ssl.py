import re
import ssl
import socket
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from modules.base import BaseModule


class SslModule(BaseModule):
    name = "ssl"
    description = "SSL/TLS Configuration Scanner"
    
    weak_ciphers = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
        "ADH", "AECDH", "LOW", "EXP", "PSK", "SRP", "IDEA", "SEED",
        "RC2", "CAMELLIA", "ARIA"
    ]
    
    strong_ciphers = [
        "ECDHE", "DHE", "AES128-GCM", "AES256-GCM", "CHACHA20"
    ]
    
    cipher_suites_to_test = [
        ("TLS_RSA_WITH_RC4_128_SHA", "RC4", "CRITICAL"),
        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "HIGH"),
        ("TLS_RSA_WITH_DES_CBC_SHA", "DES", "CRITICAL"),
        ("TLS_RSA_WITH_NULL_SHA", "NULL cipher", "CRITICAL"),
        ("TLS_RSA_EXPORT", "Export cipher", "CRITICAL"),
        ("TLS_RSA_WITH_AES_128_CBC_SHA", "CBC without AEAD", "LOW"),
    ]
    
    known_weak_keys = {
        "debian_weak_keys": "Known weak Debian OpenSSL keys",
        "factorable_keys": "Potentially factorable RSA key",
    }
    
    async def scan(self, target):
        self.findings = []
        self.cert_info = {}
        
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
                    evidence="Site does not support HTTPS",
                    confidence_evidence=["no_encryption"]
                )
                return self.findings
        
        await self._check_certificate(host, port)
        await self._check_certificate_chain(host, port)
        await self._check_key_strength(host, port)
        await self._check_protocols(host, port)
        await self._check_ciphers_detailed(host, port)
        await self._check_forward_secrecy(host, port)
        await self._check_compression(host, port)
        await self._check_renegotiation(host, port)
        await self._check_headers(target)
        await self._check_mixed_content(target)
        
        if self.aggressive:
            await self._check_ocsp_stapling(host, port)
            await self._check_ct_logs(host, port)
            await self._check_heartbleed(host, port)
            await self._check_ticketbleed(host, port)
            await self._check_robot(host, port)
        
        if port == 443:
            await self._check_http2(host, port)
        
        return self.findings
    
    async def _check_certificate(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert(binary_form=False)
                    
                    if cert_der:
                        self.cert_info["fingerprint_sha256"] = hashlib.sha256(cert_der).hexdigest()
                        self.cert_info["fingerprint_sha1"] = hashlib.sha1(cert_der).hexdigest()
                    
                    if cert:
                        not_after = cert.get("notAfter")
                        not_before = cert.get("notBefore")
                        
                        if not_after:
                            try:
                                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days_left = (exp_date - datetime.now()).days
                                
                                if days_left < 0:
                                    self.add_finding(
                                        "CRITICAL",
                                        "SSL Certificate Expired",
                                        url=f"https://{host}",
                                        evidence=f"Expired {abs(days_left)} days ago on {not_after}",
                                        confidence_evidence=["cert_expired", "security_risk"]
                                    )
                                elif days_left < 7:
                                    self.add_finding(
                                        "CRITICAL",
                                        "SSL Certificate Expiring Very Soon",
                                        url=f"https://{host}",
                                        evidence=f"Expires in {days_left} days",
                                        confidence_evidence=["cert_expiring"]
                                    )
                                elif days_left < 30:
                                    self.add_finding(
                                        "HIGH",
                                        "SSL Certificate Expiring Soon",
                                        url=f"https://{host}",
                                        evidence=f"Expires in {days_left} days on {not_after}",
                                        confidence_evidence=["cert_expiring"]
                                    )
                                elif days_left < 90:
                                    self.add_finding(
                                        "MEDIUM",
                                        "SSL Certificate Expires Within 90 Days",
                                        url=f"https://{host}",
                                        evidence=f"Expires in {days_left} days"
                                    )
                            except:
                                pass
                        
                        if not_before:
                            try:
                                start_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                                if start_date > datetime.now():
                                    self.add_finding(
                                        "CRITICAL",
                                        "SSL Certificate Not Yet Valid",
                                        url=f"https://{host}",
                                        evidence=f"Valid from: {not_before}"
                                    )
                            except:
                                pass
                        
                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        
                        self.cert_info["subject"] = subject
                        self.cert_info["issuer"] = issuer
                        
                        if subject.get("commonName") == issuer.get("commonName"):
                            org = subject.get("organizationName", "")
                            if org != issuer.get("organizationName", ""):
                                self.add_finding(
                                    "HIGH",
                                    "Self-Signed Certificate",
                                    url=f"https://{host}",
                                    evidence=f"Subject: {subject.get('commonName')}",
                                    confidence_evidence=["self_signed", "trust_issue"]
                                )
                        
                        cn = subject.get("commonName", "")
                        san = cert.get("subjectAltName", [])
                        san_names = [x[1] for x in san if x[0] == "DNS"]
                        
                        self.cert_info["san"] = san_names
                        
                        hostname_valid = False
                        if host in san_names:
                            hostname_valid = True
                        elif cn and ("*" in cn):
                            wildcard_base = cn.replace("*.", "")
                            if host.endswith("." + wildcard_base) or host == wildcard_base:
                                hostname_valid = True
                        elif host == cn:
                            hostname_valid = True
                        
                        for san in san_names:
                            if "*" in san:
                                wildcard_base = san.replace("*.", "")
                                if host.endswith("." + wildcard_base) or host == wildcard_base:
                                    hostname_valid = True
                                    break
                        
                        if not hostname_valid:
                            self.add_finding(
                                "HIGH",
                                "Certificate Hostname Mismatch",
                                url=f"https://{host}",
                                evidence=f"Host: {host}, CN: {cn}, SANs: {', '.join(san_names[:5])}",
                                confidence_evidence=["hostname_mismatch", "mitm_risk"]
                            )
                        
                        if cn and "*" in cn:
                            if cn.count("*") > 1 or cn.startswith("*.*."):
                                self.add_finding(
                                    "MEDIUM",
                                    "Invalid Wildcard Certificate",
                                    url=f"https://{host}",
                                    evidence=f"CN: {cn}"
                                )
                        
                        serial = cert.get("serialNumber")
                        if serial and serial == "0" * len(serial):
                            self.add_finding(
                                "LOW",
                                "Certificate has zero serial number",
                                url=f"https://{host}",
                                evidence="Serial: 0 (unusual)"
                            )
                        
        except ssl.SSLError as e:
            self.add_finding(
                "HIGH",
                f"SSL Error: {str(e)[:100]}",
                url=f"https://{host}",
                evidence="SSL handshake failed",
                confidence_evidence=["ssl_error"]
            )
        except socket.timeout:
            self.add_finding(
                "MEDIUM",
                "SSL Connection Timeout",
                url=f"https://{host}",
                evidence="Connection timed out during SSL handshake"
            )
        except Exception as e:
            pass
    
    async def _check_certificate_chain(self, host, port):
        try:
            context = ssl.create_default_context()
            
            try:
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        pass
            except ssl.SSLCertVerificationError as e:
                error_msg = str(e).lower()
                
                if "certificate verify failed" in error_msg:
                    if "self signed" in error_msg or "self-signed" in error_msg:
                        pass
                    elif "unable to get local issuer" in error_msg:
                        self.add_finding(
                            "HIGH",
                            "Incomplete Certificate Chain",
                            url=f"https://{host}",
                            evidence="Missing intermediate certificates",
                            confidence_evidence=["incomplete_chain", "trust_issue"]
                        )
                    elif "certificate has expired" in error_msg:
                        pass
                    else:
                        self.add_finding(
                            "HIGH",
                            "Certificate Verification Failed",
                            url=f"https://{host}",
                            evidence=str(e)[:100],
                            confidence_evidence=["cert_invalid"]
                        )
        except Exception:
            pass
    
    async def _check_key_strength(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    cipher = ssock.cipher()
                    if cipher:
                        key_bits = cipher[2]
                        cipher_name = cipher[0]
                        
                        if "RSA" in cipher_name:
                            if key_bits and key_bits < 2048:
                                self.add_finding(
                                    "HIGH",
                                    f"Weak RSA Key Size: {key_bits} bits",
                                    url=f"https://{host}",
                                    evidence="RSA keys should be at least 2048 bits",
                                    confidence_evidence=["weak_key", "crypto_issue"]
                                )
                            elif key_bits and key_bits < 3072:
                                self.add_finding(
                                    "LOW",
                                    f"RSA Key Size Could Be Stronger: {key_bits} bits",
                                    url=f"https://{host}",
                                    evidence="Consider 3072+ bits for long-term security"
                                )
                        
                        elif "ECDSA" in cipher_name or "ECDHE" in cipher_name:
                            if key_bits and key_bits < 256:
                                self.add_finding(
                                    "HIGH",
                                    f"Weak ECC Key Size: {key_bits} bits",
                                    url=f"https://{host}",
                                    evidence="ECC keys should be at least 256 bits",
                                    confidence_evidence=["weak_key"]
                                )
        except Exception:
            pass
    
    async def _check_protocols(self, host, port):
        protocols_to_check = []
        
        if hasattr(ssl, 'PROTOCOL_SSLv2'):
            protocols_to_check.append((ssl.PROTOCOL_SSLv2, "SSLv2", "CRITICAL"))
        
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            protocols_to_check.append((ssl.PROTOCOL_SSLv3, "SSLv3", "CRITICAL"))
        
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            protocols_to_check.append((ssl.PROTOCOL_TLSv1, "TLSv1.0", "HIGH"))
        
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            protocols_to_check.append((ssl.PROTOCOL_TLSv1_1, "TLSv1.1", "MEDIUM"))
        
        supported_protocols = []
        
        for protocol, name, severity in protocols_to_check:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        supported_protocols.append(name)
                        
                        vuln_note = ""
                        if name == "SSLv2":
                            vuln_note = " (DROWN vulnerable)"
                        elif name == "SSLv3":
                            vuln_note = " (POODLE vulnerable)"
                        elif name == "TLSv1.0":
                            vuln_note = " (BEAST/CRIME vulnerable)"
                        
                        self.add_finding(
                            severity,
                            f"Deprecated Protocol: {name}{vuln_note}",
                            url=f"https://{host}",
                            evidence=f"{name} should be disabled",
                            confidence_evidence=["deprecated_protocol", "security_risk"]
                        )
            except ssl.SSLError:
                pass
            except Exception:
                pass
        
        tls13_supported = False
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    tls13_supported = True
                    self.add_finding(
                        "INFO",
                        "TLSv1.3 Supported",
                        url=f"https://{host}",
                        evidence="Modern TLS version available"
                    )
        except:
            pass
        
        if not tls13_supported:
            self.add_finding(
                "LOW",
                "TLSv1.3 Not Supported",
                url=f"https://{host}",
                evidence="Consider enabling TLSv1.3 for improved security"
            )
    
    async def _check_ciphers_detailed(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        protocol = cipher[1]
                        key_bits = cipher[2]
                        
                        self.cert_info["negotiated_cipher"] = cipher_name
                        self.cert_info["negotiated_protocol"] = protocol
                        
                        for weak in self.weak_ciphers:
                            if weak.upper() in cipher_name.upper():
                                self.add_finding(
                                    "HIGH",
                                    f"Weak Cipher Negotiated: {cipher_name}",
                                    url=f"https://{host}",
                                    evidence=f"Contains weak component: {weak}",
                                    confidence_evidence=["weak_cipher", "crypto_issue"]
                                )
                                break
                        
                        if key_bits and key_bits < 128:
                            self.add_finding(
                                "CRITICAL",
                                f"Very Weak Cipher Key: {key_bits} bits",
                                url=f"https://{host}",
                                evidence="Key length must be >= 128 bits",
                                confidence_evidence=["weak_key", "critical_crypto"]
                            )
                        elif key_bits and key_bits < 256:
                            pass
                        
                        if "CBC" in cipher_name and "SHA" in cipher_name:
                            self.add_finding(
                                "LOW",
                                "Non-AEAD Cipher Suite",
                                url=f"https://{host}",
                                evidence=f"Cipher: {cipher_name}, Prefer GCM or CHACHA20"
                            )
                        
                        if "ECDHE" not in cipher_name and "DHE" not in cipher_name:
                            self.add_finding(
                                "MEDIUM",
                                "No Forward Secrecy",
                                url=f"https://{host}",
                                evidence=f"Cipher: {cipher_name}",
                                confidence_evidence=["no_pfs"]
                            )
        except Exception:
            pass
    
    async def _check_forward_secrecy(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            pfs_ciphers = [
                'ECDHE+AESGCM', 'ECDHE+CHACHA20', 'DHE+AESGCM', 'DHE+CHACHA20',
                'ECDHE+AES', 'DHE+AES'
            ]
            context.set_ciphers(':'.join(pfs_ciphers))
            
            try:
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cipher = ssock.cipher()
                        if cipher:
                            self.add_finding(
                                "INFO",
                                "Forward Secrecy Supported",
                                url=f"https://{host}",
                                evidence=f"PFS cipher available: {cipher[0]}"
                            )
            except ssl.SSLError:
                self.add_finding(
                    "HIGH",
                    "Forward Secrecy Not Supported",
                    url=f"https://{host}",
                    evidence="No ECDHE or DHE cipher suites accepted",
                    confidence_evidence=["no_pfs", "key_compromise_risk"]
                )
        except Exception:
            pass
    
    async def _check_compression(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    compression = ssock.compression()
                    if compression:
                        self.add_finding(
                            "HIGH",
                            "TLS Compression Enabled (CRIME/BREACH)",
                            url=f"https://{host}",
                            evidence=f"Compression: {compression}",
                            confidence_evidence=["tls_compression", "crime_breach_vulnerable"]
                        )
        except Exception:
            pass
    
    async def _check_renegotiation(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    
                    try:
                        ssock.do_handshake()
                    except ssl.SSLError as e:
                        if "renegotiation" in str(e).lower():
                            self.add_finding(
                                "MEDIUM",
                                "Insecure Renegotiation",
                                url=f"https://{host}",
                                evidence="Server allows insecure renegotiation",
                                confidence_evidence=["renegotiation_vuln"]
                            )
        except Exception:
            pass
    
    async def _check_headers(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        
        if "strict-transport-security" not in headers:
            self.add_finding(
                "MEDIUM",
                "Missing HSTS Header",
                url=target,
                evidence="Strict-Transport-Security not set",
                confidence_evidence=["missing_hsts"]
            )
        else:
            hsts = headers["strict-transport-security"]
            
            if re.search(r"max-age\s*=\s*0", hsts, re.IGNORECASE):
                self.add_finding(
                    "HIGH",
                    "HSTS Disabled (max-age=0)",
                    url=target,
                    evidence="HSTS effectively disabled",
                    confidence_evidence=["hsts_disabled"]
                )
            else:
                try:
                    max_age_match = re.search(r'max-age\s*=\s*(\d+)', hsts)
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        if max_age < 2592000:
                            self.add_finding(
                                "MEDIUM",
                                f"HSTS max-age Too Short ({max_age}s)",
                                url=target,
                                evidence="Should be at least 30 days (2592000s)",
                                confidence_evidence=["weak_hsts"]
                            )
                except:
                    pass
            
            if "includesubdomains" not in hsts.lower():
                self.add_finding(
                    "LOW",
                    "HSTS Missing includeSubDomains",
                    url=target,
                    evidence="Subdomains not protected"
                )
            
            if "preload" not in hsts.lower():
                self.add_finding(
                    "INFO",
                    "HSTS Missing Preload",
                    url=target,
                    evidence="Consider adding to browser preload list"
                )
        
        if "public-key-pins" in headers or "public-key-pins-report-only" in headers:
            self.add_finding(
                "INFO",
                "Deprecated HPKP Header Present",
                url=target,
                evidence="HPKP is deprecated and removed from browsers"
            )
        
        if "expect-ct" in headers:
            self.add_finding(
                "INFO",
                "Deprecated Expect-CT Header",
                url=target,
                evidence="Certificate Transparency is now mandatory"
            )
    
    async def _check_mixed_content(self, target):
        resp = await self.http.get(target)
        if not resp.get("status"):
            return
        
        text = resp.get("text", "")
        
        http_resources = re.findall(r'(src|href|action)=["\']http://[^"\']+["\']', text, re.I)
        
        if http_resources and "https://" in target:
            unique_resources = list(set(http_resources))[:5]
            self.add_finding(
                "MEDIUM",
                f"Mixed Content: {len(http_resources)} HTTP Resources",
                url=target,
                evidence=f"HTTP resources on HTTPS page",
                confidence_evidence=["mixed_content", "downgrade_risk"]
            )
    
    async def _check_ocsp_stapling(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    try:
                        ocsp_response = ssock.get_channel_binding("tls-server-end-point")
                        if ocsp_response:
                            self.add_finding(
                                "INFO",
                                "OCSP Stapling Supported",
                                url=f"https://{host}",
                                evidence="OCSP response stapled"
                            )
                    except:
                        self.add_finding(
                            "LOW",
                            "OCSP Stapling Not Detected",
                            url=f"https://{host}",
                            evidence="Consider enabling OCSP stapling"
                        )
        except Exception:
            pass
    
    async def _check_ct_logs(self, host, port):
        ct_header = None
        
        try:
            resp = await self.http.get(f"https://{host}")
            if resp.get("status"):
                headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                ct_header = headers.get("expect-ct")
        except:
            pass
        
        self.add_finding(
            "INFO",
            "Certificate Transparency",
            url=f"https://{host}",
            evidence="CT is now enforced by default in modern browsers"
        )
    
    async def _check_heartbleed(self, host, port):
        pass
    
    async def _check_ticketbleed(self, host, port):
        pass
    
    async def _check_robot(self, host, port):
        pass

    async def _check_http2(self, host, port):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if hasattr(context, "set_alpn_protocols"):
                context.set_alpn_protocols(["h2", "http/1.1"])
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    alpn = getattr(ssock, "selected_alpn_protocol", lambda: None)()
                    
                    if alpn == "h2":
                        self.add_finding(
                            "INFO",
                            "HTTP/2 Supported",
                            url=f"https://{host}",
                            evidence="ALPN: h2"
                        )
                    else:
                        self.add_finding(
                            "LOW",
                            "HTTP/2 Not Supported",
                            url=f"https://{host}",
                            evidence="Consider enabling HTTP/2 for performance"
                        )
        except Exception:
            pass
