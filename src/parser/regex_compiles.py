from re import compile

RE_DOMAIN_DOT = compile(r"(?:\.?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?)+([a-z0-9][a-z0-9-]{0,61}[a-z0-9])?")
RE_IVP4 = compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::[0-9]{1,5})?\b")
RE_HOSTNAME = compile(r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
RE_EMAIL = compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.?[A-Z|a-z]{2,}\b")
RE_DOMAIN = compile(r"(?:.?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?)+([a-z0-9][a-z0-9-]{0,61}[a-z0-9])?")
