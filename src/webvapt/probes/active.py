SQL_ERRORS = [
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "sqlite3::",
    "pg_query()",
    "ora-01756",
]


def reflects(payload: str, body: str) -> bool:
    return payload in (body or "")


def sqli_error(body: str) -> bool:
    b = (body or "").lower()
    return any(s in b for s in SQL_ERRORS)
