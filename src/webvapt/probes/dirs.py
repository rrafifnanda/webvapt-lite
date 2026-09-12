DIRS = [
    "admin",
    "login",
    "dashboard",
    "api",
    "config",
    ".env",
    ".git/HEAD",
    "wp-admin",
    "server-status",
    "actuator/health",
]


def is_interesting(status: int) -> bool:
    return status in (200, 301, 302, 401, 403)
