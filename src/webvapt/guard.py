import ipaddress
import socket
from urllib.parse import urlparse


class GuardError(Exception):
    pass


def assert_authorized(authorized: bool):
    if not authorized:
        raise GuardError(
            "Refusing: pass --i-authorized only for systems you own or have written permission to test."
        )


def enforce_scope(target: str, allow_private: bool = False) -> str:
    u = urlparse(target if "://" in target else "http://" + target)
    if u.scheme not in ("http", "https"):
        raise GuardError("Only http/https allowed.")
    host = u.hostname or ""
    try:
        ip = ipaddress.ip_address(host)
        is_private = ip.is_private or ip.is_loopback
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            is_private = ipaddress.ip_address(resolved).is_private
        except Exception:
            is_private = False
    if is_private and not allow_private:
        raise GuardError("Refusing private/local target without --allow-private.")
    return target if u.path else f"{u.scheme}://{host}/"
