from dataclasses import dataclass


@dataclass
class ProbeContext:
    url: str
    headers: dict
