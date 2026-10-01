from __future__ import annotations
import re
from pathlib import Path
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
IPV4_RE = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\\r\n:*?\"<>|]+\\)*[^\\\r\n:*?\"<>|]*")

def extract_iocs(texts: list[str]) -> dict:
    joined = "\n".join(texts)
    urls = sorted(set(URL_RE.findall(joined)))[:1000]
    ips = sorted(set(IPV4_RE.findall(joined)))[:1000]
    domains = set(DOMAIN_RE.findall(joined))
    for u in urls:
        try:
            host = urlsplit(u).hostname
            if host:
                domains.add(host)
        except Exception:
            pass
    paths = sorted(set(PATH_RE.findall(joined)))[:1000]
    return {
        "urls": urls,
        "ipv4": ips,
        "domains": sorted(domains)[:1000],
        "windows_paths": paths,
    }
