from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit


class IoCType(StrEnum):
    """Kind of indicator an input string represents."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"

    @property
    def family(self) -> str:
        """Provider-level grouping this indicator belongs to.

        Returns one of `file`, `ip`, `domain` or `url`.
        """
        if self in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
            return "file"
        if self in (IoCType.IPV4, IoCType.IPV6):
            return "ip"
        return self.value


class UnrecognizedIoCError(ValueError):
    """Raised when an input string matches no supported indicator type."""


@dataclass(frozen=True, slots=True)
class ClassifiedIoC:
    """An input string recognised as an indicator.

    Attributes:
        raw: The string exactly as supplied by the caller.
        value: The refanged, normalised form used for provider queries.
        type: The recognised indicator type.
    """

    raw: str
    value: str
    type: IoCType

    @property
    def family(self) -> str:
        """Provider-level grouping this indicator belongs to."""
        return self.type.family


_HASH_LENGTHS = {32: IoCType.MD5, 40: IoCType.SHA1, 64: IoCType.SHA256}

_HEX_RE = re.compile(r"\A[a-f0-9]+\Z")
_LABEL_RE = re.compile(r"\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
_TLD_RE = re.compile(r"\A[a-z]{2,63}\Z")
_SCHEME_RE = re.compile(r"\A[a-z][a-z0-9+.-]*://", re.IGNORECASE)

_DEFANG_SUBSTITUTIONS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[dot]", "."),
    ("(dot)", "."),
)

_DEFANG_SCHEMES = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
)


def refang(value: str) -> str:
    """Return `value` with common defanging conventions reversed.

    Handles bracketed separators (`evil[.]com`, `10.0.0[.]1`) and neutered
    schemes (`hxxp://`), which is how indicators are usually pasted out of
    reports and tickets.
    """
    result = value.strip().strip("\"'<>")
    for defanged, restored in _DEFANG_SUBSTITUTIONS:
        result = result.replace(defanged, restored)
    lowered = result.lower()
    for defanged, restored in _DEFANG_SCHEMES:
        if lowered.startswith(defanged):
            result = restored + result[len(defanged) :]
            break
    return result


def _is_domain(value: str) -> bool:
    if len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    if not _TLD_RE.match(labels[-1]):
        return False
    return all(_LABEL_RE.match(label) for label in labels)


def _classify_ip(value: str) -> IoCType | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IoCType.IPV4 if address.version == 4 else IoCType.IPV6


def classify(value: str) -> ClassifiedIoC:
    """Recognise `value` as an indicator of compromise.

    Accepts defanged input. Hashes are lowercased and hostnames are reduced to
    their registrable form (trailing dot and `www.` prefix removed) so that the
    same indicator written different ways resolves to one cache entry.

    Args:
        value: A single indicator, such as a hash, IP, domain or URL.

    Returns:
        The classified indicator, carrying both the raw and normalised forms.

    Raises:
        UnrecognizedIoCError: If `value` is empty or matches no supported type.
    """
    raw = value.strip()
    if not raw:
        raise UnrecognizedIoCError("No indicator supplied.")

    candidate = refang(raw)

    if _SCHEME_RE.match(candidate):
        parts = urlsplit(candidate)
        if not parts.netloc:
            raise UnrecognizedIoCError(f"{raw!r} looks like a URL but has no host.")
        bare_host = parts.netloc.rsplit("@", 1)[-1].split(":", 1)[0]
        is_bare_http = (
            parts.scheme in ("http", "https")
            and parts.path in ("", "/")
            and not parts.query
            and not parts.fragment
        )
        if is_bare_http and _is_domain(bare_host.lower().rstrip(".")):
            return ClassifiedIoC(raw=raw, value=_normalise_host(bare_host), type=IoCType.DOMAIN)
        return ClassifiedIoC(raw=raw, value=candidate, type=IoCType.URL)

    lowered = candidate.lower()

    hash_type = _HASH_LENGTHS.get(len(lowered))
    if hash_type and _HEX_RE.match(lowered):
        return ClassifiedIoC(raw=raw, value=lowered, type=hash_type)

    ip_type = _classify_ip(candidate.strip("[]"))
    if ip_type:
        return ClassifiedIoC(raw=raw, value=candidate.strip("[]"), type=ip_type)

    host = _normalise_host(lowered)
    if _is_domain(host):
        return ClassifiedIoC(raw=raw, value=host, type=IoCType.DOMAIN)

    if "/" in lowered and _is_domain(_normalise_host(lowered.split("/", 1)[0])):
        return ClassifiedIoC(raw=raw, value=f"http://{candidate}", type=IoCType.URL)

    raise UnrecognizedIoCError(
        f"{raw!r} is not a recognised hash, IP address, domain or URL."
    )


def _normalise_host(host: str) -> str:
    stripped = host.lower().rstrip(".")
    return stripped[4:] if stripped.startswith("www.") else stripped
