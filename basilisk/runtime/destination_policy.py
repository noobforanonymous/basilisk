"""Outbound destination controls for hostile-target scanner isolation."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import ParseResult, parse_qsl, urlparse, urlunparse

from basilisk.core.redaction import is_sensitive_key


class DestinationPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ApprovedDestination:
    """A policy-approved URL paired with the exact socket address to use."""

    url: str
    connect_url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]
    selected_address: str
    host_header: str
    server_hostname: str


@dataclass(frozen=True)
class DestinationPolicy:
    allow_private: bool = False
    allow_insecure_http: bool = False
    allowed_hosts: tuple[str, ...] = ()
    max_redirects: int = 3

    async def validate(self, url: str) -> str:
        await self.approve(url)
        return url

    async def approve(self, url: str) -> ApprovedDestination:
        """Validate and pin a destination to one address from this DNS resolution."""
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https", "ws", "wss"}:
            raise DestinationPolicyError(f"unsupported target URL scheme: {parsed.scheme or 'missing'}")
        if parsed.scheme in {"http", "ws"} and not self.allow_insecure_http:
            raise DestinationPolicyError("unencrypted HTTP/WebSocket targets require explicit policy opt-in")
        if parsed.username or parsed.password:
            raise DestinationPolicyError("credentials in target URLs are not allowed")
        sensitive_query_keys = [
            key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if is_sensitive_key(key)
        ]
        if sensitive_query_keys:
            raise DestinationPolicyError(
                "credentials in target URL query parameters are not allowed"
            )
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if not hostname:
            raise DestinationPolicyError("target URL has no hostname")
        if self.allowed_hosts and not any(_host_matches(hostname, rule) for rule in self.allowed_hosts):
            raise DestinationPolicyError(f"target host is not in the outbound allowlist: {hostname}")
        addresses = await asyncio.to_thread(_resolve_addresses, hostname, parsed.port)
        if not addresses:
            raise DestinationPolicyError(f"target hostname did not resolve: {hostname}")
        if not self.allow_private:
            blocked = [address for address in addresses if not _is_public(address)]
            if blocked:
                raise DestinationPolicyError(
                    f"target resolved to blocked non-public address: {blocked[0]}"
                )
        canonical_addresses = tuple(sorted(
            {str(ipaddress.ip_address(address)) for address in addresses},
            key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
        ))
        selected = canonical_addresses[0]
        port = parsed.port or (443 if parsed.scheme in {"https", "wss"} else 80)
        encoded_hostname = hostname.encode("idna").decode("ascii")
        return ApprovedDestination(
            url=url,
            connect_url=_replace_url_host(parsed, selected),
            hostname=encoded_hostname,
            port=port,
            addresses=canonical_addresses,
            selected_address=selected,
            host_header=_host_header(encoded_hostname, parsed.port),
            server_hostname=encoded_hostname,
        )


def _resolve_addresses(hostname: str, port: int | None) -> list[str]:
    try:
        literal = ipaddress.ip_address(hostname)
        return [str(literal)]
    except ValueError:
        pass
    results = socket.getaddrinfo(hostname, port or 443, type=socket.SOCK_STREAM)
    return sorted({str(item[4][0]) for item in results})


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return bool(ip.is_global) and not any(
        (
            ip.is_loopback,
            ip.is_private,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def _host_matches(hostname: str, rule: str) -> bool:
    normalized = rule.casefold().rstrip(".")
    if normalized.startswith("*."):
        suffix = normalized[1:]
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == normalized


def _replace_url_host(parsed: ParseResult, address: str) -> str:
    rendered = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    netloc = f"{rendered}:{parsed.port}" if parsed.port is not None else rendered
    return urlunparse(parsed._replace(netloc=netloc))


def _host_header(hostname: str, explicit_port: int | None) -> str:
    rendered = f"[{hostname}]" if ":" in hostname else hostname
    return f"{rendered}:{explicit_port}" if explicit_port is not None else rendered
