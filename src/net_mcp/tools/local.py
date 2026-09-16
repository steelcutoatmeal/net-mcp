"""Local network diagnostic tools.

Runs standard CLI tools on the user's machine and returns structured output.
All commands are read-only diagnostics — nothing is modified.

Tools that may require elevated permissions (mtr) will attempt to run and
return a clear error message if permission is denied, rather than failing
silently.

Security: All inputs are passed as list arguments to subprocess (never
shell=True) to prevent command injection. Hostnames, IPs, DNS record types,
port specs and nmap targets are validated before use. Validation failures are
returned as ``CommandResult(success=False, error=...)`` rather than raised, so
the LLM always receives a structured answer it can act on.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import shlex
import shutil
import subprocess
from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from net_mcp import USER_AGENT
from net_mcp.config import get_config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# Hostnames, IPv4, IPv6 (optionally with a %zone) and CIDR prefixes. Spaces,
# shell metacharacters, commas, wildcards and underscores are all rejected.
_SAFE_HOST_RE = re.compile(r"[a-zA-Z0-9.\-:/%]+")

# DNS query names may additionally contain underscores (_dmarc, _sip._tcp,
# DKIM selectors) but never colons, slashes or zone IDs.
_SAFE_DNS_NAME_RE = re.compile(r"[a-zA-Z0-9._\-]+")

# dig treats any argument matching +option (case-insensitively) as an option,
# so a record type must be a bare alphanumeric mnemonic: A, AAAA, TYPE65 ...
_DNS_RECORD_TYPE_RE = re.compile(r"[A-Z0-9]{1,10}")

# RFC 1123 hostname: dot-separated labels of alphanumerics with inner hyphens.
_HOSTNAME_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?"
)

_PORT_NUMBER_RE = re.compile(r"[0-9]{1,5}")

# http(s) URL with no whitespace or shell metacharacters. Brackets and braces
# are allowed because curl runs with -g (no globbing).
_SAFE_URL_RE = re.compile(r"https?://[^\s;|&`$'\"\\]+", re.IGNORECASE)

# nmap expands a prefix into every address it contains and, with -Pn, probes
# each one. Cap blocks at 256 addresses so a scan can finish inside the timeout.
_NMAP_MIN_PREFIXLEN = {4: 24, 6: 120}

_CURL_MAX_OUTPUT = 10_000


def _validate_host(value: str) -> str:
    """Validate a hostname/IP input. Raises ValueError if suspicious.

    A surrounding ``[...]`` around an IPv6 literal is stripped, because ping,
    traceroute, dig and friends do not accept bracketed addresses.
    """
    value = value.strip()
    if len(value) >= 2 and value[0] == "[" and value[-1] == "]":
        value = value[1:-1]
    if not value or len(value) > 253:
        raise ValueError(f"Invalid host: {value!r}")
    # Reject leading '-' (and '/'): args are passed positionally, but a value
    # like '-oN/tmp/x' or '--script=...' would otherwise be parsed as a flag
    # by ping/traceroute/nmap/etc. A real hostname never starts with these.
    if value[0] in "-/":
        raise ValueError(
            f"Invalid host: {value!r} — must not begin with '-' or '/' "
            "(could be interpreted as a command-line flag)."
        )
    if not _SAFE_HOST_RE.fullmatch(value):
        raise ValueError(
            f"Invalid characters in host: {value!r}. Only alphanumerics, dots, "
            "hyphens, colons, slashes and '%' are allowed; an IPv6 literal may "
            "be wrapped in []."
        )
    return value


def _validate_dns_name(value: str) -> str:
    """Validate a DNS query name for dig/nslookup (underscores allowed)."""
    value = value.strip()
    if not value or len(value) > 253:
        raise ValueError(f"Invalid DNS name: {value!r}")
    if value[0] in "-/+@":
        raise ValueError(
            f"Invalid DNS name: {value!r} — must not begin with '-', '/', '+' or '@' "
            "(could be interpreted as a dig option)."
        )
    if not _SAFE_DNS_NAME_RE.fullmatch(value):
        raise ValueError(
            f"Invalid characters in DNS name: {value!r}. Only alphanumerics, dots, "
            "hyphens and underscores are allowed."
        )
    return value


def _validate_record_type(value: str) -> str:
    """Validate a DNS record type mnemonic (A, AAAA, MX, TYPE65 ...).

    dig parses ``+option`` and ``-x`` style arguments case-insensitively no
    matter where they appear, so anything other than 1-10 alphanumerics is
    rejected before it can reach the command line.
    """
    value = value.strip().upper()
    if not _DNS_RECORD_TYPE_RE.fullmatch(value):
        raise ValueError(
            f"Invalid DNS record type: {value!r}. Use a mnemonic such as A, AAAA, "
            "MX, NS, TXT, SOA or TYPE<n> for numeric types."
        )
    return value


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port must be 1-65535, got {port}")
    return port


def _validate_port_spec(spec: str) -> str:
    """Validate an nmap ``-p`` spec: comma-separated ports and ``lo-hi`` ranges.

    Every number is checked with ``_validate_port`` and ranges must ascend.
    Returns the spec with surrounding whitespace removed from each item.
    """
    parts = [p.strip() for p in spec.split(",")]
    if any(not p for p in parts):
        raise ValueError(
            f"Invalid port spec: {spec!r}. Use forms like '22,80,443' or '1-1024'."
        )
    for part in parts:
        lo, sep, hi = part.partition("-")
        if not _PORT_NUMBER_RE.fullmatch(lo) or (
            sep and not _PORT_NUMBER_RE.fullmatch(hi)
        ):
            raise ValueError(
                f"Invalid port spec: {spec!r}. Use forms like '22,80,443' or '1-1024'."
            )
        lo_n = _validate_port(int(lo))
        if sep and _validate_port(int(hi)) < lo_n:
            raise ValueError(f"Invalid port range {part!r}: end is lower than start.")
    return ",".join(parts)


def _validate_nmap_target(value: str) -> str:
    """Validate an nmap target: one IP, one hostname, or a small CIDR block.

    nmap's own target grammar also accepts octet ranges (10.0.0-255.1),
    wildcards (10.0.*.*) and comma lists, each of which can expand to
    millions of hosts. Those are rejected here, and CIDR prefixes are capped
    at /24 (IPv4) and /120 (IPv6), i.e. 256 addresses.
    """
    value = _validate_host(value)
    host, slash, _ = value.partition("/")
    if slash:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR target: {value!r}") from None
        min_len = _NMAP_MIN_PREFIXLEN[net.version]
        if net.prefixlen < min_len:
            raise ValueError(
                f"Prefix {value!r} is too large to scan: targets are capped at "
                f"/{min_len} for IPv{net.version} (256 addresses). Scan smaller "
                "blocks separately."
            )
        return value
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return value
    # Not an IP literal, so it must be a plain hostname. nmap reads an
    # all-numeric string containing '-' as an octet range, so require a letter.
    if not _HOSTNAME_RE.fullmatch(host) or not re.search(r"[a-zA-Z]", host):
        raise ValueError(
            f"Invalid nmap target: {value!r}. Give a single IP address, a hostname, "
            "or a CIDR prefix no larger than /24 (IPv4) or /120 (IPv6). Octet "
            "ranges such as 10.0.0-255.1, wildcards and comma-separated lists "
            "are not allowed."
        )
    return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IS_MACOS = platform.system() == "Darwin"
_IS_LINUX = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"


def _as_text(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr).

    Never uses shell=True. Returns a clear message if the command is not
    found, times out (partial stdout is preserved) or permission is denied.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0])
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        logger.warning("Command timed out after %ss: %s", timeout, shlex.join(cmd))
        partial = _as_text(exc.stdout)
        msg = f"Command timed out after {timeout}s"
        if partial:
            msg += " (partial output returned in stdout)"
        return 124, partial, msg
    except PermissionError:
        logger.warning("Permission denied running %s", cmd[0])
        return (
            126,
            "",
            f"Permission denied running {cmd[0]}. This command may require admin/sudo.",
        )


def _find_cmd(*names: str) -> str | None:
    """Find the first available command from a list of candidates."""
    for name in names:
        if shutil.which(name):
            return name
    return None


# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


class CommandResult(BaseModel):
    command: str = Field(
        description=(
            "The exact command line that was executed, or the tool name if the "
            "command never ran"
        )
    )
    returncode: int = Field(
        description=(
            "Process exit status. 0 = success; 2 = input rejected before running; "
            "124 = timed out; 126 = disabled by config or permission denied; "
            "127 = binary not found"
        )
    )
    stdout: str = Field(
        description="Standard output of the command (curl output is capped at 10,000 characters)"
    )
    stderr: str = Field(
        description=(
            "Standard error of the command, or the failure message when the "
            "command did not run"
        )
    )
    success: bool = Field(
        description="True when the command ran and exited with status 0"
    )
    platform: str = Field(
        description="Operating system the command ran on (Darwin, Linux or Windows)"
    )
    error: str = Field(
        default="",
        description=(
            "Why the tool could not produce a result: input validation failure, "
            "tool disabled by configuration, binary not installed, or no service "
            "answered. Empty when the command executed."
        ),
    )
    note: str = Field(default="", description="Additional context about the result")


def _not_run(
    command: str, message: str, *, returncode: int = 2, note: str = ""
) -> CommandResult:
    """Result for a tool that could not run its command.

    The message is mirrored into ``stderr`` for callers that only look there.
    """
    return CommandResult(
        command=command,
        returncode=returncode,
        stdout="",
        stderr=message,
        success=False,
        platform=platform.system(),
        error=message,
        note=note,
    )


def _completed(
    cmd: list[str], rc: int, out: str, err: str, *, note: str = ""
) -> CommandResult:
    """Result for a command that was actually executed."""
    return CommandResult(
        command=shlex.join(cmd),
        returncode=rc,
        stdout=out,
        stderr=err,
        success=rc == 0,
        platform=platform.system(),
        note=note,
    )


def _disabled_result(tool: str) -> CommandResult:
    """Result returned when an active local tool is disabled by config."""
    return _not_run(
        tool,
        (
            f"{tool} is disabled. It can scan or fetch arbitrary network "
            "targets from this host, so it is off by default. To enable it, "
            "set allow_active_tools = true under [local] in config.toml, or "
            "set the NET_MCP_ALLOW_ACTIVE_LOCAL_TOOLS=1 environment variable."
        ),
        returncode=126,
        note="Active local tool disabled by configuration.",
    )


def _missing_result(tool: str, hint: str) -> CommandResult:
    """Result returned when a required binary is not installed."""
    return _not_run(tool, f"{tool} not found. {hint}", returncode=127)


_STATE_KEYWORDS = {
    "listen": {"LISTEN", "LISTENING"},
    "established": {"ESTABLISHED"},
}


def _filter_connection_lines(output: str, state: str) -> str:
    """Keep only socket lines in the requested state, plus column headers.

    Used where netstat has no state filter. Recognises the state column of
    netstat on macOS/BSD (LISTEN), Windows (LISTENING) and Linux.
    """
    wanted = _STATE_KEYWORDS.get(state)
    if not wanted:
        return output
    kept: list[str] = []
    for line in output.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        is_header = tokens[0] in ("Active", "Proto")
        is_socket = tokens[0].lower().startswith(("tcp", "udp"))
        if is_header or (
            is_socket and any(tok.upper() in wanted for tok in tokens[1:])
        ):
            kept.append(line)
    return "\n".join(kept) + ("\n" if kept else "")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_local_tools(mcp: FastMCP) -> None:
    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_ping(
        host: Annotated[
            str,
            Field(
                description="Hostname or IP address to ping (an IPv6 literal may be bracketed)"
            ),
        ],
        count: Annotated[
            int,
            Field(ge=1, le=100, description="Number of echo requests to send (1-100)"),
        ] = 4,
        timeout: Annotated[
            int, Field(ge=1, le=30, description="Seconds to wait for each reply (1-30)")
        ] = 5,
    ) -> CommandResult:
        """Ping a host from the local machine.

        Sends ICMP echo requests and reports round-trip time, packet loss,
        and latency statistics. Does not require admin privileges. Invalid
        hosts are reported in the result's error field rather than raised.
        """
        try:
            host = _validate_host(host)
        except ValueError as exc:
            return _not_run("ping", str(exc))

        if _IS_WINDOWS:
            # Windows ping: -w is the per-reply timeout in milliseconds.
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
        elif _IS_MACOS:
            # macOS/BSD ping: -W is the per-packet wait in MILLISECONDS. Passing
            # seconds here (e.g. -W 5) waits only 5ms, so any reply slower than
            # that is reported as "out of wait time" / lost.
            cmd = ["ping", "-c", str(count), "-W", str(timeout * 1000), host]
        else:
            # Linux iputils ping: -W is the per-packet wait in SECONDS.
            cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

        rc, out, err = _run(cmd, timeout=count * timeout + 10)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_traceroute(
        host: Annotated[
            str,
            Field(
                description="Hostname or IP address to trace (an IPv6 literal may be bracketed)"
            ),
        ],
        max_hops: Annotated[
            int, Field(ge=1, le=64, description="Maximum number of hops (1-64)")
        ] = 30,
    ) -> CommandResult:
        """Trace the network path to a host from the local machine.

        Shows each hop along the route with latency. Uses UDP probes by
        default (no admin required). On macOS/Linux uses traceroute,
        on Windows uses tracert. If the trace exceeds its time budget the
        partial output collected so far is returned with returncode 124.
        """
        try:
            host = _validate_host(host)
        except ValueError as exc:
            return _not_run("traceroute", str(exc))

        if _IS_WINDOWS:
            cmd = ["tracert", "-h", str(max_hops), host]
        else:
            tr = _find_cmd("traceroute")
            if not tr:
                return _missing_result(
                    "traceroute",
                    "Install with: brew install traceroute (macOS) or "
                    "apt install traceroute (Linux)",
                )
            cmd = [tr, "-m", str(max_hops), host]

        rc, out, err = _run(cmd, timeout=max_hops * 5)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_mtr(
        host: Annotated[
            str,
            Field(
                description="Hostname or IP address (an IPv6 literal may be bracketed)"
            ),
        ],
        count: Annotated[
            int, Field(ge=1, le=100, description="Number of pings per hop (1-100)")
        ] = 10,
    ) -> CommandResult:
        """Run mtr (My Traceroute) combining ping and traceroute.

        Shows per-hop packet loss and latency statistics. Requires mtr
        to be installed. May require admin/sudo for raw ICMP sockets
        on some systems — if permission is denied, the error will say so.
        """
        try:
            host = _validate_host(host)
        except ValueError as exc:
            return _not_run("mtr", str(exc))

        mtr = _find_cmd("mtr")
        if not mtr:
            return _missing_result(
                "mtr",
                "Install with: brew install mtr (macOS) or apt install mtr (Linux)",
            )

        # --report mode produces text output and exits after `count` cycles.
        cmd = [mtr, "--report", "--report-cycles", str(count), host]

        rc, out, err = _run(cmd, timeout=count * 5 + 30)

        note = ""
        if rc != 0 and (
            "permission" in err.lower() or "operation not permitted" in err.lower()
        ):
            note = (
                "mtr requires raw socket access. Try: sudo mtr or run net-mcp "
                "with elevated permissions."
            )

        return _completed(cmd, rc, out, err, note=note)

    @mcp.tool(tags={"local", "network", "dns"})
    def local_dig(
        name: Annotated[
            str,
            Field(
                description="Domain name to query (underscore labels such as _dmarc.example.com are allowed)"
            ),
        ],
        record_type: Annotated[
            str,
            Field(
                description="DNS record type mnemonic: A, AAAA, MX, NS, TXT, SOA, ... or TYPE<n>"
            ),
        ] = "A",
        server: Annotated[
            str | None,
            Field(
                description="DNS server to query (e.g. '8.8.8.8'). None uses system default."
            ),
        ] = None,
        short: Annotated[
            bool, Field(description="Short output (just the answer, no headers)")
        ] = False,
    ) -> CommandResult:
        """Run dig on the local machine for DNS lookups.

        Unlike dns_lookup (which uses dnspython), this runs the actual dig
        binary and returns raw output including query time, server used,
        and all sections. Useful for seeing exactly what a real resolver
        returns. Falls back to nslookup when dig is not installed. Does not
        require admin privileges.

        record_type must be a bare mnemonic (1-10 letters/digits); dig
        options such as '+trace' or '-x' are rejected and reported in the
        result's error field.
        """
        try:
            name = _validate_dns_name(name)
            record_type = _validate_record_type(record_type)
            if server:
                server = _validate_host(server.strip().lstrip("@"))
        except ValueError as exc:
            return _not_run("dig", str(exc))

        dig = _find_cmd("dig")
        if not dig:
            return _nslookup_fallback(name, record_type, server)

        cmd = [dig, name, record_type]
        if server:
            cmd.append(f"@{server}")
        if short:
            cmd.append("+short")

        rc, out, err = _run(cmd, timeout=15)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_interfaces() -> CommandResult:
        """Show network interfaces and their IP addresses on the local machine.

        Returns interface names, IP addresses, subnet masks, and status.
        Uses ifconfig on macOS, ip addr on Linux, ipconfig on Windows.
        Does not require admin privileges.
        """
        if _IS_WINDOWS:
            cmd = ["ipconfig", "/all"]
        elif _IS_LINUX:
            ip_cmd = _find_cmd("ip")
            cmd = [ip_cmd, "-c", "addr"] if ip_cmd else ["ifconfig", "-a"]
        else:
            cmd = ["ifconfig"]

        rc, out, err = _run(cmd, timeout=10)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_routes() -> CommandResult:
        """Show the local routing table.

        Displays all routes including default gateway, connected networks,
        and static routes. Uses netstat -rn on macOS, ip route on Linux,
        route print on Windows. Does not require admin privileges.
        """
        if _IS_WINDOWS:
            cmd = ["route", "print"]
        elif _IS_LINUX:
            ip_cmd = _find_cmd("ip")
            cmd = [ip_cmd, "route"] if ip_cmd else ["netstat", "-rn"]
        else:
            cmd = ["netstat", "-rn"]

        rc, out, err = _run(cmd, timeout=10)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_connections(
        state: Annotated[
            Literal["all", "listen", "established"],
            Field(
                description=(
                    "Which sockets to show: 'all' (default), 'listen' (listening "
                    "TCP ports only) or 'established' (connected TCP sessions only)."
                )
            ),
        ] = "all",
    ) -> CommandResult:
        """Show active network connections and listening ports.

        Displays TCP/UDP sockets with local/remote addresses and state.
        Uses ss on Linux (netstat as a fallback) and netstat on macOS and
        Windows. ss filters by state natively; netstat on macOS, Windows and
        older Linux has no state filter, so for 'listen' and 'established'
        this tool filters the output lines itself after the command runs and
        says so in the note field. Does not require admin privileges (PIDs
        may require admin).
        """
        filtered = state != "all"
        if _IS_WINDOWS:
            cmd = ["netstat", "-an"]
        elif _IS_LINUX:
            ss = _find_cmd("ss")
            if ss:
                filtered = False
                if state == "listen":
                    cmd = [ss, "-tlnp"]
                elif state == "established":
                    cmd = [ss, "-tnp", "state", "established"]
                else:
                    cmd = [ss, "-tunap"]
            else:
                cmd = ["netstat", "-tunap"]
        else:
            # macOS/BSD: -p tcp restricts to TCP sockets; there is no state flag.
            cmd = ["netstat", "-an", "-p", "tcp"] if filtered else ["netstat", "-an"]

        rc, out, err = _run(cmd, timeout=15)

        notes: list[str] = []
        if filtered and rc == 0:
            out = _filter_connection_lines(out, state)
            notes.append(
                f"netstat cannot filter by state on {platform.system()}; output "
                f"lines were filtered to '{state}' sockets by net-mcp."
            )
        if "permission" in err.lower():
            notes.append("Some connection details (PIDs) require admin privileges.")

        return _completed(cmd, rc, out, err, note=" ".join(notes))

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_arp() -> CommandResult:
        """Show the ARP table (IP-to-MAC address mappings).

        Displays cached ARP entries for the local network. Useful for
        seeing what hosts are on the same L2 segment.
        Does not require admin privileges.
        """
        if _IS_WINDOWS:
            cmd = ["arp", "-a"]
        elif _IS_LINUX:
            ip_cmd = _find_cmd("ip")
            cmd = [ip_cmd, "neigh"] if ip_cmd else ["arp", "-a"]
        else:
            cmd = ["arp", "-a"]

        rc, out, err = _run(cmd, timeout=10)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network"})
    def local_whois(
        query: Annotated[
            str,
            Field(
                description="Domain, IP address, or ASN (e.g. 'cloudflare.com', '1.1.1.1', 'AS13335')"
            ),
        ],
    ) -> CommandResult:
        """Run a whois lookup from the local machine.

        Queries the appropriate whois server for domain registration,
        IP allocation, or ASN information. Does not require admin privileges.
        """
        try:
            query = _validate_host(query)
        except ValueError as exc:
            return _not_run("whois", str(exc))

        whois = _find_cmd("whois")
        if not whois:
            return _missing_result(
                "whois",
                "Install with: brew install whois (macOS) or apt install whois (Linux)",
            )

        cmd = [whois, query]
        rc, out, err = _run(cmd, timeout=30)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_curl(
        url: Annotated[
            str,
            Field(
                description="URL to fetch (e.g. 'https://example.com'). https:// is assumed when no scheme is given."
            ),
        ],
        head_only: Annotated[
            bool, Field(description="Only fetch headers, not body")
        ] = False,
        follow_redirects: Annotated[
            bool, Field(description="Follow HTTP redirects (at most 5)")
        ] = True,
        timeout: Annotated[
            int, Field(ge=1, le=120, description="Request timeout in seconds (1-120)")
        ] = 15,
    ) -> CommandResult:
        """Make an HTTP request from the local machine using curl.

        Useful for testing connectivity, checking HTTP headers, TLS
        certificates, and response codes from the local network perspective.
        Output is capped at 10,000 characters (the note field says when it
        was truncated). Does not require admin privileges.

        curl runs with -q (ignores ~/.curlrc) and -g (no URL globbing, so
        brackets and braces in the URL are literal and cannot fan out into
        many requests). Only http:// and https:// URLs are accepted.

        Disabled by default. When enabled via allow_active_tools this tool
        deliberately does NOT block private, loopback, link-local or cloud
        metadata addresses (for example 127.0.0.1, 10.0.0.0/8 or
        169.254.169.254): reaching internal endpoints from this host is part
        of its purpose as a local diagnostic, and operators who enable it
        accept that trade-off.
        """
        if not get_config().allow_active_local_tools:
            return _disabled_result("curl")

        url = url.strip()
        scheme = re.match(r"([a-z][a-z0-9+.\-]*)://", url, re.IGNORECASE)
        if scheme is None:
            url = f"https://{url}"
        elif scheme.group(1).lower() not in ("http", "https"):
            return _not_run(
                "curl",
                f"Unsupported URL scheme {scheme.group(1)!r}: only http:// and "
                "https:// URLs are accepted.",
            )
        if not _SAFE_URL_RE.fullmatch(url):
            return _not_run(
                "curl",
                f"Invalid URL: {url!r}. Only http(s) URLs without whitespace or "
                "shell metacharacters are accepted.",
            )

        curl = _find_cmd("curl")
        if not curl:
            return _missing_result("curl", "Install curl and make sure it is on PATH.")

        # -q must be the FIRST argument for curl to skip ~/.curlrc.
        cmd = [curl, "-q", "-g", "-s", "-S", "--max-time", str(timeout)]
        cmd.append("-I" if head_only else "-i")  # -i includes headers with body
        if follow_redirects:
            cmd.extend(["-L", "--max-redirs", "5"])
        cmd.append(url)

        rc, out, err = _run(cmd, timeout=timeout + 5)
        note = ""
        if len(out) > _CURL_MAX_OUTPUT:
            out = out[:_CURL_MAX_OUTPUT]
            note = f"stdout truncated to {_CURL_MAX_OUTPUT} characters."
        return _completed(cmd, rc, out, err, note=note)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_nmap(
        target: Annotated[
            str,
            Field(
                description="One IP address, one hostname, or a CIDR block of at most /24 (IPv4) or /120 (IPv6)"
            ),
        ],
        ports: Annotated[
            str | None,
            Field(
                description="Port spec: comma-separated ports and/or ranges, e.g. '22,80,443' or '1-1024'. Default scans nmap's top 1000 ports."
            ),
        ] = None,
    ) -> CommandResult:
        """Run an nmap TCP connect scan on a target.

        Uses TCP connect scan (-sT, no admin needed) with host discovery
        skipped (-Pn) and reports only open ports. SYN scans and OS
        detection require root and are not used. Nmap must be installed
        separately.

        Targets are limited to one host or a CIDR block of at most 256
        addresses (/24 for IPv4, /120 for IPv6): with -Pn nmap probes every
        address in the block, so a larger prefix would exhaust the 120 s
        time budget without finishing. nmap's octet-range (10.0.0-255.1),
        wildcard and comma-list target syntax is rejected for the same
        reason; scan several small blocks instead. Rejected inputs are
        reported in the result's error field.

        Disabled by default (it can scan arbitrary internal hosts from this
        machine). Enable via allow_active_tools in config.
        """
        if not get_config().allow_active_local_tools:
            return _disabled_result("nmap")

        try:
            target = _validate_nmap_target(target)
            if ports:
                ports = _validate_port_spec(ports)
        except ValueError as exc:
            return _not_run("nmap", str(exc))

        nmap = _find_cmd("nmap")
        if not nmap:
            return _missing_result(
                "nmap",
                "Install with: brew install nmap (macOS) or apt install nmap (Linux)",
            )

        # -sT = TCP connect scan (no root needed)
        # -Pn = skip host discovery (just scan ports)
        cmd = [nmap, "-sT", "-Pn", "--open"]
        if ":" in target:  # IPv6 literal or prefix; hostnames never contain ':'
            cmd.append("-6")
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)

        rc, out, err = _run(cmd, timeout=120)

        note = ""
        if "root" in err.lower() or "permission" in err.lower():
            note = (
                "Some nmap features require admin. TCP connect scan (-sT) should "
                "work without it."
            )

        return _completed(cmd, rc, out, err, note=note)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_netstat_stats() -> CommandResult:
        """Show network protocol statistics (TCP, UDP, ICMP counters).

        Displays packet counts, error rates, retransmissions, and other
        protocol-level statistics. Useful for diagnosing network health issues.
        Does not require admin privileges.
        """
        if _IS_WINDOWS:
            cmd = ["netstat", "-s"]
        elif _IS_LINUX:
            ss = _find_cmd("ss")
            cmd = [ss, "-s"] if ss else ["netstat", "-s"]
        else:
            cmd = ["netstat", "-s"]

        rc, out, err = _run(cmd, timeout=10)
        return _completed(cmd, rc, out, err)

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_public_ip() -> CommandResult:
        """Get the public IP address of the local machine.

        Queries external services (ifconfig.me, ipify, icanhazip) in turn
        until one answers, identifying itself with the net-mcp User-Agent.
        Useful for verifying NAT, VPN, or proxy configuration.
        Does not require admin privileges.
        """
        curl = _find_cmd("curl")
        if not curl:
            return _missing_result("curl", "Install curl and make sure it is on PATH.")

        # Try multiple services in case one is down.
        services = [
            "https://ifconfig.me/ip",
            "https://api.ipify.org",
            "https://icanhazip.com",
        ]
        for service in services:
            cmd = [curl, "-q", "-s", "-A", USER_AGENT, "--max-time", "5", service]
            rc, out, err = _run(cmd, timeout=10)
            if rc == 0 and out.strip():
                return _completed(cmd, 0, out.strip(), "")
            logger.warning(
                "Public IP lookup via %s failed (rc=%s): %s", service, rc, err.strip()
            )

        return _not_run(
            "public IP lookup",
            "Could not determine public IP from any service",
            returncode=1,
        )


# ---------------------------------------------------------------------------
# Fallback helpers
# ---------------------------------------------------------------------------


def _nslookup_fallback(
    name: str, record_type: str, server: str | None
) -> CommandResult:
    """Fall back to nslookup when dig is not available.

    ``name``, ``record_type`` and ``server`` must already be validated.
    """
    nslookup = _find_cmd("nslookup")
    if not nslookup:
        return _missing_result("dig/nslookup", "Neither dig nor nslookup is installed.")

    logger.warning("dig not found; falling back to nslookup")
    cmd = [nslookup, f"-type={record_type}", name]
    if server:
        cmd.append(server)

    rc, out, err = _run(cmd, timeout=15)
    return _completed(cmd, rc, out, err, note="dig not found, fell back to nslookup")
