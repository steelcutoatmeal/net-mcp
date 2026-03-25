"""Local network diagnostic tools.

Runs standard CLI tools on the user's machine and returns structured output.
All commands are read-only diagnostics — nothing is modified.

Tools that may require elevated permissions (mtr) will attempt to run and
return a clear error message if permission is denied, rather than failing
silently.

Security: All inputs are passed as list arguments to subprocess (never
shell=True) to prevent command injection. Hostnames and IPs are validated
before use.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from typing import Annotated

from fastmcp import FastMCP
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# Allow hostnames, IPv4, IPv6, and CIDR prefixes. Reject anything suspicious.
_SAFE_HOST_RE = re.compile(
    r"^[a-zA-Z0-9.\-:/%\[\]]+$"
)


def _validate_host(value: str) -> str:
    """Validate a hostname/IP input. Raises ValueError if suspicious."""
    value = value.strip()
    if not value or len(value) > 253:
        raise ValueError(f"Invalid host: {value!r}")
    if not _SAFE_HOST_RE.match(value):
        raise ValueError(
            f"Invalid characters in host: {value!r}. "
            "Only alphanumeric, dots, hyphens, colons, slashes, and brackets allowed."
        )
    return value


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port must be 1-65535, got {port}")
    return port


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IS_MACOS = platform.system() == "Darwin"
_IS_LINUX = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"


def _run(
    cmd: list[str], timeout: int = 30
) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr).

    Never uses shell=True. Returns a clear message if the command
    is not found or permission is denied.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out after {timeout}s"
    except PermissionError:
        return 126, "", f"Permission denied running {cmd[0]}. This command may require admin/sudo."


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
    command: str = Field(description="The exact command that was executed")
    returncode: int
    stdout: str
    stderr: str
    success: bool
    platform: str
    note: str = Field(default="", description="Additional context about the result")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_local_tools(mcp: FastMCP) -> None:

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_ping(
        host: Annotated[str, Field(description="Hostname or IP address to ping")],
        count: Annotated[int, Field(description="Number of pings to send")] = 4,
        timeout: Annotated[int, Field(description="Timeout per ping in seconds")] = 5,
    ) -> CommandResult:
        """Ping a host from the local machine.

        Sends ICMP echo requests and reports round-trip time, packet loss,
        and latency statistics. Does not require admin privileges.
        """
        host = _validate_host(host)
        count = min(count, 100)  # cap to prevent abuse

        if _IS_WINDOWS:
            cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout), host]

        rc, out, err = _run(cmd, timeout=count * timeout + 10)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_traceroute(
        host: Annotated[str, Field(description="Hostname or IP address to trace")],
        max_hops: Annotated[int, Field(description="Maximum number of hops")] = 30,
    ) -> CommandResult:
        """Trace the network path to a host from the local machine.

        Shows each hop along the route with latency. Uses UDP probes by
        default (no admin required). On macOS/Linux uses traceroute,
        on Windows uses tracert.
        """
        host = _validate_host(host)
        max_hops = min(max_hops, 64)

        if _IS_WINDOWS:
            cmd = ["tracert", "-h", str(max_hops), host]
        else:
            tr = _find_cmd("traceroute")
            if not tr:
                return CommandResult(
                    command="traceroute",
                    returncode=127,
                    stdout="",
                    stderr="traceroute not found. Install with: brew install traceroute (macOS) or apt install traceroute (Linux)",
                    success=False,
                    platform=platform.system(),
                )
            cmd = [tr, "-m", str(max_hops), host]

        rc, out, err = _run(cmd, timeout=max_hops * 5)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_mtr(
        host: Annotated[str, Field(description="Hostname or IP address")],
        count: Annotated[int, Field(description="Number of pings per hop")] = 10,
    ) -> CommandResult:
        """Run mtr (My Traceroute) combining ping and traceroute.

        Shows per-hop packet loss and latency statistics. Requires mtr
        to be installed. May require admin/sudo for raw ICMP sockets
        on some systems — if permission is denied, the error will say so.
        """
        host = _validate_host(host)
        count = min(count, 100)

        mtr = _find_cmd("mtr")
        if not mtr:
            return CommandResult(
                command="mtr",
                returncode=127,
                stdout="",
                stderr="mtr not found. Install with: brew install mtr (macOS) or apt install mtr (Linux)",
                success=False,
                platform=platform.system(),
            )

        # --report mode produces text output and exits
        # --no-dns avoids slow reverse lookups unless user wants them
        cmd = [mtr, "--report", "--report-cycles", str(count), host]

        rc, out, err = _run(cmd, timeout=count * 5 + 30)

        note = ""
        if rc != 0 and ("permission" in err.lower() or "operation not permitted" in err.lower()):
            note = "mtr requires raw socket access. Try: sudo mtr or run net-mcp with elevated permissions."

        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
            note=note,
        )

    @mcp.tool(tags={"local", "network", "dns"})
    def local_dig(
        name: Annotated[str, Field(description="Domain name to query")],
        record_type: Annotated[str, Field(description="DNS record type (A, AAAA, MX, NS, TXT, SOA, etc.)")] = "A",
        server: Annotated[
            str | None,
            Field(description="DNS server to query (e.g. '8.8.8.8'). None uses system default."),
        ] = None,
        short: Annotated[bool, Field(description="Short output (just the answer, no headers)")] = False,
    ) -> CommandResult:
        """Run dig on the local machine for DNS lookups.

        Unlike dns_lookup (which uses dnspython), this runs the actual dig
        binary and returns raw output including query time, server used,
        and all sections. Useful for seeing exactly what a real resolver returns.
        Does not require admin privileges.
        """
        name = _validate_host(name)
        record_type = record_type.upper().strip()

        dig = _find_cmd("dig")
        if not dig:
            # Fall back to nslookup
            return _nslookup_fallback(name, record_type, server)

        cmd = [dig, name, record_type]
        if server:
            server = _validate_host(server)
            cmd.append(f"@{server}")
        if short:
            cmd.append("+short")

        rc, out, err = _run(cmd, timeout=15)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

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
            if ip_cmd:
                cmd = [ip_cmd, "-c", "addr"]
            else:
                cmd = ["ifconfig", "-a"]
        else:
            cmd = ["ifconfig"]

        rc, out, err = _run(cmd, timeout=10)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

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
            if ip_cmd:
                cmd = [ip_cmd, "route"]
            else:
                cmd = ["netstat", "-rn"]
        else:
            # macOS
            cmd = ["netstat", "-rn"]

        rc, out, err = _run(cmd, timeout=10)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_connections(
        state: Annotated[
            str | None,
            Field(description="Filter by state: 'listen', 'established', 'all'. Default is 'all'."),
        ] = "all",
    ) -> CommandResult:
        """Show active network connections and listening ports.

        Displays TCP/UDP connections with local/remote addresses and state.
        Uses netstat on macOS, ss on Linux, netstat on Windows.
        Does not require admin privileges (PIDs may require admin).
        """
        if _IS_WINDOWS:
            cmd = ["netstat", "-an"]
        elif _IS_LINUX:
            ss = _find_cmd("ss")
            if ss:
                flags = "-tunap"
                if state == "listen":
                    flags = "-tlnp"
                elif state == "established":
                    flags = "-tnp"
                cmd = [ss, flags]
            else:
                cmd = ["netstat", "-tunap"]
        else:
            # macOS
            if state == "listen":
                cmd = ["netstat", "-an", "-p", "tcp"]
            else:
                cmd = ["netstat", "-an"]

        rc, out, err = _run(cmd, timeout=15)

        note = ""
        if "permission" in err.lower():
            note = "Some connection details (PIDs) require admin privileges."

        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
            note=note,
        )

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
            if ip_cmd:
                cmd = [ip_cmd, "neigh"]
            else:
                cmd = ["arp", "-a"]
        else:
            cmd = ["arp", "-a"]

        rc, out, err = _run(cmd, timeout=10)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network"})
    def local_whois(
        query: Annotated[
            str,
            Field(description="Domain, IP address, or ASN (e.g. 'cloudflare.com', '1.1.1.1', 'AS13335')"),
        ],
    ) -> CommandResult:
        """Run a whois lookup from the local machine.

        Queries the appropriate whois server for domain registration,
        IP allocation, or ASN information. Does not require admin privileges.
        """
        query = _validate_host(query)

        whois = _find_cmd("whois")
        if not whois:
            return CommandResult(
                command="whois",
                returncode=127,
                stdout="",
                stderr="whois not found. Install with: brew install whois (macOS) or apt install whois (Linux)",
                success=False,
                platform=platform.system(),
            )

        cmd = [whois, query]
        rc, out, err = _run(cmd, timeout=30)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_curl(
        url: Annotated[str, Field(description="URL to fetch (e.g. 'https://example.com')")],
        head_only: Annotated[bool, Field(description="Only fetch headers, not body")] = False,
        follow_redirects: Annotated[bool, Field(description="Follow HTTP redirects")] = True,
        timeout: Annotated[int, Field(description="Request timeout in seconds")] = 15,
    ) -> CommandResult:
        """Make an HTTP request from the local machine using curl.

        Useful for testing connectivity, checking HTTP headers, TLS
        certificates, and response codes from the local network perspective.
        Does not require admin privileges.
        """
        # Validate URL has a scheme
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Basic URL validation - no spaces, no shell metacharacters
        if not re.match(r'^https?://[^\s;|&`$]+$', url):
            raise ValueError(f"Invalid URL: {url!r}")

        curl = _find_cmd("curl")
        if not curl:
            return CommandResult(
                command="curl",
                returncode=127,
                stdout="",
                stderr="curl not found",
                success=False,
                platform=platform.system(),
            )

        cmd = [curl, "-s", "-S", "--max-time", str(timeout)]
        if head_only:
            cmd.extend(["-I"])
        else:
            cmd.extend(["-i"])  # include headers with body
        if follow_redirects:
            cmd.extend(["-L", "--max-redirs", "5"])
        cmd.append(url)

        rc, out, err = _run(cmd, timeout=timeout + 5)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out[:10000],  # cap output to prevent massive responses
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_nmap(
        target: Annotated[str, Field(description="Host or IP to scan")],
        ports: Annotated[
            str | None,
            Field(description="Port spec (e.g. '22,80,443' or '1-1024'). Default scans common ports."),
        ] = None,
    ) -> CommandResult:
        """Run an nmap TCP connect scan on a target.

        Uses TCP connect scan (-sT) which does NOT require admin privileges.
        SYN scans and OS detection require root and are not used here.
        Nmap must be installed separately.
        """
        target = _validate_host(target)

        nmap = _find_cmd("nmap")
        if not nmap:
            return CommandResult(
                command="nmap",
                returncode=127,
                stdout="",
                stderr="nmap not found. Install with: brew install nmap (macOS) or apt install nmap (Linux)",
                success=False,
                platform=platform.system(),
            )

        # -sT = TCP connect scan (no root needed)
        # -Pn = skip host discovery (just scan ports)
        cmd = [nmap, "-sT", "-Pn", "--open"]
        if ports:
            # Validate port spec: only digits, commas, hyphens
            if not re.match(r'^[\d,\-]+$', ports):
                raise ValueError(f"Invalid port spec: {ports!r}")
            cmd.extend(["-p", ports])
        cmd.append(target)

        rc, out, err = _run(cmd, timeout=120)

        note = ""
        if "root" in err.lower() or "permission" in err.lower():
            note = "Some nmap features require admin. TCP connect scan (-sT) should work without it."

        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
            note=note,
        )

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
            if ss:
                cmd = [ss, "-s"]
            else:
                cmd = ["netstat", "-s"]
        else:
            # macOS
            cmd = ["netstat", "-s"]

        rc, out, err = _run(cmd, timeout=10)
        return CommandResult(
            command=" ".join(cmd),
            returncode=rc,
            stdout=out,
            stderr=err,
            success=rc == 0,
            platform=platform.system(),
        )

    @mcp.tool(tags={"local", "network", "diagnostic"})
    def local_public_ip() -> CommandResult:
        """Get the public IP address of the local machine.

        Queries external services to determine the public-facing IP.
        Useful for verifying NAT, VPN, or proxy configuration.
        Does not require admin privileges.
        """
        # Try multiple services in case one is down
        services = [
            ["curl", "-s", "--max-time", "5", "https://ifconfig.me"],
            ["curl", "-s", "--max-time", "5", "https://api.ipify.org"],
            ["curl", "-s", "--max-time", "5", "https://icanhazip.com"],
        ]

        curl = _find_cmd("curl")
        if not curl:
            return CommandResult(
                command="curl",
                returncode=127,
                stdout="",
                stderr="curl not found",
                success=False,
                platform=platform.system(),
            )

        for cmd in services:
            rc, out, err = _run(cmd, timeout=10)
            if rc == 0 and out.strip():
                return CommandResult(
                    command=" ".join(cmd),
                    returncode=0,
                    stdout=out.strip(),
                    stderr="",
                    success=True,
                    platform=platform.system(),
                )

        return CommandResult(
            command="public IP lookup",
            returncode=1,
            stdout="",
            stderr="Could not determine public IP from any service",
            success=False,
            platform=platform.system(),
        )


# ---------------------------------------------------------------------------
# Fallback helpers
# ---------------------------------------------------------------------------


def _nslookup_fallback(name: str, record_type: str, server: str | None) -> CommandResult:
    """Fall back to nslookup when dig is not available."""
    nslookup = _find_cmd("nslookup")
    if not nslookup:
        return CommandResult(
            command="dig/nslookup",
            returncode=127,
            stdout="",
            stderr="Neither dig nor nslookup found",
            success=False,
            platform=platform.system(),
        )

    cmd = [nslookup, f"-type={record_type}", name]
    if server:
        cmd.append(_validate_host(server))

    rc, out, err = _run(cmd, timeout=15)
    return CommandResult(
        command=" ".join(cmd),
        returncode=rc,
        stdout=out,
        stderr=err,
        success=rc == 0,
        platform=platform.system(),
        note="dig not found, fell back to nslookup",
    )
