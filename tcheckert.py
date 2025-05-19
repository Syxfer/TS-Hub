import asyncio
import socket
import ssl
import aiohttp
from aiohttp import ClientSession
from urllib.parse import urlparse
import certifi
import json
from typing import List, Dict, Any
import requests
import threading
import time

async def _fetch(session: ClientSession, url: str, method: str = 'GET', data: Any = None, headers: Dict[str, str] = None, timeout: int = 10) -> tuple[int, Dict[str, str], str]:
    """Fetches content from a URL with error handling and timeout."""
    try:
        async with session.request(method, url, data=data, headers=headers, timeout=timeout, ssl=False) as response:
            return response.status, response.headers, await response.text(errors='ignore')
    except aiohttp.ClientError as e:
        return -1, {}, f"Client error: {e}"
    except asyncio.TimeoutError:
        return -2, {}, "Request timed out"

async def _check_ssl_tls(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Checks SSL/TLS configuration for a given hostname and port."""
    results = {"ssl_found": False, "weak_version": None, "certificate": None, "cipher": None, "error": None}
    try:
        context = ssl.create_default_context()
        context.set_ciphers('DEFAULT')
        transport = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transport.settimeout(5)
        await asyncio.get_running_loop().sock_connect(transport, (hostname, port))
        secure_transport = context.wrap_socket(transport, server_hostname=hostname)
        results["ssl_found"] = True
        cert = secure_transport.getpeercert()
        results["certificate"] = {
            "subject": dict(item[0] for item in cert.get('subject', [])),
            "issuer": dict(item[0] for item in cert.get('issuer', [])),
            "not_before": cert.get('notBefore'),
            "not_after": cert.get('notAfter'),
            "serial_number": cert.get('serialNumber')
        }
        version = secure_transport.version()
        if version in ("TLSv1", "TLSv1.1"):
            results["weak_version"] = version
        results["cipher"] = secure_transport.cipher()
        secure_transport.close()
    except (socket.error, ssl.SSLError, asyncio.TimeoutError) as e:
        results["error"] = str(e)
    return results

async def _check_http_headers(session: ClientSession, url: str) -> Dict[str, bool]:
    """Checks for the presence of common security-related HTTP headers."""
    headers_present = {
        "Strict-Transport-Security": False,
        "X-Frame-Options": False,
        "Content-Security-Policy": False,
        "X-Content-Type-Options": False,
        "Referrer-Policy": False,
        "Permissions-Policy": False,
        "X-XSS-Protection": False
    }
    status, headers, _ = await _fetch(session, url, method='HEAD')
    if 200 <= status < 300:
        for header in headers_present:
            if header in headers:
                headers_present[header] = True
    return headers_present

async def _check_robots_txt(session: ClientSession, url: str) -> Dict[str, Any]:
    """Checks for the presence and content of robots.txt."""
    results = {"found": False, "disallow_all": False, "entries": [], "error": None}
    robots_url = url.rstrip("/") + "/robots.txt"
    status, _, content = await _fetch(session, robots_url)
    if status == 200:
        results["found"] = True
        if "Disallow: /" in content:
            results["disallow_all"] = True
        results["entries"] = [line.strip() for line in content.splitlines() if line.startswith("Disallow:") or line.startswith("Allow:")]
    elif status == 404:
        pass  
    else:
        results["error"] = f"HTTP status code: {status}"
    return results

async def _check_common_files(session: ClientSession, url: str, files: List[str]) -> Dict[str, int]:
    """Checks for the HTTP status of common files and directories."""
    results = {}
    tasks = [asyncio.create_task(_fetch(session, url.rstrip("/") + "/" + file, method='HEAD')) for file in files]
    for i, task in enumerate(tasks):
        status, _, _ = await task
        results[files[i]] = status
    return results

async def _scan_url(url: str) -> Dict[str, Any]:
    """Performs a security scan on the given URL."""
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return {"error": "Invalid URL format"}

    hostname = parsed_url.netloc
    port = 443 if parsed_url.scheme == "https" else 80

    async with ClientSession() as session:
        ssl_results = await _check_ssl_tls(hostname, port)
        header_results = await _check_http_headers(session, url)
        robots_results = await _check_robots_txt(session, url)
        common_file_results = await _check_common_files(session, url, ["admin.php", "login.php", "config.php", ".git/", "wp-admin/", ".env", "admin.html", "dev.html", "dev.php", "config.html", "config.json", "config", "robots.txt", "dev","admin","dtat.php"])

        return {
            "url": url,
            "ssl_tls": ssl_results,
            "http_headers": header_results,
            "robots_txt": robots_results,
            "common_files": common_file_results
        }

def format_scan_results(results: Dict[str, Any]) -> str:
    """Formats the scan results into a more readable output."""
    output = f"Scan Results for: {results.get('url', 'N/A')}\n\n"

    output += "SSL/TLS Configuration:\n"
    ssl_info = results.get("ssl_tls", {})
    if ssl_info.get("ssl_found"):
        output += f"  SSL/TLS Found: Yes\n"
        if ssl_info.get("weak_version"):
            output += f"  Weak TLS Version Found: {ssl_info['weak_version']}\n"
        if ssl_info.get("certificate"):
            cert = ssl_info["certificate"]
            output += "  Certificate:\n"
            output += f"    Subject: {cert.get('subject')}\n"
            output += f"    Issuer: {cert.get('issuer')}\n"
            output += f"    Not Before: {cert.get('not_before')}\n"
            output += f"    Not After: {cert.get('not_after')}\n"
            output += f"    Serial Number: {cert.get('serial_number')}\n"
        if ssl_info.get("cipher"):
            output += f"  Cipher: {ssl_info['cipher'][0]}\n"
        if ssl_info.get("error"):
            output += f"  Error: {ssl_info['error']}\n"
    else:
        output += "  SSL/TLS Not Found or Error Occurred.\n"
        if ssl_info.get("error"):
            output += f"  Error: {ssl_info['error']}\n"
    output += "\n"

    output += "HTTP Security Headers:\n"
    headers_info = results.get("http_headers", {})
    for header, present in headers_info.items():
        status = "Present" if present else "Not Present"
        output += f"  {header}: {status}\n"
    output += "\n"

    output += "robots.txt Analysis:\n"
    robots_info = results.get("robots_txt", {})
    if robots_info.get("found"):
        output += f"  robots.txt Found: Yes\n"
        output += f"  Disallow All: {'Yes' if robots_info.get('disallow_all') else 'No'}\n"
        if robots_info.get("entries"):
            output += "  Entries:\n"
            for entry in robots_info["entries"]:
                output += f"    - {entry}\n"
    else:
        output += f"  robots.txt Not Found.\n"
        if robots_info.get("error"):
            output += f"  Error: {robots_info['error']}\n"
    output += "\n"

    output += "Common Files/Directories Check:\n"
    common_files_info = results.get("common_files", {})
    for file, status_code in common_files_info.items():
        output += f"  {file}: "
        if 200 <= status_code < 300:
            output += f"Found (Status: {status_code})\n"
        elif status_code == 404:
            output += "Not Found\n"
        elif status_code > 0:
            output += f"Status: {status_code}\n"
        else:
            output += "Error\n"

    return output

async def main():
    target = input("Enter target URL (e.g., https://example.com) > ")
    if not target.startswith("http://") and not target.startswith("https://"):
        print("Invalid URL.")
        return
    results = await _scan_url(target)
    print("\n" + format_scan_results(results))
    print("\nScan completed.")

if __name__ == "__main__":
    asyncio.run(main())