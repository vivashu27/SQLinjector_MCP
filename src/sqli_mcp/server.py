"""SQL Injection MCP Server - Main server implementation."""

import asyncio
from typing import Optional
from mcp.server.fastmcp import FastMCP

from sqli_mcp.models import (
    DatabaseType, InjectionType, HttpMethod, WAFBypassTechnique,
    AuthConfig, ProxyConfig, ScanConfig, ScanResult, VulnerabilityFinding
)
from sqli_mcp.scanner import Scanner, quick_scan
from sqli_mcp.payloads import (
    get_all_payloads, get_payloads_by_type, get_payloads_by_database,
    load_custom_payloads, apply_waf_bypass, get_waf_bypass_variants,
    PAYLOAD_CATEGORIES
)
from sqli_mcp.http_client import parse_url_params


# Create MCP server
mcp = FastMCP("SQLi-MCP")

# Store scan results for later retrieval
scan_results: dict[str, ScanResult] = {}
custom_payloads_cache: dict[str, list] = {}


# ============================================================================
# TOOLS
# ============================================================================

@mcp.tool()
async def scan_url(
    target_url: str,
    method: str = "GET",
    post_data: Optional[str] = None,
    injection_types: Optional[str] = None,
    database_types: Optional[str] = None,
    headers: Optional[str] = None,
    cookies: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_ssl: bool = True,
    waf_bypass: str = "none",
    timeout: float = 10.0,
    delay_threshold: float = 5.0
) -> dict:
    """
    Scan a URL for SQL injection vulnerabilities in all detected parameters.
    
    Args:
        target_url: Target URL with query parameters to scan (e.g., http://example.com/page?id=1)
        method: HTTP method - GET or POST
        post_data: POST data as key=value pairs separated by & (e.g., username=admin&password=test)
        injection_types: Comma-separated injection types to test (error_based, time_based, boolean_based, union_based, blind)
        database_types: Comma-separated database types to test (mysql, mssql, postgresql, oracle, sqlite, generic)
        headers: Custom headers as key:value pairs separated by | (e.g., X-Custom:value|X-API-Key:abc123)
        cookies: Cookies as key=value pairs separated by ; (e.g., session=abc123;token=xyz)
        bearer_token: Bearer token for Authorization header
        proxy_url: Proxy URL for Burp Suite or other proxies (e.g., http://127.0.0.1:8080)
        verify_ssl: Verify SSL certificates (set to false when using proxy)
        waf_bypass: WAF bypass technique (none, url_encode, double_url_encode, hex_encode, unicode, case_swap, comment_injection)
        timeout: Request timeout in seconds
        delay_threshold: Delay threshold in seconds for time-based detection
    
    Returns:
        Scan results with vulnerabilities found
    """
    # Parse injection types
    inj_types = list(InjectionType)
    if injection_types:
        inj_types = [InjectionType(t.strip()) for t in injection_types.split(",")]
    
    # Parse database types
    db_types = list(DatabaseType)
    if database_types:
        db_types = [DatabaseType(t.strip()) for t in database_types.split(",")]
    
    # Parse headers
    header_dict = {}
    if headers:
        for h in headers.split("|"):
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()
    
    # Parse cookies
    cookie_dict = {}
    if cookies:
        for c in cookies.split(";"):
            if "=" in c:
                k, v = c.split("=", 1)
                cookie_dict[k.strip()] = v.strip()
    
    # Parse POST data
    post_dict = None
    if post_data:
        post_dict = {}
        for p in post_data.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                post_dict[k.strip()] = v.strip()
    
    # Build config
    auth = AuthConfig(headers=header_dict, cookies=cookie_dict, bearer_token=bearer_token)
    proxy = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url, verify_ssl=verify_ssl) if proxy_url else None
    
    config = ScanConfig(
        target_url=target_url,
        method=HttpMethod(method.upper()),
        post_data=post_dict,
        injection_types=inj_types,
        database_types=db_types,
        auth=auth,
        proxy=proxy,
        waf_bypass=WAFBypassTechnique(waf_bypass),
        timeout=timeout,
        delay_threshold=delay_threshold
    )
    
    scanner = Scanner(config)
    result = await scanner.scan()
    
    # Cache result
    scan_results[result.scan_id] = result
    
    return result.model_dump()


@mcp.tool()
async def scan_get_parameter(
    target_url: str,
    parameter: str,
    injection_types: Optional[str] = None,
    database_types: Optional[str] = None,
    headers: Optional[str] = None,
    cookies: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_ssl: bool = True,
    waf_bypass: str = "none"
) -> dict:
    """
    Test a specific GET parameter for SQL injection.
    
    Args:
        target_url: Target URL (e.g., http://example.com/page?id=1&name=test)
        parameter: Specific parameter name to test (e.g., id)
        injection_types: Comma-separated injection types to test
        database_types: Comma-separated database types to test  
        headers: Custom headers as key:value pairs separated by |
        cookies: Cookies as key=value pairs separated by ;
        bearer_token: Bearer token for Authorization header
        proxy_url: Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)
        verify_ssl: Verify SSL certificates
        waf_bypass: WAF bypass technique
    
    Returns:
        Scan results for the specified parameter
    """
    return await scan_url(
        target_url=target_url,
        method="GET",
        injection_types=injection_types,
        database_types=database_types,
        headers=headers,
        cookies=cookies,
        bearer_token=bearer_token,
        proxy_url=proxy_url,
        verify_ssl=verify_ssl,
        waf_bypass=waf_bypass
    )


@mcp.tool()
async def scan_post_parameter(
    target_url: str,
    post_data: str,
    parameter: str,
    injection_types: Optional[str] = None,
    database_types: Optional[str] = None,
    headers: Optional[str] = None,
    cookies: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_ssl: bool = True,
    waf_bypass: str = "none"
) -> dict:
    """
    Test a specific POST parameter for SQL injection.
    
    Args:
        target_url: Target URL
        post_data: POST body data as key=value pairs separated by & (e.g., username=admin&password=test)
        parameter: Specific parameter name in POST data to test
        injection_types: Comma-separated injection types to test
        database_types: Comma-separated database types to test
        headers: Custom headers as key:value pairs separated by |
        cookies: Cookies as key=value pairs separated by ;
        bearer_token: Bearer token for Authorization header
        proxy_url: Proxy URL for Burp Suite or other proxies
        verify_ssl: Verify SSL certificates
        waf_bypass: WAF bypass technique
    
    Returns:
        Scan results for the specified POST parameter
    """
    # Build config with specific parameter
    inj_types = list(InjectionType)
    if injection_types:
        inj_types = [InjectionType(t.strip()) for t in injection_types.split(",")]
    
    db_types = list(DatabaseType)
    if database_types:
        db_types = [DatabaseType(t.strip()) for t in database_types.split(",")]
    
    header_dict = {}
    if headers:
        for h in headers.split("|"):
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()
    
    cookie_dict = {}
    if cookies:
        for c in cookies.split(";"):
            if "=" in c:
                k, v = c.split("=", 1)
                cookie_dict[k.strip()] = v.strip()
    
    post_dict = {}
    for p in post_data.split("&"):
        if "=" in p:
            k, v = p.split("=", 1)
            post_dict[k.strip()] = v.strip()
    
    auth = AuthConfig(headers=header_dict, cookies=cookie_dict, bearer_token=bearer_token)
    proxy = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url, verify_ssl=verify_ssl) if proxy_url else None
    
    config = ScanConfig(
        target_url=target_url,
        method=HttpMethod.POST,
        parameter=parameter,
        post_data=post_dict,
        injection_types=inj_types,
        database_types=db_types,
        auth=auth,
        proxy=proxy,
        waf_bypass=WAFBypassTechnique(waf_bypass)
    )
    
    scanner = Scanner(config)
    result = await scanner.scan()
    scan_results[result.scan_id] = result
    
    return result.model_dump()


@mcp.tool()
async def test_payload(
    target_url: str,
    payload: str,
    parameter: str,
    method: str = "GET",
    post_data: Optional[str] = None,
    headers: Optional[str] = None,
    cookies: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_ssl: bool = True,
    waf_bypass: str = "none"
) -> dict:
    """
    Test a specific SQL injection payload against a target.
    
    Args:
        target_url: Target URL
        payload: SQL injection payload to test
        parameter: Parameter to inject the payload into
        method: HTTP method (GET or POST)
        post_data: POST data if method is POST
        headers: Custom headers as key:value pairs separated by |
        cookies: Cookies as key=value pairs separated by ;
        bearer_token: Bearer token for Authorization header
        proxy_url: Proxy URL for Burp Suite
        verify_ssl: Verify SSL certificates
        waf_bypass: WAF bypass technique to apply to payload
    
    Returns:
        Test result with response details
    """
    from sqli_mcp.http_client import HttpClient, inject_payload_in_url, inject_payload_in_data
    import time
    
    # Parse headers/cookies
    header_dict = {}
    if headers:
        for h in headers.split("|"):
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()
    
    cookie_dict = {}
    if cookies:
        for c in cookies.split(";"):
            if "=" in c:
                k, v = c.split("=", 1)
                cookie_dict[k.strip()] = v.strip()
    
    auth = AuthConfig(headers=header_dict, cookies=cookie_dict, bearer_token=bearer_token)
    proxy = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url, verify_ssl=verify_ssl) if proxy_url else None
    
    client = HttpClient(auth=auth, proxy=proxy)
    
    # Apply WAF bypass
    encoded_payload = apply_waf_bypass(payload, WAFBypassTechnique(waf_bypass))
    
    try:
        if method.upper() == "GET":
            test_url = inject_payload_in_url(target_url, parameter, encoded_payload)
            response, elapsed = await client.request_with_timing(test_url, HttpMethod.GET)
        else:
            post_dict = {}
            if post_data:
                for p in post_data.split("&"):
                    if "=" in p:
                        k, v = p.split("=", 1)
                        post_dict[k.strip()] = v.strip()
            
            test_data = inject_payload_in_data(post_dict, parameter, encoded_payload)
            response, elapsed = await client.request_with_timing(
                target_url, HttpMethod.POST, data=test_data
            )
        
        return {
            "success": True,
            "status_code": response.status_code,
            "response_time": round(elapsed, 3),
            "response_length": len(response.text),
            "payload_used": encoded_payload,
            "original_payload": payload,
            "waf_bypass_applied": waf_bypass,
            "response_preview": response.text[:500] if len(response.text) > 500 else response.text
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "payload_used": encoded_payload
        }


@mcp.tool()
def list_payloads(
    category: Optional[str] = None,
    database: Optional[str] = None,
    limit: int = 20
) -> dict:
    """
    List available SQL injection payloads.
    
    Args:
        category: Filter by category (error_based, time_based, boolean_based, union_based, blind)
        database: Filter by database type (mysql, mssql, postgresql, oracle, sqlite, generic)
        limit: Maximum number of payloads to return
    
    Returns:
        List of available payloads with descriptions
    """
    if category:
        inj_type = InjectionType(category)
        payloads = get_payloads_by_type(inj_type)
    elif database:
        db_type = DatabaseType(database)
        payloads = get_payloads_by_database(db_type)
    else:
        payloads = get_all_payloads()
    
    # Apply database filter if both category and database specified
    if category and database:
        db_type = DatabaseType(database)
        payloads = [p for p in payloads if p.database_type == db_type or p.database_type == DatabaseType.GENERIC]
    
    return {
        "total_count": len(payloads),
        "showing": min(limit, len(payloads)),
        "categories": PAYLOAD_CATEGORIES,
        "payloads": [
            {
                "value": p.value,
                "type": p.injection_type.value,
                "database": p.database_type.value,
                "description": p.description
            }
            for p in payloads[:limit]
        ]
    }


@mcp.tool()
def load_custom_payloads_from_file(
    file_path: str,
    injection_type: str = "error_based",
    database_type: str = "generic",
    name: str = "custom"
) -> dict:
    """
    Load custom SQL injection payloads from a file.
    
    Args:
        file_path: Absolute path to the payload file (one payload per line)
        injection_type: Injection type for loaded payloads
        database_type: Database type for loaded payloads
        name: Name to cache the payloads under for later use
    
    Returns:
        Information about loaded payloads
    """
    try:
        payloads = load_custom_payloads(
            file_path,
            InjectionType(injection_type),
            DatabaseType(database_type)
        )
        custom_payloads_cache[name] = payloads
        
        return {
            "success": True,
            "name": name,
            "count": len(payloads),
            "preview": [p.value for p in payloads[:5]],
            "message": f"Loaded {len(payloads)} custom payloads from {file_path}"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"File not found: {file_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def get_waf_bypass_payloads(payload: str) -> dict:
    """
    Get all WAF bypass variants of a payload.
    
    Args:
        payload: Original SQL injection payload
    
    Returns:
        Dictionary of bypass techniques and their encoded payloads
    """
    variants = get_waf_bypass_variants(payload)
    return {
        "original": payload,
        "techniques": list(variants.keys()),
        "variants": variants
    }


@mcp.tool()
def get_scan_result(scan_id: str) -> dict:
    """
    Retrieve a previous scan result by ID.
    
    Args:
        scan_id: Scan ID from a previous scan
    
    Returns:
        Scan result details
    """
    if scan_id in scan_results:
        return scan_results[scan_id].model_dump()
    return {"error": f"Scan ID {scan_id} not found"}


# Store batch scan results
batch_results: dict[str, dict] = {}

# Store pending URLs for chunked scanning
pending_scans: dict[str, dict] = {}


@mcp.tool()
async def scan_urls_batch(
    urls: str,
    method: str = "GET",
    injection_types: Optional[str] = None,
    database_types: Optional[str] = None,
    headers: Optional[str] = None,
    cookies: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_ssl: bool = True,
    waf_bypass: str = "none",
    concurrency: int = 3,
    timeout: float = 5.0,
    quick_mode: bool = True,
    max_urls_per_batch: int = 10
) -> dict:
    """
    Scan multiple URLs for SQL injection vulnerabilities in batch.
    Use quick_mode=True (default) for faster scans that won't timeout.
    
    Args:
        urls: Newline-separated list of URLs to scan
        method: HTTP method - GET or POST
        injection_types: Comma-separated injection types (default: error_based only in quick_mode)
        database_types: Comma-separated database types (default: generic,mysql in quick_mode)
        headers: Custom headers as key:value pairs separated by |
        cookies: Cookies as key=value pairs separated by ;
        bearer_token: Bearer token for Authorization header
        proxy_url: Proxy URL for Burp Suite or other proxies
        verify_ssl: Verify SSL certificates
        waf_bypass: WAF bypass technique
        concurrency: Number of concurrent scans (1-10, default 3)
        timeout: Request timeout in seconds per URL (default 5)
        quick_mode: Use quick scan with fewer payloads (default True, recommended for many URLs)
        max_urls_per_batch: Max URLs to scan in one call (default 10, use continue_batch for more)
    
    Returns:
        Batch scan results. If more URLs remain, use continue_batch with the batch_id.
    """
    import uuid
    import time
    
    # Parse URLs
    url_list = [u.strip() for u in urls.strip().split('\n') if u.strip() and u.strip().startswith('http')]
    
    if not url_list:
        return {"error": "No valid URLs provided. URLs must start with http:// or https://"}
    
    # Limit concurrency and batch size for stability
    concurrency = max(1, min(10, concurrency))
    max_urls_per_batch = max(1, min(25, max_urls_per_batch))
    
    batch_id = str(uuid.uuid4())[:8]
    start_time = time.time()
    
    # In quick_mode, use minimal payloads for speed
    if quick_mode:
        inj_types = [InjectionType.ERROR_BASED]
        db_types = [DatabaseType.GENERIC, DatabaseType.MYSQL]
    else:
        inj_types = list(InjectionType)
        db_types = list(DatabaseType)
    
    # Override with user-specified types if provided
    if injection_types:
        inj_types = [InjectionType(t.strip()) for t in injection_types.split(",")]
    if database_types:
        db_types = [DatabaseType(t.strip()) for t in database_types.split(",")]
    
    header_dict = {}
    if headers:
        for h in headers.split("|"):
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()
    
    cookie_dict = {}
    if cookies:
        for c in cookies.split(";"):
            if "=" in c:
                k, v = c.split("=", 1)
                cookie_dict[k.strip()] = v.strip()
    
    auth = AuthConfig(headers=header_dict, cookies=cookie_dict, bearer_token=bearer_token)
    proxy = ProxyConfig(http_proxy=proxy_url, https_proxy=proxy_url, verify_ssl=verify_ssl) if proxy_url else None
    
    # Split into current batch and remaining
    current_batch = url_list[:max_urls_per_batch]
    remaining_urls = url_list[max_urls_per_batch:]
    
    # Store remaining for continuation
    if remaining_urls:
        pending_scans[batch_id] = {
            "remaining_urls": remaining_urls,
            "method": method,
            "injection_types": injection_types,
            "database_types": database_types,
            "headers": headers,
            "cookies": cookies,
            "bearer_token": bearer_token,
            "proxy_url": proxy_url,
            "verify_ssl": verify_ssl,
            "waf_bypass": waf_bypass,
            "concurrency": concurrency,
            "timeout": timeout,
            "quick_mode": quick_mode,
            "max_urls_per_batch": max_urls_per_batch,
            "all_results": []
        }
    
    # Semaphore for concurrency control
    semaphore = asyncio.Semaphore(concurrency)
    
    async def scan_single_url(url: str) -> dict:
        async with semaphore:
            try:
                config = ScanConfig(
                    target_url=url,
                    method=HttpMethod(method.upper()),
                    injection_types=inj_types,
                    database_types=db_types,
                    auth=auth,
                    proxy=proxy,
                    waf_bypass=WAFBypassTechnique(waf_bypass),
                    timeout=timeout
                )
                scanner = Scanner(config)
                result = await scanner.scan()
                scan_results[result.scan_id] = result
                
                return {
                    "url": url,
                    "scan_id": result.scan_id,
                    "status": "completed",
                    "vulnerabilities_found": len(result.vulnerabilities),
                    "vulnerable": len(result.vulnerabilities) > 0
                }
            except asyncio.TimeoutError:
                return {"url": url, "status": "timeout", "vulnerable": False}
            except Exception as e:
                return {"url": url, "status": "error", "error": str(e)[:100], "vulnerable": False}
    
    # Run scans concurrently
    tasks = [scan_single_url(url) for url in current_batch]
    results = await asyncio.gather(*tasks)
    
    duration = time.time() - start_time
    
    # Summary
    total_in_batch = len(results)
    completed = sum(1 for r in results if r["status"] == "completed")
    errors = sum(1 for r in results if r["status"] in ["error", "timeout"])
    vulnerable_count = sum(1 for r in results if r.get("vulnerable", False))
    
    batch_result = {
        "batch_id": batch_id,
        "urls_in_this_batch": total_in_batch,
        "total_urls_submitted": len(url_list),
        "remaining_urls": len(remaining_urls),
        "completed": completed,
        "errors": errors,
        "vulnerable_urls": vulnerable_count,
        "duration_seconds": round(duration, 2),
        "quick_mode": quick_mode,
        "results": results,
        "vulnerable_urls_list": [r["url"] for r in results if r.get("vulnerable", False)],
        "has_more": len(remaining_urls) > 0,
        "continue_hint": f"Use continue_batch(batch_id='{batch_id}') to scan remaining {len(remaining_urls)} URLs" if remaining_urls else None
    }
    
    batch_results[batch_id] = batch_result
    return batch_result


@mcp.tool()
async def continue_batch(batch_id: str) -> dict:
    """
    Continue scanning remaining URLs from a previous batch.
    Use this when scan_urls_batch returns has_more=True.
    
    Args:
        batch_id: Batch ID from a previous scan_urls_batch call
    
    Returns:
        Next batch of scan results
    """
    if batch_id not in pending_scans:
        return {"error": f"No pending scans for batch {batch_id}. Batch may be complete or expired."}
    
    pending = pending_scans[batch_id]
    remaining = pending["remaining_urls"]
    
    if not remaining:
        del pending_scans[batch_id]
        return {"message": "All URLs in this batch have been scanned", "batch_id": batch_id}
    
    # Build URL string for the next batch
    urls_str = "\n".join(remaining)
    
    # Scan next batch
    result = await scan_urls_batch(
        urls=urls_str,
        method=pending["method"],
        injection_types=pending["injection_types"],
        database_types=pending["database_types"],
        headers=pending["headers"],
        cookies=pending["cookies"],
        bearer_token=pending["bearer_token"],
        proxy_url=pending["proxy_url"],
        verify_ssl=pending["verify_ssl"],
        waf_bypass=pending["waf_bypass"],
        concurrency=pending["concurrency"],
        timeout=pending["timeout"],
        quick_mode=pending["quick_mode"],
        max_urls_per_batch=pending["max_urls_per_batch"]
    )
    
    # Update the original batch_id reference
    result["original_batch_id"] = batch_id
    
    # Clean up if complete
    if not result.get("has_more", False) and batch_id in pending_scans:
        del pending_scans[batch_id]
    
    return result


@mcp.tool()
async def scan_urls_from_file(
    file_path: str,
    method: str = "GET",
    injection_types: Optional[str] = None,
    database_types: Optional[str] = None,
    headers: Optional[str] = None,
    cookies: Optional[str] = None,
    bearer_token: Optional[str] = None,
    proxy_url: Optional[str] = None,
    verify_ssl: bool = True,
    waf_bypass: str = "none",
    concurrency: int = 3,
    timeout: float = 5.0,
    quick_mode: bool = True,
    max_urls_per_batch: int = 10
) -> dict:
    """
    Scan multiple URLs from a file for SQL injection vulnerabilities.
    Returns results in chunks to avoid timeouts. Use continue_batch to get more results.
    
    Args:
        file_path: Absolute path to file containing URLs (one URL per line)
        method: HTTP method - GET or POST
        injection_types: Comma-separated injection types to test
        database_types: Comma-separated database types to test
        headers: Custom headers as key:value pairs separated by |
        cookies: Cookies as key=value pairs separated by ;
        bearer_token: Bearer token for Authorization header
        proxy_url: Proxy URL for Burp Suite or other proxies
        verify_ssl: Verify SSL certificates
        waf_bypass: WAF bypass technique
        concurrency: Number of concurrent scans (1-10, default 3)
        timeout: Request timeout in seconds per URL (default 5)
        quick_mode: Use quick scan with fewer payloads (default True)
        max_urls_per_batch: Max URLs to scan in one call (default 10)
    
    Returns:
        Batch scan results. If more URLs remain, use continue_batch with the batch_id.
    """
    from pathlib import Path
    
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            urls = f.read()
    except Exception as e:
        return {"error": f"Failed to read file: {str(e)}"}
    
    # Count URLs for info
    url_count = len([u for u in urls.strip().split('\n') if u.strip() and u.strip().startswith('http')])
    
    # Delegate to batch scanner
    result = await scan_urls_batch(
        urls=urls,
        method=method,
        injection_types=injection_types,
        database_types=database_types,
        headers=headers,
        cookies=cookies,
        bearer_token=bearer_token,
        proxy_url=proxy_url,
        verify_ssl=verify_ssl,
        waf_bypass=waf_bypass,
        concurrency=concurrency,
        timeout=timeout,
        quick_mode=quick_mode,
        max_urls_per_batch=max_urls_per_batch
    )
    
    result["source_file"] = file_path
    result["total_urls_in_file"] = url_count
    return result


@mcp.tool()
def get_batch_result(batch_id: str) -> dict:
    """
    Retrieve a previous batch scan result by ID.
    
    Args:
        batch_id: Batch ID from a previous batch scan
    
    Returns:
        Batch scan result details
    """
    if batch_id in batch_results:
        return batch_results[batch_id]
    return {"error": f"Batch ID {batch_id} not found"}


@mcp.tool()
def get_vulnerable_urls(batch_id: str) -> dict:
    """
    Get only the vulnerable URLs from a batch scan.
    
    Args:
        batch_id: Batch ID from a previous batch scan
    
    Returns:
        List of vulnerable URLs with their scan details
    """
    if batch_id not in batch_results:
        return {"error": f"Batch ID {batch_id} not found"}
    
    batch = batch_results[batch_id]
    vulnerable = [r for r in batch["results"] if r.get("vulnerable", False)]
    
    return {
        "batch_id": batch_id,
        "total_scanned": batch["total_urls"],
        "vulnerable_count": len(vulnerable),
        "vulnerable_urls": vulnerable
    }


# ============================================================================
# RESOURCES
# ============================================================================

@mcp.resource("payloads://all")
def get_all_payloads_resource() -> str:
    """Get all available SQL injection payloads."""
    payloads = get_all_payloads()
    lines = [f"# SQL Injection Payloads ({len(payloads)} total)\n"]
    
    current_type = None
    for p in payloads:
        if p.injection_type != current_type:
            current_type = p.injection_type
            lines.append(f"\n## {current_type.value.upper()}\n")
        lines.append(f"- [{p.database_type.value}] {p.value}")
        if p.description:
            lines.append(f"  # {p.description}")
    
    return "\n".join(lines)


@mcp.resource("payloads://{category}")
def get_payloads_by_category(category: str) -> str:
    """Get payloads for a specific category."""
    try:
        inj_type = InjectionType(category)
        payloads = get_payloads_by_type(inj_type)
        
        lines = [f"# {category.upper()} SQL Injection Payloads ({len(payloads)} total)\n"]
        for p in payloads:
            lines.append(f"[{p.database_type.value}] {p.value}")
            if p.description:
                lines.append(f"  # {p.description}")
        
        return "\n".join(lines)
    except ValueError:
        return f"Unknown category: {category}. Valid categories: {', '.join(PAYLOAD_CATEGORIES.keys())}"


@mcp.resource("results://{scan_id}")
def get_result_resource(scan_id: str) -> str:
    """Get detailed scan results."""
    if scan_id not in scan_results:
        return f"Scan ID {scan_id} not found"
    
    result = scan_results[scan_id]
    lines = [
        f"# Scan Results: {scan_id}",
        f"Target: {result.target_url}",
        f"Parameters tested: {', '.join(result.parameters_tested)}",
        f"Payloads tested: {result.payloads_tested}",
        f"Duration: {result.duration_seconds}s",
        f"\n## Vulnerabilities Found: {len(result.vulnerabilities)}\n"
    ]
    
    for i, v in enumerate(result.vulnerabilities, 1):
        lines.append(f"### Finding #{i}")
        lines.append(f"- Parameter: {v.parameter}")
        lines.append(f"- Type: {v.injection_type.value}")
        lines.append(f"- Database: {v.database_type.value if v.database_type else 'Unknown'}")
        lines.append(f"- Confidence: {v.confidence}")
        lines.append(f"- Payload: `{v.payload_used}`")
        lines.append(f"- Evidence: {v.evidence}\n")
    
    if result.errors:
        lines.append("\n## Errors\n")
        for e in result.errors:
            lines.append(f"- {e}")
    
    return "\n".join(lines)


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
