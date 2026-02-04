"""SQL Injection Scanner - Core scanning logic."""

import asyncio
import re
import uuid
import time
from typing import Optional

from sqli_mcp.models import (
    ScanConfig, ScanResult, VulnerabilityFinding, Payload,
    InjectionType, DatabaseType, HttpMethod, WAFBypassTechnique
)
from sqli_mcp.http_client import (
    HttpClient, parse_url_params, inject_payload_in_url, inject_payload_in_data
)
from sqli_mcp.payloads import get_payloads_filtered, apply_waf_bypass


# Database error patterns for detection
DB_ERROR_PATTERNS = {
    DatabaseType.MYSQL: [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Unclosed quotation mark after the character string",
        r"SQLSTATE\[.*\]: Syntax error",
    ],
    DatabaseType.MSSQL: [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.",
        r"Exception.*\WRoadhouse\.",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"macaborla\.\w+\.\w+Exception",
        r"com\.microsoft\.sqlserver\.jdbc",
    ],
    DatabaseType.POSTGRESQL: [
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
        r"ERROR: parser:",
        r"PostgreSQL query failed",
        r"org\.postgresql\.jdbc",
    ],
    DatabaseType.ORACLE: [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    DatabaseType.SQLITE: [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError:",
        r"SQLite3::SQLException",
        r"org\.sqlite\.JDBC",
        r"SQLiteException",
    ],
}


class Scanner:
    """SQL Injection vulnerability scanner."""
    
    def __init__(self, config: ScanConfig):
        """
        Initialize scanner with configuration.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.client = HttpClient(
            auth=config.auth,
            proxy=config.proxy,
            timeout=config.timeout
        )
        self.results: list[VulnerabilityFinding] = []
        self.errors: list[str] = []
        self.payloads_tested = 0
    
    def _detect_database_from_error(self, response_text: str) -> Optional[DatabaseType]:
        """Detect database type from error messages."""
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type
        return None
    
    def _check_error_based(self, response_text: str) -> tuple[bool, Optional[DatabaseType], str]:
        """
        Check response for error-based SQL injection indicators.
        
        Returns:
            Tuple of (is_vulnerable, detected_db_type, evidence)
        """
        db_type = self._detect_database_from_error(response_text)
        if db_type:
            # Extract a snippet of the error as evidence
            for pattern in DB_ERROR_PATTERNS[db_type]:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    # Get context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    evidence = response_text[start:end].strip()
                    return True, db_type, f"Database error detected: {evidence}"
        
        return False, None, ""
    
    def _check_boolean_based(
        self,
        baseline_response: str,
        true_response: str,
        false_response: str
    ) -> tuple[bool, str]:
        """
        Check for boolean-based SQL injection by comparing responses.
        
        Args:
            baseline_response: Original response without injection
            true_response: Response with true condition payload
            false_response: Response with false condition payload
        
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        baseline_len = len(baseline_response)
        true_len = len(true_response)
        false_len = len(false_response)
        
        # Check if true condition matches baseline but false differs significantly
        if abs(true_len - baseline_len) < 100 and abs(false_len - baseline_len) > 100:
            return True, f"Response length differs: true={true_len}, false={false_len}, baseline={baseline_len}"
        
        # Check if true and false responses differ significantly from each other
        if abs(true_len - false_len) > 100:
            return True, f"Boolean conditions produce different responses: true={true_len}, false={false_len}"
        
        return False, ""
    
    def _check_time_based(
        self,
        baseline_time: float,
        inject_time: float,
        threshold: float = 4.0
    ) -> tuple[bool, str]:
        """
        Check for time-based SQL injection by comparing response times.
        
        Args:
            baseline_time: Response time without injection
            inject_time: Response time with time-based payload
            threshold: Minimum delay to consider as vulnerability
        
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        delay = inject_time - baseline_time
        if delay >= threshold:
            return True, f"Response delayed by {delay:.2f}s (threshold: {threshold}s)"
        return False, ""
    
    async def _get_baseline(self) -> tuple[str, int, float]:
        """
        Get baseline response for comparison.
        
        Returns:
            Tuple of (response_text, status_code, response_time)
        """
        try:
            if self.config.method == HttpMethod.GET:
                response, elapsed = await self.client.request_with_timing(
                    self.config.target_url,
                    HttpMethod.GET
                )
            else:
                response, elapsed = await self.client.request_with_timing(
                    self.config.target_url,
                    HttpMethod.POST,
                    data=self.config.post_data
                )
            return response.text, response.status_code, elapsed
        except Exception as e:
            self.errors.append(f"Baseline request failed: {str(e)}")
            return "", 0, 0.0
    
    async def _test_payload(
        self,
        payload: Payload,
        parameter: str,
        baseline_text: str,
        baseline_time: float
    ) -> Optional[VulnerabilityFinding]:
        """Test a single payload against a parameter."""
        try:
            # Apply WAF bypass if configured
            payload_value = apply_waf_bypass(payload.value, self.config.waf_bypass)
            
            if self.config.method == HttpMethod.GET:
                test_url = inject_payload_in_url(
                    self.config.target_url, parameter, payload_value
                )
                response, elapsed = await self.client.request_with_timing(
                    test_url, HttpMethod.GET
                )
            else:
                test_data = inject_payload_in_data(
                    self.config.post_data or {}, parameter, payload_value
                )
                response, elapsed = await self.client.request_with_timing(
                    self.config.target_url, HttpMethod.POST, data=test_data
                )
            
            self.payloads_tested += 1
            
            # Check for vulnerabilities based on injection type
            if payload.injection_type == InjectionType.ERROR_BASED:
                is_vuln, db_type, evidence = self._check_error_based(response.text)
                if is_vuln:
                    return VulnerabilityFinding(
                        url=self.config.target_url,
                        parameter=parameter,
                        method=self.config.method,
                        injection_type=InjectionType.ERROR_BASED,
                        database_type=db_type,
                        payload_used=payload_value,
                        evidence=evidence,
                        confidence="high"
                    )
            
            elif payload.injection_type == InjectionType.TIME_BASED:
                is_vuln, evidence = self._check_time_based(
                    baseline_time, elapsed, self.config.delay_threshold
                )
                if is_vuln:
                    return VulnerabilityFinding(
                        url=self.config.target_url,
                        parameter=parameter,
                        method=self.config.method,
                        injection_type=InjectionType.TIME_BASED,
                        database_type=payload.database_type if payload.database_type != DatabaseType.GENERIC else None,
                        payload_used=payload_value,
                        evidence=evidence,
                        confidence="medium"
                    )
            
            # For other types, check for error patterns
            is_vuln, db_type, evidence = self._check_error_based(response.text)
            if is_vuln:
                return VulnerabilityFinding(
                    url=self.config.target_url,
                    parameter=parameter,
                    method=self.config.method,
                    injection_type=payload.injection_type,
                    database_type=db_type,
                    payload_used=payload_value,
                    evidence=evidence,
                    confidence="medium"
                )
            
        except asyncio.TimeoutError:
            # Timeout might indicate successful time-based injection
            if payload.injection_type == InjectionType.TIME_BASED:
                return VulnerabilityFinding(
                    url=self.config.target_url,
                    parameter=parameter,
                    method=self.config.method,
                    injection_type=InjectionType.TIME_BASED,
                    database_type=payload.database_type if payload.database_type != DatabaseType.GENERIC else None,
                    payload_used=payload.value,
                    evidence=f"Request timed out after {self.config.timeout}s (likely time-based SQLi)",
                    confidence="medium"
                )
        except Exception as e:
            self.errors.append(f"Error testing payload on {parameter}: {str(e)}")
        
        return None
    
    async def scan_parameter(
        self,
        parameter: str,
        payloads: Optional[list[Payload]] = None
    ) -> list[VulnerabilityFinding]:
        """
        Scan a specific parameter for SQL injection.
        
        Args:
            parameter: Parameter name to test
            payloads: Optional list of payloads (uses built-in if not provided)
        
        Returns:
            List of vulnerability findings
        """
        findings: list[VulnerabilityFinding] = []
        
        # Get baseline
        baseline_text, baseline_status, baseline_time = await self._get_baseline()
        if not baseline_text and baseline_status == 0:
            return findings
        
        # Get payloads to test
        if payloads is None:
            payloads = []
            for injection_type in self.config.injection_types:
                for db_type in self.config.database_types:
                    payloads.extend(get_payloads_filtered(injection_type, db_type))
        
        # Test each payload
        for payload in payloads:
            finding = await self._test_payload(
                payload, parameter, baseline_text, baseline_time
            )
            if finding:
                findings.append(finding)
                # Optionally stop on first finding per injection type
                # to save time - can be made configurable
        
        return findings
    
    async def scan(self) -> ScanResult:
        """
        Run the full SQL injection scan.
        
        Returns:
            ScanResult with all findings
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]
        
        # Determine parameters to test
        if self.config.parameter:
            parameters = [self.config.parameter]
        elif self.config.method == HttpMethod.GET:
            parameters = list(parse_url_params(self.config.target_url).keys())
        elif self.config.post_data:
            parameters = list(self.config.post_data.keys())
        else:
            parameters = []
        
        if not parameters:
            self.errors.append("No parameters found to test")
        
        # Scan each parameter
        all_findings: list[VulnerabilityFinding] = []
        for param in parameters:
            findings = await self.scan_parameter(param)
            all_findings.extend(findings)
        
        duration = time.time() - start_time
        
        return ScanResult(
            scan_id=scan_id,
            target_url=self.config.target_url,
            parameters_tested=parameters,
            payloads_tested=self.payloads_tested,
            vulnerabilities=all_findings,
            errors=self.errors,
            duration_seconds=round(duration, 2)
        )


async def quick_scan(
    url: str,
    method: HttpMethod = HttpMethod.GET,
    parameter: Optional[str] = None,
    post_data: Optional[dict[str, str]] = None,
    auth_config: Optional[dict] = None,
    proxy_config: Optional[dict] = None,
    waf_bypass: WAFBypassTechnique = WAFBypassTechnique.NONE
) -> ScanResult:
    """
    Convenience function for quick SQL injection scanning.
    
    Args:
        url: Target URL
        method: HTTP method
        parameter: Specific parameter to test
        post_data: POST data if method is POST
        auth_config: Auth configuration dict
        proxy_config: Proxy configuration dict
        waf_bypass: WAF bypass technique
    
    Returns:
        ScanResult
    """
    from sqli_mcp.models import AuthConfig, ProxyConfig
    
    auth = AuthConfig(**auth_config) if auth_config else None
    proxy = ProxyConfig(**proxy_config) if proxy_config else None
    
    config = ScanConfig(
        target_url=url,
        method=method,
        parameter=parameter,
        post_data=post_data,
        auth=auth,
        proxy=proxy,
        waf_bypass=waf_bypass
    )
    
    scanner = Scanner(config)
    return await scanner.scan()
