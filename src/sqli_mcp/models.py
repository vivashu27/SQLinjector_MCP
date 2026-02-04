"""Pydantic models for SQL Injection MCP Server."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class DatabaseType(str, Enum):
    """Supported database types."""
    MYSQL = "mysql"
    MSSQL = "mssql"
    POSTGRESQL = "postgresql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


class InjectionType(str, Enum):
    """SQL injection types."""
    ERROR_BASED = "error_based"
    TIME_BASED = "time_based"
    BOOLEAN_BASED = "boolean_based"
    UNION_BASED = "union_based"
    BLIND = "blind"
    STACKED = "stacked"


class HttpMethod(str, Enum):
    """HTTP methods for requests."""
    GET = "GET"
    POST = "POST"


class WAFBypassTechnique(str, Enum):
    """WAF bypass encoding techniques."""
    NONE = "none"
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    HEX_ENCODE = "hex_encode"
    UNICODE = "unicode"
    CASE_SWAP = "case_swap"
    COMMENT_INJECTION = "comment_injection"


class AuthConfig(BaseModel):
    """Authentication configuration for requests."""
    headers: dict[str, str] = Field(default_factory=dict, description="Custom headers (e.g., Authorization)")
    cookies: dict[str, str] = Field(default_factory=dict, description="Cookies for session-based auth")
    bearer_token: Optional[str] = Field(default=None, description="Bearer token for Authorization header")


class ProxyConfig(BaseModel):
    """Proxy configuration for request routing."""
    http_proxy: Optional[str] = Field(default=None, description="HTTP proxy URL (e.g., http://127.0.0.1:8080)")
    https_proxy: Optional[str] = Field(default=None, description="HTTPS proxy URL")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")


class ScanConfig(BaseModel):
    """Configuration for SQL injection scanning."""
    target_url: str = Field(..., description="Target URL to scan")
    method: HttpMethod = Field(default=HttpMethod.GET, description="HTTP method")
    parameter: Optional[str] = Field(default=None, description="Specific parameter to test")
    post_data: Optional[dict[str, str]] = Field(default=None, description="POST body data")
    injection_types: list[InjectionType] = Field(
        default_factory=lambda: list(InjectionType),
        description="Injection types to test"
    )
    database_types: list[DatabaseType] = Field(
        default_factory=lambda: list(DatabaseType),
        description="Database types to test payloads for"
    )
    auth: Optional[AuthConfig] = Field(default=None, description="Authentication config")
    proxy: Optional[ProxyConfig] = Field(default=None, description="Proxy configuration")
    waf_bypass: WAFBypassTechnique = Field(default=WAFBypassTechnique.NONE, description="WAF bypass technique")
    timeout: float = Field(default=10.0, description="Request timeout in seconds")
    delay_threshold: float = Field(default=5.0, description="Delay threshold for time-based detection")


class Payload(BaseModel):
    """SQL injection payload."""
    value: str = Field(..., description="The payload string")
    injection_type: InjectionType = Field(..., description="Type of injection")
    database_type: DatabaseType = Field(..., description="Target database type")
    description: Optional[str] = Field(default=None, description="Payload description")


class VulnerabilityFinding(BaseModel):
    """A discovered SQL injection vulnerability."""
    url: str = Field(..., description="Vulnerable URL")
    parameter: str = Field(..., description="Vulnerable parameter")
    method: HttpMethod = Field(..., description="HTTP method used")
    injection_type: InjectionType = Field(..., description="Type of injection detected")
    database_type: Optional[DatabaseType] = Field(default=None, description="Detected database type")
    payload_used: str = Field(..., description="Payload that triggered the vulnerability")
    evidence: str = Field(..., description="Evidence of vulnerability")
    confidence: str = Field(default="medium", description="Confidence level: low, medium, high")


class ScanResult(BaseModel):
    """Result of a SQL injection scan."""
    scan_id: str = Field(..., description="Unique scan identifier")
    target_url: str = Field(..., description="Scanned URL")
    parameters_tested: list[str] = Field(default_factory=list, description="Parameters tested")
    payloads_tested: int = Field(default=0, description="Number of payloads tested")
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list, description="Found vulnerabilities")
    errors: list[str] = Field(default_factory=list, description="Errors during scan")
    duration_seconds: float = Field(default=0.0, description="Scan duration")
