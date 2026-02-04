"""Payload loader and WAF bypass utilities."""

import urllib.parse
from pathlib import Path
from typing import Optional

from sqli_mcp.models import Payload, InjectionType, DatabaseType, WAFBypassTechnique
from sqli_mcp.payloads.error_based import ERROR_BASED_PAYLOADS
from sqli_mcp.payloads.time_based import TIME_BASED_PAYLOADS
from sqli_mcp.payloads.boolean_based import BOOLEAN_BASED_PAYLOADS
from sqli_mcp.payloads.union_based import UNION_BASED_PAYLOADS
from sqli_mcp.payloads.blind import BLIND_PAYLOADS


# Payload categories for listing
PAYLOAD_CATEGORIES = {
    "error_based": "Error-based SQL injection payloads that trigger database errors",
    "time_based": "Time-based blind SQL injection using database sleep functions",
    "boolean_based": "Boolean-based payloads that detect differences in responses",
    "union_based": "UNION-based payloads for extracting data through UNION queries",
    "blind": "Blind SQL injection payloads for character-by-character extraction",
}


def get_all_payloads() -> list[Payload]:
    """Get all built-in payloads."""
    return (
        ERROR_BASED_PAYLOADS +
        TIME_BASED_PAYLOADS +
        BOOLEAN_BASED_PAYLOADS +
        UNION_BASED_PAYLOADS +
        BLIND_PAYLOADS
    )


def get_payloads_by_type(injection_type: InjectionType) -> list[Payload]:
    """Get payloads filtered by injection type."""
    return [p for p in get_all_payloads() if p.injection_type == injection_type]


def get_payloads_by_database(database_type: DatabaseType) -> list[Payload]:
    """Get payloads filtered by database type."""
    all_payloads = get_all_payloads()
    return [
        p for p in all_payloads 
        if p.database_type == database_type or p.database_type == DatabaseType.GENERIC
    ]


def get_payloads_filtered(
    injection_type: Optional[InjectionType] = None,
    database_type: Optional[DatabaseType] = None
) -> list[Payload]:
    """Get payloads with optional filtering by type and database."""
    payloads = get_all_payloads()
    
    if injection_type:
        payloads = [p for p in payloads if p.injection_type == injection_type]
    
    if database_type:
        payloads = [
            p for p in payloads 
            if p.database_type == database_type or p.database_type == DatabaseType.GENERIC
        ]
    
    return payloads


def load_custom_payloads(
    file_path: str,
    injection_type: InjectionType = InjectionType.ERROR_BASED,
    database_type: DatabaseType = DatabaseType.GENERIC
) -> list[Payload]:
    """
    Load custom payloads from a file (one payload per line).
    
    Args:
        file_path: Path to the file containing payloads
        injection_type: Default injection type for loaded payloads
        database_type: Default database type for loaded payloads
    
    Returns:
        List of Payload objects
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Payload file not found: {file_path}")
    
    payloads = []
    with open(path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line and not line.startswith("#"):  # Skip empty lines and comments
                payloads.append(Payload(
                    value=line,
                    injection_type=injection_type,
                    database_type=database_type,
                    description=f"Custom payload from {path.name}:{line_num}"
                ))
    
    return payloads


def apply_waf_bypass(payload: str, technique: WAFBypassTechnique) -> str:
    """
    Apply WAF bypass encoding to a payload.
    
    Args:
        payload: The original SQL injection payload
        technique: The bypass technique to apply
    
    Returns:
        Encoded payload string
    """
    if technique == WAFBypassTechnique.NONE:
        return payload
    
    elif technique == WAFBypassTechnique.URL_ENCODE:
        # URL encode special characters
        return urllib.parse.quote(payload, safe='')
    
    elif technique == WAFBypassTechnique.DOUBLE_URL_ENCODE:
        # Double URL encode
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    elif technique == WAFBypassTechnique.HEX_ENCODE:
        # Hex encode the payload (useful for some contexts)
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    elif technique == WAFBypassTechnique.UNICODE:
        # Unicode encoding for bypassing simple filters
        encoded = ""
        for char in payload:
            if char in " '\"=<>":
                encoded += f"%u{ord(char):04x}"
            else:
                encoded += char
        return encoded
    
    elif technique == WAFBypassTechnique.CASE_SWAP:
        # Alternate case for keywords to bypass case-sensitive filters
        keywords = ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR", "ORDER", "BY", 
                   "INSERT", "UPDATE", "DELETE", "DROP", "NULL", "SLEEP", "WAITFOR",
                   "CONCAT", "VERSION", "DATABASE", "USER", "TABLE", "HAVING", "GROUP"]
        result = payload
        for keyword in keywords:
            # Apply mixed case: SeLeCt, uNiOn, etc.
            mixed = ""
            for i, c in enumerate(keyword):
                mixed += c.lower() if i % 2 == 0 else c.upper()
            result = result.replace(keyword, mixed)
            result = result.replace(keyword.lower(), mixed)
        return result
    
    elif technique == WAFBypassTechnique.COMMENT_INJECTION:
        # Insert comments between SQL keywords to bypass filters
        # Replace spaces with inline comments
        return payload.replace(" ", "/**/")
    
    return payload


def get_waf_bypass_variants(payload: str) -> dict[str, str]:
    """
    Get all WAF bypass variants of a payload.
    
    Args:
        payload: Original payload
    
    Returns:
        Dictionary mapping technique name to encoded payload
    """
    variants = {}
    for technique in WAFBypassTechnique:
        if technique != WAFBypassTechnique.NONE:
            variants[technique.value] = apply_waf_bypass(payload, technique)
    return variants
